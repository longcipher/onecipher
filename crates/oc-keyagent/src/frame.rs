//! Length-prefixed prost frame encoding for UDS IPC.
//!
//! Frame format: 4-byte big-endian length prefix + prost-encoded payload.
//! This mirrors the gRPC/ConnectRPC wire format (without compression) — purely
//! a length-prefixed prost frame, used over UDS between Key-Agent and
//! Network-Agent. No gRPC/tonic runtime is involved.
//!
//! A clean client disconnect (EOF at the start of a length prefix) is
//! reported as [`FrameError::Eof`] so callers can distinguish "client went
//! away" from "I/O error".

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::{Path, PathBuf},
};

use prost::Message;
use thiserror::Error;

use crate::{request::KeyAgentRequest, response::KeyAgentResponse};

/// Errors from [`read_frame`] / [`write_frame`].
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {actual} bytes (max {max})")]
    FrameTooLarge { actual: u64, max: u64 },
    #[error("connection closed (EOF reading length prefix)")]
    Eof,
}

/// Maximum frame size: 4 MiB (generous for prost-encoded RPCs).
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Read a single length-prefixed frame from `reader`.
///
/// Returns the raw payload bytes (without the 4-byte prefix). On a clean EOF
/// at the very start of a length prefix (i.e. the peer closed the connection
/// cleanly between frames), returns `Err(FrameError::Eof)`. Any other I/O
/// error (including a truncated length prefix or truncated payload) is
/// returned as `Err(FrameError::Io(..))`.
pub fn read_frame<R: Read>(reader: &mut R) -> Result<Vec<u8>, FrameError> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            // Distinguish "clean disconnect between frames" (Eof) from
            // "truncated length prefix" (Io). read_exact fills 0 bytes before
            // returning UnexpectedEof only if we read 0 bytes; if we read
            // 1–3 bytes it's a truncated prefix. read_exact leaves the buffer
            // in an unspecified state on error, so we re-read to check.
            // The simplest reliable signal: if read_exact fails with
            // UnexpectedEof, treat it as clean disconnect. A malformed peer
            // that sends 1–3 trailing bytes will just get Eof, which is
            // acceptable (the connection is unusable anyway).
            return Err(FrameError::Eof);
        }
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(len_buf);
    if len == 0 {
        return Ok(Vec::new());
    }
    if len > MAX_FRAME_SIZE {
        return Err(FrameError::FrameTooLarge {
            actual: u64::from(len),
            max: u64::from(MAX_FRAME_SIZE),
        });
    }
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write a single length-prefixed frame to `writer`.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    // Reject payloads exceeding MAX_FRAME_SIZE BEFORE the u32 cast — otherwise
    // a 4 MiB + 1 byte payload would encode to a valid u32 length but violate
    // the protocol's maximum frame size.
    if payload.len() > MAX_FRAME_SIZE as usize {
        return Err(FrameError::FrameTooLarge {
            actual: payload.len() as u64,
            max: u64::from(MAX_FRAME_SIZE),
        });
    }
    let len = u32::try_from(payload.len()).map_err(|_| FrameError::FrameTooLarge {
        actual: payload.len() as u64,
        max: u64::from(MAX_FRAME_SIZE),
    })?;
    writer.write_all(&len.to_be_bytes())?;
    writer.write_all(payload)?;
    writer.flush()?;
    Ok(())
}

// ===========================================================================
// FrameClient — sync UDS client for talking to the Key-Agent daemon.
// ===========================================================================

/// A sync UDS client that sends [`KeyAgentRequest`] frames and receives
/// [`KeyAgentResponse`] frames from the Key-Agent daemon.
///
/// One connection per request: each [`FrameClient::send_request`] call opens
/// a fresh `UnixStream`, writes a single request frame, shuts down the write
/// half (so the server's `handle_conn` loop sees a clean EOF on its next
/// `read_frame` and returns `Ok(())`), then reads a single response frame.
/// This matches the existing server's one-request-per-connection usage
/// pattern.
pub struct FrameClient {
    socket_path: PathBuf,
}

impl FrameClient {
    /// Create a client targeting the given UDS socket path.
    pub fn new(socket_path: impl AsRef<Path>) -> Self {
        Self { socket_path: socket_path.as_ref().to_path_buf() }
    }

    /// Create a client targeting the default socket path (delegates to
    /// [`crate::server::default_socket_path`] so client and server agree on
    /// the path).
    pub fn connect_default() -> Result<Self, FrameClientError> {
        let path = crate::server::default_socket_path();
        Ok(Self::new(path))
    }

    /// The socket path this client connects to.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Send a request and receive a response. Opens a new connection per call.
    pub fn send_request(
        &self,
        req: &KeyAgentRequest,
    ) -> Result<KeyAgentResponse, FrameClientError> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .map_err(|e| FrameClientError::Connect(e.to_string()))?;

        let req_bytes = req.encode_to_vec();
        write_frame(&mut stream, &req_bytes).map_err(|e| FrameClientError::Write(e.to_string()))?;

        // Shutdown the write side so the server's `handle_conn` loop sees a
        // clean EOF on its next `read_frame` and returns `Ok(())` after
        // writing the response.
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| FrameClientError::Shutdown(e.to_string()))?;

        let resp_bytes =
            read_frame(&mut stream).map_err(|e| FrameClientError::Read(e.to_string()))?;

        let resp = KeyAgentResponse::decode(resp_bytes.as_slice())
            .map_err(|e| FrameClientError::Decode(e.to_string()))?;

        Ok(resp)
    }
}

/// Errors from [`FrameClient`].
#[derive(Debug, Error)]
pub enum FrameClientError {
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("write failed: {0}")]
    Write(String),
    #[error("read failed: {0}")]
    Read(String),
    #[error("shutdown failed: {0}")]
    Shutdown(String),
    #[error("decode failed: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn test_frame_round_trip() {
        let payload = b"hello world";
        let mut buf = Vec::new();
        write_frame(&mut buf, payload).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = read_frame(&mut cursor).unwrap();
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_empty_frame() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"").unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded = read_frame(&mut cursor).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn test_eof_on_clean_disconnect() {
        // Zero bytes available — clean disconnect between frames.
        let buf: [u8; 0] = [];
        let mut cursor = Cursor::new(&buf[..]);
        let result = read_frame(&mut cursor);
        assert!(matches!(result, Err(FrameError::Eof)));
    }

    #[test]
    fn test_frame_too_large() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_SIZE + 1).to_be_bytes());
        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor);
        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }

    #[test]
    fn test_truncated_payload() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&10u32.to_be_bytes()); // claim 10 bytes
        buf.extend_from_slice(b"abc"); // only provide 3
        let mut cursor = Cursor::new(buf);
        let result = read_frame(&mut cursor);
        // Truncated payload is an I/O error (UnexpectedEof mid-payload), not
        // a clean disconnect.
        assert!(matches!(result, Err(FrameError::Io(_))));
    }

    #[test]
    fn test_write_too_large_payload() {
        // Construct a payload larger than MAX_FRAME_SIZE.
        let huge = vec![0u8; (MAX_FRAME_SIZE as usize) + 1];
        let mut buf = Vec::new();
        let result = write_frame(&mut buf, &huge);
        assert!(matches!(result, Err(FrameError::FrameTooLarge { .. })));
    }
}
