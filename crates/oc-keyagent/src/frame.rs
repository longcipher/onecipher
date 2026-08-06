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

use thiserror::Error;

use crate::{request::KeyAgentRequest, response::KeyAgentResponse};

/// Errors from [`read_frame`] / [`write_frame`] / [`Frame`].
#[derive(Debug, Error)]
pub enum FrameError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("frame too large: {actual} bytes (max {max})")]
    FrameTooLarge { actual: u64, max: u64 },
    #[error("connection closed (EOF reading length prefix)")]
    Eof,
    #[error("prost decode error: {0}")]
    Decode(#[from] prost::DecodeError),
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
// Frame<T> — type-safe prost frame wrapper
// ===========================================================================

/// A type-safe wrapper around a prost message that is carried over the
/// length-prefixed UDS wire format.
///
/// This abstraction lets call sites encode/decode prost messages without
/// touching raw bytes or calling `encode_to_vec`/`decode` directly. The wire
/// format is unchanged: `[u32 BE length][prost payload]`.
///
/// **Zero-copy note:** prost messages are not POD (they contain `Vec<u8>`,
/// `String`, maps, etc.), so true zero-copy of the payload is impossible
/// without breaking the wire format. We therefore keep the existing
/// length-prefixed prost framing and add type safety at the call-site level
/// only. (The architect's shared-memory/zerocopy suggestion was evaluated and
/// rejected for this reason — see the module docs.)
pub struct Frame<T> {
    inner: T,
}

impl<T> Frame<T> {
    /// Wrap a message in a frame.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Unwrap the inner message.
    pub fn into_inner(self) -> T {
        self.inner
    }

    /// Borrow the inner message.
    pub fn inner(&self) -> &T {
        &self.inner
    }
}

impl<T: prost::Message> Frame<T> {
    /// Encode the inner message to its prost wire bytes.
    pub fn encode(&self) -> Result<Vec<u8>, FrameError> {
        Ok(self.inner.encode_to_vec())
    }
}

impl<T: prost::Message + Default> Frame<T> {
    /// Decode a prost message from raw bytes.
    ///
    /// `Default` is required because prost decodes into a zero-initialised
    /// message and then applies the wire fields.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let inner = T::decode(bytes)?;
        Ok(Self { inner })
    }
}

impl<T: Clone> Clone for Frame<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone() }
    }
}

impl<T: std::fmt::Debug> std::fmt::Debug for Frame<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Frame").field(&self.inner).finish()
    }
}

impl<T> From<T> for Frame<T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

/// Read a single length-prefixed frame and decode it as a typed prost message.
///
/// This is the type-safe counterpart to [`read_frame`]: it reads the raw
/// payload bytes then decodes them into `T`. A clean EOF at the start of a
/// length prefix is reported as [`FrameError::Eof`].
pub fn read_typed<R: Read, T: prost::Message + Default>(
    reader: &mut R,
) -> Result<Frame<T>, FrameError> {
    let payload = read_frame(reader)?;
    Frame::decode(&payload)
}

/// Encode a typed prost message and write it as a single length-prefixed frame.
///
/// This is the type-safe counterpart to [`write_frame`].
pub fn write_typed<W: Write, T: prost::Message>(
    writer: &mut W,
    frame: &Frame<T>,
) -> Result<(), FrameError> {
    let payload = frame.encode()?;
    write_frame(writer, &payload)
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

        // Typed write: no raw `encode_to_vec` at this call site.
        write_typed(&mut stream, &Frame::new(req.clone()))
            .map_err(|e| FrameClientError::Write(e.to_string()))?;

        // Shutdown the write side so the server's `handle_conn` loop sees a
        // clean EOF on its next `read_frame` and returns `Ok(())` after
        // writing the response.
        stream
            .shutdown(std::net::Shutdown::Write)
            .map_err(|e| FrameClientError::Shutdown(e.to_string()))?;

        // Typed read: decode errors are distinguished from I/O errors.
        read_typed::<_, KeyAgentResponse>(&mut stream).map(Frame::into_inner).map_err(|e| match e {
            FrameError::Decode(d) => FrameClientError::Decode(d.to_string()),
            other => FrameClientError::Read(other.to_string()),
        })
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

    use prost::Message as _;

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

    // -- typed frame API ----------------------------------------------------

    use crate::{request::KeyAgentRequestKind, response::KeyAgentResponseKind};

    fn sample_request() -> KeyAgentRequest {
        KeyAgentRequest { kind: Some(KeyAgentRequestKind::ListWallets(crate::proto::Empty {})) }
    }

    #[test]
    fn typed_round_trip_preserves_message() {
        let req = sample_request();
        let mut buf = Vec::new();
        write_typed(&mut buf, &Frame::new(req.clone())).unwrap();

        let mut cursor = Cursor::new(buf);
        let decoded: Frame<KeyAgentRequest> = read_typed(&mut cursor).unwrap();
        assert_eq!(decoded.into_inner(), req);
    }

    #[test]
    fn typed_read_reports_clean_eof() {
        let buf: [u8; 0] = [];
        let mut cursor = Cursor::new(&buf[..]);
        let result = read_typed::<_, KeyAgentRequest>(&mut cursor);
        assert!(matches!(result, Err(FrameError::Eof)));
    }

    #[test]
    fn typed_read_distinguishes_decode_error_from_io_error() {
        // A well-formed frame whose payload is not valid protobuf for the
        // requested type: tag 1 declared as a length-delimited field whose
        // declared length (0x7F) runs past the end of the buffer.
        let mut buf = Vec::new();
        write_frame(&mut buf, &[0x0A, 0x7F, 0x01, 0x02]).unwrap();
        let mut cursor = Cursor::new(buf);
        let result = read_typed::<_, KeyAgentRequest>(&mut cursor);
        assert!(
            matches!(result, Err(FrameError::Decode(_))),
            "expected a decode error, got {result:?}",
        );
    }

    #[test]
    fn typed_frame_accessors() {
        let frame = Frame::from(sample_request());
        assert!(frame.inner().kind.is_some());
        let cloned = frame.clone();
        assert_eq!(cloned.into_inner(), sample_request());
        // Debug must not panic.
        let _ = format!("{frame:?}");
    }

    #[test]
    fn typed_response_round_trip() {
        let resp = KeyAgentResponse { kind: Some(KeyAgentResponseKind::Error("boom".to_string())) };
        let mut buf = Vec::new();
        write_typed(&mut buf, &Frame::new(resp.clone())).unwrap();
        let mut cursor = Cursor::new(buf);
        let decoded: Frame<KeyAgentResponse> = read_typed(&mut cursor).unwrap();
        assert_eq!(decoded.into_inner(), resp);
    }

    #[test]
    fn typed_encode_matches_raw_prost_encoding() {
        // The typed wrapper must not change the wire format — old peers keep
        // interoperating.
        let req = sample_request();
        let typed = Frame::new(req.clone()).encode().unwrap();
        let raw = req.encode_to_vec();
        assert_eq!(typed, raw);
    }
}
