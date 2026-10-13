// Zero-dependency PNG icon generator: renders the OneCipher "O" mark at
// 16/32/48/128 px into public/icon/. A minimal PNG encoder (IHDR + IDAT +
// IEND, zlib via node:zlib) keeps the toolchain dependency-free.

import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const outDir = join(root, 'public', 'icon');
mkdirSync(outDir, { recursive: true });

const BG = [16, 24, 40, 255]; // #101828
const FG = [74, 222, 128, 255]; // #4ade80
const MID = [28, 38, 58, 255];

function crc32(buf) {
  let c = ~0;
  for (const byte of buf) {
    c ^= byte;
    for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return ~c >>> 0;
}

function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
}

function encodePng(size, pixelAt) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 6; // RGBA
  const raw = Buffer.alloc(size * (size * 4 + 1));
  let offset = 0;
  for (let y = 0; y < size; y++) {
    raw[offset++] = 0; // filter: none
    for (let x = 0; x < size; x++) {
      const [r, g, b, a] = pixelAt(x, y);
      raw[offset++] = r;
      raw[offset++] = g;
      raw[offset++] = b;
      raw[offset++] = a;
    }
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw)),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

/// A rounded square with a bold "O" ring — simple, readable at 16px.
function pixelAt(size) {
  const radius = size * 0.22;
  const inner = size * 0.26;
  const outer = size * 0.38;
  const center = size / 2;
  return (x, y) => {
    // Rounded-rect background.
    const rx = Math.min(x, size - 1 - x);
    const ry = Math.min(y, size - 1 - y);
    const inCorner = rx < radius && ry < radius;
    const inBg = !inCorner || Math.hypot(rx - radius, ry - radius) <= radius;
    const distance = Math.hypot(x - center + 0.5, y - center + 0.5);
    const ring = distance >= inner && distance <= outer;
    // Node marker at the ring's right side.
    const dot = Math.hypot(x - (center + outer), y - center + 0.5) <= size * 0.09;
    if (!inBg) return [0, 0, 0, 0];
    if (dot) return FG;
    if (ring) return FG;
    if (distance < inner - size * 0.05) return MID;
    return BG;
  };
}

for (const size of [16, 32, 48, 128]) {
  const png = encodePng(size, pixelAt(size));
  writeFileSync(join(outDir, `icon-${size}.png`), png);
  console.log(`wrote public/icon/icon-${size}.png (${png.length} bytes)`);
}
