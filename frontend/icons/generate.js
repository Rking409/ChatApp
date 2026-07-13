const fs = require('fs');
const zlib = require('zlib');
const path = require('path');

function createPNG(size) {
  const sig = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  function chunk(type, data) {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(data.length);
    const c = Buffer.concat([Buffer.from(type), data]);
    const crc = crc32(c);
    const crcBuf = Buffer.alloc(4);
    crcBuf.writeUInt32BE(crc);
    return Buffer.concat([len, c, crcBuf]);
  }

  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(size, 0);
  ihdr.writeUInt32BE(size, 4);
  ihdr[8] = 8;
  ihdr[9] = 6;
  ihdr[10] = 0;
  ihdr[11] = 0;
  ihdr[12] = 0;

  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    const row = y * (size * 4 + 1);
    raw[row] = 0;
    for (let x = 0; x < size; x++) {
      const cx = x / size;
      const cy = y / size;
      const dist = Math.sqrt((cx - 0.5) ** 2 + (cy - 0.5) ** 2) * 2;
      const r = Math.round(245 * (1 - cy * 0.3));
      const g = Math.round(169 * (1 - cx * 0.3) + 162 * cx * 0.3);
      const b = Math.round(71 * (1 - cx * 0.4) + 255 * cx * 0.4);
      const a = dist < 0.85 ? 255 : Math.round(255 * Math.max(0, 1 - (dist - 0.85) * 10));
      const idx = row + 1 + x * 4;
      raw[idx] = r;
      raw[idx + 1] = g;
      raw[idx + 2] = b;
      raw[idx + 3] = a;
    }
  }

  const compressed = zlib.deflateSync(raw);
  return Buffer.concat([sig, chunk('IHDR', ihdr), chunk('IDAT', compressed), chunk('IEND', Buffer.alloc(0))]);
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    table[n] = c;
  }
  for (let i = 0; i < buf.length; i++) crc = table[(crc ^ buf[i]) & 0xFF] ^ (crc >>> 8);
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

const dir = path.dirname(__filename);
fs.writeFileSync(path.join(dir, 'icon-192.png'), createPNG(192));
fs.writeFileSync(path.join(dir, 'icon-512.png'), createPNG(512));
console.log('Icons generated successfully');
