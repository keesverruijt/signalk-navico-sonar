'use strict'
// Render captured conventional-sonar (channel 0x02) pings from a pcap into a waterfall PNG.
//   node tools/render-pcap-png.js test/fixtures/zeuss_conventional.pcap out.png [srcAddr]
const fs = require('fs')
const zlib = require('zlib')
const proto = require('../lib/protocol')

function * udp (file) {
  const d = fs.readFileSync(file)
  const l2 = d.readUInt32LE(20) === 113 ? 16 : 14
  let off = 24
  while (off + 16 <= d.length) {
    const cap = d.readUInt32LE(off + 8); off += 16
    const ip = d.subarray(off + l2, off + cap); off += cap
    if (ip.length < 20 || (ip[0] >> 4) !== 4 || ip[9] !== 17) continue
    const ihl = (ip[0] & 0xf) * 4
    const src = Array.from(ip.subarray(12, 16)).join('.')
    const u = ip.subarray(ihl)
    yield { src, dport: u.readUInt16BE(2), payload: u.subarray(8, 8 + u.readUInt16BE(4) - 8) }
  }
}

const file = process.argv[2] || 'test/fixtures/zeuss_conventional.pcap'
const out = process.argv[3] || 'echogram.png'
const wantSrc = process.argv[4]

// collect distinct conventional pings (dedupe by seq), keep order
const pings = []; const seen = new Set()
for (const { src, dport, payload } of udp(file)) {
  if (dport !== proto.DATA_PORT) continue
  if (wantSrc && src !== wantSrc) continue
  const d = proto.parseData(payload)
  if (!d || d.kind !== 'data' || d.channel !== 0x02) continue
  const key = src + ':' + d.pingSeq
  if (seen.has(key)) continue
  seen.add(key); pings.push(d)
}
if (!pings.length) { console.error('no conventional (ch 0x02) pings found'); process.exit(1) }

const H = Math.min(700, pings[0].samples.length)
const srcN = pings[0].samples.length
const W = pings.length
const rgba = Buffer.alloc(W * H * 4)
for (let x = 0; x < W; x++) {
  const s = pings[x].samples
  for (let y = 0; y < H; y++) {
    const bin = (y / H * srcN) | 0
    let a = s[bin] || 0
    // amber palette
    const r = a, g = (a * 0.7) | 0, b = (a * 0.15) | 0
    const o = (y * W + x) * 4
    rgba[o] = r; rgba[o + 1] = g; rgba[o + 2] = b; rgba[o + 3] = 255
  }
}
fs.writeFileSync(out, encodePNG(W, H, rgba))
console.log(`rendered ${W} pings x ${H}px -> ${out}`)

// ---- minimal PNG encoder (truecolor+alpha) ----
function encodePNG (w, h, rgba) {
  const raw = Buffer.alloc((w * 4 + 1) * h)
  for (let y = 0; y < h; y++) {
    raw[y * (w * 4 + 1)] = 0 // filter none
    rgba.copy(raw, y * (w * 4 + 1) + 1, y * w * 4, (y + 1) * w * 4)
  }
  const idat = zlib.deflateSync(raw)
  const chunk = (type, data) => {
    const b = Buffer.alloc(12 + data.length)
    b.writeUInt32BE(data.length, 0); b.write(type, 4)
    data.copy(b, 8)
    b.writeUInt32BE(crc32(b.subarray(4, 8 + data.length)) >>> 0, 8 + data.length)
    return b
  }
  const ihdr = Buffer.alloc(13)
  ihdr.writeUInt32BE(w, 0); ihdr.writeUInt32BE(h, 4); ihdr[8] = 8; ihdr[9] = 6
  return Buffer.concat([
    Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]),
    chunk('IHDR', ihdr), chunk('IDAT', idat), chunk('IEND', Buffer.alloc(0))
  ])
}
var crcTable
function crc32 (buf) {
  if (!crcTable) { crcTable = []; for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c } }
  let c = 0xffffffff
  for (let i = 0; i < buf.length; i++) c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8)
  return c ^ 0xffffffff
}
