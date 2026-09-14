'use strict'
// Navico NEON sonar network protocol (reverse-engineered from NEON 2.x captures).
// Ports (UDP, broadcast on 255.255.255.255 and 169.254.255.255):
//   10752  heartbeat / source discovery      (role 0x15 = networked sonar e.g. Vulcan; 0x18 = NEON MFD-hosted sonar)
//   10753  status / settings (ranges, freqs)
//   10754  echogram data  (0x28 records; 8-bit amplitude samples)
//   10758/10768/10788  control / subscription  (0x01 00 00 00 1c 00 .. <ip> ..)
// All little-endian. See README.md for the full field notes.

const HEARTBEAT_PORT = 10752
const STATUS_PORT = 10753
const DATA_PORT = 10754

function cstr (buf, off, len) {
  let end = off
  const max = off + len
  while (end < max && buf[end] !== 0) end++
  return buf.toString('latin1', off, end)
}

// ---- 10752 heartbeat -------------------------------------------------------
// [0]=0x01 [1]=role  [2..34]=name0 (nickname/model id)  [34..66]=name1 (display model)
// trailer (role 0x18 NEON sonar, len 327): includes 6-byte source MAC, serial, channel
//   counts, two 32-byte transducer-type strings, brand, sw version.
function parseHeartbeat (buf, rinfo) {
  if (buf.length < 66 || buf[0] !== 0x01) return null
  const role = buf[1]
  const hb = {
    kind: 'heartbeat',
    address: rinfo && rinfo.address,
    role,
    isSource: role === 0x15,          // networked sonar (Vulcan-style)
    isNeonSonar: role === 0x18,       // MFD-hosted internal sonar (what we publish)
    name: cstr(buf, 2, 32),
    model: cstr(buf, 34, 32)
  }
  // Best-effort trailer decode (offsets validated on kiel2 / Zeus S 2.3.195, len 327).
  if (buf.length >= 327) {
    hb.mac = Array.from(buf.subarray(100, 106)).map(b => b.toString(16).padStart(2, '0')).join(':')
    // two transducer-type strings live in the mid trailer; scan for the first printable run
    hb.transducer = firstString(buf, 106, 200)
    hb.serial = firstString(buf, 250, 300)
    hb.brand = firstString(buf, 280, 327)
  }
  return hb
}

function firstString (buf, from, to) {
  let s = ''
  for (let i = from; i < Math.min(to, buf.length); i++) {
    const c = buf[i]
    if (c >= 32 && c < 127) s += String.fromCharCode(c)
    else if (s.length >= 3) return s
    else s = ''
  }
  return s.length >= 3 ? s : null
}

// ---- 10754 echogram data ---------------------------------------------------
// [0]=0x28 [1]=channel (0x02 conventional, 0x03 forward/structure)
// [2:4]=? [4:6]=headerLen (samples start here, seen 29) [6:8]=sampleCount (u16)
// [8:12]=pingSeq (u32) [12:16]=float rangeUpper? (~5.0) [16:20]=float rangeLower/depthish
// samples: <sampleCount> u8 amplitudes at offset headerLen.
function parseData (buf) {
  if (buf.length < 12 || buf[0] !== 0x28) return null
  const channel = buf[1]
  if (channel === 0x01) return parseStatusRecord(buf) // 0x28 0x01 = status (see 10753)
  const headerLen = buf.readUInt16LE(4)
  const sampleCount = buf.readUInt16LE(6)
  const pingSeq = buf.readUInt32LE(8)
  const f12 = buf.readFloatLE(12)
  const f16 = buf.readFloatLE(16)
  const start = headerLen
  const end = Math.min(start + sampleCount, buf.length)
  const samples = buf.subarray(start, end) // Uint8, one amplitude per range bin
  return {
    kind: 'data',
    channel,
    pingSeq,
    sampleCount,
    rangeUpper: f12,
    rangeLower: f16, // drifts per-ping; likely depth/auto-range (calibrate against N2K depth)
    samples
  }
}

// ---- 10753 status ----------------------------------------------------------
function parseStatus (buf) {
  if (buf.length < 8 || buf[0] !== 0x28) return null
  return parseStatusRecord(buf)
}
function parseStatusRecord (buf) {
  const floats = []
  for (let o = 8; o + 4 <= Math.min(buf.length, 48); o += 4) floats.push(buf.readFloatLE(o))
  return { kind: 'status', sub: buf[1], floats, raw: buf }
}

// Bottom pick. In shallow/harbour water the saturated near-field ring is the
// strongest return, so "strongest bin" fails; the bottom is instead the DEEPEST
// sustained return. We: (1) skip the leading saturated near-field block, then
// (2) scan up from the deepest bin for the first return above an adaptive
// threshold and walk up to its leading edge (the water/sediment interface).
// Returns { bin, amp }; bin === -1 when no bottom is found.
function estimateBottomBin (samples, nearFieldSkip = 20) {
  const n = samples.length
  if (!n) return { bin: -1, amp: 0 }
  let maxAmp = 0
  for (let i = 0; i < n; i++) if (samples[i] > maxAmp) maxAmp = samples[i]
  if (maxAmp === 0) return { bin: -1, amp: 0 }

  // (1) end of the leading near-field/surface ring (contiguous high block)
  let nf = 0
  while (nf < n && samples[nf] >= 0.6 * maxAmp) nf++
  const start = Math.max(nearFieldSkip | 0, nf + Math.round(0.02 * n))
  if (start >= n) return { bin: -1, amp: 0 }

  // (2) adaptive threshold from the amplitude in the search region only
  let regionMax = 0
  for (let i = start; i < n; i++) if (samples[i] > regionMax) regionMax = samples[i]
  if (regionMax === 0) return { bin: -1, amp: 0 }
  const thr = Math.max(8, 0.5 * regionMax)

  // deepest bin above threshold, then walk up to the return's leading edge
  let bi = -1
  for (let i = n - 1; i >= start; i--) { if (samples[i] >= thr) { bi = i; break } }
  if (bi < 0) return { bin: -1, amp: 0 }
  let top = bi
  while (top > start && samples[top - 1] >= 0.5 * thr) top--
  return { bin: top, amp: samples[bi] }
}

module.exports = {
  HEARTBEAT_PORT, STATUS_PORT, DATA_PORT,
  parseHeartbeat, parseData, parseStatus, estimateBottomBin
}
