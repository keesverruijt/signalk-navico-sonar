'use strict'
// Offline validation: replay a captured pcap through the protocol parser.
//   node test/parse-pcap.js test/fixtures/zeuss_conventional.pcap
const fs = require('fs')
const proto = require('../lib/protocol')

function * udpPackets (file) {
  const d = fs.readFileSync(file)
  const linktype = d.readUInt32LE(20)
  const l2 = linktype === 113 ? 16 : 14 // SLL vs EN10MB
  let off = 24
  while (off + 16 <= d.length) {
    const cap = d.readUInt32LE(off + 8); off += 16
    const frame = d.subarray(off, off + cap); off += cap
    const ip = frame.subarray(l2)
    if (ip.length < 20 || (ip[0] >> 4) !== 4 || ip[9] !== 17) continue
    const ihl = (ip[0] & 0xf) * 4
    const src = Array.from(ip.subarray(12, 16)).join('.')
    const udp = ip.subarray(ihl)
    const dport = udp.readUInt16BE(2)
    const ulen = udp.readUInt16BE(4)
    yield { src, dport, payload: udp.subarray(8, 8 + ulen - 8) }
  }
}

const file = process.argv[2] || 'test/fixtures/zeuss_conventional.pcap'
if (!fs.existsSync(file)) {
  console.log(`No capture at ${file}. Captures aren't committed (they contain device`)
  console.log('MACs/serials). Grab one on a device on the sonar network:')
  console.log('  su 0 tcpdump -i any -n -s0 -w sonar.pcap "udp and portrange 10740-10830"')
  console.log('then: node test/parse-pcap.js sonar.pcap')
  process.exit(0)
}
const sources = new Map()
let dataCount = 0; const seqs = new Set(); let sample

for (const { src, dport, payload } of udpPackets(file)) {
  if (dport === proto.HEARTBEAT_PORT) {
    const hb = proto.parseHeartbeat(payload, { address: src })
    if (hb) sources.set(src, hb)
  } else if (dport === proto.DATA_PORT) {
    const d = proto.parseData(payload)
    if (d && d.kind === 'data') {
      dataCount++; seqs.add(d.pingSeq); sample = d
    }
  }
}

console.log('=== sources (heartbeats) ===')
for (const [src, hb] of sources) {
  console.log(`  ${src}  role 0x${hb.role.toString(16)} ${hb.isNeonSonar ? '[NEON sonar]' : hb.isSource ? '[net source]' : ''}` +
    `  name=${JSON.stringify(hb.name)} model=${JSON.stringify(hb.model)}` +
    (hb.transducer ? ` xdcr=${JSON.stringify(hb.transducer)}` : ''))
}
console.log(`\n=== data: ${dataCount} packets, ${seqs.size} distinct pings ===`)
if (sample) {
  const b = proto.estimateBottomBin(sample.samples)
  console.log(`  last ping seq=${sample.pingSeq} ch=${sample.channel} samples=${sample.sampleCount} ` +
    `rangeUpper=${sample.rangeUpper.toFixed(2)} rangeLower=${sample.rangeLower.toFixed(2)} bottomBin=${b.bin}/${sample.samples.length} amp=${b.amp}`)
}
