'use strict'
// Replay a captured pcap as live UDP broadcasts on the local network, so the
// plugin + webapp can be exercised offline (no sonar hardware needed).
//   node tools/replay-pcap.js test/fixtures/zeuss_conventional.pcap [--loop] [--speed=1] [--bcast=127.0.0.1]
const fs = require('fs')
const dgram = require('dgram')

const args = process.argv.slice(2)
const file = args.find(a => !a.startsWith('--')) || 'test/fixtures/zeuss_conventional.pcap'
const loop = args.includes('--loop')
const speed = parseFloat((args.find(a => a.startsWith('--speed=')) || '=1').split('=')[1]) || 1
const bcast = (args.find(a => a.startsWith('--bcast=')) || '=255.255.255.255').split('=')[1]

const d = fs.readFileSync(file)
const l2 = d.readUInt32LE(20) === 113 ? 16 : 14
const pkts = []
let off = 24
while (off + 16 <= d.length) {
  const tsSec = d.readUInt32LE(off); const tsUsec = d.readUInt32LE(off + 4)
  const cap = d.readUInt32LE(off + 8); off += 16
  const ip = d.subarray(off + l2, off + cap); off += cap
  if (ip.length < 20 || (ip[0] >> 4) !== 4 || ip[9] !== 17) continue
  const ihl = (ip[0] & 0xf) * 4
  const u = ip.subarray(ihl)
  const dport = u.readUInt16BE(2)
  const ulen = u.readUInt16BE(4)
  pkts.push({ t: tsSec + tsUsec / 1e6, dport, payload: Buffer.from(u.subarray(8, 8 + ulen - 8)) })
}
console.log(`replaying ${pkts.length} udp packets from ${file} -> ${bcast} (speed ${speed}x)`)

const sock = dgram.createSocket('udp4')
sock.bind(() => sock.setBroadcast(true))

async function run () {
  do {
    const t0 = pkts[0].t; const start = Date.now()
    for (const p of pkts) {
      const due = (p.t - t0) * 1000 / speed
      const wait = due - (Date.now() - start)
      if (wait > 1) await new Promise(r => setTimeout(r, wait))
      sock.send(p.payload, p.dport, bcast)
    }
  } while (loop)
  sock.close()
}
run()
