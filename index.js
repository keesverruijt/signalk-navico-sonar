'use strict'
const dgram = require('dgram')
const proto = require('./lib/protocol')

// Signal K node-server plugin.
// - Binds the Navico sonar UDP ports and parses heartbeats / echogram data.
// - Emits Signal K depth deltas (best-effort bottom pick, calibratable).
// - Streams parsed pings to the bundled webapp over a WebSocket for a live waterfall.
module.exports = function (app) {
  let sockets = []
  let wss = null
  let upgradeHandler = null   // only set on the app.server fallback path
  const sources = new Map()   // address -> heartbeat info
  const lastData = new Map()  // address -> ms timestamp of last echogram packet
  let clients = new Set()
  let lastSourcesSig = ''
  const DATA_TTL_MS = 15000   // a source is "active" if it sent data this recently

  // A source is worth listing when it has a real transducer OR is currently
  // producing echogram data. Bare role-0x18 announcers (e.g. an MFD with no
  // transducer, empty xdcr, no data) are marked inactive so the UI can hide them.
  const sourceList = () => {
    const now = Date.now()
    return [...sources.entries()].map(([addr, hb]) => {
      const td = hb.transducer && hb.transducer !== 'Unknown' ? hb.transducer : ''
      const hasData = now - (lastData.get(addr) || 0) < DATA_TTL_MS
      return Object.assign({}, hb, { hasData, active: !!td || hasData })
    })
  }

  const plugin = {
    id: 'signalk-navico-sonar',
    name: 'Navico NEON Sonar',
    description: 'Consumes the Navico NEON sonar network protocol (echogram + depth).'
  }

  // Same-origin WebSocket: the waterfall connects to
  //   ws(s)://<sk-host>/plugins/signalk-navico-sonar/stream
  // No separate port — TLS (wss) and access control are inherited from the SK
  // HTTP server. Preferred path is app.registerWebSocket('/stream'); older
  // servers fall back to hooking app.server's `upgrade` event directly.
  const WS_SUBPATH = '/stream'
  const WS_PATH = '/plugins/' + plugin.id + WS_SUBPATH

  const onWsConnection = (ws) => {
    clients.add(ws)
    try { ws.send(JSON.stringify({ type: 'sources', sources: sourceList() })) } catch (_) {}
    ws.on('close', () => clients.delete(ws))
    ws.on('error', () => clients.delete(ws))
  }

  plugin.schema = {
    type: 'object',
    properties: {
      emitDepth: { type: 'boolean', title: 'Emit environment.depth.belowTransducer from bottom pick', default: true },
      preferSource: { type: 'string', title: 'Preferred source name (e.g. "kiel2"); blank = first NEON sonar', default: '' },
      nearFieldSkip: { type: 'number', title: 'Bins to skip for bottom detection (near-field ring)', default: 20 }
    }
  }

  plugin.start = function (options) {
    const opts = Object.assign({ emitDepth: true, preferSource: '', nearFieldSkip: 20 }, options)

    // --- WebSocket fan-out to the webapp, same-origin on the SK HTTP server ---
    try {
      if (typeof app.registerWebSocket === 'function') {
        // Official API: endpoint at /plugins/<id>/stream, auto-removed on stop.
        wss = app.registerWebSocket(WS_SUBPATH)
        wss.on('connection', onWsConnection)
        app.debug(`waterfall WS at ${WS_PATH} (registerWebSocket)`)
      } else if (app.server && typeof app.server.on === 'function') {
        // Fallback for older SK servers without registerWebSocket: hook the
        // shared HTTP server's upgrade event ourselves (path-filtered).
        const WebSocket = require('ws')
        wss = new WebSocket.Server({ noServer: true })
        wss.on('connection', onWsConnection)
        upgradeHandler = (req, socket, head) => {
          let path = req.url
          try { path = new URL(req.url, 'http://x').pathname } catch (_) {}
          if (path !== WS_PATH) return // not ours — leave it for other handlers
          if (!wss) { socket.destroy(); return }
          wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req))
        }
        app.server.on('upgrade', upgradeHandler)
        app.debug(`waterfall WS at ${WS_PATH} (app.server fallback)`)
      } else {
        app.error('no registerWebSocket and no app.server; webapp live stream disabled')
      }
    } catch (e) {
      app.error('webapp live stream disabled: ' + e.message)
    }

    const broadcast = (obj) => {
      if (!clients.size) return
      const msg = obj.type === 'ping'
        ? packPing(obj)             // binary frame for echogram (compact)
        : JSON.stringify(obj)
      for (const ws of clients) { try { ws.send(msg) } catch (_) {} }
    }

    // Re-send the source list to clients only when the set of *active* sources
    // changes (a source appears, starts producing data, or goes stale), so the
    // dropdown reflects reality without spamming.
    const maybeBroadcastSources = () => {
      const list = sourceList()
      const sig = list.map(s => s.address + ':' + (s.active ? 1 : 0)).join(',')
      if (sig !== lastSourcesSig) { lastSourcesSig = sig; broadcast({ type: 'sources', sources: list }) }
    }

    const bind = (port, handler) => {
      const s = dgram.createSocket({ type: 'udp4', reuseAddr: true })
      s.on('message', (buf, rinfo) => { try { handler(buf, rinfo) } catch (e) { app.debug('parse err ' + e.message) } })
      s.on('error', (e) => app.error(`udp ${port}: ${e.message}`))
      s.bind(port, () => { try { s.setBroadcast(true) } catch (_) {} })
      sockets.push(s)
    }

    bind(proto.HEARTBEAT_PORT, (buf, rinfo) => {
      const hb = proto.parseHeartbeat(buf, rinfo)
      if (!hb) return
      const prev = sources.get(rinfo.address)
      sources.set(rinfo.address, hb)
      if (!prev) app.debug(`source ${rinfo.address} ${hb.name} (${hb.model})`)
      maybeBroadcastSources() // catches new sources and sources going stale
    })

    bind(proto.STATUS_PORT, (buf, rinfo) => {
      const st = proto.parseStatus(buf)
      if (st) broadcast({ type: 'status', address: rinfo.address, sub: st.sub, floats: st.floats })
    })

    bind(proto.DATA_PORT, (buf, rinfo) => {
      const d = proto.parseData(buf)
      if (!d || d.kind !== 'data') return
      const src = sources.get(rinfo.address)
      // mark this source as live; announce if it just became active
      const prevTs = lastData.get(rinfo.address) || 0
      lastData.set(rinfo.address, Date.now())
      if (Date.now() - prevTs > DATA_TTL_MS) maybeBroadcastSources()
      // filter to the chosen source (or all if none chosen)
      if (opts.preferSource && (!src || src.name !== opts.preferSource)) return
      broadcast({ type: 'ping', address: rinfo.address, channel: d.channel, pingSeq: d.pingSeq,
        rangeUpper: d.rangeUpper, rangeLower: d.rangeLower, samples: d.samples })

      if (opts.emitDepth && d.channel === 0x02) {
        const b = proto.estimateBottomBin(d.samples, opts.nearFieldSkip)
        if (b.bin > 0 && d.rangeLower > 0) {
          const depth = (b.bin / d.samples.length) * d.rangeLower
          app.handleMessage(plugin.id, {
            updates: [{ source: { label: plugin.id + ':' + (src ? src.name : rinfo.address) },
              values: [{ path: 'environment.depth.belowTransducer', value: depth }] }]
          })
        }
      }
    })

    app.setPluginStatus('Listening for Navico sonar on UDP 10752/10753/10754')
  }

  plugin.stop = function () {
    for (const s of sockets) { try { s.close() } catch (_) {} }
    sockets = []
    if (upgradeHandler && app.server) { try { app.server.removeListener('upgrade', upgradeHandler) } catch (_) {} }
    upgradeHandler = null
    // registerWebSocket endpoints are removed by the server on stop; closing the
    // WSS here just drops any open clients. (Harmless on the fallback path too.)
    if (wss) { try { wss.close() } catch (_) {} wss = null }
    clients = new Set(); sources.clear()
  }

  // compact binary frame:
  //   [0x01][channel][u32 seq][f32 rangeLower][u16 n][4B src IPv4][n bytes samples]
  // The source IPv4 lets the webapp filter the waterfall to one source.
  function packPing (p) {
    const n = p.samples.length
    const buf = Buffer.allocUnsafe(1 + 1 + 4 + 4 + 2 + 4 + n)
    buf[0] = 0x01; buf[1] = p.channel
    buf.writeUInt32LE(p.pingSeq >>> 0, 2)
    buf.writeFloatLE(p.rangeLower || 0, 6)
    buf.writeUInt16LE(n, 10)
    const oct = String(p.address || '').split('.')
    for (let i = 0; i < 4; i++) buf[12 + i] = oct.length === 4 ? (parseInt(oct[i], 10) & 0xff) : 0
    p.samples.copy(buf, 16)
    return buf
  }

  return plugin
}
