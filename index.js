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
  const sources = new Map()   // address -> heartbeat info
  let clients = new Set()

  const plugin = {
    id: 'signalk-navico-sonar',
    name: 'Navico NEON Sonar',
    description: 'Consumes the Navico NEON sonar network protocol (echogram + depth).'
  }

  // Same-origin WebSocket path: the waterfall connects to
  //   ws(s)://<sk-host>/plugins/signalk-navico-sonar/stream
  // No separate port — TLS (wss) and access control are inherited from the SK
  // HTTP server. We attach to that server's `upgrade` event in registerWithRouter().
  const WS_PATH = '/plugins/' + plugin.id + '/stream'

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

    // --- WebSocket fan-out to the webapp (lazy require so the plugin loads even if ws missing) ---
    // noServer mode: no listen(); upgrades are routed in from the shared SK
    // HTTP server by the handler installed in registerWithRouter().
    try {
      const WebSocket = require('ws')
      wss = new WebSocket.Server({ noServer: true })
      wss.on('connection', (ws) => {
        clients.add(ws)
        ws.send(JSON.stringify({ type: 'sources', sources: [...sources.values()] }))
        ws.on('close', () => clients.delete(ws))
      })
      app.debug(`waterfall WS ready at ${WS_PATH}`)
    } catch (e) {
      app.error('ws module not available; webapp live stream disabled: ' + e.message)
    }

    const broadcast = (obj) => {
      if (!clients.size) return
      const msg = obj.type === 'ping'
        ? packPing(obj)             // binary frame for echogram (compact)
        : JSON.stringify(obj)
      for (const ws of clients) { try { ws.send(msg) } catch (_) {} }
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
      if (!prev) { app.debug(`source ${rinfo.address} ${hb.name} (${hb.model})`); broadcast({ type: 'sources', sources: [...sources.values()] }) }
    })

    bind(proto.STATUS_PORT, (buf, rinfo) => {
      const st = proto.parseStatus(buf)
      if (st) broadcast({ type: 'status', address: rinfo.address, sub: st.sub, floats: st.floats })
    })

    bind(proto.DATA_PORT, (buf, rinfo) => {
      const d = proto.parseData(buf)
      if (!d || d.kind !== 'data') return
      const src = sources.get(rinfo.address)
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

  // Mount the webapp's WebSocket on the SK server's own HTTP server (same origin,
  // same port), instead of opening a private port. WS upgrades fire at the Node
  // HTTP-server level rather than through Express, so we hook the server's
  // `upgrade` event. We grab the server from the first request that reaches our
  // router (req.socket.server), install a path-filtered handler once, and hand
  // matching upgrades to our noServer WebSocket.Server.
  plugin.registerWithRouter = function (router) {
    let installed = false
    router.use((req, _res, next) => {
      if (!installed && req.socket && req.socket.server && typeof req.socket.server.on === 'function') {
        const server = req.socket.server
        server.on('upgrade', (upReq, socket, head) => {
          let path = upReq.url
          try { path = new URL(upReq.url, 'http://x').pathname } catch (_) {}
          if (path !== WS_PATH) return // not ours — leave it for other upgrade handlers
          if (!wss) { socket.destroy(); return } // plugin stopped
          wss.handleUpgrade(upReq, socket, head, (ws) => wss.emit('connection', ws, upReq))
        })
        installed = true
        app.debug(`sonar WS upgrade mounted at ${WS_PATH}`)
      }
      next()
    })
  }

  plugin.stop = function () {
    for (const s of sockets) { try { s.close() } catch (_) {} }
    sockets = []
    if (wss) { try { wss.close() } catch (_) {} wss = null }
    clients = new Set(); sources.clear()
  }

  // compact binary frame: [0x01][channel][u32 seq][f32 rangeLower][u16 n][n bytes samples]
  function packPing (p) {
    const n = p.samples.length
    const buf = Buffer.allocUnsafe(1 + 1 + 4 + 4 + 2 + n)
    buf[0] = 0x01; buf[1] = p.channel
    buf.writeUInt32LE(p.pingSeq >>> 0, 2)
    buf.writeFloatLE(p.rangeLower || 0, 6)
    buf.writeUInt16LE(n, 10)
    p.samples.copy(buf, 12)
    return buf
  }

  return plugin
}
