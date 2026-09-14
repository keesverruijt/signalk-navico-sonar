# signalk-navico-sonar

A Signal K consumer for the **Navico NEON sonar network protocol** (reverse-engineered from
NEON 2.x traffic). It discovers network sonar sources (B&G/Simrad/Lowrance networked sonar such
as the Vulcan, and NEON MFD-hosted internal "CSM" sonar), emits Signal K **depth** deltas, and
serves a live **echogram waterfall** webapp.

> Status: v1 / experimental. The protocol was decoded from packet captures; field notes below
> are best-effort and marked where uncertain.

## The protocol (UDP, little-endian, broadcast to `255.255.255.255` and `169.254.255.255`)

| Port | Purpose |
|------|---------|
| `10752` | Heartbeat / source discovery |
| `10753` | Status / settings (ranges, frequencies) |
| `10754` | Echogram data (8-bit amplitude samples) |
| `10758` / `10768` / `10788` | Control / subscription (how an MFD drives a source) |

### 10752 heartbeat
```
[0]      0x01
[1]      role      0x15 = networked sonar (Vulcan-style),  0x18 = NEON MFD-hosted sonar
[2..34]  name0     source nickname / id     e.g. "kiel2", "vulcan7"
[34..66] name1     display model            e.g. "Zeus S 12", "Vulcan 7R"
[66..]   trailer   6-byte source MAC, serial, channel counts, two 32-byte transducer-type
                   strings (e.g. "Generic 50/200kHz", or "Unknown"), brand, sw version
```
A working internal sounder announces as **role 0x18** with its nickname and a real transducer
type. (Our reference: a Zeus S publishing `kiel2` / `Generic 50/200kHz`.)

### 10754 echogram data
```
[0]      0x28
[1]      channel   0x02 conventional, 0x03 downscan, 0x04 sidescan (forward/structure vary)
[4..6]   u16 headerLen (samples start here; observed 29)
[6..8]   u16 sampleCount (e.g. 1400)
[8..12]  u32 pingSeq
[12..16] f32 rangeUpper (~5.0, ~constant)
[16..20] f32 rangeLower (drifts per-ping; treat as depth/auto-range — CALIBRATE vs N2K depth)
[headerLen .. +sampleCount]  u8 amplitude per range bin (0 = beyond range/bottom)
```

### 10758 control (not required for a read-only consumer)
`01 00 00 00 1c 00 .. <ip> ..` fixed-size records carrying subscriber IPs — this is how e.g. the
SRX subscribes to / controls a source. Documented for a future publisher/bridge.

## What the plugin does
- Binds `10752/10753/10754`, parses them (`lib/protocol.js`).
- Emits `environment.depth.belowTransducer` from a bottom pick on the conventional channel
  (best-effort; calibratable via options).
- Streams parsed pings to the webapp over a **same-origin WebSocket** at
  `/plugins/signalk-navico-sonar/stream` (no private port — it rides the Signal K HTTP server, so it
  inherits `wss://` TLS and access control) as a compact binary frame; the webapp renders a scrolling
  waterfall on a `<canvas>`.

## Install (on your Signal K server)
```
cd ~/.signalk/node_modules   # or your SK plugin dir
git clone <this> signalk-navico-sonar && cd signalk-navico-sonar && npm install
# enable "Navico NEON Sonar" in the SK admin UI (Server → Plugin Config)
```
Webapp: `http://<sk-server>:3000/signalk-navico-sonar/`. It connects back to the plugin over a
same-origin WebSocket automatically (`ws://` or `wss://` to match the page), so it works remotely /
behind a reverse proxy with no extra port. For offline dev you can open `public/index.html`
standalone and point it elsewhere with `?ws=<port>` or `?ws=ws://host:port`.

## Develop / test offline (no hardware)
```
npm test                                             # parse a captured pcap through the parser
node tools/render-pcap-png.js test/fixtures/zeuss_conventional.pcap out.png 169.254.226.203
node tools/replay-pcap.js test/fixtures/zeuss_conventional.pcap --loop   # re-broadcast capture as live UDP
```
Packet captures are **not committed** (they contain device MACs, serials, and network layout).
Capture your own on any device on the sonar network:
```
su 0 tcpdump -i any -n -s0 -w sonar.pcap "udp and portrange 10740-10830"
node test/parse-pcap.js sonar.pcap
```

## Performance / Rust-WASM
Data rate is modest (~100 pkts/s, ~140 KB/s), so Node parsing and JS/canvas rendering are fine
for v1. If the browser waterfall needs more headroom (many channels, high ping rates, phones),
the natural Rust‑WASM slot is the **column decode + palette → RGBA** step in `public/` (replace
`drawColumn`'s inner loop with a WASM function writing directly into an `ImageData` buffer).
Parsing can stay in Node.

## Roadmap
- Calibrate `rangeLower` → true depth against N2K PGN 128267.
- Downscan/sidescan channel views; multi-source tabs.
- Optional **publisher** mode (role-0x18 heartbeat + 10754 stream) to re-expose any source —
  e.g. bridge an internal sounder that isn't announcing, once a data source is available.
