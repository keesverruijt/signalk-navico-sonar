Packet captures are intentionally not committed (they contain device MACs,
serials, and network layout). Capture your own on a device on the sonar network:

  su 0 tcpdump -i any -n -s0 -w sonar.pcap "udp and portrange 10740-10830"

then: node test/parse-pcap.js sonar.pcap
