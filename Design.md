


BlockWorks IPStack Design
=========================
- Driven from bottom, up. why? external device & event driven.
- Static.
- Streaming.
- Low RAM usage.
- Instant startup.
- Low power usage.
- Completely decoupled.
- Build-time configuration.
- Reduce the moving parts.

Layering
========

Application/HTTP
TCP/UDP
IPv4/ARP
PCAP/TUN


Use cases
=========
- Simple client, IoT style, no need ofr bridge, smallest devices can talk high-level protocols.
- Instant-on very low-power simple webserver.
- Extremely RAM-limited application; e.g. MSP430 attached to ethernet PHY.


Notes
=====
- Could use gperf to generate perfect hashing table for mapping app<->port, etc.


