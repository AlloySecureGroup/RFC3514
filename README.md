# rfc3514: the evil bit for Scapy and tcpdump

An implementation of [RFC 3514](https://datatracker.ietf.org/doc/rfc3514/), the
"evil bit." RFC 3514 is an April Fools' Day RFC that defines a single reserved
bit in the IPv4 header: packets with evil intent are supposed to set it, so a
compliant firewall can trivially drop them.

This toolkit gives Scapy first class support for reading and setting that
bit, plus the matching tcpdump/BPF filter and a few pcap utilities.

## Wire format

Byte 6 of the IPv4 header (0-indexed from the start of the header) holds the
flags:

| bit  | mask   | meaning                        |
|------|--------|---------------------------------|
| 7    | 0x80   | evil bit (RFC 3514)             |
| 6    | 0x40   | DF (don't fragment)             |
| 5    | 0x20   | MF (more fragments)             |
| 0-4  |        | high bits of fragment offset    |

Modern Scapy already models this as an easter egg (`IP().flags` recognizes
`'evil'` as a flag name). `rfc3514.py` patches older Scapy builds that don't,
so the module works either way.

## Files

- `rfc3514.py`, the module and CLI. Import it for the `mark_evil()` /
  `is_evil()` helpers, or run it directly for the command line tools below.

## Requirements

```
pip install scapy
```

Live sniffing and sending generally need root or `CAP_NET_RAW`.

## Library usage

```python
from rfc3514 import mark_evil, is_evil
from scapy.all import IP

pkt = IP(dst="203.0.113.1")
evil_pkt = mark_evil(pkt, evil=True)

is_evil(pkt)        # False
is_evil(evil_pkt)   # True
```

## tcpdump / BPF filters

The evil bit is a plain bit test on byte 6, so no plugin is needed:

```
tcpdump -i eth0 'ip[6] & 0x80 != 0'   # evil packets only
tcpdump -i eth0 'ip[6] & 0x80 = 0'    # benign packets only
```

The same expressions work as a Scapy `sniff(filter=...)` string.

## Command line tools

Print the filters for a given interface:

```
python3 rfc3514.py filter --iface eth0
```

Scan a pcap (for example one captured with `tcpdump -w capture.pcap`) for
evil packets:

```
python3 rfc3514.py check capture.pcap
```

Rewrite the evil bit across a whole pcap:

```
python3 rfc3514.py mark in.pcap out.pcap            # sets the bit
python3 rfc3514.py mark in.pcap out.pcap --benign   # clears the bit
```

Live sniff and label each packet as it arrives (needs root):

```
sudo python3 rfc3514.py sniff --iface eth0
sudo python3 rfc3514.py sniff --iface eth0 --evil-only
```

Build one benign and one evil packet and show the raw header bytes side by
side:

```
python3 rfc3514.py demo
```

## Actually dropping evil packets at the OS level

`rfc3514.py` observes and manipulates the bit; it doesn't run as a firewall
itself. To drop evil packets outright with iptables, matching RFC 3514's
suggested behavior:

```
iptables -I INPUT -m u32 --u32 "6&0x80=0x80" -j DROP
```

## Caveat

RFC 3514 is a joke RFC. No real router, host, or attacker sets this bit in
practice, so this toolkit is for education and amusement, not an actual
security control.
