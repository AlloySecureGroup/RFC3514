#!/usr/bin/env python3
"""
rfc3514.py: RFC 3514 (the "evil bit") support for Scapy, plus the matching
tcpdump/BPF filter and a couple of pcap utilities.

RFC 3514 is an April Fools' Day RFC. It defines a single reserved bit in
the IPv4 header, the high bit of the "flags" byte, sitting right next to
DF and MF, that packets with evil intent are supposed to set. A compliant
firewall can then trivially drop anything with the bit set.

Wire format (IPv4 header byte 6, 0-indexed from the start of the header):

    bit:   7      6      5      0-4
           evil   DF     MF     high bits of fragment offset

    0x80 = evil bit  (RFC 3514: 1 means the packet carries evil intent)
    0x40 = DF
    0x20 = MF

Usage examples:

    # print the tcpdump/BPF filters
    python3 rfc3514.py filter

    # check a pcap captured with tcpdump for evil packets
    sudo tcpdump -w capture.pcap
    python3 rfc3514.py check capture.pcap

    # rewrite a pcap so every packet is marked evil (or benign)
    python3 rfc3514.py mark capture.pcap out.pcap --evil

    # live sniff and report the evil/benign status of each packet
    sudo python3 rfc3514.py sniff --iface eth0

    # build one evil and one benign packet and show the header bytes
    python3 rfc3514.py demo
"""

import argparse
import sys

from scapy.all import IP, sniff, wrpcap, rdpcap, hexdump
from scapy.fields import FlagsField

EVIL_BIT_MASK = 0x80

# RFC 3514 compliant tcpdump / BPF filter expressions.
# Byte 6 of the IP header is the flags byte; the top bit is the evil bit.
BPF_EVIL = "ip[6] & 0x80 != 0"
BPF_BENIGN = "ip[6] & 0x80 = 0"


def _ensure_evil_flag():
    """
    Make sure Scapy's IP.flags field knows about the 'evil' name, in case
    an older Scapy build does not already ship it. Recent Scapy versions
    already include this as an easter egg, so this is usually a no-op.
    """
    for i, f in enumerate(IP.fields_desc):
        if getattr(f, "name", None) == "flags":
            names = list(getattr(f, "names", []))
            if "evil" not in names:
                if names[:2] != ["MF", "DF"]:
                    names = ["MF", "DF"]
                names.append("evil")
                IP.fields_desc[i] = FlagsField("flags", 0, 3, names)
            return
    raise RuntimeError("could not find the IP 'flags' field to patch")


_ensure_evil_flag()


def mark_evil(pkt, evil=True):
    """Return a copy of an IP packet with the evil bit set or cleared."""
    pkt = pkt.copy()
    ip = pkt.getlayer(IP)
    if ip is None:
        raise ValueError("packet has no IP layer to mark")
    ip.flags.evil = bool(evil)
    if "chksum" in ip.fields:
        del ip.chksum
    return pkt


def is_evil(pkt):
    """Return True if the packet has an IP layer with the evil bit set."""
    ip = pkt.getlayer(IP)
    if ip is None:
        return False
    return bool(ip.flags.evil)


def cmd_filter(args):
    print("RFC 3514 compliant tcpdump/BPF filters:")
    print("  evil only:    tcpdump -i {} '{}'".format(args.iface, BPF_EVIL))
    print("  benign only:  tcpdump -i {} '{}'".format(args.iface, BPF_BENIGN))
    print()
    print("These also work as Scapy sniff() filter strings, e.g.:")
    print("  sniff(iface='{}', filter='{}', prn=lambda p: p.summary())".format(args.iface, BPF_EVIL))


def cmd_check(args):
    packets = rdpcap(args.pcap)
    evil_count = 0
    for i, pkt in enumerate(packets):
        if pkt.haslayer(IP) and is_evil(pkt):
            evil_count += 1
            print("packet {}: EVIL   {}".format(i, pkt.summary()))
    print()
    print("{} of {} IP packets have the evil bit set.".format(evil_count, len(packets)))


def cmd_mark(args):
    packets = rdpcap(args.pcap)
    out = []
    for pkt in packets:
        if pkt.haslayer(IP):
            out.append(mark_evil(pkt, evil=not args.benign))
        else:
            out.append(pkt)
    wrpcap(args.outfile, out)
    state = "benign" if args.benign else "evil"
    print("wrote {} packets ({}) to {}".format(len(out), state, args.outfile))


def cmd_sniff(args):
    bpf = BPF_EVIL if args.evil_only else None

    def report(pkt):
        if not pkt.haslayer(IP):
            return
        status = "EVIL" if is_evil(pkt) else "benign"
        print("[{}] {}".format(status, pkt.summary()))

    print("sniffing on {} (RFC 3514 evil-bit monitor, ctrl-c to stop)".format(args.iface))
    sniff(iface=args.iface, filter=bpf, prn=report, store=False)


def cmd_demo(args):
    benign = IP(dst="203.0.113.1")
    evil = mark_evil(IP(dst="203.0.113.1"), evil=True)

    print("benign packet, flags byte should NOT have 0x80 set:")
    hexdump(benign)
    print()
    print("evil packet, flags byte SHOULD have 0x80 set:")
    hexdump(evil)
    print()
    print("is_evil(benign) =", is_evil(benign))
    print("is_evil(evil)   =", is_evil(evil))


def main():
    parser = argparse.ArgumentParser(description="RFC 3514 (evil bit) toolkit for Scapy and tcpdump")
    sub = parser.add_subparsers(dest="command", required=True)

    p_filter = sub.add_parser("filter", help="print the tcpdump/BPF filter strings")
    p_filter.add_argument("--iface", default="eth0")
    p_filter.set_defaults(func=cmd_filter)

    p_check = sub.add_parser("check", help="scan a pcap for evil packets")
    p_check.add_argument("pcap", help="pcap file, e.g. one captured with tcpdump -w")
    p_check.set_defaults(func=cmd_check)

    p_mark = sub.add_parser("mark", help="rewrite the evil bit across a pcap")
    p_mark.add_argument("pcap")
    p_mark.add_argument("outfile")
    p_mark.add_argument("--benign", action="store_true", help="clear the bit instead of setting it")
    p_mark.set_defaults(func=cmd_mark)

    p_sniff = sub.add_parser("sniff", help="live sniff and report evil/benign status")
    p_sniff.add_argument("--iface", default="eth0")
    p_sniff.add_argument("--evil-only", action="store_true")
    p_sniff.set_defaults(func=cmd_sniff)

    p_demo = sub.add_parser("demo", help="build a benign and an evil packet and show the bytes")
    p_demo.set_defaults(func=cmd_demo)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
