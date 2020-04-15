use chrono::Utc;
use clap::{App, Arg};
use dnsclient::sync::DNSClient;
use dnsclient::UpstreamServer;
use pnet::packet::icmp;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::{IcmpCodes, MutableEchoRequestPacket};
use pnet::packet::icmp::{IcmpPacket, IcmpTypes};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::{ipv4_packet_iter, transport_channel, TransportChannelType};
use regex::Regex;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;
use std::{process, thread};

fn main() {
    // Display CLI
    let arguments = App::new("cling (Cloudflare Latency Inspector - Networking Gui)")
        .version("1.0")
        .about("Check latency to a server")
        .author("JMS")
        .arg(
            Arg::with_name("ip_or_domain")
                .help("the IPv4 address or the domain to ping")
                .required(true)
                .validator(|value| {
                    let domain_regex =
                        Regex::new(r"^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$").unwrap();
                    if Ipv4Addr::from_str(&value).is_ok() || domain_regex.is_match(&value) {
                        Ok(())
                    } else {
                        Err("Invalid IPv4 address or domain".to_owned())
                    }
                }),
        )
        .get_matches();

    // Get the IP to ping
    let ip_or_domain = arguments.value_of("ip_or_domain").unwrap().to_owned();
    let destination_ip = {
        if let Ok(ip) = Ipv4Addr::from_str(&ip_or_domain) {
            ip
        } else {
            let cloudflare_dns_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53);
            let google1_dns_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53);
            let google2_dns_server = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53);
            let dnsclient = DNSClient::new(vec![
                UpstreamServer::new(cloudflare_dns_server),
                UpstreamServer::new(google1_dns_server),
                UpstreamServer::new(google2_dns_server),
            ]);
            println!("Looking up IP address...");
            if let Ok(mut destination_ips) = dnsclient.query_a(&ip_or_domain) {
                destination_ips.pop().unwrap()
            } else {
                println!("Could not get any IP addresses for the given domain");
                return;
            }
        }
    };

    // Setup Tx and Rx
    let protocol = TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
    if let Ok((mut tx, mut rx)) = transport_channel(1024, protocol) {
        let id = process::id() as u16;
        let running = Arc::new(AtomicBool::new(true));
        let requests_sent = Arc::new(AtomicU16::new(0));
        let replies_received = Arc::new(AtomicU16::new(0));
        let rtt_sum = Arc::new(AtomicI64::new(0));

        // Setup Ctrl+C signal handler
        let r = running.clone();
        let rs = requests_sent.clone();
        let rr = replies_received.clone();
        let rtts = rtt_sum.clone();
        ctrlc::set_handler(move || {
            r.store(false, Ordering::SeqCst);

            // Print report
            let requests_sent = rs.load(Ordering::SeqCst);
            let replies_received = rr.load(Ordering::SeqCst);
            let rtt_sum = rtts.load(Ordering::SeqCst);
            println!("\n--------------------------------------");
            println!(
                "{} packets={}: average_rtt={:.2} ms, packet_loss={:.2}%",
                ip_or_domain,
                requests_sent,
                rtt_sum as f64 / replies_received as f64,
                1.0 - (replies_received as f64 / requests_sent as f64)
            );
        })
        .expect("Could not set Ctrl+C signal handler");

        // Spawn a thread that sends echo requests in a loop
        let r = running.clone();
        let rs = requests_sent.clone();
        thread::spawn(move || {
            while r.load(Ordering::SeqCst) {
                let sqeuence_number = rs.fetch_add(1, Ordering::SeqCst) + 1;

                // Construct a packet
                let mut icmp_data = [0u8; 8 + 8]; // 8 bytes for the ICMP header, 8 bytes for the timestamp payload
                let mut icmp = MutableEchoRequestPacket::new(&mut icmp_data).unwrap();
                icmp.set_icmp_type(IcmpTypes::EchoRequest);
                icmp.set_icmp_code(IcmpCodes::NoCode);
                icmp.set_identifier(id);
                icmp.set_sequence_number(sqeuence_number);
                icmp.set_payload(&bincode::serialize(&Utc::now().timestamp_millis()).unwrap());
                icmp.set_checksum(icmp::checksum(&IcmpPacket::new(icmp.packet()).unwrap()));

                let mut packet_data = [0u8; 20 + 8 + 8]; // 20 bytes for the IPv4 header, 8 bytes for the ICMP header, 8 bytes for the timestamp payload
                let mut packet = MutableIpv4Packet::new(&mut packet_data).unwrap();
                packet.set_version(4);
                packet.set_header_length(5);
                packet.set_dscp(0);
                packet.set_ecn(0);
                packet.set_total_length(20 + 8 + 8);
                packet.set_identification(0);
                packet.set_flags(2);
                packet.set_fragment_offset(0);
                packet.set_ttl(64);
                packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
                packet.set_destination(destination_ip);
                packet.set_options(&[]);
                packet.set_payload(icmp.packet_mut());
                packet.set_checksum(ipv4::checksum(&Ipv4Packet::new(packet.packet()).unwrap()));

                // Send the packet, then sleep for 0.9 seconds
                tx.send_to(packet, IpAddr::V4(destination_ip))
                    .expect("Could not send ICMP echo request");
                thread::sleep(Duration::from_millis(900));
            }
        });

        // Spawn a thread that loops over incoming packets and print the elapsed time of any replies
        let r = running.clone();
        thread::spawn(move || {
            let mut previous_reply_sequence_number = 0;
            let mut packet_iter = ipv4_packet_iter(&mut rx);
            while r.load(Ordering::SeqCst) {
                if let Ok((packet, from_address)) = packet_iter.next() {
                    if packet.get_next_level_protocol() == IpNextHeaderProtocols::Icmp {
                        if let Some(packet) = IcmpPacket::new(packet.payload()) {
                            if packet.get_icmp_type() == IcmpTypes::EchoReply {
                                let packet = EchoReplyPacket::new(packet.packet()).unwrap();
                                if packet.get_identifier() == id {
                                    let time_sent: Result<i64, _> =
                                        bincode::deserialize(packet.payload());
                                    if let Ok(time_sent) = time_sent {
                                        let reply_missed = packet.get_sequence_number() - 1
                                            != previous_reply_sequence_number;
                                        previous_reply_sequence_number =
                                            packet.get_sequence_number();
                                        replies_received.fetch_add(1, Ordering::SeqCst);

                                        let rtt = Utc::now().timestamp_millis() - time_sent;
                                        rtt_sum.fetch_add(rtt, Ordering::SeqCst);

                                        println!(
                                            "{}: icmp_seq={} time={} ms{}",
                                            from_address,
                                            packet.get_sequence_number(),
                                            rtt,
                                            if reply_missed {
                                                " (potential packet loss)"
                                            } else {
                                                ""
                                            }
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        // Don't exit main() until Ctrl+C is pressed
        while running.load(Ordering::SeqCst) {}
    }
}
