use std::env::args;
use std::fs::File;
use std::process::exit;

use pcap_file::pcap::PcapReader;
use pnet::packet::Packet;

use erspan::{erspan_decap, ErspanError};

fn main() {
    let filename_opt = args().nth(1);
    if None == filename_opt {
        println!("Usage: cargo run --example pcap <filename.pcap>");
        exit(1);
    }

    let file = File::open(args().nth(1).unwrap()).expect("File not found");
    let mut pcap_reader = PcapReader::new(file).expect("Invalid pcap file");

    let mut erspan_packets = 0;
    let mut other_packets = 0;
    let mut errors = 0;

    while let Some(packet_maybe) = pcap_reader.next_packet() {
        match packet_maybe {
            Ok(packet) => {
                match erspan_decap(&*packet.data) {
                    Ok(_parsed_erspan) => {
                        erspan_packets += 1;
                    }
                    Err(ErspanError::UnknownPacket) => {
                        other_packets += 1;
                    }
                    Err(_e) => {
                        errors += 1;
                    }
                }
            }
            Err(_e) => {
                errors += 1;
            }
        }
    }
    println!("Packets types: ERSPAN {}, other {}, errors {}", erspan_packets, other_packets, errors);
}
