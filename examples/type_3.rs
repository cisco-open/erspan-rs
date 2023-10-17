// SPDX-License-Identifier: MIT
//
// Copyright 2023 Cisco Systems, Inc. and its affiliates
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use erspan::erspan_decap;

fn main() {
    let packet = "525400349b816cab051f0c740800450000ee00004000fa2f57540a000a010a000a8c100022eba387d821200000014b1cd79a000000090c00000100000ea93456fec7b8686cab051f0c740800450000b00c5440003511187cd1ce3a380a000a671cb7a4fe009cd107fef728910d03001c06c7b868000000020000000100000000000000006c0dca0cfcac602e6291bc91c4eea5894309e97f7db0cfaeabbf0615b21b4836a9bb345f4eff7c5e6af56bb44c67f720bfc53a5fccc62be2b6caef55f6c735b122c82f3e1630a7988312bebafe9f3082baee8cea429f0d103376cab0690ee95089054c262396bc19fa0b0ce1c2349ad7cb73128675b2b6ae";
    let packet_bytes = &hex::decode(packet).unwrap();
    match erspan_decap(packet_bytes) {
        Ok(gre) => {
            println!("GRE {:?} {} > {} original packet data size {} bytes",
                     gre.version, gre.source, gre.destination, gre.original_data_packet.len());

            let packet_inside = &EthernetPacket::new(&*gre.original_data_packet).unwrap();
            let payload = packet_inside.payload();
            match Ipv4Packet::new(payload) {
                Some(packet_ipv4) => {
                    println!("Original packet inside: {:?}", packet_ipv4);
                }
                _ => eprintln!("Invalid packet inside")
            }
        }
        Err(e) => {
            eprintln!("Error parsing GRE packet {:?}", e)
        }
    }
}
