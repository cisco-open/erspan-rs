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
    let packet = "bcd0744b920d5254002e67850800450001ec5be24000022ff1ee0a000a8c0a000a87100022eb000023352000000ad0a4fd6d0000800001005e7ffffa525400cf4ec80800450001b652b90000021160830a000a01effffffa6360076c01a230844e4f54494659202a20485454502f312e310d0a484f53543a203233392e3235352e3235352e3235303a313930300d0a43414348452d434f4e54524f4c3a206d61782d6167653d36300d0a4c4f434154494f4e3a20687474703a2f2f31302e302e31302e313a323138392f726f6f74446573632e786d6c0d0a5345525645523a20467265654253442f31342e302d43555252454e542055506e502f312e31204d696e6955506e50642f322e322e310d0a4e543a20757569643a32653232646136622d316234352d353766312d663466352d30343336393561303662370d0a55534e3a20757569643a32653232646136622d316234352d353766312d663466352d30343336393561303662370d0a4e54533a20737364703a616c6976650d0a4f50543a2022687474703a2f2f736368656d61732e75706e702e6f72672f75706e702f312f302f223b206e733d30310d0a30312d4e4c533a20313639373238363736300d0a424f4f5449442e55504e502e4f52473a20313639373238363736300d0a434f4e46494749442e55504e502e4f52473a20313333370d0a0d0a";
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
