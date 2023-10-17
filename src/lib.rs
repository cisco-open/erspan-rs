// SPDX-License-Identifier: MIT
//
// Copyright 2023 Cisco Systems, Inc. and its affiliates
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

use std::io::{Cursor};
use std::net::IpAddr;

use byteorder::{BigEndian, ReadBytesExt};
use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::Packet;
use thiserror::Error;

mod tests;

#[derive(Debug)]
pub struct GreHeader {
    pub version: u8,
    pub checksum_flag: bool,
    pub sequence_num_flag: bool,
    pub key_flag: bool,
    pub checksum: Option<u16>,
    pub key: Option<u32>,
    pub sequence_number: Option<u32>,
}

#[derive(Debug)]
pub struct ErspanHeader {
    pub gre_header: GreHeader,
    pub source: IpAddr,
    pub destination: IpAddr,
    pub version: ErspanType,
    pub vlan: u16,
    pub cos: u8,
    pub encap_type: u8,
    pub truncated: bool,
    pub session_id: u16,
    pub port_index: u32,
    pub security_group_tag: Option<u16>,
    pub original_data_packet: Vec<u8>,
}

#[derive(Debug, PartialEq)]
pub enum ErspanType {
    Type1 = 0,
    Type2 = 1,
    Type3 = 2,
    Unknown,
}

#[derive(Error, Debug, PartialEq)]
pub enum ErspanError {
    /// Represents an empty source. For example, an empty text file being given
    /// as input to `count_words()`.
    #[error("Unknown Ethernet packet type")]
    UnknownPacket,

    #[error("Unknown IpV4 packet type")]
    InvalidIpV4Packet,

    #[error("Unknown transport protocol, not GRE/ERSPAN")]
    InvalidTransportProtocol,

    #[error("Packet too short")]
    PacketTooShort,

    #[error("GRE protocol not containing ERSPAN")]
    InvalidGrePacketType,

    #[error("GRE with routing option not implemented yet")]
    GreWithRoutingNotImplemented,
}

pub fn erspan_decap(erspan_packet: &[u8]) -> Result<ErspanHeader, ErspanError> {
    match EthernetPacket::new(erspan_packet) {
        Some(eframe) => {
            match eframe.get_ethertype() {
                EtherTypes::Ipv4 => handle_ipv4_packet(&eframe),
                _ => Err(ErspanError::UnknownPacket)
            }
        }
        _ => Err(ErspanError::UnknownPacket)
    }
}

fn handle_ipv4_packet(ethernet: &EthernetPacket) -> Result<ErspanHeader, ErspanError> {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
        )
    } else {
        Err(ErspanError::InvalidIpV4Packet)
    }
}

fn handle_transport_protocol(
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
) -> Result<ErspanHeader, ErspanError> {
    match protocol {
        IpNextHeaderProtocols::Gre => {
            handle_gre_packet(source, destination, packet)
        }
        _ =>
            Err(ErspanError::InvalidTransportProtocol)
    }
}


pub fn handle_gre_packet(source: IpAddr, destination: IpAddr, packet: &[u8]) -> Result<ErspanHeader, ErspanError> {

    let min_gre_headers_size = 16;

    if packet.len() < min_gre_headers_size {
        return
            Err(ErspanError::PacketTooShort);
    }

    // GRE header
    let mut rdr = Cursor::new(&packet);
    let flags = rdr.read_u16::<BigEndian>().unwrap();
    let checksum_flag = (flags & 0b1000_0000_0000_0000) > 0;
    let routing_flag = (flags & 0b100_0000_0000_0000) > 0;
    let key_flag = (flags & 0b10_0000_0000_0000) > 0;
    let sequence_num_flag = (flags & 0b1_0000_0000_0000) > 0;
    let gre_version = (flags & 0b111) as u8;

    let proto_type = rdr.read_u16::<BigEndian>().unwrap();
    if proto_type != 0x88be && proto_type != 0x22EB {   // ERSPAN packet type constant
        return Err(ErspanError::InvalidGrePacketType);
    }

    let checksum = if checksum_flag {
        Some(rdr.read_u16::<BigEndian>().unwrap())
    } else {
        None
    };

    if routing_flag {
        return Err(ErspanError::GreWithRoutingNotImplemented);
    }

    let key = if key_flag {
        Some(rdr.read_u32::<BigEndian>().unwrap())
    } else {
        None
    };

    let seq = if sequence_num_flag {
        Some(rdr.read_u32::<BigEndian>().unwrap())
    } else {
        None
    };

    // start of ERSPAN header
    let version_and_vlan = rdr.read_u16::<BigEndian>().unwrap();
    let version_num = version_and_vlan >> 12;
    let mut gre_headers_size = 8 + 8;  // gre + erspan headers
    let version = match version_num {
        0 => {
            gre_headers_size = 8 + 8;  // gre + erspan headers
            ErspanType::Type1
        },
        1 => {
            gre_headers_size = 8 + 8;  // gre + erspan headers
            ErspanType::Type2
        },
        2 => {
            gre_headers_size = 8 + 12;  // gre + erspan headers
            ErspanType::Type3
        },
        _ => ErspanType::Unknown
    };
    let vlan = version_and_vlan & 0x0FFF;

    let gre_header_rest = rdr.read_u16::<BigEndian>().unwrap();
    let cos = (gre_header_rest >> 13) as u8;  // & 0b1110_0000_0000_0000;
    let encap_type = (gre_header_rest >> 11) as u8;   // & 0b0001_1000_0000_0000;
    let truncated = (gre_header_rest  >> 10) == 1; // & 0b0000_0100_0000_0000) > 0;
    let session_id = gre_header_rest & 0b0000_0011_1111_1111;

    let gre_header_rest2 = rdr.read_u64::<BigEndian>().unwrap();
    let port_index = (gre_header_rest2 & 0b0000_0000_0000_1111_1111_1111_1111_1111) as u32;

    let mut security_group_tag = None;
    if proto_type == 0x22EB {   // type III additional params
        let _timestamp = rdr.read_u32::<BigEndian>().unwrap();
        security_group_tag = Some(rdr.read_u16::<BigEndian>().unwrap());

        let second_flags = rdr.read_u16::<BigEndian>().unwrap();

        let optional_subheader_present = second_flags & 0b1;

        if optional_subheader_present == 1 {
            gre_headers_size = gre_headers_size + 8;
            let _platform_spec_info = rdr.read_u32::<BigEndian>().unwrap();
            let _upper_timestamp = rdr.read_u32::<BigEndian>().unwrap();  // TODO process timestamp
        }
    }

    let (_, data) = packet.split_at(gre_headers_size);
    let buf = Vec::from(data);

    // TODO other flags

    Ok(ErspanHeader {
        gre_header: GreHeader {
            version: gre_version,
            checksum_flag,
            sequence_num_flag,
            key_flag,
            checksum,
            key,
            sequence_number: seq
        },
        source,
        destination,
        version,
        vlan,
        cos,
        encap_type,
        truncated,
        session_id,
        port_index,
        security_group_tag,
        original_data_packet: buf,
    })
}
