// SPDX-License-Identifier: MIT
//
// Copyright 2023 Cisco Systems, Inc. and its affiliates
//
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT.

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::str::FromStr;

    use pnet::packet::ethernet::{EthernetPacket, EtherTypes};
    use pnet::util::MacAddr;

    use crate::{erspan_decap, ErspanError, ErspanType};

    #[test]
    fn erspan_decap_packet() {
        let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
        let packet_bytes = &hex::decode(packet).unwrap();
        let original_packet = match erspan_decap(packet_bytes) {
            Ok(result) => {
                assert_eq!(result.version, ErspanType::Type2);
                assert_eq!(result.vlan, 1);
                assert_eq!(result.gre_header.version, 0);
                assert_eq!(result.gre_header.checksum_flag, false);
                assert_eq!(result.gre_header.key_flag, false);
                assert_eq!(result.gre_header.sequence_num_flag, true);
                assert_eq!(result.original_data_packet.len() > 0, true);
                assert_eq!(result.gre_header.sequence_number.unwrap(), 2114488375);
                assert_eq!(result.gre_header.checksum, None);
                assert_eq!(result.gre_header.key, None);
                assert_eq!(result.source, IpAddr::from_str("10.0.10.1").unwrap());
                assert_eq!(result.destination, IpAddr::from_str("10.0.10.133").unwrap());
                assert_eq!(result.cos, 0);
                assert_eq!(result.encap_type, 0);
                assert_eq!(result.truncated, false);
                assert_eq!(result.session_id, 1);
                assert_eq!(result.port_index, 1);
                assert_eq!(result.security_group_tag, None);
                result.original_data_packet
            }
            Err(e) => panic!("{}", e)
        };

        assert_eq!(original_packet.len(), 55);
        let eframe = &EthernetPacket::new(original_packet.as_slice()).unwrap();
        assert_eq!(eframe.get_ethertype(), EtherTypes::Ipv4);
        assert_eq!(eframe.get_source(), MacAddr::from_str("6c:ab:05:1f:0c:74").unwrap());
        assert_eq!(eframe.get_destination(), MacAddr::from_str("54:b2:03:07:ee:ed").unwrap());
    }

    #[test]
    fn erspan_typ3_decap_packet() {
        let packet = "525400349b816cab051f0c740800450000ee00004000fa2f57540a000a010a000a8c100022eba387d821200000014b1cd79a000000090c00000100000ea93456fec7b8686cab051f0c740800450000b00c5440003511187cd1ce3a380a000a671cb7a4fe009cd107fef728910d03001c06c7b868000000020000000100000000000000006c0dca0cfcac602e6291bc91c4eea5894309e97f7db0cfaeabbf0615b21b4836a9bb345f4eff7c5e6af56bb44c67f720bfc53a5fccc62be2b6caef55f6c735b122c82f3e1630a7988312bebafe9f3082baee8cea429f0d103376cab0690ee95089054c262396bc19fa0b0ce1c2349ad7cb73128675b2b6ae";
        let packet_bytes = &hex::decode(packet).unwrap();
        let original_packet = match erspan_decap(packet_bytes) {
            Ok(result) => {
                assert_eq!(result.version, ErspanType::Type3);
                assert_eq!(result.vlan, 0);
                assert_eq!(result.gre_header.version, 0);
                assert_eq!(result.gre_header.checksum_flag, false);
                assert_eq!(result.gre_header.key_flag, false);
                assert_eq!(result.gre_header.sequence_num_flag, true);
                assert!(result.original_data_packet.len() < packet_bytes.len() - 16);
                assert_eq!(result.gre_header.sequence_number.unwrap(), 2743588897);
                assert_eq!(result.gre_header.checksum, None);
                assert_eq!(result.gre_header.key, None);
                assert_eq!(result.source, IpAddr::from_str("10.0.10.1").unwrap());
                assert_eq!(result.destination, IpAddr::from_str("10.0.10.140").unwrap());
                assert_eq!(result.cos, 0);
                assert_eq!(result.encap_type, 0);
                assert_eq!(result.truncated, false);
                assert_eq!(result.session_id, 1);
                assert_eq!(result.security_group_tag, Some(0));
                result.original_data_packet
            }
            Err(e) => panic!("{}", e)
        };

        assert_eq!(original_packet.len(), 190);
        let eframe = &EthernetPacket::new(original_packet.as_slice()).unwrap();
        assert_eq!(eframe.get_ethertype(), EtherTypes::Ipv4);
        assert_eq!(eframe.get_source(), MacAddr::from_str("6c:ab:05:1f:0c:74").unwrap());
        assert_eq!(eframe.get_destination(), MacAddr::from_str("34:56:fe:c7:b8:68").unwrap());
    }

    #[test]
    fn erspan_decap_packet_failure1() {
        let packet = "52";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(_result) => panic!("Unexpected end"),
            Err(e) => assert_eq!(e, ErspanError::UnknownPacket)
        }
    }

    #[test]
    fn erspan_decap_packet_no_erspan() {
        let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100089be7e088837100100010000000054b20307eeed6cab051f0c74080045000029250e000039116cb059bb82400a000a0b2703e1f60015fab0ee1c108eee4ece4a36cd840096";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(_result) => panic!("Unexpected end"),
            Err(e) => assert_eq!(e, ErspanError::InvalidGrePacketType)
        }
    }

    #[test]
    fn erspan_decap_packet_too_short() {
        let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a85100088be7e08883710010001";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(_result) => panic!("Unexpected end"),
            Err(e) => assert_eq!(e, ErspanError::PacketTooShort)
        }
    }

    #[test]
    fn erspan_decap_packet_invalid_ipv4() {
        let packet = "52540072a57f6cab051f0c7408004500005b00004000fa2f57ee0a000a010a000a";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(_result) => panic!("Unexpected end"),
            Err(e) => assert_eq!(e, ErspanError::InvalidIpV4Packet)
        }
    }

    #[test]
    fn erspan_decap_packet_invalid_ipv4_x() {
        let packet = "9801a7a0c751525400349b810800451000b0398f40004006d8030a000a8c0a000a1a0016e4fe28aa45f22318fe3b801801f5294800000101080adf7040c64ef704c0380dc7040b31e56e14329632a5da156d35a71647065331762f829479e270f9dc39998316313d0262d30cb459d165a7f28043d23edbaee8a0837744963dc1dc8920ac028a021e1d51ae99d5a873fb287215f7f2a18065e9919417da786cf05b65d2a4f43c9113ddde9df355c3630b3ff31a90f1588531c8a7d3ef636b";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(_result) =>
                panic!("Unexpected end"),
            Err(e) => assert_eq!(e, ErspanError::InvalidTransportProtocol)
        }
    }

    #[test]
    fn erspan_from_web() {
        let packet = "6400f1e201126400f1e2010108004500009600004000fe2f76330202020201010101100088be0000070410170864000000006400f1e103036400f1e1020208004500006408940000ff0185001700000217000003080057b5001600000000000000a825d7abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(erspan) => {
                assert_eq!(erspan.version, ErspanType::Type2);
                assert_eq!(erspan.source, IpAddr::from_str("2.2.2.2").unwrap());
                assert_eq!(erspan.destination, IpAddr::from_str("1.1.1.1").unwrap());
            }
            Err(_e) => {
                panic!("Unexpected end")
            }
        }
    }

    #[test]
    fn erspan_from_fs() {
        let packet = "a0369fc7a3cd3cfdfeca59610800450000b229eb4000fe2fc8030a0021260a005508100088be106d3901100100010001005400778dce1d9500778dce1efd080045000080b8c340002006acfb0a4bdc963040dd97a10501bb22b9104c384e4e998018ffff322800000101080a02cd2ece02cd2c4616030300470100004303035d27a980b86ef5493858f553b853f54c384ef5d2b86ef5d4b86ef5dfb86ef601000004000400ff01000016000d0012001005030403020301030501040102010101";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(erspan) => {
                assert_eq!(erspan.version, ErspanType::Type2);
                assert_eq!(erspan.source, IpAddr::from_str("10.0.33.38").unwrap());
                assert_eq!(erspan.destination, IpAddr::from_str("10.0.85.8").unwrap());
                assert_eq!(erspan.original_data_packet.len(), 142);
            }
            Err(_e) => {
                panic!("Unexpected end")
            }
        }
    }

    #[test]
    fn erspan_from_fs_v6() {
        let packet = "a0369fc7a3cd3cfdfeca596108004500007a28ce4000fe2fc9580a0021260a005508100088be1b9e3e77100100010001005400778dce1d9500778dce1efd86dd60000000002006400000000000000000000000000a52efdd0000000000000000000000003047f0e02c5c01bbe861cea5f67b003780101001ddca00000101080a0d8e92af9b545636";
        let packet_bytes = &hex::decode(packet).unwrap();
        match erspan_decap(packet_bytes) {
            Ok(erspan) => {
                assert_eq!(erspan.version, ErspanType::Type2);
                assert_eq!(erspan.source, IpAddr::from_str("10.0.33.38").unwrap());
                assert_eq!(erspan.destination, IpAddr::from_str("10.0.85.8").unwrap());
                assert_eq!(erspan.original_data_packet.len(), 86);
            }
            Err(_e) => {
                panic!("Unexpected end")
            }
        }
    }

    #[test]
    fn erspan_v6() {
        let packet = "a0cec81537e95254002e678586dd600dde7b00df3c4020000000000000000000000000000050200000000000000000000000000000402f00040104010100100022eb0000000f200000653e1b352a000080003333000000fbf64b1f2b2f7e86dd600dde7b008d11fffe80000000000000f44b1ffffe2b2f7eff0200000000000000000000000000fb14e914e9008de6ef000084000000000400000000095f7365727669636573075f646e732d7364045f756470056c6f63616c00000c00010000119400140c5f6465766963652d696e666f045f746370c023045f736d62c041000c0001000011940009065542554e5455c048c00c000c0001000011940002c048c034000c0001000011940009065542554e5455c034";
        let packet_bytes = &hex::decode(packet).unwrap();
        let original_packet = match erspan_decap(packet_bytes) {
            Ok(erspan) => {
                assert_eq!(erspan.version, ErspanType::Type3);
                assert_eq!(erspan.source, IpAddr::from_str("2000::50").unwrap());
                assert_eq!(erspan.destination, IpAddr::from_str("2000::40").unwrap());
                assert_eq!(erspan.session_id, 101);
                assert_eq!(erspan.original_data_packet.len(), 195);
                erspan.original_data_packet
            }
            Err(e) => {
                panic!("Unexpected end {:?}", e)
            }
        };

        // validates original packet content
        assert_eq!(original_packet.len(), 195);
        let eframe = &EthernetPacket::new(original_packet.as_slice()).unwrap();
        assert_eq!(eframe.get_ethertype(), EtherTypes::Ipv6);
        assert_eq!(eframe.get_source(), MacAddr::from_str("f6:4b:1f:2b:2f:7e").unwrap());
        assert_eq!(eframe.get_destination(), MacAddr::from_str("33:33:00:00:00:fb").unwrap());
    }
}
