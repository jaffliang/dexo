//! Minimal DNS wire codec for A / AAAA / HTTPS (SVCB) queries used by DoH.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;
pub const SVCPARAM_IPV4HINT: u16 = 4;
pub const SVCPARAM_ECH: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    pub target: String,
    pub ipv4hint: Vec<Ipv4Addr>,
    pub ech_config: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Lookup {
    pub ipv4: Vec<Ipv4Addr>,
    pub ipv6: Vec<Ipv6Addr>,
    pub https: Vec<HttpsRecord>,
}

pub fn encode_query(id: u16, name: &str, record_type: u16) -> Result<Vec<u8>, &'static str> {
    let mut message = Vec::with_capacity(64);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    message.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    message.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
    encode_name(&mut message, name)?;
    message.extend_from_slice(&record_type.to_be_bytes());
    message.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(message)
}

pub fn decode_lookup(message: &[u8], expected_id: u16) -> Result<Lookup, &'static str> {
    if message.len() < 12 {
        return Err("truncated dns header");
    }
    let id = u16::from_be_bytes([message[0], message[1]]);
    if id != expected_id {
        return Err("dns id mismatch");
    }
    let flags = u16::from_be_bytes([message[2], message[3]]);
    if flags & 0x000F != 0 {
        return Err("dns response error");
    }
    let qdcount = u16::from_be_bytes([message[4], message[5]]) as usize;
    let ancount = u16::from_be_bytes([message[6], message[7]]) as usize;
    let nscount = u16::from_be_bytes([message[8], message[9]]) as usize;
    let arcount = u16::from_be_bytes([message[10], message[11]]) as usize;
    let mut offset = 12;
    for _ in 0..qdcount {
        skip_name(message, &mut offset)?;
        offset = offset.checked_add(4).ok_or("truncated question")?;
        if offset > message.len() {
            return Err("truncated question");
        }
    }

    let mut lookup = Lookup::default();
    take_records(message, &mut offset, ancount, &mut lookup)?;
    // Authority is unused; skip so Additional HTTPS/A records are still visible.
    take_records(message, &mut offset, nscount, &mut Lookup::default())?;
    take_records(message, &mut offset, arcount, &mut lookup)?;
    Ok(lookup)
}

fn take_records(
    message: &[u8],
    offset: &mut usize,
    count: usize,
    lookup: &mut Lookup,
) -> Result<(), &'static str> {
    for _ in 0..count {
        skip_name(message, offset)?;
        if *offset + 10 > message.len() {
            return Err("truncated answer");
        }
        let record_type = u16::from_be_bytes([message[*offset], message[*offset + 1]]);
        let class = u16::from_be_bytes([message[*offset + 2], message[*offset + 3]]);
        let rdlength = u16::from_be_bytes([message[*offset + 8], message[*offset + 9]]) as usize;
        *offset += 10;
        if *offset + rdlength > message.len() {
            return Err("truncated rdata");
        }
        let rdata = &message[*offset..*offset + rdlength];
        *offset += rdlength;
        if class != CLASS_IN {
            continue;
        }
        match record_type {
            TYPE_A if rdata.len() == 4 => {
                lookup.ipv4.push(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
            }
            TYPE_AAAA if rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                lookup.ipv6.push(Ipv6Addr::from(octets));
            }
            TYPE_HTTPS => match decode_https(rdata) {
                Ok(record) => {
                    lookup.ipv4.extend(record.ipv4hint.iter().copied());
                    lookup.https.push(record);
                }
                Err(_) => {}
            },
            _ => {}
        }
    }
    Ok(())
}

fn encode_name(out: &mut Vec<u8>, name: &str) -> Result<(), &'static str> {
    let trimmed = name.trim_end_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return Err("empty dns name");
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 || !label.is_ascii() {
            return Err("invalid dns label");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    Ok(())
}

fn skip_name(message: &[u8], offset: &mut usize) -> Result<(), &'static str> {
    let mut jumps = 0;
    let mut cursor = *offset;
    let mut consumed = 0usize;
    let mut saw_pointer = false;
    loop {
        if cursor >= message.len() {
            return Err("truncated name");
        }
        let length = message[cursor];
        if length & 0xC0 == 0xC0 {
            if cursor + 1 >= message.len() {
                return Err("truncated name pointer");
            }
            if !saw_pointer {
                consumed += 2;
            }
            cursor = (((length as usize) & 0x3F) << 8) | message[cursor + 1] as usize;
            saw_pointer = true;
            jumps += 1;
            if jumps > 10 {
                return Err("name pointer loop");
            }
            continue;
        }
        if length & 0xC0 != 0 {
            return Err("invalid name length");
        }
        cursor += 1;
        if !saw_pointer {
            consumed += 1;
        }
        if length == 0 {
            break;
        }
        cursor = cursor.checked_add(length as usize).ok_or("truncated name")?;
        if !saw_pointer {
            consumed += length as usize;
        }
    }
    *offset += if saw_pointer { consumed } else { cursor.saturating_sub(*offset) };
    Ok(())
}

pub(crate) fn decode_https(rdata: &[u8]) -> Result<HttpsRecord, &'static str> {
    if rdata.len() < 3 {
        return Err("truncated https rr");
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut offset = 2;
    let target = decode_uncompressed_name(rdata, &mut offset)?;
    let mut ech_config = None;
    let mut ipv4hint = Vec::new();
    while offset + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let length = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if offset + length > rdata.len() {
            break;
        }
        let value = &rdata[offset..offset + length];
        offset += length;
        if key == SVCPARAM_ECH && ech_config.is_none() {
            ech_config = Some(value.to_vec());
        }
        if key == SVCPARAM_IPV4HINT {
            ipv4hint.extend(parse_ipv4hint(value));
        }
    }
    Ok(HttpsRecord {
        priority,
        target,
        ipv4hint,
        ech_config,
    })
}

fn parse_ipv4hint(value: &[u8]) -> Vec<Ipv4Addr> {
    value
        .chunks_exact(4)
        .map(|octets| Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]))
        .collect()
}

fn decode_uncompressed_name(data: &[u8], offset: &mut usize) -> Result<String, &'static str> {
    let mut labels = Vec::new();
    loop {
        if *offset >= data.len() {
            return Err("truncated https target");
        }
        let length = data[*offset] as usize;
        *offset += 1;
        if length == 0 {
            break;
        }
        if length > 63 || *offset + length > data.len() {
            return Err("invalid https target");
        }
        let label = std::str::from_utf8(&data[*offset..*offset + length]).map_err(|_| "https target utf8")?;
        labels.push(label.to_ascii_lowercase());
        *offset += length;
    }
    Ok(labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_query_and_answer() {
        let query = encode_query(0x1234, "linux.do", TYPE_A).unwrap();
        assert_eq!(&query[0..2], &[0x12, 0x34]);
        assert_eq!(query[query.len() - 4], 0);
        assert_eq!(&query[query.len() - 4..], &[0x00, 0x01, 0x00, 0x01]);

        let mut answer = query.clone();
        answer[2] = 0x81;
        answer[3] = 0x80;
        answer[6] = 0;
        answer[7] = 1;
        // name pointer to offset 12, type A, class IN, ttl, rdlength 4, 1.2.3.4
        answer.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3C, 0x00, 0x04, 1, 2, 3, 4]);

        let lookup = decode_lookup(&answer, 0x1234).unwrap();
        assert_eq!(lookup.ipv4, vec![Ipv4Addr::new(1, 2, 3, 4)]);
    }

    #[test]
    fn extracts_ech_config_from_https_rdata() {
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.push(0); // root target
        rdata.extend_from_slice(&SVCPARAM_ECH.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.extend_from_slice(&[0xAA, 0xBB, 0xCC]);

        let record = decode_https(&rdata).unwrap();
        assert_eq!(record.priority, 1);
        assert_eq!(record.target, "");
        assert_eq!(record.ech_config.as_deref(), Some(&[0xAA, 0xBB, 0xCC][..]));
    }

    #[test]
    fn linux_do_https_wire_keeps_ech_and_ipv4hint() {
        // Captured RFC 8484 answer for `linux.do` TYPE=HTTPS (id 0x1111).
        // Presentation: alpn=h3,h2 ipv4hint=104.20.16.234,172.66.166.61
        // ech=AEX+DQBBtQAgACASGui8…cloudflare-ech.com ipv6hint=…
        let message = hex(
            "111181800001000100000000056c696e757802646f0000410001c00c004100010000012c0088\
             0001000001000602683302683200040008681410eaac42a63d000500470045fe0d0041b50020\
             0020121ae8bca202378d31efc2e5db4cce83f4a8ed582ec5e043b69e362c42e7ab0f00040001\
             00010012636c6f7564666c6172652d6563682e636f6d00000006002026064700001000000000\
             0000681410ea260647000010000000000000ac42a63d",
        );
        let lookup = decode_lookup(&message, 0x1111).expect("linux.do HTTPS wire");
        assert_eq!(lookup.https.len(), 1, "HTTPS RR must not be dropped");
        let ech = lookup.https[0]
            .ech_config
            .as_ref()
            .expect("ECH SvcParam key 5 must be parsed");
        assert!(ech.len() > 16, "ECHConfigList too short: {}", ech.len());
        assert_eq!(&ech[..2], &[0x00, 0x45]);
        assert!(
            ech.windows(b"cloudflare-ech.com".len())
                .any(|window| window == b"cloudflare-ech.com"),
            "ECH public name missing"
        );
        assert_eq!(
            lookup.ipv4,
            vec![
                Ipv4Addr::new(104, 20, 16, 234),
                Ipv4Addr::new(172, 66, 166, 61)
            ]
        );
        assert_eq!(lookup.https[0].ipv4hint, lookup.ipv4);
    }

    #[test]
    fn rejects_mismatched_id() {
        let query = encode_query(1, "example.com", TYPE_A).unwrap();
        assert!(decode_lookup(&query, 2).is_err());
    }

    fn hex(input: &str) -> Vec<u8> {
        let compact: String = input.chars().filter(|ch| !ch.is_whitespace()).collect();
        (0..compact.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&compact[index..index + 2], 16).unwrap())
            .collect()
    }
}
