//! Minimal DNS wire codec for A / AAAA / HTTPS (SVCB) queries used by DoH.

use std::net::{Ipv4Addr, Ipv6Addr};

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;
pub const SVCPARAM_ECH: u16 = 5;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    pub target: String,
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
    let mut offset = 12;
    for _ in 0..qdcount {
        skip_name(message, &mut offset)?;
        offset = offset.checked_add(4).ok_or("truncated question")?;
        if offset > message.len() {
            return Err("truncated question");
        }
    }

    let mut lookup = Lookup::default();
    for _ in 0..ancount {
        skip_name(message, &mut offset)?;
        if offset + 10 > message.len() {
            return Err("truncated answer");
        }
        let record_type = u16::from_be_bytes([message[offset], message[offset + 1]]);
        let class = u16::from_be_bytes([message[offset + 2], message[offset + 3]]);
        let rdlength = u16::from_be_bytes([message[offset + 8], message[offset + 9]]) as usize;
        offset += 10;
        if offset + rdlength > message.len() {
            return Err("truncated rdata");
        }
        let rdata = &message[offset..offset + rdlength];
        offset += rdlength;
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
            TYPE_HTTPS => {
                if let Ok(record) = decode_https(rdata) {
                    lookup.https.push(record);
                }
            }
            _ => {}
        }
    }
    Ok(lookup)
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

fn decode_https(rdata: &[u8]) -> Result<HttpsRecord, &'static str> {
    if rdata.len() < 3 {
        return Err("truncated https rr");
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    let mut offset = 2;
    let target = decode_uncompressed_name(rdata, &mut offset)?;
    let mut ech_config = None;
    while offset + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[offset], rdata[offset + 1]]);
        let length = u16::from_be_bytes([rdata[offset + 2], rdata[offset + 3]]) as usize;
        offset += 4;
        if offset + length > rdata.len() {
            return Err("truncated svcparam");
        }
        let value = &rdata[offset..offset + length];
        offset += length;
        if key == SVCPARAM_ECH && ech_config.is_none() {
            ech_config = Some(value.to_vec());
        }
    }
    Ok(HttpsRecord {
        priority,
        target,
        ech_config,
    })
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
    fn rejects_mismatched_id() {
        let query = encode_query(1, "example.com", TYPE_A).unwrap();
        assert!(decode_lookup(&query, 2).is_err());
    }
}
