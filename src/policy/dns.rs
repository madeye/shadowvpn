//! Minimal DNS wire parsing — just enough for policy routing.
//!
//! The proxy only needs two things from a DNS message: the queried name (to
//! decide which upstream to use) and the IPv4 addresses in an answer (to add to
//! the ipset). It never builds messages — queries and responses are relayed
//! verbatim between the stub resolver and the upstreams — so this module is
//! read-only and deliberately tiny. It is not a general-purpose DNS library.
//!
//! Both helpers are total: any malformed input yields `None` / an empty vector
//! rather than panicking.

use std::net::Ipv4Addr;

/// Fixed DNS header length in bytes.
const HEADER_LEN: usize = 12;
/// RR TYPE for an IPv4 address record (`A`).
const TYPE_A: u16 = 1;
/// RR CLASS for the Internet (`IN`).
const CLASS_IN: u16 = 1;

/// Build a standard recursive `A`/`IN` query for `name` with transaction id
/// `id`. Used to pre-warm the cache; labels longer than 63 bytes are skipped.
pub fn build_query(id: u16, name: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(name.len() + 18);
    m.extend_from_slice(&id.to_be_bytes());
    m.extend_from_slice(&[0x01, 0x00]); // flags: RD (recursion desired)
    m.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    m.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR = 0
    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            continue;
        }
        m.push(label.len() as u8);
        m.extend_from_slice(label.as_bytes());
    }
    m.push(0); // root label
    m.extend_from_slice(&TYPE_A.to_be_bytes());
    m.extend_from_slice(&CLASS_IN.to_be_bytes());
    m
}

/// Extract the (lower-cased, dot-joined) name from the first question of a DNS
/// message, or `None` if there is no question or the message is malformed.
///
/// Question names do not use compression, so this reads plain labels.
pub fn question_name(msg: &[u8]) -> Option<String> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let (name, _) = read_name(msg, HEADER_LEN)?;
    Some(name)
}

/// Extract the first question as `(name, qtype, qclass)` — the natural cache
/// key for a query. Returns `None` if there is no question or it is malformed.
pub fn question(msg: &[u8]) -> Option<(String, u16, u16)> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return None;
    }
    let (name, pos) = read_name(msg, HEADER_LEN)?;
    if pos + 4 > msg.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
    let qclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
    Some((name, qtype, qclass))
}

/// The smallest TTL across the answer section, or `None` if there are no
/// answer records (used to bound how long a response may be cached).
pub fn min_ttl(msg: &[u8]) -> Option<u32> {
    if msg.len() < HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = HEADER_LEN;
    for _ in 0..qdcount {
        pos = skip_name(msg, pos)?;
        pos += 4;
        if pos > msg.len() {
            return None;
        }
    }

    let mut min: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_name(msg, pos)?;
        if pos + 10 > msg.len() {
            break;
        }
        let ttl = u32::from_be_bytes([msg[pos + 4], msg[pos + 5], msg[pos + 6], msg[pos + 7]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10 + rdlength;
        min = Some(min.map_or(ttl, |m| m.min(ttl)));
    }
    min
}

/// Extract every IPv4 address from the answer section of a DNS response.
///
/// Returns an empty vector for a query, an answer with no `A` records, or any
/// malformed message.
pub fn a_records(msg: &[u8]) -> Vec<Ipv4Addr> {
    let mut out = Vec::new();
    if msg.len() < HEADER_LEN {
        return out;
    }
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    let ancount = u16::from_be_bytes([msg[6], msg[7]]);

    let mut pos = HEADER_LEN;
    // Skip each question: QNAME + QTYPE(2) + QCLASS(2).
    for _ in 0..qdcount {
        pos = match skip_name(msg, pos) {
            Some(p) => p,
            None => return out,
        };
        pos += 4;
        if pos > msg.len() {
            return out;
        }
    }

    // Walk the answer RRs.
    for _ in 0..ancount {
        pos = match skip_name(msg, pos) {
            Some(p) => p,
            None => return out,
        };
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2) = 10 bytes of fixed fields.
        if pos + 10 > msg.len() {
            return out;
        }
        let rtype = u16::from_be_bytes([msg[pos], msg[pos + 1]]);
        let rclass = u16::from_be_bytes([msg[pos + 2], msg[pos + 3]]);
        let rdlength = u16::from_be_bytes([msg[pos + 8], msg[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlength > msg.len() {
            return out;
        }
        if rtype == TYPE_A && rclass == CLASS_IN && rdlength == 4 {
            out.push(Ipv4Addr::new(
                msg[pos],
                msg[pos + 1],
                msg[pos + 2],
                msg[pos + 3],
            ));
        }
        pos += rdlength;
    }
    out
}

/// Read a (possibly compressed) name starting at `pos`, returning the dot-joined
/// lower-cased name and the offset just past the name *in the original stream*
/// (i.e. past the first pointer if one is encountered).
fn read_name(msg: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut jumped = false;
    let mut after_ptr = start;
    let mut budget = msg.len(); // guard against pointer loops

    loop {
        if pos >= msg.len() || budget == 0 {
            return None;
        }
        budget -= 1;
        let len = msg[pos];
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    pos += 1;
                    if !jumped {
                        after_ptr = pos;
                    }
                    break;
                }
                let l = len as usize;
                let s = pos + 1;
                let e = s + l;
                if e > msg.len() {
                    return None;
                }
                labels.push(String::from_utf8_lossy(&msg[s..e]).to_ascii_lowercase());
                pos = e;
            }
            0xC0 => {
                if pos + 1 >= msg.len() {
                    return None;
                }
                let ptr = (((len & 0x3F) as usize) << 8) | msg[pos + 1] as usize;
                if !jumped {
                    after_ptr = pos + 2;
                    jumped = true;
                }
                if ptr >= msg.len() {
                    return None;
                }
                pos = ptr;
            }
            _ => return None, // 0x40 / 0x80 are reserved
        }
    }
    Some((labels.join("."), after_ptr))
}

/// Skip over a (possibly compressed) name, returning the offset just past it.
fn skip_name(msg: &[u8], start: usize) -> Option<usize> {
    let mut pos = start;
    loop {
        if pos >= msg.len() {
            return None;
        }
        let len = msg[pos];
        match len & 0xC0 {
            0x00 => {
                if len == 0 {
                    return Some(pos + 1);
                }
                pos += 1 + len as usize;
            }
            0xC0 => {
                // A pointer is always the end of the name; it is 2 bytes wide.
                return if pos + 1 < msg.len() {
                    Some(pos + 2)
                } else {
                    None
                };
            }
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a DNS query for `name` (type A).
    fn query(name: &str) -> Vec<u8> {
        let mut m = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            m.push(label.len() as u8);
            m.extend_from_slice(label.as_bytes());
        }
        m.push(0);
        m.extend_from_slice(&TYPE_A.to_be_bytes());
        m.extend_from_slice(&CLASS_IN.to_be_bytes());
        m
    }

    #[test]
    fn reads_question_name() {
        assert_eq!(
            question_name(&query("www.google.com")).as_deref(),
            Some("www.google.com")
        );
        assert_eq!(
            question_name(&query("EXAMPLE.com")).as_deref(),
            Some("example.com")
        );
        assert_eq!(question_name(b"short"), None);
    }

    /// Build a response to `q` with the given (ip, ttl) A records.
    fn response_with(q: &[u8], records: &[([u8; 4], u32)]) -> Vec<u8> {
        let mut m = q.to_vec();
        m[2] = 0x81;
        m[3] = 0x80;
        m[6] = (records.len() >> 8) as u8;
        m[7] = records.len() as u8;
        for (ip, ttl) in records {
            m.extend_from_slice(&[0xC0, 0x0C]); // name pointer
            m.extend_from_slice(&TYPE_A.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&ttl.to_be_bytes());
            m.extend_from_slice(&4u16.to_be_bytes());
            m.extend_from_slice(ip);
        }
        m
    }

    #[test]
    fn build_query_round_trips() {
        let q = build_query(0xABCD, "www.example.com");
        assert_eq!(&q[0..2], &[0xAB, 0xCD]); // id
        let (name, qtype, qclass) = question(&q).unwrap();
        assert_eq!(name, "www.example.com");
        assert_eq!((qtype, qclass), (TYPE_A, CLASS_IN));
    }

    #[test]
    fn reads_question_tuple() {
        let (name, qtype, qclass) = question(&query("a.b.example.com")).unwrap();
        assert_eq!(name, "a.b.example.com");
        assert_eq!((qtype, qclass), (TYPE_A, CLASS_IN));
        assert!(question(b"short").is_none());
    }

    #[test]
    fn min_ttl_picks_smallest() {
        let m = response_with(
            &query("example.com"),
            &[([1, 2, 3, 4], 300), ([5, 6, 7, 8], 60)],
        );
        assert_eq!(min_ttl(&m), Some(60));
        assert_eq!(min_ttl(&query("example.com")), None); // a query has no answers
    }

    #[test]
    fn extracts_a_records_with_compression() {
        // Response: header (ancount=2), one question, two A answers that point
        // back to the question name via a compression pointer (0xC0 0x0C).
        let mut m = query("example.com");
        m[2] = 0x81; // QR=1, RD=1
        m[3] = 0x80; // RA=1
        m[6] = 0x00;
        m[7] = 0x02; // ANCOUNT = 2
        for ip in [[93, 184, 216, 34], [1, 2, 3, 4]] {
            m.extend_from_slice(&[0xC0, 0x0C]); // name pointer -> offset 12
            m.extend_from_slice(&TYPE_A.to_be_bytes());
            m.extend_from_slice(&CLASS_IN.to_be_bytes());
            m.extend_from_slice(&300u32.to_be_bytes()); // TTL
            m.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
            m.extend_from_slice(&ip);
        }
        let ips = a_records(&m);
        assert_eq!(
            ips,
            vec![Ipv4Addr::new(93, 184, 216, 34), Ipv4Addr::new(1, 2, 3, 4)]
        );
    }

    #[test]
    fn ignores_non_a_and_malformed() {
        assert!(a_records(&query("example.com")).is_empty()); // query, no answers
        assert!(a_records(b"").is_empty());
        assert!(a_records(b"\x00\x00\x00\x00\xff\xff\xff\xff").is_empty()); // bogus counts
    }
}
