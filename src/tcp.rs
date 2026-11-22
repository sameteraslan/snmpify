//! SNMP over TCP (RFC 3430): messages back to back on a stream, each a
//! BER SEQUENCE whose header gives its length.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The largest message accepted on a stream.
pub(crate) const MAX_MESSAGE: usize = 1 << 20;

/// Reads one message (its full TLV). `Ok(None)` at a clean end of stream.
pub(crate) async fn read_message<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0u8; 2];
    match r.read_exact(&mut head[..1]).await {
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    r.read_exact(&mut head[1..]).await?;
    let bad = |m: &str| io::Error::new(io::ErrorKind::InvalidData, m.to_string());
    if head[0] != 0x30 {
        return Err(bad("not an SNMP message"));
    }
    let mut msg = head.to_vec();
    let len = if head[1] < 0x80 {
        head[1] as usize
    } else {
        let n = (head[1] & 0x7F) as usize;
        if n == 0 || n > 4 {
            return Err(bad("bad message length"));
        }
        let mut l = [0u8; 4];
        r.read_exact(&mut l[..n]).await?;
        msg.extend_from_slice(&l[..n]);
        l[..n].iter().fold(0usize, |a, &b| (a << 8) | b as usize)
    };
    if len > MAX_MESSAGE {
        return Err(bad("message too large"));
    }
    let start = msg.len();
    msg.resize(start + len, 0);
    r.read_exact(&mut msg[start..]).await?;
    Ok(Some(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn frames() {
        let one = crate::CommunityMessage::new(
            crate::Version::V2c,
            "public",
            crate::Pdu::get(1, [[1u32, 3, 6]]),
        )
        .encode();
        let big = crate::CommunityMessage::new(
            crate::Version::V2c,
            "public",
            crate::Pdu::set(2, vec![crate::VarBind::new([1, 3, 6], "x".repeat(300))]),
        )
        .encode();
        let mut stream: Vec<u8> = [one.clone(), big.clone()].concat();
        let mut r = stream.as_slice();
        assert_eq!(read_message(&mut r).await.unwrap().unwrap(), one);
        assert_eq!(read_message(&mut r).await.unwrap().unwrap(), big);
        assert!(read_message(&mut r).await.unwrap().is_none());
        // Truncated, not SNMP, absurd lengths.
        stream.truncate(one.len() + 10);
        let mut r = &stream[one.len()..];
        assert!(read_message(&mut r).await.is_err());
        for bad in [
            &[0x02u8, 0x01][..],
            &[0x30, 0x80],
            &[0x30, 0x85, 1, 1, 1, 1, 1],
            &[0x30, 0x84, 0x7f, 0, 0, 0],
        ] {
            let mut r = bad;
            assert!(read_message(&mut r).await.is_err(), "{bad:?}");
        }
    }
}
