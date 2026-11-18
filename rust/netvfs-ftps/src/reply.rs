// SPDX-License-Identifier: LGPL-2.1-or-later
//! Control connection replies (RFC 959 4.2): reading them within caps, and what their codes mean.

use netvfs_vfs::{ErrorName, Status};
use tokio::io::{AsyncBufRead, AsyncBufReadExt};

/// Longest reply line read.
pub const MAX_LINE: usize = 8 * 1024;
/// Largest reply read, all lines.
pub const MAX_REPLY: usize = 64 * 1024;

/// One reply: its code and lines without the code prefix or line end.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reply {
    /// Three digits.
    pub code: u16,
    /// Text of each line; continuation lines verbatim.
    pub lines: Vec<Vec<u8>>,
}

impl Reply {
    /// First digit: 1 preliminary, 2 done, 3 more needed, 4 transient, 5 permanent failure.
    #[must_use]
    pub const fn class(&self) -> u16 {
        self.code / 100
    }

    /// The lines as one text, for error details.
    #[must_use]
    pub fn text(&self) -> String {
        let joined: Vec<String> =
            self.lines.iter().map(|l| String::from_utf8_lossy(l).trim().to_owned()).collect();
        format!("{} {}", self.code, joined.join(" ").trim())
    }
}

fn garbled(what: &str) -> Status {
    Status::new(ErrorName::ProtocolError, "The server sent an unreadable reply").with_detail(what.to_owned())
}

/// One line without its end; `None` at the end of the stream.
async fn line(r: &mut (impl AsyncBufRead + Unpin), budget: &mut usize) -> Result<Option<Vec<u8>>, Status> {
    let mut out = Vec::new();
    loop {
        let buf = r.fill_buf().await.map_err(|e| lost(&e.to_string()))?;
        if buf.is_empty() {
            return if out.is_empty() { Ok(None) } else { Err(garbled("cut off")) };
        }
        let (take, done) = match buf.iter().position(|b| *b == b'\n') {
            Some(at) => (at.saturating_add(1), true),
            None => (buf.len(), false),
        };
        if out.len().saturating_add(take) > MAX_LINE.saturating_add(2) || take > *budget {
            return Err(garbled("too long"));
        }
        *budget = budget.saturating_sub(take);
        out.extend_from_slice(buf.get(..take).unwrap_or_default());
        r.consume(take);
        if done {
            out.pop();
            if out.last() == Some(&b'\r') {
                out.pop();
            }
            return Ok(Some(out));
        }
    }
}

/// `ConnectionLost` with `why`.
#[must_use]
pub fn lost(why: &str) -> Status {
    Status::new(ErrorName::ConnectionLost, "The connection to the server was lost")
        .with_detail(why.to_owned())
}

#[allow(clippy::arithmetic_side_effects, reason = "three ASCII digits")]
fn code_of(l: &[u8]) -> Option<(u16, u8)> {
    let digits = l.get(..3)?;
    if !digits.iter().all(u8::is_ascii_digit) || !(b'1'..=b'5').contains(digits.first()?) {
        return None;
    }
    let code = digits.iter().fold(0u16, |n, d| n * 10 + u16::from(d - b'0'));
    let sep = l.get(3).copied().unwrap_or(b' ');
    Some((code, sep))
}

/// The next reply.
///
/// # Errors
/// `ConnectionLost` when the stream ends or fails; `ProtocolError` for a line without code, a line or reply
/// over its cap.
pub async fn read(r: &mut (impl AsyncBufRead + Unpin)) -> Result<Reply, Status> {
    let mut budget = MAX_REPLY;
    let first = line(r, &mut budget).await?.ok_or_else(|| lost("closed"))?;
    let (code, sep) = code_of(&first).ok_or_else(|| garbled("no reply code"))?;
    let mut lines = vec![first.get(4..).unwrap_or_default().to_vec()];
    match sep {
        b' ' => return Ok(Reply { code, lines }),
        b'-' => {}
        _ => return Err(garbled("bad separator")),
    }
    loop {
        let next = line(r, &mut budget).await?.ok_or_else(|| lost("closed"))?;
        if code_of(&next) == Some((code, b' ')) {
            lines.push(next.get(4..).unwrap_or_default().to_vec());
            return Ok(Reply { code, lines });
        }
        lines.push(next);
    }
}

/// The error a failed reply means, for an operation named `what`.
#[must_use]
pub fn error(reply: &Reply, what: &str) -> Status {
    let (name, message) = match reply.code {
        421 | 425 | 426 => (ErrorName::ConnectionLost, format!("{what}: the server closed the connection")),
        452 | 552 => (ErrorName::NoSpace, format!("{what}: no space left on the server")),
        530 => (ErrorName::AuthFailed, "The server did not accept the user name or password".to_owned()),
        553 => (ErrorName::InvalidName, format!("{what}: the server refused the name")),
        500 | 502 | 504 => (ErrorName::Unsupported, format!("{what}: the server does not support this")),
        450 | 550 => (ErrorName::PermissionDenied, format!("{what}: the server refused")),
        _ => (ErrorName::ProtocolError, format!("{what}: unexpected reply from the server")),
    };
    Status::new(name, message).with_detail(reply.text())
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn parse(input: &[u8]) -> Result<Reply, Status> {
        read(&mut &input[..]).await
    }

    #[tokio::test]
    async fn single_and_multi_line_replies() {
        let r = parse(b"220 Welcome\r\nrest").await.unwrap();
        assert_eq!((r.code, r.lines), (220, vec![b"Welcome".to_vec()]));
        let r = parse(b"211-Features:\r\n MLST type*;size*;\r\n EPSV\r\n211-not the end\r\n211 End\r\n")
            .await
            .unwrap();
        assert_eq!(r.code, 211);
        assert_eq!(
            r.lines,
            vec![
                b"Features:".to_vec(),
                b" MLST type*;size*;".to_vec(),
                b" EPSV".to_vec(),
                b"211-not the end".to_vec(),
                b"End".to_vec()
            ]
        );
        assert_eq!(parse(b"200\n").await.unwrap(), Reply { code: 200, lines: vec![Vec::new()] });
        assert_eq!(parse(b"200 x\n").await.unwrap().text(), "200 x");
        assert_eq!(r.class(), 2);
    }

    #[tokio::test]
    async fn bad_replies_are_refused() {
        for input in [&b"hello\r\n"[..], b"600 no\r\n", b"20 x\r\n", b"2a0 x\r\n", b"200x\r\n", b"200 cut"] {
            assert_eq!(parse(input).await.unwrap_err().name, ErrorName::ProtocolError, "{input:?}");
        }
        assert_eq!(parse(b"").await.unwrap_err().name, ErrorName::ConnectionLost);
        assert_eq!(parse(b"211-start\r\n").await.unwrap_err().name, ErrorName::ConnectionLost);
    }

    #[tokio::test]
    async fn lines_and_replies_are_capped() {
        let mut ok = b"200 ".to_vec();
        ok.resize(8 * 1024, b'x');
        ok.extend_from_slice(b"\r\n");
        parse(&ok).await.unwrap();
        let mut long = b"200 ".to_vec();
        long.resize(MAX_LINE + 1, b'x');
        long.extend_from_slice(b"\r\n");
        assert_eq!(parse(&long).await.unwrap_err().name, ErrorName::ProtocolError);
        let mut many = b"211-x\r\n".to_vec();
        while many.len() <= MAX_REPLY {
            many.extend_from_slice(b" filler line\r\n");
        }
        many.extend_from_slice(b"211 End\r\n");
        assert_eq!(parse(&many).await.unwrap_err().name, ErrorName::ProtocolError);
        // 64 KiB in all is still read.
        let mut full = b"211-x\r\n".to_vec();
        while full.len() + 1000 <= 64 * 1024 - 9 {
            full.extend_from_slice(&[b' '; 998]);
            full.extend_from_slice(b"\r\n");
        }
        let pad = 64 * 1024 - 9 - full.len();
        full.extend(std::iter::repeat_n(b' ', pad - 2));
        full.extend_from_slice(b"\r\n211 End\r\n");
        assert_eq!(full.len(), 64 * 1024);
        parse(&full).await.unwrap();
        full.insert(7, b' ');
        assert_eq!(parse(&full).await.unwrap_err().name, ErrorName::ProtocolError);
    }

    #[test]
    fn codes_name_errors() {
        let e = |code| error(&Reply { code, lines: vec![b"why".to_vec()] }, "Op").name;
        for (code, name) in [
            (421, ErrorName::ConnectionLost),
            (425, ErrorName::ConnectionLost),
            (426, ErrorName::ConnectionLost),
            (452, ErrorName::NoSpace),
            (552, ErrorName::NoSpace),
            (530, ErrorName::AuthFailed),
            (553, ErrorName::InvalidName),
            (500, ErrorName::Unsupported),
            (502, ErrorName::Unsupported),
            (504, ErrorName::Unsupported),
            (450, ErrorName::PermissionDenied),
            (550, ErrorName::PermissionDenied),
            (451, ErrorName::ProtocolError),
            (200, ErrorName::ProtocolError),
        ] {
            assert_eq!(e(code), name, "{code}");
        }
        let s = error(&Reply { code: 550, lines: vec![b"No access".to_vec()] }, "Removing");
        assert_eq!(
            (s.message.as_str(), s.detail.as_str()),
            ("Removing: the server refused", "550 No access")
        );
    }
}
