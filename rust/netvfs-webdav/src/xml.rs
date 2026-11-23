// SPDX-License-Identifier: LGPL-2.1-or-later
//! PROPFIND bodies and the multistatus answer (RFC 4918 13, RFC 4331 quotas). The answer is hostile: no DTD,
//! no entities beyond XML's five and character references, caps on responses, text and nesting.

use crate::paths::href_path;
use netvfs_vfs::{ErrorName, Status};
use quick_xml::events::Event;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;

/// Responses in one multistatus at most.
pub const MAX_RESPONSES: usize = 200_000;
/// Longest text of one element.
pub const MAX_TEXT: usize = 32 * 1024;
/// Deepest nesting.
pub const MAX_DEPTH: usize = 32;

/// PROPFIND body asking for what an entry needs.
pub const PROPFIND_ENTRY: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<d:propfind xmlns:d="DAV:"><d:prop>"#,
    "<d:resourcetype/><d:getcontentlength/><d:getlastmodified/><d:getetag/><d:getcontenttype/>",
    "</d:prop></d:propfind>"
);

/// PROPFIND body asking for the quota (RFC 4331).
pub const PROPFIND_QUOTA: &str = concat!(
    r#"<?xml version="1.0" encoding="utf-8"?>"#,
    r#"<d:propfind xmlns:d="DAV:"><d:prop>"#,
    "<d:resourcetype/><d:quota-available-bytes/><d:quota-used-bytes/>",
    "</d:prop></d:propfind>"
);

const DAV: Namespace<'static> = Namespace("DAV:");

/// The properties of one resource the server answered with 2xx.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Props {
    /// `resourcetype` holds `collection`.
    pub collection: bool,
    /// `getcontentlength`.
    pub length: Option<u64>,
    /// `getlastmodified`, ms since the epoch.
    pub modified_ms: Option<i64>,
    /// `getetag`, verbatim.
    pub etag: Vec<u8>,
    /// `getcontenttype`.
    pub content_type: String,
    /// `quota-available-bytes`; negative values (unknown, unlimited) are `None`.
    pub quota_available: Option<u64>,
    /// `quota-used-bytes`.
    pub quota_used: Option<u64>,
}

/// One `response`: decoded path and properties.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Response {
    /// The decoded path of its `href`.
    pub path: Vec<u8>,
    /// Its properties.
    pub props: Props,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum El {
    Multistatus,
    Response,
    Href,
    Status,
    Propstat,
    Prop,
    ResourceType,
    Collection,
    Length,
    Modified,
    Etag,
    ContentType,
    QuotaAvailable,
    QuotaUsed,
    Other,
}

fn element(ns: &ResolveResult<'_>, local: &str) -> El {
    if *ns != ResolveResult::Bound(DAV) {
        return El::Other;
    }
    match local {
        "multistatus" => El::Multistatus,
        "response" => El::Response,
        "href" => El::Href,
        "status" => El::Status,
        "propstat" => El::Propstat,
        "prop" => El::Prop,
        "resourcetype" => El::ResourceType,
        "collection" => El::Collection,
        "getcontentlength" => El::Length,
        "getlastmodified" => El::Modified,
        "getetag" => El::Etag,
        "getcontenttype" => El::ContentType,
        "quota-available-bytes" => El::QuotaAvailable,
        "quota-used-bytes" => El::QuotaUsed,
        _ => El::Other,
    }
}

fn bad(why: impl Into<String>) -> Status {
    Status::new(ErrorName::ProtocolError, "The server sent a malformed folder listing").with_detail(why)
}

fn status_code(line: &str) -> Option<u16> {
    line.split_ascii_whitespace().nth(1)?.parse().ok()
}

fn ok_status(line: &str) -> bool {
    status_code(line).is_some_and(|c| (200..300).contains(&c))
}

fn quota(text: &str) -> Option<u64> {
    text.trim().parse::<i64>().ok().and_then(|n| u64::try_from(n).ok())
}

fn http_date_ms(text: &str) -> Option<i64> {
    let at = httpdate::parse_http_date(text.trim()).ok()?;
    let since = at.duration_since(std::time::UNIX_EPOCH).ok()?;
    i64::try_from(since.as_millis()).ok()
}

#[derive(Debug, Default)]
struct Parser {
    stack: Vec<El>,
    text: String,
    out: Vec<Response>,
    responses: usize,
    href: Option<Vec<u8>>,
    href_count: usize,
    response_ok: bool,
    props: Props,
    propstat: Props,
    propstat_ok: bool,
    root_seen: bool,
}

impl Parser {
    fn parent(&self) -> Option<El> {
        self.stack.last().copied()
    }

    fn start(&mut self, el: El) -> Result<(), Status> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(bad("nested too deep"));
        }
        if self.stack.is_empty() {
            if el != El::Multistatus || self.root_seen {
                return Err(bad("not a multistatus"));
            }
            self.root_seen = true;
        }
        match (self.parent(), el) {
            (Some(El::Multistatus), El::Response) => {
                if self.responses >= MAX_RESPONSES {
                    return Err(bad("too many responses"));
                }
                self.responses = self.responses.saturating_add(1);
                self.href = None;
                self.href_count = 0;
                self.response_ok = true;
                self.props = Props::default();
            }
            (Some(El::Response), El::Propstat) => {
                self.propstat = Props::default();
                self.propstat_ok = false;
            }
            (Some(El::ResourceType), El::Collection)
                if self.stack.ends_with(&[El::Response, El::Propstat, El::Prop, El::ResourceType]) =>
            {
                self.propstat.collection = true;
            }
            _ => {}
        }
        self.text.clear();
        self.stack.push(el);
        Ok(())
    }

    fn end(&mut self) -> Result<(), Status> {
        let el = self.stack.pop().ok_or_else(|| bad("unbalanced end tag"))?;
        let parent = self.parent();
        let text = std::mem::take(&mut self.text);
        match (parent, el) {
            (Some(El::Response), El::Href) => {
                self.href_count = self.href_count.saturating_add(1);
                self.href = href_path(text.as_bytes());
            }
            (Some(El::Response), El::Status) => self.response_ok = ok_status(&text),
            (Some(El::Propstat), El::Status) => self.propstat_ok = ok_status(&text),
            (Some(El::Prop), field) if self.stack.ends_with(&[El::Response, El::Propstat, El::Prop]) => {
                self.prop(field, &text);
            }
            (Some(El::Response), El::Propstat) if self.propstat_ok => {
                let p = std::mem::take(&mut self.propstat);
                merge(&mut self.props, p);
            }
            (Some(El::Multistatus), El::Response) => {
                if let (true, 1, Some(path)) = (self.response_ok, self.href_count, self.href.take()) {
                    self.out.push(Response { path, props: std::mem::take(&mut self.props) });
                }
            }
            _ => {}
        }
        Ok(())
    }

    fn prop(&mut self, field: El, text: &str) {
        let p = &mut self.propstat;
        match field {
            El::Length => p.length = text.trim().parse().ok(),
            El::Modified => p.modified_ms = http_date_ms(text),
            El::Etag => p.etag = text.trim().as_bytes().to_vec(),
            El::ContentType => text.trim().clone_into(&mut p.content_type),
            El::QuotaAvailable => p.quota_available = quota(text),
            El::QuotaUsed => p.quota_used = quota(text),
            _ => {}
        }
    }

    fn push_text(&mut self, s: &str) -> Result<(), Status> {
        if self.text.len().saturating_add(s.len()) > MAX_TEXT {
            return Err(bad("text too long"));
        }
        self.text.push_str(s);
        Ok(())
    }
}

fn merge(into: &mut Props, p: Props) {
    into.collection |= p.collection;
    into.length = p.length.or(into.length);
    into.modified_ms = p.modified_ms.or(into.modified_ms);
    if !p.etag.is_empty() {
        into.etag = p.etag;
    }
    if !p.content_type.is_empty() {
        into.content_type = p.content_type;
    }
    into.quota_available = p.quota_available.or(into.quota_available);
    into.quota_used = p.quota_used.or(into.quota_used);
}

fn predefined(name: &str) -> Option<&'static str> {
    Some(match name {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        _ => return None,
    })
}

/// The responses of a multistatus body, in order; those with a non-2xx status, without exactly one valid `href`,
/// are left out.
///
/// # Errors
/// `ProtocolError` for anything but a well-formed multistatus within the caps.
pub fn parse(body: &[u8]) -> Result<Vec<Response>, Status> {
    let mut reader = NsReader::from_reader(body);
    reader.config_mut().expand_empty_elements = true;
    let mut p = Parser::default();
    loop {
        let (ns, event) = reader.read_resolved_event().map_err(|e| bad(e.to_string()))?;
        match event {
            Event::Start(e) => {
                let el = element(&ns, e.local_name().as_ref());
                p.start(el)?;
            }
            Event::End(_) => p.end()?,
            Event::Text(t) => p.push_text(&t.xml10_content())?,
            Event::CData(t) => p.push_text(&t.into_inner())?,
            Event::GeneralRef(r) => {
                let resolved = if r.is_char_ref() {
                    r.resolve_char_ref()
                        .map_err(|e| bad(e.to_string()))?
                        .ok_or_else(|| bad("bad character"))?
                        .to_string()
                } else {
                    predefined(&r.into_inner()).ok_or_else(|| bad("unknown entity"))?.to_owned()
                };
                p.push_text(&resolved)?;
            }
            Event::DocType(_) => return Err(bad("a document type declaration")),
            Event::Empty(_) => return Err(bad("unexpanded empty element")),
            Event::Eof => break,
            Event::Decl(_) | Event::PI(_) | Event::Comment(_) => {}
        }
    }
    if !p.stack.is_empty() || !p.root_seen {
        return Err(bad("truncated"));
    }
    Ok(p.out)
}

#[cfg(test)]
mod tests;
