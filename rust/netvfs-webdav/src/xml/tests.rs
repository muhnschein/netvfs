// SPDX-License-Identifier: LGPL-2.1-or-later
use super::*;

fn ms(xml: &str) -> String {
    format!(r#"<?xml version="1.0" encoding="utf-8"?><d:multistatus xmlns:d="DAV:">{xml}</d:multistatus>"#)
}

fn response(href: &str, props: &str, status: &str) -> String {
    format!(
        "<d:response><d:href>{href}</d:href><d:propstat><d:prop>{props}</d:prop>\
         <d:status>{status}</d:status></d:propstat></d:response>"
    )
}

fn one(xml: &str) -> Response {
    let mut all = parse(ms(xml).as_bytes()).unwrap();
    assert_eq!(all.len(), 1, "{all:?}");
    all.remove(0)
}

fn malformed(body: &str) {
    let e = parse(body.as_bytes()).unwrap_err();
    assert_eq!(e.name, ErrorName::ProtocolError, "{body}");
}

#[test]
fn a_file_and_a_folder() {
    let body = ms(&[
        response(
            "/dav/d/",
            "<d:resourcetype><d:collection/></d:resourcetype><d:getetag>\"e1\"</d:getetag>",
            "HTTP/1.1 200 OK",
        ),
        response(
            "/dav/d/f%20x.txt",
            "<d:resourcetype/><d:getcontentlength> 12 </d:getcontentlength>\
             <d:getlastmodified>Sun, 06 Nov 1994 08:49:37 GMT</d:getlastmodified>\
             <d:getcontenttype>text/plain</d:getcontenttype><d:getetag>W/\"e2\"</d:getetag>",
            "HTTP/1.1 200 OK",
        ),
    ]
    .concat());
    let all = parse(body.as_bytes()).unwrap();
    assert_eq!(
        all,
        vec![
            Response {
                path: b"/dav/d/".to_vec(),
                props: Props { collection: true, etag: b"\"e1\"".to_vec(), ..Props::default() }
            },
            Response {
                path: b"/dav/d/f x.txt".to_vec(),
                props: Props {
                    collection: false,
                    length: Some(12),
                    modified_ms: Some(784_111_777_000),
                    etag: b"W/\"e2\"".to_vec(),
                    content_type: "text/plain".to_owned(),
                    ..Props::default()
                }
            },
        ]
    );
}

#[test]
fn any_prefix_or_default_namespace_is_dav() {
    let body = r#"<multistatus xmlns="DAV:"><response><href>/a</href><propstat><prop>
        <x:resourcetype xmlns:x="DAV:"><x:collection/></x:resourcetype></prop>
        <status>HTTP/1.1 200 OK</status></propstat></response></multistatus>"#;
    let all = parse(body.as_bytes()).unwrap();
    assert_eq!(all.len(), 1);
    assert!(all[0].props.collection);
}

#[test]
fn other_namespaces_are_not_dav() {
    let r = one(&response(
        "/a",
        r#"<o:resourcetype xmlns:o="urn:other"><o:collection/></o:resourcetype>
           <o:getcontentlength xmlns:o="urn:other">5</o:getcontentlength><d:collection/>"#,
        "HTTP/1.1 200 OK",
    ));
    assert_eq!(r.props, Props::default());
}

#[test]
fn only_2xx_propstats_count() {
    let r = one("<d:response><d:href>/x</d:href>\
         <d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength></d:prop>\
         <d:status>HTTP/1.1 200 OK</d:status></d:propstat>\
         <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>e</d:getetag></d:prop>\
         <d:status>HTTP/1.1 404 Not Found</d:status></d:propstat>\
         <d:propstat><d:prop><d:getcontenttype>a/b</d:getcontenttype></d:prop></d:propstat></d:response>");
    assert_eq!(r.props, Props { length: Some(5), ..Props::default() });
}

#[test]
fn later_2xx_propstats_add_to_earlier_ones() {
    let r = one("<d:response><d:href>/x</d:href>\
         <d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength><d:getetag>a</d:getetag></d:prop>\
         <d:status>HTTP/1.1 200 OK</d:status></d:propstat>\
         <d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype><d:getetag>b</d:getetag>\
         <d:getcontenttype>t/u</d:getcontenttype></d:prop><d:status>HTTP/1.1 204 x</d:status></d:propstat>\
         </d:response>");
    assert_eq!(
        r.props,
        Props {
            collection: true,
            length: Some(5),
            etag: b"b".to_vec(),
            content_type: "t/u".to_owned(),
            ..Props::default()
        }
    );
}

#[test]
fn failed_responses_and_bad_hrefs_are_left_out() {
    let body = ms(&[
        "<d:response><d:href>/gone</d:href><d:status>HTTP/1.1 404 Not Found</d:status></d:response>",
        "<d:response><d:href>/a</d:href><d:href>/b</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>",
        &response("relative", "", "HTTP/1.1 200 OK"),
        &response("/bad%zz", "", "HTTP/1.1 200 OK"),
        &response("/nul%00", "", "HTTP/1.1 200 OK"),
        "<d:response><d:propstat><d:prop/><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>",
        &response("/kept", "", "HTTP/1.1 200 OK"),
        "<d:response><d:href>/ok</d:href><d:status>HTTP/1.1 200 OK</d:status></d:response>",
    ]
    .concat());
    let paths: Vec<Vec<u8>> = parse(body.as_bytes()).unwrap().into_iter().map(|r| r.path).collect();
    assert_eq!(paths, vec![b"/kept".to_vec(), b"/ok".to_vec()]);
}

#[test]
fn entities_cdata_and_absolute_hrefs() {
    let r = one(&response(
        "https://nas:8443/a&amp;b&#x20;c<![CDATA[&d]]>",
        "<d:getetag>&quot;&lt;x&gt;&apos;&#65;&quot;</d:getetag>",
        "HTTP/1.1 200 OK",
    ));
    assert_eq!(r.path, b"/a&b c&d");
    assert_eq!(r.props.etag, b"\"<x>'A\"");
}

#[test]
fn values_that_do_not_parse_are_unknown() {
    let r = one(&response(
        "/x",
        "<d:getcontentlength>-1</d:getcontentlength><d:getlastmodified>yesterday</d:getlastmodified>",
        "HTTP/1.1 200 OK",
    ));
    assert_eq!((r.props.length, r.props.modified_ms), (None, None));
    let r = one(&response(
        "/x",
        "<d:getlastmodified>Thu, 01 Jan 1970 00:00:00 GMT</d:getlastmodified>",
        "HTTP/1.1 200 OK",
    ));
    assert_eq!(r.props.modified_ms, Some(0));
}

#[test]
fn quotas() {
    let r = one(&response(
        "/",
        "<d:quota-available-bytes>100</d:quota-available-bytes><d:quota-used-bytes> 23 </d:quota-used-bytes>",
        "HTTP/1.1 200 OK",
    ));
    assert_eq!((r.props.quota_available, r.props.quota_used), (Some(100), Some(23)));
    let r = one(&response("/", "<d:quota-available-bytes>-3</d:quota-available-bytes>", "HTTP/1.1 200 OK"));
    assert_eq!((r.props.quota_available, r.props.quota_used), (None, None));
}

#[test]
fn status_lines() {
    assert_eq!(status_code("HTTP/1.1 207 Multi-Status"), Some(207));
    assert_eq!(status_code("HTTP/1.1"), None);
    assert_eq!(status_code("HTTP/1.1 x"), None);
    assert!(ok_status("HTTP/1.1 200 OK") && ok_status("HTTP/1.1 299 x"));
    assert!(!ok_status("HTTP/1.1 199 x") && !ok_status("HTTP/1.1 300 x") && !ok_status(""));
}

#[test]
fn an_empty_multistatus_is_no_entries() {
    assert_eq!(parse(ms("").as_bytes()).unwrap(), Vec::new());
    assert_eq!(parse(br#"<d:multistatus xmlns:d="DAV:"/>"#).unwrap(), Vec::new());
}

#[test]
fn malformed_bodies() {
    malformed("");
    malformed("<html><body>Login</body></html>");
    malformed(r#"<d:prop xmlns:d="DAV:"/>"#);
    malformed(r#"<multistatus xmlns="urn:not-dav"/>"#);
    let whole = ms(&response("/a", "", "HTTP/1.1 200 OK"));
    malformed(std::str::from_utf8(&whole.as_bytes()[..60]).unwrap());
    malformed(&format!("{}{}", ms(""), ms("")));
    malformed(&format!(r#"<!DOCTYPE x [<!ENTITY a "b">]>{}"#, ms("")));
    malformed(&ms(&response("/a&ent;", "", "HTTP/1.1 200 OK")));
    malformed(&ms(&response("/a&#0;", "", "HTTP/1.1 200 OK")));
    malformed(&ms("<d:response></d:propstat>"));
    malformed("<d:multistatus xmlns:d=\"DAV:\">\u{0}</d:multistatus>\u{ff}<");
}

#[test]
fn properties_count_only_in_their_place() {
    let ok = "<d:status>HTTP/1.1 200 OK</d:status>";
    let r = one(&format!(
        "<d:response><d:href>/x</d:href><d:propstat><d:prop><x:wrap xmlns:x=\"urn:x\">\
         <d:resourcetype><d:collection/></d:resourcetype></x:wrap></d:prop>{ok}</d:propstat></d:response>"
    ));
    assert!(!r.props.collection, "a collection outside resourcetype of a prop");
    let r = one(&format!(
        "<d:response><d:href>/x</d:href><d:propstat><x:wrap xmlns:x=\"urn:x\"><d:prop>\
         <d:getcontentlength>9</d:getcontentlength></d:prop></x:wrap>{ok}</d:propstat></d:response>"
    ));
    assert_eq!(r.props.length, None, "a prop outside a propstat");
    let r = one(&format!(
        "<d:response><d:href>/x</d:href>\
         <d:propstat><d:prop><d:getcontentlength>5</d:getcontentlength></d:prop>{ok}</d:propstat>\
         <d:propstat><d:prop><d:getcontentlength>9</d:getcontentlength></d:prop></d:propstat></d:response>"
    ));
    assert_eq!(r.props.length, Some(5), "a propstat without status");
}

#[test]
fn caps_hold() {
    let deep = format!("{}{}", "<x>".repeat(MAX_DEPTH), "</x>".repeat(MAX_DEPTH));
    malformed(&ms(&deep));
    let shallow = format!("{}{}", "<x>".repeat(MAX_DEPTH - 1), "</x>".repeat(MAX_DEPTH - 1));
    parse(ms(&shallow).as_bytes()).unwrap();

    let long = "a".repeat(32 * 1024);
    let r = one(&response("/x", &format!("<d:getcontenttype>{long}</d:getcontenttype>"), "HTTP/1.1 200 OK"));
    assert_eq!(r.props.content_type.len(), 32 * 1024);
    malformed(&ms(&response(
        "/x",
        &format!("<d:getcontenttype>{long}b</d:getcontenttype>"),
        "HTTP/1.1 200 OK",
    )));

    let empty = "<d:response/>";
    parse(ms(&empty.repeat(MAX_RESPONSES)).as_bytes()).unwrap();
    malformed(&ms(&empty.repeat(MAX_RESPONSES + 1)));
}

#[test]
fn request_bodies_are_well_formed_propfinds() {
    for body in [PROPFIND_ENTRY, PROPFIND_QUOTA] {
        let mut reader = NsReader::from_reader(body.as_bytes());
        let mut names = Vec::new();
        loop {
            match reader.read_resolved_event().unwrap() {
                (ns, Event::Start(e) | Event::Empty(e)) => {
                    assert_eq!(ns, ResolveResult::Bound(DAV));
                    names.push(e.local_name().as_ref().to_owned());
                }
                (_, Event::Eof) => break,
                _ => {}
            }
        }
        assert_eq!(names[..2], ["propfind".to_owned(), "prop".to_owned()]);
        assert!(names.contains(&"resourcetype".to_owned()));
    }
    assert!(PROPFIND_ENTRY.contains("getlastmodified") && PROPFIND_QUOTA.contains("quota-used-bytes"));
}
