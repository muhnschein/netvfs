# picky-asn1-der 0.5.7, with one change

netvfs builds sspi's DER decoder `picky-asn1-der` from this copy
(`[patch.crates-io]` in `rust/Cargo.toml` and `rust/fuzz/Cargo.toml`).
Everything in this folder but this file is the crate as published on
crates.io (`picky-asn1-der-0.5.7.crate`, SHA-256
`b4467118a2c640f4040aea27d01293620984b0b3f3ef0c53577c3bbf6bab4256`;
Devolutions/picky-rs commit `59487be05e6db1f01f5faa72fc926eb5fb4751b1`,
folder `picky-asn1-der`), except one line, and without its `Cargo.lock`
(cargo ignores a path dependency's lockfile; its old pins only drew advisory
alerts).

## What was changed

`src/de/mod.rs`, in `Deserializer::h_next_object`:

```diff
--- a/src/de/mod.rs
+++ b/src/de/mod.rs
@@ -87,7 +87,7 @@
                     let peeked = self.reader.peek_buffer()?;
                     let msg_len = Length::deserialized(&mut Cursor::new(&peeked.buffer()[1..]))?;
                     let header_len = Length::encoded_len(msg_len) + 1;
-                    (Tag::from(peeked.buffer()[0]), header_len + msg_len)
+                    (Tag::from(peeked.buffer()[0]), header_len.checked_add(msg_len).ok_or(Asn1DerError::TruncatedData)?)
                 } else {
                     let tag = Tag::from(self.reader.read_one()?);
                     let len = Length::deserialized(&mut self.reader)?;
```

## Why

An SMB server's SESSION_SETUP response carries a SPNEGO token, which sspi
decodes with this crate. For an `Asn1RawDer` field, the decoder adds the
header length to the DER length the server sent. A length of 8 bytes
`0xff` (`usize::MAX`) overflows that sum: with overflow checks (debug
builds, tests, the fuzz targets) the process panics; without them (release
builds) the sum wraps to a few bytes, and that many bytes pass for the
whole object. With `checked_add` the overflow is `TruncatedData`, as is any
other length past the input.

`rust/netvfs-smb` tests it (`auth::tests::a_der_length_of_usize_max_is_refused`),
and the input is a seed of the fuzz target `spnego`
(`rust/fuzz/seeds/spnego/der-length-usize-max`).

This folder is not part of the netvfs workspace: no formatting, lints,
tests, coverage, Sonar analysis or cargo-mutants run on it.
