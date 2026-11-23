#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import unittest

import no_comments as nc


def found(path, text):
    return [text[s:e] for s, e in nc.offences(path, text)]


class Rust(unittest.TestCase):
    def test_line_doc_and_block_comments_found(self):
        text = "//! crate\n/// item\nfn f() {} // tail\n/* a /* nested */ b */\nfn g() {}\n"
        self.assertEqual(found("a.rs", text), ["/// item", "// tail", "/* a /* nested */ b */"])

    def test_strings_chars_and_lifetimes_hide_nothing(self):
        text = 'fn f<\'a>(x: &\'a str) -> char { let _ = "//"; let _ = r#"/* " */"#; let _ = b"//"; \'"\' }\n'
        self.assertEqual(found("a.rs", text), [])

    def test_comment_after_char_literal_found(self):
        self.assertEqual(found("a.rs", "let c = '\"'; // x\n"), ["// x"])

    def test_slash_after_block_is_division_in_rust(self):
        self.assertEqual(found("a.rs", "let n = { 4 } / 2; // half\n"), ["// half"])

    def test_spdx_only_on_first_line(self):
        text = "// SPDX-License-Identifier: LGPL-2.1-or-later\n// SPDX-License-Identifier: MIT\n"
        self.assertEqual(found("a.rs", text), ["// SPDX-License-Identifier: MIT"])

    def test_bare_nosonar_kept_explained_one_found(self):
        text = "a(); // NOSONAR\nb(); // NOSONAR: why\n"
        self.assertEqual(found("a.rs", text), ["// NOSONAR: why"])

    def test_api_docs_kept_private_docs_found(self):
        text = (
            "/// A.\npub struct A {\n    /// Field.\n    pub x: u8,\n    /// Private.\n    y: u8,\n}\n"
            "/// Private fn.\nfn f() {}\n/// Crate.\npub(crate) fn g() {}\n"
            "/// Kind.\npub enum K {\n    /// One.\n    One,\n    /// Two.\n    Two {\n        /// Size.\n        size: u8,\n    },\n}\n"
            "/// Trait.\npub trait T {\n    /// Method.\n    fn m(&self);\n}\n"
            "/// Attr.\n#[derive(Debug)]\npub struct B;\n//! Inner.\n"
        )
        self.assertEqual(found("a.rs", text), ["/// Private.", "/// Private fn.", "/// Crate."])

    def test_plain_comment_above_pub_item_found(self):
        self.assertEqual(found("a.rs", "// why\npub fn f() {}\n"), ["// why"])

    def test_closed_enum_or_string_brace_does_not_scope_fields(self):
        field = "struct S {\n    /// Doc.\n    x: u8,\n}\n"
        self.assertEqual(found("a.rs", "enum E {\n    V,\n}\n" + field), ["/// Doc."])
        self.assertEqual(found("a.rs", 'const A: &str = "enum {";\n' + field), ["/// Doc."])

    def test_variant_doc_kept_below_where_clause(self):
        self.assertEqual(found("a.rs", "pub enum E<T>\nwhere\n    T: Copy,\n{\n    /// One.\n    One(T),\n}\n"), [])

    def test_doc_after_safety_comment_is_no_safety(self):
        self.assertEqual(found("a.rs", "// SAFETY: x\n/// Doc.\nfn f() {}\n"), ["/// Doc."])

    def test_safety_comment_kept_plain_comment_found(self):
        text = "// SAFETY: fd is ours,\n// open until here.\nunsafe { close(fd) };\n// why\nlet x = 1;\n"
        self.assertEqual(found("a.rs", text), ["// why"])
        self.assertEqual(found("a.rs", "// Note: SAFETY: x\nunsafe { f() };\n"), ["// Note: SAFETY: x"])

    def test_safety_section_kept_only_above_pub_unsafe_fn(self):
        kept = "/// # Safety\n/// `p` is live.\npub unsafe fn f(p: *mut u8) {}\n"
        self.assertEqual(found("a.rs", kept), [])
        self.assertEqual(found("a.rs", "/// # Safety\n/// `p` is live.\nunsafe fn f() {}\n"), ["/// # Safety", "/// `p` is live."])
        exported = '/// # Safety\n/// C runtime calls it.\n#[no_mangle]\npub unsafe extern "C" fn main() {}\n'
        self.assertEqual(found("a.rs", exported), [])


class Qml(unittest.TestCase):
    def test_lupdate_source_text_kept(self):
        text = 'Label {\n    //% "Copy"\n    text: qsTrId("lautta-copy") // id\n}\n'
        self.assertEqual(found("A.qml", text), ["// id"])

    def test_regex_literal_is_no_comment(self):
        text = 'var x = s.replace(/\\/+$/, "")\nvar y = a / b // half\nvar z = /[/]/.test(s)\n'
        self.assertEqual(found("a.js", text), ["// half"])
        self.assertEqual(found("a.js", "var r = s.split(/\\/\\//)\n"), [])

    def test_escaped_quote_stays_in_string(self):
        self.assertEqual(found("a.js", 'var s = "a\\" // no"; // yes\n'), ["// yes"])

    def test_slashes_in_regex_class(self):
        self.assertEqual(found("a.js", "var r = /[///]/\n"), [])

    def test_single_quotes_are_strings_in_js(self):
        self.assertEqual(found("a.js", "var u = 'http://x'\n"), [])

    def test_lupdate_marker_is_js_only(self):
        self.assertEqual(found("a.rs", '//% "x"\n'), ['//% "x"'])


class Cpp(unittest.TestCase):
    def test_lupdate_source_text_kept(self):
        text = '//% "Copy"\nreturn qtTrId("netvfs-copy"); // id\n'
        self.assertEqual(found("src/a.cpp", text), ["// id"])

    def test_comments_found_strings_and_chars_skipped(self):
        text = 'auto s = "// no"; char c = \'"\'; int n = 1\'000; // yes\nauto r = R"x(/* no */)x"; /* yes */\n'
        self.assertEqual(found("src/a.cpp", text), ["// yes", "/* yes */"])

    def test_division_is_no_regex(self):
        self.assertEqual(found("a.cpp", "int x = int{4} / 2; // c\n"), ["// c"])

    def test_quote_in_char_and_raw_string(self):
        self.assertEqual(found("a.cpp", "char q = '\"'; // yes\n"), ["// yes"])
        self.assertEqual(found("a.cpp", 'auto r = R"x(a" // no )x"; // yes\n'), ["// yes"])

    def test_public_header_comments_kept(self):
        text = "// SPDX-License-Identifier: LGPL-2.1-or-later\n// API doc.\nclass A;\n"
        self.assertEqual(found("src/core/backend.h", text), [])
        self.assertEqual(found("src/core/statemutex.h", text), ["// API doc."])

    def test_attribution_header_kept(self):
        text = "// SPDX-License-Identifier: LGPL-2.1-or-later\n// Adapted from x:\n//   SPDX-FileCopyrightText: 2020 Y\n#include <a>\n// later\n"
        self.assertEqual(found("a.cpp", text), ["// later"])

    def test_c_block_spdx(self):
        self.assertEqual(found("x.map", "/* SPDX-License-Identifier: MIT */\n/* why */\n"), ["/* why */"])


class Xml(unittest.TestCase):
    def test_spdx_after_declaration_kept(self):
        text = '<?xml version="1.0"?>\n<!-- SPDX-License-Identifier: MIT -->\n<!-- why -->\n<a/>\n'
        self.assertEqual(found("x.xml.in", text), ["<!-- why -->"])

    def test_bridge_interface_docs_kept(self):
        text = "<node>\n<!-- API doc -->\n</node>\n"
        self.assertEqual(found("tests/bridge/contract/org.netvfs.Bridge1.xml", text), [])
        self.assertEqual(found("src/other.xml", text), ["<!-- API doc -->"])


class Hash(unittest.TestCase):
    def test_shell(self):
        text = '#!/bin/sh\n# SPDX-License-Identifier: LGPL-2.1-or-later\necho "a # b" $# ${#x} # tail\n# full\n'
        self.assertEqual(found("a.sh", text), ["# tail", "# full"])

    def test_shell_heredoc_body_is_data(self):
        text = "cat <<EOF\na\n# not a comment\nEOF\n# comment\n"
        self.assertEqual(found("a.sh", text), ["# comment"])

    def test_escaped_quote_in_hash_string(self):
        self.assertEqual(found("a.toml", 'a = "x\\" # no" # yes\n'), ["# yes"])

    def test_shell_escaped_quote(self):
        self.assertEqual(found("a.sh", "echo \\' # x\n"), ["# x"])

    def test_shebang_only_on_first_line(self):
        self.assertEqual(found("a.sh", "echo\n#!/bin/sh\n"), ["#!/bin/sh"])

    def test_yaml_and_toml(self):
        text = 'a: "x # y"\nb: c#d\nuses: x@abc # v1\n'
        self.assertEqual(found("w.yml", text), ["# v1"])
        self.assertEqual(found("C.toml", "# top\nk = 'a # b'\n"), ["# top"])

    def test_makefile(self):
        self.assertEqual(found("Makefile", "a:\n\techo $$# x\n# note\n"), ["# note"])

    def test_qmake_and_dockerfile(self):
        self.assertEqual(found("a.pro", "QT += core # why\nX = $$Y\n"), ["# why"])
        self.assertEqual(found("t/Dockerfile.distro", "# why\nRUN a\n"), ["# why"])
        self.assertEqual(found(".qmake.conf", "A = 1 # why\n"), ["# why"])

    def test_full_line_formats(self):
        self.assertEqual(found("x.spec", "Name: a\n# note\nURL: b#c\n"), ["# note"])

    def test_python_comments_and_docstrings(self):
        text = '"""Module."""\ndef f():\n    """Doc."""\n    return "# no"  # yes\n'
        self.assertEqual(found("a.py", text), ['"""Module."""', '"""Doc."""', "# yes"])


class Strip(unittest.TestCase):
    def test_no_blank_line_left_at_block_edges(self):
        self.assertEqual(nc.strip("a.rs", "fn a() {\n    // x\n\n    b();\n}\n"), "fn a() {\n    b();\n}\n")
        self.assertEqual(nc.strip("a.rs", "fn a() {\n    b();\n\n    // x\n}\n"), "fn a() {\n    b();\n}\n")

    def test_blank_lines_away_from_comments_stay(self):
        self.assertEqual(nc.strip("a.rs", "fn a() {\n\n    b(); // x\n}\n"), "fn a() {\n\n    b();\n}\n")

    def test_trailing_blank_lines_collapse(self):
        self.assertEqual(nc.strip("a.rs", "x(); // c\n\n\n"), "x();\n")

    def test_comment_lines_go_without_leaving_gaps(self):
        text = "fn a() {\n    // why\n    b();\n}\n\n// about c\n\nfn c() {} // tail\n"
        self.assertEqual(nc.strip("a.rs", text), "fn a() {\n    b();\n}\n\nfn c() {}\n")

    def test_block_comment_with_code_after_it(self):
        self.assertEqual(nc.strip("a.rs", "x(/* one */);\n/* two\n   lines */ y();\n"), "x();\n y();\n")

    def test_header_line_keeps_only_spdx(self):
        text = "// SPDX-License-Identifier: LGPL-2.1-or-later Says what.\n// More.\nimport QtQuick 2.6\n"
        self.assertEqual(nc.strip("A.qml", text), "// SPDX-License-Identifier: LGPL-2.1-or-later\nimport QtQuick 2.6\n")

    def test_docstring_beside_code_just_goes(self):
        self.assertEqual(nc.strip("a.py", 'def f():\n    """Doc."""\n    return 1\n'), "def f():\n    return 1\n")

    def test_docstring_only_body_becomes_pass(self):
        self.assertEqual(nc.strip("a.py", 'class E(Exception):\n    """Doc."""\n'), "class E(Exception):\n    pass\n")

    def test_nosonar_keeps_marker_only(self):
        self.assertEqual(nc.strip("a.rs", "f(); // NOSONAR: blocking pool\n"), "f(); // NOSONAR\n")

    def test_stripped_text_passes_check(self):
        text = "// SPDX-License-Identifier: MIT\n/// doc\nfn f() {\n    // x\n}\n"
        self.assertEqual(found("a.rs", nc.strip("a.rs", text)), [])


class Scope(unittest.TestCase):
    def test_vendored_code_and_test_data_excluded(self):
        paths = list(nc.tracked())
        self.assertIn("Makefile", paths)
        self.assertIn("src/core/backend.cpp", paths)
        self.assertIn("rust/netvfs-smb/src/crypto.rs", paths)
        self.assertFalse([p for p in paths if p.startswith(("vendor/", "rust/vendor/", "doc/"))])
        self.assertFalse([p for p in paths if "/testdata/" in p or "/tests/data/" in p])
        self.assertNotIn(".github/codeql/rust-queries/HardcodedCryptographicValue.ql", paths)

    def test_public_headers_from_core_pro(self):
        self.assertIn("src/core/backend.h", nc.public_headers())
        self.assertNotIn("src/core/statemutex.h", nc.public_headers())

    def test_unknown_formats_unchecked(self):
        self.assertIsNone(nc.language("doc/README.md"))
        self.assertIsNone(nc.language("a.json"))


if __name__ == "__main__":
    unittest.main()
