#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Tests of the packaging checks (SPEC-v2 XP-1, XP-3): tools/ci/check-files.py
against small specs and install trees, tools/ci/check-noshareenum.sh against
shared objects built here with and without DCE/RPC code (needs cc and
readelf). Run from anywhere: tests/packaging/test_packaging.py
"""
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CHECK_FILES = os.path.join(ROOT, "tools", "ci", "check-files.py")
CHECK_NOSHAREENUM = os.path.join(ROOT, "tools", "ci", "check-noshareenum.sh")

SPEC = """\
%bcond_with extra
Name:    demo
Version: 1.0
Release: 1

%package core
Summary: core
%description core
core

%if %{with extra}
%package extra
Summary: extra
%description extra
extra
%endif

%files core
%license LICENSE
%dir %{_libdir}/demo
%{_libdir}/libdemo.so.*
%{_datadir}/demo
%config %{_sysconfdir}/demo/demo{,-local}.conf

%files tools
%attr(0755,root,root) %{_bindir}/demo-*

%if %{with extra}
%files extra
%{_prefix}/libexec/demo/helper
%endif
"""

TREE = [
    "usr/lib/x86_64-linux-gnu/demo/",
    "usr/lib/x86_64-linux-gnu/libdemo.so.1",
    "usr/share/demo/a.json",
    "usr/share/demo/sub/b.json",
    "etc/demo/demo.conf",
    "etc/demo/demo-local.conf",
    "usr/bin/demo-cli",
]


class CheckFiles(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.root = os.path.join(self.work, "root")
        self.spec = os.path.join(self.work, "demo.spec")
        self.write_spec(SPEC)
        for path in TREE:
            self.add(path)

    def tearDown(self):
        shutil.rmtree(self.work)

    def write_spec(self, text):
        with open(self.spec, "w", encoding="utf-8") as spec:
            spec.write(text)

    def add(self, path):
        full = os.path.join(self.root, path)
        if path.endswith("/"):
            os.makedirs(full, exist_ok=True)
            return
        os.makedirs(os.path.dirname(full), exist_ok=True)
        with open(full, "w", encoding="utf-8") as file:
            file.write(path)

    def run_check(self, *extra):
        result = subprocess.run([sys.executable, CHECK_FILES, "--spec", self.spec,
                                 "--map", "/usr/lib/x86_64-linux-gnu=/usr/lib64", *extra, self.root],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return result.returncode, result.stdout

    def assert_problem(self, text, *extra):
        code, output = self.run_check(*extra)
        self.assertEqual(code, 1, output)
        self.assertIn(text, output)

    def test_complete_tree_passes(self):
        code, output = self.run_check("--list")
        self.assertEqual(code, 0, output)
        self.assertIn("demo-core\n", output)
        self.assertIn("    /usr/lib64/libdemo.so.1\n", output)
        self.assertIn("    /usr/share/demo/sub/b.json\n", output)
        self.assertIn("    /etc/demo/demo-local.conf\n", output)
        self.assertIn("demo-tools\n    /usr/bin/demo-cli\n", output)

    def test_unpackaged_file(self):
        self.add("usr/lib/x86_64-linux-gnu/libdemo.so")
        self.assert_problem("file /usr/lib64/libdemo.so is in no package")

    def test_file_in_two_packages(self):
        self.write_spec(SPEC + "\n%files dup\n%{_bindir}/demo-cli\n")
        self.assert_problem("file /usr/bin/demo-cli is in several packages: demo-tools, demo-dup")

    def test_entry_that_matches_nothing(self):
        os.remove(os.path.join(self.root, "usr/bin/demo-cli"))
        self.assert_problem("demo-tools: /usr/bin/demo-* matches nothing")

    def test_allowed_missing_entry(self):
        os.remove(os.path.join(self.root, "usr/bin/demo-cli"))
        code, output = self.run_check("--allow-missing", "/usr/bin/*")
        self.assertEqual(code, 0, output)

    def test_dir_entry_owns_only_the_folder(self):
        self.add("usr/lib/x86_64-linux-gnu/demo/plugin.so")
        self.assert_problem("file /usr/lib64/demo/plugin.so is in no package")

    def test_unowned_netvfs_style_directory(self):
        self.write_spec(SPEC.replace("%dir %{_libdir}/demo\n", ""))
        self.add("usr/lib/x86_64-linux-gnu/netvfs-demo/")
        self.assert_problem("directory /usr/lib64/netvfs-demo is in no package")

    def test_directory_owned_twice(self):
        self.add("usr/share/netvfs/x.conf")
        self.write_spec(SPEC + "\n%files one\n%{_datadir}/netvfs\n\n%files two\n%dir %{_datadir}/netvfs\n")
        self.assert_problem("directory /usr/share/netvfs is in several packages: demo-one, demo-two")

    def test_condition_off_leaves_file_unpackaged(self):
        self.add("usr/libexec/demo/helper")
        self.assert_problem("file /usr/libexec/demo/helper is in no package")

    def test_condition_on_packages_file(self):
        self.add("usr/libexec/demo/helper")
        code, output = self.run_check("--with", "extra", "--list")
        self.assertEqual(code, 0, output)
        self.assertIn("demo-extra\n    /usr/libexec/demo/helper\n", output)

    def test_condition_on_without_file(self):
        self.assert_problem("demo-extra: /usr/libexec/demo/helper matches nothing", "--with", "extra")

    def test_unknown_macro_is_an_error(self):
        self.write_spec(SPEC + "\n%files more\n%{_nosuchdir}/x\n")
        code, output = self.run_check()
        self.assertEqual(code, 2, output)
        self.assertIn("unknown macro: %{_nosuchdir}", output)

    def test_real_spec_parses(self):
        result = subprocess.run([sys.executable, CHECK_FILES, "--allow-missing", "*", self.root],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        self.assertIn("packages", result.stdout)
        self.assertNotEqual(result.returncode, 2, result.stdout)


@unittest.skipUnless(shutil.which("cc") and shutil.which("readelf"), "needs cc and readelf")
class CheckNoShareEnum(unittest.TestCase):
    def setUp(self):
        self.work = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.work)

    def build(self, name, source, strip):
        c_file = os.path.join(self.work, name + ".c")
        so_file = os.path.join(self.work, name + ".so")
        with open(c_file, "w", encoding="utf-8") as file:
            file.write(textwrap.dedent(source))
        subprocess.run(["cc", "-shared", "-fPIC", "-o", so_file, c_file], check=True)
        if strip:
            subprocess.run(["strip", so_file], check=True)
        return so_file

    def run_check(self, so_file):
        result = subprocess.run([CHECK_NOSHAREENUM, so_file], stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, check=False)
        return result.returncode, result.stdout

    def test_clean_plugin_passes(self):
        so_file = self.build("clean", """
            const char *smb_message(void) { return "Share enumeration is not available"; }
            """, strip=True)
        code, output = self.run_check(so_file)
        self.assertEqual(code, 0, output)

    def test_dcerpc_strings_fail(self):
        so_file = self.build("strings", """
            const char *smb_message(void) { return "DCERPC FAULT status=0x%08x"; }
            """, strip=True)
        code, output = self.run_check(so_file)
        self.assertEqual(code, 1, output)
        self.assertIn("share enumeration strings", output)

    def test_srvsvc_pipe_name_fails(self):
        so_file = self.build("pipe", """
            const char *smb_pipe(void) { return "srvsvc"; }
            """, strip=True)
        code, output = self.run_check(so_file)
        self.assertEqual(code, 1, output)

    def test_dcerpc_symbols_fail(self):
        so_file = self.build("symbols", """
            __attribute__((visibility("hidden"))) int dcerpc_bind_cb(int x) { return x + 1; }
            int smb_entry(int x) { return dcerpc_bind_cb(x); }
            """, strip=False)
        code, output = self.run_check(so_file)
        self.assertEqual(code, 1, output)
        self.assertIn("dcerpc_bind_cb", output)

    def test_not_elf_fails(self):
        code, output = self.run_check(os.path.join(ROOT, "LICENSE"))
        self.assertEqual(code, 1, output)


if __name__ == "__main__":
    unittest.main()
