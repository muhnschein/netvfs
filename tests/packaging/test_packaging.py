#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Tests of the packaging checks (SPEC-v2 XP-1): tools/ci/check-files.py
against small specs and install trees, and tools/ci/check-ffi-lib.sh against
stand-ins for netvfs-bridge's C ABI and
tools/ci/check-rs-lib.sh against stand-ins for libnetvfs-rs.so, built here
(they need cc and readelf). Run from anywhere:
tests/packaging/test_packaging.py
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
CHECK_FFI_LIB = os.path.join(ROOT, "tools", "ci", "check-ffi-lib.sh")
CHECK_RS_LIB = os.path.join(ROOT, "tools", "ci", "check-rs-lib.sh")

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


FFI_INSTALLED = "/usr/lib64/netvfs/libnetvfs-bridge-ffi.so"


@unittest.skipUnless(shutil.which("cc") and shutil.which("readelf"), "needs cc and readelf")
class CheckFfiLib(unittest.TestCase):
    """A library that exports nvb_ffi_get only and links a stand-in for
    libnetvfs.so.1, and a "bridge" that names its installed path."""

    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.write("netvfs.c", "int netvfs_version(void) { return 1; }\n")
        subprocess.run(["cc", "-shared", "-fPIC", "-Wl,-soname,libnetvfs.so.1", "-o",
                        os.path.join(self.work, "libnetvfs.so.1"), os.path.join(self.work, "netvfs.c")],
                       check=True)
        self.write("exports.map", "{ global: nvb_ffi_get; local: *; };\n")
        self.bridge = self.write("netvfs-bridge", "\0loads " + FFI_INSTALLED + "\0")

    def tearDown(self):
        shutil.rmtree(self.work)

    def write(self, name, text):
        path = os.path.join(self.work, name)
        with open(path, "w", encoding="utf-8") as file:
            file.write(text)
        return path

    def build(self, source=None, flags=("-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"),
              exports=True, netvfs=True):
        source = source or """
            #include <unistd.h>
            int netvfs_version(void);
            const void *nvb_ffi_get(void) { return netvfs_version() + getpid() ? "" : 0; }
            """
        c_file = self.write("ffi.c", textwrap.dedent(source))
        so_file = os.path.join(self.work, "libnetvfs-bridge-ffi.so")
        command = ["cc", "-shared", "-fPIC", "-o", so_file, c_file, *flags]
        if exports:
            command.append("-Wl,--version-script=" + os.path.join(self.work, "exports.map"))
        if netvfs:
            command += ["-L" + self.work, "-l:libnetvfs.so.1"]
        subprocess.run(command, check=True)
        return so_file

    def run_check(self, so_file, max_glibc="99.0", bridge=None, installed=FFI_INSTALLED):
        result = subprocess.run([CHECK_FFI_LIB, so_file, installed, bridge or self.bridge, max_glibc],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return result.returncode, result.stdout

    def assert_fails(self, text, so_file, **kwargs):
        code, output = self.run_check(so_file, **kwargs)
        self.assertEqual(code, 1, output)
        self.assertIn(text, output)

    def test_hardened_library_passes(self):
        code, output = self.run_check(self.build())
        self.assertEqual(code, 0, output)
        self.assertIn("exports nvb_ffi_get, links libnetvfs.so.1", output)

    def test_second_export_fails(self):
        so_file = self.build("""
            #include <unistd.h>
            int netvfs_version(void);
            int nvb_extra(void) { return netvfs_version() + getpid(); }
            const void *nvb_ffi_get(void) { return nvb_extra() ? "" : 0; }
            """, exports=False)
        self.assert_fails('exports "nvb_extra nvb_ffi_get", expected only nvb_ffi_get', so_file)

    def test_no_libnetvfs_fails(self):
        so_file = self.build("const void *nvb_ffi_get(void) { return \"\"; }\n",
                             netvfs=False)
        self.assert_fails("does not link libnetvfs.so.1", so_file)

    def test_newer_glibc_fails(self):
        self.assert_fails("needs GLIBC_", self.build(), max_glibc="2.0")

    def test_lazy_binding_fails(self):
        self.assert_fails("does not bind now", self.build(flags=("-Wl,-z,relro", "-Wl,-z,lazy")))

    def test_no_relro_fails(self):
        self.assert_fails("no RELRO", self.build(flags=("-Wl,-z,norelro", "-Wl,-z,now")))

    def test_executable_stack_fails(self):
        self.assert_fails("executable stack",
                          self.build(flags=("-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,execstack")))

    def test_bridge_looking_elsewhere_fails(self):
        bridge = self.write("other-bridge", "\0loads /usr/lib/netvfs/libnetvfs-bridge-ffi.so\0")
        self.assert_fails("does not load it from " + FFI_INSTALLED, self.build(), bridge=bridge)


RS_INSTALLED = "/usr/lib64/netvfs/libnetvfs-rs.so"


class CheckRsLib(unittest.TestCase):
    """A library that exports nvr_get only and links only the C runtime, and
    plugins that name its installed path."""

    def setUp(self):
        self.work = tempfile.mkdtemp()
        self.write("other.c", "int other_version(void) { return 1; }\n")
        subprocess.run(["cc", "-shared", "-fPIC", "-Wl,-soname,libother.so.1", "-o",
                        os.path.join(self.work, "libother.so.1"), os.path.join(self.work, "other.c")],
                       check=True)
        self.write("exports.map", "{ global: nvr_get; local: *; };\n")
        self.plugin = self.write("libnetvfs-sftp.so", "\0loads " + RS_INSTALLED + "\0")

    def tearDown(self):
        shutil.rmtree(self.work)

    def write(self, name, text):
        path = os.path.join(self.work, name)
        with open(path, "w", encoding="utf-8") as file:
            file.write(text)
        return path

    def build(self, source=None, flags=("-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,noexecstack"),
              exports=True, libs=("-lm",)):
        source = source or """
            #include <math.h>
            #include <unistd.h>
            const void *nvr_get(void) { return sqrt((double)getpid()) > 0 ? "" : 0; }
            """
        c_file = self.write("rs.c", textwrap.dedent(source))
        so_file = os.path.join(self.work, "libnetvfs-rs.so")
        command = ["cc", "-shared", "-fPIC", "-o", so_file, c_file, *flags, "-L" + self.work, "-Wl,--no-as-needed",
                   *libs]
        if exports:
            command.append("-Wl,--version-script=" + os.path.join(self.work, "exports.map"))
        subprocess.run(command, check=True)
        return so_file

    def run_check(self, so_file, max_glibc="99.0", plugins=None, installed=RS_INSTALLED):
        plugins = [self.plugin] if plugins is None else plugins
        result = subprocess.run([CHECK_RS_LIB, so_file, max_glibc, installed, *plugins],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        return result.returncode, result.stdout

    def assert_fails(self, text, so_file, **kwargs):
        code, output = self.run_check(so_file, **kwargs)
        self.assertEqual(code, 1, output)
        self.assertIn(text, output)

    def test_hardened_library_passes(self):
        code, output = self.run_check(self.build())
        self.assertEqual(code, 0, output)
        self.assertIn("exports nvr_get, links libm.so.6 libc.so.6", output)
        self.assertIn("loaded from " + RS_INSTALLED + " by 1 plugin(s)", output)

    def test_no_plugin_yet_passes(self):
        code, output = self.run_check(self.build(), plugins=[])
        self.assertEqual(code, 0, output)
        self.assertIn("by 0 plugin(s)", output)

    def test_second_export_fails(self):
        so_file = self.build("""
            int nvr_extra(void) { return 1; }
            const void *nvr_get(void) { return nvr_extra() ? "" : 0; }
            """, exports=False)
        self.assert_fails('exports "nvr_extra nvr_get", expected only nvr_get', so_file)

    def test_other_library_fails(self):
        self.assert_fails("links libother.so.1", self.build(libs=("-l:libother.so.1",)))

    def test_newer_glibc_fails(self):
        self.assert_fails("needs GLIBC_", self.build(), max_glibc="2.0")

    def test_lazy_binding_fails(self):
        self.assert_fails("does not bind now", self.build(flags=("-Wl,-z,relro", "-Wl,-z,lazy")))

    def test_no_relro_fails(self):
        self.assert_fails("no RELRO", self.build(flags=("-Wl,-z,norelro", "-Wl,-z,now")))

    def test_executable_stack_fails(self):
        self.assert_fails("executable stack",
                          self.build(flags=("-Wl,-z,relro", "-Wl,-z,now", "-Wl,-z,execstack")))

    def test_plugin_looking_elsewhere_fails(self):
        elsewhere = self.write("libnetvfs-smb.so", "\0loads /usr/lib/netvfs/libnetvfs-rs.so\0")
        self.assert_fails("libnetvfs-smb.so does not load it from " + RS_INSTALLED, self.build(),
                          plugins=[self.plugin, elsewhere])


if __name__ == "__main__":
    unittest.main()
