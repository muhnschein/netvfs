#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
"""Checks the %files sections of the RPM spec against an install tree
(SPEC-v2 XP-1): every installed file belongs to exactly one package, every
%files entry matches something, and every netvfs directory is owned by
exactly one package. rpmbuild only reports unpackaged files; this runs on the
host build in seconds and also finds files listed in two packages.

The spec is read with the Sailfish OS macro values (%{_libdir} is /usr/lib64
...). A host install puts libraries elsewhere: --map rewrites install paths
before the comparison, e.g. --map /usr/lib/x86_64-linux-gnu=/usr/lib64.

Usage:
  tools/ci/check-files.py [--spec FILE] [--map FROM=TO]... [--with NAME]...
                          [--without NAME]... [--allow-missing GLOB]...
                          [--list] ROOT
ROOT is an install tree (make install INSTALL_ROOT=ROOT). --allow-missing
names %files entries the host build does not install (fnmatch, matched
against the entry with its macros expanded). --list prints every package
with its files.
"""
import argparse
import fnmatch
import os
import re
import sys

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# rpm macros of the Sailfish OS 5.2 target that the spec may use.
SAILFISH_MACROS = {
    "_prefix": "/usr",
    "_exec_prefix": "/usr",
    "_bindir": "/usr/bin",
    "_sbindir": "/usr/sbin",
    "_libdir": "/usr/lib64",
    "_libexecdir": "/usr/libexec",
    "_datadir": "/usr/share",
    "_includedir": "/usr/include",
    "_sysconfdir": "/etc",
    "_localstatedir": "/var",
    "_unitdir": "/usr/lib/systemd/system",
    "_userunitdir": "/usr/lib/systemd/user",
    "nil": "",
}

SECTIONS = {
    "package", "description", "prep", "build", "install", "check", "clean",
    "files", "changelog", "pre", "post", "preun", "postun", "pretrans",
    "posttrans", "verifyscript", "triggerin", "triggerun", "triggerpostun",
    "filetriggerin", "filetriggerun", "transfiletriggerin", "transfiletriggerun",
}

# Words of %files lines and conditionals that are not macros.
DIRECTIVES = {
    "dir", "doc", "license", "ghost", "exclude", "defattr", "docdir", "attr", "verify",
    "lang", "caps", "config", "artifact", "missingok", "if", "else", "endif",
}

# Attributes of a %files line that do not change which path it names.
ATTRIBUTE = re.compile(r"%(?:attr|verify|lang|caps|config)\([^)]*\)\s*|"
                       r"%(?:config|artifact|missingok)\b\s*")
MACRO = re.compile(r"%\{([?!]*)([A-Za-z_][A-Za-z0-9_]*)(?:\s+([^}]*))?\}|%([A-Za-z_][A-Za-z0-9_]*)")


class SpecError(Exception):
    """A spec construct this checker does not understand."""


class Spec:
    """The %files sections of a spec: {package: [(kind, pattern)]} with kind
    "file", "dir" (%dir), "ghost" or "exclude"."""

    def __init__(self, conditions):
        self.macros = dict(SAILFISH_MACROS)
        self.conditions = conditions
        self.files = {}
        self.packages = []
        self._stack = []
        self._section = None

    def expand(self, text, depth=0):
        if depth > 20:
            raise SpecError("macro recursion in: " + text)
        expanded = MACRO.sub(self._macro, text)
        return expanded if expanded == text else self.expand(expanded, depth + 1)

    def _macro(self, match):
        flags, name, arg, bare = match.group(1) or "", match.group(2), match.group(3), match.group(4)
        if bare:
            name = bare
        if name in ("with", "without") and arg:
            enabled = self.conditions.get(arg.strip(), False)
            return "1" if enabled == (name == "with") else "0"
        if name in self.macros:
            return "" if "!" in flags else self.macros[name]
        if "?" in flags:
            return ""
        if bare and name in SECTIONS | DIRECTIVES:
            return match.group(0)
        raise SpecError("unknown macro: " + match.group(0))

    def active(self):
        return all(self._stack)

    def read(self, path):
        with open(path, encoding="utf-8") as spec:
            for number, line in enumerate(spec, 1):
                try:
                    self._line(line.rstrip("\n"))
                except SpecError as error:
                    raise SpecError(f"{path}:{number}: {error}") from None
        if self._stack:
            raise SpecError(f"{path}: %if without %endif")
        return self

    def _line(self, line):
        stripped = line.strip()
        if self._conditional(stripped) or not self.active():
            return
        if stripped.startswith("%bcond_with ") or stripped.startswith("%bcond_without "):
            self._bcond(stripped.split())
            return
        if self._definition(stripped):
            return
        word = re.match(r"%([a-z]+)\b", stripped)
        if word and word.group(1) in SECTIONS:
            self._start_section(word.group(1), stripped)
        elif self._section is not None and stripped and not stripped.startswith("#"):
            self._file_line(stripped)

    def _conditional(self, stripped):
        if stripped.startswith("%if ") or stripped.startswith("%if\t"):
            self._stack.append(self.active() and self._evaluate(stripped[3:]))
        elif stripped == "%else" or stripped.startswith("%else "):
            if not self._stack:
                raise SpecError("%else without %if")
            outer = all(self._stack[:-1])
            self._stack[-1] = outer and not self._stack[-1]
        elif stripped == "%endif" or stripped.startswith("%endif "):
            if not self._stack:
                raise SpecError("%endif without %if")
            self._stack.pop()
        else:
            return False
        return True

    def _evaluate(self, expression):
        value = self.expand(expression).strip()
        negate = value.startswith("!")
        if negate:
            value = value[1:].strip()
        if not re.fullmatch(r"\d+", value):
            raise SpecError("unsupported %if expression: " + expression.strip())
        return (int(value) != 0) != negate

    def _bcond(self, words):
        name = words[1]
        if name not in self.conditions:
            self.conditions[name] = words[0] == "%bcond_without"

    def _definition(self, stripped):
        definition = re.match(r"%(?:define|global)\s+(\w+)\s+(.*)", stripped)
        if definition:
            self.macros[definition.group(1)] = definition.group(2)
            return True
        tag = re.match(r"(Name|Version|Release):\s*(\S+)", stripped)
        if tag and self._section is None:
            self.macros[tag.group(1).lower()] = self.expand(tag.group(2))
            return True
        return False

    def _start_section(self, name, stripped):
        self._section = None
        if name != "files":
            return
        words = self.expand(stripped).split()[1:]
        package = self.macros["name"]
        while words:
            word = words.pop(0)
            if word == "-n":
                package = words.pop(0)
            elif word == "-f":
                raise SpecError("%files -f lists cannot be checked")
            else:
                package = self.macros["name"] + "-" + word
        if package in self.files:
            raise SpecError("second %files section for " + package)
        self._section = package
        self.packages.append(package)
        self.files[package] = []

    def _file_line(self, stripped):
        line = ATTRIBUTE.sub("", self.expand(stripped)).strip()
        kind = "file"
        for directive, meaning in (("%dir", "dir"), ("%ghost", "ghost"), ("%exclude", "exclude"),
                                   ("%doc", "doc"), ("%license", "doc")):
            if line.startswith(directive + " "):
                kind, line = meaning, line[len(directive):].strip()
        if line.startswith("%defattr") or (kind == "doc" and not line.startswith("/")):
            return
        if not line.startswith("/"):
            raise SpecError("not an absolute path: " + stripped)
        for path in expand_braces(line):
            self.files[self._section].append(("file" if kind == "doc" else kind, path))


def expand_braces(pattern):
    """rpm's {a,b} alternatives in %files entries."""
    match = re.search(r"\{([^{}]*)\}", pattern)
    if not match:
        return [pattern]
    head, tail = pattern[:match.start()], pattern[match.end():]
    result = []
    for alternative in match.group(1).split(","):
        result.extend(expand_braces(head + alternative + tail))
    return result


class Tree:
    """The install tree, with paths as they are on the target."""

    def __init__(self, root, mappings):
        self.files = set()
        self.dirs = set()
        for directory, subdirs, names in os.walk(root):
            for name in subdirs:
                full = os.path.join(directory, name)
                target = self._target(full, root, mappings)
                (self.files if os.path.islink(full) else self.dirs).add(target)
            for name in names:
                self.files.add(self._target(os.path.join(directory, name), root, mappings))

    @staticmethod
    def _target(full, root, mappings):
        path = "/" + os.path.relpath(full, root)
        for source, destination in mappings:
            if path == source or path.startswith(source + "/"):
                return destination + path[len(source):]
        return path

    def glob(self, pattern):
        parts = pattern.split("/")
        return sorted(path for path in self.files | self.dirs
                      if len(path.split("/")) == len(parts)
                      and all(fnmatch.fnmatchcase(p, q) for p, q in zip(path.split("/"), parts)))

    def below(self, directory):
        prefix = directory + "/"
        return [path for path in self.files | self.dirs if path.startswith(prefix)]


class Ownership:
    """Which packages own each path of the tree."""

    def __init__(self, spec, tree, allow_missing):
        self.owners = {}
        self.problems = []
        for package in spec.packages:
            self._package(package, spec.files[package], tree, allow_missing)

    def _package(self, package, entries, tree, allow_missing):
        claimed = set()
        excluded = set()
        for kind, pattern in entries:
            matches = tree.glob(pattern)
            if not matches and kind not in ("ghost", "exclude") \
                    and not any(fnmatch.fnmatchcase(pattern, glob) for glob in allow_missing):
                self.problems.append(f"{package}: {pattern} matches nothing in the install tree")
            for path in matches:
                target = excluded if kind == "exclude" else claimed
                target.add(path)
                if kind not in ("dir", "exclude") and path in tree.dirs:
                    target.update(tree.below(path))
        for path in sorted(claimed - excluded):
            self.owners.setdefault(path, []).append(package)

    def check(self, tree):
        for path in sorted(tree.files):
            self._expect_one(path, self.owners.get(path, []), "file")
        for path in sorted(tree.dirs):
            if any(part.startswith("netvfs") for part in path.split("/")):
                self._expect_one(path, self.owners.get(path, []), "directory")
        return self.problems

    def _expect_one(self, path, owners, what):
        if not owners:
            self.problems.append(f"{what} {path} is in no package")
        elif len(owners) > 1:
            self.problems.append(f"{what} {path} is in several packages: {', '.join(owners)}")


def parse_arguments(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("root")
    parser.add_argument("--spec", default=os.path.join(ROOT_DIR, "rpm", "netvfs.spec"))
    parser.add_argument("--map", action="append", default=[], metavar="FROM=TO")
    parser.add_argument("--with", dest="with_", action="append", default=[], metavar="NAME")
    parser.add_argument("--without", action="append", default=[], metavar="NAME")
    parser.add_argument("--allow-missing", action="append", default=[], metavar="GLOB")
    parser.add_argument("--list", action="store_true")
    return parser.parse_args(argv)


def main(argv):
    args = parse_arguments(argv)
    conditions = {name: True for name in args.with_}
    conditions.update({name: False for name in args.without})
    mappings = [tuple(mapping.rstrip("/").split("=", 1)) for mapping in args.map]
    if not os.path.isdir(args.root):
        print(f"{args.root}: not a folder", file=sys.stderr)
        return 2
    try:
        spec = Spec(conditions).read(args.spec)
    except SpecError as error:
        print(error, file=sys.stderr)
        return 2
    tree = Tree(args.root, mappings)
    ownership = Ownership(spec, tree, args.allow_missing)
    problems = ownership.check(tree)
    if args.list:
        for package in spec.packages:
            print(package)
            for path in sorted(p for p, owners in ownership.owners.items() if package in owners):
                print("    " + path)
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"{len(spec.packages)} packages, {len(tree.files)} files, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
