#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
import ast
import functools
import io
import re
import subprocess
import sys
import tokenize

PROJECT = "netvfs"
EXCLUDED_PREFIXES = (
    "vendor/",
    "rust/vendor/",
    "doc/",
    "art/",
    "translations/",
    "tests/bridge/generator/golden/",
    "tests/bridge/generator/consumers/",
    ".github/codeql/rust-queries/HardcodedCryptographicValue.ql",
)
EXCLUDED_PARTS = ("/testdata/", "/tests/data/", "/corpus/", "/fixtures/")
NAMED = {"Makefile": "make", ".qmake.conf": "make", ".gitignore": "line"}
EXTENSIONS = {
    ".rs": "rust", ".qml": "js", ".js": "js", ".cpp": "cpp", ".h": "cpp", ".c": "cpp", ".map": "cpp",
    ".sh": "sh", ".py": "py", ".pro": "make", ".pri": "make", ".xml": "xml",
    ".toml": "hash", ".yml": "hash", ".yaml": "hash", ".qls": "hash",
    ".spec": "line", ".desktop": "line", ".properties": "line", ".conf": "line",
}
PUBLIC_API_XML = ("tests/bridge/contract/org.netvfs.Bridge1.xml", "rust/netvfs-bridge-proto/org.netvfs.Bridge1.xml")

SPDX = re.compile(r"^(//|#|/\*|<!--) SPDX-License-Identifier: [\w.+-]+( OR [\w.+-]+)*( \*/| -->)?$")
SPDX_PREFIX = re.compile(r"^(// SPDX-License-Identifier: [\w.+-]+)\s")
NOSONAR = "// NOSONAR"
LUPDATE = re.compile(r"^//% ")
SAFETY_COMMENT = re.compile(r"(?m)^[ \t]*// SAFETY: [^\n]*\n(?:[ \t]*//(?![/!])[^\n]*\n)*")
RUST_DOC = re.compile(r"(?m)^[ \t]*///(?!/)[^\n]*\n(?:[ \t]*///(?!/)[^\n]*\n)*")
FIELD = re.compile(r"r?#?[a-z_][a-z0-9_]*\s*:")
BLOCK_KIND = re.compile(r"\b(trait|enum)\b")
PUBLIC_HEADERS = re.compile(r"PUBLIC_HEADERS = \\\n((?:[ \t]+\S+(?: \\)?\n)+)")


def allowed(path, text, start, end):
    if base_allowed(path, text, start, end) or in_attribution_header(path, text, start):
        return True
    lang = language(path)
    if lang == "rust":
        return rust_api_or_safety(text, start, end)
    return (lang == "cpp" and path in public_headers()) or (lang == "xml" and path in PUBLIC_API_XML)


def rust_api_or_safety(text, start, end):
    if text.startswith("//!", start) or in_match(SAFETY_COMMENT, text, start):
        return True
    return in_match(RUST_DOC, text, start) and api_item_follows(text, end)


def in_attribution_header(path, text, start):
    end = 0
    for s, e in comments(path, text):
        if text[end:s].strip():
            break
        end = e
    return start < end and "SPDX-FileCopyrightText" in text[:end]


def in_match(pattern, text, start):
    return any(m.start() <= start < m.end() for m in pattern.finditer(text))


def api_item_follows(text, start):
    lines = (line.strip() for line in text[start:].split("\n"))
    item = next((line for line in lines if line and not line.startswith(("///", "#["))), "")
    kind = enclosing_kind(text, start)
    if item.startswith("pub ") or kind == "trait":
        return True
    return kind == "enum" if FIELD.match(item) else item[:1].isupper()


def enclosing_kind(text, start):
    code = list(text[:start])
    for s, e in comments_and_literals(text[:start]):
        code[s:e] = " " * (e - s)
    code = "".join(code)
    stack = []
    for m in re.finditer(r"[{}]", code):
        if m.group() == "}":
            stack = stack[:-1]
            continue
        found = BLOCK_KIND.search(code[code.rfind("\n", 0, m.start()) + 1 : m.start()])
        inherited = "enum" if stack and stack[-1] == "enum" else ""
        stack.append(found.group(1) if found else inherited)
    return stack[-1] if stack else ""


def comments_and_literals(text):
    scanner, literals = CScanner(text, "rust"), []
    plain_literal = scanner.literal

    def literal(end, kind='"'):
        literals.append((scanner.i, end))
        return plain_literal(end, kind)

    scanner.literal = literal
    return scanner.run() + literals


@functools.lru_cache(maxsize=1)
def public_headers():
    try:
        with open("src/core/core.pro", encoding="utf-8") as f:
            m = PUBLIC_HEADERS.search(f.read())
    except OSError:
        m = None
    return {"src/core/" + h for h in re.findall(r"(\S+\.h)", m.group(1))} if m else set()


QUOTE_RE = re.compile(r"""'(\\(u\{[0-9a-fA-F]+\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'""")
RUST_RAW = re.compile(r'(?:br|cr|r)(#*)"')
CPP_RAW = re.compile(r'R"([^()\\ ]{0,16})\(')
HEREDOC = re.compile(r"<<-?\s*['\"]?(\w+)['\"]?")
REGEX_BEFORE = set("(,=:[!&|?{};+-*%<>~^") | {"", "return", "typeof", "case", "in"}
HASH_BEFORE = {" ", "\t"}
SHELL_HASH_BEFORE = {" ", "\t", ";", "(", "|", "&"}


def language(path):
    name = path.rsplit("/", 1)[-1]
    if name in NAMED:
        return NAMED[name]
    if name.startswith("Dockerfile"):
        return "line"
    if name.endswith(".xml.in"):
        return "xml"
    ext = "." + name.rsplit(".", 1)[-1] if "." in name else ""
    return EXTENSIONS.get(ext)


def ident(c):
    return c.isalnum() or c == "_"


def close_of(text, i, close):
    j = text.find(close, i)
    return len(text) if j < 0 else j + len(close)


class CScanner:
    def __init__(self, text, lang):
        self.text, self.lang = text, lang
        self.i, self.prev, self.out = 0, "", []

    def run(self):
        steps = (self.line_comment, self.block_comment, self.rust_raw, self.cpp_raw, self.digit_separator,
                 self.quoted, self.rust_char, self.regex)
        while self.i < len(self.text):
            if not any(step() for step in steps):
                self.plain()
        return self.out

    def at(self, s):
        return self.text.startswith(s, self.i)

    def comment(self, end):
        self.out.append((self.i, end))
        self.i = end
        return True

    def literal(self, end, kind='"'):
        self.i, self.prev = end, kind
        return True

    def line_comment(self):
        if not self.at("//"):
            return False
        j = self.text.find("\n", self.i)
        return self.comment(len(self.text) if j < 0 else j)

    def block_comment(self):
        if not self.at("/*"):
            return False
        depth, j = 1, self.i + 2
        while j < len(self.text) and depth:
            if self.lang == "rust" and self.text.startswith("/*", j):
                depth, j = depth + 1, j + 2
            elif self.text.startswith("*/", j):
                depth, j = depth - 1, j + 2
            else:
                j += 1
        return self.comment(j)

    def word_start(self):
        return self.i == 0 or not ident(self.text[self.i - 1])

    def rust_raw(self):
        m = self.lang == "rust" and self.word_start() and RUST_RAW.match(self.text, self.i)
        return bool(m) and self.literal(close_of(self.text, m.end(), '"' + m.group(1)))

    def cpp_raw(self):
        m = self.lang == "cpp" and self.word_start() and CPP_RAW.match(self.text, self.i)
        return bool(m) and self.literal(close_of(self.text, m.end(), ")" + m.group(1) + '"'))

    def digit_separator(self):
        if self.lang == "cpp" and self.at("'") and self.i > 0 and self.text[self.i - 1].isalnum():
            self.i += 1
            return True
        return False

    def quoted(self):
        c = self.text[self.i]
        if not (c == '"' or (self.lang != "rust" and c in "'`")):
            return False
        j = self.i + 1
        while j < len(self.text) and self.text[j] != c:
            j += 2 if self.text[j] == "\\" else 1
        return self.literal(j + 1, c)

    def rust_char(self):
        if self.lang != "rust" or not self.at("'"):
            return False
        m = QUOTE_RE.match(self.text, self.i)
        return self.literal(m.end() if m else self.i + 1, "'")

    def regex(self):
        if self.lang != "js" or not self.at("/") or self.prev not in REGEX_BEFORE:
            return False
        j, klass = self.i + 1, False
        while j < len(self.text) and self.text[j] != "\n":
            c = self.text[j]
            if c == "\\":
                j += 1
            elif c == "[" or c == "]":
                klass = c == "["
            elif c == "/" and not klass:
                break
            j += 1
        return self.literal(j + 1, "/")

    def plain(self):
        c = self.text[self.i]
        if ident(c):
            j = self.i
            while j < len(self.text) and ident(self.text[j]):
                j += 1
            self.prev, self.i = self.text[self.i : j], j
            return
        if not c.isspace():
            self.prev = c
        self.i += 1


def line_offsets(text):
    offset = 0
    for line in text.split("\n"):
        yield offset, line
        offset += len(line) + 1


def next_quote(c, quote, quotes):
    if quote:
        return None if c == quote else quote
    return c if c in quotes else None


def hash_at(line, before, quotes, escapes):
    quote, i = None, 0
    while i < len(line):
        c = line[i]
        if c == "\\" and (escapes or quote == '"'):
            i += 2
            continue
        if quote or c in quotes:
            quote = next_quote(c, quote, quotes)
        elif c == "#" and (i == 0 or line[i - 1] in before):
            return i
        i += 1
    return None


def hash_comments(text, quotes="'\"", escapes=False):
    out = []
    for offset, line in line_offsets(text):
        i = hash_at(line, HASH_BEFORE, quotes, escapes)
        if i is not None:
            out.append((offset + i, offset + len(line)))
    return out


def heredoc_at(line, i):
    return HEREDOC.match(line, i) if line.startswith("<<", i) else None


def shell_line(line, quote):
    i, heredoc = 0, None
    while i < len(line):
        c = line[i]
        if c == "\\" and quote != "'":
            i += 2
            continue
        m = None if quote else heredoc_at(line, i)
        if quote or c in "'\"":
            quote = next_quote(c, quote, "'\"")
        elif c == "#" and (i == 0 or line[i - 1] in SHELL_HASH_BEFORE):
            return i, quote, heredoc
        elif m:
            heredoc = m.group(1)
        i += 1
    return None, quote, heredoc


def shell_comments(text):
    out, quote, heredoc = [], None, None
    for offset, line in line_offsets(text):
        if heredoc is not None:
            heredoc = None if line.lstrip("\t") == heredoc else heredoc
            continue
        i, quote, heredoc = shell_line(line, quote)
        if i is not None:
            out.append((offset + i, offset + len(line)))
    return out


def line_comments(text):
    out = []
    for offset, line in line_offsets(text):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            out.append((offset + len(line) - len(stripped), offset + len(line)))
    return out


def xml_comments(text):
    out, i = [], text.find("<!--")
    while i >= 0:
        end = close_of(text, i, "-->")
        out.append((i, end))
        i = text.find("<!--", end)
    return out


def docstring(node):
    if not isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) or not node.body:
        return None
    first = node.body[0]
    is_text = isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str)
    return first if is_text else None


def python_comments(text):
    starts = [offset for offset, _ in line_offsets(text)]
    out = [(starts[t.start[0] - 1] + t.start[1], starts[t.end[0] - 1] + t.end[1])
           for t in tokenize.generate_tokens(io.StringIO(text).readline) if t.type == tokenize.COMMENT]
    for node in ast.walk(ast.parse(text)):
        d = docstring(node)
        if d is not None:
            out.append((starts[d.lineno - 1] + d.col_offset, starts[d.end_lineno - 1] + d.end_col_offset))
    return sorted(out)


def sole_docstrings(text):
    starts = [offset for offset, _ in line_offsets(text)]
    return {starts[node.body[0].lineno - 1] + node.body[0].col_offset for node in ast.walk(ast.parse(text))
            if not isinstance(node, ast.Module) and docstring(node) is not None and len(node.body) == 1}


SCANNERS = {
    "rust": lambda t: CScanner(t, "rust").run(),
    "js": lambda t: CScanner(t, "js").run(),
    "cpp": lambda t: CScanner(t, "cpp").run(),
    "sh": shell_comments,
    "py": python_comments,
    "hash": hash_comments,
    "make": lambda t: hash_comments(t, quotes="", escapes=True),
    "line": line_comments,
    "xml": xml_comments,
}


@functools.lru_cache(maxsize=4)
def comments(path, text):
    lang = language(path)
    return SCANNERS[lang](text) if lang else []


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def header_line(text, start):
    line = text.count("\n", 0, start)
    return line == 0 or (line == 1 and text.startswith(("#!", "<?xml")))


def base_allowed(path, text, start, end):
    body = text[start:end]
    if start == 0 and body.startswith("#!"):
        return True
    if header_line(text, start) and SPDX.match(body):
        return True
    return body == NOSONAR or (language(path) in ("js", "cpp") and LUPDATE.match(body) is not None)


def offences(path, text):
    return [(s, e) for s, e in comments(path, text) if not allowed(path, text, s, e)]


def replacement(path, text, start, end):
    body = text[start:end]
    if body.startswith(NOSONAR):
        return NOSONAR
    if language(path) == "py" and start in sole_docstrings(text):
        return "pass"
    m = SPDX_PREFIX.match(body)
    return m.group(1) if m and start == 0 else ""


def remove(path, text):
    pieces, pos, touched = [], 0, set()
    for s, e in comments(path, text):
        if allowed(path, text, s, e):
            continue
        keep = replacement(path, text, s, e)
        pieces += [text[pos:s], keep + "\n" * (text.count("\n", s, e) - keep.count("\n"))]
        touched.update(range(text.count("\n", 0, s), text.count("\n", 0, e) + 1))
        pos = e
    pieces.append(text[pos:])
    return "".join(pieces), touched


def strip(path, text):
    new, touched = remove(path, text)
    result, gaps = [], set()
    for idx, line in enumerate(new.split("\n")):
        if idx in touched and not line.strip():
            gaps.add(len(result))
            continue
        result.append(line.rstrip() if idx in touched else line)
    return "\n".join(tidy_blank(result, gaps))


def redundant_blank(prev, nxt):
    if prev is None or not prev.strip():
        return True
    return prev.rstrip().endswith(("{", "[", "(")) or (nxt is not None and nxt.strip().startswith(("}", "]", ")")))


def tidy_blank(lines, gaps):
    out = []
    for idx, line in enumerate(lines):
        at_gap = idx in gaps or idx + 1 in gaps
        nxt = lines[idx + 1] if idx + 1 < len(lines) else None
        if not line.strip() and at_gap and redundant_blank(out[-1] if out else None, nxt):
            continue
        out.append(line)
    while len(out) > 1 and out[-1] == "" and out[-2] == "":
        out.pop()
    return out


def checked(path):
    return not path.startswith(EXCLUDED_PREFIXES) and not any(p in "/" + path for p in EXCLUDED_PARTS)


def tracked():
    files = subprocess.run(["git", "ls-files", "-z"], capture_output=True, check=True).stdout.decode()
    return [p for p in files.split("\0") if p and checked(p) and language(p)]


def fix(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    new = strip(path, text)
    if new != text:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)


def report(path):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    found = offences(path, text)
    for s, e in found:
        print(f"{path}:{line_of(text, s)}: {text[s:e].splitlines()[0][:80]}")
    return len(found)


def main(argv):
    wanted = set(argv[1:] if argv[:1] == ["--fix"] else argv)
    paths = [p for p in tracked() if not wanted or p in wanted]
    if argv[:1] == ["--fix"]:
        for path in paths:
            fix(path)
        return 0
    bad = sum(report(path) for path in paths)
    if bad:
        print(f"no-comments: {bad} comment(s); {PROJECT} has no code comments (AGENTS.md).", file=sys.stderr)
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
