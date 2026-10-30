"""code-triage: a tiny static scanner for Python.

Walks the AST and flags patterns that are almost always a bug, not a
style choice. No LLM, no network, no dependencies — this is the part that
actually matters, because if a dumb pattern matcher can't catch it, you
should know that before you pay a model to look.

Usage: see cli.py, or call scan_source(code) directly.
"""

import ast
import re
from dataclasses import dataclass, field


@dataclass
class Finding:
    rule: str
    severity: str  # high | medium | low
    line: int
    message: str
    snippet: str = ""

    def __str__(self):
        return f"{self.rule} [{self.severity}] line {self.line}: {self.message}"


_SECRET_NAME = re.compile(r"(password|passwd|secret|api[_-]?key|access[_-]?token|token)", re.I)
_TOKEN_NAME = re.compile(r"(token|password|secret|api[_-]?key)", re.I)
_PLACEHOLDER = re.compile(r"(example|your-|xxx|changeme|placeholder|todo|dummy)", re.I)


def _is_const_str(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str)


def _is_tainted(node):
    """True if the value is built at runtime from something, not a literal.

    A plain string literal is safe-ish for our purposes (it's fixed text);
    anything composed — f-string, %, .format(), concat, variable — we
    treat as attacker-influenced. Hacky but works: over-flagging a
    composed query is the safe direction for a scanner.
    """
    if _is_const_str(node):
        return False
    return isinstance(
        node,
        (ast.BinOp, ast.JoinedStr, ast.FormattedValue, ast.Call, ast.Name,
         ast.Subscript, ast.Attribute),
    )


def _dotted(node):
    """'a.b.c' for Attribute/Name chains, else ''."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Visitor(ast.NodeVisitor):
    def __init__(self, lines):
        self.lines = lines
        self.findings = []

    def _add(self, rule, severity, node, message):
        snippet = ""
        if 1 <= node.lineno <= len(self.lines):
            snippet = self.lines[node.lineno - 1].strip()
        self.findings.append(Finding(rule, severity, node.lineno, message, snippet))

    # --- calls: the bulk of the rules live here ---
    def visit_Call(self, node):
        name = _dotted(node.func)

        # SQL injection: execute() with a composed query and no parameters.
        if name.endswith((".execute", ".executemany", ".executescript")) or name == "execute":
            if node.args and _is_tainted(node.args[0]) and len(node.args) == 1:
                self._add("sql-injection", "high", node,
                          "query string built at runtime and passed without parameters")
        elif name == "eval" or name == "exec":
            if node.args and _is_tainted(node.args[0]):
                self._add("code-exec", "high", node,
                          f"{name}() on a non-constant value")
        elif name == "os.system":
            if node.args and _is_tainted(node.args[0]):
                self._add("shell-injection", "high", node,
                          "os.system() with a composed command string")
        elif name.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("shell-injection", "high", node,
                              "subprocess with shell=True")
        elif name in ("pickle.load", "pickle.loads", "marshal.load", "marshal.loads"):
            self._add("unsafe-deserialize", "high", node,
                     f"{name}() on untrusted data can run arbitrary code")
        elif name == "yaml.load":
            safe = any(kw.arg == "Loader" and "SafeLoader" in _dotted(kw.value)
                       for kw in node.keywords)
            if not safe:
                self._add("unsafe-deserialize", "high", node,
                          "yaml.load() without SafeLoader")
        elif name in ("hashlib.md5", "hashlib.sha1") or (
                name == "hashlib.new" and node.args
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value in ("md5", "sha1")):
            self._add("weak-crypto", "medium", node,
                     "MD5/SHA1 are broken for integrity — use sha256")
        elif name.startswith("requests.") and name.split(".")[-1] in (
                "get", "post", "put", "delete", "patch", "request"):
            for kw in node.keywords:
                if kw.arg == "verify" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
                    self._add("insecure-request", "medium", node,
                              "requests call with verify=False disables TLS checks")
        elif name in ("tarfile.extract", "tarfile.extractall") or name.endswith(".extractall"):
            if not any(kw.arg == "filter" for kw in node.keywords):
                self._add("unsafe-extract", "medium", node,
                          "tar extraction without filter= can write outside the target dir")
        elif name.endswith(".run"):
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
                    self._add("debug-mode", "medium", node,
                              "debug=True in production exposes a debugger console")

        self.generic_visit(node)

    # --- assignments: secrets and weak randomness live here ---
    def visit_Assign(self, node):
        for target in node.targets:
            if not isinstance(target, ast.Name):
                continue
            if _SECRET_NAME.search(target.id) and isinstance(node.value, ast.Constant) \
                    and isinstance(node.value.value, str) \
                    and len(node.value.value) >= 8 \
                    and not _PLACEHOLDER.search(node.value.value):
                self._add("hardcoded-secret", "medium", node,
                          f"credential assigned to '{target.id}' in source")
            if _TOKEN_NAME.search(target.id) and isinstance(node.value, ast.Call) \
                    and _dotted(node.value.func).startswith("random."):
                self._add("weak-random", "low", node,
                          "random module used to generate a security token — use secrets")
        self.generic_visit(node)


def scan_source(code, filename="<string>"):
    """Scan one Python source string. Returns a list of Findings."""
    try:
        tree = ast.parse(code, filename=filename)
    except SyntaxError as exc:
        return [Finding("parse-error", "low", exc.lineno or 0,
                        f"could not parse: {exc.msg}")]
    visitor = _Visitor(code.splitlines())
    visitor.visit(tree)
    return sorted(visitor.findings, key=lambda f: f.line)


def scan_file(path):
    with open(path, encoding="utf-8") as fh:
        return scan_source(fh.read(), filename=str(path))
