"""AST-based taint-tracking detector for Python samples.

Where the heuristic baseline matches *lines of text*, this detector parses
the sample into an abstract syntax tree and tracks **provenance**: where
each value came from, and whether tainted data can reach a dangerous sink.

Model in brief (see ``analyze`` for the implementation):

- **Sources** — function parameters (snippet analysis assumes caller input
  is attacker-controlled), ``input()``, ``request.*`` / ``sys.argv``
  access, values read back out of a database (``fetchone``/``fetchall`` —
  the second-order premise: stored data is not trusted), and HTTP response
  data (redirect targets come from the network, not from the programmer).
- **Propagation** — provenance flows through assignments, binary ops,
  f-strings and ``.format()``, subscripts/attributes, and generic calls.
  Calls to functions defined in the same file use *summaries*: the set of
  parameter labels that reach the callee's return value.
- **Facts, not just booleans** — each value carries its provenance set and
  a ``path_safe`` bit. ``os.path.basename()`` keeps a value tainted (it is
  still user data for a SQL sink) but marks it neutralized for path sinks.
  ``int()``/``float()`` casts sanitize outright.
- **Sinks** — ``execute``/``executemany`` with a tainted query and no
  parameter argument; file ``open`` of a tainted, not-path-safe path;
  fetches (``urlopen``, ``requests.*``) of a tainted URL whose provenance
  is not fully covered by a hostname-allowlist check in the same function
  (this is what catches unvalidated *redirect* targets: the initial URL's
  provenance was checked, the ``Location`` header's was not);
  ``pickle``/``marshal`` loads and ``yaml.load`` without ``SafeLoader`` on
  tainted data.

Deliberate scope limits (they show up as misses, and that is the point of
running two baselines):

- **Python only.** Java samples return no findings; Java needs a different
  front end, not more regexes.
- **Dataflow categories only** — SQL injection, SSRF, path traversal,
  insecure deserialization. Hardcoded credentials, weak cryptography and
  XXE are API-misuse patterns, not dataflow problems; the regex baseline
  covers them and this detector does not pretend to.
- Function summaries track provenance only, so path sanitization must
  happen in the same function as the ``open()`` sink to be credited.
- The analysis is intra-procedural with one level of summaries, processed
  statement-by-statement with a small fixpoint for returns; it is a
  teaching-grade analyzer, not a production SAST tool.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass

from ..dataset import Sample
from .base import Detector, Finding

# Intrinsic provenance labels (not tied to a parameter).
DB_READ = "db:read"
FETCH_RESPONSE = "fetch:response"
USER_INPUT = "input"
REQUEST = "request"
ARGV = "argv"

_RATIONALES = {
    "sql_injection": "Tainted data reaches a SQL execute() call without parameterization.",
    "path_traversal": "Tainted data reaches open() without basename/realpath confinement.",
    "ssrf": "Tainted URL reaches an HTTP fetch without an allowlist check covering its provenance.",
    "ssrf_redirect": (
        "A redirect target (response data) is fetched without re-validating its host — "
        "the allowlist check only covered the original URL."
    ),
    "insecure_deserialization": "Tainted data reaches an unsafe deserialization call.",
}


@dataclass(frozen=True)
class _Facts:
    """What the analyzer knows about one value."""

    prov: frozenset = frozenset()  # provenance labels; empty = clean
    path_safe: bool = True  # taint neutralized *for path sinks* (e.g. basename)

    @property
    def tainted(self) -> bool:
        return bool(self.prov)


_CLEAN = _Facts()
_TAINTED_UNSAFE_PATH = frozenset()


def _combine(a: _Facts, b: _Facts) -> _Facts:
    prov = a.prov | b.prov
    if not prov:
        return _CLEAN
    return _Facts(prov=prov, path_safe=a.path_safe and b.path_safe)


def _dotted(node: ast.expr) -> str | None:
    """Dotted name for Name/Attribute chains ('os.path.join'), else None."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _root_name(node: ast.expr) -> str | None:
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


_FETCH_ATTRS = {"get", "post", "put", "delete", "head", "request", "urlopen"}
_FETCH_ROOTS = {"requests", "urllib", "session", "http"}


class _Analyzer:
    def __init__(self, tree: ast.Module):
        self.tree = tree
        self.functions: dict[str, ast.FunctionDef] = {}
        self.summaries: dict[str, frozenset] = {}
        self.findings: list[tuple[str, int, frozenset]] = []
        self._validated: set[str] = set()  # provenance covered by host checks
        self._globals: dict[str, _Facts] = {}

    # -- driver ------------------------------------------------------------

    def run(self) -> list[tuple[str, int, frozenset]]:
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self.functions[node.name] = node

        # Module-level statements build the global environment (and can
        # contain sinks of their own).
        module_env: dict[str, _Facts] = {}
        returns: set[str] = set()
        for node in self.tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            self._exec_stmt(node, module_env, record=True, returns=returns)
        self._globals = module_env

        # Fixpoint over summaries (return-value provenance per function).
        for _ in range(3):
            changed = False
            for name, fn in self.functions.items():
                env = dict(self._globals)
                env.update(self._param_env(fn))
                self._validated = set()
                rets: set[str] = set()
                self._exec_body(fn.body, env, record=False, returns=rets)
                new = frozenset(rets)
                if self.summaries.get(name) != new:
                    self.summaries[name] = new
                    changed = True
            if not changed:
                break

        # Final pass with recording on.
        for fn in self.functions.values():
            env = dict(self._globals)
            env.update(self._param_env(fn))
            self._validated = set()
            rets = set()
            self._exec_body(fn.body, env, record=True, returns=rets)
        return self.findings

    @staticmethod
    def _param_env(fn: ast.FunctionDef) -> dict[str, _Facts]:
        env = {}
        args = fn.args
        positional = list(args.posonlyargs) + list(args.args)
        for arg in positional + list(args.kwonlyargs):
            env[arg.arg] = _Facts(prov=frozenset({f"param:{arg.arg}"}), path_safe=False)
        if args.vararg:
            env[args.vararg.arg] = _Facts(
                prov=frozenset({f"param:{args.vararg.arg}"}), path_safe=False
            )
        if args.kwarg:
            env[args.kwarg.arg] = _Facts(
                prov=frozenset({f"param:{args.kwarg.arg}"}), path_safe=False
            )
        return env

    # -- statements ----------------------------------------------------------

    def _exec_body(self, stmts, env, *, record, returns):
        for stmt in stmts:
            self._exec_stmt(stmt, env, record=record, returns=returns)

    def _merge_envs(self, *envs) -> dict[str, _Facts]:
        merged: dict[str, _Facts] = {}
        keys = set().union(*(e.keys() for e in envs)) if envs else set()
        for key in keys:
            facts = [e[key] for e in envs if key in e]
            prov = frozenset().union(*(f.prov for f in facts))
            if not prov:
                merged[key] = _CLEAN
            else:
                merged[key] = _Facts(
                    prov=prov, path_safe=all(f.path_safe for f in facts)
                )
        return merged

    def _bind(self, target: ast.expr, facts: _Facts, env) -> None:
        if isinstance(target, ast.Name):
            env[target.id] = facts
        elif isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self._bind(elt, facts, env)
        elif isinstance(target, ast.Starred):
            self._bind(target.value, facts, env)
        # Subscript/Attribute targets mutate an object; we don't track those.

    def _exec_stmt(self, node, env, *, record, returns) -> None:
        if isinstance(node, ast.Assign):
            facts = self._eval(node.value, env, record=record)
            for target in node.targets:
                self._bind(target, facts, env)
        elif isinstance(node, ast.AnnAssign):
            if node.value is not None:
                self._bind(
                    node.target, self._eval(node.value, env, record=record), env
                )
        elif isinstance(node, ast.AugAssign):
            facts = self._eval(node.value, env, record=record)
            if isinstance(node.target, ast.Name):
                env[node.target.id] = _combine(env.get(node.target.id, _CLEAN), facts)
        elif isinstance(node, ast.Expr):
            self._eval(node.value, env, record=record)
        elif isinstance(node, ast.Return):
            if node.value is not None:
                returns.update(self._eval(node.value, env, record=record).prov)
        elif isinstance(node, ast.If):
            self._eval(node.test, env, record=record)
            self._note_host_checks(node.test, env, record=record)
            body_env = dict(env)
            self._exec_body(node.body, body_env, record=record, returns=returns)
            else_env = dict(env)
            self._exec_body(node.orelse, else_env, record=record, returns=returns)
            env.clear()
            env.update(self._merge_envs(body_env, else_env))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            facts = self._eval(node.iter, env, record=record)
            loop_env = dict(env)
            self._bind(node.target, facts, loop_env)
            self._exec_body(node.body, loop_env, record=record, returns=returns)
            self._exec_body(node.orelse, loop_env, record=record, returns=returns)
            env.clear()
            env.update(self._merge_envs(env, loop_env))
        elif isinstance(node, ast.While):
            self._eval(node.test, env, record=record)
            body_env = dict(env)
            self._exec_body(node.body, body_env, record=record, returns=returns)
            env.clear()
            env.update(self._merge_envs(env, body_env))
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                facts = self._eval(item.context_expr, env, record=record)
                if item.optional_vars is not None:
                    self._bind(item.optional_vars, facts, env)
            self._exec_body(node.body, env, record=record, returns=returns)
        elif isinstance(node, ast.Try):
            self._exec_body(node.body, env, record=record, returns=returns)
            for handler in node.handlers:
                self._exec_body(handler.body, env, record=record, returns=returns)
            self._exec_body(node.orelse, env, record=record, returns=returns)
            self._exec_body(node.finalbody, env, record=record, returns=returns)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef,
                               ast.Import, ast.ImportFrom, ast.Pass, ast.Break,
                               ast.Continue, ast.Global, ast.Nonlocal)):
            pass  # definitions handled by the driver; the rest carry no data flow
        else:
            for child in ast.iter_child_nodes(node):
                if isinstance(child, ast.expr):
                    self._eval(child, env, record=record)
                elif isinstance(child, ast.stmt):
                    self._exec_stmt(child, env, record=record, returns=returns)

    def _note_host_checks(self, test: ast.expr, env, *, record) -> None:
        """Record provenance covered by a hostname/netloc allowlist check.

        A URL value is 'validated' for later fetch sinks iff every label in
        its provenance was the object of a ``.hostname``/``.netloc`` check
        somewhere in this function. Redirect targets fail this test because
        their provenance includes response data nobody checked.
        """
        for sub in ast.walk(test):
            if isinstance(sub, ast.Attribute) and sub.attr in ("hostname", "netloc"):
                facts = self._eval(sub.value, env, record=record)
                self._validated.update(facts.prov)

    # -- expressions ---------------------------------------------------------

    def _eval(self, node, env, *, record) -> _Facts:
        if node is None or isinstance(node, ast.Constant):
            return _CLEAN
        if isinstance(node, ast.Name):
            return env.get(node.id, _CLEAN)
        if isinstance(node, ast.BinOp):
            return _combine(
                self._eval(node.left, env, record=record),
                self._eval(node.right, env, record=record),
            )
        if isinstance(node, ast.BoolOp):
            facts = _CLEAN
            for value in node.values:
                facts = _combine(facts, self._eval(value, env, record=record))
            return facts
        if isinstance(node, ast.UnaryOp):
            return self._eval(node.operand, env, record=record)
        if isinstance(node, ast.IfExp):
            self._eval(node.test, env, record=record)
            return _combine(
                self._eval(node.body, env, record=record),
                self._eval(node.orelse, env, record=record),
            )
        if isinstance(node, ast.JoinedStr):
            facts = _CLEAN
            for value in node.values:
                facts = _combine(facts, self._eval(value, env, record=record))
            return facts
        if isinstance(node, ast.FormattedValue):
            return self._eval(node.value, env, record=record)
        if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
            facts = _CLEAN
            for elt in node.elts:
                facts = _combine(facts, self._eval(elt, env, record=record))
            return facts
        if isinstance(node, ast.Dict):
            facts = _CLEAN
            for part in list(node.keys) + list(node.values):
                if part is not None:
                    facts = _combine(facts, self._eval(part, env, record=record))
            return facts
        if isinstance(node, ast.Subscript):
            facts = self._eval(node.value, env, record=record)
            self._eval(node.slice, env, record=record)
            root = _root_name(node)
            if root == "request":
                return _Facts(prov=facts.prov | {REQUEST}, path_safe=False)
            return facts
        if isinstance(node, ast.Attribute):
            facts = self._eval(node.value, env, record=record)
            root = _root_name(node)
            if root == "request":
                return _Facts(prov=facts.prov | {REQUEST}, path_safe=False)
            if root == "sys" and _dotted(node) == "sys.argv":
                return _Facts(prov={ARGV}, path_safe=False)
            return facts
        if isinstance(node, ast.Starred):
            return self._eval(node.value, env, record=record)
        if isinstance(node, ast.Await):
            return self._eval(node.value, env, record=record)
        if isinstance(node, ast.Compare):
            for part in [node.left] + list(node.comparators):
                self._eval(part, env, record=record)
            return _CLEAN
        if isinstance(node, ast.Call):
            return self._eval_call(node, env, record=record)
        # Fallback: union of child expressions (conservative).
        facts = _CLEAN
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.expr):
                facts = _combine(facts, self._eval(child, env, record=record))
        return facts

    # -- calls: sinks + result facts -----------------------------------------

    def _record(self, record: bool, category: str, line: int, prov: frozenset) -> None:
        if record:
            self.findings.append((category, line, prov))

    def _eval_call(self, node: ast.Call, env, *, record) -> _Facts:
        func = node.func
        dotted = _dotted(func)
        attr = func.attr if isinstance(func, ast.Attribute) else None
        root = _root_name(func) if isinstance(func, ast.Attribute) else None

        arg_facts = [self._eval(a, env, record=record) for a in node.args]
        kw_facts = {
            kw.arg: self._eval(kw.value, env, record=record) for kw in node.keywords
        }
        object_facts = (
            self._eval(func.value, env, record=record)
            if isinstance(func, ast.Attribute)
            else _CLEAN
        )

        is_fetch = attr == "urlopen" or (attr in _FETCH_ATTRS and root in _FETCH_ROOTS)

        # ---- sinks ----
        if record:
            if attr in ("execute", "executemany"):
                parameterized = len(node.args) >= 2 or "params" in kw_facts
                if arg_facts and arg_facts[0].tainted and not parameterized:
                    self._record(record, "sql_injection", node.lineno, arg_facts[0].prov)
            if is_fetch:
                url_facts = arg_facts[0] if arg_facts else kw_facts.get("url", _CLEAN)
                if url_facts.tainted and not url_facts.prov <= self._validated:
                    category = (
                        "ssrf_redirect"
                        if FETCH_RESPONSE in url_facts.prov
                        else "ssrf"
                    )
                    self._record(record, category, node.lineno, url_facts.prov)
            if (isinstance(func, ast.Name) and func.id == "open") or dotted == "io.open":
                if arg_facts and arg_facts[0].tainted and not arg_facts[0].path_safe:
                    self._record(
                        record, "path_traversal", node.lineno, arg_facts[0].prov
                    )
            if dotted in ("pickle.loads", "pickle.load", "marshal.loads", "marshal.load"):
                if arg_facts and arg_facts[0].tainted:
                    self._record(
                        record, "insecure_deserialization", node.lineno, arg_facts[0].prov
                    )
            if dotted == "yaml.load":
                loader_safe = any(
                    kw.arg == "Loader"
                    and (_dotted(kw.value) or "").endswith("SafeLoader")
                    for kw in node.keywords
                )
                if not loader_safe and arg_facts and arg_facts[0].tainted:
                    self._record(
                        record, "insecure_deserialization", node.lineno, arg_facts[0].prov
                    )

        # ---- result facts ----
        if dotted == "os.path.basename" and arg_facts:
            return _Facts(prov=arg_facts[0].prov, path_safe=True)
        if dotted in ("os.path.realpath", "os.path.normpath", "os.path.abspath") and arg_facts:
            return arg_facts[0]
        if dotted == "os.path.join" and arg_facts:
            prov = frozenset().union(*(f.prov for f in arg_facts))
            if not prov:
                return _CLEAN
            return _Facts(prov=prov, path_safe=all(f.path_safe for f in arg_facts))
        if isinstance(func, ast.Name) and func.id in ("int", "float"):
            return _CLEAN
        if isinstance(func, ast.Name) and func.id == "input":
            return _Facts(prov={USER_INPUT}, path_safe=False)
        if attr in ("fetchone", "fetchall", "fetchmany"):
            # Second-order source: what comes back out of the database is
            # stored data, and stored data is not trusted.
            return _Facts(prov={DB_READ}, path_safe=False)
        if is_fetch and arg_facts:
            return _Facts(
                prov=arg_facts[0].prov | {FETCH_RESPONSE}, path_safe=False
            )
        if isinstance(func, ast.Name) and func.id in self.functions:
            return self._apply_summary(func.id, node, arg_facts, kw_facts)
        # Generic call: taint flows from the object and every argument.
        facts = object_facts
        for f in arg_facts:
            facts = _combine(facts, f)
        for f in kw_facts.values():
            facts = _combine(facts, f)
        if facts.tainted:
            # Stringifying / stripping / decoding does not sanitize a path.
            return _Facts(prov=facts.prov, path_safe=False)
        return _CLEAN

    def _apply_summary(self, name, node: ast.Call, arg_facts, kw_facts) -> _Facts:
        fn = self.functions[name]
        positional = [a.arg for a in list(fn.args.posonlyargs) + list(fn.args.args)]
        prov: set[str] = set()
        for label in self.summaries.get(name, frozenset()):
            if label.startswith("param:"):
                param = label[len("param:"):]
                if param in positional:
                    idx = positional.index(param)
                    if idx < len(arg_facts):
                        prov |= arg_facts[idx].prov
                elif param in kw_facts:
                    prov |= kw_facts[param].prov
                # Unbound parameter: its provenance simply doesn't flow in.
            else:
                prov.add(label)
        if not prov:
            return _CLEAN
        # Summaries track provenance only; path-sanitization credit does not
        # cross function boundaries (documented limitation).
        return _Facts(prov=frozenset(prov), path_safe=False)


def analyze(code: str) -> list[tuple[str, int, frozenset]]:
    """Run the analyzer over Python source; [] if it does not parse."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    return _Analyzer(tree).run()


class AstTaintDetector(Detector):
    name = "ast-taint-baseline"

    def detect(self, sample: Sample) -> list[Finding]:
        if sample.language != "python":
            return []
        findings: list[Finding] = []
        seen: set[tuple[str, int]] = set()
        for category, line, prov in analyze(sample.code):
            # The redirect case is a *kind* of SSRF; score it under the
            # dataset's ssrf category but keep its sharper rationale.
            scored_category = "ssrf" if category == "ssrf_redirect" else category
            key = (scored_category, line)
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    category=scored_category,
                    line=line,
                    rationale=_RATIONALES[category],
                )
            )
        return findings

    # propose_patch intentionally inherits the default (None): this
    # detector evaluates detection only, and reporting patch coverage of
    # 0 next to the heuristic's partial coverage is part of the comparison.
