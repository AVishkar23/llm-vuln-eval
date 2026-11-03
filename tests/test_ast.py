"""AST taint detector: unit tests on inline snippets + dataset integration.

The unit tests pin the *model*, not just outcomes: provenance has to flow
through f-strings, helper functions, and database reads, and sanitizers
have to neutralize it in the category-specific ways the detector claims.
"""

from pathlib import Path

from vulneval.dataset import Sample, load_dataset
from vulneval.detectors.ast_taint import AstTaintDetector

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

DETECTOR = AstTaintDetector()


def _sample(code, *, pair_id="inline", category="sql_injection", language="python",
            vulnerable=True):
    return Sample(
        pair_id=pair_id,
        category=category,
        language=language,
        severity="high",
        is_vulnerable=vulnerable,
        code=code,
        source_name="inline",
        vulnerable_lines=(),
        explanation="",
        fix_summary="",
        fix_markers=(),
    )


def _categories(code, **kwargs):
    return {f.category for f in DETECTOR.detect(_sample(code, **kwargs))}


# --- SQL injection: flow variants -------------------------------------------

def test_concat_sqli_caught():
    code = (
        "def get_user(conn, username):\n"
        "    q = \"SELECT * FROM users WHERE name = '\" + username + \"'\"\n"
        "    return conn.execute(q)\n"
    )
    assert "sql_injection" in _categories(code)


def test_fstring_sqli_caught():
    # No '+' anywhere: a line pattern for concatenation cannot see this.
    code = (
        "def get_user(conn, username):\n"
        "    return conn.execute(f\"SELECT * FROM users WHERE name = '{username}'\")\n"
    )
    assert "sql_injection" in _categories(code)


def test_parameterized_execute_is_clean():
    code = (
        "def get_user(conn, username):\n"
        "    return conn.execute('SELECT * FROM users WHERE name = ?', (username,))\n"
    )
    assert _categories(code) == set()


def test_int_cast_sanitizes():
    code = (
        "def get_user(conn, user_id):\n"
        "    q = 'SELECT * FROM users WHERE id = ' + str(int(user_id))\n"
        "    return conn.execute(q)\n"
    )
    assert _categories(code) == set()


def test_second_order_sqli_via_database_read():
    # Data written safely comes back out of the DB and is concatenated.
    code = (
        "def lookup(conn):\n"
        "    row = conn.execute('SELECT name FROM audit LIMIT 1').fetchone()\n"
        "    name = row[0]\n"
        "    return conn.execute(f\"SELECT * FROM events WHERE actor = '{name}'\")\n"
    )
    assert "sql_injection" in _categories(code)


def test_taint_flows_through_helper_function():
    code = (
        "def build(name):\n"
        "    return 'SELECT * FROM t WHERE n = ' + name\n"
        "\n"
        "def run(conn, user):\n"
        "    return conn.execute(build(user))\n"
    )
    assert "sql_injection" in _categories(code)


# --- Path traversal -----------------------------------------------------------

def test_raw_join_open_fires():
    code = (
        "import os\n"
        "BASE = '/srv/files'\n"
        "def read(name):\n"
        "    return open(os.path.join(BASE, name)).read()\n"
    )
    assert "path_traversal" in _categories(code, category="path_traversal")


def test_basename_neutralizes_path_sink_but_not_sql():
    path_code = (
        "import os\n"
        "BASE = '/srv/files'\n"
        "def read(name):\n"
        "    safe = os.path.basename(name)\n"
        "    return open(os.path.join(BASE, safe)).read()\n"
    )
    assert "path_traversal" not in _categories(path_code, category="path_traversal")
    sql_code = (
        "import os\n"
        "def get(conn, name):\n"
        "    safe = os.path.basename(name)\n"
        "    return conn.execute('SELECT * FROM t WHERE n = ' + safe)\n"
    )
    assert "sql_injection" in _categories(sql_code)


# --- SSRF ---------------------------------------------------------------------

def test_unvalidated_fetch_fires():
    code = (
        "import urllib.request\n"
        "def fetch(url):\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    assert "ssrf" in _categories(code, category="ssrf")


def test_allowlisted_fetch_is_clean():
    code = (
        "import urllib.request\n"
        "from urllib.parse import urlparse\n"
        "ALLOWED = {'example.com'}\n"
        "def fetch(url):\n"
        "    if urlparse(url).hostname not in ALLOWED:\n"
        "        raise ValueError('nope')\n"
        "    return urllib.request.urlopen(url).read()\n"
    )
    assert _categories(code, category="ssrf") == set()


def test_unvalidated_redirect_target_fires():
    # Initial URL is checked; the redirect Location is not — provenance of
    # the second fetch includes response data the check never covered.
    code = (
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "ALLOWED = {'example.com'}\n"
        "def fetch(url):\n"
        "    if urlparse(url).hostname not in ALLOWED:\n"
        "        raise ValueError('nope')\n"
        "    r = requests.get(url, timeout=5)\n"
        "    if r.is_redirect:\n"
        "        r = requests.get(r.headers['Location'], timeout=5)\n"
        "    return r.content\n"
    )
    assert "ssrf" in _categories(code, category="ssrf")


def test_revalidated_redirect_target_is_clean():
    code = (
        "import requests\n"
        "from urllib.parse import urlparse\n"
        "ALLOWED = {'example.com'}\n"
        "def fetch(url):\n"
        "    if urlparse(url).hostname not in ALLOWED:\n"
        "        raise ValueError('nope')\n"
        "    r = requests.get(url, timeout=5)\n"
        "    if r.is_redirect:\n"
        "        target = r.headers['Location']\n"
        "        if urlparse(target).hostname not in ALLOWED:\n"
        "            raise ValueError('redirect not allowlisted')\n"
        "        r = requests.get(target, timeout=5)\n"
        "    return r.content\n"
    )
    assert _categories(code, category="ssrf") == set()


# --- Deserialization ------------------------------------------------------------

def test_pickle_loads_on_input_fires():
    code = (
        "import pickle\n"
        "def load(blob):\n"
        "    return pickle.loads(blob)\n"
    )
    assert "insecure_deserialization" in _categories(
        code, category="insecure_deserialization"
    )


def test_yaml_load_without_safe_loader_fires_and_with_it_is_clean():
    vuln = "import yaml\ndef load(text):\n    return yaml.load(text)\n"
    fixed = "import yaml\ndef load(text):\n    return yaml.load(text, Loader=yaml.SafeLoader)\n"
    assert "insecure_deserialization" in _categories(
        vuln, category="insecure_deserialization"
    )
    assert _categories(fixed, category="insecure_deserialization") == set()


# --- Scope honesty ----------------------------------------------------------------

def test_java_samples_are_out_of_scope():
    code = "class X { void f(String u) { stmt.execute(\"SELECT \" + u); } }"
    assert DETECTOR.detect(_sample(code, language="java")) == []


def test_unparsable_code_returns_no_findings():
    assert DETECTOR.detect(_sample("def broken(:\n")) == []


# --- Dataset integration ------------------------------------------------------------

def _dataset_sample(samples, pair_id, vulnerable):
    return next(
        s for s in samples if s.pair_id == pair_id and s.is_vulnerable == vulnerable
    )


def test_ast_flags_no_fixed_python_sample_in_dataset():
    samples = load_dataset(DATA_DIR)
    for sample in samples:
        if not sample.is_vulnerable and sample.language == "python":
            assert DETECTOR.detect(sample) == [], sample.sample_id


def test_ast_catches_the_flow_variants_the_regex_misses():
    samples = load_dataset(DATA_DIR)
    for pair_id in ("sqli2_py", "ssrf_redirect_py"):
        vuln = _dataset_sample(samples, pair_id, True)
        categories = {f.category for f in DETECTOR.detect(vuln)}
        assert categories == {vuln.category}, (pair_id, categories)
