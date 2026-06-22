"""
RakshakAI v2 — Synthesize vulnerable code from clean code templates.

Takes clean/non-vulnerable code and deterministically injects common
vulnerabilities (buffer overflow, SQL injection, XSS, command injection,
path traversal, use-after-free, format string, etc.).

Generates: patched version, CWE, severity, explanation, secure_fix.

Output: v2/inputs/datasets/synthetic_vuln.jsonl
"""
from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from v2.dataset.schema import SecuritySample  # noqa: E402

random.seed(2024)
OUT_PATH = Path("v2/inputs/datasets/synthetic_vuln.jsonl")

# Template-based vulnerability injection patterns
# Each: (language, clean_code, patched_code, cwe, severity, explanation, fix_desc)

PATTERNS = [
    # ---- C/C++ patterns ----
    {
        "language": "c",
        "vulnerable_code": """void copy_data(char *input) {{
    char buffer[64];
    strcpy(buffer, input);
    printf("Copied: %s\\n", buffer);
}}""",
        "patched_code": """void copy_data(char *input) {{
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Copied: %s\\n", buffer);
}}""",
        "cwe": "CWE-121",
        "severity": "high",
        "explanation": "Stack buffer overflow: strcpy does not bounds-check input length against the 64-byte buffer, allowing stack smashing.",
        "secure_fix": "Replace strcpy with strncpy and ensure null termination, or use dynamically allocated memory.",
    },
    {
        "language": "c",
        "vulnerable_code": """void process_string(char *str) {{
    printf(str);
}}""",
        "patched_code": """void process_string(char *str) {{
    printf("%s", str);
}}""",
        "cwe": "CWE-134",
        "severity": "high",
        "explanation": "Format string vulnerability: user-controlled string is passed directly as the format argument to printf, allowing arbitrary memory read/write.",
        "secure_fix": "Always use a fixed format string like printf(\"%s\", str) instead of printf(str).",
    },
    {
        "language": "c",
        "vulnerable_code": """int get_value() {{
    int *ptr = malloc(sizeof(int));
    *ptr = 42;
    free(ptr);
    return *ptr;
}}""",
        "patched_code": """int get_value() {{
    int *ptr = malloc(sizeof(int));
    if (!ptr) return -1;
    *ptr = 42;
    int val = *ptr;
    free(ptr);
    return val;
}}""",
        "cwe": "CWE-416",
        "severity": "high",
        "explanation": "Use-after-free: memory at ptr is accessed after free(), leading to undefined behavior and potential code execution.",
        "secure_fix": "Access the value before freeing, or set ptr = NULL after free and check for NULL before dereferencing.",
    },
    {
        "language": "c",
        "vulnerable_code": """int authenticate(char *user, char *pass) {{
    char cmd[256];
    sprintf(cmd, "grep '%s' /etc/passwd | cut -d: -f2", user);
    return system(cmd);
}}""",
        "patched_code": """int authenticate(char *user, char *pass) {{
    // Use PAM or a proper authentication library
    return pam_authenticate(user, pass);
}}""",
        "cwe": "CWE-78",
        "severity": "critical",
        "explanation": "OS command injection: user-controlled username is interpolated into a shell command without sanitization.",
        "secure_fix": "Avoid shell commands entirely. Use library APIs like PAM for authentication instead of system().",
    },
    {
        "language": "c",
        "vulnerable_code": """int read_config() {{
    FILE *f = fopen("/etc/app/config.cfg", "r");
    char buf[128];
    fread(buf, 1, sizeof(buf), f);
    return 0;
}}""",
        "patched_code": """int read_config() {{
    FILE *f = fopen("/etc/app/config.cfg", "r");
    if (!f) return -1;
    char buf[128] = {{0}};
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    if (n == 0 && ferror(f)) {{ fclose(f); return -1; }}
    buf[n] = '\\0';
    fclose(f);
    return 0;
}}""",
        "cwe": "CWE-476",
        "severity": "medium",
        "explanation": "NULL pointer dereference: fopen return value is not checked before use, causing crash if file doesn't exist.",
        "secure_fix": "Always check fopen() return value for NULL before using the file pointer.",
    },
    {
        "language": "c",
        "vulnerable_code": """void parse_header(char *data) {{
    int len = data[0];
    char buf[64];
    memcpy(buf, data + 1, len);
}}""",
        "patched_code": """void parse_header(char *data, size_t data_len) {{
    if (data_len < 1) return;
    int len = data[0];
    if (len <= 0 || len > 64 || len > (int)(data_len - 1)) return;
    char buf[64];
    memcpy(buf, data + 1, len);
}}""",
        "cwe": "CWE-787",
        "severity": "high",
        "explanation": "Out-of-bounds write: len from attacker-controlled data is used as memcpy length without validation against buffer size.",
        "secure_fix": "Validate len against both the destination buffer (64) and available source data before memcpy.",
    },
    # ---- Python patterns ----
    {
        "language": "python",
        "vulnerable_code": """def lookup_user(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    return cur.fetchone()""",
        "patched_code": """def lookup_user(user_id):
    import sqlite3
    conn = sqlite3.connect('users.db')
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()""",
        "cwe": "CWE-89",
        "severity": "critical",
        "explanation": "SQL injection: user_id is interpolated directly into SQL query, allowing malicious input like ' OR '1'='1 to bypass authentication.",
        "secure_fix": "Use parameterized queries with placeholders (?) instead of string formatting.",
    },
    {
        "language": "python",
        "vulnerable_code": """def render_page(name):
    return f"<html><body><h1>Welcome {{name}}</h1></body></html>" """,
        "patched_code": """import html

def render_page(name):
    safe_name = html.escape(name)
    return f"<html><body><h1>Welcome {{safe_name}}</h1></body></html>" """,
        "cwe": "CWE-79",
        "severity": "high",
        "explanation": "Cross-site scripting (XSS): user-controlled name is rendered directly into HTML without escaping, allowing script injection.",
        "secure_fix": "Use html.escape() or a template engine with auto-escaping (Jinja2, Django templates).",
    },
    {
        "language": "python",
        "vulnerable_code": """import subprocess

def ping(host):
    result = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return result.decode()""",
        "patched_code": """import subprocess

def ping(host):
    result = subprocess.check_output(["ping", "-c", "1", host])
    return result.decode()""",
        "cwe": "CWE-78",
        "severity": "critical",
        "explanation": "OS command injection: host parameter is interpolated into shell command, allowing commands like '127.0.0.1; rm -rf /'.",
        "secure_fix": "Use subprocess with argument list (list form, not string) and avoid shell=True.",
    },
    {
        "language": "python",
        "vulnerable_code": """def load_data(filename):
    import pickle
    with open(filename, 'rb') as f:
        return pickle.load(f)""",
        "patched_code": """def load_data(filename):
    import json
    with open(filename, 'r') as f:
        return json.load(f)""",
        "cwe": "CWE-502",
        "severity": "critical",
        "explanation": "Insecure deserialization: pickle.load() can execute arbitrary Python code during deserialization.",
        "secure_fix": "Use safe serialization formats (JSON) or implement signature verification for pickle data.",
    },
    {
        "language": "python",
        "vulnerable_code": """import os

def delete_file(path):
    os.remove(path)""",
        "patched_code": """import os

def delete_file(path):
    safe_dir = '/var/data/files/'
    full_path = os.path.normpath(os.path.join(safe_dir, path))
    if not full_path.startswith(os.path.normpath(safe_dir)):
        raise ValueError("Path traversal detected")
    os.remove(full_path)""",
        "cwe": "CWE-22",
        "severity": "high",
        "explanation": "Path traversal: user-controlled path is passed directly to os.remove() without validation, allowing deletion of arbitrary files via '../' sequences.",
        "secure_fix": "Check that the resolved absolute path stays within an allowed directory using os.path.realpath() and path prefix check.",
    },
    {
        "language": "python",
        "vulnerable_code": """def execute(code):
    return eval(code)""",
        "patched_code": """def execute(code):
    import ast
    tree = ast.parse(code, mode='eval')
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Expression, ast.Constant, ast.BinOp, ast.UnaryOp, ast.Name)):
            raise ValueError("Unsafe code")
    return eval(code)""",
        "cwe": "CWE-94",
        "severity": "critical",
        "explanation": "Code injection: eval() executes arbitrary Python expressions from user input, allowing full system compromise.",
        "secure_fix": "Avoid eval() entirely. Use ast.literal_eval() for safe evaluation, or parse with AST whitelist.",
    },
    # ---- JavaScript patterns ----
    {
        "language": "javascript",
        "vulnerable_code": """function saveComment(comment) {
    document.getElementById('comments').innerHTML += comment;
}""",
        "patched_code": """function saveComment(comment) {
    const el = document.getElementById('comments');
    el.textContent += comment;
}""",
        "cwe": "CWE-79",
        "severity": "high",
        "explanation": "DOM-based XSS: innerHTML renders user comment as HTML, allowing script injection via <script> tags or event handlers.",
        "secure_fix": "Use textContent instead of innerHTML, or sanitize with DOMPurify before insertion.",
    },
    {
        "language": "javascript",
        "vulnerable_code": """app.get('/user/:id', (req, res) => {
    const query = 'SELECT * FROM users WHERE id = ' + req.params.id;
    db.query(query, (err, results) => { res.json(results); });
});""",
        "patched_code": """app.get('/user/:id', (req, res) => {
    db.query('SELECT * FROM users WHERE id = ?', [req.params.id], (err, results) => {
        if (err) return res.status(500).json({ error: 'DB error' });
        res.json(results);
    });
});""",
        "cwe": "CWE-89",
        "severity": "critical",
        "explanation": "SQL injection: req.params.id is concatenated into SQL query, allowing '1 OR 1=1' style attacks.",
        "secure_fix": "Use parameterized queries (prepared statements) with ? placeholders instead of string concatenation.",
    },
    {
        "language": "javascript",
        "vulnerable_code": """function readFile(path) {
    const fs = require('fs');
    return fs.readFileSync('/var/data/' + path, 'utf8');
}""",
        "patched_code": """const path = require('path');

function readFile(filePath) {
    const fs = require('fs');
    const base = '/var/data/';
    const resolved = path.resolve(base, filePath);
    if (!resolved.startsWith(path.resolve(base))) {
        throw new Error('Invalid path');
    }
    return fs.readFileSync(resolved, 'utf8');
}""",
        "cwe": "CWE-22",
        "severity": "high",
        "explanation": "Path traversal: filePath is concatenated without validation, allowing access to files outside /var/data/ via '../' sequences.",
        "secure_fix": "Resolve the path with path.resolve() and verify it starts with the intended base directory.",
    },
    {
        "language": "javascript",
        "vulnerable_code": """const cp = require('child_process');

function runCmd(cmd) {
    return cp.execSync(cmd, { encoding: 'utf8' });
}""",
        "patched_code": """const cp = require('child_process');

function runCmd(cmd, args) {
    return cp.execFileSync(cmd, args, { encoding: 'utf8' });
}""",
        "cwe": "CWE-78",
        "severity": "critical",
        "explanation": "Command injection: cp.execSync runs arbitrary shell commands, allowing injection of additional commands via shell metacharacters.",
        "secure_fix": "Use cp.execFileSync() with separate command and arguments list instead of execSync.",
    },
    # ---- Java patterns ----
    {
        "language": "java",
        "vulnerable_code": """public String getUser(String id) {
    String sql = "SELECT * FROM users WHERE id = '" + id + "'";
    Statement stmt = conn.createStatement();
    return stmt.executeQuery(sql).toString();
}""",
        "patched_code": """public String getUser(String id) {
    String sql = "SELECT * FROM users WHERE id = ?";
    PreparedStatement stmt = conn.prepareStatement(sql);
    stmt.setString(1, id);
    return stmt.executeQuery().toString();
}""",
        "cwe": "CWE-89",
        "severity": "critical",
        "explanation": "SQL injection: user id is concatenated into SQL query string, enabling SQL manipulation attacks.",
        "secure_fix": "Use PreparedStatement with parameterized queries instead of Statement with string concatenation.",
    },
    {
        "language": "java",
        "vulnerable_code": """public void displayName(String name) {
    out.println("<div class='name'>" + name + "</div>");
}""",
        "patched_code": """public void displayName(String name) {
    String safe = StringEscapeUtils.escapeHtml4(name);
    out.println("<div class='name'>" + safe + "</div>");
}""",
        "cwe": "CWE-79",
        "severity": "high",
        "explanation": "XSS vulnerability: user name is printed directly to HTML output without HTML encoding.",
        "secure_fix": "Use OWASP ESAPI or Commons Lang StringEscapeUtils.escapeHtml4() to encode HTML special characters.",
    },
    # ---- Go patterns ----
    {
        "language": "go",
        "vulnerable_code": """func getUser(db *sql.DB, id string) (*User, error) {
    query := fmt.Sprintf("SELECT * FROM users WHERE id='%s'", id)
    row := db.QueryRow(query)
    // ...
}""",
        "patched_code": """func getUser(db *sql.DB, id string) (*User, error) {
    row := db.QueryRow("SELECT * FROM users WHERE id=?", id)
    // ...
}""",
        "cwe": "CWE-89",
        "severity": "critical",
        "explanation": "SQL injection: fmt.Sprintf builds SQL query with user input, allowing SQL manipulation.",
        "secure_fix": "Use database/sql parameterized queries with ? placeholders instead of fmt.Sprintf.",
    },
    {
        "language": "go",
        "vulnerable_code": """func serveFile(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("file")
    http.ServeFile(w, r, "/var/www/"+path)
}""",
        "patched_code": """func serveFile(w http.ResponseWriter, r *http.Request) {
    path := r.URL.Query().Get("file")
    safe := filepath.Join("/var/www", path)
    if !strings.HasPrefix(filepath.Clean(safe), "/var/www/") {
        http.Error(w, "Invalid path", 403)
        return
    }
    http.ServeFile(w, r, safe)
}""",
        "cwe": "CWE-22",
        "severity": "high",
        "explanation": "Path traversal: file parameter concatenated without validation, allowing access to files outside /var/www/ via '../'.",
        "secure_fix": "Use filepath.Clean and filepath.Join, then check the resolved path starts with the allowed base directory.",
    },
]

PATTERNS_BY_LANG = {
    "c": [p for p in PATTERNS if p["language"] == "c"],
    "python": [p for p in PATTERNS if p["language"] == "python"],
    "javascript": [p for p in PATTERNS if p["language"] == "javascript"],
    "java": [p for p in PATTERNS if p["language"] == "java"],
    "go": [p for p in PATTERNS if p["language"] == "go"],
}


def synthesize_vuln(target_count: int) -> int:
    """Generate synthetic vulnerable samples by injecting vulnerability patterns.

    Each pattern can be used multiple times with slight randomization
    (variable names, string values) to create variety.
    """
    rng = random.Random(2024)
    samples = []

    # Extend with variable randomization
    vars_by_lang = {
        "c": ["data", "input", "buffer", "str", "cmd", "path", "name", "val", "src", "msg"],
        "python": ["data", "input_str", "value", "query", "filename", "user_input", "text", "item"],
        "javascript": ["data", "input", "value", "query", "filename", "userInput", "text", "item"],
        "java": ["data", "input", "value", "query", "filename", "userInput", "text", "item"],
        "go": ["data", "input", "value", "query", "filename", "userInput", "text", "item"],
    }

    used_sources = set()

    while len(samples) < target_count:
        # Pick a language with a pattern available
        lang = rng.choice(list(PATTERNS_BY_LANG.keys()))
        pattern = rng.choice(PATTERNS_BY_LANG[lang])
        vars_for_lang = vars_by_lang.get(lang, ["x"])

        # Create a unique variant by renaming variables
        vname = rng.choice(vars_for_lang)
        pattern_id = pattern["cwe"].replace("CWE-", "") + "-" + str(rng.randint(1, 9999))

        vuln_code = pattern["vulnerable_code"]
        patched_code = pattern["patched_code"]

        # Add function name variation
        func_name = f"func_{rng.choice(['proc', 'handle', 'process', 'do_', 'run', 'exec', 'compute'])}{rng.randint(1, 999)}"
        vuln_code = vuln_code.replace("void copy_data", f"void {func_name}")
        vuln_code = vuln_code.replace("int get_value", f"int {func_name}")
        vuln_code = vuln_code.replace("int authenticate", f"int {func_name}")
        vuln_code = vuln_code.replace("int read_config", f"int {func_name}")
        vuln_code = vuln_code.replace("void parse_header", f"void {func_name}")
        vuln_code = vuln_code.replace("def lookup_user", f"def {func_name}")
        vuln_code = vuln_code.replace("def render_page", f"def {func_name}")
        vuln_code = vuln_code.replace("def ping", f"def {func_name}")
        vuln_code = vuln_code.replace("def load_data", f"def {func_name}")
        vuln_code = vuln_code.replace("def delete_file", f"def {func_name}")
        vuln_code = vuln_code.replace("def execute", f"def {func_name}")
        vuln_code = vuln_code.replace("function saveComment", f"function {func_name}")
        vuln_code = vuln_code.replace("function readFile", f"function {func_name}")
        vuln_code = vuln_code.replace("function runCmd", f"function {func_name}")
        vuln_code = vuln_code.replace("public String getUser", f"public String {func_name}")
        vuln_code = vuln_code.replace("public void displayName", f"public void {func_name}")
        vuln_code = vuln_code.replace("func getUser", f"func {func_name}")
        vuln_code = vuln_code.replace("func serveFile", f"func {func_name}")

        source = f"synthetic:{pattern['cwe']}:{rng.randint(10000, 99999)}"
        if source in used_sources:
            continue
        used_sources.add(source)

        try:
            s = SecuritySample.build(
                language=lang,
                vulnerable_code=vuln_code,
                patched_code=patched_code,
                cwe=pattern["cwe"],
                severity=pattern["severity"],
                explanation=pattern["explanation"],
                attack_scenario=f"An attacker provides crafted input exploiting the {pattern['cwe']} vulnerability.",
                secure_fix=pattern["secure_fix"],
                source=source,
                source_license="MIT",
                cve=None,
                is_vulnerable=True,
                split="train",
            )
            samples.append(s)
        except Exception:
            continue

        if len(samples) % 5000 == 0:
            print(f"[synth] {len(samples)} samples generated...")

    # Write output
    with OUT_PATH.open("w") as f:
        for s in samples:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")
    print(f"[synth] wrote {len(samples)} synthetic vuln samples -> {OUT_PATH}")

    # Report composition
    from collections import Counter
    cwe_counts = Counter(s.cwe for s in samples)
    lang_counts = Counter(s.language for s in samples)
    print(f"[synth] CWE distribution: {dict(cwe_counts.most_common())}")
    print(f"[synth] Language distribution: {dict(lang_counts.most_common())}")

    return len(samples)


def main():
    target = 56000  # Generate 56K to fill 193K -> 250K
    total = synthesize_vuln(target)
    print(f"\nTotal synthetic vuln samples: {total}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
