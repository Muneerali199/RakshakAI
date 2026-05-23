#!/usr/bin/env python3
"""
RAKSHAKAI - ELITE DATASET GENERATOR
============================================================
Creates a comprehensive, research-backed dataset for India's 
first security AI model: RakshakAI
============================================================
"""

import json
import pandas as pd
from pathlib import Path

def create_elite_dataset():
    samples = []
    
    # Define all vulnerability patterns with CWE IDs
    vuln_patterns = [
        ("SQL_INJECTION", "CWE-89", "A03:2021", "critical", [
            'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
            'db.query("SELECT * FROM users WHERE name = \'" + username + "\'")',
            'db.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            'connection.query("SELECT * FROM users WHERE id = " + req.params.id)',
            'Statement stmt = conn.createStatement();\nString sql = "SELECT * FROM users WHERE id = " + userId;',
        ]),
        ("XSS", "CWE-79", "A03:2021", "high", [
            'return "<div>" + user_input + "</div>"',
            'document.getElementById("output").innerHTML = userInput',
            'element.innerHTML = req.params.value',
            'response.getWriter().write(userInput);',
            'out.println("<div>" + name + "</div>");',
        ]),
        ("COMMAND_INJECTION", "CWE-78", "A03:2021", "critical", [
            'os.system("ping " + user_input)',
            'subprocess.call("ls " + directory, shell=True)',
            'exec("cat " + filename)',
            'child_process.execSync("ping " + req.body.host)',
            'Runtime.getRuntime().exec("ping " + host);',
        ]),
        ("HARDCODED_SECRET", "CWE-798", "A07:2021", "critical", [
            'API_KEY = "sk_live_abc123xyz789"',
            'SECRET_TOKEN = "super_secret_value"',
            'password = "Password123"',
            'const API_KEY = "sk_live_abc123";',
            'private static final String API_KEY = "sk-abc123";',
        ]),
        ("PATH_TRAVERSAL", "CWE-22", "A01:2021", "critical", [
            'open("uploads/" + filename)',
            'with open(user_file) as f: return f.read()',
            'fs.readFileSync("uploads/" + filename)',
            'new FileInputStream(userFile);',
        ]),
        ("WEAK_CRYPTO", "CWE-327", "A02:2021", "critical", [
            'hashlib.md5(password).hexdigest()',
            'hashlib.sha1(data).hexdigest()',
            'crypto.createHash("md5")',
            'MessageDigest.getInstance("MD5");',
        ]),
        ("SSTI", "CWE-94", "A03:2021", "critical", [
            'Template("Hello " + user).render()',
            'render_template_string(user_input)',
            'handlebars.compile(userInput)(data)',
        ]),
        ("INSECURE_DESERIALIZATION", "CWE-502", "A04:2021", "critical", [
            'pickle.loads(data)',
            'yaml.load(user_data)',
            'unserialize(userInput)',
            'ObjectInputStream.readObject();',
        ]),
        ("JWT_VULNERABILITY", "CWE-347", "A02:2021", "critical", [
            'jwt.decode(token, options={"verify_signature": False})',
            'jwt.verify(token, secret, {algorithms: []})',
        ]),
        ("REDOS", "CWE-1333", "A01:2021", "high", [
            're.compile(user_input + "+$")',
            'regex.match(userData)',
            'new RegExp(userInput + "+")',
        ]),
        ("SSRF", "CWE-918", "A10:2021", "high", [
            'requests.get(url)',
            'urllib.request.urlopen(user_url)',
            'fetch(url)',
        ]),
        ("XXE", "CWE-611", "A04:2021", "critical", [
            'ET.parse(user_xml)',
            'new DOMParser().parseFromString(userxml);',
            'DocumentBuilder dbf = DocumentBuilderFactory.newInstance().newDocumentBuilder();',
        ]),
    ]
    
    # Generate 200 samples per pattern per vulnerability class
    for label, cwe, owasp, severity, patterns in vuln_patterns:
        for code in patterns:
            for _ in range(200):
                samples.append({
                    "code": code,
                    "language": "python",
                    "label": label,
                    "is_vulnerable": 1,
                    "cwe": cwe,
                    "owasp": owasp,
                    "severity": severity
                })
    
    # Generate SECURE (clean) patterns
    secure_patterns = [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'element.textContent = sanitizer.escape(userInput)',
        'subprocess.run(["ping", "-c", "1", host], check=True)',
        'filepath = os.path.join("uploads", os.path.basename(filename))',
        'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
        'hashlib.sha256(data).hexdigest()',
        'data = json.loads(user_data)',
        'db.query("SELECT * FROM users WHERE id = ?", [userId])',
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
    ]
    
    for code in secure_patterns:
        for _ in range(100):
            samples.append({
                "code": code,
                "language": "python",
                "label": "SECURE",
                "is_vulnerable": 0,
                "cwe": "",
                "owasp": "",
                "severity": "clean"
            })
    
    # Create DataFrame
    df = pd.DataFrame(samples)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split: 80% train, 10% val, 10% test
    train_size = int(0.8 * len(df))
    val_size = int(0.1 * len(df))
    
    train = df[:train_size]
    val = df[train_size:train_size + val_size]
    test = df[train_size + val_size:]
    
    # Save CSVs
    output_dir = Path("dataset")
    output_dir.mkdir(exist_ok=True)
    
    train.to_csv(output_dir / "train.csv", index=False)
    val.to_csv(output_dir / "val.csv", index=False)
    test.to_csv(output_dir / "test.csv", index=False)
    
    # Metadata
    metadata = {
        "model_name": "RakshakAI",
        "version": "1.0.0",
        "full_name": "Code Guardian AAtman",
        "tagline": "India's First Security AI",
        "origin": "Made in India",
        "base_model": "microsoft/codebert-base",
        "total_samples": len(df),
        "train_samples": len(train),
        "val_samples": len(val),
        "test_samples": len(test),
        "vulnerable_samples": int(df["is_vulnerable"].sum()),
        "secure_samples": int(len(df) - df["is_vulnerable"].sum()),
        "classes": df["label"].nunique(),
        "cwe_mappings": {v[0]: v[1] for v in vuln_patterns},
        "owasp_coverage": list(set([v[2] for v in vuln_patterns])),
    }
    
    with open(output_dir / "metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    return train, val, test, df, metadata

if __name__ == "__main__":
    train, val, test, df, meta = create_elite_dataset()
    
    print("""
    ============================================================
    🏛️ CODE GUARDIAN - AATMAN ELITE DATASET READY!
    ============================================================
    """)
    print(f"📊 Total: {len(df):,}")
    print(f"📚 Train: {len(train):,}")
    print(f"📖 Val: {len(val):,}")
    print(f"📝 Test: {len(test):,}")
    print()
    print(f"⚠ Vulnerable: {int(df['is_vulnerable'].sum()):,}")
    print(f"✓ Secure: {int(len(df) - df['is_vulnerable'].sum()):,}")
    print()
    print(f"🎯 Vulnerability Classes: {df['label'].nunique()}")
    print(f"📁 Files: dataset/train.csv, val.csv, test.csv, metadata.json")
    print("""
    ============================================================
    
    🚀 Ready for Training!
    
    Option 1 - Local (CPU):
        cd ml-model && source cg-ml-env/bin/activate
        python3 train.py
    
    Option 2 - Google Colab (GPU):
        Upload ml-model/ folder
        !pip install -r requirements.txt
        !python3 train.py
    ============================================================
    """)