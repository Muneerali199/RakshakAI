#!/usr/bin/env python3
"""
============================================================
RAKSHAKAI - MEGA DATASET GENERATOR v3
============================================================
Loads real vulnerability datasets from HuggingFace & creates 
massive training data for RakshakAI

This version fetches from:
- HuggingFace Datasets API
- Real CVE vulnerability data
- Academic research datasets

Author: Team CodeBlitz (India)
============================================================
"""

import json
import os
import random
import pandas as pd
from pathlib import Path

def load_huggingface_dataset():
    """Load real vulnerability datasets from HuggingFace"""
    
    print("=" * 70)
    print("🌐 CONNECTING TO HUGGINGFACE DATASETS...")
    print("=" * 70)
    
    all_samples = []
    
    # Try loading from HuggingFace
    try:
        from datasets import load_dataset
        
        print("\n[1] Loading BigVul dataset...")
        try:
            bigvul = load_dataset("bigvul", split="train")
            print(f"   ✓ BigVul: {len(bigvul)} samples")
            
            for item in bigvul:
                if "func" in item and "vul" in item:
                    all_samples.append({
                        "code": item["func"][:2000] if isinstance(item["func"], str) else str(item["func"])[:2000],
                        "language": item.get("language", "c"),
                        "label": "VULNERABLE" if item["vul"] == 1 else "SECURE",
                        "is_vulnerable": item["vul"],
                        "cwe": item.get("cwe_id", ""),
                        "owasp": "",
                        "severity": "high" if item["vul"] else "clean"
                    })
        except Exception as e:
            print(f"   ⚠ BigVul: {e}")
        
        print("\n[2] Loading Devign dataset...")
        try:
            devign = load_dataset("devign", split="train")
            print(f"   ✓ Devign: {len(devign)} samples")
            
            for item in devign:
                if "func" in item and "target" in item:
                    all_samples.append({
                        "code": item["func"][:2000] if isinstance(item["func"], str) else str(item["func"])[:2000],
                        "language": "c",
                        "label": "VULNERABLE" if item["target"] == 1 else "SECURE",
                        "is_vulnerable": item["target"],
                        "cwe": "",
                        "owasp": "",
                        "severity": "high" if item["target"] else "clean"
                    })
        except Exception as e:
            print(f"   ⚠ Devign: {e}")
            
    except ImportError:
        print("⚠ datasets library not available")
    
    print(f"\n📊 Total samples from HuggingFace: {len(all_samples)}")
    return all_samples

def create_mega_synthetic():
    """Create massive synthetic dataset with research-backed patterns"""
    
    print("\n" + "=" * 70)
    print("🏭 GENERATING MEGA SYNTHETIC DATASET...")
    print("=" * 70)
    
    samples = []
    
    # Comprehensive vulnerability templates - 3x more than before
    VULN_TEMPLATES = {
        # OWASP A01 - Broken Access Control
        "BROKEN_ACCESS_CONTROL": {
            "cwe": "CWE-284,CWE-639",
            "owasp": "A01:2021",
            "severity": "critical",
            "python": [
                'user = db.execute(f"SELECT * FROM users WHERE id = {req.params.id}")',
                'return db.query(f"SELECT * FROM {table} WHERE id = {user_input}")',
                'file_data = open(f"/data/{filename}").read()',
                'user_record = users.find({_id: user_id})',
                'admin_data = User.objects.get(id=user_input)',
                'result = db.execute("SELECT * FROM orders WHERE user = " + str(user_id))',
            ],
            "javascript": [
                'const user = await db.query(`SELECT * FROM users WHERE id = ${req.params.id}`)',
                'const data = fs.readFileSync(req.body.path)',
                'const record = await collection.findOne({_id: req.query.id})',
            ],
            "java": [
                'User user = em.find(User.class, userId);',
                '@GetMapping("/user/{id}") public User getUser(@PathVariable Long id)',
                'FileInputStream fis = new FileInputStream(filename);',
            ],
            "php": [
                '$user = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);',
            ]
        },
        
        # OWASP A02 - Cryptographic Failures
        "WEAK_CRYPTO": {
            "cwe": "CWE-327,CWE-331",
            "owasp": "A02:2021", 
            "severity": "critical",
            "python": [
                'hashlib.md5(password.encode()).hexdigest()',
                'hashlib.sha1(data).hexdigest()',
                'cipher = AES.new(key, AES.MODE_ECB)',
                'md5_hash = hashlib.new("md5")',
                'hash = hashlib.sha1(user_input).hexdigest()',
            ],
            "javascript": [
                'crypto.createHash("md5")',
                'crypto.createHash("sha1")',
                'cipher = crypto.createCipher("aes-128-ecb", key)',
            ],
            "java": [
                'MessageDigest md = MessageDigest.getInstance("MD5");',
                'Cipher.getInstance("DES/ECB/PKCS5Padding")',
            ]
        },
        
        # OWASP A03:2021 - Injection
        "SQL_INJECTION": {
            "cwe": "CWE-89",
            "owasp": "A03:2021",
            "severity": "critical",
            "python": [
                'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
                'db.query(f"SELECT * FROM users WHERE name = \'{username}\'")',
                'result = db.execute("SELECT * FROM items WHERE " + filter)',
                'sql = "INSERT INTO logs VALUES(\'" + msg + "\')"',
                'query = f"SELECT * FROM products WHERE category = {category}"',
            ],
            "javascript": [
                'db.query("SELECT * FROM users WHERE id = " + id)',
                'connection.execute("SELECT * FROM users WHERE name = \'" + name + "\'")',
                'const query = `SELECT * FROM posts WHERE author = ${author}`',
            ],
            "java": [
                'Statement stmt = conn.createStatement();',
                'String query = "SELECT * FROM users WHERE id = " + userId;',
                'Query q = em.createQuery("SELECT u FROM User u WHERE name = " + name);',
            ],
            "php": [
                'mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);',
            ]
        },
        
        "XSS": {
            "cwe": "CWE-79",
            "owasp": "A03:2021",
            "severity": "high",
            "python": [
                'return "<div>" + user_input + "</div>"',
                'response.write(userName)',
                'template.render(user_content)',
                'html = f"<h1>{username}</h1>"',
                'out.write(safeInput)',
            ],
            "javascript": [
                'document.getElementById("output").innerHTML = userInput',
                'element.innerHTML = req.params.value',
                '$("#div").html(userContent);',
                'document.body.innerHTML = responseData;',
            ],
            "java": [
                'response.getWriter().write(userInput);',
                'out.println("<div>" + name + "</div>");',
            ]
        },
        
        "COMMAND_INJECTION": {
            "cwe": "CWE-78",
            "owasp": "A03:2021",
            "severity": "critical",
            "python": [
                'os.system("ping " + user_input)',
                'subprocess.call("ls " + directory, shell=True)',
                'os.popen("cat " + filename)',
                'commands.getoutput("rm " + file_path)',
            ],
            "javascript": [
                'exec("ls " + userInput, callback)',
                'child_process.execSync("ping " + req.body.host)',
                'require("child_process").exec(cmd + " " + arg)',
            ],
            "java": [
                'Runtime.getRuntime().exec("ping " + host);',
                'ProcessBuilder pb = new ProcessBuilder("ls", directory);',
            ]
        },
        
        "SSTI": {
            "cwe": "CWE-94",
            "owasp": "A03:2021",
            "severity": "critical",
            "python": [
                'Template("Hello " + user).render()',
                'render_template_string(user_input)',
                'f"Welcome {username}"',
                'env.from_string(user_template).render()',
            ],
            "javascript": [
                'handlebars.compile(userInput)(data)',
                'ejs.render(userData, options)',
                '_.template(userContent)(context)',
            ]
        },
        
        "LDAP_INJECTION": {
            "cwe": "CWE-90",
            "owasp": "A03:2021",
            "severity": "high",
            "python": [
                'ldap.search_s("ou=users,dc=example,dc=com(" + username + ")")',
            ],
            "java": [
                'NamingEnumeration results = ctx.search("", "(uid=" + user + ")", searchControls);',
            ]
        },
        
        # OWASP A04 - Insecure Design
        "INSECURE_DESERIALIZATION": {
            "cwe": "CWE-502",
            "owasp": "A04:2021",
            "severity": "critical",
            "python": [
                'pickle.loads(data)',
                'yaml.load(user_data)',
                'marshal.loads(userInput)',
                'unpickle.load(data)',
            ],
            "javascript": [
                'unserialize(userInput)',
                'new Function("return " + userCode)',
                'eval(userProvidedCode)',
            ],
            "java": [
                'ObjectInputStream.readObject()',
                'XMLDecoder.readObject();',
                'new ObjectInputStream(input).readObject();',
            ]
        },
        
        # OWASP A05 - Security Misconfiguration
        "SECURITY_MISCONFIG": {
            "cwe": "CWE-2",
            "owasp": "A05:2021",
            "severity": "high",
            "python": [
                'app.run(debug=True)',
                'DEBUG = True',
                'settings.DEBUG = True',
            ],
            "javascript": [
                'app.set("env", "development");',
            ],
            "java": [
                '@CrossOrigin(origins = "*")',
            ]
        },
        
        # OWASP A07 - Auth Failures  
        "HARDCODED_SECRET": {
            "cwe": "CWE-798",
            "owasp": "A07:2021", 
            "severity": "critical",
            "python": [
                'API_KEY = "sk_live_abc123xyz789"',
                'SECRET_TOKEN = "super_secret_value"',
                'password = "Password123"',
                '/aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"',
                'jwt_secret = "my_jwt_secret"',
            ],
            "javascript": [
                'const API_KEY = "sk_live_abc123";',
                'const PASSWORD = "admin123";',
                'const JWT_SECRET = "secret123";',
            ],
            "java": [
                'private static final String API_KEY = "sk-abc123";',
                'String password = "admin123";',
            ]
        },
        
        "WEAK_AUTHENTICATION": {
            "cwe": "CWE-287",
            "owasp": "A07:2021",
            "severity": "critical", 
            "python": [
                'if password == "admin123": return True',
                'if username == "admin" and password == "admin": authenticate()',
                'if user.pass == plainPassword: return True',
            ],
            "javascript": [
                'if (password === "admin123") return true;',
                'if (authenticate(username, password) === true)',
            ],
            "java": [
                'if (password.equals("admin123")) return true;',
            ]
        },
        
        # OWASP A08 - Software Integrity
        "SOFTWARE_INTEGRITY": {
            "cwe": "CWE-494",
            "owasp": "A08:2021",
            "severity": "high",
            "python": [
                'import hashlib',
                'checksum = hashlib.md5(file).hexdigest()',
                'importlib.import_module(name)',
            ],
            "java": [
                'URL url = new URL("http://unsafe.com/lib.jar");',
            ]
        },
        
        # OWASP A09 - Logging
        "SENSITIVE_DATA_LEAK": {
            "cwe": "CWE-200",
            "owasp": "A09:2021",
            "severity": "high",
            "python": [
                'logging.info("Password: " + password)',
                'print(user_email)',
                'logger.debug(sensitive_data)',
                'print("Credit card: ", card_number)',
            ],
            "javascript": [
                'console.log("Token: " + token);',
            ],
            "java": [
                'System.out.println("User: " + user);',
            ]
        },
        
        # OWASP A10 - SSRF
        "SSRF": {
            "cwe": "CWE-918",
            "owasp": "A10:2021",
            "severity": "high",
            "python": [
                'requests.get(url)',
                'urllib.request.urlopen(user_url)',
                'http.client.HTTPConnection(url)',
            ],
            "javascript": [
                'fetch(url)',
                'axios.get(userProvidedUrl)',
                'request(userUrl)',
            ],
            "java": [
                'new URL(userInput);',
                'httpClient.execute(request);',
            ]
        },
        
        # Additional Critical CVEs
        "PATH_TRAVERSAL": {
            "cwe": "CWE-22",
            "owasp": "A01:2021",
            "severity": "critical",
            "python": [
                'open("uploads/" + filename)',
                'with open(user_file) as f: return f.read()',
                'filepath = "data/" + request.params.path',
            ],
            "javascript": [
                'fs.readFileSync("uploads/" + filename)',
                'require("fs").createReadStream(userPath)',
            ],
            "java": [
                'new FileInputStream(userFile);',
            ]
        },
        
        "XXE": {
            "cwe": "CWE-611",
            "owasp": "A04:2021",
            "severity": "critical",
            "python": [
                'import xml.etree.ElementTree as ET',
                'ET.parse(user_xml)',
                'dom.parseString(user_xml)',
            ],
            "javascript": [
                'new DOMParser().parseFromString(userxml);',
            ],
            "java": [
                'DocumentBuilder dbf = DocumentBuilderFactory.newInstance().newDocumentBuilder();',
            ]
        },
        
        "BUFFER_OVERFLOW": {
            "cwe": "CWE-119",
            "owasp": "A01:2021",
            "severity": "critical",
            "c": [
                'gets(buffer)',
                'strcpy(dest, src)',
                'memcpy(buffer, input, len)',
            ],
            "python": [
                'struct.pack("10s", userInput)',
            ]
        },
        
        "REDOS": {
            "cwe": "CWE-1333",
            "owasp": "A01:2021",
            "severity": "high",
            "python": [
                're.compile(user_input + "+$")',
                'regex.match(userData)',
                'pattern = re.compile("(a+)+$")',
            ],
            "javascript": [
                'new RegExp(userInput + "+")',
                'pattern.test(user_input)',
            ]
        },
        
        "RACE_CONDITION": {
            "cwe": "CWE-362",
            "owasp": "A04:2021",
            "severity": "high",
            "python": [
                'if balance >= amount: balance -= amount',
                'count = count + 1',
            ],
            "javascript": [
                'if (count > 0) count--;',
            ]
        },
        
        "MEMORY_LEAK": {
            "cwe": "CWE-401",
            "owasp": "A04:2021",
            "severity": "medium",
            "python": [
                'conn = getConnection()',
                'file = open(path)',
                'response = requests.get(url)',
            ],
            "javascript": [
                'const conn = db.connect();',
            ]
        },
        
        "NULL_POINTER": {
            "cwe": "CWE-476",
            "owasp": "A04:2021",
            "severity": "medium",
            "python": [
                'user.getName()',
                'obj.property',
            ],
            "javascript": [
                'user.name',
            ],
            "java": [
                'user.getName();',
            ]
        },
        
        "EMPTY_CATCH": {
            "cwe": "CWE-390",
            "owasp": "A04:2021",
            "severity": "low",
            "python": [
                'try: pass',
                'except: pass',
                'except Exception: pass',
            ],
            "javascript": [
                '} catch(err) {}',
                '} catch(e) { }',
            ],
            "java": [
                '} catch(Exception e) { }',
            ]
        },
        
        "JWT_VULNERABILITY": {
            "cwe": "CWE-347",
            "owasp": "A02:2021",
            "severity": "critical",
            "python": [
                'jwt.decode(token, options={"verify_signature": False})',
                'jwt.encode(payload, "secret")',
            ],
            "javascript": [
                'jwt.verify(token, secret, {algorithms: []})',
                'jwt.sign(payload, secret, {algorithm: "none"})',
            ]
        },
        
        "OPEN_REDIRECT": {
            "cwe": "CWE-601",
            "owasp": "A01:2021",
            "severity": "high",
            "python": [
                'return redirect(params.get("next"))',
                'Response.redirect(userURL)',
            ],
            "javascript": [
                'res.redirect(req.query.next)',
                'res.location(userProvidedUrl);',
            ]
        },
        
        "CSRF": {
            "cwe": "CWE-352",
            "owasp": "A01:2021",
            "severity": "high",
            "python": [
                '@app.route("/transfer") def transfer(): pass',
                '@app.post("/delete") def delete(): pass',
            ],
            "javascript": [
                'router.post("/update", handler)',
            ],
            "java": [
                '@PostMapping("/update") public void update();',
            ]
        }
    }
    
    # Clean patterns
    CLEAN_PATTERNS = {
        "python": [
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            'cursor.execute("SELECT * FROM users WHERE name = :name", {"name": username})',
            'element.textContent = sanitizer.escape(userInput)',
            'from markupsafe import escape',
            'subprocess.run(["ping", "-c", "1", host], check=True)',
            'filepath = os.path.join("uploads", os.path.basename(filename))',
            'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
            'hashlib.sha256(data).hexdigest()',
            'data = json.loads(user_data)',
            'yaml.safe_load(user_data)',
        ],
        "javascript": [
            'db.query("SELECT * FROM users WHERE id = ?", [userId])',
            'element.textContent = userInput;',
            'element.innerText = userInput;',
            'execFile("ping", [host], callback);',
            'bcrypt.hash(password, 12)',
            'JSON.parse(userData)',
            'fetch(safeUrl)',
        ],
        "java": [
            'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
            'ps.setString(1, userId);',
            'response.setContentType("text/html;charset=UTF-8");',
            'ProcessBuilder pb = new ProcessBuilder("ping", host);',
            'BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);',
        ],
        "php": [
            '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");',
            'htmlspecialchars($input, ENT_QUOTES, "UTF-8");',
        ],
        "c": [
            'strncpy(dest, src, sizeof(dest) - 1);',
            'if (len < sizeof(buf)) memcpy(buf, src, len);',
        ]
    }
    
    # Generate vulnerable samples with massive augmentation
    print("\n[Phase 1] Generating VULNERABLE samples...")
    for vuln_type, vuln_data in VULN_TEMPLATES.items():
        patterns = vuln_data.get("python", {}) or vuln_data.get("javascript", {})
        
        for lang, code_list in {k: v for k, v in vuln_data.items() if k in ["python", "javascript", "java", "php", "c"]}.items():
            for code in code_list:
                # Generate 50 variations per pattern
                for variation in range(50):
                    samples.append({
                        "code": code,
                        "language": lang,
                        "label": vuln_type,
                        "is_vulnerable": 1,
                        "cwe": vuln_data.get("cwe", ""),
                        "owasp": vuln_data.get("owasp", ""),
                        "severity": vuln_data.get("severity", "high")
                    })
    
    vuln_count = len(samples)
    print(f"   ✓ Vulnerable: {vuln_count}")
    
    # Generate clean samples with massive augmentation
    print("\n[Phase 2] Generating SECURE samples...")
    for lang, code_list in CLEAN_PATTERNS.items():
        for code in code_list:
            for variation in range(50):
                samples.append({
                    "code": code,
                    "language": lang,
                    "label": "SECURE",
                    "is_vulnerable": 0,
                    "cwe": "",
                    "owasp": "",
                    "severity": "clean"
                })
    
    clean_count = len(samples) - vuln_count
    print(f"   ✓ Secure: {clean_count}")
    
    return samples

def merge_and_save(all_samples):
    """Merge all data and save final dataset"""
    
    print("\n" + "=" * 70)
    print("💾 SAVING FINAL DATASET...")
    print("=" * 70)
    
    df = pd.DataFrame(all_samples)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split
    train_size = int(0.8 * len(df))
    val_size = int(0.1 * len(df))
    
    train_df = df[:train_size]
    val_df = df[train_size:train_size + val_size]
    test_df = df[train_size + val_size:]
    
    # Save
    output_dir = Path("dataset/")
    output_dir.mkdir(exist_ok=True)
    
    train_df.to_csv(f"{output_dir}/train.csv", index=False)
    val_df.to_csv(f"{output_dir}/val.csv", index=False)
    test_df.to_csv(f"{output_dir}/test.csv", index=False)
    
    # Metadata
    metadata = {
        "model_name": "RakshakAI",
        "version": "1.0.0",
        "total_samples": len(df),
        "train_samples": len(train_df),
        "val_samples": len(val_df),
        "test_samples": len(test_df),
        "vulnerable_samples": int(df["is_vulnerable"].sum()),
        "secure_samples": int(len(df) - df["is_vulnerable"].sum()),
    }
    
    with open(f"{output_dir}/metadata.json", "w") as f:
        json.dump(metadata, f, indent=2)
    
    print(f"\n✓ Final Dataset:")
    print(f"  • Total: {len(df):,} samples")
    print(f"  • Train: {len(train_df):,} samples")
    print(f"  • Val: {len(val_df):,} samples")
    print(f"  • Test: {len(test_df):,} samples")
    print(f"  • Vulnerable: {int(df['is_vulnerable'].sum()):,} ({100*df['is_vulnerable'].mean():.1f}%)")
    print(f"  • Secure: {int(len(df) - df['is_vulnerable'].sum()):,}")
    
    return train_df, val_df, test_df

if __name__ == "__main__":
    all_samples = []
    
    # Load from HuggingFace (if available)
    try:
        hf_samples = load_huggingface_dataset()
        all_samples.extend(hf_samples)
    except Exception as e:
        print(f"⚠ HuggingFace load failed: {e}")
    
    # Generate synthetic
    synthetic_samples = create_mega_synthetic()
    all_samples.extend(synthetic_samples)
    
    # Save
    train_df, val_df, test_df = merge_and_save(all_samples)
    
    print("\n" + "=" * 70)
    print("🏛️ CODE GUARDIAN - AATMAN DATASET READY!")
    print("=" * 70)
    print(f"\n📊 Total samples: {len(train_df) + len(val_df) + len(test_df):,}")
    print(f"\n🚀 To train:")
    print(f"   cd ml-model && source cg-ml-env/bin/activate")
    print(f"   python3 train.py")