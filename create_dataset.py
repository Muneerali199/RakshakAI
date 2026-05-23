"""
RakshakAI - Complete Training Dataset Generator
Generates comprehensive training data for vulnerability detection

This script creates a large, balanced dataset of:
- Vulnerable code samples (positive)
- Clean/fixed code samples (negative)
- Multiple programming languages
"""

import json
import random
import os
from pathlib import Path
from datetime import datetime

# ========================================================
# VULNERABILITY TEMPLATES (Multi-language)
# ========================================================

VULNERABILITY_DATABASE = {
    "SQL_INJECTION": {
        "description": "User input concatenated directly into SQL queries",
        "cwe": "CWE-89",
        "owasp": "A03:2021",
        "python": [
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")',
            'db.query("SELECT * FROM items WHERE " + filter)',
            'sql = "INSERT INTO logs VALUES(\'" + msg + "\')"',
            'cursor.execute(f"SELECT * FROM users WHERE email = \'{email}\'")'
        ],
        "javascript": [
            'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
            'const query = "SELECT * FROM products WHERE " + filter',
            'connection.query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            'await db.execute(`SELECT * FROM users WHERE id = ${userId}`)'
        ],
        "java": [
            'Statement stmt = conn.createStatement();\nString query = "SELECT * FROM users WHERE id = " + userId;',
            '@Query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            'entityManager.createQuery("SELECT u FROM User u WHERE name = " + name)'
        ],
        "php": [
            '$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);',
            '$db->query("SELECT * FROM posts WHERE author = \'" . $author . "\'")'
        ]
    },
    "XSS": {
        "description": "User input rendered without sanitization",
        "cwe": "CWE-79",
        "owasp": "A03:2021",
        "python": [
            'return "<div>" + user_input + "</div>"',
            'Response.write(userName)',
            'template.render_string(user_content)'
        ],
        "javascript": [
            'document.getElementById("output").innerHTML = userInput',
            'element.innerHTML = req.params.value',
            '$("#div").html(userContent);',
            'render("<span>" + data + "</span>")'
        ],
        "java": [
            'response.getWriter().write(userInput)',
            'out.println("<div>" + name + "</div>")',
            '@Component public String sink(String input) { return input; }'
        ],
        "php": [
            'echo "<div>" . $_GET["content"] . "</div>";',
            'print $userMessage;'
        ]
    },
    "COMMAND_INJECTION": {
        "description": "User input passed to shell commands unsanitized",
        "cwe": "CWE-78",
        "owasp": "A03:2021",
        "python": [
            'os.system("ping " + user_input)',
            'subprocess.call("ls " + directory, shell=True)',
            'os.popen("cat " + filename)',
            'commands.getstatusoutput("rm " + file)'
        ],
        "javascript": [
            'exec("ls " + userInput, callback)',
            'child_process.execSync("ping " + req.body.host)',
            'require("child_process").spawn(cmd + " " + arg)'
        ],
        "java": [
            'Runtime.getRuntime().exec("ping " + host)',
            'ProcessBuilder pb = new ProcessBuilder("ls", directory);',
            'Runtime r = Runtime.getRuntime();\nr.exec(cmd + input)'
        ]
    },
    "HARDCODED_SECRET": {
        "description": "Credentials or secrets hardcoded in source",
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "python": [
            'API_KEY = "sk_live_abc123xyz789"',
            'password = "admin123"',
            'SECRET_TOKEN = "my-secret-value"',
            'db_password = "Password123"'
        ],
        "javascript": [
            'const API_KEY = "sk_live_abc123";',
            'const SECRET = "my-secret-token";',
            'const PASSWORD = "admin123";'
        ],
        "java": [
            'private static final String API_KEY = "sk-abc123";',
            'String password = "admin123";',
            'private String token = "secret123";'
        ],
        "php": [
            '$apiKey = "sk_live_abc123";',
            '$password = "admin123";'
        ]
    },
    "PATH_TRAVERSAL": {
        "description": "File paths constructed from user input without validation",
        "cwe": "CWE-22",
        "owasp": "A01:2021",
        "python": [
            'open("uploads/" + filename)',
            'with open(user_file) as f: return f.read()',
            'filepath = "data/" + request.params.path'
        ],
        "javascript": [
            'fs.readFileSync("uploads/" + filename)',
            'require("fs").createReadStream(userPath)',
            'path.join("files", req.body.file)'
        ],
        "java": [
            'new FileInputStream(userFile)',
            'Files.readAllPaths(Paths.get("data/" + name))',
            'File f = new File(directory + filename);'
        ]
    },
    "WEAK_CRYPTO": {
        "description": "Using weak hashing/encryption (MD5, SHA1)",
        "cwe": "CWE-327",
        "owasp": "A02:2021",
        "python": [
            'hashlib.md5(data).hexdigest()',
            'hashlib.sha1(password).hexdigest()',
            'hashlib.new("md5")'
        ],
        "javascript": [
            'crypto.createHash("md5")',
            'require("crypto").createHash("sha1")',
            'md5(userInput)'
        ],
        "java": [
            'MessageDigest.getInstance("MD5")',
            'DigestUtils.md5Hex(data)',
            'Cipher.getInstance("DES")'
        ]
    },
    "SSTI": {
        "description": "User input in template strings executed as code",
        "cwe": "CWE-94",
        "owasp": "A03:2021",
        "python": [
            'Template("Hello " + user).render()',
            'render_template_string(user_input)',
            'f"Welcome {username}"'
        ],
        "javascript": [
            'handlebars.compile(userInput)(data)',
            'ejs.render(userData, options)',
            '_.template(userContent)(context)'
        ]
    },
    "INSECURE_DESERIALIZATION": {
        "description": "Deserializing untrusted data",
        "cwe": "CWE-502",
        "owasp": "A08:2021",
        "python": [
            'pickle.loads(data)',
            'yaml.load(user_data)',
            'marshal.loads(userInput)'
        ],
        "javascript": [
            'JSON.parse(userData)',
            'unserialize(userInput)',
            'new Function("return " + userCode)'
        ],
        "java": [
            'ObjectInputStream.readObject()',
            'XMLDecoder.readObject()',
            'new ObjectInputStream(input).readObject()'
        ]
    },
    "JWT_VULNERABILITY": {
        "description": "JWT signature not verified or uses weak algorithm",
        "cwe": "CWE-347",
        "owasp": "A02:2021",
        "python": [
            'jwt.decode(token, options={"verify_signature": False})',
            'jwt.encode(payload, "secret")',
            'PyJWT().decode(token, algorithms=["HS256"])'
        ],
        "javascript": [
            'jwt.verify(token, secret, {algorithms: []})',
            'jwt.sign(payload, secret, {algorithm: "none"})'
        ],
        "java": [
            'io.jsonwebtoken.Jwts.parser().setSigningKey(secret).parseClaimsJws(token)'
        ]
    },
    "REDOS": {
        "description": "Regular expression denial of service",
        "cwe": "CWE-1333",
        "owasp": "A01:2021",
        "python": [
            're.compile(user_input + "+$")',
            'regex.match(userData)',
            'pattern = "(a+)+$"'
        ],
        "javascript": [
            'new RegExp(user_input + "+")',
            'regex.test(user_data)',
            'pattern.match(user_input)'
        ]
    },
    "CSRF": {
        "description": "Missing CSRF protection on state-changing operations",
        "cwe": "CWE-352",
        "owasp": "A01:2021",
        "python": [
            '@app.route("/transfer") def transfer(): pass',
            '@app.post("/delete") def delete(): pass'
        ],
        "javascript": [
            'router.post("/update", handler)',
            'app.post("/transfer", controller)'
        ],
        "java": [
            '@PostMapping("/update") public void update()',
            '@RequestMapping(value = "/delete", method = RequestMethod.POST)'
        ]
    },
    "OPEN_REDIRECT": {
        "description": "Unvalidated redirect to external URLs",
        "cwe": "CWE-601",
        "owasp": "A01:2021",
        "python": [
            'return redirect(params.get("next"))',
            'Response.redirect(userURL)',
            'redirect(request.args.get("url"))'
        ],
        "javascript": [
            'res.redirect(req.query.next)',
            'res.location(userProvidedUrl)',
            'response.redirect(url)'
        ]
    },
    "NULL_DEREFERENCE": {
        "description": "Using potentially null object without null check",
        "cwe": "CWE-476",
        "owasp": "A04:2021",
        "python": [
            'user.getName()',
            'object.property',
            'data.toString()'
        ],
        "javascript": [
            'user.name',
            'obj.property',
            'data.value'
        ],
        "java": [
            'user.getName()',
            'object.getProperty()',
            'data.toString()'
        ]
    },
    "MEMORY_LEAK": {
        "description": "Resource not properly closed",
        "cwe": "CWE-401",
        "owasp": "A04:2021",
        "python": [
            'conn = getConnection()',
            'file = open(path)',
            'response = requests.get(url)'
        ],
        "javascript": [
            'const conn = db.connect()',
            'const stream = fs.createReadStream(path)'
        ],
        "java": [
            'Connection conn = getConnection()',
            'InputStream is = new FileInputStream(file)'
        ]
    },
    "EMPTY_CATCH": {
        "description": "Silently swallowing exceptions",
        "cwe": "CWE-390",
        "owasp": "A04:2021",
        "python": [
            'try: pass',
            'except: pass',
            'except Exception: pass'
        ],
        "javascript": [
            '} catch(err) {}',
            '} catch(e) { // ignore }',
            '} catch(error) { // no action }'
        ],
        "java": [
            '} catch(Exception e) { }',
            '} catch(IOException ex) { // empty }',
            '} catch(Error e) { }'
        ]
    },
    "BUFFER_OVERFLOW": {
        "description": "Unsafe memory operations without bounds checking",
        "cwe": "CWE-120",
        "owasp": "A01:2021",
        "c": [
            'strcpy(dest, userInput)',
            'memcpy(buffer, input, size)',
            'gets(userInput)'
        ],
        "python": [
            'struct.pack("10s", userInput)',
            'array.fromstring(userInput)'
        ]
    }
}

# ========================================================
# CLEAN CODE SAMPLES
# ========================================================

CLEAN_SAMPLES = {
    "python": [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'element.textContent = sanitizer.escape(userInput)',
        'subprocess.run(["ping", "-c", "1", host], check=True)',
        'filepath = os.path.join("uploads", os.path.basename(filename))',
        'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
        'user_input = escape(user_input)',
        'data = json.loads(user_data)',
        'return redirect(url_for("success"))'
    ],
    "javascript": [
        'db.query("SELECT * FROM users WHERE id = ?", [userId])',
        'element.textContent = userInput;',
        'execFile("ping", [host], callback)',
        'const safePath = path.basename(userPath);',
        'bcrypt.hash(password, 12)',
        'const escape = require("escape-html");',
        'const data = JSON.parse(userData)',
        'res.redirect("/success")'
    ],
    "java": [
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");',
        'ps.setString(1, userId);',
        'ProcessBuilder pb = new ProcessBuilder("ping", host);',
        'Path safePath = Paths.get(filename).getFileName();',
        'BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();',
        'response.sendRedirect("/success");'
    ],
    "php": [
        '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");',
        'htmlspecialchars($input, ENT_QUOTES);',
        '$safe = basename($filename);',
        'password_hash($pass, PASSWORD_BCRYPT);',
        'header("Location: /success");'
    ]
}

def generate_dataset(num_samples=5000, augment_factor=10):
    """Generate comprehensive training dataset"""
    
    print("=" * 60)
    print("GENERATING TRAINING DATASET")
    print("=" * 60)
    
    samples = []
    
    # Generate vulnerable samples
    print("\n[1] Generating vulnerable samples...")
    for vuln_type, vuln_data in VULNERABILITY_DATABASE.items():
        languages = vuln_data.get("python", []) and list(vuln_data.keys()) or ["python"]
        
        for lang in languages:
            if lang not in vuln_data or not vuln_data[lang]:
                continue
                
            code_list = vuln_data[lang]
            
            for original_code in code_list:
                # Add base sample
                samples.append({
                    "code": original_code,
                    "language": lang,
                    "label": vuln_type,
                    "is_vulnerable": 1,
                    "cwe": vuln_data.get("cwe", ""),
                    "description": vuln_data.get("description", "")
                })
                
                # Generate augmented variations
                for i in range(augment_factor):
                    augmented = augment_code(original_code, lang, i)
                    samples.append({
                        "code": augmented,
                        "language": lang,
                        "label": vuln_type,
                        "is_vulnerable": 1,
                        "cwe": vuln_data.get("cwe", ""),
                        "description": vuln_data.get("description", "")
                    })
    
    print(f"    Vulnerable samples: {len(samples)}")
    
    # Generate clean samples
    print("\n[2] Generating clean samples...")
    for lang, code_list in CLEAN_SAMPLES.items():
        for original_code in code_list:
            samples.append({
                "code": original_code,
                "language": lang,
                "label": "CLEAN",
                "is_vulnerable": 0,
                "cwe": "",
                "description": "Safe code following best practices"
            })
            
            # Augment clean samples too
            for i in range(3):
                augmented = augment_code(original_code, lang, i)
                samples.append({
                    "code": augmented,
                    "language": lang,
                    "label": "CLEAN",
                    "is_vulnerable": 0,
                    "cwe": "",
                    "description": "Safe code following best practices"
                })
    
    print(f"    Clean samples: {len([s for s in samples if s['is_vulnerable'] == 0])}")
    print(f"    Total samples: {len(samples)}")
    
    return samples

def augment_code(code, lang, seed):
    """Generate variations of code to increase dataset size"""
    random.seed(seed * 17 + hash(code) % 1000)
    
    variations = []
    
    # Variable name variations
    var_names = ["user", "data", "input", "value", "param", "item", "record", "entry"]
    new_var = random.choice(var_names)
    
    # Function name variations  
    func_names = ["process", "handle", "execute", "run", "parse"]
    new_func = random.choice(func_names)
    
    return code  # Return original for now (can implement more complex augmentation)

def save_dataset(samples, output_dir="dataset/"):
    """Save dataset to CSV files"""
    import pandas as pd
    
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    df = pd.DataFrame(samples)
    
    # Shuffle
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)
    
    # Split
    train_size = int(0.8 * len(df))
    val_size = int(0.1 * len(df))
    
    train_df = df[:train_size]
    val_df = df[train_size:train_size + val_size]
    test_df = df[train_size + val_size:]
    
    # Save
    train_df.to_csv(f"{output_dir}train.csv", index=False)
    val_df.to_csv(f"{output_dir}val.csv", index=False)
    test_df.to_csv(f"{output_dir}test.csv", index=False)
    
    print(f"\n[3] Dataset saved:")
    print(f"    Train: {len(train_df)} samples")
    print(f"    Val: {len(val_df)} samples")
    print(f"    Test: {len(test_df)} samples")
    
    # Label distribution
    print(f"\n[4] Label Distribution:")
    for label, count in df["label"].value_counts().items():
        print(f"    {label}: {count}")
    
    return train_df, val_df, test_df

def export_for_colab(output_file="rakshakai-dataset.zip"):
    """Export dataset for Google Colab"""
    import zipfile
    
    with zipfile.ZipFile(output_file, 'w') as z:
        z.write("ml-model/dataset/train.csv", "train.csv")
        z.write("ml-model/dataset/val.csv", "val.csv")
        z.write("ml-model/dataset/test.csv", "test.csv")
        z.write("ml-model/train.py", "train.py")
        z.write("ml-model/requirements.txt", "requirements.txt")
    
    print(f"\n[5] Exported to: {output_file}")
    print("    Upload this file to Google Colab to train with GPU!")

if __name__ == "__main__":
    # Generate dataset
    samples = generate_dataset(num_samples=5000, augment_factor=10)
    
    # Save
    train_df, val_df, test_df = save_dataset(samples)
    
    # Export note
    print("\n" + "=" * 60)
    print("DATASET READY!")
    print("=" * 60)
    print("Option 1: Train locally (CPU) - ~2.5 hours")
    print("  cd RakshakAI && source rakshakai-env/bin/activate")
    print("  python3 train.py")
    print()
    print("Option 2: Train on Google Colab (GPU) - ~20 mins")
    print("  1. Upload RakshakAI/ folder")
    print("  2. Run: !pip install -r requirements.txt")
    print("  3. Run: !python train.py")
    print("=" * 60)