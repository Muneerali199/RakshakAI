"""
RakshakAI — Knowledge Distillation Training Pipeline

Trains a lightweight student model (RakshakLightweightTransformer)
guided by a larger teacher model (CodeBERT).

If teacher is unavailable, trains standalone with label smoothing.
"""
from __future__ import annotations
import os
import sys
import json
import time
import math
import random
import logging
import argparse
from pathlib import Path
from datetime import datetime

import torch
import torch.nn as nn
import torch.nn.functional as F
from torch.utils.data import Dataset, DataLoader

# Adjust path for running from RakshakAI dir
sys.path.insert(0, str(Path(__file__).parent))

VULNERABILITY_CLASSES = [
    "CLEAN",
    "SQL_INJECTION", "XSS", "CSRF", "PATH_TRAVERSAL", "COMMAND_INJECTION",
    "HARDCODED_SECRET", "INSECURE_DESERIALIZATION", "OPEN_REDIRECT",
    "WEAK_CRYPTO", "JWT_VULNERABILITY", "LDAP_INJECTION", "XXE_INJECTION",
    "SSTI", "REDOS", "NULL_DEREFERENCE", "MEMORY_LEAK", "RACE_CONDITION",
    "BUFFER_OVERFLOW", "EMPTY_CATCH", "INFINITE_LOOP",
]

NUM_CLASSES = len(VULNERABILITY_CLASSES)
LABEL2ID = {l: i for i, l in enumerate(VULNERABILITY_CLASSES)}
ID2LABEL = {i: l for l, i in LABEL2ID.items()}


def setup_logging():
    log_file = f"training_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s | %(levelname)s | %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(log_file)],
    )
    return logging.getLogger(__name__)


logger = setup_logging()


# ═══════════════════════════════════════════════════════════
# DATASET GENERATION
# ═══════════════════════════════════════════════════════════

class VulnerabilityDatasetGenerator:
    """Generates synthetic code vulnerability dataset."""

    TEMPLATES = {
        "SQL_INJECTION": {
            "python": [
                'query = "SELECT * FROM users WHERE id = " + user_id',
                'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")',
                'db.query("SELECT * FROM items WHERE " + filter_param)',
                'sql = f"SELECT * FROM users WHERE email = \'{email}\'"',
                'conn.execute("DELETE FROM posts WHERE id = " + str(post_id))',
            ],
            "javascript": [
                'db.query("SELECT * FROM users WHERE id = " + req.params.id)',
                'const query = `SELECT * FROM products WHERE id = ${productId}`',
                'connection.query("SELECT * FROM users WHERE name = \'" + name + "\'")',
            ],
            "java": [
                'Statement stmt = conn.createStatement(); String q = "SELECT * FROM users WHERE id = " + userId;',
                'String query = "SELECT * FROM users WHERE name = \'" + name + "\'";',
            ],
            "php": [
                '$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET["id"]);',
            ],
        },
        "XSS": {
            "python": [
                'return "<div>" + user_input + "</div>"',
                'Response.write(userName)',
            ],
            "javascript": [
                'document.getElementById("output").innerHTML = userInput',
                'element.innerHTML = req.params.value',
                '$("#div").html(userContent)',
                'render("<span>" + data + "</span>")',
            ],
            "java": [
                'response.getWriter().write(userInput)',
                'out.println("<div>" + name + "</div>")',
            ],
        },
        "COMMAND_INJECTION": {
            "python": [
                'os.system("ping " + user_input)',
                'subprocess.call("ls " + directory, shell=True)',
                'os.popen("cat " + filename)',
            ],
            "javascript": [
                'exec("ls " + userInput, callback)',
                'child_process.execSync("ping " + req.body.host)',
            ],
            "java": [
                'Runtime.getRuntime().exec("ping " + host)',
                'ProcessBuilder pb = new ProcessBuilder("ls", directory);',
            ],
        },
        "HARDCODED_SECRET": {
            "python": [
                'API_KEY = "sk_live_abc123xyz789"',
                'password = "admin123"',
                'SECRET_TOKEN = "my-secret-value"',
                'db_password = "Password123"',
            ],
            "javascript": [
                'const API_KEY = "sk_live_abc123";',
                'const SECRET = "my-secret-token";',
            ],
            "java": [
                'private static final String API_KEY = "sk-abc123";',
                'String password = "admin123";',
            ],
            "php": [
                '$apiKey = "sk_live_abc123";',
            ],
        },
        "PATH_TRAVERSAL": {
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
                'new FileInputStream(userFile)',
                'File f = new File(directory + filename);',
            ],
        },
        "WEAK_CRYPTO": {
            "python": [
                'hashlib.md5(data).hexdigest()',
                'hashlib.sha1(password).hexdigest()',
            ],
            "javascript": [
                'crypto.createHash("md5")',
                'require("crypto").createHash("sha1")',
            ],
            "java": [
                'MessageDigest.getInstance("MD5")',
                'Cipher.getInstance("DES")',
            ],
        },
        "SSTI": {
            "python": [
                'Template("Hello " + user).render()',
                'render_template_string(user_input)',
            ],
            "javascript": [
                'handlebars.compile(userInput)(data)',
                'ejs.render(userData, options)',
            ],
        },
        "INSECURE_DESERIALIZATION": {
            "python": [
                "pickle.loads(data)",
                'yaml.load(user_data)',
            ],
            "javascript": [
                'unserialize(userInput)',
                'new Function("return " + userCode)',
            ],
            "java": [
                'ObjectInputStream.readObject()',
            ],
        },
        "JWT_VULNERABILITY": {
            "python": [
                'jwt.decode(token, options={"verify_signature": False})',
                'jwt.encode(payload, "secret")',
            ],
            "javascript": [
                'jwt.verify(token, secret, {algorithms: []})',
            ],
        },
        "REDOS": {
            "javascript": [
                'new RegExp(user_input + "+")',
                'regex.test(user_data)',
            ],
            "python": [
                're.compile(user_input + "+$")',
            ],
        },
        "CSRF": {
            "python": [
                '@app.route("/transfer") def transfer(): pass',
            ],
            "javascript": [
                'router.post("/update", handler)',
            ],
            "java": [
                '@PostMapping("/update") public void update() {}',
            ],
        },
        "OPEN_REDIRECT": {
            "python": [
                'return redirect(params.get("next"))',
            ],
            "javascript": [
                'res.redirect(req.query.next)',
            ],
        },
        "NULL_DEREFERENCE": {
            "python": [
                'user.getName()  # user might be null',
            ],
            "javascript": [
                'user.name  # might be null',
            ],
            "java": [
                'user.getName()  # no null check',
            ],
        },
        "MEMORY_LEAK": {
            "python": [
                'conn = getConnection()  # never closed',
                'file = open(path)  # never closed',
            ],
            "javascript": [
                'const conn = db.connect()  # never closed',
            ],
            "java": [
                'Connection conn = getConnection()  # not closed',
            ],
        },
        "EMPTY_CATCH": {
            "python": [
                "try:\n    pass\nexcept:\n    pass",
            ],
            "javascript": [
                "} catch(err) {}",
            ],
            "java": [
                "} catch(Exception e) { }",
            ],
        },
        "BUFFER_OVERFLOW": {
            "c": [
                "strcpy(dest, userInput)",
                "gets(userInput)",
            ],
        },
        "RACE_CONDITION": {
            "python": [
                "if balance >= amount: balance -= amount",
            ],
            "java": [
                "if (balance >= amount) { balance -= amount; }",
            ],
        },
        "INFINITE_LOOP": {
            "python": [
                "while True: pass",
            ],
            "javascript": [
                "while(true) {}",
            ],
        },
        "LDAP_INJECTION": {
            "python": [
                'ldap.search("dc=example,dc=com", "(uid=" + user + ")")',
            ],
        },
        "XXE_INJECTION": {
            "python": [
                'etree.fromstring(user_xml)',
            ],
            "java": [
                'DocumentBuilderFactory db = DocumentBuilderFactory.newInstance();\nDocument doc = db.newDocumentBuilder().parse(userXml);',
            ],
        },
    }

    CLEAN_TEMPLATES = {
        "python": [
            'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
            'element.textContent = sanitizer.escape(userInput)',
            'subprocess.run(["ping", host], check=True)',
            'filepath = os.path.join("uploads", os.path.basename(filename))',
            'hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())',
            'data = json.loads(user_data)',
            'return redirect(url_for("success"))',
            'path = os.path.normpath(os.path.join(BASE_DIR, filename))',
            'stmt = conn.prepare("SELECT * FROM users WHERE id = ?")',
            'result = re.sub(r"[<>\"\']", "", user_input)',
            'secret = os.environ.get("API_KEY")',
            'with open(filepath, "r") as f: contents = f.read()',
            'ip = validate_ip(host)',
            'allowed = ["css", "js", "png"]\nif ext in allowed: pass',
            'quote = conn.escape_string(username)',
        ],
        "javascript": [
            'db.query("SELECT * FROM users WHERE id = ?", [userId])',
            'element.textContent = userInput',
            'execFile("ping", [host], callback)',
            'const safePath = path.basename(userPath)',
            'const data = JSON.parse(userData)',
            'res.redirect("/success")',
            'const sanitized = DOMPurify.sanitize(userInput)',
            'const escaped = escapeHtml(userContent)',
            'crypto.createHash("sha256").update(data).digest("hex")',
        ],
        "java": [
            'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");\nps.setString(1, userId);',
            'ProcessBuilder pb = new ProcessBuilder("ping", host);',
            'response.sendRedirect("/success")',
            'import org.owasp.encoder.Encode;\nString safe = Encode.forHtml(userInput);',
        ],
        "php": [
            '$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");\n$stmt->execute([":id" => $id]);',
            'htmlspecialchars($input, ENT_QUOTES, "UTF-8")',
            'password_hash($pass, PASSWORD_BCRYPT)',
        ],
    }

    def generate(self, num_samples: int = 10000) -> list[dict]:
        samples = []
        num_classes = len(self.TEMPLATES)

        # Vulnerable samples
        vuln_per_class = max(1, num_samples // 2 // num_classes)
        for vuln_type, langs in self.TEMPLATES.items():
            for lang, examples in langs.items():
                for _ in range(max(1, vuln_per_class // max(len(langs), 1))):
                    code = random.choice(examples)
                    samples.append({
                        "code": code,
                        "language": lang,
                        "label": vuln_type,
                        "is_vulnerable": 1,
                    })

        # Clean samples
        clean_count = num_samples - len(samples)
        for _ in range(clean_count):
            lang = random.choice(list(self.CLEAN_TEMPLATES.keys()))
            code = random.choice(self.CLEAN_TEMPLATES[lang])
            samples.append({
                "code": code,
                "language": lang,
                "label": "CLEAN",
                "is_vulnerable": 0,
            })

        random.shuffle(samples)
        logger.info(f"Generated {len(samples)} samples ({len([s for s in samples if s['is_vulnerable']])} vulnerable, {len([s for s in samples if not s['is_vulnerable']])} clean)")
        return samples


# ═══════════════════════════════════════════════════════════
# DATASET CLASS
# ═══════════════════════════════════════════════════════════

class CodeDataset(Dataset):
    def __init__(self, samples: list[dict], tokenizer, max_length: int = 256):
        self.samples = samples
        self.tokenizer = tokenizer
        self.max_length = max_length

    def __len__(self):
        return len(self.samples)

    def __getitem__(self, idx):
        sample = self.samples[idx]
        code = sample["code"]
        label = sample["label"]
        lang = sample["language"]

        # Prepend language marker
        text = f"[{lang}] {code}"
        input_ids = self.tokenizer.encode(text, self.max_length)
        label_id = LABEL2ID.get(label, 0)

        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "labels": torch.tensor(label_id, dtype=torch.long),
            "attention_mask": torch.tensor(
                [1 if t != self.tokenizer.pad_id else 0 for t in input_ids],
                dtype=torch.long,
            ),
        }


# ═══════════════════════════════════════════════════════════
# KNOWLEDGE DISTILLATION
# ═══════════════════════════════════════════════════════════

class DistillationTrainer:
    def __init__(
        self,
        student_model: nn.Module,
        teacher_model: nn.Module | None = None,
        device: str = "cpu",
        temperature: float = 4.0,
        alpha: float = 0.3,
    ):
        self.student = student_model.to(device)
        self.teacher = teacher_model.to(device) if teacher_model else None
        self.device = device
        self.temperature = temperature
        self.alpha = alpha
        self.ce_loss = nn.CrossEntropyLoss()

    def train_epoch(
        self,
        loader: DataLoader,
        optimizer: torch.optim.Optimizer,
        scheduler=None,
    ) -> float:
        self.student.train()
        total_loss = 0

        for batch in loader:
            input_ids = batch["input_ids"].to(self.device)
            attention_mask = batch["attention_mask"].to(self.device)
            labels = batch["labels"].to(self.device)

            optimizer.zero_grad()

            student_logits = self.student(input_ids, attention_mask)

            if self.teacher is not None:
                with torch.no_grad():
                    teacher_logits = self.teacher(input_ids, attention_mask)

                soft_targets = F.softmax(teacher_logits / self.temperature, dim=-1)
                soft_student = F.log_softmax(student_logits / self.temperature, dim=-1)
                distill_loss = F.kl_div(soft_student, soft_targets, reduction="batchmean")
                distill_loss *= self.temperature ** 2

                ce_loss = self.ce_loss(student_logits, labels)
                loss = self.alpha * distill_loss + (1 - self.alpha) * ce_loss
            else:
                loss = self.ce_loss(student_logits, labels)

            loss.backward()
            torch.nn.utils.clip_grad_norm_(self.student.parameters(), 1.0)
            optimizer.step()
            if scheduler:
                scheduler.step()

            total_loss += loss.item()

        return total_loss / len(loader)

    @torch.no_grad()
    def evaluate(self, loader: DataLoader) -> dict:
        self.student.eval()
        total, correct = 0, 0
        all_preds, all_labels = [], []
        total_loss = 0

        for batch in loader:
            input_ids = batch["input_ids"].to(self.device)
            attention_mask = batch["attention_mask"].to(self.device)
            labels = batch["labels"].to(self.device)

            student_logits = self.student(input_ids, attention_mask)
            loss = self.ce_loss(student_logits, labels)
            total_loss += loss.item()

            preds = student_logits.argmax(dim=-1)
            correct += (preds == labels).sum().item()
            total += labels.size(0)
            all_preds.extend(preds.cpu().tolist())
            all_labels.extend(labels.cpu().tolist())

        return {
            "accuracy": correct / total if total > 0 else 0,
            "loss": total_loss / len(loader),
            "correct": correct,
            "total": total,
            "predictions": all_preds,
            "labels": all_labels,
        }


# ═══════════════════════════════════════════════════════════
# TEACHER MODEL LOADER
# ═══════════════════════════════════════════════════════════

def load_teacher_model(device: str = "cpu"):
    """Load CodeBERT as teacher for distillation. Returns None if unavailable."""
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification
        logger.info("Loading CodeBERT teacher model...")
        tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
        model = AutoModelForSequenceClassification.from_pretrained(
            "microsoft/codebert-base", num_labels=NUM_CLASSES
        )
        model.to(device)
        model.eval()
        logger.info("Teacher model loaded successfully")
        return model, tokenizer
    except Exception as e:
        logger.warning(f"Could not load teacher model: {e}")
        logger.info("Training without knowledge distillation (standalone mode)")
        return None, None


# ═══════════════════════════════════════════════════════════
# MAIN TRAINING
# ═══════════════════════════════════════════════════════════

def train_lightweight(args):
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    logger.info(f"Using device: {device}")
    logger.info(f"Training config: {vars(args)}")

    # 1. Generate dataset
    logger.info("Generating training dataset...")
    generator = VulnerabilityDatasetGenerator()
    samples = generator.generate(args.num_samples)

    # Split
    random.shuffle(samples)
    n_train = int(len(samples) * args.train_split)
    n_val = int(len(samples) * args.val_split)
    train_samples = samples[:n_train]
    val_samples = samples[n_train : n_train + n_val]
    test_samples = samples[n_train + n_val:]

    logger.info(f"Train: {len(train_samples)}, Val: {len(val_samples)}, Test: {len(test_samples)}")

    # 2. Create tokenizer
    from rakshak_tokenizer import RakshakTokenizer

    tokenizer_path = "models/rakshak_tokenizer.json"
    if os.path.exists(tokenizer_path):
        tokenizer = RakshakTokenizer.load(tokenizer_path)
        logger.info(f"Loaded existing tokenizer from {tokenizer_path}")
    else:
        logger.info("Training tokenizer...")
        tokenizer = RakshakTokenizer(vocab_size=args.vocab_size)
        texts = [s["code"] for s in samples]
        tokenizer.train(texts)
        tokenizer.save(tokenizer_path)

    # 3. Create datasets
    train_ds = CodeDataset(train_samples, tokenizer, args.max_length)
    val_ds = CodeDataset(val_samples, tokenizer, args.max_length)
    test_ds = CodeDataset(test_samples, tokenizer, args.max_length)

    train_loader = DataLoader(train_ds, batch_size=args.batch_size, shuffle=True, num_workers=0)
    val_loader = DataLoader(val_ds, batch_size=args.batch_size, num_workers=0)
    test_loader = DataLoader(test_ds, batch_size=args.batch_size, num_workers=0)

    # 4. Create student model
    from rakshak_model import RakshakLightweightTransformer

    student = RakshakLightweightTransformer(
        vocab_size=args.vocab_size,
        d_model=args.d_model,
        num_heads=args.num_heads,
        d_ff=args.d_ff,
        num_layers=args.num_layers,
        num_classes=NUM_CLASSES,
        max_len=args.max_length,
        dropout=args.dropout,
        pad_token_id=tokenizer.pad_id,
    )

    params = student.count_params()
    logger.info(f"Student model params: {params['total']:,} total, {params['trainable']:,} trainable")

    # 5. Load teacher for distillation
    teacher_model, _ = load_teacher_model(device)

    if teacher_model:
        logger.info("Training with knowledge distillation")
    else:
        logger.info("Training standalone (no teacher)")

    # 6. Setup trainer
    trainer = DistillationTrainer(
        student_model=student,
        teacher_model=teacher_model,
        device=device,
        temperature=args.temperature,
        alpha=args.distill_alpha if teacher_model else 0.0,
    )

    optimizer = torch.optim.AdamW(student.parameters(), lr=args.lr, weight_decay=args.weight_decay)
    total_steps = len(train_loader) * args.epochs
    scheduler = torch.optim.lr_scheduler.CosineAnnealingLR(optimizer, T_max=total_steps)

    # 7. Training loop
    best_acc = 0.0
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 60)
    logger.info("STARTING TRAINING")
    logger.info("=" * 60)

    for epoch in range(args.epochs):
        start = time.time()
        train_loss = trainer.train_epoch(train_loader, optimizer, scheduler)
        metrics = trainer.evaluate(val_loader)
        elapsed = time.time() - start

        logger.info(
            f"Epoch {epoch+1:2d}/{args.epochs} | "
            f"Train Loss: {train_loss:.4f} | "
            f"Val Loss: {metrics['loss']:.4f} | "
            f"Val Acc: {metrics['accuracy']:.4f} ({metrics['correct']}/{metrics['total']}) | "
            f"Time: {elapsed:.1f}s"
        )

        if metrics["accuracy"] > best_acc:
            best_acc = metrics["accuracy"]
            torch.save(
                {
                    "epoch": epoch,
                    "model_state_dict": student.state_dict(),
                    "optimizer_state_dict": optimizer.state_dict(),
                    "best_acc": best_acc,
                    "config": {
                        "vocab_size": args.vocab_size,
                        "d_model": args.d_model,
                        "num_heads": args.num_heads,
                        "d_ff": args.d_ff,
                        "num_layers": args.num_layers,
                        "num_classes": NUM_CLASSES,
                        "max_length": args.max_length,
                        "label2id": LABEL2ID,
                        "id2label": ID2LABEL,
                    },
                },
                output_dir / "best_model.pt",
            )
            logger.info(f"  → New best model saved (acc: {best_acc:.4f})")

        torch.save(
            student.state_dict(),
            output_dir / f"checkpoint_epoch_{epoch+1}.pt",
        )

    # 8. Final evaluation
    logger.info("=" * 60)
    logger.info("TRAINING COMPLETE")
    logger.info("=" * 60)

    # Load best and test
    checkpoint = torch.load(output_dir / "best_model.pt", map_location=device)
    student.load_state_dict(checkpoint["model_state_dict"])
    trainer.student = student

    test_metrics = trainer.evaluate(test_loader)
    logger.info(f"Test Accuracy: {test_metrics['accuracy']:.4f} ({test_metrics['correct']}/{test_metrics['total']})")

    # Per-class accuracy
    from sklearn.metrics import classification_report
    try:
        report = classification_report(
            test_metrics["labels"],
            test_metrics["predictions"],
            target_names=[ID2LABEL[i] for i in range(NUM_CLASSES)],
            zero_division=0,
        )
        logger.info(f"Classification Report:\n{report}")
    except ImportError:
        logger.info("Install scikit-learn for detailed metrics")

    # 9. Export to ONNX for inference
    try:
        export_to_onnx(student, tokenizer, output_dir)
    except Exception as e:
        logger.warning(f"ONNX export failed: {e}")

    logger.info(f"Best validation accuracy: {best_acc:.4f}")
    logger.info(f"Model saved to: {output_dir / 'best_model.pt'}")
    return best_acc


def export_to_onnx(model, tokenizer, output_dir):
    """Export model to ONNX for fast CPU inference."""
    import onnx
    import onnxruntime

    dummy_input = torch.randint(0, 1000, (1, 256), dtype=torch.long)
    dummy_mask = torch.ones(1, 256, dtype=torch.long)

    torch.onnx.export(
        model,
        (dummy_input, dummy_mask),
        output_dir / "model.onnx",
        input_names=["input_ids", "attention_mask"],
        output_names=["logits"],
        dynamic_axes={
            "input_ids": {0: "batch_size"},
            "attention_mask": {0: "batch_size"},
            "logits": {0: "batch_size"},
        },
        opset_version=14,
    )
    logger.info(f"Model exported to ONNX: {output_dir / 'model.onnx'}")

    # Validate
    session = onnxruntime.InferenceSession(str(output_dir / "model.onnx"))
    logger.info(f"ONNX model validated: {session.get_inputs()[0].name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train RakshakAI lightweight model")

    # Dataset
    parser.add_argument("--num-samples", type=int, default=10000, help="Total samples to generate")
    parser.add_argument("--train-split", type=float, default=0.8)
    parser.add_argument("--val-split", type=float, default=0.1)

    # Model architecture
    parser.add_argument("--vocab-size", type=int, default=8000, help="Tokenizer vocabulary size")
    parser.add_argument("--d-model", type=int, default=128, help="Transformer embedding dimension")
    parser.add_argument("--num-heads", type=int, default=4, help="Attention heads")
    parser.add_argument("--d-ff", type=int, default=256, help="Feed-forward hidden dimension")
    parser.add_argument("--num-layers", type=int, default=4, help="Transformer encoder layers")
    parser.add_argument("--dropout", type=float, default=0.1)

    # Training
    parser.add_argument("--batch-size", type=int, default=16)
    parser.add_argument("--lr", type=float, default=2e-4)
    parser.add_argument("--weight-decay", type=float, default=0.01)
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--max-length", type=int, default=256)

    # Distillation
    parser.add_argument("--temperature", type=float, default=4.0, help="Distillation temperature")
    parser.add_argument("--distill-alpha", type=float, default=0.3, help="Distillation loss weight")

    # Output
    parser.add_argument("--output-dir", type=str, default="models/rakshakai-v1/")

    args = parser.parse_args()

    # Default to tiny config
    if not any(arg.startswith("--d-model") for arg in sys.argv[1:]):
        logger.info("Using default tiny configuration (--d-model 128, 4 layers, 8k vocab)")
        logger.info("  For small:  --d-model 256 --num-heads 8 --d-ff 512 --num-layers 6 --vocab-size 16000")
        logger.info("  For medium: --d-model 384 --num-heads 12 --d-ff 768 --num-layers 8 --vocab-size 32000")

    train_lightweight(args)
