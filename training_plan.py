#!/usr/bin/env python3
"""
RakshakAI ML Model Training Script
Optimized for MacBook Pro i9 (8-core CPU, 16GB RAM) - No GPU

Hardware Analysis:
- CPU: Intel Core i9-9880H @ 2.30GHz (8 cores, 16 threads)
- RAM: 17GB usable
- Disk: 838GB available
- GPU: Intel UHD 630 (no CUDA)
- Training: CPU only (slow but functional)

Training Strategy:
- Use DistilBERT instead of CodeBERT (6 layers vs 12, 40% smaller)
- Reduce MAX_LENGTH to 256 (from 512)
- Use batch size of 4 (from 16) to prevent OOM
- Use gradient accumulation to simulate larger batches
- Estimate: ~3-5 hours for 10,000 samples on CPU
"""

import os
import sys
import json
import time
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)s | %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(f'training_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
    ]
)
logger = logging.getLogger(__name__)

# ========================================================
# CONFIGURATION - OPTIMIZED FOR MACBOOK PRO I9 (CPU)
# ========================================================
CONFIG = {
    # Model Configuration
    "model_name": "microsoft/codebert-base",  # CodeBERT (works better for code)
    # "model_name": "distilbert-base-uncased",  # Alternative: faster but less accurate
    
    # Training Hyperparameters - Optimized for CPU
    "max_length": 256,           # Reduced from 512 (50% less memory)
    "batch_size": 4,            # Reduced from 16 (prevents OOM)
    "gradient_accumulation_steps": 4,  # Effective batch = 4 * 4 = 16
    "epochs": 10,               # Full training
    "learning_rate": 2e-5,
    "warmup_steps": 100,         # Reduced from 500
    
    # Dataset
    "train_samples": 5000,       # Start with 5k (can scale to 10k)
    "val_split": 0.2,
    "test_split": 0.1,
    
    # Hardware
    "num_workers": 4,           # Use 4 cores for DataLoader
    "mixed_precision": False,    # No GPU = no mixed precision
    
    # Paths
    "output_dir": "models/rakshakai-v1/",
    "dataset_dir": "dataset/",
}

# Vulnerability Classes (21 classes)
VULNERABILITY_CLASSES = [
    "SQL_INJECTION", "XSS", "CSRF", "PATH_TRAVERSAL", "COMMAND_INJECTION",
    "HARDCODED_SECRET", "INSECURE_DESERIALIZATION", "OPEN_REDIRECT",
    "WEAK_CRYPTO", "JWT_VULNERABILITY", "LDAP_INJECTION", "XXE_INJECTION",
    "SSTI", "REDOS", "NULL_DEREFERENCE", "MEMORY_LEAK", "RACE_CONDITION",
    "BUFFER_OVERFLOW", "EMPTY_CATCH", "INFINITE_LOOP", "CLEAN"
]

LABEL2ID = {label: idx for idx, label in enumerate(VULNERABILITY_CLASSES)}
ID2LABEL = {idx: label for label, idx in LABEL2ID.items()}

def print_hardware_info():
    """Print current hardware configuration"""
    logger.info("=" * 60)
    logger.info("HARDWARE ANALYSIS")
    logger.info("=" * 60)
    
    # CPU Info
    try:
        import subprocess
        cpu_info = subprocess.run(['sysctl', '-n', 'machdep.cpu.brand_string'], 
                                  capture_output=True, text=True)
        logger.info(f"CPU: {cpu_info.stdout.strip()}")
    except:
        logger.info("CPU: Intel Core i9-9880H")
    
    # Memory
    try:
        mem_bytes = os.sysconf('SC_PHYS_PAGES') * os.sysconf('SC_PAGESIZE')
        mem_gb = mem_bytes / (1024**3)
        logger.info(f"RAM: {mem_gb:.1f} GB usable")
    except:
        logger.info("RAM: ~16 GB")
    
    # Disk
    import shutil
    disk = shutil.disk_usage("/")
    logger.info(f"Disk: {disk.free / (1024**3):.0f} GB free")
    
    # PyTorch
    try:
        import torch
        logger.info(f"PyTorch: {torch.__version__}")
        logger.info(f"CUDA Available: {torch.cuda.is_available()}")
    except ImportError:
        logger.warning("PyTorch not installed")
    
    logger.info("=" * 60)

def estimate_training_time():
    """Estimate training time based on hardware"""
    samples = CONFIG["train_samples"]
    epochs = CONFIG["epochs"]
    batch_size = CONFIG["batch_size"]
    steps_per_epoch = samples // batch_size
    
    # CPU estimate: ~0.5-1 second per batch on Intel i9
    time_per_batch = 0.75  # seconds
    total_time_seconds = steps_per_epoch * epochs * time_per_batch
    total_hours = total_time_seconds / 3600
    
    logger.info("=" * 60)
    logger.info("TRAINING ESTIMATE")
    logger.info("=" * 60)
    logger.info(f"Samples: {samples}")
    logger.info(f"Batch size: {batch_size} (effective: {batch_size * CONFIG['gradient_accumulation_steps']})")
    logger.info(f"Steps per epoch: {steps_per_epoch}")
    logger.info(f"Epochs: {epochs}")
    logger.info(f"Estimated time: ~{total_hours:.1f} hours ({total_hours/60:.1f} minutes)")
    logger.info("=" * 60)
    
    return total_hours

def create_synthetic_dataset():
    """Generate synthetic training data"""
    logger.info("Creating synthetic dataset...")
    
    samples = []
    
    # Manual examples for each vulnerability type
    vulnerability_examples = {
        "SQL_INJECTION": [
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'cursor.execute("SELECT * FROM users WHERE name = \'" + username + "\'")',
            'db.query("SELECT * FROM items WHERE " + filter)',
        ],
        "XSS": [
            'document.getElementById("output").innerHTML = userInput',
            'element.innerHTML = req.params.value',
            '$("#div").html(userContent);',
        ],
        "COMMAND_INJECTION": [
            'os.system("ping " + user_input)',
            'subprocess.call("ls " + directory, shell=True)',
            'exec("cat " + filename)',
        ],
        "HARDCODED_SECRET": [
            'API_KEY = "sk_live_abc123xyz"',
            'password = "admin123"',
            'const SECRET = "my-secret-token"',
        ],
        "PATH_TRAVERSAL": [
            'open("uploads/" + filename)',
            'File.new(path + user_file)',
            'f = open(request.params.file)',
        ],
        "WEAK_CRYPTO": [
            'hashlib.md5(data).hexdigest()',
            'hashlib.sha1(data).hexdigest()',
            'Crypto.createCipher("des")',
        ],
        "SSTI": [
            'Template("Hello " + user)',
            'render_template_string(user_input)',
            'f"Welcome {username}"',
        ],
        "INSECURE_DESERIALIZATION": [
            'pickle.loads(data)',
            'yaml.load(user_data)',
            'ObjectInputStream.readObject()',
        ],
        "JWT_VULNERABILITY": [
            'jwt.decode(token, options={"verify_signature": False})',
            'jwt.decode(token, algorithms=["RS256"], options={"verify": False})',
        ],
        "REDOS": [
            'regex = /^(a+)+$/',
            'pattern.match(userInput)',
            'new RegExp(userInput + "+")',
        ],
        "CSRF": [
            '@app.post("/transfer") def transfer(): pass',
            '@PostMapping("/update") public void update():',
            'router.post("/delete", handler)',
        ],
        "OPEN_REDIRECT": [
            'redirect(params.get("url"))',
            'return ResponseEntity.status(302).location(new URI(url)).build()',
            'res.redirect(userProvidedUrl)',
        ],
        "NULL_DEREFERENCE": [
            'user.getName()  # user might be null',
            'obj.property',
            'data.toString()  # no null check',
        ],
        "MEMORY_LEAK": [
            'conn = getConnection()  # never closed',
            'file = open(path)  # never closed',
            'new BufferedReader()  # never closed',
        ],
        "EMPTY_CATCH": [
            'try: pass',
            'catch (Exception e) { }',
            '} catch(err) {}',
        ],
        "BUFFER_OVERFLOW": [
            'strcpy(dest, userInput)',
            'memcpy(buffer, input, size)',
            'char s[10]; strcpy(s, user)',
        ],
        "RACE_CONDITION": [
            'if (balance >= amount) balance -= amount',
            'count = count + 1',
            'if (user.loggedIn) doSomething()',
        ],
        "WEAK_CRYPTO": [
            'bcrypt.hashpw(password, bcrypt.gensalt(1))',
            'Security.setProperty("crypto.policy", "unlimited")',
        ],
    }
    
    # Generate samples for each vulnerability type
    for vuln_type, examples in vulnerability_examples.items():
        for example in examples:
            # Determine language from syntax
            if "def " in example or "import " in example or ":" in example:
                lang = "python"
            elif "import " in example or "const " in example or "=>" in example:
                lang = "javascript"
            elif "public " in example or "private " in example:
                lang = "java"
            else:
                lang = "python"  # default
                
            samples.append({
                "code": example,
                "language": lang,
                "label": vuln_type,
                "is_vulnerable": 1 if vuln_type != "CLEAN" else 0
            })
    
    # Add clean (non-vulnerable) samples
    clean_samples = [
        "def get_user(user_id): return db.query('SELECT * FROM users WHERE id = ?', (user_id,))",
        "element.textContent = sanitizer.escape(userInput)",
        "subprocess.run(['ls', '-la', directory])",
        "password = os.environ.get('API_KEY')",
        "filepath = os.path.join('uploads', os.path.basename(filename))",
        "hashlib.sha256(data).hexdigest()",
    ]
    
    for example in clean_samples:
        samples.append({
            "code": example,
            "language": "python",
            "label": "CLEAN",
            "is_vulnerable": 0
        })
    
    logger.info(f"Created {len(samples)} synthetic samples")
    return samples

def main():
    """Main training entry point"""
    logger.info("Starting RakshakAI ML Training...")
    logger.info(f"Time: {datetime.now()}")
    
    # 1. Hardware Analysis
    print_hardware_info()
    
    # 2. Estimate Training Time
    estimate = estimate_training_time()
    
    # Question: Does user want to continue?
    if estimate > 5:
        logger.warning(f"Training will take ~{estimate:.1f} hours on CPU.")
        logger.warning("Recommendation: Consider using Google Colab (free GPU).")
    
    # 3. Create Dataset
    dataset = create_synthetic_dataset()
    
    # 4. Save Dataset
    output_dir = Path(CONFIG["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    
    dataset_path = Path(CONFIG["dataset_dir"])
    dataset_path.mkdir(parents=True, exist_ok=True)
    
    import pandas as pd
    df = pd.DataFrame(dataset)
    df.to_csv(f"{CONFIG['dataset_dir']}train_raw.csv", index=False)
    
    logger.info(f"Dataset saved to {CONFIG['dataset_dir']}train_raw.csv")
    logger.info(f"Total samples: {len(df)}")
    logger.info(f"Label distribution:\n{df['label'].value_counts().to_string()}")
    
    logger.info("=" * 60)
    logger.info("READY TO TRAIN")
    logger.info("=" * 60)
    logger.info("To start training, run: python3 ml-model/train.py")
    logger.info("Or use Google Colab for faster training with GPU.")
    
    # Save configuration
    with open("training_config.json", "w") as f:
        json.dump(CONFIG, f, indent=2)
    
    return CONFIG

if __name__ == "__main__":
    main()