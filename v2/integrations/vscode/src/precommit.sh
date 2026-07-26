#!/bin/bash
# RakshakAI Pre-commit Hook - Blocks commits if vulnerabilities found

echo "🛡️  RakshakAI: Scanning staged files..."

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(py|js|ts|java|go|rs|c|cpp|php|rb)$' || true)

if [ -z "$STAGED_FILES" ]; then
  echo "✅ No code files to scan"
  exit 0
fi

# Scan each staged file
HAS_VULN=0
CRITICAL_COUNT=0
HIGH_COUNT=0

for FILE in $STAGED_FILES; do
  if [ -f "$FILE" ]; then
    echo "  Scanning: $FILE"
    
    # Call RakshakAI server to scan
    RESULT=$(curl -s -X POST http://localhost:8080/v2/scan \
      -H "Content-Type: application/json" \
      -d "{\"code\": \"$(cat "$FILE" | sed 's/"/\\"/g' | sed ':a;N;$!ba;s/\n/\\n/g')\"," \
         "\"language\": \"${FILE##*.}\"," \
         "\"provider\": \"ollama\"}" 2>/dev/null || echo '{"finding":{}}')
    
    # Check if vulnerability found
    CWE=$(echo "$RESULT" | grep -o '"cwe":"[^"]*"' | cut -d'"' -f4 || true)
    SEVERITY=$(echo "$RESULT" | grep -o '"severity":"[^"]*"' | cut -d'"' -f4 || true)
    VULN=$(echo "$RESULT" | grep -o '"vulnerability":"[^"]*"' | cut -d'"' -f4 || true)
    
    if [ ! -z "$CWE" ]; then
      echo "  ❌ Found: $CWE - $VULN ($SEVERITY)"
      HAS_VULN=1
      
      if [ "$SEVERITY" = "critical" ]; then
        CRITICAL_COUNT=$((CRITICAL_COUNT + 1))
      elif [ "$SEVERITY" = "high" ]; then
        HIGH_COUNT=$((HIGH_COUNT + 1))
      fi
    fi
  fi
done

# Block commit if vulnerabilities found
if [ $HAS_VULN -eq 1 ]; then
  echo ""
  echo "🚨 COMMIT BLOCKED!"
  echo "   Found vulnerabilities: $CRITICAL_COUNT critical, $HIGH_COUNT high"
  echo ""
  echo "Please fix the vulnerabilities before committing."
  echo "Or use: git commit --no-verify to bypass (not recommended)"
  echo ""
  echo "Run 'rakshakai' CLI to scan and fix issues."
  exit 1
fi

echo "✅ No vulnerabilities found - commit allowed"
exit 0
