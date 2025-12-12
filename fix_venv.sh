#!/bin/bash
echo "=== Recreating Virtual Environment (Fix for DBus) ==="

# Deactivate if running (handled by user shell, but good practice to mention)
# Remove old venv
if [ -d "venv" ]; then
    echo "[*] Removing old venv..."
    rm -rf venv
fi

# Create new venv with system site packages
echo "[*] Creating new venv with --system-site-packages..."
python3 -m venv --system-site-packages venv

# Upgrade pip inside venv
echo "[*] Upgrading pip..."
venv/bin/pip install --upgrade pip

# Install dependencies
echo "[*] Installing dependencies (simplepyble, cryptography)..."
venv/bin/pip install simplepyble cryptography

echo "=== Venv Fixed ==="
echo "Please run: source venv/bin/activate"
echo "Then: python3 sink/main.py"
