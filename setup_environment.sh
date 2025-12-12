#!/bin/bash
echo "=== SIC Project Environment Setup ==="

# 1. Update System
echo "[*] Updating package list..."
sudo apt update

# 2. Install System Dependencies for BlueZ and DBus
echo "[*] Installing system dependencies (BlueZ, libglib2, python3-dbus, python3-gi, python3-tkinter)..."
sudo apt install -y python3-dbus python3-gi python3-gi-cairo gir1.2-gtk-3.0 libgirepository1.0-dev libcairo2-dev python3-tk bluez libbluetooth-dev

# 3. Setup Python Virtual Environment (Optional if not using system packages directly)
# Note: On Kali/Debian, mixing system packages (apt) and pip is tricky.
# Simplest way for dbus-python is to use the apt version (`python3-dbus`).

echo "[*] Installing simplepyble and other python libs..."
# If inside a venv, you can try:
# pip install simplepyble cryptography

# If failing due to 'externally-managed-environment', and you want to install specifically for this user:
# pip install --break-system-packages simplepyble cryptography
# OR use a venv with --system-site-packages to inherit python3-dbus

if [ "$VIRTUAL_ENV" != "" ]; then
    echo "Detected VirtualEnv: $VIRTUAL_ENV"
    echo "Attempting to install PyPI packages..."
    pip install simplepyble cryptography
else
    echo "[!] Not in a VirtualEnv."
    echo "Recommended: Create a venv that inherits system packages:"
    echo "  python3 -m venv --system-site-packages venv"
    echo "  source venv/bin/activate"
    echo "Then run this script again or manually run: pip install simplepyble cryptography"
fi

echo "=== Setup Complete (Check for errors above) ==="
echo "Try running: python3 -c 'import dbus, simplepyble, gi; print(\"Imports OK\")'"
