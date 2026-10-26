#!/bin/bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo "[+] Done. Run with: python3 recon8.py <target>"

