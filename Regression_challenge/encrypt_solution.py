"""
encrypt_csv.py

This script encrypts a CSV file using a password-based Fernet key.
The resulting file can be safely shared and later decrypted
using the same password (as implemented in your Streamlit app).
"""
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import streamlit as st  # <- needed to read secrets

# --- Functions ---
def generate_key(password: str) -> bytes:
    """Generate a 32-byte Fernet key from a password using SHA-256."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_csv(input_csv: str, output_file: str, password: str):
    """Encrypt a CSV file using a password and save it to output_file."""
    with open(input_csv, "rb") as f:
        data = f.read()
    
    key = generate_key(password)
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(data)
    
    with open(output_file, "wb") as f:
        f.write(encrypted_data)
    
    print(f"Encrypted CSV saved to: {output_file}")

# --- Usage ---
if __name__ == "__main__":
    input_csv = "Regression_challenge/predicition_true_values.csv"
    output_file = "Regression_challenge/encrypted_data.csv"

    # Access password from Streamlit secrets
    password = st.secrets["pwd"]

    encrypt_csv(input_csv, output_file, password)
