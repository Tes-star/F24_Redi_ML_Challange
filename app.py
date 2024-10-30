from sklearn.metrics import f1_score
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import io
from datetime import datetime
import matplotlib.pyplot as plt  # Importing matplotlib for plotting

# Generate a 32-byte key for Fernet encryption from the password
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Decrypt the CSV file with the correct labels
def decrypt_csv(input_file: str, password: str) -> pd.DataFrame:
    key = generate_key(password)
    fernet = Fernet(key)
    with open(input_file, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    return pd.read_csv(io.BytesIO(decrypted_data), delimiter=";")

# Load correct labels
pwd = st.secrets['pwd']
correct_labels = decrypt_csv("encrypted_data.csv", pwd)

# Detect delimiter in uploaded file
def detect_delimiter(uploaded_file) -> str:
    sample = uploaded_file.read(1024).decode()
    uploaded_file.seek(0)
    for delimiter in [',', ';', '\t', '|']:
        try:
            if pd.read_csv(io.StringIO(sample), delimiter=delimiter, nrows=5).shape[1] > 1:
                return delimiter
        except:
            continue
    return None

# Leaderboard file
leaderboard_file = "leaderboard.csv"

# Display title and instructions
st.title("Prediction Evaluation for BAKKI Project")
st.write("""
Upload a CSV with two columns: ID and Label. 
Ensure the file includes all required IDs, without any missing IDs.
""")
st.write("A sample file named example_prediction.csv is provided for guidance.")

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

# Leaderboard display
def display_leaderboard():
    try:
        leaderboard_df = pd.read_csv(leaderboard_file)
        leaderboard_df.sort_values(by="Score", ascending=False, inplace=True)
        st.write("### Leaderboard")
        st.write(
            leaderboard_df.style.highlight_max(subset=['Score'], color='yellow')  # Highlight max v
