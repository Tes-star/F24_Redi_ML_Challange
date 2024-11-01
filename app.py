from sklearn.metrics import f1_score
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import io
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
from streamlit_gsheets import GSheetsConnection

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

# Connect to Google Sheets
conn = st.connection("gsheets", type=GSheetsConnection)
leaderboard_df = conn.read(
    worksheet="data",
    ttl="10m",
    usecols=[0, 1, 2],
)

# Display leaderboard
def display_leaderboard():
    st.write("### Leaderboard")
    st.write(
        leaderboard_df.sort_values(by="Score", ascending=False)
        .style.highlight_max(subset=['Score'], color='yellow')
        .background_gradient(cmap="Greens")
    )

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded_file is not None:
    delimiter = detect_delimiter(uploaded_file)
    if delimiter:
        try:
            df = pd.read_csv(uploaded_file, delimiter=delimiter)
            
            if set(['ID', 'Label']).issubset(df.columns):
                if df['ID'].dtype == 'int64' and df['Label'].dtype == 'int64':
                    
                    # Check IDs are the same and in the same order
                    if list(df['ID']) != list(correct_labels['ID']):
                        st.error("Mismatch in ID column. Ensure IDs match exactly and are in the same order.")
                    else:
                        st.success("CSV format is correct!")
                        st.divider()

                        # Merge prediction DataFrame with correct labels
                        merged_df = pd.merge(df, correct_labels, on="ID", suffixes=('_pred', '_true'))

                        # Calculate F1 score
                        score = f1_score(merged_df['Label_pred'], merged_df['Label_true'], average='macro')
                        st.write(f"Prediction f1_score(average='macro') **{score * 100:.2f}%**")
                        
                        # Check if the score is better than 65%
                        if score < 0.65:
                            st.warning("You're close! A score of 65% is achievable without advanced strategies. Keep trying!")

                        # Ask for user's name
                        user_name = st.text_input("Enter your name for the leaderboard:", "")

                        # Add to leaderboard button
                        if st.button("Add to Leaderboard"):
                            if user_name:
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                new_entry = pd.DataFrame([[user_name, score, timestamp]], columns=["Name", "Score", "Timestamp"])
                                
                                # Append new score to Google Sheets leaderboard
                                leaderboard_df = pd.concat([leaderboard_df, new_entry], ignore_index=True)
                                conn.write(leaderboard_df)
                                
                                st.success("Your score has been added to the leaderboard!")
                            else:
                                st.warning("Please enter your name to subscribe to the leaderboard.")
                        display_leaderboard()
                        
        except Exception as e:
            st.error(f"Error processing the file: {e}")
    else:
        st.error("Could not detect a valid delimiter. Please ensure the file is correctly formatted.")
else:
    st.info("Awaiting file upload...")
