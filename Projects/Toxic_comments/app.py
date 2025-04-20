from sklearn.metrics import f1_score
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import io
import numpy as np
from datetime import datetime
import gspread
from oauth2client.service_account import ServiceAccountCredentials
import json

# Generate a 32-byte key for Fernet encryption from the password
def generate_key(password: str) -> bytes:
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Decrypt the CSV file with the correct labels
def decrypt_csv(input_file: str, password: str) -> pd.DataFrame:
    key = generate_key(password)
    fernet = Fernet(key)
    with open(input_file, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    return pd.read_csv(io.BytesIO(decrypted_data))

# Set up Google Sheets API
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/spreadsheets",
         "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive"]

cred={
  "type": st.secrets['type'],
  "project_id":  st.secrets['project_id'],
  "private_key_id":  st.secrets['private_key_id'],
  "private_key":  st.secrets['private_key'],
  "client_email":  st.secrets['client_email'],
  "client_id": st.secrets['client_id'],
  "auth_uri":  st.secrets['auth_uri'],
  "token_uri":  st.secrets['token_uri'],
  "auth_provider_x509_cert_url":  st.secrets['auth_provider_x509_cert_url'],
  "client_x509_cert_url":  st.secrets['client_x509_cert_url'],
  "universe_domain":  st.secrets['universe_domain'],
}
with open('cred.json', 'w') as f:
    json.dump(cred, f)

creds = ServiceAccountCredentials.from_json_keyfile_name('cred.json', scope)
client = gspread.authorize(creds)
sheet = client.open("leaderboard").get_worksheet(2)  # Open first sheet of the leaderboard spreadsheet

# Load correct labels
pwd = st.secrets['pwd']
correct_labels = decrypt_csv("Projects/Toxic_comments/test_labels_pwd.csv", pwd)

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

# Display title and instructions
st.title("Score Evaluation: Project Toxic language 🧪💬")
st.write("""Upload your predition CSV with the columns: ID, toxic,severe_toxic,obscene,threat,insult,identity_hate. Ensure the file includes all required IDs, without any missing IDs.""")
st.write("A sample file named sample_submission.csv was provided for guidance.")
st.write("### Leaderboard")

# Display leaderboard placeholder
leaderboard_placeholder = st.empty()

# Function to display leaderboard from Google Sheets
def display_leaderboard():
    leaderboard_placeholder.write("### Leaderboard")  # Set the header before attempting to read data
    try:
        leaderboard_data = sheet.get_all_records(numericise_ignore=["all"])  # Retrieve data as list of dictionaries
        if leaderboard_data:  # Check if there's data to display
            leaderboard_df = pd.DataFrame(leaderboard_data)
            leaderboard_df['Score'] = leaderboard_df['Score'].str.replace(',', '.').astype(float)
            leaderboard_df.sort_values(by="Score", ascending=False, inplace=True)
            leaderboard_placeholder.write(
                leaderboard_df.style.background_gradient(cmap="Greens").highlight_max(subset=['Score'], color='green')
            )
        else:
            leaderboard_placeholder.write("No entries yet.")
        return leaderboard_df
    except Exception as e:
        leaderboard_placeholder.write("Error fetching leaderboard data.")
        st.error(str(e))
        return pd.DataFrame()

# Display initial leaderboard
display_leaderboard()

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

# Process uploaded file
if uploaded_file is not None:
    delimiter = detect_delimiter(uploaded_file)
    if delimiter:
        df = pd.read_csv(uploaded_file, delimiter=delimiter)
        
        # Check for necessary columns
        if set(['id'] + list(correct_labels.columns[1:])).issubset(df.columns):
            if df['id'].dtype == correct_labels['id'].dtype:
                
                # Check IDs are the same and in the same order
                if list(df['id']) != list(correct_labels['id']):
                    st.error("Mismatch in ID column. Ensure IDs match exactly and are in the same order.")
                else:
                    st.success("CSV format is correct!")
                    st.divider()

                    # Remove rows with only -1 in correct labels
                    valid_rows = ~(correct_labels.iloc[:, 1:] == -1).all(axis=1)
                    correct_labels = correct_labels[valid_rows]
                    df = df[valid_rows]

                    # Merge prediction DataFrame with correct labels
                    merged_df = pd.merge(df, correct_labels, on="id", suffixes=('_pred', '_true'))

                    # Calculate F1 scores for each label
                    label_columns = correct_labels.columns[1:]  # All label columns except 'id'
                    f1_scores = {}
                    for label in label_columns:
                        f1_scores[label] = f1_score(
                            merged_df[f"{label}_pred"],
                            merged_df[f"{label}_true"],
                            average='macro'
                        )

                    # Compute the average F1 score across all labels
                    avg_f1_score = sum(f1_scores.values()) / len(f1_scores)

                    st.write(f"Average F1 Score across all labels: **{avg_f1_score * 100:.2f}%**")

                    user_name = st.text_input("Enter your name for the leaderboard:", "")

                    # Add to leaderboard button
                    if st.button("Add to Leaderboard"):
                        if user_name:
                            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            score_entry = [user_name, avg_f1_score, timestamp]

                            # Retrieve leaderboard data
                            leaderboard_data = sheet.get_all_records(numericise_ignore=["all"])
                            leaderboard_df = pd.DataFrame(leaderboard_data)
                            leaderboard_df['Score'] = leaderboard_df['Score'].str.replace(',', '.').astype(float)

                            # Append new score to Google Sheets
                            sheet.append_row(score_entry)
                            st.balloons()

                            st.success("Your score has been added to the leaderboard!")

                            # Update the leaderboard display
                            display_leaderboard()

                        else:
                            st.info("Press the button to add your score to the leaderboard.")

                
            else:
                st.error("The file must contain 'id' and 'is_canceled' columns.")
        
    else:
        st.error("Could not detect a valid delimiter. Please ensure the file is correctly formatted.")
else:
    st.info("Awaiting file upload...")
