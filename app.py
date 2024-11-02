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
    return pd.read_csv(io.BytesIO(decrypted_data), delimiter=";")

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
sheet = client.open("leaderboard").sheet1  # Open first sheet of the leaderboard spreadsheet

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

# Display title and instructions
st.title("Prediction Evaluation for BAKKI Project")
st.write("""Upload a CSV with two columns: ID and Label. Ensure the file includes all required IDs, without any missing IDs.""")
st.write("A sample file named example_prediction.csv is provided for guidance.")

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

# Display leaderboard from Google Sheets
def display_leaderboard():
    try:
        leaderboard_data = sheet.get_all_records(numericise_ignore=["all"])  # Retrieve data as list of dictionaries
        leaderboard_df = pd.DataFrame(leaderboard_data)
        leaderboard_df['Score'].str.replace(',', '.').astype(float)
        leaderboard_df.sort_values(by="Score", ascending=False, inplace=True)
        st.write("### Leaderboard")
        st.write(
            leaderboard_df.style.highlight_max(subset=['Score'], color='yellow')
            .background_gradient(cmap="Greens")
        )
        return leaderboard_df
    except Exception as e:
        st.write("### Leaderboard")
        st.write("No entries yet.")
        return pd.DataFrame()

# Process uploaded file
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
                                score_entry = [user_name, score, timestamp]

                                # Check if user already exists and update score if necessary
                                leaderboard_data = sheet.get_all_records(numericise_ignore=["all"])
                                
                                leaderboard_df = pd.DataFrame(leaderboard_data)
                                leaderboard_df['Score'].str.replace(',', '.').astype(float)
                                if user_name in leaderboard_df['Name'].values:
                                    current_best_score = leaderboard_df.loc[leaderboard_df['Name'] == user_name, 'Score'].max()
                                    if score > current_best_score:
                                        # Find and update the row with the new high score
                                        cell = sheet.find(user_name)
                                        sheet.update_cell(cell.row, 2, score)
                                        sheet.update_cell(cell.row, 3, timestamp)
                                        st.balloons()
                                else:
                                    # Append new score to Google Sheets
                                    sheet.append_row(score_entry)
                                    st.balloons()

                                st.success("Your score has been added to the leaderboard!")
                            else:
                                st.warning("Please enter your name to subscribe to the leaderboard.")
                        else:
                            st.info("Press the button to add your score to the leaderboard.")

                        # Display the graph
                        leaderboard_df = display_leaderboard()
                        
                        
                else:
                    st.error("Both 'ID' and 'Label' columns must be integers.")
            else:
                st.error("The file must contain 'ID' and 'Label' columns.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")
    else:
        st.error("Could not detect a valid delimiter. Please ensure the file is correctly formatted.")
else:
    st.info("Awaiting file upload...")
