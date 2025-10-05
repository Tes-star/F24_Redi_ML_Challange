from sklearn.metrics import mean_squared_error
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

# Define the constant for the prediction column name as requested by the user
PRED_COL = 'Quantity_Sold_(kilo)'

# Generate a 32-byte key for Fernet encryption from the password
def generate_key(password: str) -> bytes:
    """Generates a Fernet encryption key from a password using SHA256 hashing."""
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

# Decrypt the CSV file with the correct labels
def decrypt_csv(input_file: str, password: str) -> pd.DataFrame:
    """Decrypts a Fernet-encrypted file and loads it into a pandas DataFrame."""
    key = generate_key(password)
    fernet = Fernet(key)
    with open(input_file, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    # The ground truth file is assumed to use a comma delimiter (,)
    return pd.read_csv(io.BytesIO(decrypted_data), delimiter=",")

# Set up Google Sheets API
scope = ["https://spreadsheets.google.com/feeds", "https://www.googleapis.com/auth/spreadsheets",
         "https://www.googleapis.com/auth/drive.file", "https://www.googleapis.com/auth/drive"]

# Load secrets from Streamlit environment
try:
    # Use st.secrets as a dictionary-like object directly for cleaner access
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
    # Write to a temporary file for gspread
    with open('cred.json', 'w') as f:
        json.dump(cred, f)
    
    creds = ServiceAccountCredentials.from_json_keyfile_name('cred.json', scope)
    client = gspread.authorize(creds)
    sheet = client.open("leaderboard").worksheet("F25_Regression_challenge")  # Open sheet
except Exception as e:
    st.error(f"Failed to initialize Google Sheets connection. Check your `st.secrets` configuration. Error: {e}")
    sheet = None

# Load correct labels (ground truth)
try:
    pwd = st.secrets['pwd']
    correct_labels = decrypt_csv("Regression_challenge/encrypted_data.csv", pwd)
    # Ensure the ground truth column is present
    if PRED_COL not in correct_labels.columns:
        raise KeyError(f"The decrypted ground truth data must contain the '{PRED_COL}' column.")
except Exception as e:
    st.error(f"Failed to load or decrypt correct labels. Please check the encrypted file and password in st.secrets. Error: {e}")
    # Create an empty DataFrame with the required columns for safer operation later
    correct_labels = pd.DataFrame({'ID': [], PRED_COL: []})

# Detect delimiter in uploaded file
def detect_delimiter(uploaded_file) -> str:
    """Reads a sample from the file to automatically determine the delimiter."""
    sample = uploaded_file.read(1024).decode()
    uploaded_file.seek(0)
    for delimiter in [',', ';', '\t', '|']:
        try:
            # Try to read the file with the current delimiter, check if it results in more than one column
            if pd.read_csv(io.StringIO(sample), delimiter=delimiter, nrows=5).shape[1] > 1:
                return delimiter
        except Exception:
            continue
    return None

# Display title and instructions
st.title("Regression challenge: Score Evaluation")
st.write(f"""Upload your prediction CSV with two columns: **ID** and **{PRED_COL}**. 
Ensure the file includes all required IDs, without any missing IDs. 
The leaderboard ranks submissions by **lowest Mean Squared Error (MSE)**.""") # UPDATED INSTRUCTION
st.write("A sample file named example_prediction.csv was provided for guidance.")
st.write("---") # Separator
st.write("### Leaderboard")

# Display leaderboard placeholder
leaderboard_placeholder = st.empty()

# Function to display leaderboard from Google Sheets
def display_leaderboard():
    """Fetches and displays the current leaderboard data from Google Sheets."""
    if sheet is None:
        leaderboard_placeholder.write("Leaderboard unavailable due to connection error.")
        return pd.DataFrame()
        
    try:
        # Get all records, preventing gspread from trying to convert the 'Score' column which is a string (e.g., '123,45')
        leaderboard_data = sheet.get_all_records(numericise_ignore=["all"])
        
        if leaderboard_data:
            leaderboard_df = pd.DataFrame(leaderboard_data)
            
            # Clean and convert Score column to float
            leaderboard_df['Score'] = leaderboard_df['Score'].astype(str).str.replace(',', '.').astype(float)
            leaderboard_df.sort_values(by="Score", ascending=True, inplace=True)  # Lower is better
            
            # Display the formatted DataFrame
            leaderboard_placeholder.dataframe(
                leaderboard_df.style.background_gradient(cmap="Greens_r")#.highlight_min(subset=['Score'], color='lightgreen')
            )
            return leaderboard_df
        else:
            leaderboard_placeholder.write("No entries yet.")
            return pd.DataFrame()
    except Exception as e:
        leaderboard_placeholder.error("Error fetching or processing leaderboard data.")
        st.error(str(e))
        return pd.DataFrame()

# Display initial leaderboard
display_leaderboard()

# File uploader
st.write("---") # Separator
uploaded_file = st.file_uploader("Upload your CSV prediction file", type=["csv"])

# Process uploaded file
if uploaded_file is not None:
    delimiter = detect_delimiter(uploaded_file)
    
    if correct_labels.empty:
        st.error("Cannot proceed: Ground truth labels failed to load or decrypt.")
        st.stop()
        
    required_ids_set = set(correct_labels['ID'].unique())
    
    if delimiter:
        try:
            df = pd.read_csv(uploaded_file, delimiter=delimiter)
            
            # --- VALIDATION BLOCK START ---
            
            # 1. Column Check
            required_cols = ['ID', PRED_COL]
            uploaded_cols_set = set(df.columns)
            missing_cols = list(set(required_cols) - uploaded_cols_set)
            extra_cols = list(uploaded_cols_set - set(required_cols + list(correct_labels.columns))) # Exclude potential PRED_COL if somehow included
            
            if missing_cols:
                error_msg = f"❌ **Missing Required Columns:** Your file is missing column(s): **{', '.join(missing_cols)}**."
                if extra_cols:
                    error_msg += f" (It also contains extra, unneeded column(s): **{', '.join(extra_cols)}**.)"
                st.error(error_msg)
                st.stop()
            
            if extra_cols:
                 st.warning(f"⚠️ **Found Unneeded Columns:** Your file contains extra columns that will be ignored: **{', '.join(extra_cols)}**.")

            # 2. ID Data Type Check
            if df['ID'].dtype not in ['int64', 'float64']:
                st.error("❌ **ID Data Type Error:** The 'ID' column must be numeric (integer or float).")
                st.stop()

            # Convert IDs to integers for consistent comparison with ground truth
            df['ID'] = df['ID'].round().astype('int64')

            # 3. ID Uniqueness Check
            duplicate_ids = df[df.duplicated(subset=['ID'], keep=False)]['ID'].unique()
            if len(duplicate_ids) > 0:
                hint = f"Found **{len(duplicate_ids)}** IDs appearing more than once. Please ensure each ID is unique."
                hint += f"\n\n**Duplicates Found:** {', '.join(map(str, duplicate_ids[:10]))}"
                if len(duplicate_ids) > 10:
                    hint += f" and **{len(duplicate_ids) - 10}** more."
                st.error(f"❌ **Duplicate IDs Found**\n\n{hint}")
                st.stop()

            # 4. ID Set Matching Check
            uploaded_ids_set = set(df['ID'])
            
            missing_ids = list(required_ids_set - uploaded_ids_set)
            extra_ids = list(uploaded_ids_set - required_ids_set)
            
            errors_found = False
            
            if missing_ids:
                errors_found = True
                hint = f"Your file is missing predictions for **{len(missing_ids)}** required IDs."
                hint += f"\n\n**First 10 Missing IDs:** {', '.join(map(str, missing_ids[:10]))}"
                if len(missing_ids) > 10:
                    hint += f" and **{len(missing_ids) - 10}** more."
                st.error(f"❌ **Missing IDs Error**\n\n{hint}")

            if extra_ids:
                errors_found = True
                hint = f"Your file contains predictions for **{len(extra_ids)}** IDs that are not needed."
                hint += f"\n\n**First 10 Unneeded IDs:** {', '.join(map(str, extra_ids[:10]))}"
                if len(extra_ids) > 10:
                    hint += f" and **{len(extra_ids) - 10}** more."
                st.error(f"❌ **Unneeded IDs Error**\n\n{hint}")
                
            if errors_found:
                st.stop()
            
            # --- VALIDATION BLOCK END ---
            
            st.success("✅ **Validation Successful!** The file format, required columns, and ID set match the test data.")
            st.divider()

            # The proper way to ensure alignment is a merge, which handles order mismatch.
            # Use an 'inner' merge since we've already confirmed the ID sets are identical.
            merged_df = pd.merge(df, correct_labels, on="ID", suffixes=("_pred", "_true"), how='inner')
            
            # The column names after merge will be 'Quantity_Sold_(kilo)_pred' and 'Quantity_Sold_(kilo)_true'
            pred_col_merged = PRED_COL + "_pred"
            PRED_COL_merged = PRED_COL + "_true"

            # Calculate MSE
            mse = mean_squared_error(merged_df[PRED_COL_merged], merged_df[pred_col_merged])
            st.metric(label="Prediction Mean Squared Error (MSE)", value=f"{mse:.4f}")
            
            st.divider()
            
            # Submission section
            user_name = st.text_input("Enter your name for the leaderboard:", "")

            # Add to leaderboard button
            if st.button("Add to Leaderboard"):
                if user_name and sheet is not None:
                    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    
                    # gspread stores floats as strings. Use dot for consistency.
                    score_str = f"{mse:.4f}".replace('.', ',') 
                    score_entry = [user_name, score_str, timestamp]

                    # Append new score to Google Sheets
                    sheet.append_row(score_entry)
                    st.balloons()
                    st.success("Your score has been added to the leaderboard!")

                    # Update the leaderboard display
                    display_leaderboard()
                elif sheet is None:
                    st.error("Cannot submit: Leaderboard connection failed.")
                else:
                    st.warning("Please enter your name to submit to the leaderboard.")
            else:
                st.info("Press the button to add your score to the leaderboard.")

        except Exception as e:
            st.error(f"❌ **File Processing Error:** An unexpected error occurred while processing the file: {e}")
    else:
        st.error("❌ **Delimiter Error:** Could not detect a valid delimiter. Please ensure the file is correctly formatted (comma, semicolon, tab, or pipe separated).")
else:
    st.info("Awaiting file upload...")