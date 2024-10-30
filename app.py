from sklearn.metrics import f1_score
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import io
from datetime import datetime

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

# Leaderboard data
leaderboard_file = "leaderboard.csv"

# Display title and instructions
st.title("Prediction Evaluation for BAKKI Project")
st.write("""
Upload a CSV with two columns: `ID` and `Label`. 
Ensure the file includes all required IDs, without any missing IDs.
""")
st.write("A sample file named `example_prediction.csv` is provided for guidance.")

# Input for user name
user_name = st.text_input("Enter your name (optional):")

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

# Process uploaded file
if uploaded_file is not None:
    delimiter = detect_delimiter(uploaded_file)
    if delimiter:
        st.write(f"Detected delimiter: `{delimiter}`")
        try:
            df = pd.read_csv(uploaded_file, delimiter=delimiter)
            st.write("Preview of uploaded file:", df.head())
            
            if set(['ID', 'Label']).issubset(df.columns):
                if df['ID'].dtype == 'int64' and df['Label'].dtype == 'int64':
                    
                    # Check IDs are the same and in the same order
                    if list(df['ID']) != list(correct_labels['ID']):
                        st.error("Mismatch in `ID` column. Ensure IDs match exactly and are in the same order.")
                        st.write("Expected format (sample):", correct_labels.head())
                        st.write("Your format (sample):", df.head())
                    else:
                        st.success("CSV format is correct!")
                                                
                        # Merge prediction DataFrame with correct labels
                        merged_df = pd.merge(df, correct_labels, on="ID", suffixes=('_pred', '_true'))

                        # Display the columns in the merged DataFrame for debugging
                        st.write("Merged columns:", merged_df.columns.tolist())

                        # Calculate F1 score with the appropriate label column
                        score = f1_score(merged_df['Label_pred'], merged_df['Label'], average='weighted')

                        # Display the score
                        st.write(f"Prediction accuracy: **{score:.3f}%**")
                        st.write("Comparison of predictions and correct labels:", merged_df)

                        # Save the score with timestamp
                        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        score_entry = {
                            "Name": user_name if user_name else "Anonymous",
                            "Score": score,
                            "Timestamp": timestamp
                        }
                        
                        # Append score to leaderboard
                        try:
                            leaderboard_df = pd.read_csv(leaderboard_file)
                            leaderboard_df = leaderboard_df.append(score_entry, ignore_index=True)
                        except FileNotFoundError:
                            leaderboard_df = pd.DataFrame([score_entry])
                        
                        leaderboard_df.to_csv(leaderboard_file, index=False)
                        
                        # Check if the score is the best
                        best_score = leaderboard_df["Score"].max()
                        if score == best_score:
                            st.balloons()
                            st.write("🎉 Congratulations! You have the highest score ever! 🎉")

                        # Display leaderboard
                        st.write("### Leaderboard")
                        top_scores = leaderboard_df.sort_values(by="Score", ascending=False).head(10)
                        st.write(top_scores)
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
