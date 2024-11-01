from sklearn.metrics import f1_score
import streamlit as st
import pandas as pd
from cryptography.fernet import Fernet
import base64
import hashlib
import io
import numpy as np
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns  # Importing seaborn for enhanced visualizations

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
st.write("""Upload a CSV with two columns: ID and Label. Ensure the file includes all required IDs, without any missing IDs.""")
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
            leaderboard_df.style.highlight_max(subset=['Score'], color='yellow')  # Highlight max values in 'Score' column
            .background_gradient(cmap="Greens")  # Use 'Greens' color map for background gradient
        )
        return leaderboard_df  # Return the leaderboard DataFrame for further processing
    except FileNotFoundError:
        st.write("### Leaderboard")
        st.write("No entries yet.")
        return pd.DataFrame()  # Return an empty DataFrame if no file found

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
                            if user_name:  # Check if user_name is provided
                                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                score_entry = {
                                    "Name": user_name,
                                    "Score": score,
                                    "Timestamp": timestamp
                                }
                                
                                # Append score to leaderboard if it's a new high score
                                try:
                                    leaderboard_df = pd.read_csv(leaderboard_file)
                                    # Check if user already exists in the leaderboard
                                    if user_name in leaderboard_df['Name'].values:
                                        # Get current best score for this user
                                        current_best_score = leaderboard_df.loc[leaderboard_df['Name'] == user_name, 'Score'].max()
                                        # Update the score entry if the new score is better
                                        if score > current_best_score:
                                            leaderboard_df.loc[leaderboard_df['Name'] == user_name, 'Score'] = score
                                            leaderboard_df.loc[leaderboard_df['Name'] == user_name, 'Timestamp'] = timestamp
                                    else:
                                        leaderboard_df = pd.concat([leaderboard_df, pd.DataFrame([score_entry])], ignore_index=True)
                                except FileNotFoundError:
                                    leaderboard_df = pd.DataFrame([score_entry])

                                # Save the updated leaderboard
                                leaderboard_df.to_csv(leaderboard_file, index=False)

                                st.success("Your score has been added to the leaderboard!")
                                
                            else:
                                st.warning("Please enter your name to subscribe to the leaderboard.")
                        else:
                            st.info("Press the button to add your score to the leaderboard.")

                        # Display the graph
                        leaderboard_df = display_leaderboard()  # Get the updated leaderboard
                        
                        if not leaderboard_df.empty:
                            # Convert 'Timestamp' to datetime and round to the nearest hour
                            leaderboard_df['Timestamp'] = pd.to_datetime(leaderboard_df['Timestamp']).dt.floor('H')

                            # Group by Name and Timestamp to get the latest score for each hour
                            best_scores = leaderboard_df.groupby(['Name', 'Timestamp']).agg(
                                Best_Score=('Score', 'max')
                            ).reset_index()

                            # Filter out anonymized names if needed
                            best_scores = best_scores[best_scores['Name'] != 'anonym']  # Adjust as needed

                            # Calculate personal best for each user
                            best_scores['Personal_Best'] = best_scores.groupby('Name')['Best_Score'].cummax()

                            # Add last score for each user
                            best_scores['Last_Score'] = best_scores.groupby('Name')['Best_Score'].transform(lambda x: x.ffill().bfill())  # Last score for each user

                            # Plotting
                            plt.figure(figsize=(16, 10))  # Increased size and DPI
                            sns.set(style="whitegrid")  # Set background style
                            palette = sns.color_palette("husl", len(best_scores['Name'].unique()))  # Unique palette

                            # Plotting the personal best scores
                            sns.lineplot(data=best_scores, x='Timestamp', y='Personal_Best', hue='Name', palette=palette, linewidth=2)

                            # Adding last observation points (continuing the line)
                            last_scores = best_scores[best_scores['Timestamp'] == best_scores.groupby('Name')['Timestamp'].transform('max')]
                            sns.lineplot(data=last_scores, x='Timestamp', y='Last_Score', hue='Name', palette=palette, linewidth=2, linestyle='--')

                            # Draw the baseline at y=0.65
                            plt.axhline(y=0.65, color='black', linestyle='--', linewidth=0.5, label='Baseline')

                            plt.title('Personal Best Scores Over Time', fontsize=20, fontweight='bold')
                            plt.xlabel('Timestamp (Rounded to Hour)', fontsize=16)
                            plt.ylabel('Personal Best Score', fontsize=16)

                            # Set x-ticks for every hour
                            plt.xticks(rotation=45)
                            plt.yticks(fontsize=14)

                            # Set y limits
                            plt.ylim(0, 1.04)

                            # Add y-gridlines every 0.05
                            plt.yticks(np.arange(0.0, 1.04, 0.05))
                            plt.grid(visible=True, linestyle='--', linewidth=0.5)  # Style for grid
                            plt.legend(title='Names', fontsize=14, title_fontsize='15', loc='upper left', bbox_to_anchor=(1, 1))
                            plt.tight_layout()
                            # Render the plot in Streamlit
                            st.pyplot(plt, clear_figure=True)  # Clear figure after rendering to prevent overlapping on reruns

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
