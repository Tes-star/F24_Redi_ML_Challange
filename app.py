import streamlit as st
import pandas as pd
import io

# Sample correct labels for Titanic dataset (id, label)
correct_labels = {
    1: 0, 2: 1, 3: 1, 4: 0, 5: 1, 6: 0, 7: 0, 8: 1, 9: 0, 10: 1, # etc.
    # Add the full set of correct Titanic labels here
}

# Convert correct_labels to a DataFrame for comparison
correct_df = pd.DataFrame(list(correct_labels.items()), columns=['id', 'label'])

# Function to detect delimiter in uploaded file
def detect_delimiter(uploaded_file):
    sample = uploaded_file.read(1024).decode()
    uploaded_file.seek(0)  # Reset pointer after reading the sample
    delimiters = [',', ';', '\t', '|']
    
    # Test which delimiter works best
    for delimiter in delimiters:
        try:
            df = pd.read_csv(io.StringIO(sample), delimiter=delimiter, nrows=5)
            if df.shape[1] > 1:
                return delimiter
        except Exception as e:
            continue
    return None

# Streamlit app
st.title("Machine Learning Predictions Evaluation")

# Instructions
st.write("""
Upload a CSV file with two columns: `id` and `label`. The `id` column should correspond to unique identifiers, 
and the `label` column should contain the predicted labels.
The file must contain all the required ids, and there cannot be any missing ids.
""")

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded_file is not None:
    # Detect delimiter
    delimiter = detect_delimiter(uploaded_file)
    
    if delimiter:
        st.write(f"Detected delimiter: `{delimiter}`")
        try:
            # Read uploaded CSV file with detected delimiter
            df = pd.read_csv(uploaded_file, delimiter=delimiter)
            st.write("Uploaded CSV file preview:")
            st.write(df)

            # Validate the structure of the uploaded file
            if "id" in df.columns and "label" in df.columns:
                if df['id'].dtype == 'int64' and df['label'].dtype == 'int64':
                    st.success("CSV format is correct!")
                    
                    # Check if all IDs are present
                    missing_ids = set(correct_df['id']) - set(df['id'])
                    extra_ids = set(df['id']) - set(correct_df['id'])

                    if missing_ids:
                        st.error(f"Missing ids: {missing_ids}")
                    elif extra_ids:
                        st.error(f"Unexpected extra ids found: {extra_ids}")
                    else:
                        # Merge predictions with correct labels
                        merged_df = pd.merge(df, correct_df, on="id", suffixes=('_pred', '_true'))
                        
                        # Calculate accuracy
                        accuracy = (merged_df['label_pred'] == merged_df['label_true']).mean()
                        
                        st.write(f"Accuracy of predictions: **{accuracy * 100:.2f}%**")
                        st.write("Comparison of predictions and correct labels:")
                        st.write(merged_df)
                else:
                    st.error("Both 'id' and 'label' columns must be integers.")
            else:
                st.error("The uploaded file must contain 'id' and 'label' columns.")
        except Exception as e:
            st.error(f"Error processing the file: {e}")
    else:
        st.error("Could not detect a valid delimiter. Please ensure the file is correctly formatted.")
else:
    st.info("Awaiting file upload...")
