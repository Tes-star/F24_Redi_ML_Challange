import streamlit as st
import pandas as pd

# Sample correct labels for Titanic dataset (id, label)
# Replace this with the actual correct labels (0 or 1 for survived/did not survive)
correct_labels = {
    1: 0, 2: 1, 3: 1, 4: 0, 5: 1, 6: 0, 7: 0, 8: 1, 9: 0, 10: 1, # etc.
    # Add the full set of correct Titanic labels here
}

# Convert correct_labels to a DataFrame for comparison
correct_df = pd.DataFrame(list(correct_labels.items()), columns=['id', 'label'])

# Streamlit app
st.title("Machine Learning Predictions Evaluation")

# Instructions
st.write("""
Upload a CSV file with two columns: `id` and `label`. The `id` column should correspond to unique identifiers, 
and the `label` column should contain the predicted labels.
""")

# File uploader
uploaded_file = st.file_uploader("Upload your CSV file", type=["csv"])

if uploaded_file is not None:
    # Read uploaded CSV file
    try:
        df = pd.read_csv(uploaded_file)
        st.write("Uploaded CSV file:")
        st.write(df)
        
        # Validate the structure of the uploaded file
        if "id" in df.columns and "label" in df.columns:
            if df['id'].dtype == 'int64' and df['label'].dtype == 'int64':
                st.success("CSV format is correct!")
                
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
        st.error(f"Error reading the file: {e}")
else:
    st.info("Awaiting file upload...")
