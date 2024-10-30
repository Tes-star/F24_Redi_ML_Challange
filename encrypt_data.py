from cryptography.fernet import Fernet
import pandas as pd
import base64
import hashlib
import io

def generate_key(password: str) -> bytes:
    # Hash the password to create a 32-byte key for Fernet
    return base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest())

def encrypt_csv(input_file: str, output_file: str, password: str):
    # Generate a key from the password
    key = generate_key(password)
    fernet = Fernet(key)

    # Read the CSV file as bytes
    with open(input_file, "rb") as file:
        file_data = file.read()

    # Encrypt the file data
    encrypted_data = fernet.encrypt(file_data)

    # Save the encrypted data to the output file
    with open(output_file, "wb") as file:
        file.write(encrypted_data)

# Decrypt the CSV file with the correct labels
def decrypt_csv(input_file: str, password: str) -> pd.DataFrame:
    key = generate_key(password)
    fernet = Fernet(key)
    with open(input_file, "rb") as file:
        decrypted_data = fernet.decrypt(file.read())
    return pd.read_csv(io.BytesIO(decrypted_data),delimiter=";")



pwd = "KADCoxXLO7YRz18"

encrypt_csv("prediction_correct.csv", "encrypted_data.csv", pwd)
df = decrypt_csv("encrypted_data.csv", pwd)
print(df)
print(df)