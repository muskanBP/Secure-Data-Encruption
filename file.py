import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Generate encryption key and cipher
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# In-memory data storage
stored_data = {}  # {"id": {"encrypted": ..., "hashed_pass": ...}}

# Initialize session state
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0

MAX_ATTEMPTS = 3

# Helper Functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    for item in stored_data.values():
        if item["encrypted"] == encrypted_text and item["hashed_pass"] == hash_passkey(passkey):
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# UI
st.title("🔐 Secure Data Locker")

menu = st.sidebar.radio("Select Page", ["Home", "Store", "Retrieve", "Login"])

# Home
if menu == "Home":
    st.subheader("Welcome!")
    st.markdown("""
    - 🔒 Store your private data securely
    - 🔑 Retrieve it using your secret passkey
    """)

# Store Data
elif menu == "Store":
    st.subheader("Store Data")
    data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Create passkey", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            data_id = f"id_{len(stored_data)+1}"
            encrypted = encrypt_data(data, passkey)
            stored_data[data_id] = {
                "encrypted": encrypted,
                "hashed_pass": hash_passkey(passkey)
            }
            st.success("Data encrypted and stored!")
            st.code(encrypted)
            st.warning("Copy the encrypted text. You need it to retrieve your data.")
        else:
            st.error("Please enter both data and a passkey.")

# Retrieve Data
elif menu == "Retrieve":
    st.subheader("Retrieve Data")

    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.error("❌ Too many failed attempts. Please login to continue.")
        st.stop()

    encrypted_input = st.text_area("Paste your encrypted data:")
    pass_input = st.text_input("Enter your passkey", type="password")

    if st.button("Decrypt"):
        if encrypted_input and pass_input:
            result = decrypt_data(encrypted_input, pass_input)
            if result:
                st.success("Decryption successful!")
                st.text_area("Your decrypted data:", result, height=150)
            else:
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"Incorrect passkey. {remaining} attempts left.")
        else:
            st.error("Please provide encrypted text and passkey.")

# Admin Login to reset attempts
elif menu == "Login":
    st.subheader("Admin Login")

    if st.session_state.failed_attempts < MAX_ATTEMPTS:
        st.info("Login not required yet.")
        if st.button("Go Back"):
            st.experimental_rerun()
    else:
        admin_pass = st.text_input("Admin password:", type="password")
        if st.button("Reset Attempts"):
            if admin_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.success("Attempts reset successfully.")
                st.experimental_rerun()
            else:
                st.error("Wrong admin password.")
