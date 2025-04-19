import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# Initialize only once
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()
    st.session_state.cipher = Fernet(st.session_state.encryption_key)

if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

MAX_ATTEMPTS = 3

# Helper functions
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return st.session_state.cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed = hash_passkey(passkey)
    for item in st.session_state.stored_data.values():
        if item["encrypted"] == encrypted_text and item["hashed_pass"] == hashed:
            st.session_state.failed_attempts = 0
            return st.session_state.cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# UI
st.title("🔐 Secure Data Locker")

menu = st.sidebar.radio("Select Page", ["Home", "Store", "Retrieve", "Login"])

# Home Page
if menu == "Home":
    st.subheader("Welcome!")
    st.markdown("""
    - 🔒 Store your private data securely
    - 🔑 Retrieve it using your secret passkey
    """)

# Store Page
elif menu == "Store":
    st.subheader("Store Data")
    data = st.text_area("Enter data to encrypt:")
    passkey = st.text_input("Create passkey:", type="password")

    if st.button("Encrypt & Store"):
        if data and passkey:
            data_id = f"id_{len(st.session_state.stored_data) + 1}"
            encrypted = encrypt_data(data, passkey)
            st.session_state.stored_data[data_id] = {
                "encrypted": encrypted,
                "hashed_pass": hash_passkey(passkey)
            }
            st.success("✅ Data encrypted and stored!")
            st.code(encrypted)
            st.warning("⚠️ Copy the encrypted text. You'll need it to retrieve your data.")
        else:
            st.error("❗ Please enter both data and a passkey.")

# Retrieve Page
elif menu == "Retrieve":
    st.subheader("Retrieve Data")

    if st.session_state.failed_attempts >= MAX_ATTEMPTS:
        st.error("❌ Too many failed attempts. Please login.")
        st.stop()

    encrypted_input = st.text_area("Paste your encrypted data:")
    pass_input = st.text_input("Enter your passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_input and pass_input:
            result = decrypt_data(encrypted_input, pass_input)
            if result:
                st.success("✅ Decryption successful!")
                st.text_area("Your decrypted data:", result, height=150)
            else:
                remaining = MAX_ATTEMPTS - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey. {remaining} attempts left.")
        else:
            st.error("Please enter both encrypted data and passkey.")

# Login Page
elif menu == "Login":
    st.subheader("Admin Login")

    if st.session_state.failed_attempts < MAX_ATTEMPTS:
        st.info("Login not needed yet.")
        if st.button("Go Back"):
            st.experimental_rerun()
    else:
        admin_pass = st.text_input("Enter admin password:", type="password")
        if st.button("Reset Attempts"):
            if admin_pass == "admin123":
                st.session_state.failed_attempts = 0
                st.success("✅ Attempts reset!")
                st.experimental_rerun()
            else:
                st.error("Wrong admin password.")
