import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Generate/load a secure key (only for demo purposes)
KEY_FILE = "key.key"
DATA_FILE = "data.json"

if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as f:
        KEY = f.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(KEY)

cipher = Fernet(KEY)

# Load existing data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Initialize session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "authorized" not in st.session_state:
    st.session_state.authorized = False

# Hashing
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Encryption
def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

# Decryption
def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Save to JSON
def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)

# App UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome")
    st.write("Securely store and retrieve data using encryption and hashed passkeys.")

elif choice == "Store Data":
    st.subheader("📁 Store Data Securely")

    username = st.text_input("Enter a Username")
    data = st.text_area("Enter your Data")
    passkey = st.text_input("Create a Passkey", type="password")

    if st.button("Encrypt & Store"):
        if username and data and passkey:
            hashed_key = hash_passkey(passkey)
            encrypted = encrypt_data(data)
            stored_data[username] = {
                "encrypted": encrypted,
                "passkey": hashed_key
            }
            save_data()
            st.success("✅ Data stored securely!")
        else:
            st.error("⚠️ All fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Encrypted Data")

    username = st.text_input("Enter Username")
    passkey = st.text_input("Enter Passkey", type="password")

    if st.button("Decrypt"):
        if username in stored_data:
            hashed = hash_passkey(passkey)
            if hashed == stored_data[username]["passkey"]:
                decrypted = decrypt_data(stored_data[username]["encrypted"])
                st.success(f"✅ Your Decrypted Data: {decrypted}")
                st.session_state.failed_attempts = 0
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                if st.session_state.failed_attempts >= 3:
                    st.warning("🔒 Too many failed attempts! Redirecting to login...")
                    st.switch_page("Login")
        else:
            st.error("❌ Username not found!")

elif choice == "Login":
    st.subheader("🔑 Login to Continue")
    master_key = st.text_input("Enter Admin Password", type="password")

    if st.button("Login"):
        if master_key == "admin123":  # Replace in production
            st.session_state.authorized = True
            st.session_state.failed_attempts = 0
            st.success("✅ Access Granted! Now you can retry.")
        else:
            st.error("❌ Incorrect Admin Password.")