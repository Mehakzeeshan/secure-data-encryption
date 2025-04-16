import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# --- Session State Setup ---
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "reauthorized" not in st.session_state:
    st.session_state.reauthorized = False
if "last_page" not in st.session_state:
    st.session_state.last_page = "Home"
if "encryption_key" not in st.session_state:
    st.session_state.encryption_key = Fernet.generate_key()

# --- Cipher Setup ---
cipher = Fernet(st.session_state.encryption_key)

# --- In-Memory Storage ---
stored_data = {}  # Format: { encrypted_text: { "encrypted_text": "...", "passkey": "hashed" } }

# --- Helper Functions ---
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for key, value in stored_data.items():
        if value["encrypted_text"] == encrypted_text and value["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None

# --- Sidebar Navigation ---
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.last_page))
st.session_state.last_page = choice

# --- Page Logic ---
st.title("🔒 Secure Data Encryption System")

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey
            }
            st.success("✅ Data stored securely!")
            st.code(encrypted_text, language="text")
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    if st.session_state.failed_attempts >= 3 and not st.session_state.reauthorized:
        st.warning("🔒 Too many failed attempts! Please reauthorize.")
        st.session_state.last_page = "Login"
        st.rerun()
    else:
        st.subheader("🔍 Retrieve Your Data")
        encrypted_text = st.text_area("Enter Encrypted Data:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_text and passkey:
                decrypted_text = decrypt_data(encrypted_text, passkey)
                if decrypted_text:
                    st.success("✅ Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    remaining = max(0, 3 - st.session_state.failed_attempts)
                    st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining}")
                    if st.session_state.failed_attempts >= 3:
                        st.warning("🔐 Redirecting to Login...")
                        st.session_state.last_page = "Login"
                        st.rerun()
            else:
                st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Replace with real auth in production
            st.session_state.failed_attempts = 0
            st.session_state.reauthorized = True
            st.session_state.last_page = "Retrieve Data"
            st.success("✅ Reauthorized! Redirecting...")
            st.rerun()
        else:
            st.error("❌ Incorrect master password!")
