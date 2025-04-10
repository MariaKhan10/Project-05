import streamlit as st
import json
import os
import base64
import hashlib
from datetime import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

# File paths
USER_FILE = "users.json"
DATA_FILE = "secure_data.json"
SALT = b'secure-salt-value'  

# Load data from files
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

if os.path.exists(USER_FILE):
    with open(USER_FILE, "r") as f:
        users = json.load(f)
else:
    users = {}

# Session state
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = None
if "current_user" not in st.session_state:
    st.session_state.current_user = None

# Key derivation

def generate_key(passkey: str) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(passkey.encode()))

# Encrypt and decrypt

def encrypt_data(text: str, passkey: str) -> str:
    key = generate_key(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text: str, passkey: str) -> str | None:
    key = generate_key(passkey)
    cipher = Fernet(key)
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# File saving

def save_users():
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f, indent=4)

# Lockout system

def is_locked_out():
    if st.session_state.lockout_time:
        if datetime.now() < st.session_state.lockout_time:
            return True
        else:
            st.session_state.failed_attempts = 0
            st.session_state.lockout_time = None
    return False

# UI

st.sidebar.title("🔐 Secure Data App")
page = st.sidebar.radio("Navigate", ["Login", "Register", "Store Data", "Retrieve Data"])

# ----------------- REGISTER -----------------
if page == "Register":
    st.title("📝 Register")
    new_email = st.text_input("Enter email")
    new_password = st.text_input("Enter password", type="password")
    
    if st.button("Register"):
        if new_email in users:
            st.error("⚠️ User already exists!")
        elif new_email and new_password:
            users[new_email] = hashlib.sha256(new_password.encode()).hexdigest()
            save_users()
            st.success("✅ Registration successful. Please log in.")
        else:
            st.error("All fields required!")

# ----------------- LOGIN -----------------
elif page == "Login":
    st.title("🔐 Login")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if email in users and users[email] == hashlib.sha256(password.encode()).hexdigest():
            st.session_state.current_user = email
            st.success("✅ Logged in successfully!")
        else:
            st.error("❌ Invalid credentials")

# ----------------- STORE -----------------
elif page == "Store Data":
    st.title("📥 Store Data")
    if not st.session_state.current_user:
        st.warning("Please login first from the Login page.")
    else:
        text = st.text_area("Text to encrypt")
        passkey = st.text_input("Enter a passkey", type="password")

        if st.button("Encrypt & Save"):
            if text and passkey:
                encrypted = encrypt_data(text, passkey)
                stored_data[st.session_state.current_user] = {"encrypted_text": encrypted}
                save_data()
                st.success("✅ Data encrypted and stored.")
                st.code(encrypted, language="text")
            else:
                st.error("⚠️ All fields are required.")

# ----------------- RETRIEVE -----------------
elif page == "Retrieve Data":
    st.title("🔍 Retrieve Your Data")

    if not st.session_state.current_user:
        st.warning("Please login first from the Login page.")
    elif is_locked_out():
        st.warning("🚫 Too many failed attempts. Try again later.")
    else:
        encrypted_input = st.text_area("Paste your encrypted data")
        passkey = st.text_input("Enter your passkey", type="password")

        if st.button("Decrypt"):
            user_email = st.session_state.current_user
            if user_email in stored_data:
                decrypted = decrypt_data(encrypted_input, passkey)
                if decrypted:
                    st.success("✅ Data decrypted successfully!")
                    st.text_area("Decrypted Text:", decrypted, height=150)
                    st.session_state.failed_attempts = 0
                else:
                    st.session_state.failed_attempts += 1
                    attempts_left = 3 - st.session_state.failed_attempts
                    if st.session_state.failed_attempts >= 3:
                        # 🚨 Force logout after 3 failed attempts
                        st.session_state.failed_attempts = 0
                        st.session_state.lockout_time = None
                        st.session_state.current_user = None
                        st.error("🚫 3 failed attempts. You have been logged out for security reasons.")
                        st.rerun()
                    else:
                        st.error(f"❌ Incorrect passkey! Attempts left: {attempts_left}")
            else:
                st.error("❌ No data found for this user.")


st.markdown(
    "<hr><div style='text-align: center; font-size: 18px; color: grey;'>"
    "🔐 Built by <b>Maria Khan</b> with ❤️"
    "</div>",
    unsafe_allow_html=True
)