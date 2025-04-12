import base64
import streamlit as st
import json
import os
import hashlib
import time
import uuid
from cryptography.fernet import Fernet

from hashlib import pbkdf2_hmac

# === Initialize session state variables ===
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "current_page" not in st.session_state:
    st.session_state.current_page = "Home"
if "last_attempt_time" not in st.session_state:
    st.session_state.last_attempt_time = 0

# === function to hash passkey ===
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

def generate_key_from_passkey(passkey):
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

def encrypt_data(text, passkey):
    key = generate_key_from_passkey(passkey)
    cipher = Fernet(key)
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text, passkey, data_id):
    try:
        hashed_passkey = hash_passkey(passkey)
        if data_id in st.session_state.stored_data and st.session_state.stored_data[data_id]['passkey'] == hashed_passkey:
            key = generate_key_from_passkey(passkey)
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_text.encode()).decode()
            st.session_state.failed_attempts = 0
            return decrypted 
        else:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None

    except Exception as e:
        st.session_state.failed_attempts += 1
        st.session_state.last_attempt_time = time.time()
        return None

def generate_data_id():
    import uuid
    return str(uuid.uuid4())

def reset_failed_attempts():
    st.session_state.failed_attempts = 0

def change_page(page):
    st.session_state.current_page = page
    
# === Streamlit UI Configuration ===
st.title("🔏 Secure Data Encryption System")    

# === Navigation ===
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))

# Updated current page based on sidebar selection
st.session_state.current_page = choice

# Check if too many failed attempts have been made
if st.session_state.failed_attempts >= 3:
    st.session_state.current_page = "Login"
    st.warning("❌ Too many failed attempts. Please reauthenticate.")
    
# Display current page    
if st.session_state.current_page == "Home":
    st.subheader("🏠 Welcome to Secure Data Encryption System!")
    st.write("Use this app to **securely store and retrieve sensitive data**")
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data", use_container_width=True):
            change_page("Store Data")
    with col2:
        if st.button("Retrieve Data", use_container_width=True):
            change_page("Retrieve Data")
    
    st.info(f"🔑Currently storing {len(st.session_state.stored_data)} encrypted data entries")

elif st.session_state.current_page == "Store Data":
    st.subheader("📦 Store Data Securely")
    user_data = st.text_area("Enter sensitive data:")
    passkey = st.text_input("Create passkey:", type="password")
    confirm_passkey = st.text_input("Confirm passkey:", type="password")
        
    if st.button("Encrypt and Save"):
        if user_data and passkey and confirm_passkey:
            if passkey != confirm_passkey:
                st.error("❌ Passkeys do not match")
            else:
                data_id = generate_data_id()
                # Hash the passkey
                hashed_passkey = hash_passkey(passkey)
                # Encrypt the user data
                encrypted_text = encrypt_data(user_data, passkey)
                # Store in the required format
                st.session_state.stored_data[data_id] = {
                    'encrypted_text': encrypted_text,
                    'passkey': hashed_passkey
                }
                st.success("✅ Data stored successfully!")

                # Display the data ID for retrival 
                st.code(data_id, language="text")
                st.info("🔑 Keep this Data ID and passkey safe for future retrieval")    
        else:
            st.error("❌ Please fill in all fields")

elif st.session_state.current_page == "Retrieve Data":
    st.subheader("🔑 Retrieve Your Data") 

    # Show attempts remaining 
    attempts_remaining = 3 -st.session_state.failed_attempts
    st.info(f"Attempts remaining:{attempts_remaining}")

    data_id = st.text_input("Enter Data ID:")
    passkey = st.text_input("Enter passkey:", type="password")


    if st.button("Decrypt"):
        if data_id and passkey:
            # Check if the data ID exists
            if data_id in st.session_state.stored_data:
                # Retrieve the encrypted text
                encrypted_text = st.session_state.stored_data[data_id]['encrypted_text']
                # Decrypt the data
                decrypted_text = decrypt_data(encrypted_text, passkey, data_id)
                
                if decrypted_text:
                    st.success("✅ Decryption successfully!")
                    st.markdown("### Your Decrypted Data:")
                    st.code(decrypted_text, language="text")
                else:
                    st.error(f"❌ Incorrect passkey! Attempts Remaining: {3 - st.session_state.failed_attempts}")
            else:
                st.error("❌ Invalid Data ID!")
            # Check if too many failed attempts have been made
            if st.session_state.failed_attempts >= 3:
                # Reset failed attempts and redirect to login page
                st.warning("🔒 Too many failed attempts. Please reauthenticate.")    
                st.session_state.current_page = "Login"
                st.rerun()
        else:
            st.error("⚠️Both fields are required")

elif st.session_state.current_page == "Login":
    st.subheader("🔒 Reauthentication Required")

    if time.time() - st.session_state.last_attempt_time < 10 and st.session_state.failed_attemts >= 3:
        remaining_time = int(10 - (time.time() - st.session_state.last_attempt_time))
        st.warning(f"🔒 Please wait {remaining_time} seconds before trying again.")

    else:
        login_pass = st.text_input("Enter Master Passkey:", type="password")
        
        if st.button("Login"):
            if login_pass == "admin123":
                reset_failed_attempts()
                st.success("✅ Reauthrized successfully!")
                st.session_state.current_page = "Home"
                st.rerun()
            else:
                st.error("❌ Incorrect password")
#    Add a footer                 
st.markdown("---")
st.markdown("🔏 Secure Data Encryption System | Educational Project")
