import streamlit as st
from cryptography.fernet import Fernet
import sqlite3
import secrets
import string
import hashlib
import base64


st.set_page_config(
    page_title="secure data locker",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)


def apply_vaultx_theme():
    st.markdown(f"""
    <style>
        /* Main container */
        .main {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
        }}
        
        /* Title styling */
        h1, h2, h3 {{
            color: #00d1ff !important;
            text-align: center;
            font-family: 'Arial', sans-serif;
        }}
        
        /* Button styling */
        .stButton>button {{
            background: #00d1ff !important;
            color: #000 !important;
            border-radius: 5px !important;
            font-weight: bold !important;
            width: 100% !important;
            border: none !important;
        }}
        
        /* Input fields */
        .stTextInput>div>div>input, 
        .stPassword>div>div>input {{
            background-color: rgba(255,255,255,0.1) !important;
            color: black !important;  /* Changed to black */
            border-radius: 5px !important;
            border: 1px solid #00d1ff !important;
        }}
        
        /* Make password dots black */
        input[type="password"] {{
            color: black !important;
            -webkit-text-security: disc !important;
        }}
        
        /* Hide unnecessary elements */
        header, footer {{
            visibility: hidden;
        }}
        .stApp {{
            background: transparent;
        }}
    </style>
    """, unsafe_allow_html=True)

apply_vaultx_theme()

def generate_key():
    return Fernet.generate_key()

def init_db():
    conn = sqlite3.connect('vaultx.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY,
                 password TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS passwords 
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT,
                 website TEXT NOT NULL,
                 password TEXT NOT NULL)''')
    conn.commit()
    conn.close()

def encrypt_password(password, key):
    fernet = Fernet(key)
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(encrypted_password, key):
    fernet = Fernet(key)
    return fernet.decrypt(encrypted_password.encode()).decode()

def generate_password(length=12):
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(chars) for _ in range(length))

# --- Authentication ---
def create_user(username, password, key):
    conn = sqlite3.connect('vaultx.db')
    c = conn.cursor()
    encrypted_pwd = encrypt_password(password, key)
    c.execute("INSERT INTO users VALUES (?, ?)", (username, encrypted_pwd))
    conn.commit()
    conn.close()

def verify_user(username, password, key):
    conn = sqlite3.connect('vaultx.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username=?", (username,))
    result = c.fetchone()
    conn.close()
    
    if result:
        stored_pwd = decrypt_password(result[0], key)
        return stored_pwd == password
    return False


def login_section():
    col1, col2, col3 = st.columns([1,2,1])
    with col2:
        st.title("Welcome to VaultX")
        st.markdown("<h3 style='text-align: center;'>Secure Data Locker</h3>", unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["Login", "Register"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Username")
                password = st.text_input("Password", type="password")
                
                if st.form_submit_button("Login"):
                    if username and password:
                        if 'key' in st.session_state and verify_user(username, password, st.session_state.key):
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.rerun()
                        else:
                            st.error("Invalid credentials")
                    else:
                        st.error("Please enter both fields")
        
        with tab2:
            with st.form("register_form"):
                new_username = st.text_input("Choose Username")
                new_password = st.text_input("Choose Password", type="password")
                confirm_password = st.text_input("Confirm Password", type="password")
                
                if st.form_submit_button("Register"):
                    if new_username and new_password and confirm_password:
                        if new_password == confirm_password:
                            if 'key' not in st.session_state:
                                st.session_state.key = generate_key()
                            create_user(new_username, new_password, st.session_state.key)
                            st.success("Registration successful! Please login")
                        else:
                            st.error("Passwords don't match")
                    else:
                        st.error("Please fill all fields")

def password_manager():
    st.title(f"🔐 {st.session_state.username}'s Vault")
    
 
    with st.expander("➕ Add New Password"):
        with st.form("add_password"):
            website = st.text_input("Website")
            password = st.text_input("Password", type="password")
            col1, col2 = st.columns(2)
            with col1:
                if st.form_submit_button("Generate Strong"):
                    st.session_state.gen_pwd = generate_password()
                    st.rerun()
            with col2:
                if st.form_submit_button("Save"):
                    if website and password:
                        conn = sqlite3.connect('vaultx.db')
                        c = conn.cursor()
                        encrypted_pwd = encrypt_password(password, st.session_state.key)
                        c.execute("INSERT INTO passwords (username, website, password) VALUES (?, ?, ?)",
                                 (st.session_state.username, website, encrypted_pwd))
                        conn.commit()
                        conn.close()
                        st.success("Password saved!")
    
   
    st.subheader("Your Saved Passwords")
    conn = sqlite3.connect('vaultx.db')
    c = conn.cursor()
    c.execute("SELECT website, password FROM passwords WHERE username=?", (st.session_state.username,))
    passwords = c.fetchall()
    conn.close()
    
    if passwords:
        for website, pwd in passwords:
            decrypted = decrypt_password(pwd, st.session_state.key)
            with st.expander(website):
                st.text_input("Password", value=decrypted, type="password", key=f"pwd_{website}")
                if st.button("Copy", key=f"copy_{website}"):
                    st.session_state.clipboard = decrypted
                    st.toast("Copied to clipboard!")
    else:
        st.warning("No passwords saved yet")


init_db()

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    login_section()
else:
    password_manager()
    
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()