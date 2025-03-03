import streamlit as st
import base64
import os
from Crypto.Cipher import DES, AES, ARC4
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
import io

if 'users' not in st.session_state:
    st.session_state.users = {}

def get_file_extension(filename):
    return os.path.splitext(filename)[1]

st.markdown(
    """
    <style>
    body {
        background-color: #FFFAF0;
    }
    .stButton > button {
        background-color: #FF69B4;
        color: white;
        font-size: 16px;
        border-radius: 10px;
    }
    .stTextInput, .stTextArea {
        border-radius: 10px;
        border: 2px solid #FF69B4;
    }
    </style>
    """,
    unsafe_allow_html=True
)

def show_registration():
    st.title("📝 Registrasi Akun")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")
    if st.button("✨ Daftar Sekarang ✨"):
        if username in st.session_state.users:
            st.error("❌ Username sudah terdaftar!")
        else:
            st.session_state.users[username] = password
            st.success("✅ Akun berhasil dibuat! Silakan login.")

def show_login():
    st.title("🔑 Login ke 2RCRYPT")
    username = st.text_input("👤 Username")
    password = st.text_input("🔒 Password", type="password")
    if st.button("🚀 Login"):
        if username in st.session_state.users and st.session_state.users[username] == password:
            st.session_state.authenticated = True
            st.rerun()
        else:
            st.error("❌ Username atau password salah!")

def simple_xor(data, key):
    key = key.encode('utf-8')
    extended_key = (key * (len(data) // len(key) + 1))[:len(data)]
    return bytes([b ^ extended_key[i] for i, b in enumerate(data)])

def rc4_encrypt(data, key):
    cipher = ARC4.new(key.encode('utf-8'))
    return cipher.encrypt(data)

def des_encrypt(data, key, mode):
    key = key.encode('utf-8').ljust(8, b'\0')[:8]
    if isinstance(data, str):
        data = data.encode('utf-8')
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        return cipher.encrypt(pad(data, DES.block_size))
    elif mode == 'CBC':
        iv = get_random_bytes(8)
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, DES.block_size))
    elif mode == 'CTR':
        iv = get_random_bytes(8)
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
        return iv + cipher.encrypt(data)

def des_decrypt(ciphertext, key, mode):
    key = key.encode('utf-8').ljust(8, b'\0')[:8]
    if mode == 'ECB':
        cipher = DES.new(key, DES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), DES.block_size)
    elif mode == 'CBC':
        iv = ciphertext[:8]
        cipher = DES.new(key, DES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[8:]), DES.block_size)
    elif mode == 'CTR':
        iv = ciphertext[:8]
        ctr = Counter.new(64, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = DES.new(key, DES.MODE_CTR, counter=ctr)
        return cipher.decrypt(ciphertext[8:])

def aes_encrypt(data, key, mode):
    key = key.encode('utf-8').ljust(32, b'\0')[:32]
    if isinstance(data, str):
        data = data.encode('utf-8')
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(pad(data, AES.block_size))
    elif mode == 'CBC':
        iv = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(pad(data, AES.block_size))
    elif mode == 'CTR':
        iv = get_random_bytes(16)
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return iv + cipher.encrypt(data)

def aes_decrypt(ciphertext, key, mode):
    key = key.encode('utf-8').ljust(32, b'\0')[:32]
    if mode == 'ECB':
        cipher = AES.new(key, AES.MODE_ECB)
        return unpad(cipher.decrypt(ciphertext), AES.block_size)
    elif mode == 'CBC':
        iv = ciphertext[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size)
    elif mode == 'CTR':
        iv = ciphertext[:16]
        ctr = Counter.new(128, initial_value=int.from_bytes(iv, byteorder='big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.decrypt(ciphertext[16:])

def encrypt_file(file_bytes, key, algorithm, mode=None):
    if algorithm == "XOR":
        return simple_xor(file_bytes, key)
    elif algorithm == "RC4":
        return rc4_encrypt(file_bytes, key)
    elif algorithm == "DES":
        return des_encrypt(file_bytes, key, mode)
    elif algorithm == "AES":
        return aes_encrypt(file_bytes, key, mode)

def decrypt_file(file_bytes, key, algorithm, mode=None):
    if algorithm == "XOR":
        return simple_xor(file_bytes, key)
    elif algorithm == "RC4":
        return rc4_encrypt(file_bytes, key)  
    elif algorithm == "DES":
        return des_decrypt(file_bytes, key, mode)
    elif algorithm == "AES":
        return aes_decrypt(file_bytes, key, mode)

def main():
    st.sidebar.title("📌 Menu")
    choice = st.sidebar.radio("🔽 Pilih Opsi", ("Login", "Registrasi"))
    if choice == "Login":
        show_login()
    else:
        show_registration()
    
    if 'authenticated' in st.session_state and st.session_state.authenticated:
        st.title("🔒 2RCRYPT")
        algorithm = st.selectbox("🛠 Pilih Algoritma", ("XOR", "RC4", "DES", "AES"))
        mode = None
        if algorithm in ["DES", "AES"]:
            mode = st.selectbox("🎛 Pilih Mode", ("ECB", "CBC", "CTR"))
        key = st.text_input("🔑 Masukkan Kunci")
        input_method = st.radio("📥 Pilih Jenis Input", ("Teks", "File"))
        
        if input_method == "Teks":
            message = st.text_area("📝 Masukkan Pesan")
            if st.button("🔐 Enkripsi 🔒") and message and key:
                try:
                    encrypted_data = encrypt_file(message.encode('utf-8'), key, algorithm, mode)
                    result = base64.b64encode(encrypted_data).decode()  
                    st.text_area("🔑 Ciphertext (Base64)", result)
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan saat enkripsi: {str(e)}")
            if st.button("🔓 Dekripsi 🔑") and message:
                try:
                    decrypted_data = base64.b64decode(message)
                    result = decrypt_file(decrypted_data, key, algorithm, mode).decode('utf-8', errors='ignore')
                    st.text_area("📜 Plaintext", result)
                except Exception as e:
                    st.error(f"❌ Terjadi kesalahan saat dekripsi: {str(e)}")
        
        else:
            uploaded_file = st.file_uploader("📂 Unggah File")
            if uploaded_file:
                file_bytes = uploaded_file.read()
                file_extension = get_file_extension(uploaded_file.name)
                
                if st.button("🔐 Enkripsi File 📂"):
                    encrypted_data = encrypt_file(file_bytes, key, algorithm, mode)
                    encrypted_filename = f"{uploaded_file.name}.enc"
                    st.download_button("⬇️ Unduh File Terenkripsi", data=encrypted_data, file_name=encrypted_filename)
                
                if st.button("🔓 Dekripsi File 📂"):
                    decrypted_data = decrypt_file(file_bytes, key, algorithm, mode)
                    decrypted_filename = f"decrypted{file_extension}"
                    st.download_button("⬇️ Unduh File Terdekripsi", data=decrypted_data, file_name=decrypted_filename)

if __name__ == "__main__":
    main()