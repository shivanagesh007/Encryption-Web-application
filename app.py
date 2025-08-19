from flask import Flask, request, jsonify, render_template
from cryptography.fernet import Fernet
import base64

app = Flask(__name__)

# Generate a Fernet key from password
def get_key(password):
    salted_password = password + "SeeMeSalt123!"
    key = base64.urlsafe_b64encode(salted_password.ljust(32)[:32].encode())
    return key

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        text = data.get("text", "")
        password = data.get("password", "")
        
        if not text or not password:
            return jsonify({"error": "Text and password are required"}), 400
            
        # Generate key from password
        key = get_key(password)
        fernet = Fernet(key)
        
        # Encrypt the text
        encrypted = fernet.encrypt(text.encode())
        
        return jsonify({"ciphertext": encrypted.decode()})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        ciphertext = data.get("ciphertext", "")
        password = data.get("password", "")
        
        if not ciphertext or not password:
            return jsonify({"error": "Ciphertext and password are required"}), 400
            
        # Generate key from password
        key = get_key(password)
        fernet = Fernet(key)
        
        # Decrypt the text
        decrypted = fernet.decrypt(ciphertext.encode())
        
        return jsonify({"plaintext": decrypted.decode()})
    except Exception as e:
        return jsonify({"error": "Decryption failed. Wrong password or invalid ciphertext."}), 400

if __name__ == '__main__':
    app.run(debug=True)