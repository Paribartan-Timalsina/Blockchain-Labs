import flask
from flask import request, jsonify
import jsonpickle
import os
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

app = flask.Flask(__name__)

def generate_keys():
    """Generate RSA key pair if not already present."""
    if not os.path.exists('private_key.pem') or not os.path.exists('public_key.pem'):
        key = RSA.generate(2048)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        with open('private_key.pem', 'wb') as file:
            file.write(private_key)
        with open('public_key.pem', 'wb') as file:
            file.write(public_key)
        print("Keys generated")
    else:
        print("Keys already exist")

generate_keys()

@app.route("/send_key", methods=['GET'])
def send_key():
    """Send the public key to the client."""
    with open('public_key.pem', 'rb') as file:
        public_key = file.read()
    return jsonpickle.encode(public_key.decode('utf-8'))

@app.route("/decrypt_message", methods=['POST'])
def decrypt_message_api():
    """Decrypt AES-encrypted message using the stored private key."""
    with open('private_key.pem', 'rb') as file:
        private_key = RSA.import_key(file.read())

    data = request.get_json()
    encrypted_message = data['encrypted_message']
    encrypted_aes_key = data['encrypted_aes_key']

    aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    decrypted_message = decrypt_message(encrypted_message, aes_key)
    
    return jsonify({"decrypted_message": decrypted_message})

def decrypt_aes_key(encrypted_key, rsa_private_key):
    """Decrypt AES key using RSA private key."""
    cipher_rsa = PKCS1_OAEP.new(rsa_private_key)
    decrypted_key = cipher_rsa.decrypt(bytes.fromhex(encrypted_key))
    return decrypted_key

def decrypt_message(encrypted_message, aes_key):
    """Decrypt message using AES."""
    encrypted_data = bytes.fromhex(encrypted_message)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher_aes = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return decrypted_message.decode('utf-8')

if __name__ == "__main__":
    app.run(debug=True,port=8080)
