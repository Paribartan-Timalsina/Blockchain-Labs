import requests
import jsonpickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

SERVER_URL = "http://127.0.0.1:8080"  # Server URL

def get_server_public_key():
    """Retrieve the public key from the server."""
    response = requests.get(f"{SERVER_URL}/send_key")
    public_key_pem = jsonpickle.decode(response.text)
    return public_key_pem.encode('utf-8')

def encrypt_aes_key(aes_key, public_key_pem):
    """Encrypt AES key using the server's RSA public key."""
    public_key = RSA.import_key(public_key_pem)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    return encrypted_key.hex()

def encrypt_message(message, aes_key):
    """Encrypt a message using AES encryption."""
    cipher_aes = AES.new(aes_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode('utf-8'))
    encrypted_data = cipher_aes.nonce + tag + ciphertext
    return encrypted_data.hex()

def send_encrypted_data(encrypted_message, encrypted_aes_key):
    """Send encrypted AES key and message to the server for decryption."""
    payload = {
        "encrypted_message": encrypted_message,
        "encrypted_aes_key": encrypted_aes_key
    }
    response = requests.post(f"{SERVER_URL}/decrypt_message", json=payload)
    return response.json()

def main():
    """Client-side secure communication workflow."""
    # Step 1: Get the server's public RSA key
    server_public_key = get_server_public_key()
    
    # Step 2: Generate a random AES key (128-bit)
    aes_key = get_random_bytes(16)

    # Step 3: Encrypt the AES key using the server’s RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, server_public_key)

    # Step 4: Encrypt a message using AES encryption
    original_message = input("Enter the message you want to send: ")
    encrypted_message = encrypt_message(original_message, aes_key)

    print(f"Original Message: {original_message}")
    print(f"Encrypted Message: {encrypted_message}")
    print(f"Encrypted AES Key: {encrypted_aes_key}")

    # Step 5: Send encrypted data to the server for decryption
    response = send_encrypted_data(encrypted_message, encrypted_aes_key)
    
    # Step 6: Receive and print the decrypted message from the server
    decrypted_message = response.get("decrypted_message", "Decryption failed")
    print(f"Decrypted Message from Server: {decrypted_message}")

if __name__ == "__main__":
    main()
