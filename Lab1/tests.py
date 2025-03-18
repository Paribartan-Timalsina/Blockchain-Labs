import unittest
import requests
import jsonpickle
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
import base64

SERVER_URL = "http://127.0.0.1:8080"  # Server URL

class SecureCommunicationTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Fetch server's public key once before running tests."""
        response = requests.get(f"{SERVER_URL}/send_key")
        cls.server_public_key = jsonpickle.decode(response.text).encode("utf-8")
        cls.aes_key = get_random_bytes(16)  # Generate AES key (128-bit)

    def encrypt_aes_key(self, aes_key, public_key_pem):
        """Helper method to encrypt the AES key using RSA public key."""
        public_key = RSA.import_key(public_key_pem)
        cipher_rsa = PKCS1_OAEP.new(public_key)
        return cipher_rsa.encrypt(aes_key).hex()

    def encrypt_message(self, message, aes_key):
        """Helper method to encrypt messages using AES."""
        cipher_aes = AES.new(aes_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(message.encode("utf-8"))
        encrypted_data = cipher_aes.nonce + tag + ciphertext
        return encrypted_data.hex()

    def test_1_server_key_retrieval(self):
        """Test if the server's public key is retrievable and valid."""
        self.assertTrue(self.server_public_key.startswith(b"-----BEGIN PUBLIC KEY-----"))

    def test_2_encryption_decryption(self):
        """Test if an encrypted message is correctly decrypted by the server."""
        original_message = "Hello, This is the secure server!"
        encrypted_aes_key = self.encrypt_aes_key(self.aes_key, self.server_public_key)
        encrypted_message = self.encrypt_message(original_message, self.aes_key)

        payload = {
            "encrypted_message": encrypted_message,
            "encrypted_aes_key": encrypted_aes_key
        }
        response = requests.post(f"{SERVER_URL}/decrypt_message", json=payload)

        self.assertEqual(response.status_code, 200)
        decrypted_message = response.json().get("decrypted_message", "")
        self.assertEqual(decrypted_message, original_message)

    def test_3_invalid_aes_key(self):
        """Test server's response to an invalid AES key (wrong decryption)."""
        wrong_aes_key = get_random_bytes(16)  # Generate a random wrong key
        encrypted_message = self.encrypt_message("Hello, Secure Server!", wrong_aes_key)
        encrypted_aes_key = self.encrypt_aes_key(self.aes_key, self.server_public_key)

        payload = {
            "encrypted_message": encrypted_message,
            "encrypted_aes_key": encrypted_aes_key
        }
        response = requests.post(f"{SERVER_URL}/decrypt_message", json=payload)

        self.assertEqual(response.status_code, 500)  # Expect a failure due to invalid decryption

if __name__ == "__main__":
    unittest.main()
