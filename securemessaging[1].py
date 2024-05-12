from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import hashlib
import base64

class SecureMessaging:
    def __init__(self, sender_private_key, recipient_public_key, username, password):
        self.sender_private_key = sender_private_key
        self.recipient_public_key = recipient_public_key
        self.username = username
        self.password = password

    def authenticate_user(self):
        input_username = input("Enter username: ")
        input_password = input("Enter password: ")
        if input_username == self.username and input_password == self.password:
            print("Authentication successful.")
            return True
        else:
            print("Authentication failed. Invalid username or password.")
            return False

    def encrypt_message(self, message):
        # Here, let's just encode the message to bytes for demonstration
        encrypted_message = message.encode()
        return encrypted_message

    def decrypt_message(self, encrypted_message):
        # Here, let's just decode the message from bytes for demonstration
        decrypted_message = encrypted_message.decode()
        return decrypted_message

    def generate_signature(self, message):
        # Generate digital signature with sender's private key
        signature = self.sender_private_key.sign(
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return base64.b64encode(signature)

    def verify_signature(self, message, signature):
        # Verify digital signature with sender's public key
        try:
            self.sender_private_key.public_key().verify(
                base64.b64decode(signature),
                message.encode(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("Signature verified.")
            return True
        except Exception as e:
            print("Signature verification failed:", e)
            return False

    def generate_hash(self, message):
        # Generate hash value for data integrity
        h = hashlib.sha256()
        h.update(message.encode())
        return h.digest()

    def verify_hash(self, message, hash_value):
        # Verify hash value for data integrity
        return hashlib.sha256(message.encode()).digest() == hash_value

# Example usage:
# Generate sender's and recipient's key pairs
sender_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
sender_public_key = sender_private_key.public_key()
recipient_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
recipient_public_key = recipient_private_key.public_key()

# Initialize SecureMessaging instance with username and password
username = "Sameerdubey"
password = "dubey@863"
secure_messaging = SecureMessaging(sender_private_key, recipient_public_key, username, password)

# Authenticate user
if secure_messaging.authenticate_user():
    # User authenticated, proceed with messaging operations
    message = input("Enter your message: ")

    # Encrypt message (not implemented here)
    encrypted_message = secure_messaging.encrypt_message(message)
    print("Encrypted message:", encrypted_message)

    # Decrypt message (not implemented here)
    decrypted_message = secure_messaging.decrypt_message(encrypted_message)
    print("Decrypted message:", decrypted_message)

    # Generate and verify digital signature
    signature = secure_messaging.generate_signature(message)
    print("Generated signature:", signature)
    secure_messaging.verify_signature(message, signature)

    # Generate and verify hash value
    hash_value = secure_messaging.generate_hash(message)
    print("Generated hash value:", hash_value)
    print("Hash value verified:", secure_messaging.verify_hash(message, hash_value))
