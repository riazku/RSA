from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Generate RSA key pair
key = RSA.generate(2048)

# Get public and private keys
public_key = key.publickey().export_key()
private_key = key.export_key()

# Write keys to files
with open('public.pem', 'wb') as f:
    f.write(public_key)

with open('private.pem', 'wb') as f:
    f.write(private_key)

# Function to Encrypt a message
def encrypt_message(message, public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher_rsa.encrypt(message.encode())
    return encrypted_message

# Function to Decrypt a message
def decrypt_message(encrypted_message, private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(encrypted_message)
    return decrypted_message.decode()


message = "Bscs041"
print("Text is:", message)

encrypted = encrypt_message(message, 'public.pem')
print("Encrypted message:", encrypted)

decrypted = decrypt_message(encrypted, 'private.pem')
print("Decrypted message:", decrypted)
