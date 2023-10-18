from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os

def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def generate_ecc_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(filename, 'wb') as key_file:
        key_file.write(pem)

def load_key_from_file(filename):
    if not os.path.isfile(filename):
        print(f"Error: Key file '{filename}' does not exist.")
        return None

    with open(filename, 'rb') as key_file:
        key_data = key_file.read()
        key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
    return key

def xor_encrypt(data, key):
    return bytes(x ^ key for x in data)

def xor_decrypt(data, key):
    return xor_encrypt(data, key)

def save_audio(filename, data):
    with open(filename, 'wb') as f:
        f.write(data)

def load_audio(filename):
    if not os.path.isfile(filename):
        print(f"Error: Audio file '{filename}' does not exist.")
        return None

    with open(filename, 'rb') as f:
        return f.read()

def des_encrypt(data, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def des_decrypt(data, key, iv):
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def aes_encrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

def aes_decrypt(data, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(data) + decryptor.finalize()

def main():
    while True:
        print("\nAudio Encryption Menu:")
        print("1. RSA Encryption")
        print("2. RSA Decryption")
        print("3. ECC Encryption")
        print("4. ECC Decryption")
        print("5. DES Encryption")
        print("6. DES Decryption")
        print("7. AES Encryption")
        print("8. AES Decryption")
        print("0. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            private_key, public_key = generate_rsa_key_pair()
            save_key_to_file(private_key, 'rsa_private_key.pem')
            audio_file = input("Enter the path to the .wav audio file: ")
            audio_data = load_audio(audio_file)

            if audio_data is not None:
                encrypted_data = xor_encrypt(audio_data, 42)  # Replace with actual RSA encryption
                save_audio("encrypted_audio.wav", encrypted_data)
                print("RSA encryption completed.")

        elif choice == '2':
            private_key = load_key_from_file('rsa_private_key.pem')
            encrypted_audio_file = input("Enter the path to the encrypted audio file: ")
            encrypted_audio_data = load_audio(encrypted_audio_file)

            if private_key is not None and encrypted_audio_data is not None:
                decrypted_data = xor_decrypt(encrypted_audio_data, 42)  # Replace with actual RSA decryption
                save_audio("decrypted_audio.wav", decrypted_data)
                print("RSA decryption completed.")

        elif choice == '3':
            private_key, public_key = generate_ecc_key_pair()
            save_key_to_file(private_key, 'ecc_private_key.pem')
            audio_file = input("Enter the path to the .wav audio file: ")
            audio_data = load_audio(audio_file)

            if audio_data is not None:
                encrypted_data = xor_encrypt(audio_data, 42)  # Replace with actual ECC encryption
                save_audio("encrypted_audio.wav", encrypted_data)
                print("ECC encryption completed.")

        elif choice == '4':
            private_key = load_key_from_file('ecc_private_key.pem')
            encrypted_audio_file = input("Enter the path to the encrypted audio file: ")
            encrypted_audio_data = load_audio(encrypted_audio_file)

            if private_key is not None and encrypted_audio_data is not None:
                decrypted_data = xor_decrypt(encrypted_audio_data, 42)  # Replace with actual ECC decryption
                save_audio("decrypted_audio.wav", decrypted_data)
                print("ECC decryption completed.")

        elif choice == '5':
            # DES Encryption
            des_key = os.urandom(8)
            iv = os.urandom(8)
            audio_file = input("Enter the path to the .wav audio file: ")
            audio_data = load_audio(audio_file)

            if audio_data is not None:
                encrypted_data = des_encrypt(audio_data, des_key, iv)
                save_audio("encrypted_audio.wav", encrypted_data)
                print("DES encryption completed.")

        elif choice == '6':
            # DES Decryption
            des_key = os.urandom(8)
            iv = os.urandom(8)
            encrypted_audio_file = input("Enter the path to the encrypted audio file: ")
            encrypted_audio_data = load_audio(encrypted_audio_file)

            if encrypted_audio_data is not None:
                decrypted_data = des_decrypt(encrypted_audio_data, des_key, iv)
                save_audio("decrypted_audio.wav", decrypted_data)
                print("DES decryption completed.")

        elif choice == '7':
            # AES Encryption
            aes_key = os.urandom(16)
            iv = os.urandom(16)
            audio_file = input("Enter the path to the .wav audio file: ")
            audio_data = load_audio(audio_file)

            if audio_data is not None:
                encrypted_data = aes_encrypt(audio_data, aes_key, iv)
                save_audio("encrypted_audio.wav", encrypted_data)
                print("AES encryption completed.")

        elif choice == '8':
            # AES Decryption
            aes_key = os.urandom(16)
            iv = os.urandom(16)
            encrypted_audio_file = input("Enter the path to the encrypted audio file: ")
            encrypted_audio_data = load_audio(encrypted_audio_file)

            if encrypted_audio_data is not None:
                decrypted_data = aes_decrypt(encrypted_audio_data, aes_key, iv)
                save_audio("decrypted_audio.wav", decrypted_data)
                print("AES decryption completed.")

        elif choice == '0':
            break

        else:
            print("Error: Invalid choice. Please choose a valid option.")

if __name__ == "__main__":
    main()
