from Crypto.Cipher import AES

def encrypt(msg, key):
    # Create an AES cipher object with the key using the mode EAX
    # Message should be encoded
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce

    # Encrypt the message
    ciphertext, tag = cipher.encrypt_and_digest(msg)

    return  ciphertext, nonce, tag

def decrypt(ciphertext, key, nonce, tag):
    # Create an AES cipher object with the key using the mode EAX
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

    # Decrypt the message
    plaintext = cipher.decrypt(ciphertext)

    try:
        cipher.verify(tag)
        return plaintext
    except ValueError:
        return False