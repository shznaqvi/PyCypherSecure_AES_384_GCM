import base64
import hashlib

from Cryptodome.Cipher import AES  # from pycryptodomex v-3.10.4
from Cryptodome.Random import get_random_bytes

KEY = 'ThWmZq4t7w!zVaLu@b1ePeRcE!V3r5u8x/A?D*G-KaPdSgVkYp3s6v9y$BNE)H@M'

HASH_NAME = "sha384"
IV_LENGTH = 12
# ITERATION_COUNT = 65536
KEY_LENGTH = 32
SALT_LENGTH = 16
TAG_LENGTH = 16


def encrypt(key, plain_message):
    # salt = get_random_bytes(SALT_LENGTH)  # Random salt of 16 bytes
    # secret = get_hash_384(KEY, IV_LENGTH, KEY_LENGTH)

    iv = get_random_bytes(IV_LENGTH)  # Random IV of 12 bytes
    cipher = AES.new(key, AES.MODE_GCM, iv)

    encrypted_message_byte, tag = cipher.encrypt_and_digest(plain_message.encode("utf-8"))
    cipher_byte = iv + encrypted_message_byte + tag
    # print("IV: "+str(base64.b64encode(iv).decode("utf-8")))
    # print("encrypted_message_byte: "+str(base64.b64encode(encrypted_message_byte).decode("utf-8")))
    # print("tag: "+str(base64.b64encode(tag).decode("utf-8")))

    encoded_cipher_byte = base64.b64encode(cipher_byte)
    # return encoded_cipher_byte
    return bytes.decode(encoded_cipher_byte)


def decrypt(key, cipher_message):
    encrypted = base64.b64decode(cipher_message)
    iv = encrypted[:IV_LENGTH]
    # salt = decoded_cipher_byte[IV_LENGTH:(IV_LENGTH + SALT_LENGTH)]
    ciphertext = encrypted[IV_LENGTH:-TAG_LENGTH]
    tag = encrypted[-TAG_LENGTH:]

    # print("cipher_message: " + str(cipher_message))
    # print("encrypted: " + str(encrypted))
    # print("iv: " + str(iv))
    # print("ciphertext: " + str(ciphertext))
    # print("tag: " + str(tag))
    # print("key: " + str(key))

    # base64_bytes = cipher_message
    # message_bytes = base64.b64decode(base64_bytes)
    # message = message_bytes
    # # print("decoded_cipher_byte: "+str(encrypted))
    # print("message: "+str(message))
    # print("cipher_message: "+str(cipher_message))
    # print("IV: "+str(base64.b64encode(iv).decode("utf-8")))
    # print("encrypted_message_byte: "+str(base64.b64encode(ciphertext).decode("utf-8")))
    # print("tag: "+str(base64.b64encode(tag).decode("utf-8")))
    # secret = get_hash_384(KEY, IV_LENGTH, KEY_LENGTH)
    cipher = AES.new(key, AES.MODE_GCM, iv)

    decrypted = cipher.decrypt_and_verify(ciphertext, tag)
    decrypted = decrypted.decode("utf-8")
    return decrypted


# def get_secret_key(key, salt):
#     return hashlib.pbkdf2_hmac(HASH_NAME, key.encode(), salt, ITERATION_COUNT, KEY_LENGTH)

# Hash a single string with hashlib.sha256


def get_hash_384(key, offset, length):
    # $hash = base64_encode(hash('sha384', $key, true));
    # $hashedkey = substr($hash, $offset, $length);
    # a_string = 'Qo9DWrwhuOMaloKqLDC0lgBUWCEn9IN0'
    a_string = key
    hashed_string = hashlib.sha384(a_string.encode('utf-8')).digest()
    hashed_string = base64.b64encode(hashed_string)
    print("Hashed: " + str(hashed_string[offset:length + offset].decode('utf-8')))
    #    print("Hashed: "+str(base64.b64encode(hashed_string).decode("utf-8")))
    #    hashed_string = base64.b64encode(hashed_string).decode("utf-8")
    #   print("Hashed: "+hashed_string)
    return hashed_string[offset:length + offset]
    # return hashed_string


outputFormat = "{:<25}:{}"
# secret_key = "ThWmZq4t7w!zVaLu@b1ePeRcE!V3r5u8x/A?D*G-KaPdSgVkYp3s6v9y$BNE)H@M"
secret_key = get_hash_384(KEY, IV_LENGTH, KEY_LENGTH)
plain_text = "This is an encrypted message."
encrypted_in_php = "IDOUom1Mlf/XX0Ichoeh0oKj4JszB15Kpg7GlCE5eYZO0iR4shjjTjVd5Gr7p8jI6o1wQvQnVD+k"
encrypted_in_java = "X0kwJM4kk1iK5jR9CNMQnmF0Cbav62ABxxa9U9eckWeCvHmkNd3QKAkc60OAClgBlCi4SI5g17ke"

print("------ AES-GCM Encryption (in Python) ------")
print(outputFormat.format("encryption input", plain_text))
cipher_text = encrypt(secret_key, plain_text)
print(outputFormat.format("encryption output", cipher_text))

print("\n------ AES-GCM Decryption (Using Python Encryption) ------")
unciphered_text = decrypt(secret_key, cipher_text)
print(outputFormat.format("decryption input", cipher_text))
print(outputFormat.format("decryption output", unciphered_text))

print("\n------ AES-GCM Decryption (using PHP Encryption) ------")
decrypted_text_php = decrypt(secret_key, encrypted_in_php)
print(outputFormat.format("decryption input", encrypted_in_php))
print(outputFormat.format("decryption output", decrypted_text_php))

print("\n------ AES-GCM Decryption (using JAVA/Android Encryption) ------")
decrypted_text_java = decrypt(secret_key, encrypted_in_java)
print(outputFormat.format("decryption input", encrypted_in_java))
print(outputFormat.format("decryption output", decrypted_text_java))
