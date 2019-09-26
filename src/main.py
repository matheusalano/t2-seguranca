from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random


def pad(text, block_size):
    return text + (block_size - len(text) % block_size) * chr(block_size - len(text) % block_size)


def unpad(text):
    return text[0:-ord(text[-1])]


def decrypt_AES_CBC(ciphertext, key):
    b_text = bytes.fromhex(ciphertext[32:])
    b_key = bytes.fromhex(key)
    b_iv = bytes.fromhex(ciphertext[:32])

    cipher = AES.new(b_key, AES.MODE_CBC, b_iv)
    return cipher.decrypt(b_text).decode('utf-8')


def decrypt_AES_CTR(ciphertext, key, iv):
    b_text = bytes.fromhex(ciphertext)
    b_key = bytes.fromhex(key)

    counter = Counter.new(128, initial_value=int(iv, AES.block_size))

    cipher = AES.new(b_key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(b_text).decode('utf-8')


def encrypt_AES_CBC(plaintext, key):

    b_key = bytes.fromhex(key)
    iv = Random.new().read(AES.block_size)

    text = pad(plaintext, AES.block_size)

    cipher = AES.new(b_key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(text)).hex()


def encrypt_AES_CTR(plaintext, key, iv):
    b_key = bytes.fromhex(key)

    counter = Counter.new(128, initial_value=int(iv, AES.block_size))

    cipher = AES.new(b_key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(plaintext).hex()


if __name__ == "__main__":
    cbc_key = '140b41b22a29beb4061bda66b6747e14'
    ciphertext = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'
    plain = '4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c642077696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f72657320646120416d6572696361204368616d70696f6e736869702e'

    new_enc = encrypt_AES_CBC(bytes.fromhex(plain).decode('utf-8'), cbc_key)
    print(new_enc)
    print(decrypt_AES_CBC(new_enc, cbc_key))
