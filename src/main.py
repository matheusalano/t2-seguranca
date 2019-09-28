from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto import Random
import binascii


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


def decrypt_AES_CTR(ciphertext, key):
    b_text = bytes.fromhex(ciphertext[32:])
    b_key = bytes.fromhex(key)

    counter = Counter.new(128, initial_value=int(ciphertext[:32], AES.block_size))

    cipher = AES.new(b_key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(b_text).decode('utf-8')


def encrypt_AES_CBC(plaintext, key):

    b_key = bytes.fromhex(key)
    iv = Random.new().read(AES.block_size)

    text = pad(plaintext, AES.block_size)

    cipher = AES.new(b_key, AES.MODE_CBC, iv)
    return (iv + cipher.encrypt(text)).hex()


def encrypt_AES_CTR(plaintext, key):
    b_key = bytes.fromhex(key)
    iv = Random.new().read(AES.block_size)

    counter = Counter.new(128, initial_value=int(binascii.hexlify(iv), AES.block_size))
    cipher = AES.new(b_key, AES.MODE_CTR, counter=counter)

    return (iv + cipher.encrypt(plaintext)).hex()


if __name__ == "__main__":

    t1_cbc_key = '140b41b22a29beb4061bda66b6747e14'
    t1_cbc_ciphertext = '4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81'

    t2_cbc_key = '140b41b22a29beb4061bda66b6747e14'
    t2_cbc_ciphertext = '5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253'

    t3_ctr_key = '36f18357be4dbd77f050515c73fcf9f2'
    t3_ctr_ciphertext = '69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329'

    t4_ctr_key = '36f18357be4dbd77f050515c73fcf9f2'
    t4_ctr_ciphertext = '770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451'

    t5_ctr_key = '36f18357be4dbd77f050515c73fcf9f2'
    t5_ctr_plaintext = '5468697320697320612073656e74656e636520746f20626520656e63727970746564207573696e672041455320616e6420435452206d6f64652e'

    t6_cbc_key = '140b41b22a29beb4061bda66b6747e14'
    t6_cbc_plaintext = '4e657874205468757273646179206f6e65206f66207468652062657374207465616d7320696e2074686520776f726c642077696c6c2066616365206120626967206368616c6c656e676520696e20746865204c696265727461646f72657320646120416d6572696361204368616d70696f6e736869702e'

    print('\nTarefa 1 - Decrypt AES CBC:')
    print(decrypt_AES_CBC(t1_cbc_ciphertext, t1_cbc_key))

    print('\nTarefa 2 - Decrypt AES CBC:')
    print(decrypt_AES_CBC(t2_cbc_ciphertext, t2_cbc_key))

    print('\nTarefa 3 - Decrypt AES CTR:')
    print(decrypt_AES_CTR(t3_ctr_ciphertext, t3_ctr_key))

    print('\nTarefa 4 - Decrypt AES CTR:')
    print(decrypt_AES_CTR(t4_ctr_ciphertext, t4_ctr_key))

    print('\nTarefa 5 - Encrypt AES CTR:')
    t5_ctr_plaintext = bytes.fromhex(t5_ctr_plaintext).decode('utf-8')
    t5_encrypted = encrypt_AES_CTR(t5_ctr_plaintext, t5_ctr_key)
    print('Encrypted: ', t5_encrypted)
    print('Decrypted: ', decrypt_AES_CTR(t5_encrypted, t5_ctr_key))

    print('\nTarefa 6 - Encrypt AES CBC:')
    t6_cbc_plaintext = bytes.fromhex(t6_cbc_plaintext).decode('utf-8')
    t6_encrypted = encrypt_AES_CBC(t6_cbc_plaintext, t6_cbc_key)
    print('Encrypted: ', t6_encrypted)
    print('Decrypted: ', decrypt_AES_CBC(t6_encrypted, t6_cbc_key))
    
