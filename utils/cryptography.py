import os

from Crypto.Cipher import AES
import hashlib
import hmac

from binary.reader import whatsappReadBinary
from binary.writer import WABinaryWriter


def encrypt_and_mac(mess_tag, mess_node, mess_args, mac_key, enc_key):
    stream = WABinaryWriter()
    stream.write_node(mess_node)
    mess_bin = stream.getData()

    enc = AESEncrypt(enc_key, mess_bin)
    encrypted_mess = HmacSha256(mac_key, enc) + enc  # this may need padding to 64 byte boundary

    return bytearray(mess_tag + ',') + bytearray(mess_args) + encrypted_mess


def decrypt_node(message_content, mac_key, enc_key):
    hmac_validation = HmacSha256(mac_key, message_content[32:])
    if hmac_validation != message_content[0:32]:
        raise ValueError('Hmac mismatch')

    data = AESDecrypt(enc_key, message_content[32:])

    return whatsappReadBinary(data, True)


def HmacSha256(key, sign):
    return hmac.new(key, sign, hashlib.sha256).digest()


def HKDF(key, length, appInfo=""):  # implements RFC 5869, some parts from https://github.com/MirkoDziadzka/pyhkdf
    key = HmacSha256("\0" * 32, key)
    keyStream = ""
    keyBlock = ""
    blockIndex = 1
    while len(keyStream) < length:
        keyBlock = hmac.new(key, msg=keyBlock + appInfo + chr(blockIndex), digestmod=hashlib.sha256).digest()
        blockIndex += 1
        keyStream += keyBlock

    return keyStream[:length]


def AESPad(s):
    bs = AES.block_size
    return s + (bs - len(s) % bs) * chr(bs - len(s) % bs)


def to_bytes(n, length, endianess='big'):
    h = '%x' % n
    s = ('0' * (len(h) % 2) + h).zfill(length * 2).decode('hex')

    return s if endianess == 'big' else s[::-1]


def AESUnpad(s):
    return s[:-ord(s[len(s) - 1:])]


def AESEncrypt(key, plaintext):
    """
    like "AESPad"/"AESUnpad" from https://stackoverflow.com/a/21928790
    """
    plaintext = AESPad(plaintext)
    iv = os.urandom(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    return iv + cipher.encrypt(plaintext)


def AESDecrypt(key, ciphertext):  # from https://stackoverflow.com/a/20868265
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])

    return AESUnpad(plaintext)
