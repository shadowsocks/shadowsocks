#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Void Copyright NO ONE
#
# Void License
#
# The code belongs to no one. Do whatever you want.
# Forget about boring open source license.
#
# AEAD cipher for shadowsocks
#

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_int, create_string_buffer, byref, c_void_p

import hashlib
from struct import pack, unpack

from shadowsocks.crypto import util
from shadowsocks.crypto import hkdf
from shadowsocks.common import ord, chr


EVP_CTRL_GCM_SET_IVLEN = 0x9
EVP_CTRL_GCM_GET_TAG = 0x10
EVP_CTRL_GCM_SET_TAG = 0x11
EVP_CTRL_CCM_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN
EVP_CTRL_CCM_GET_TAG = EVP_CTRL_GCM_GET_TAG
EVP_CTRL_CCM_SET_TAG = EVP_CTRL_GCM_SET_TAG

EVP_CTRL_AEAD_SET_IVLEN = EVP_CTRL_GCM_SET_IVLEN
EVP_CTRL_AEAD_SET_TAG = EVP_CTRL_GCM_SET_TAG
EVP_CTRL_AEAD_GET_TAG = EVP_CTRL_GCM_GET_TAG

AEAD_MSG_LEN_UNKNOWN = 0
AEAD_CHUNK_SIZE_LEN = 2
AEAD_CHUNK_SIZE_MASK = 0x3FFF

CIPHER_NONCE_LEN = {
    'aes-128-gcm': 12,
    'aes-192-gcm': 12,
    'aes-256-gcm': 12,
    'aes-128-ocb': 12,  # requires openssl 1.1
    'aes-192-ocb': 12,
    'aes-256-ocb': 12,
    'chacha20-poly1305': 12,
    'chacha20-ietf-poly1305': 12,
    'xchacha20-ietf-poly1305': 24,
    'sodium:aes-256-gcm': 12,
}

CIPHER_TAG_LEN = {
    'aes-128-gcm': 16,
    'aes-192-gcm': 16,
    'aes-256-gcm': 16,
    'aes-128-ocb': 16,  # requires openssl 1.1
    'aes-192-ocb': 16,
    'aes-256-ocb': 16,
    'chacha20-poly1305': 16,
    'chacha20-ietf-poly1305': 16,
    'xchacha20-ietf-poly1305': 16,
    'sodium:aes-256-gcm': 16,
}

SUBKEY_INFO = b"ss-subkey"

libsodium = None
sodium_loaded = False


def load_sodium(path=None):
    """
    Load libsodium helpers for nonce increment
    :return: None
    """
    global libsodium, sodium_loaded

    libsodium = util.find_library('sodium', 'sodium_increment',
                                  'libsodium', path)
    if libsodium is None:
        print('load libsodium failed with path %s' % path)
        return

    if libsodium.sodium_init() < 0:
        libsodium = None
        print('sodium init failed')
        return

    libsodium.sodium_increment.restype = c_void_p
    libsodium.sodium_increment.argtypes = (
        c_void_p, c_int
    )

    sodium_loaded = True
    return


def nonce_increment(nonce, nlen):
    """
    Increase nonce by 1 in little endian
    From libsodium sodium_increment():
    for (; i < nlen; i++) {
        c += (uint_fast16_t) n[i];
        n[i] = (unsigned char) c;
        c >>= 8;
    }
    :param nonce: string_buffer nonce
    :param nlen: nonce length
    :return: nonce plus by 1
    """
    c = 1
    i = 0
    # n = create_string_buffer(nlen)
    while i < nlen:
        c += ord(nonce[i])
        nonce[i] = chr(c & 0xFF)
        c >>= 8
        i += 1
    return  # n.raw


class AeadCryptoBase(object):
    """
    Handles basic aead process of shadowsocks protocol

    TCP Chunk (after encryption, *ciphertext*)
    +--------------+---------------+--------------+------------+
    |  *DataLen*   |  DataLen_TAG  |    *Data*    |  Data_TAG  |
    +--------------+---------------+--------------+------------+
    |      2       |     Fixed     |   Variable   |   Fixed    |
    +--------------+---------------+--------------+------------+

    UDP (after encryption, *ciphertext*)
    +--------+-----------+-----------+
    | NONCE  |  *Data*   |  Data_TAG |
    +-------+-----------+-----------+
    | Fixed  | Variable  |   Fixed   |
    +--------+-----------+-----------+
    """

    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        self._op = int(op)
        self._salt = iv
        self._nlen = CIPHER_NONCE_LEN[cipher_name]
        self._nonce = create_string_buffer(self._nlen)
        self._tlen = CIPHER_TAG_LEN[cipher_name]

        crypto_hkdf = hkdf.Hkdf(iv, key, algorithm=hashlib.sha1)
        self._skey = crypto_hkdf.expand(info=SUBKEY_INFO, length=len(key))
        # _chunk['mlen']:
        # -1, waiting data len header
        # n, n > 0, waiting data
        self._chunk = {'mlen': AEAD_MSG_LEN_UNKNOWN, 'data': b''}

        self.encrypt_once = self.aead_encrypt
        self.decrypt_once = self.aead_decrypt

        # load libsodium for nonce increment
        if not sodium_loaded:
            crypto_path = dict(crypto_path) if crypto_path else dict()
            path = crypto_path.get('sodium', None)
            load_sodium(path)

    def nonce_increment(self):
        """
        AEAD ciphers need nonce to be unique per key
        TODO: cache and check unique
        :return: None
        """
        global libsodium, sodium_loaded
        if sodium_loaded:
            libsodium.sodium_increment(byref(self._nonce), c_int(self._nlen))
        else:
            nonce_increment(self._nonce, self._nlen)
        # print("".join("%02x" % ord(b) for b in self._nonce))

    def cipher_ctx_init(self):
        """
        Increase nonce to make it unique for the same key
        :return: None
        """
        self.nonce_increment()

    def aead_encrypt(self, data):
        """
        Encrypt data with authenticate tag

        :param data: plain text
        :return: str [payload][tag] cipher text with tag
        """
        raise Exception("Must implement aead_encrypt method")

    def encrypt_chunk(self, data):
        """
        Encrypt a chunk for TCP chunks

        :param data: str
        :return: str [len][tag][payload][tag]
        """
        plen = len(data)
        # l = AEAD_CHUNK_SIZE_LEN + plen + self._tlen * 2

        # network byte order
        ctext = [self.aead_encrypt(pack("!H", plen & AEAD_CHUNK_SIZE_MASK))]
        if len(ctext[0]) != AEAD_CHUNK_SIZE_LEN + self._tlen:
            self.clean()
            raise Exception("size length invalid")

        ctext.append(self.aead_encrypt(data))
        if len(ctext[1]) != plen + self._tlen:
            self.clean()
            raise Exception("data length invalid")

        return b''.join(ctext)

    def encrypt(self, data):
        """
        Encrypt data, for TCP divided into chunks
        For UDP data, call aead_encrypt instead

        :param data: str data bytes
        :return: str encrypted data
        """
        plen = len(data)
        if plen <= AEAD_CHUNK_SIZE_MASK:
            ctext = self.encrypt_chunk(data)
            return ctext
        ctext = []
        while plen > 0:
            mlen = plen if plen < AEAD_CHUNK_SIZE_MASK \
                else AEAD_CHUNK_SIZE_MASK
            c = self.encrypt_chunk(data[:mlen])
            ctext.append(c)
            data = data[mlen:]
            plen -= mlen

        return b''.join(ctext)

    def aead_decrypt(self, data):
        """
        Decrypt data and authenticate tag

        :param data: str [len][tag][payload][tag] cipher text with tag
        :return: str plain text
        """
        raise Exception("Must implement aead_decrypt method")

    def decrypt_chunk_size(self, data):
        """
        Decrypt chunk size

        :param data: str [size][tag] encrypted chunk payload len
        :return: (int, str) msg length and remaining encrypted data
        """
        if self._chunk['mlen'] > 0:
            return self._chunk['mlen'], data
        data = self._chunk['data'] + data
        self._chunk['data'] = b""

        hlen = AEAD_CHUNK_SIZE_LEN + self._tlen
        if hlen > len(data):
            self._chunk['data'] = data
            return 0, b""
        plen = self.aead_decrypt(data[:hlen])
        plen, = unpack("!H", plen)
        if plen & AEAD_CHUNK_SIZE_MASK != plen or plen <= 0:
            self.clean()
            raise Exception('Invalid message length')

        return plen, data[hlen:]

    def decrypt_chunk_payload(self, plen, data):
        """
        Decrypted encrypted msg payload

        :param plen: int payload length
        :param data: str [payload][tag][[len][tag]....] encrypted data
        :return: (str, str) plain text and remaining encrypted data
        """
        data = self._chunk['data'] + data
        if len(data) < plen + self._tlen:
            self._chunk['mlen'] = plen
            self._chunk['data'] = data
            return b"", b""
        self._chunk['mlen'] = AEAD_MSG_LEN_UNKNOWN
        self._chunk['data'] = b""

        plaintext = self.aead_decrypt(data[:plen + self._tlen])

        if len(plaintext) != plen:
            self.clean()
            raise Exception("plaintext length invalid")

        return plaintext, data[plen + self._tlen:]

    def decrypt_chunk(self, data):
        """
        Decrypt a TCP chunk

        :param data: str [len][tag][payload][tag][[len][tag]...] encrypted msg
        :return: (str, str) decrypted msg and remaining encrypted data
        """
        plen, data = self.decrypt_chunk_size(data)
        if plen <= 0:
            return b"", b""
        return self.decrypt_chunk_payload(plen, data)

    def decrypt(self, data):
        """
        Decrypt data for TCP data divided into chunks
        For UDP data, call aead_decrypt instead

        :param data: str
        :return: str
        """
        ptext = []
        pnext, left = self.decrypt_chunk(data)
        ptext.append(pnext)
        while len(left) > 0:
            pnext, left = self.decrypt_chunk(left)
            ptext.append(pnext)
        return b''.join(ptext)


def test_nonce_increment():
    buf = create_string_buffer(12)
    print("".join("%02x" % ord(b) for b in buf))
    nonce_increment(buf, 12)
    nonce_increment(buf, 12)
    nonce_increment(buf, 12)
    nonce_increment(buf, 12)
    print("".join("%02x" % ord(b) for b in buf))
    for i in range(256):
        nonce_increment(buf, 12)
        print("".join("%02x" % ord(b) for b in buf))


if __name__ == '__main__':
    load_sodium()
    test_nonce_increment()
