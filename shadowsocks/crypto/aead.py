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

from ctypes import create_string_buffer

import hashlib
from struct import pack, unpack
from abc import ABCMeta, abstractmethod

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
    'chacha20-poly1305': 12,
    'chacha20-ietf-poly1305': 12,
    'xchacha20-ietf-poly1305': 24,
}

CIPHER_TAG_LEN = {
    'aes-128-gcm': 16,
    'aes-192-gcm': 16,
    'aes-256-gcm': 16,
    'chacha20-poly1305': 16,
    'chacha20-ietf-poly1305': 16,
    'xchacha20-ietf-poly1305': 16,
}

SUBKEY_INFO = b"ss-subkey"


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
    __metaclass__ = ABCMeta

    def __init__(self, cipher_name, key, iv, op):
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

    def cipher_ctx_init(self):
        """
        Increase nonce to make it unique for the same key
        :return: void
        """
        nonce_increment(self._nonce, self._nlen)
        # print("".join("%02x" % ord(b) for b in self._nonce))

    @abstractmethod
    def aead_encrypt(self, data):
        """
        Encrypt data with authenticate tag

        :param data: plain text
        :return: cipher text with tag
        """
        return b""

    def encrypt_chunk(self, data):
        """
        Encrypt a chunk for TCP chunks

        :param data: str
        :return: (str, int)
        """
        plen = len(data)
        l = AEAD_CHUNK_SIZE_LEN + plen + self._tlen * 2

        # network byte order
        ctext = self.aead_encrypt(pack("!H", plen & AEAD_CHUNK_SIZE_MASK))
        if len(ctext) != AEAD_CHUNK_SIZE_LEN + self._tlen:
            raise Exception("data length invalid")

        self.cipher_ctx_init()
        ctext += self.aead_encrypt(data)
        if len(ctext) != l:
            raise Exception("data length invalid")

        self.cipher_ctx_init()
        return ctext, l

    def encrypt(self, data):
        """
        Encrypt data, for TCP divided into chunks
        For UDP data, call aead_encrypt instead

        :param data: str data bytes
        :return: str encrypted data
        """
        plen = len(data)
        if plen <= AEAD_CHUNK_SIZE_MASK:
            ctext, _ = self.encrypt_chunk(data)
            return ctext
        ctext, clen = b"", 0
        while plen > 0:
            mlen = plen if plen < AEAD_CHUNK_SIZE_MASK \
                else AEAD_CHUNK_SIZE_MASK
            r, l = self.encrypt_chunk(data[:mlen])
            ctext += r
            clen += l
            data = data[mlen:]
            plen -= mlen

        return ctext

    @abstractmethod
    def aead_decrypt(self, data):
        """
        Decrypt data and authenticate tag

        :param data: str cipher text with tag
        :return: str plain text
        """
        return b""

    def decrypt_chunk_size(self, data):
        """
        Decrypt chunk size

        :param data: str encrypted msg
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
            raise Exception('Invalid message length')

        self.cipher_ctx_init()
        return plen, data[hlen:]

    def decrypt_chunk_payload(self, plen, data):
        """
        Decrypted encrypted msg payload

        :param plen: int payload length
        :param data: str encrypted data
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
            raise Exception("plaintext length invalid")

        self.cipher_ctx_init()

        return plaintext, data[plen + self._tlen:]

    def decrypt_chunk(self, data):
        """
        Decrypt a TCP chunk

        :param data: str encrypted msg
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
        ptext, left = self.decrypt_chunk(data)
        while len(left) > 0:
            pnext, left = self.decrypt_chunk(left)
            ptext += pnext
        return ptext


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
    test_nonce_increment()
