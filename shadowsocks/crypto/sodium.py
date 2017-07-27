#!/usr/bin/env python
#
# Copyright 2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_uint, c_ulonglong, byref, \
    create_string_buffer, c_void_p

from shadowsocks.crypto import util
from shadowsocks.crypto import aead
from shadowsocks.crypto.aead import AeadCryptoBase

__all__ = ['ciphers']

libsodium = None
loaded = False

buf = None
buf_size = 2048

# for salsa20 and chacha20 and chacha20-ietf
BLOCK_SIZE = 64


def load_libsodium(crypto_path=None):
    global loaded, libsodium, buf

    crypto_path = dict(crypto_path) if crypto_path else dict()
    path = crypto_path.get('sodium', None)

    if not aead.sodium_loaded:
        aead.load_sodium(path)

    if aead.sodium_loaded:
        libsodium = aead.libsodium
    else:
        print('load libsodium again with path %s' % path)
        libsodium = util.find_library('sodium', 'crypto_stream_salsa20_xor_ic',
                                      'libsodium', path)
        if libsodium is None:
            raise Exception('libsodium not found')

        if libsodium.sodium_init() < 0:
            raise Exception('libsodium init failed')

    libsodium.crypto_stream_salsa20_xor_ic.restype = c_int
    libsodium.crypto_stream_salsa20_xor_ic.argtypes = (
        c_void_p, c_char_p,  # cipher output, msg
        c_ulonglong,  # msg len
        c_char_p, c_ulonglong,  # nonce, uint64_t initial block counter
        c_char_p  # key
    )
    libsodium.crypto_stream_chacha20_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_xor_ic.argtypes = (
        c_void_p, c_char_p,
        c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p
    )
    if hasattr(libsodium, 'crypto_stream_xchacha20_xor_ic'):
        libsodium.crypto_stream_xchacha20_xor_ic.restype = c_int
        libsodium.crypto_stream_xchacha20_xor_ic.argtypes = (
            c_void_p, c_char_p,
            c_ulonglong,
            c_char_p, c_ulonglong,
            c_char_p
        )
    libsodium.crypto_stream_chacha20_ietf_xor_ic.restype = c_int
    libsodium.crypto_stream_chacha20_ietf_xor_ic.argtypes = (
        c_void_p, c_char_p,
        c_ulonglong,
        c_char_p,
        c_uint,  # uint32_t initial counter
        c_char_p
    )

    # chacha20-poly1305
    libsodium.crypto_aead_chacha20poly1305_encrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_encrypt.argtypes = (
        c_void_p, c_void_p,  # c, clen
        c_char_p, c_ulonglong,  # m, mlen
        c_char_p, c_ulonglong,  # ad, adlen
        c_char_p,  # nsec, not used
        c_char_p, c_char_p  # npub, k
    )
    libsodium.crypto_aead_chacha20poly1305_decrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_decrypt.argtypes = (
        c_void_p, c_void_p,  # m, mlen
        c_char_p,  # nsec, not used
        c_char_p, c_ulonglong,  # c, clen
        c_char_p, c_ulonglong,  # ad, adlen
        c_char_p, c_char_p  # npub, k
    )

    # chacha20-ietf-poly1305, same api structure as above
    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_encrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p,
        c_char_p, c_char_p
    )
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.restype = c_int
    libsodium.crypto_aead_chacha20poly1305_ietf_decrypt.argtypes = (
        c_void_p, c_void_p,
        c_char_p,
        c_char_p, c_ulonglong,
        c_char_p, c_ulonglong,
        c_char_p, c_char_p
    )

    # xchacha20-ietf-poly1305, same api structure as above
    if hasattr(libsodium, 'crypto_aead_xchacha20poly1305_ietf_encrypt'):
        libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt.restype = c_int
        libsodium.crypto_aead_xchacha20poly1305_ietf_encrypt.argtypes = (
            c_void_p, c_void_p,
            c_char_p, c_ulonglong,
            c_char_p, c_ulonglong,
            c_char_p,
            c_char_p, c_char_p
        )

        libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt.restype = c_int
        libsodium.crypto_aead_xchacha20poly1305_ietf_decrypt.argtypes = (
            c_void_p, c_void_p,
            c_char_p,
            c_char_p, c_ulonglong,
            c_char_p, c_ulonglong,
            c_char_p, c_char_p
        )

    # aes-256-gcm, same api structure as above
    libsodium.crypto_aead_aes256gcm_is_available.restype = c_int

    if libsodium.crypto_aead_aes256gcm_is_available():
        libsodium.crypto_aead_aes256gcm_encrypt.restype = c_int
        libsodium.crypto_aead_aes256gcm_encrypt.argtypes = (
            c_void_p, c_void_p,
            c_char_p, c_ulonglong,
            c_char_p, c_ulonglong,
            c_char_p,
            c_char_p, c_char_p
        )
        libsodium.crypto_aead_aes256gcm_decrypt.restype = c_int
        libsodium.crypto_aead_aes256gcm_decrypt.argtypes = (
            c_void_p, c_void_p,
            c_char_p,
            c_char_p, c_ulonglong,
            c_char_p, c_ulonglong,
            c_char_p, c_char_p
        )

    buf = create_string_buffer(buf_size)
    loaded = True


class SodiumCrypto(object):
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if not loaded:
            load_libsodium(crypto_path)
        self.key = key
        self.iv = iv
        self.key_ptr = c_char_p(key)
        self.iv_ptr = c_char_p(iv)
        if cipher_name == 'salsa20':
            self.cipher = libsodium.crypto_stream_salsa20_xor_ic
        elif cipher_name == 'chacha20':
            self.cipher = libsodium.crypto_stream_chacha20_xor_ic
        elif cipher_name == 'xchacha20':
            if hasattr(libsodium, 'crypto_stream_xchacha20_xor_ic'):
                self.cipher = libsodium.crypto_stream_xchacha20_xor_ic
            else:
                raise Exception('Unsupported cipher')
        elif cipher_name == 'chacha20-ietf':
            self.cipher = libsodium.crypto_stream_chacha20_ietf_xor_ic
        else:
            raise Exception('Unknown cipher')
        # byte counter, not block counter
        self.counter = 0
        self.encrypt = self.update
        self.decrypt = self.update
        self.encrypt_once = self.update
        self.decrypt_once = self.update

    def update(self, data):
        global buf_size, buf
        l = len(data)

        # we can only prepend some padding to make the encryption align to
        # blocks
        padding = self.counter % BLOCK_SIZE
        if buf_size < padding + l:
            buf_size = (padding + l) * 2
            buf = create_string_buffer(buf_size)

        if padding:
            data = (b'\0' * padding) + data
        self.cipher(byref(buf), c_char_p(data), padding + l,
                    self.iv_ptr, int(self.counter / BLOCK_SIZE), self.key_ptr)
        self.counter += l
        # buf is copied to a str object when we access buf.raw
        # strip off the padding
        return buf.raw[padding:padding + l]

    def clean(self):
        pass


class SodiumAeadCrypto(AeadCryptoBase):
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if not loaded:
            load_libsodium(crypto_path)
        AeadCryptoBase.__init__(self, cipher_name, key, iv, op, crypto_path)

        if cipher_name == 'chacha20-poly1305':
            self.encryptor = libsodium.crypto_aead_chacha20poly1305_encrypt
            self.decryptor = libsodium.crypto_aead_chacha20poly1305_decrypt
        elif cipher_name == 'chacha20-ietf-poly1305':
            self.encryptor = libsodium. \
                crypto_aead_chacha20poly1305_ietf_encrypt
            self.decryptor = libsodium. \
                crypto_aead_chacha20poly1305_ietf_decrypt
        elif cipher_name == 'xchacha20-ietf-poly1305':
            if hasattr(libsodium,
                       'crypto_aead_xchacha20poly1305_ietf_encrypt'):
                self.encryptor = libsodium. \
                    crypto_aead_xchacha20poly1305_ietf_encrypt
                self.decryptor = libsodium. \
                    crypto_aead_xchacha20poly1305_ietf_decrypt
            else:
                raise Exception('Unsupported cipher')
        elif cipher_name == 'sodium:aes-256-gcm':
            if hasattr(libsodium, 'crypto_aead_aes256gcm_encrypt'):
                self.encryptor = libsodium.crypto_aead_aes256gcm_encrypt
                self.decryptor = libsodium.crypto_aead_aes256gcm_decrypt
            else:
                raise Exception('Unsupported cipher')
        else:
            raise Exception('Unknown cipher')

    def cipher_ctx_init(self):
        global libsodium
        libsodium.sodium_increment(byref(self._nonce), c_int(self._nlen))
        # print("".join("%02x" % ord(b) for b in self._nonce))

    def aead_encrypt(self, data):
        global buf, buf_size
        plen = len(data)
        if buf_size < plen + self._tlen:
            buf_size = (plen + self._tlen) * 2
            buf = create_string_buffer(buf_size)
        cipher_out_len = c_ulonglong(0)
        self.encryptor(
            byref(buf), byref(cipher_out_len),
            c_char_p(data), c_ulonglong(plen),
            None, c_ulonglong(0), None,
            c_char_p(self._nonce.raw), c_char_p(self._skey)
        )
        if cipher_out_len.value != plen + self._tlen:
            raise Exception("Encrypt failed")

        self.cipher_ctx_init()
        return buf.raw[:cipher_out_len.value]

    def aead_decrypt(self, data):
        global buf, buf_size
        clen = len(data)
        if buf_size < clen:
            buf_size = clen * 2
            buf = create_string_buffer(buf_size)
        cipher_out_len = c_ulonglong(0)
        r = self.decryptor(
            byref(buf), byref(cipher_out_len),
            None,
            c_char_p(data), c_ulonglong(clen),
            None, c_ulonglong(0),
            c_char_p(self._nonce.raw), c_char_p(self._skey)
        )
        if r != 0:
            raise Exception("Decrypt failed")

        if cipher_out_len.value != clen - self._tlen:
            raise Exception("Decrypt failed")

        self.cipher_ctx_init()
        return buf.raw[:cipher_out_len.value]


ciphers = {
    'salsa20': (32, 8, SodiumCrypto),
    'chacha20': (32, 8, SodiumCrypto),
    'xchacha20': (32, 24, SodiumCrypto),
    'chacha20-ietf': (32, 12, SodiumCrypto),
    # AEAD: iv_len = salt_len = key_len
    'chacha20-poly1305': (32, 32, SodiumAeadCrypto),
    'chacha20-ietf-poly1305': (32, 32, SodiumAeadCrypto),
    'xchacha20-ietf-poly1305': (32, 32, SodiumAeadCrypto),
    'sodium:aes-256-gcm': (32, 32, SodiumAeadCrypto),
}


def test_chacha20():
    print("Test chacha20")
    cipher = SodiumCrypto('chacha20', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('chacha20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_xchacha20():
    print("Test xchacha20")
    cipher = SodiumCrypto('xchacha20', b'k' * 32, b'i' * 24, 1)
    decipher = SodiumCrypto('xchacha20', b'k' * 32, b'i' * 24, 0)

    util.run_cipher(cipher, decipher)


def test_salsa20():
    print("Test salsa20")
    cipher = SodiumCrypto('salsa20', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('salsa20', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20_ietf():
    print("Test chacha20-ietf")
    cipher = SodiumCrypto('chacha20-ietf', b'k' * 32, b'i' * 16, 1)
    decipher = SodiumCrypto('chacha20-ietf', b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20_poly1305():
    print("Test chacha20-poly1305 [payload][tag]")
    cipher = SodiumAeadCrypto('chacha20-poly1305',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('chacha20-poly1305',
                                b'k' * 32, b'i' * 32, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20_poly1305_chunk():
    print("Test chacha20-poly1305 chunk [size][tag][payload][tag]")
    cipher = SodiumAeadCrypto('chacha20-poly1305',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('chacha20-poly1305',
                                b'k' * 32, b'i' * 32, 0)

    cipher.encrypt_once = cipher.encrypt
    decipher.decrypt_once = decipher.decrypt

    util.run_cipher(cipher, decipher)


def test_chacha20_ietf_poly1305():
    print("Test chacha20-ietf-poly1305 [payload][tag]")
    cipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                b'k' * 32, b'i' * 32, 0)

    util.run_cipher(cipher, decipher)


def test_chacha20_ietf_poly1305_chunk():
    print("Test chacha20-ietf-poly1305 chunk [size][tag][payload][tag]")
    cipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('chacha20-ietf-poly1305',
                                b'k' * 32, b'i' * 32, 0)

    cipher.encrypt_once = cipher.encrypt
    decipher.decrypt_once = decipher.decrypt

    util.run_cipher(cipher, decipher)


def test_aes_256_gcm():
    print("Test sodium:aes-256-gcm [payload][tag]")
    cipher = SodiumAeadCrypto('sodium:aes-256-gcm',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('sodium:aes-256-gcm',
                                b'k' * 32, b'i' * 32, 0)

    util.run_cipher(cipher, decipher)


def test_aes_256_gcm_chunk():
    print("Test sodium:aes-256-gcm chunk [size][tag][payload][tag]")
    cipher = SodiumAeadCrypto('sodium:aes-256-gcm',
                              b'k' * 32, b'i' * 32, 1)
    decipher = SodiumAeadCrypto('sodium:aes-256-gcm',
                                b'k' * 32, b'i' * 32, 0)

    cipher.encrypt_once = cipher.encrypt
    decipher.decrypt_once = decipher.decrypt

    util.run_cipher(cipher, decipher)


if __name__ == '__main__':
    test_chacha20()
    test_xchacha20()
    test_salsa20()
    test_chacha20_ietf()
    test_chacha20_poly1305()
    test_chacha20_poly1305_chunk()
    test_chacha20_ietf_poly1305()
    test_chacha20_ietf_poly1305_chunk()
    test_aes_256_gcm()
    test_aes_256_gcm_chunk()
