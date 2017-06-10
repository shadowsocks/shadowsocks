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
# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4


from __future__ import absolute_import, division, print_function, \
    with_statement

from ctypes import c_char_p, c_int, c_size_t, byref,\
    create_string_buffer, c_void_p

from shadowsocks import common
from shadowsocks.crypto import util
from shadowsocks.crypto.aead import AeadCryptoBase

__all__ = ['ciphers']

libmbedtls = None
loaded = False

buf = None
buf_size = 2048

CIPHER_ENC_UNCHANGED = -1

# define MAX_KEY_LENGTH 64
# define MAX_NONCE_LENGTH 32
# typedef struct {
#     uint32_t init;
#     uint64_t counter;
#     cipher_evp_t *evp;
#     cipher_t *cipher;
#     buffer_t *chunk;
#     uint8_t salt[MAX_KEY_LENGTH];
#     uint8_t skey[MAX_KEY_LENGTH];
#     uint8_t nonce[MAX_NONCE_LENGTH];
# } cipher_ctx_t;
#
# sizeof(cipher_ctx_t) = 196

CIPHER_CTX_SIZE = 256


def load_mbedtls(crypto_path=None):
    global loaded, libmbedtls, buf

    crypto_path = dict(crypto_path) if crypto_path else dict()
    path = crypto_path.get('mbedtls', None)
    libmbedtls = util.find_library('mbedcrypto',
                                   'mbedtls_cipher_init',
                                   'libmbedcrypto', path)
    if libmbedtls is None:
        raise Exception('libmbedcrypto(mbedtls) not found with path %s'
                        % path)

    libmbedtls.mbedtls_cipher_init.restype = None
    libmbedtls.mbedtls_cipher_free.restype = None

    libmbedtls.mbedtls_cipher_info_from_string.restype = c_void_p
    libmbedtls.mbedtls_cipher_info_from_string.argtypes = (c_char_p,)

    libmbedtls.mbedtls_cipher_setup.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_setup.argtypes = (c_void_p, c_void_p)

    libmbedtls.mbedtls_cipher_setkey.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_setkey.argtypes = (
        c_void_p,  # ctx
        c_char_p,  # key
        c_int,     # key_bitlen, not bytes
        c_int      # op: 1 enc, 0 dec, -1 none
    )

    libmbedtls.mbedtls_cipher_set_iv.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_set_iv.argtypes = (
        c_void_p,  # ctx
        c_char_p,  # iv
        c_size_t   # iv_len
    )

    libmbedtls.mbedtls_cipher_reset.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_reset.argtypes = (c_void_p,)  # ctx

    if hasattr(libmbedtls, 'mbedtls_cipher_update_ad'):
        libmbedtls.mbedtls_cipher_update_ad.restype = c_int  # 0 on success
        libmbedtls.mbedtls_cipher_update_ad.argtypes = (
            c_void_p,  # ctx
            c_char_p,  # ad
            c_size_t   # ad_len
        )

    libmbedtls.mbedtls_cipher_update.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_update.argtypes = (
        c_void_p,  # ctx
        c_char_p,  # input
        c_size_t,  # ilen, must be multiple of block size except last one
        c_void_p,  # *output
        c_void_p   # *olen
    )

    libmbedtls.mbedtls_cipher_finish.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_finish.argtypes = (
        c_void_p,  # ctx
        c_void_p,  # *output
        c_void_p   # *olen
    )

    if hasattr(libmbedtls, 'mbedtls_cipher_write_tag'):
        libmbedtls.mbedtls_cipher_write_tag.restype = c_int  # 0 on success
        libmbedtls.mbedtls_cipher_write_tag.argtypes = (
            c_void_p,  # ctx
            c_void_p,  # *tag
            c_size_t   # tag_len
        )
        libmbedtls.mbedtls_cipher_check_tag.restype = c_int  # 0 on success
        libmbedtls.mbedtls_cipher_check_tag.argtypes = (
            c_void_p,  # ctx
            c_char_p,  # tag
            c_size_t   # tag_len
        )

    libmbedtls.mbedtls_cipher_crypt.restype = c_int  # 0 on success
    libmbedtls.mbedtls_cipher_crypt.argtypes = (
        c_void_p,  # ctx
        c_char_p,  # iv
        c_size_t,  # iv_len, = 0 if iv = NULL
        c_char_p,  # input
        c_size_t,  # ilen
        c_void_p,  # *output, no less than ilen + block_size
        c_void_p   # *olen
    )

    if hasattr(libmbedtls, 'mbedtls_cipher_auth_encrypt'):
        libmbedtls.mbedtls_cipher_auth_encrypt.restype = c_int  # 0 on success
        libmbedtls.mbedtls_cipher_auth_encrypt.argtypes = (
            c_void_p,  # ctx
            c_char_p,  # iv
            c_size_t,  # iv_len
            c_char_p,  # ad
            c_size_t,  # ad_len
            c_char_p,  # input
            c_size_t,  # ilen
            c_void_p,  # *output, no less than ilen + block_size
            c_void_p,  # *olen
            c_void_p,  # *tag
            c_size_t   # tag_len
        )
        libmbedtls.mbedtls_cipher_auth_decrypt.restype = c_int  # 0 on success
        libmbedtls.mbedtls_cipher_auth_decrypt.argtypes = (
            c_void_p,  # ctx
            c_char_p,  # iv
            c_size_t,  # iv_len
            c_char_p,  # ad
            c_size_t,  # ad_len
            c_char_p,  # input
            c_size_t,  # ilen
            c_void_p,  # *output, no less than ilen + block_size
            c_void_p,  # *olen
            c_char_p,  # tag
            c_size_t,  # tag_len
        )

    buf = create_string_buffer(buf_size)
    loaded = True


class MbedTLSCryptoBase(object):
    """
    MbedTLS crypto base class
    """
    def __init__(self, cipher_name, crypto_path=None):
        global loaded
        self._ctx = create_string_buffer(b'\0' * CIPHER_CTX_SIZE)
        self._cipher = None
        if not loaded:
            load_mbedtls(crypto_path)
        cipher_name = common.to_bytes(cipher_name.upper())
        cipher = libmbedtls.mbedtls_cipher_info_from_string(cipher_name)
        if not cipher:
            raise Exception('cipher %s not found in libmbedtls' % cipher_name)
        libmbedtls.mbedtls_cipher_init(byref(self._ctx))
        if libmbedtls.mbedtls_cipher_setup(byref(self._ctx), cipher):
            raise Exception('can not setup cipher')
        self._cipher = cipher

        self.encrypt_once = self.update
        self.decrypt_once = self.update

    def update(self, data):
        """
        Encrypt/decrypt data
        :param data: str
        :return: str
        """
        global buf_size, buf
        cipher_out_len = c_size_t(0)
        l = len(data)
        if buf_size < l:
            buf_size = l * 2
            buf = create_string_buffer(buf_size)
        libmbedtls.mbedtls_cipher_update(
            byref(self._ctx),
            c_char_p(data), c_size_t(l),
            byref(buf), byref(cipher_out_len)
        )
        # buf is copied to a str object when we access buf.raw
        return buf.raw[:cipher_out_len.value]

    def __del__(self):
        self.clean()

    def clean(self):
        if self._ctx:
            libmbedtls.mbedtls_cipher_free(byref(self._ctx))


class MbedTLSAeadCrypto(MbedTLSCryptoBase, AeadCryptoBase):
    """
    Implement mbedtls Aead mode: gcm
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if cipher_name[:len('mbedtls:')] == 'mbedtls:':
            cipher_name = cipher_name[len('mbedtls:'):]
        MbedTLSCryptoBase.__init__(self, cipher_name, crypto_path)
        AeadCryptoBase.__init__(self, cipher_name, key, iv, op, crypto_path)

        key_ptr = c_char_p(self._skey)
        r = libmbedtls.mbedtls_cipher_setkey(
            byref(self._ctx),
            key_ptr, c_int(len(key) * 8),
            c_int(op)
        )
        if r:
            self.clean()
            raise Exception('can not initialize cipher context')

        r = libmbedtls.mbedtls_cipher_reset(byref(self._ctx))
        if r:
            self.clean()
            raise Exception('can not finish preparation of mbed TLS '
                            'cipher context')

    def cipher_ctx_init(self):
        """
        Nonce + 1
        :return: None
        """
        AeadCryptoBase.nonce_increment(self)

    def set_tag(self, tag):
        """
        Set tag before decrypt any data (update)
        :param tag: authenticated tag
        :return: None
        """
        tag_len = self._tlen
        r = libmbedtls.mbedtls_cipher_check_tag(
            byref(self._ctx),
            c_char_p(tag), c_size_t(tag_len)
        )
        if not r:
            raise Exception('Set tag failed')

    def get_tag(self):
        """
        Get authenticated tag, called after EVP_CipherFinal_ex
        :return: str
        """
        tag_len = self._tlen
        tag_buf = create_string_buffer(tag_len)
        r = libmbedtls.mbedtls_cipher_write_tag(
            byref(self._ctx),
            byref(tag_buf), c_size_t(tag_len)
        )
        if not r:
            raise Exception('Get tag failed')
        return tag_buf.raw[:tag_len]

    def final(self):
        """
        Finish encrypt/decrypt a chunk (<= 0x3FFF)
        :return: str
        """
        global buf_size, buf
        cipher_out_len = c_size_t(0)
        r = libmbedtls.mbedtls_cipher_finish(
            byref(self._ctx),
            byref(buf), byref(cipher_out_len)
        )
        if not r:
            # print(self._nonce.raw, r, cipher_out_len)
            raise Exception('Finalize cipher failed')
        return buf.raw[:cipher_out_len.value]

    def aead_encrypt(self, data):
        """
        Encrypt data with authenticate tag

        :param data: plain text
        :return: cipher text with tag
        """
        global buf_size, buf
        plen = len(data)
        if buf_size < plen + self._tlen:
            buf_size = (plen + self._tlen) * 2
            buf = create_string_buffer(buf_size)
        cipher_out_len = c_size_t(0)
        tag_buf = create_string_buffer(self._tlen)

        r = libmbedtls.mbedtls_cipher_auth_encrypt(
            byref(self._ctx),
            c_char_p(self._nonce.raw), c_size_t(self._nlen),
            None, c_size_t(0),
            c_char_p(data), c_size_t(plen),
            byref(buf), byref(cipher_out_len),
            byref(tag_buf), c_size_t(self._tlen)
        )
        assert cipher_out_len.value == plen
        if r:
            raise Exception('AEAD encrypt failed {0:#x}'.format(r))
        self.cipher_ctx_init()
        return buf.raw[:cipher_out_len.value] + tag_buf.raw[:self._tlen]

    def aead_decrypt(self, data):
        """
        Decrypt data and authenticate tag

        :param data: cipher text with tag
        :return: plain text
        """
        global buf_size, buf
        cipher_out_len = c_size_t(0)
        plen = len(data) - self._tlen
        if buf_size < plen:
            buf_size = plen * 2
            buf = create_string_buffer(buf_size)
        tag = data[plen:]
        r = libmbedtls.mbedtls_cipher_auth_decrypt(
            byref(self._ctx),
            c_char_p(self._nonce.raw), c_size_t(self._nlen),
            None, c_size_t(0),
            c_char_p(data), c_size_t(plen),
            byref(buf), byref(cipher_out_len),
            c_char_p(tag), c_size_t(self._tlen)
        )
        if r:
            raise Exception('AEAD encrypt failed {0:#x}'.format(r))
        self.cipher_ctx_init()
        return buf.raw[:cipher_out_len.value]


class MbedTLSStreamCrypto(MbedTLSCryptoBase):
    """
    Crypto for stream modes: cfb, ofb, ctr
    """
    def __init__(self, cipher_name, key, iv, op, crypto_path=None):
        if cipher_name[:len('mbedtls:')] == 'mbedtls:':
            cipher_name = cipher_name[len('mbedtls:'):]
        MbedTLSCryptoBase.__init__(self, cipher_name, crypto_path)
        key_ptr = c_char_p(key)
        iv_ptr = c_char_p(iv)
        r = libmbedtls.mbedtls_cipher_setkey(
            byref(self._ctx),
            key_ptr, c_int(len(key) * 8),
            c_int(op)
        )
        if r:
            self.clean()
            raise Exception('can not set cipher key')
        r = libmbedtls.mbedtls_cipher_set_iv(
            byref(self._ctx),
            iv_ptr, c_size_t(len(iv))
        )
        if r:
            self.clean()
            raise Exception('can not set cipher iv')
        r = libmbedtls.mbedtls_cipher_reset(byref(self._ctx))
        if r:
            self.clean()
            raise Exception('can not reset cipher')

        self.encrypt = self.update
        self.decrypt = self.update


ciphers = {
    'mbedtls:aes-128-cfb128': (16, 16, MbedTLSStreamCrypto),
    'mbedtls:aes-192-cfb128': (24, 16, MbedTLSStreamCrypto),
    'mbedtls:aes-256-cfb128': (32, 16, MbedTLSStreamCrypto),
    'mbedtls:aes-128-ctr': (16, 16, MbedTLSStreamCrypto),
    'mbedtls:aes-192-ctr': (24, 16, MbedTLSStreamCrypto),
    'mbedtls:aes-256-ctr': (32, 16, MbedTLSStreamCrypto),
    'mbedtls:camellia-128-cfb128': (16, 16, MbedTLSStreamCrypto),
    'mbedtls:camellia-192-cfb128': (24, 16, MbedTLSStreamCrypto),
    'mbedtls:camellia-256-cfb128': (32, 16, MbedTLSStreamCrypto),
    # AEAD: iv_len = salt_len = key_len
    'mbedtls:aes-128-gcm': (16, 16, MbedTLSAeadCrypto),
    'mbedtls:aes-192-gcm': (24, 24, MbedTLSAeadCrypto),
    'mbedtls:aes-256-gcm': (32, 32, MbedTLSAeadCrypto),
}


def run_method(method):
    from shadowsocks.crypto import openssl

    print(method, ': [stream]', 32)
    cipher = MbedTLSStreamCrypto(method, b'k' * 32, b'i' * 16, 1)
    decipher = openssl.OpenSSLStreamCrypto(method, b'k' * 32, b'i' * 16, 0)

    util.run_cipher(cipher, decipher)


def run_aead_method(method, key_len=16):
    from shadowsocks.crypto import openssl

    print(method, ': [payload][tag]', key_len)
    key_len = int(key_len)
    cipher = MbedTLSAeadCrypto(method, b'k' * key_len, b'i' * key_len, 1)
    decipher = openssl.OpenSSLAeadCrypto(
        method,
        b'k' * key_len, b'i' * key_len, 0
    )

    util.run_cipher(cipher, decipher)


def run_aead_method_chunk(method, key_len=16):
    from shadowsocks.crypto import openssl

    print(method, ': chunk([size][tag][payload][tag]', key_len)
    key_len = int(key_len)
    cipher = MbedTLSAeadCrypto(method, b'k' * key_len, b'i' * key_len, 1)
    decipher = openssl.OpenSSLAeadCrypto(
        method,
        b'k' * key_len, b'i' * key_len, 0
    )

    cipher.encrypt_once = cipher.encrypt
    decipher.decrypt_once = decipher.decrypt
    util.run_cipher(cipher, decipher)


def test_camellia_256_cfb():
    run_method('camellia-256-cfb128')


def test_aes_gcm(bits=128):
    method = "aes-{0}-gcm".format(bits)
    run_aead_method(method, bits / 8)


def test_aes_gcm_chunk(bits=128):
    method = "aes-{0}-gcm".format(bits)
    run_aead_method_chunk(method, bits / 8)


def test_aes_256_cfb():
    run_method('aes-256-cfb128')


def test_aes_256_ctr():
    run_method('aes-256-ctr')


if __name__ == '__main__':
    test_aes_256_cfb()
    test_camellia_256_cfb()
    test_aes_256_ctr()
    test_aes_gcm(128)
    test_aes_gcm(192)
    test_aes_gcm(256)
    test_aes_gcm_chunk(128)
    test_aes_gcm_chunk(192)
    test_aes_gcm_chunk(256)
