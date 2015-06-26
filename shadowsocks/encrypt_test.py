from __future__ import absolute_import, division, print_function, \
    with_statement

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../'))


from crypto import rc4_md5
from crypto import openssl
from crypto import sodium
from crypto import table

def main():
	print("\n""rc4_md5")
	rc4_md5.test()
	print("\n""aes-256-cfb")
	openssl.test_aes_256_cfb()
	print("\n""aes-128-cfb")
	openssl.test_aes_128_cfb()
	print("\n""rc4")
	openssl.test_rc4()
	print("\n""salsa20")
	sodium.test_salsa20()
	print("\n""chacha20")
	sodium.test_chacha20()
	print("\n""table")
	table.test_encryption()

if __name__ == '__main__':
	main()

