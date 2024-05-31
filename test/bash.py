# *****************************************************************************
# \file bash.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.77 (bash) algorithms
# \created 2019.12.09
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

from openssl import openssl
from settings import hex_encoder, b64_encoder, hex_decoder, b64_decoder

def bash256Hash(src):
	plain = b64_encoder(src)[0].decode()

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -bash256'.format()
	retcode, out, er__ = openssl(cmd, prefix)
	hash_ = out.decode().split(' ')[1][:-1]
	hash_ = hash_.strip()
	return bytes(hex_decoder(hash_)[0])

def bash384Hash(src):
	plain = b64_encoder(src)[0].decode()

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -bash384'.format()
	retcode, out, er__ = openssl(cmd, prefix)
	hash_ = out.decode().split(' ')[1][:-1]
	hash_ = hash_.strip()
	return bytes(hex_decoder(hash_)[0])

def bash512Hash(src):
	plain = b64_encoder(src)[0].decode()

	prefix = 'echo ' + plain[:-1] + ' | python -m base64 -d |'
	cmd = 'dgst -bash512'.format()
	retcode, out, er__ = openssl(cmd, prefix)
	hash_ = out.decode().split(' ')[1][:-1]
	hash_ = hash_.strip()
	return bytes(hex_decoder(hash_)[0])
