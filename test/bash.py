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
from util import b64_encoder, hex_encoder, hex_decoder, process_result

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

def bash_test():
	# bash256
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash256Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	process_result('bash256', res)

	# bash384
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash384Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	process_result('bash384', res)

	# bash512
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = bash512Hash(bytes(src))
	res = hex_encoder(hash_)[0].decode() != ''
	process_result('bash512', res)
