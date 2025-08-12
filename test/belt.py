# *****************************************************************************
# \file belt.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.31 (belt) algorithms
# \created 2019.12.09
# \version 2024.06.02
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import os, shutil, tempfile
from openssl import openssl
from util import b64_encoder, hex_encoder, hex_decoder, process_result

def beltBlockEncr(block, key):
	assert len(block) == 16

	plain = b64_encoder(block)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -e -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix)
	return block


def beltBlockDecr(block, key):
	assert len(block) == 16

	plain = b64_encoder(block)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, block, er__ = openssl(cmd, prefix)
	return block

def beltECBEncr(src, key):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'enc -e -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltECBDecr(src, key):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'enc -d -belt-ecb{} -nosalt -nopad -K {}'.format(key_bitlen, key)
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCBCEncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -e -belt-cbc{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCBCDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -d -belt-cbc{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCFBEncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -e -belt-cfb{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCFBDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -d -belt-cfb{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCTREncr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -e -belt-ctr{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltCTRDecr(src, key, iv):
	assert len(src) % 16 == 0

	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	iv = hex_encoder(iv)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('enc -d -belt-ctr{} -nosalt -nopad -K {} -iv {}'
		.format(key_bitlen, key, iv))
	retcode, dest, er__ = openssl(cmd, prefix)
	return dest

def beltMAC(src, key):
	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'dgst -mac belt-mac{} -macopt hexkey:{}'.format(key_bitlen, key)
	retcode, out, er__ = openssl(cmd, prefix)
	mac = out.decode().split(' ')[1][:-1]
	mac = mac.strip()
	return bytes(hex_decoder(mac)[0])

def beltHMAC(src, key):
	plain = b64_encoder(src)[0].decode()
	key = hex_encoder(key)[0].decode()
	key_bitlen = 4 * len(key)

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'dgst -mac belt-hmac -macopt hexkey:{}'.format(key)
	retcode, out, er__ = openssl(cmd, prefix)
	mac = out.decode().split(' ')[1][:-1]
	mac = mac.strip()
	return bytes(hex_decoder(mac)[0])

def beltHash(src):
	plain = b64_encoder(src)[0].decode()

	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'dgst -belt-hash'.format()
	retcode, out, er__ = openssl(cmd, prefix)
	hash_ = out.decode().split(' ')[1][:-1]
	hash_ = hash_.strip()
	return bytes(hex_decoder(hash_)[0])

def belt_test():
	# belt-block: A.1
	block = hex_decoder('b194bac80a08f53b366d008e584a5de4')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	block = beltBlockEncr(bytes(block), bytes(key))
	res = hex_encoder(block)[0].decode() == '69cca1c93557c9e3d66bc3e0fa88fa6e'
	process_result('belt-block', res)

	# belt-block-inv: A.4
	block = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	block = beltBlockDecr(bytes(block), bytes(key))
	res = hex_encoder(block)[0].decode() == '0dc5300600cab840b38448e5e993f421'
	process_result('belt-block-inv', res)

	# belt-ecb: A.9 (|X| = 384)
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltECBEncr(bytes(src), bytes(key))
	res = hex_encoder(dest)[0].decode() == (
		'69cca1c93557c9e3d66bc3e0fa88fa6e'
		'5f23102ef109710775017f73806da9dc'
		'46fb2ed2ce771f26dcb5e5d1569f9ab0')
	process_result('belt-ecb', res)

	# belt-ecb-inv: A.10 (|X| = 384)
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltECBDecr(bytes(src), bytes(key))
	res = hex_encoder(dest)[0].decode() == (
		'0dc5300600cab840b38448e5e993f421'
		'e55a239f2ab5c5d5fdb6e81b40938e2a'
		'54120ca3e6e19c7ad750fc3531daeab7')
	process_result('belt-ecb-inv', res)

	# belt-cbc: A.11 (|X| = 384)
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCBCEncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'10116efae6ad58ee14852e11da1b8a74'
		'5cf2480e8d03f1c19492e53ed3a70f60'
		'657c1ee8c0e0ae5b58388bf8a68e3309')
	process_result('belt-cbc', res)

	# belt-cbc-inv: A.12 (|X| = 384)
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	iv = hex_decoder('7ecda4d01544af8ca58450bf66d2e88a')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltCBCDecr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'730894d6158e17cc1600185a8f411cab'
		'0471ff85c83792398d8924ebd57d03db'
		'95b97a9b7907e4b020960455e46176f8')
	process_result('belt-cbc-inv', res)

	# belt-cfb: A.13 (|X| = 384)
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCFBEncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'c31e490a90efa374626cc99e4b7b8540'
		'a6e48685464a5a06849c9ca769a1b0ae'
		'55c2cc5939303ec832dd2fe16c8e5a1b')
	process_result('belt-cfb', res)

	# belt-cfb-inv: A.14 (|X| = 384)
	src = hex_decoder('e12bdc1ae28257ec703fccf095ee8df1'
					  'c1ab76389fe678caf7c6f860d5bb9c4f'
					  'f33c657b637c306add4ea7799eb23d31')[0]
	iv = hex_decoder('7ecda4d01544af8ca58450bf66d2e88a')[0]
	key = hex_decoder('92bd9b1ce5d141015445fbc95e4d0ef2'
					  '682080aa227d642f2687f93490405511')[0]
	dest = beltCFBDecr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'fa9d107a86f375ee65cd1db881224bd0'
		'16aff814938ed39b3361abb0bf0851b6'
		'52244eb06842dd4c94aa4500774e40bb')
	process_result('belt-cfb-inv', res)

	# belt-ctr: A.16 (|X| = 384)
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	iv = hex_decoder('be32971343fc9a48a02a885f194b09a1')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	dest = beltCTREncr(bytes(src), bytes(key), bytes(iv))
	res = hex_encoder(dest)[0].decode() == (
		'52c9af96ff50f64435fc43def56bd797'
		'd5b5b1ff79fb41257ab9cdf6e63e81f8'
		'f00341473eae409833622de05213773a')
	process_result('belt-ctr', res)

	# belt-mac256: A.17
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a3739cba38303a98bf6')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() == '2dab59771b4b16d0'
	process_result('belt-mac256', res)

	# belt-mac128
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	process_result('belt-mac128', res)

	# belt-mac192
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a37')[0]
	mac = beltMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	process_result('belt-mac192', res)

	# HMAC[belt-hash]
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d'
					  '5be3d61217b96181fe6786ad716b890b')[0]
	key = hex_decoder('e9dee72c8f0c0fa62ddb49f46f739647'
					  '06075316ed247a37')[0]
	mac = beltHMAC(bytes(src), bytes(key))
	res = hex_encoder(mac)[0].decode() != ''
	process_result('belt-hmac', res)

	# belt-hash: A.23
	src = hex_decoder('b194bac80a08f53b366d008e584a5de4'
					  '8504fa9d1bb6c7ac252e72c202fdce0d')[0]
	hash_ = beltHash(bytes(src))
	res = hex_encoder(hash_)[0].decode() == (
		'749e4c3653aece5e48db4761227742eb'
		'6dbe13f4a80f7beff1a9cf8d10ee7786')
	process_result('belt-hash', res)

	# belt-kwp, belt-dwp
	tmpdirname = tempfile.mkdtemp()
	params256 = os.path.join(tmpdirname, 'params256.pem')
	cmd = ('genpkey -genparam -algorithm bign -pkeyopt params:bign-curve256v1'
		' -pkeyopt enc_params:specified -pkeyopt enc_params:cofactor -out')
	openssl('{} {}'.format(cmd, params256))

	# belt-kwp128
	kwp128 = os.path.join(tmpdirname, 'kwp128.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp128 -pass pass:root -out {}'
			.format(params256, kwp128))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp128))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-kwp128', res)

	# belt-kwp192
	kwp192 = os.path.join(tmpdirname, 'kwp192.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp192 -pass pass:root -out {}'
			.format(params256, kwp192))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp192))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-kwp192', res)

	# belt-kwp256
	kwp256 = os.path.join(tmpdirname, 'kwp256.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-kwp256 -pass pass:root -out {}'
			.format(params256, kwp256))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(kwp256))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-kwp256', res)

	# belt-dwp128
	dwp128 = os.path.join(tmpdirname, 'dwp128.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp128 -pass pass:root -out {}'
			.format(params256, dwp128))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp128))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-dwp128', res)

	# belt-dwp192
	dwp192 = os.path.join(tmpdirname, 'dwp192.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp192 -pass pass:root -out {}'
			.format(params256, dwp192))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp192))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-dwp192', res)

	# belt-dwp256
	dwp256 = os.path.join(tmpdirname, 'dwp256.pem')
	retcode, out, er__ = openssl(
		'genpkey -paramfile {} -belt-dwp256 -pass pass:root -out {}'
			.format(params256, dwp256))
	retcode, out, er__ = openssl('pkey -in {} -check -passin pass:root'
		.format(dwp256))
	out = out.decode()
	res = (out.find('valid') != -1)
	process_result('belt-dwp256', res)

	shutil.rmtree(tmpdirname)
