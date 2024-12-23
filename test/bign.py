# *****************************************************************************
# \file bign.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.45 (bign) algorithms
# \created 2019.12.09
# \version 2024.06.03
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import os, re, shutil, tempfile
from openssl import openssl
from util import b64_encoder, hex_decoder, process_result

def bignParamsStd(name, out_filename, specified=False, cofactor=False):
	options = '-pkeyopt params:{}'.format(name)
	if specified:
		options += ' -pkeyopt enc_params:specified'

	if cofactor:
		options += ' -pkeyopt enc_params:cofactor'

	cmd = ('genpkey -engine bee2evp -genparam -algorithm bign {} -out {}'
		.format(options, out_filename))
	retcode, out, er__ = openssl(cmd)
	return out

def bignKeypairGen(params_file, out_filename):
	cmd = 'genpkey -engine bee2evp -paramfile {} -out {}'.format(params_file, out_filename)
	retcode, out, er__ = openssl(cmd)
	return out

def bignPubkeyCalc(private_key_file, out_filename):
	cmd = 'pkey -engine bee2evp -in {} -pubout -out {}'.format(private_key_file, out_filename)
	retcode, public_key, er__ = openssl(cmd)
	return public_key

def bignSign(prkey, hashname, src , dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = 'dgst -engine bee2evp -{} -sign {} -out {}'.format(hashname, prkey, dest)
	retcode, out, er__ = openssl(cmd, prefix=prefix)
	return retcode

def bignSign2(prkey, hashname, src, dest):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('dgst -engine bee2evp -{} -sign {} -sigopt sig:deterministic -out {}'
		.format(hashname, prkey, dest))
	retcode, out, er__ = openssl(cmd, prefix=prefix)
	return retcode

def bignVerify(prkey, hashname, src, sign_file):
	plain = b64_encoder(src)[0].decode()
	prefix = 'echo ' + plain[:-1] + ' | python3 -m base64 -d |'
	cmd = ('dgst -engine bee2evp -{} -prverify {} -hex -signature {}'
		.format(hashname, prkey, sign_file))
	retcode, out, er__ = openssl(cmd, prefix=prefix)
	return out.decode()[:-1].strip()

def bign_test():
	tmpdirname = tempfile.mkdtemp()
	# bign-genparams: bign-curve256v1
	params256 = os.path.join(tmpdirname, 'params256v1.pem')
	bignParamsStd('bign-curve256v1', params256)
	out = openssl('asn1parse -in {}'.format(params256))
	res = (out[1].decode().find('bign-curve256v1') != -1)
	process_result('bign-genec[bign-curve256v1]', res)

	# bign-genparams: bign-curve384v1
	params384 = os.path.join(tmpdirname, 'params384v1.pem')
	bignParamsStd('bign-curve384v1', params384)
	out = openssl('asn1parse -in {}'.format(params384))
	res = (out[1].decode().find('bign-curve384v1') != -1)
	process_result('bign-genec[bign-curve384v1]', res)

	# bign-genparams: bign-curve512v1
	params512 = os.path.join(tmpdirname, 'params512v1.pem')
	bignParamsStd('bign-curve512v1', params512)
	out = openssl('asn1parse -in {}'.format(params512))
	res = (out[1].decode().find('bign-curve512v1') != -1)
	process_result('bign-genec[bign-curve512v1]', res)

	# bign-genkeypair: bign-curve256v1
	prkey256 = os.path.join(tmpdirname,'prkey256v1.pem')
	bignKeypairGen(params256, prkey256)
	out = openssl('asn1parse -in {}'.format(prkey256))
	res = (out[1].decode().find('bign-curve256v1') != -1 and 
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-genkeypair[bign-curve256v1]', res)

	# bign-genkeypair: G.1
	key = '1F66B5B84B7339674533F0329C74F21834281FED0732429E0C79235FC273E269'
	asn1cnf = '''
	asn1 = SEQUENCE:SubjectPublicKeyInfo
	[SubjectPublicKeyInfo]
	version = INTEGER:0

	algorithm = SEQUENCE:AlgorithmIdentifier

	subjectPublicKey = FORMAT:HEX,OCTETSTRING:{}

	[AlgorithmIdentifier]
	algorithm = OBJECT:bign-pubkey

	parameters = OBJECT:bign-curve256v1
	'''.format(key)
	asn1_conf_file = os.path.join(tmpdirname, 'asn1_conf')
	with open(asn1_conf_file,'w') as f:
		f.write(asn1cnf)
	G1prkey256der = os.path.join(tmpdirname, 'G1prkey256.der')
	G1prkey256pem = os.path.join(tmpdirname, 'G1prkey256.pem')
	retcode, out, er__ = openssl('asn1parse -genconf {} -out {}'
		.format(asn1_conf_file, G1prkey256der))
	openssl('pkey -engine bee2evp -inform DER -in {} -outform PEM -out {}'
		.format(G1prkey256der,G1prkey256pem))
	retcode, out, er__ = openssl('asn1parse -in {}'.format(G1prkey256pem))
	out = (out.decode().strip()[out.decode().rfind('[HEX DUMP]:'):]
		.split(':')[1])
	res = (out == key)
	process_result('bign-genkeypair[bign-curve256v1](G.1)', res)

	# bign-genkeypair: bign-curve384v1
	prkey384 = os.path.join(tmpdirname, 'prkey384v1.pem')
	bignKeypairGen(params384, prkey384)
	out = openssl('asn1parse -in {}'.format(prkey384))
	res = (out[1].decode().find('bign-curve384v1') != -1 and
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-genkeypair[bign-curve384v1]', res)

	# bign-genkeypair: bign-curve512v1
	prkey512 = os.path.join(tmpdirname, 'prkey512v1.pem')
	bignKeypairGen(params512, prkey512)
	out = openssl('asn1parse -in {}'.format(prkey512))
	res = (out[1].decode().find('bign-curve512v1') != -1 and
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-genkeypair[bign-curve512v1]', res)

	# bign-calcpubkey: bign-curve256v1
	pubkey256 = os.path.join(tmpdirname, 'pubkey256v1.pem')
	bignPubkeyCalc(prkey256, pubkey256)
	out = openssl('asn1parse -in {}'.format(pubkey256))
	res = (out[1].decode().find('bign-curve256v1') != -1 and
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-calcpubkey[bign-curve256v1]', res)

	# bign-calcpubkey: G.1
	G1pubkey256 = os.path.join(tmpdirname, 'G1pubkey256v1.pem')
	bignPubkeyCalc(G1prkey256pem, G1pubkey256)
	out = openssl('asn1parse -in {} -offset 28 -dump'.format(G1pubkey256))
	out = re.sub(r'[\s]', '', out[1].decode())
	matches = re.findall('[0-9A-Fa-f]{4}-[0-9A-Fa-f]+-*[0-9A-Fa-f]+', out)
	ans = ''
	for match in matches:
		items = match.split('-')
		for item in items[1:]:
			ans += item
	res = (ans[2:] == ('bd1a5650179d79e03fcee49d4c2bd5dd'
					  'f54ce46d0cf11e4ff87bf7a890857fd0'
					  '7ac6a60361e8c8173491686d461b2826'
					  '190c2eda5909054a9ab84d2ab9d99a90'))
	process_result('bign-calcpubkey[bign-curve256v1](G.1)', res)

	# bign-calcpubkey: bign-curve384v1
	pubkey384 = os.path.join(tmpdirname, 'pubkey384v1.pem')
	bignPubkeyCalc(prkey384, pubkey384)
	out = openssl('asn1parse -in {}'.format(pubkey384))
	res = (out[1].decode().find('bign-curve384v1') != -1 and 
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-calcpubkey[bign-curve384v1]', res)

	# bign-genpubkey: bign-curve512v1
	pubkey512 = os.path.join(tmpdirname, 'pubkey512v1.pem')
	bignPubkeyCalc(prkey512, pubkey512)
	out = openssl('asn1parse -in {}'.format(pubkey512))
	res = (out[1].decode().find('bign-curve512v1') != -1 and
		out[1].decode().find('bign-pubkey') != -1)
	process_result('bign-calcpubkey[bign-curve512v1]', res)

	# bign-sign[belt-hash]
	src = hex_decoder('b194bac80a08f53b366d008e58')[0]
	signbelth = os.path.join(tmpdirname, 'signbelth.sign')
	retcode = bignSign(prkey256, 'belt-hash', bytes(src), signbelth)
	res = (retcode == 0)
	process_result('bign-sign[belt-hash]', res)

	# bign-vfy[belt-hash]
	out = bignVerify(prkey256, 'belt-hash', bytes(src), signbelth)
	res = (out == 'Verified OK')
	process_result('bign-vfy[belt-hash]', res)

	# bign-sign2[belt-hash]
	src = hex_decoder('b194bac80a08f53b366d008e58')[0]
	dsignbelth = os.path.join(tmpdirname, 'dsignbelth.sign')
	retcode = bignSign2(G1prkey256pem, 'belt-hash', bytes(src), dsignbelth)
	res = (retcode == 0)
	process_result('bign-sign2[belt-hash]', res)

	# bign-vfy[belt-hash]
	out = bignVerify(G1prkey256pem, 'belt-hash', bytes(src), dsignbelth)
	res = (out == 'Verified OK')
	process_result('bign-vfy[belt-hash]', res)

	shutil.rmtree(tmpdirname)
