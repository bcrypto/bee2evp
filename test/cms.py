# *****************************************************************************
# \file cms.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Containers: CMS, PKCS#7, PKCS#8, PKCS#12
# \created 2026.09.25
# \version 2026.09.25
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import filecmp, os, shutil, tempfile
from openssl import openssl, PROVIDER
from util import process_result

def run(cmd):
	return openssl(cmd, check=False)[0] == 0

def same(a, b):
	return os.path.exists(b) and filecmp.cmp(a, b, shallow=False)

def cms_test():
	tmp = tempfile.mkdtemp()
	msg = os.path.join(tmp, 'msg')
	out = os.path.join(tmp, 'out')
	der = os.path.join(tmp, 'der')
	with open(msg, 'wb') as f:
		f.write(b'The quick brown fox jumps over the lazy dog\n' * 10)

	for l in ('256', '384', '512'):
		key = os.path.join(tmp, 'key' + l)
		cert = os.path.join(tmp, 'cert' + l)
		openssl('genpkey -engine bee2evp -algorithm bign '
			'-pkeyopt params:bign-curve{}v1 -out {}'.format(l, key))
		openssl('req -engine bee2evp -x509 -new -subj "/CN=cms{}" '
			'-key {} -out {}'.format(l, key, cert))
		for tool in ('cms', 'smime'):
			name = '{}[{}]'.format('cms' if tool == 'cms' else 'pkcs7', l)
			# SignedData: bign-with-hbelt / bign-with-bashXXX
			res = (run('{} -engine bee2evp -sign -binary -nodetach -in {} '
					'-signer {} -inkey {} -outform DER -out {}'
					.format(tool, msg, cert, key, der)) and
				run('{} -engine bee2evp -verify -binary -inform DER -in {} '
					'-CAfile {} -out {}'.format(tool, der, cert, out)) and
				same(msg, out))
			process_result(name + '-sign', res)
			# EnvelopedData: bign-keytransport
			for cipher in ('belt-cbc256', 'belt-ctr256'):
				os.remove(out) if os.path.exists(out) else None
				res = (run('{} -engine bee2evp -encrypt -binary -in {} -{} '
						'-outform DER -out {} {}'
						.format(tool, msg, cipher, der, cert)) and
					run('{} -engine bee2evp -decrypt -binary -inform DER '
						'-in {} -recip {} -inkey {} -out {}'
						.format(tool, der, cert, key, out)) and
					same(msg, out))
				process_result('{}-encrypt[{}]'.format(name, cipher), res)

	key = os.path.join(tmp, 'key256')
	cert = os.path.join(tmp, 'cert256')

	# PasswordRecipientInfo (the engine is not visible to cms_pwri.c)
	if PROVIDER:
		os.remove(out)
		res = (run('cms -encrypt -binary -in {} -pwri_password pw '
				'-belt-cbc256 -outform DER -out {}'.format(msg, der)) and
			run('cms -decrypt -binary -inform DER -in {} -pwri_password pw '
				'-out {}'.format(der, out)) and
			same(msg, out))
		process_result('cms-pwri[belt-cbc256]', res)

	# PKCS#8: PBES2 + PBKDF2(belt-hmac) + belt-kwp256
	p8 = os.path.join(tmp, 'p8')
	res = (run('pkcs8 -engine bee2evp -topk8 -v2 belt-kwp256 -v2prf belt-hmac '
			'-in {} -passout pass:pw -out {}'.format(key, p8)) and
		run('pkcs8 -engine bee2evp -in {} -passin pass:pw -out {}'
			.format(p8, out)))
	_, dump, __ = openssl('asn1parse -in {}'.format(p8), check=False)
	res = res and b'belt-kwp256' in dump and b'belt-hmac' in dump
	process_result('pkcs8[belt-kwp256]', res)

	# PKCS#12: belt-kwp256 / belt-cbc256, MAC on belt-hash
	p12 = os.path.join(tmp, 'p12')
	res = (run('pkcs12 -engine bee2evp -export -in {} -inkey {} '
			'-keypbe belt-kwp256 -certpbe belt-cbc256 -macalg belt-hash '
			'-passout pass:pw -out {}'.format(cert, key, p12)) and
		run('pkcs12 -engine bee2evp -in {} -passin pass:pw -nodes -out {}'
			.format(p12, out)))
	res = res and b'PRIVATE KEY' in open(out, 'rb').read()
	process_result('pkcs12[belt-kwp256,belt-cbc256,belt-hash]', res)

	shutil.rmtree(tmp)
