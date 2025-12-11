# *****************************************************************************
# \file btls.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.65 (btls) ciphersuites
# \created 2019.12.09
# \version 2024.06.03
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import os, signal, shutil, tempfile, time, threading
from openssl import openssl, openssl2
from util import process_result

def btls_gen_privkey(privkey, curve):
	cmd = ('genpkey -algorithm bign -pkeyopt params:{} -out {}'
		.format(curve, privkey))
	openssl(cmd)

def btls_issue_cert(cert, privkey):
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY" \
		 -new -key {} -nodes -out {}'.format(privkey, cert))
	openssl(cmd)

def btls_server(tmpdir, suite, is_tls13, curve, cert, psk):
	assert cert or psk
	# prepare cmd
	if is_tls13:
		cmd = 's_server -engine bee2evp -tls1_3 -ciphersuites {} -rev'.format(suite)
	else:
		cmd = 's_server -engine bee2evp -tls1_2 -rev'.format(suite)

	if cert:
		privkey = os.path.join(tmpdir, suite + curve + '.sk')
		cert = os.path.join(tmpdir, suite + curve + '.cert')
		btls_gen_privkey(privkey, curve)
		btls_issue_cert(cert, privkey)
		cmd = cmd + ' -key {} -cert {}'.format(privkey, cert)
	else:
		cmd = cmd + ' -nocert'
	if psk:
		cmd = cmd + ' -psk 123456 -psk_hint 123'
	# prepare output
	output = os.path.join(tmpdir, suite + curve + '.srv')
	cmd = cmd + ' >{}'.format(output)
	# start server
	global g_server
	g_server = openssl2(cmd)

def btls_client(tmpdir, suite, is_tls13, curve, cert, psk):
	assert cert or psk
	# prepare cmd
	if is_tls13:
		cmd = 's_client -engine bee2evp -tls1_3 -ciphersuites {}'.format(suite)
	else:
		cmd = 's_client -engine bee2evp -tls1_2 -cipher {}'.format(suite)

	if psk:
		cmd = cmd + ' -psk 123456'
	if not cert and curve != 'NULL':
		cmd = cmd + ' -curves {}'.format(curve)
    # prepare output
	output = os.path.join(tmpdir, suite + curve + '.cli')
	cmd = cmd + ' >{}'.format(output)
	# run cmd
	echo = 'test_{}={}'.format(curve, suite)
	openssl(cmd, prefix='(echo ' + echo + '; sleep 1) |')
	# test if server returns the reversed initial string
	with open(output, 'r') as f:
		echo2 = f.read()
	process_result('{}[{}]'.format(suite, curve), echo2[::-1])

def btls_test():
	tmpdir = tempfile.mkdtemp()

	tls13_ciphersuites = [
		'BTLS_BASH_PRG_AE256_BASH256',
		'BTLS_BELT_CHE256_BELT_HASH']

	ciphersuites = [
		'DHE-BIGN-WITH-BELT-DWP-HBELT',
		'DHE-BIGN-WITH-BELT-CTR-MAC-HBELT',
		'DHT-BIGN-WITH-BELT-DWP-HBELT',
		'DHT-BIGN-WITH-BELT-CTR-MAC-HBELT',
		'DHE-PSK-BIGN-WITH-BELT-DWP-HBELT',
		'DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT',
		'DHT-PSK-BIGN-WITH-BELT-DWP-HBELT',
		'DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT',
		'BTLS_BASH_PRG_AE256_BASH256',
		'BTLS_BELT_CHE256_BELT_HASH']

	curves_shortlist = [
		'bign-curve256v1',
		'bign-curve384v1', 'bign-curve512v1'
	]
	curves_longlist = [
		'bign-curve256v1',
		'bign-curve384v1', 'bign-curve512v1',
		'bign-curve256v1:bign-curve384v1:bign-curve512v1',
		'bign-curve256v1:bign-curve512v1'
	]

	for suite in tls13_ciphersuites:
		# determine a list of curves
		curves = curves_shortlist
		# run over curves
		for curve in curves:
			# prepare args
			args = (tmpdir, suite, True, curve, False, True)
			# run server
			server = threading.Thread(target=btls_server, args=args)
			server.run()
			# run client
			time.sleep(1)
			client = threading.Thread(target=btls_client, args=args)
			client.run()
			# kill server
			os.killpg(os.getpgid(g_server.pid), signal.SIGTERM)

	for suite in ciphersuites:
		# psk?
		psk = suite.find('PSK') != -1
		# cert?
		cert = not psk or suite.find('DHT') != -1
		# determine a list of curves
		if suite.find('DHE-PSK') != -1:
			curves = curves_longlist
		else:
			curves = curves_shortlist
		# run over curves
		for curve in curves:
			# prepare args
			if suite in tls13_ciphersuites:
				args = (tmpdir, suite, True, curve, True, False)
			else:
				args = (tmpdir, suite, False, curve, cert, psk)
			# run server
			server = threading.Thread(target=btls_server, args=args)
			server.run()
			# run client
			time.sleep(1)
			client = threading.Thread(target=btls_client, args=args)
			client.run()
			# kill server
			os.killpg(os.getpgid(g_server.pid), signal.SIGTERM)

	shutil.rmtree(tmpdir)
