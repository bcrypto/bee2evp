# *****************************************************************************
# \file bign.py
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief A python wrapper over STB 34.101.65 (btls) ciphersuites
# \created 2019.12.09
# \version 2024.05.31
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

import os, signal, shutil, tempfile, time, threading
from openssl import openssl, openssl2
from util import process_result

def btls_gen_privkey(privfile, curve):
	cmd = ('genpkey -algorithm bign -pkeyopt params:{} -out {}'
		.format(curve, privfile))
	retcode, block, er__ = openssl(cmd)

def btls_issue_cert(privfile, certfile):
	cmd = ('req -x509 -subj "/CN=www.example.org/O=BCrypto/C=BY/ST=MINSK"\
		 -new -key {} -nodes -out {}'.format(privfile, certfile))
	retcode, block, er__ = openssl(cmd)

def btls_server_cert(tmpdirname, server_log_file, curve, psk=False):
	priv = os.path.join(tmpdirname, '{}.key'.format(curve))
	btls_gen_privkey(priv, curve)

	cert = os.path.join(tmpdirname, 'cert.pem')
	btls_issue_cert(priv, cert)

	if psk:
		cmd = 's_server -key {} -cert {} -tls1_2 -psk 123456 -psk_hint 123 \
			>> {}'.format(priv, cert, server_log_file)
	else:
		cmd = ('s_server -key {} -cert {} -tls1_2 >> {}'
				.format(priv, cert, server_log_file))

	global server_cert
	server_cert = openssl2(cmd)

def btls_client_cert(client_log_file, curve, ciphersuites, psk=False):
	for ciphersuite in ciphersuites:
		if psk:
			cmd = ('s_client -cipher {} -tls1_2 -connect 127.0.0.1:4433\
				-psk 123456 2>{}'.format(ciphersuite, client_log_file))
		else:
			cmd = ('s_client -cipher {} -tls1_2 -connect 127.0.0.1:4433\
				2>{}'.format(ciphersuite, client_log_file))

		openssl(cmd, prefix='echo test_{}={} |'.format(curve, ciphersuite))

def btls_server_nocert(server_log_file):
	cmd = ('s_server -tls1_2 -psk 123456 -psk_hint 123 -nocert >> {}'
			.format(server_log_file))

	global server_nocert
	server_nocert = openssl2(cmd)

def btls_client_nocert(client_log_file, curves_list, ciphersuites):
	for ciphersuite in ciphersuites:
		for curves in curves_list:
			if curves != 'NULL':
				cmd = ('s_client -cipher {} -tls1_2 -curves {} \
					-connect 127.0.0.1:4433 -psk 123456 2>{}'
						.format(ciphersuite, curves, client_log_file))
			else:
				cmd = ('s_client -cipher {} -tls1_2 -connect 127.0.0.1:4433\
					-psk 123456 2>{}'.format(ciphersuite, client_log_file))
			openssl(cmd, prefix='echo test_{}={} |'
				.format(curves, ciphersuite))

def btls_test():
	tmpdirname = tempfile.mkdtemp()
	server_log_file = 's_log.txt'
	client_log_file = 'c_log.txt'

	# curves list for test BDHEPSK
	curves_list_bdhepsk = [
		'NULL', 'bign-curve256v1', 'bign-curve384v1', 'bign-curve512v1',
		'bign-curve256v1:bign-curve384v1:bign-curve512v1', 
		'bign-curve256v1:bign-curve512v1']

	# curves list for test BDHE and BDHTPSK
	curves_list = ['bign-curve256v1', 'bign-curve384v1', 'bign-curve512v1']

	noPSK_cipherssuites = [
		'DHE-BIGN-WITH-BELT-DWP-HBELT', 
		'DHE-BIGN-WITH-BELT-CTR-MAC-HBELT',
		'DHT-BIGN-WITH-BELT-DWP-HBELT', 
		'DHT-BIGN-WITH-BELT-CTR-MAC-HBELT']
	bdhePSK_ciphersuites = [
		'DHE-PSK-BIGN-WITH-BELT-DWP-HBELT', 
		'DHE-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT']
	bdhtPSK_ciphersuites = [
		'DHT-PSK-BIGN-WITH-BELT-DWP-HBELT', 
		'DHT-PSK-BIGN-WITH-BELT-CTR-MAC-HBELT']
	nocert_ciphersuites = bdhePSK_ciphersuites
	cert_ciphersuites = bdhtPSK_ciphersuites + noPSK_cipherssuites

	# test NO_PSK ciphersuites
	for curve in curves_list:
		s_nopsk = threading.Thread(target=btls_server_cert, 
						args=(tmpdirname, server_log_file, curve))
		s_nopsk.run()
		time.sleep(1)
		c_nopsk = threading.Thread(target=btls_client_cert, 
						args=(client_log_file, curve, noPSK_cipherssuites))
		c_nopsk.run()

		# kill openssl s_server
		os.killpg(os.getpgid(server_cert.pid), signal.SIGTERM)
	print('End NO_PSK')

	# test BDHTPSK ciphersuites
	for curve in curves_list:
		s_dhtpsk = threading.Thread(target=btls_server_cert, 
						args=(tmpdirname, server_log_file, curve, True))
		s_dhtpsk.run()
		time.sleep(1)
		c_dhtpsk = threading.Thread(target=btls_client_cert, 
						args=(client_log_file, curve, bdhtPSK_ciphersuites, True))
		c_dhtpsk.run()

		# kill openssl s_server
		os.killpg(os.getpgid(server_cert.pid), signal.SIGTERM)
	print('End BDHTPSK')

	# test BDHEPSK ciphersuites
	s_dhepsk = threading.Thread(target=btls_server_nocert, 
					args=(server_log_file,))
	s_dhepsk.run()
	time.sleep(1)
	c_dhepsk = threading.Thread(target=btls_client_nocert, 
					args=(client_log_file, curves_list_bdhepsk, bdhePSK_ciphersuites))
	c_dhepsk.run()

	# kill openssl s_server
	os.killpg(os.getpgid(server_nocert.pid), signal.SIGTERM)
	print('End BDHEPSK')

	with open(server_log_file, 'r') as f:
		server_out = f.read()

	for ciphersuite in cert_ciphersuites:
		print(ciphersuite)
		for curves in curves_list:
			res = (server_out.find('test_{}={}'
				.format(curves, ciphersuite)) != -1)
			process_result('\t{}'.format(curves), res)

	for ciphersuite in nocert_ciphersuites:
		print(ciphersuite)
		for curves in curves_list_bdhepsk:
			res = (server_out.find('test_{}={}'
				.format(curves, ciphersuite)) != -1)
			process_result('\t{}'.format(curves), res)

	shutil.rmtree(tmpdirname)
