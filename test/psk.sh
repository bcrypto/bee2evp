openssl asn1parse -genconf psk.ini -noout -out sess.der
echo "-----BEGIN SSL SESSION PARAMETERS-----" > sess.pem
openssl enc -base64 -in sess.der >> sess.pem
echo "-----END SSL SESSION PARAMETERS-----" >> sess.pem