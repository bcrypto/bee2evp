FROM ubuntu:focal
# The last version of Ubuntu that exclusively uses OpenSSL 1.1.1 is 
# Ubuntu 20.04 LTS (Focal Fossa)
RUN apt-get clean 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install git cmake curl python3 \
    build-essential pkg-config ed -y -q

RUN DEBIAN_FRONTEND=noninteractive apt-get install libssl-dev
COPY . /usr/src
WORKDIR '/usr/src'
RUN git submodule update --init
RUN mkdir -p ./build_bee2evp

WORKDIR '/usr/src/build_bee2evp'
RUN cmake -DCMAKE_BUILD_TYPE=Debug ..
RUN make
RUN make install

RUN openssl version
RUN openssl version -d

RUN sed -i -e '/.*oid_section.*/a openssl_conf = openssl_init \n\
[openssl_init] \n\
' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '/.*\[openssl_init\].*/a engines = engine_section' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '0,/[#]\{5,\}/s/[#]\{5,\}/[engine_section] \n\
bee2evp = bee2evp_section \n\
\n\
[bee2evp_section] \n\
engine_id = bee2evp \n\
dynamic_path = \/usr\/local\/lib\/libbee2evp.so  \n\
default_algorithms = ALL \n\#########################/g' /usr/lib/ssl/openssl.cnf

RUN sed -i '/.*new_oids \].*/a \
bpki = 1.2.112.0.2.0.34.101.78 \n\
bpki-role-ca0 = \$\{bpki\}.2.0 \n\
bpki-role-ca1 = \$\{bpki\}.2.1 \n\
bpki-role-ca2 = \$\{bpki\}.2.2 \n\
bpki-role-aa  = \$\{bpki\}.2.10 \n\
bpki-role-ra = \$\{bpki\}.2.20 \n\
bpki-role-ocsp = \$\{bpki\}.2.30 \n\
bpki-role-tsa = \$\{bpki\}.2.31 \n\
bpki-role-dvcs = \$\{bpki\}.2.32 \n\
# identification servers \n\
bpki-role-ids = \$\{bpki\}.2.33 \n\
bpki-role-tls = \$\{bpki\}.2.50 \n\
# natural persons \n\
bpki-role-np = \$\{bpki\}.2.60 \n\
# foreign natural persons \n\
bpki-role-fnp = \$\{bpki\}.2.61 \n\
# legal representatives \n\
bpki-role-lr = \$\{bpki\}.2.62 \n\
# autonomous cryptographic devices \n\
bpki-role-acd = \$\{bpki\}.2.70 \n\
# server of Terminal Mode \n\
bpki-eku-serverTM = \${bpki}.3.1 \n\
# client of Terminal Mode \n\
bpki-eku-clientTM = \$\{bpki\}.3.2 \n\
# Enroll1 request \n\
bpki-ct-enroll1-req = \$\{bpki\}.5.1 \n\
# Enroll2 request \n\
bpki-ct-enroll2-req = \$\{bpki\}.5.2 \n\
# Reenroll request \n\
bpki-ct-reenroll-req = \$\{bpki\}.5.3 \n\
# Spawn request \n\
bpki-ct-spawn-req = \$\{bpki\}.5.4 \n\
# Setpwd request \n\
bpki-ct-setpwd-req = \$\{bpki\}.5.5 \n\
# Revoke request \n\
bpki-ct-revoke-req = \$\{bpki\}.5.6 \n\
# BPKIResp \n\
bpki-ct-resp = \$\{bpki\}.5.7 \n\
' /usr/lib/ssl/openssl.cnf

RUN cat /usr/lib/ssl/openssl.cnf

RUN openssl engine  -c -t bee2evp

RUN echo -n "hello world" | openssl dgst -engine bee2evp -belt-hash

WORKDIR '/usr/src/test'
RUN python3 test.py