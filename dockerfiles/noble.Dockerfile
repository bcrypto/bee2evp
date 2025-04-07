FROM ubuntu:noble

RUN apt-get clean 
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install cmake python3 -y -q


RUN apt-get install -y -q \
	build-essential \
	git \
	libssl-dev \
	pkg-config \
	ed

COPY . /usr/src

WORKDIR '/usr/src'
RUN git submodule update --init
RUN mkdir -p ./_build

WORKDIR '/usr/src/_build'
RUN cmake ..
RUN make
RUN make install

RUN openssl version
RUN openssl version -d


RUN sed -i -e '/^.default_sect.$/a activate = 1' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '/^.provider_sect.$/a bee2pro = bee2pro_section' /usr/lib/ssl/openssl.cnf

RUN sed -i -e '0,/[#]\{5,\}/s/[#]\{5,\}/[bee2pro_section] \n\
identity = bee2pro \n\
module = \/usr\/local\/lib\/libbee2evp.so \n\
activate = 1 \n\
\n\#########################/g' /usr/lib/ssl/openssl.cnf

RUN cat /usr/lib/ssl/openssl.cnf

RUN openssl list -providers

RUN echo -n "hello world" | openssl dgst -provider bee2pro -belt-hash

WORKDIR '/usr/src/test'
RUN python3 test.py

