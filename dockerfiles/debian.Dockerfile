FROM debian:bookworm-slim

RUN apt-get update \
  && apt-get install -y \
  git gcc cmake python3 doxygen \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/bee2evp

COPY . .

ARG OPENSSL_TAG

RUN bash ./utils/build_debian.sh -s -t ${OPENSSL_TAG}
