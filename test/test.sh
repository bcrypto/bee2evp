#!/bin/bash
# *****************************************************************************
# \file test.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Scripts for building and testing
# \created 2020.07.10
# \version 2023.10.02
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************


bee2evp=$(pwd)/..
build_root=$bee2evp/build
bee2=$bee2evp/bee2
openssl=$bee2evp/openssl
build_bee2evp=$build_root/build_bee2evp
build_bee2=$build_root/build_bee2
build_openssl=$build_root/build_openssl
local=$build_root/local

openssl_branch=OpenSSL_1_1_1i

install_prereq(){
  sudo apt-get update
  sudo apt-get install git gcc cmake python3
}

clean(){
  rm -rf $build_root
  rm -rf $openssl
}

update_repos(){
  echo $openssl_branch
  git submodule update --init
  git clone -b $openssl_branch --depth 1 https://github.com/openssl/openssl $openssl
}

patch_openssl(){
  cd $openssl
  cp $bee2evp/btls/btls.c ./ssl/
  cp $bee2evp/btls/btls.h ./ssl/
  git apply $bee2evp/btls/patch/$openssl_branch.patch
}

build_bee2(){
  mkdir -p $build_bee2 && mkdir -p $local && cd $build_bee2
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_PIC=ON -DCMAKE_INSTALL_PREFIX=$local $bee2
  make -j$(nproc) && make install
  ls -la $local/lib/libbee2_static.a
}

build_openssl(){
  mkdir -p $build_openssl && mkdir -p $local && cd $build_openssl
  $openssl/config shared -d --prefix=$local --openssldir=$local
  make -j$(nproc) all
  make install > build.log 2>&1 || (cat build.log && exit 1)
  ls -la $local/lib/libcrypto.a
  ls -la $local/lib/libssl.a
  ls -la $local/lib/libcrypto.so
  ls -la $local/lib/libssl.so
  ls -la $local/bin/openssl
}

build_bee2evp(){
  mkdir -p $build_bee2evp && cd $build_bee2evp
  cmake -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_LIBRARY_DIRS=$local/lib -DBEE2_INCLUDE_DIRS=$local/include \
    -DOPENSSL_LIBRARY_DIRS=$local/lib -DOPENSSL_INCLUDE_DIRS=$local/include \
    -DLIB_INSTALL_DIR=$local/lib -DCMAKE_INSTALL_PREFIX=$local $bee2evp
  make -j$(nproc) && make install
  ls -la $local/lib/libbee2evp.so
}

attach_bee2evp(){
  mv $local/openssl.cnf.dist $local/openssl.cnf
  sed -i "/\[ new\_oids\ ]/i openssl_conf = openssl_init\n[ openssl_init ]\nengines = engine_section\n[ engine_section ]\nbee2evp = bee2evp_section\n[ bee2evp_section ]\nengine_id = bee2evp\ndynamic_path = $local/lib/libbee2evp.so\ndefault_algorithms = ALL" $local/openssl.cnf
}

test_bee2evp(){
  export LD_LIBRARY_PATH="$local/lib:${LD_LIBRARY_PATH:-}"
  cd $local || exit
  cp -a ../../test/. .
  python test.py
}

#install_prereq
#clean
#update_repos
#patch_openssl
#build_bee2
#build_openssl
#build_bee2evp
#attach_bee2evp
test_bee2evp
