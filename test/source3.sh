#!/bin/bash
# *****************************************************************************
# \file source.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Reusable script code
# \created 2020.07.10
# \version 2024.06.07
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

bee2evp=$(pwd)/..
build_root=/opt/openssl/build
bee2=$bee2evp/bee2
openssl=$bee2evp/openssl
build_bee2evp=$build_root
build_bee2=$build_root/bee2
build_openssl=$build_root/openssl
local=${BEE2EVP_INSTALL_DIR:-$build_root/local}

openssl_branch=$1

install_prereq(){
  sudo apt-get update
  for package in git gcc cmake python3 doxygen
  do
    dpkg -s $package &> /dev/null
    if [ $? -ne 0 ]
    then
      echo "$package not installed"  
      sudo apt-get install $package
      echo "$package already installed"
    else
      echo "$package already installed"
    fi
  done
}

clean(){
  rm -rf $build_root
  rm -rf $openssl
}

update_repos(){
  echo $openssl_branch
  git submodule update --init
  git clone -b $openssl_branch --depth 1  https://github.com/openssl/openssl\
    $openssl
}

patch_openssl(){
  cd $openssl
  cp $bee2evp/btls/btls.c ./ssl/
  cp $bee2evp/btls/btls.h ./ssl/
  git apply $bee2evp/btls/patch/$openssl_branch.patch
}

build_bee2(){
  mkdir -p $build_bee2 && cd $build_bee2
  cmake -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_PIC=ON \
    -DCMAKE_INSTALL_PREFIX=$local \
    -DLIB_INSTALL_DIR=$local/lib64 $bee2
  make -j$(nproc) && make install
  ls -la $local/lib64/libbee2_static.a
}

build_openssl(){
  mkdir -p $build_openssl && cd $build_openssl
  $openssl/config shared -d --prefix=$local --openssldir=$local
  make -j$(nproc) all
  make install > build.log 2>&1 || (cat build.log && exit 1)
  ls -la $local/lib64/libcrypto.a
  ls -la $local/lib64/libssl.a
  ls -la $local/lib64/libcrypto.so
  ls -la $local/lib64/libssl.so
  ls -la $local/bin/openssl
}

build_bee2evp(){
  mkdir -p $build_bee2evp && cd $build_bee2evp
  cmake -DCMAKE_BUILD_TYPE=Debug \
    -DBUILD_DOC=OFF \
    -DBEE2_LIBRARY_DIRS=$local/lib64 \
    -DBEE2_INCLUDE_DIRS=$local/include \
    -DOPENSSL_LIBRARY_DIRS=$local/lib64 \
    -DOPENSSL_INCLUDE_DIRS=$local/include \
    -DLIB_INSTALL_DIR=$local/lib64 \
    -DCMAKE_INSTALL_PREFIX=$local $bee2evp
  make -j$(nproc) && make install
  ls -la $local/lib64/libbee2evp.so
}

attach_bee2evp(){
  cp $local/openssl.cnf.dist $local/openssl.cnf
  cp -L $local/lib64/libbee2evp.so $local/lib64/engines-3/bee2evp.so
}

test_bee2evp(){
  cd $local || exit
  cp -a $bee2evp/test/. .
  export LD_LIBRARY_PATH="$local/lib64:${LD_LIBRARY_PATH}"
  python3 test.py
  export LD_LIBRARY_PATH=$(echo "$LD_LIBRARY_PATH" | \
    sed -e "s|$local/lib64:||")
}
