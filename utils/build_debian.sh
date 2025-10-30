#!/bin/bash
# *****************************************************************************
# \file source.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Reusable script code
# \created 2025.10.06
# \version 2025.10.06
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************
set -eo pipefail

green () { printf "\e[32m" ; $@ ; printf "\e[0m"; }
red () { printf "\e[31m" ; $@ ; printf "\e[0m"; }

cd "$( dirname "${BASH_SOURCE[0]}" )"

usage() {
  echo "Usage: $0 [OPTIONS] <openssl_tag>"
  echo "Build bee2evp for debian based distributions:"
  echo ""
  echo "  --build-type    build type: |Debug|Release|Coverage|"
  echo "  -d, --debug     enable debug mode"
  echo "  -s,             setup"
  echo "  -b,             build"
  echo "  -t,             test"
  echo "  -h, --help      display this help and exit"
  exit 1
}

build_type=Release
bee2evp=$(pwd)/..
build_root=$bee2evp/build
bee2=$bee2evp/bee2
openssl=$bee2evp/openssl
build_bee2evp=$build_root/bee2evp
build_bee2=$build_root/bee2
build_openssl=$build_root/openssl
local=${BEE2EVP_INSTALL_DIR:-$build_root/local}
lib_path=$local/lib
is_openssl_3=false
openssl_git_url=https://github.com/openssl/openssl.git
btls_srcs_path=$bee2evp/btls/legacy
enable_setup=false
enable_build=false
enable_test=false

openssl_tag=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --build-type=*)
      build_type="${1#*=}"
      case "$build_type" in
        Debug|Release|Coverage)
          # Valid value, continue
          ;;
        *)
          echo "received build type: $build_type"
          red echo "error: --build-type must be one of: Release, Debug, Coverage"
          exit 1
          ;;
      esac
      shift
      ;;
    -d|--debug)
      build_type=Debug
      shift
      ;;
    -s)
      enable_setup=true
      shift
      ;;
    -b)
      enable_build=true
      shift
      ;;
    -t)
      enable_test=true
      shift
      ;;
    -h|--help)
      usage
      ;;
    -*)
      red echo "invalid option -- $1" >&2
      usage
      ;;
    *)
      if [[ ! -z "$1" ]]; then
        openssl_tag="$1"
        shift
      else
        usage
      fi
      ;;
  esac
done

if [[ -z "$openssl_tag" ]]; then
  red echo "openssl tag name is required" >&2
  usage
fi

echo "build_type=$build_type"
echo "openssl_tag=$openssl_tag"

clean(){
  green echo "[-] clean build files..."
  rm -rf $build_root
  rm -rf $openssl
}

check_prereq(){
  set +e
  green echo "[-] check prereq"
  for package in git gcc cmake python3
  do
    which $package &> /dev/null
    if [ $? -ne 0 ]; then
      set -e
      red echo "$package not installed"
      exit 1
    fi
  done
  set -e
  export GIT_REDIRECT_STDERR='2>&1'
}

# Check openssl major version
is_openssl_3() {
  if [[ "$openssl_tag" =~ .*[-_]([0-9]).* ]];
  then
    openssl_major_version="${BASH_REMATCH[1]}"
  fi

  if [[ "$openssl_major_version" = "3" ]];
  then
    lib_path=$local/lib64
    is_openssl_3=true
    btls_srcs_path=$bee2evp/btls
  fi
}

# Check if openssl tag exist.
check_openssl_tag(){
  green echo "[-] check openssl tag"
  git ls-remote $openssl_git_url refs/tags/$openssl_tag
}

update_repos(){
  green echo "[-] update repos"
  git submodule update --init
  git clone -b $openssl_tag --depth 1 $openssl_git_url $openssl
}

patch_openssl(){
  green echo "[-] patch openssl"
  cd $openssl
  if $is_openssl_3;
  then
    cat $btls_srcs_path/objects.txt >> $openssl/crypto/objects/objects.txt
  fi
  cp $btls_srcs_path/btls.c ./ssl/
  cp $btls_srcs_path/btls.h ./ssl/
  git apply $bee2evp/btls/patch/$openssl_tag.patch
}

build_bee2(){
  green echo "[-] build bee2"
  mkdir -p $build_bee2 && cd $build_bee2
  cmake -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_PIC=ON \
    -DCMAKE_INSTALL_PREFIX=$local \
    -DLIB_INSTALL_DIR=$lib_path $bee2
  make -j$(nproc) && make install
  ls -la $lib_path/libbee2_static.a
}

build_openssl(){
  green echo "[-] build openssl"
  mkdir -p $build_openssl && cd $build_openssl
  if [[ "$build_type" -eq "Debug" ]]; then
    $openssl/config shared -d --prefix=$local --openssldir=$local
  else
    $openssl/config shared --prefix=$local --openssldir=$local
  fi

  if $is_openssl_3;
  then
    make update
  fi
  make -j$(nproc) all
  make install > build.log 2>&1 || (cat build.log && exit 1)
  ls -la $lib_path/libcrypto.a
  ls -la $lib_path/libssl.a
  ls -la $lib_path/libcrypto.so
  ls -la $lib_path/libssl.so
  ls -la $local/bin/openssl
}

build_bee2evp(){
  green echo "[-] build bee2evp"
  mkdir -p $build_bee2evp && cd $build_bee2evp
  cmake -DCMAKE_BUILD_TYPE=$build_type \
    -DBUILD_DOC=OFF \
    -DBEE2_LIBRARY_DIRS=$lib_path \
    -DBEE2_INCLUDE_DIRS=$local/include \
    -DOPENSSL_LIBRARY_DIRS=$lib_path \
    -DOPENSSL_INCLUDE_DIRS=$local/include \
    -DLIB_INSTALL_DIR=$lib_path \
    -DCMAKE_INSTALL_PREFIX=$local $bee2evp
  make -j$(nproc) && make install
  ls -la $lib_path/libbee2evp.so
}

attach_bee2evp(){
  green echo "[-] attach bee2evp"
  cp $local/openssl.cnf.dist $local/openssl.cnf
  if $is_openssl_3;
  then
    sed -i "/providers = provider\_sect/a engines = engine_sect\
\n\n[ engine_sect]\
\nbee2evp = bee2evp_section\
\n\n[ bee2evp_section ]\
\nengine_id = bee2evp\
\ndynamic_path = $lib_path/libbee2evp.so\
\ndefault_algorithms = ALL" $local/openssl.cnf
  else
    sed -i "/\[ new\_oids \]/i openssl_conf = openssl_init\
\n[ openssl_init ]\
\nengines = engine_section\
\n[ engine_section ]\
\nbee2evp = bee2evp_section\
\n[ bee2evp_section ]\
\nengine_id = bee2evp\
\ndynamic_path = $lib_path/libbee2evp.so\
\ndefault_algorithms = ALL\
\n" $local/openssl.cnf
  fi
}

test_bee2evp(){
  cd $local || exit
  cp -a $bee2evp/test/. .
  export PATH=$local/bin:$PATH
  export OPENSSL_CONF=$local/openssl.cnf
  export LD_LIBRARY_PATH="$lib_path:${LD_LIBRARY_PATH}"
  green echo "[-] test evp"
  $build_bee2evp/test/testb2e
  green echo "[-] test bee2evp"
  python3 test.py
  export LD_LIBRARY_PATH=$(echo "$LD_LIBRARY_PATH" | \
    sed -e "s|$lib_path:||")
}

setup(){
  green echo "Setup..."
  clean
  check_prereq
  check_openssl_tag
  update_repos
  patch_openssl
  green echo "Setup ended"
}

build(){
  green echo "Building..."
  build_bee2
  build_openssl
  build_bee2evp
  attach_bee2evp
  green echo "Build ended"
}

is_openssl_3

if $enable_setup; then
  setup
fi

if $enable_build; then
  build
fi

if $enable_test; then
  test_bee2evp
fi
