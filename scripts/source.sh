#!/bin/bash
# *****************************************************************************
# \file source.sh
# \project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
# \brief Reusable script code
# \created 2020.07.10
# \version 2025.11.13
# \copyright The Bee2evp authors
# \license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
# *****************************************************************************

set -eo pipefail

green () { printf "\e[32m" ; $@ ; printf "\e[0m"; }
red () { printf "\e[31m" ; $@ ; printf "\e[0m"; }

usage() {
  echo "Usage: $0 [OPTIONS] <openssl_tag>"
  echo ""
  echo "  --build-type    build type: |Debug|Release|Coverage|"
  echo "  -d, --debug     enable debug mode"
  echo "  -s,             setup"
  echo "  -b,             build (=bb+bo+be)"
  echo "  -bb,             build Bee2"
  echo "  -bo,             build OpenSSL" 
  echo "  -be,             build Bee2evp"
  echo "  -t,             test"
  echo "  -h, --help      display this help and exit"
  exit 1
}

default_opt() {
  build_type=Release
  enable_setup=false
  enable_build=false
  enable_bee2=false
  enable_bee2evp=false
  enable_openssl=false
  enable_test=false
  openssl_tag=""
}

parse_opt() {
  case $1 in
    --build-type=*)
      build_type="${1#*=}"
      case "$build_type" in
        Debug|Release|Coverage)
          # Valid value, continue
          ;;
        *)
          echo "received build type: $build_type"
          red echo "--build-type must be one of: Release, Debug, Coverage"
          exit 1
          ;;
      esac
      ;;
    -d|--debug)
      build_type=Debug
      ;;
    -s)
      enable_setup=true
      ;;
    -t)
      enable_test=true
      ;;
    -b)
      enable_build=true
      ;;
    -bb)
      enable_bee2=true
      ;;
    -bo)
      enable_openssl=true
      ;;
    -be)
      enable_bee2evp=true
      ;;
    -h|--help)
      ;;
    -*)
      red echo "invalid option -- $1" >&2
      usage
      ;;
    *)
      if [[ ! -z "$1" ]]; then
        openssl_tag="$1"
      else
        usage
      fi
      ;;
  esac
}

check_opt() {
  if [[ -z "$openssl_tag" ]]; then
    red echo "openssl tag name is required" >&2
    usage
  fi
  if $enable_build; then
    enable_bee2=true
    enable_openssl=true
    enable_bee2evp=true
  else
    if [[ $enable_bee2 == true || $enable_openssl == true || \
        $enable_bee2evp == true ]]; then
      enable_build=true
    fi
  fi

  echo "build_type=$build_type"
  echo "openssl_tag=$openssl_tag"
}

# Check openssl major version
is_openssl_3() {
  is_openssl_3=false
  if [[ "$openssl_tag" =~ .*[-_]([0-9]).* ]];
  then
    openssl_major_version="${BASH_REMATCH[1]}"
  fi

  if [[ "$openssl_major_version" = "3" ]];
  then
    is_openssl_3=true
  fi
}

set_dir(){
  scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
  bee2evp=$(cd $scripts_dir/../ && pwd)
  build_root=$bee2evp/build
  bee2=$bee2evp/bee2
  openssl=$bee2evp/openssl
  build_bee2evp=$build_root/bee2evp
  build_bee2=$build_root/bee2
  build_openssl=$build_root/openssl
  local=${BEE2EVP_INSTALL_DIR:-$build_root/local}
  lib_path=$local/lib
  openssl_git_url=https://github.com/openssl/openssl.git
}

system_opt(){
  ossl_config=""
  lib_name=libbee2evp.so

  os_name=$(uname -s)
  arch=$(uname -m)

  echo "System detection: OS=$os_name, Arch=$arch"
    
  case "$os_name" in
    Linux)
      # Linux distribution detection
      ossl_config="linux-$arch"
      ;;
    Darwin)
      # macOS detection
      lib_name=libbee2evp.dylib
      ossl_config="darwin64-$arch-cc"
      ;;
    CYGWIN*|MINGW*|MSYS*)
      # Windows via Cygwin/MSYS2/MinGW
      lib_name=bee2evp.dll
      ossl_config="mingw64"
      ;;
    *)
      # Fallback for unknown systems      
      echo "Unknown system. Default settings are used."
      ;;
  esac
}

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
    btls_srcs_path=$bee2evp/btls
    cat $btls_srcs_path/objects.txt >> $openssl/crypto/objects/objects.txt
  else  
    btls_srcs_path=$bee2evp/btls/legacy
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
    -DCMAKE_INSTALL_LIBDIR=$lib_path $bee2
  make -j$(nproc) && make install
  ls -la $lib_path/*bee2_static.*
}

build_openssl(){
  green echo "[-] build openssl"
  mkdir -p $build_openssl && cd $build_openssl
  ossl_opt="shared --prefix=$local --openssldir=$local --libdir=lib"
  if [[ "$build_type" -eq "Debug" ]]; then
    $openssl/Configure $ossl_config $ossl_opt --debug
  else
    $openssl/Configure $ossl_config $ossl_opt
  fi

  if $is_openssl_3;
  then
    make update
  fi
  make -j$(nproc) all
  make install > build.log 2>&1 || (cat build.log && exit 1)
  ls -la $lib_path/*crypto.*
  ls -la $lib_path/*ssl.*
  ls -la $local/bin/openssl*
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
    -DCMAKE_INSTALL_LIBDIR=$lib_path \
    -DCMAKE_INSTALL_PREFIX=$local $bee2evp
  make -j$(nproc) && make install
  ls -la $lib_path/$lib_name
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
\ndynamic_path = $lib_path/$lib_name\
\ndefault_algorithms = ALL" $local/openssl.cnf
  else
    sed -i "/\[ new\_oids \]/i openssl_conf = openssl_init\
\n[ openssl_init ]\
\nengines = engine_section\
\n[ engine_section ]\
\nbee2evp = bee2evp_section\
\n[ bee2evp_section ]\
\nengine_id = bee2evp\
\ndynamic_path = $lib_path/$lib_name\
\ndefault_algorithms = ALL\
\n" $local/openssl.cnf
  fi
}

test_bee2evp(){
  green echo "[-] test bee2evp"
  cd $local || exit
  cp -a $bee2evp/test/. .
  export PATH=$local/bin:$PATH
  export OPENSSL_CONF=$local/openssl.cnf
  export LD_LIBRARY_PATH="$lib_path:${LD_LIBRARY_PATH}"
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
  if $enable_bee2; then
    build_bee2
  fi
  if $enable_openssl; then
    build_openssl
  fi
  if $enable_bee2evp; then
    build_bee2evp
    attach_bee2evp
  fi  
  green echo "Build ended"
}
