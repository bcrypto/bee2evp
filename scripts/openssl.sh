
scripts_dir="$( dirname "${BASH_SOURCE[0]}" )"
bee2evp=$(cd $scripts_dir/../../bee2evp && pwd)
build_root=$bee2evp/build
local=${BEE2EVP_INSTALL_DIR:-$build_root/local}
lib_path=$local/lib

run_bee2prv(){
  export PATH=$local/bin:$PATH
  export OPENSSL_CONF=$local/openssl.cnf
  export LD_LIBRARY_PATH="$lib_path:${LD_LIBRARY_PATH}"
  echo "[-] run openssl"
  $local/bin/openssl $@
}
run_bee2prv $@