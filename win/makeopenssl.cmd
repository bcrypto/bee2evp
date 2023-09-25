@echo off
rem ===========================================================================
rem \brief Сборка OpenSSL[bee2evp]
rem \project bee2evp
rem \created 2021.06.09
rem \version 2023.09.25
rem \pre Данный файл размещен в папке bee2evp\some_folder
rem \pre Исходные тексты openssl размещены в папке bee2evp\openssl (..\openssl)
rem \pre Следует настроить путь VSPATH к средствам разработки Visual Studio
rem \pre Следует настроить путь DISTRIB к выходным бинарным файлам
rem \usage makeopenssl {debug32|release32|debug64|release64}
rem ===========================================================================

@echo off

set VSPATH="C:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\VC\Auxiliary\Build"
set DISTRIB="..\win\vs15\distrib\"

if .%1. equ .debug32. (
  set VARS_OPT=x86
  set CONF_OPT=debug-VC-WIN32
) else if .%1. equ .debug64. (
  set VARS_OPT=amd64
  set CONF_OPT=debug-VC-WIN64A
) else if .%1. equ .release32. (
  set VARS_OPT=x86
  set CONF_OPT=VC-WIN32
) else if .%1. equ .release64. (
  set VARS_OPT=amd64
  set CONF_OPT=VC-WIN64A
) else (
  echo "Usage: makeopenssl {debug32|release32|debug64|release64}"
  exit
)

echo Config = %1%
echo VARS_OPT = %VARS_OPT%
echo CONF_OPT = %CONF_OPT%

md ..\build
cd ..\build

rem target options: {x86|amd64|x64|ia64|x86_amd64|x86_ia64}
call %VSPATH%\vcvarsall.bat %VARS_OPT%

rem target options: {debug-VC-WIN32|VC-WIN32|debug-VC-WIN64A|VC-WIN64A}
rem additional options: no-asm
rem linkage options: {/MT|/MTd|/MD|/MDd}
perl ..\openssl\Configure %CONF_OPT%
perl -pi -e "s/MD/MT/g" makefile

nmake
rem nmake test
rem nmake install

md %DISTRIB%\%1%
copy libcrypto*.* %DISTRIB%\%1%
copy libssl*.* %DISTRIB%\%1%
copy apps\openssl.exe %DISTRIB%\%1%
md %DISTRIB%\%1%\openssl
copy include\openssl\opensslconf.h %DISTRIB%\%1%\openssl
