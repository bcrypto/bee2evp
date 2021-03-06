/*
*******************************************************************************
\file info.h
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Common info
\created 2012.04.01
\version 2019.05.23
\license This program is released under the GNU General Public License 
version 3 with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
*******************************************************************************
*/

/*!
*******************************************************************************
\file info.h
\brief Общая информация
*******************************************************************************
*/


#ifndef __BEE2EVP_INFO
#define __BEE2EVP_INFO

#define BEE2EVP_NAME			"Bee2evp"
#define BEE2EVP_VERSION_MAJOR	"1"
#define BEE2EVP_VERSION_MINOR 	"0"
#define BEE2EVP_VERSION_PATCH	"6"

#define BEE2EVP_VERSION\
		BEE2EVP_VERSION_MAJOR "." BEE2EVP_VERSION_MINOR "." BEE2EVP_VERSION_PATCH

#define BEE2EVP_VERSION_NUM\
		1, 0, 6

/*!
*******************************************************************************
\mainpage Криптографический плагин Bee2evp для OpenSSL

\version 1.0.4

\section toc Содержание

-#	\ref descr
-#	\ref make
-#	\ref license

\section descr Описание

Библиотека bee2evp является плагином (engine) популярной криптографической 
библиотеки OpenSSL. Плагин предоставляет криптографические сервисы библиотеки 
bee2 по интерфейсу EVP.

\section make Сборка

Подготовка конфигурационных файлов:

\verbatim
mkdir build
cd build
cmake  ..
\endverbatim

Конфигурация отладочной версии:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Debug ..
\endverbatim

Конфигурация со средствами мониторинга покрытия:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Coverage ..
\endverbatim

Конфигурация со средствами проверки адресов (AddressSanitizer):

\verbatim
cmake -DCMAKE_BUILD_TYPE=ASan ..
cmake -DCMAKE_BUILD_TYPE=ASanDbg ..
\endverbatim

Конфигурация со средствами проверки памяти (MemorySanitizer):

\verbatim
cmake -DCMAKE_BUILD_TYPE=MemSan ..
cmake -DCMAKE_BUILD_TYPE=MemSanDbg ..
\endverbatim

Конфигурация со строгой компиляцией:

\verbatim
cmake -DCMAKE_BUILD_TYPE=Check ..
\endverbatim

Сборка:

\verbatim
make
\endverbatim

Установка:

\verbatim
make install
\endverbatim

\section license Лицензия

Библиотека распространяется на условиях GNU General Public License версии 3
(GNU GPL v3) с дополнительным разрешением на использование библиотеки 
OpenSSL.

\verbatim

Bee2evp: a cryptographic plugin (engine) for OpenSSL
Copyright (c) 2013-2019, Bee2evp authors

This file is part of Bee2evp. Bee2evp is legal property of its developers,
whose names are not listed here. Please refer to source files for contact 
information. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

\endverbatim

\verbatim

====================================================================
Copyright (c) 1998-2019 The OpenSSL Project.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions
are met:

1. Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in
   the documentation and/or other materials provided with the
   distribution.

3. All advertising materials mentioning features or use of this
   software must display the following acknowledgment:
   "This product includes software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit. (http://www.openssl.org/)"

4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
   endorse or promote products derived from this software without
   prior written permission. For written permission, please contact
   openssl-core@openssl.org.

5. Products derived from this software may not be called "OpenSSL"
   nor may "OpenSSL" appear in their names without prior written
   permission of the OpenSSL Project.

6. Redistributions of any form whatsoever must retain the following
   acknowledgment:
   "This product includes software developed by the OpenSSL Project
   for use in the OpenSSL Toolkit (http://www.openssl.org/)"

THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
OF THE POSSIBILITY OF SUCH DAMAGE.
====================================================================

This product includes cryptographic software written by Eric Young
(eay@cryptsoft.com).  This product includes software written by Tim
Hudson (tjh@cryptsoft.com).

\endverbatim

*******************************************************************************
*/

#endif // __BEE2EVP_INFO
