/*
*******************************************************************************
\file bee2prov.h
\project bee2evp [Plugin for bee2 usage in OpenSSL]
\brief Definitions and interfaces for Bee2evp provider
\created 2025.04.08
\version 2025.04.08
\copyright The Bee2evp authors
\license Licensed under the Apache License, Version 2.0 (see LICENSE.txt).
*******************************************************************************
*/

/*!
*******************************************************************************
\file bee2prov.h
\brief Определения и интерфейсы для провайдера
*******************************************************************************
*/

#ifndef __BEE2PROV_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/opensslv.h>

#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/types.h>

/*!
*******************************************************************************
\file bee2prov.h

\section Hash Алгоритмы хэширования

СТБ 34.101.31 (belt)
Реализован алгоритм belt-hash (размер хэша 256 бит)

СТБ 34.101.77-2016 (bash)
Реализованы алгоритмы семейства bash стандартных уровней стойкости 
l = 128, 192, 256. Используются названия алгоритмов, заданные в приложении Б 
к СТБ 34.101.77: к префиксу "bash" добавляется удвоенный уровень стойкости.
*******************************************************************************
*/

/* Общие функции для алгоритмов хэширования */

/*!	\brief Получить названия и типы параметров алгоритма хэширования

    Для алгоритмов хэширования поддерживаются следующие параметры:
    - blocksize - длина блока данных
    - size - размер хэш-значения
    - flags - флаги

    \todo : разобрать значения флагов

	\return Массив (таблица) параметров.
*/
const OSSL_PARAM *md_gettable_params(
    void *provctx       /*!< [in] контекст провайдера, не используется */
);

/*!	\brief Получить значения параметров алгоритма хэширования

    Заполняются значения параметров, определенных в функции md_gettable_params.
	\return Признак успеха (<= 0 в случае ошибки).
*/
int md_get_params(
    OSSL_PARAM params[],        /*!< [in,out] таблица параметров */
    unsigned int blocksize,     /*!< [in] длина блока данных */
    unsigned int size,          /*!< [in] размер хэш-значения */
    unsigned int flags          /*!< [in] флаги */
);

/* Таблицы функций алгоритмов хэширования */
extern const OSSL_DISPATCH provBeltHash_functions[];
extern const OSSL_DISPATCH provBash256_functions[];
extern const OSSL_DISPATCH provBash384_functions[];
extern const OSSL_DISPATCH provBash512_functions[];

#endif // OPENSSL_VERSION_MAJOR >= 3

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* __BEE2PROV_H */