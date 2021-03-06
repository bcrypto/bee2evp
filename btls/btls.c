/*
*******************************************************************************
\file btls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief BTLS ciphersuites
\created 2021.01.11
\version 2021.03.03
\license This program is released under the GNU General Public License 
version 3 with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
*******************************************************************************
*/

#include <crypto/evp.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include "ssl_local.h"
#include "../crypto/evp/evp_local.h"

#include "btls.h"

/*
*******************************************************************************
Алгоритм belt-mac256 для TLS

Для представления алгоритма belt-mac256 в связке BELT_CTR_MAC криптонаборов 
BTLS алгоритм belt-mac56 позиционируется ка алгоритм хэширования (MD). 
Это вынужденная мера, потому что альтернативный вариант -- AEAD -- будет 
означать, что при генерации ключевого материала ключи имитозащиты связки 
BELT_CTR_MAC не будут выделены как отдельные (см. функцию 
tls1_change_cipher_state() модуля t1_enc.c).

MD-интерфейс belt-mac256 объявлен, но не реализован. Функционал belt-mac256 
встроен в алгоритм belt-ctr-tls (TLS-версия belt-ctr). Это алгоритм объявлен 
с флагом AEAD и поэтому обращения к MD-интерфейсу belt-mac256 не используются 
(см. обработку флага EVP_CIPH_FLAG_AEAD_CIPHER в модуле t1_enc.c).

Регистрация belt-mac256 выполняется в модуле ssl_ciph.c и состоит в следующем:
- идентификатор NID_belt_mac256 добавляется в таблицу ssl_cipher_table_mac
  и связывается с флагом SSL_BELTMAC. Флаг SSL_BELTMAC устанавливается в слове 
  описания криптонабора для указания на использование belt-mac256;
- в таблице ssl_mac_pkey_id устанавливается ссылка на методы belt-mac256;
- в таблице ssl_mac_secret_size устанавливается длина ключа belt-mac256
  (32 октета).
*******************************************************************************
*/

const EVP_MD* evpMDBeltMac256()
{
	static const EVP_MD md_belt_mac256 = 
	{
		NID_belt_mac256,
    };
	return &md_belt_mac256;
}

/*
*******************************************************************************
Инициализация

\remark Для регистрации в статических массивах OpenSSL задействованные nid'ы 
должны быть статическими. Но OpenSSL не позволяет назначать nid'ы при 
регистрации oid'ов. С другой стороны, логика назначения вполне прозрачна: 
nid'ы назначаются последовательно, начиная с номера NUM_NID, указанного в 
crypto/objects/obj_dat.h. Мы учитываем эту логику, фактически предугадывая 
nid'ы.

\warning Регистрация nid'ов в btls_init() должна выполняться в том же порядке,
что и их объявление в btls.h.

\todo Покрыть переменную btls_inited  мьютексом.
*******************************************************************************
*/

static int btls_inited = 0;

int btls_init()
{
	if (btls_inited)
		return 1;
	if (OBJ_create("1.2.112.0.2.0.34.101.45.2.1", 
		"bign-pubkey", "bign-pubkey") != NID_bign_pubkey)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.31.81", 
		"belt-hash", "belt-hash") != NID_belt_hash)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.31.67",
		"belt-dwp-tls", "belt-dwp-tls") != NID_belt_dwpt)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.31.44", 
		"belt-ctr-tls", "belt-ctr-tls") != NID_belt_ctrt)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.31.53", 
		"belt-mac256", "belt-mac256") != NID_belt_mac256)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.45.12", 
		"bign-with-hbelt", "bign-with-hbelt") != NID_bign_with_hbelt)
		return 0;
	if (OBJ_create("1.2.112.0.2.0.34.101.45.3.1", 
		"bign-curve256v1", "bign-curve256v1") != NID_bign_curve256v1)
		return 0;
	if (OBJ_new_nid(1) != NID_kxbdhe)
		return 0;
	if (OBJ_new_nid(1) != NID_bign128_auth)
		return 0;
	if (!EVP_add_digest(evpMDBeltMac256()))
		return 0;
	btls_inited++;
	return 1;
}

/*
*******************************************************************************
Механизм BIGN_DHE

Протокол:
 - S -> C: ServerKeyExchange[подписанный эфемерный ключ ДХ]
 - S <- C: ClientKeyExchange[эфемерный ключ ДХ]

\remark ДХ = "Диффи -- Хеллмана".

Ключи ДХ лежат на той же эллиптической кривой, что и открытый ключ сертификата 
сервера. Для сравнения, в механизме ECDHE используется кривая, не обязательно 
связанная с сертификатом. Номер кривой передается в ServerKeyExchange. 
Отличия BIGN_DHE от ECDHE незначительны, и мы пользуемся этим, минимально 
отступая от кода OpenSSL.

Подготовка SKE: btls_construct_ske_bign_dhe
Обработка SKE: btls_process_ske_bign_dhe (на основе tls_process_ske_ecdhe)

Подготовка CKE: tls_construct_cke_ecdhe (стандартная функция)
Обработка CKE: tls_process_cke_ecdhe (стандартная функция)

Вызовы перечисленных функций встраиваются в модули ssl/statem/statem_srvr.c, 
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHE).
*******************************************************************************
*/
int btls_construct_ske_bign_dhe(SSL* s, WPACKET* pkt)
{
	EVP_PKEY_CTX* ctx = NULL;
    EVP_PKEY* pk = NULL;
    unsigned char* pk_val = NULL;
    size_t pk_len = 0;
    int  ret = 1;
	// получить ключ сертификата
    EVP_PKEY* pkey = s->cert->pkeys[SSL_PKEY_BIGN].privatekey;
	if (!pkey)
	{
		ret = 0;
		goto err;
	}
	// сгенерировать ключ ДХ
	if (s->s3->tmp.pkey != NULL ||
		(ctx = EVP_PKEY_CTX_new(pkey, NULL)) == NULL ||
		!EVP_PKEY_keygen_init(ctx) || 
		!EVP_PKEY_keygen(ctx, &pk))
	{
		ret = 0;
		goto err;
	}
	// записать ключ ДХ
	if (!EVP_PKEY_get_raw_public_key(pk, NULL, &pk_len) ||
		!(pk_val = OPENSSL_malloc(pk_len)) ||
		!EVP_PKEY_get_raw_public_key(pk, pk_val, &pk_len) ||
		!WPACKET_sub_memcpy_u8(pkt, pk_val, pk_len))
	{
		ret = 0;
		goto err;
	}
	// запомнить ключ ДХ
	s->s3->tmp.pkey = pk;
	pk = NULL;
err:
   	 EVP_PKEY_CTX_free(ctx);
   	 EVP_PKEY_free(pk);
     if (pk_val) 
	 {
    	 OPENSSL_cleanse(pk_val, pk_len);
    	 OPENSSL_free(pk_val);
     }
     if (ret == 0)
    	SSLfatal(s, SSL_AD_INTERNAL_ERROR,
    		SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
	return ret;
}

int btls_process_ske_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey)
{
	PACKET encoded_pt;
	// определить статический открытый ключ сервера
	if ((*pkey = X509_get0_pubkey(s->session->peer)) == 0)
		return 0;
	// загрузить параметры открытого ключа сервера
	if (s->s3->peer_tmp == 0 && (s->s3->peer_tmp = EVP_PKEY_new()) == 0)
			return 0;
	if (!EVP_PKEY_copy_parameters(s->s3->peer_tmp, *pkey))
		return 0;
	// загрузить эфемерный открытый ключ сервера
	if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) 
		return 0;
	if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
			PACKET_data(&encoded_pt),
			PACKET_remaining(&encoded_pt)))
		return 0;
	// завершить
	return 1;
}
