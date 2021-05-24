/*
*******************************************************************************
\file btls.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief BTLS ciphersuites
\created 2021.01.11
\version 2021.03.22
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
#include <openssl/rand.h>

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
	if (OBJ_new_nid(1) != NID_kxbdht)
		return 0;
	if (OBJ_new_nid(1) != NID_kxbdhe_psk)
		return 0;
	if (OBJ_new_nid(1) != NID_kxbdht_psk)
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

int btls_construct_ske_psk_bign_dhe(SSL* s, WPACKET* pkt)
{
	int ret = 1;
    size_t len = (s->cert->psk_identity_hint == NULL)
                    ? 0 : strlen(s->cert->psk_identity_hint);
	if (len > PSK_MAX_IDENTITY_LEN
            || !WPACKET_sub_memcpy_u16(pkt, s->cert->psk_identity_hint,
                                       len)) {
        SSLfatal(s, SSL_AD_INTERNAL_ERROR,
                 SSL_F_TLS_CONSTRUCT_SERVER_KEY_EXCHANGE,
                 ERR_R_INTERNAL_ERROR);
        ret = 0;
		goto err;
    }
	int sec_bits = EVP_PKEY_security_bits(
			s->cert->pkeys[SSL_PKEY_BIGN].privatekey);
	char* params_id = ((sec_bits == 128) ? "bign-curve256v1\0" :
			((sec_bits == 192) ? "bign-curve384v1\0" : "bign-curve512v1\0"));
	//ASN1_OBJECT *o = OBJ_nid2txt();
	WPACKET_sub_memcpy_u8(pkt, params_id, strlen(params_id)+1);
	ret = btls_construct_ske_bign_dhe(s, pkt);
err:
   	return ret;
}

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

int btls_process_ske_psk_bign_dhe(SSL* s, PACKET* pkt, EVP_PKEY** pkey)
{
	PACKET encoded_pt;
	PACKET params_p;
    unsigned int length;
    const unsigned char *data;
    if (!PACKET_get_1(pkt, &length) ||
        !PACKET_get_bytes(pkt, &data, (size_t)length)) {
        return 0;
    }
    int nid_curve = OBJ_ln2nid(data);
	if (s->s3->peer_tmp == 0 && (s->s3->peer_tmp = EVP_PKEY_new()) == 0)
			return 0;
	EVP_PKEY* pkey_1 = EVP_PKEY_new();
	EVP_PKEY_set_type(pkey_1, NID_bign_pubkey);

    EVP_PKEY* pkey_ = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pkey_1, NULL);
    EVP_PKEY_paramgen_init(ctx);
    EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_ALG_CTRL + 1, nid_curve, -1);
    EVP_PKEY_paramgen(ctx, &pkey_);

    if (!EVP_PKEY_copy_parameters(s->s3->peer_tmp, pkey_))
    		return 0;

	// загрузить эфемерный открытый ключ сервера
	if (!PACKET_get_length_prefixed_1(pkt, &encoded_pt)) 
		return 0;
	if (!EVP_PKEY_set1_tls_encodedpoint(s->s3->peer_tmp,
			PACKET_data(&encoded_pt),
			PACKET_remaining(&encoded_pt)))
		return 0;
	//ASN1_OBJECT *o = OBJ_nid2obj(OBJ_txt2nid(data));
	//ASN1_OBJECT *o1 = OBJ_nid2obj(s->s3->peer_tmp->type);
	//if (o1 != o) {
	//	return 0;
	//}
	// завершить
	return 1;
}

/*
*******************************************************************************
Механизм BIGN_DHT

Протокол:
 - C -> S: ClientKeyExchange[зашифрованный pre_master_secret]

Ключ pre_master_secret состоит из 48 октетов. Он генерируется клиентом с 
помощью функции RAND_bytes().

Ключ pre_master_secret зашифровывается на открытом ключе сервера из сертификата 
сервера. Зашифрование выполняется с помощью алгоритма bign-keytransport. При 
зашифровании используется нулевой заголовок ключа. В результате зашифрования 
получается токен ключа. 

Подготовка CKE: btls_construct_cke_bign_dht.
Обработка CKE: btls_process_сke_bign_dht.

Вызовы перечисленных функций встраиваются в модули ssl/statem/statem_srvr.c, 
ssl/statem/statem_clnt.c (см. обработку флага SSL_kBDHT).

todo: Клиент должен проверить установку флага keyEncipherment в расширении 
KeyUsage сертификата сервера.

todo: Можно ли взять под контроль генерацию pre_master_secret клиентом?
*******************************************************************************
*/

int btls_construct_cke_bign_dht(SSL* s, WPACKET* pkt){
	unsigned char* pms = NULL;
	size_t pms_len = 48;
	EVP_PKEY_CTX* pkey_ctx = NULL;
	X509* peer_cert;
	unsigned char* token = NULL;
	size_t token_len = 0;
	int ret = 0;
	// подготовка pms = pre_master_secret
	pms = OPENSSL_malloc(pms_len);
	if (!pms)
		goto err;
	if (!RAND_bytes(pms, pms_len))
		goto err;
	peer_cert = s->session->peer;
	if (!peer_cert)
		goto err;
	// определить server_pubkey
	pkey_ctx = EVP_PKEY_CTX_new(X509_get0_pubkey(peer_cert), NULL);
	// token <- bign_keytransport(pms, server_pubkey)
	if (!EVP_PKEY_encrypt_init(pkey_ctx))
		goto err;
	if (!EVP_PKEY_encrypt(pkey_ctx, NULL, &token_len, pms, pms_len))
		goto err;
	token = OPENSSL_malloc(token_len);
	if (!token)
		goto err;
	if (!EVP_PKEY_encrypt(pkey_ctx, token, &token_len, pms, pms_len))
		goto err;
	if (!WPACKET_sub_memcpy_u8(pkt, token, token_len))
		goto err;
	// сохранить pms
	s->s3->tmp.pms = pms;
	s->s3->tmp.pmslen = pms_len;
	pms = NULL;
	ret = 1;
err:
	if (pms)
		OPENSSL_free(pms);
	if (token)
		OPENSSL_free(token);
	if (pkey_ctx)
		EVP_PKEY_CTX_free(pkey_ctx);
	if (ret == 0)
		SSLfatal(s, SSL_AD_INTERNAL_ERROR,
			SSL_F_TLS_CONSTRUCT_CLIENT_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
	return ret;
}

int btls_process_cke_bign_dht(SSL* s, PACKET* pkt){
	EVP_PKEY* pk = NULL;
	EVP_PKEY_CTX* pkey_ctx = NULL;
	unsigned char* pms = NULL;
	size_t pms_len = 0;
	const unsigned char* token;
	unsigned int token_len;
	int ret = 0;
	// подготовить личный ключ
	pk = s->cert->pkeys[SSL_PKEY_BIGN].privatekey;
	if (pk == NULL)
		goto err;
	pkey_ctx = EVP_PKEY_CTX_new(pk, NULL);
	if (pkey_ctx == NULL)
		goto err;
	if (!EVP_PKEY_decrypt_init(pkey_ctx))
		goto err;
	// извлечь токен ключа
	if (!PACKET_get_1(pkt, &token_len) || 
		!PACKET_get_bytes(pkt, &token, token_len) || 
		PACKET_remaining(pkt) != 0)
		goto err;
	// снять защиту с токена
	if (!EVP_PKEY_decrypt(pkey_ctx, NULL, &pms_len, token, token_len) ||
		pms_len != 48)
		goto err;
	pms = (unsigned char*)OPENSSL_malloc(pms_len);
	if (!EVP_PKEY_decrypt(pkey_ctx, pms, &pms_len, token, token_len))
		goto err;
	if (!ssl_generate_master_secret(s, pms, pms_len, 0))
		goto err;
	ret = 1;
err:
	if (pkey_ctx != NULL)
		EVP_PKEY_CTX_free(pkey_ctx);
	if (pms != NULL)
		OPENSSL_free(pms);
	if (ret == 0)
		SSLfatal(s, SSL_AD_INTERNAL_ERROR,
			SSL_F_TLS_PROCESS_CLIENT_KEY_EXCHANGE,
			ERR_R_INTERNAL_ERROR);
	return ret;
}
