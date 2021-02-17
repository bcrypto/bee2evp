/*
*******************************************************************************
\file bee2evp.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Registration of bee2evp in OpenSSL
\created 2014.11.06
\version 2021.02.17
\license This program is released under the GNU General Public License 
version 3 with the additional exemption that compiling, linking, 
and/or using OpenSSL is allowed. See Copyright Notices in bee2evp/info.h.
*******************************************************************************
*/

#include <openssl/crypto.h>
#include <openssl/objects.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <bee2/core/mem.h>
#include <bee2/core/mt.h>
#include <bee2/core/rng.h>
#include <bee2/core/str.h>
#include <bee2/core/util.h>
#include "bee2evp/bee2evp.h"
#include "bee2evp_lcl.h"

/*
*******************************************************************************
Реквизиты библиотеки bee2evp
*******************************************************************************
*/

const char SN_bee2evp[] = "bee2evp";
const char LN_bee2evp[] = "Bee2evp Engine [belt + bign + bash]";

/*
*******************************************************************************
Блобы

В структуре EVP_MD_CTX реализация запрашивает под указатель память объема
sizeof(blob_t)  размещает в выделенной памяти объект типа blob_t,
фактически еще один указатель. Так сделано потому, что set-доступ к указателю
на пользовательские данные (md_data) закрыт.

В структуре EVP_CIPHER_CTX set-доступ к указателю на пользовательские данные
(cipher_data) открыт и реализация проще.

\warning OpenSSL не всегда гарантирует выделение памяти под указатель
EVP_MD_CTX::md_data, который возвращается функцией EVP_MD_CTX_md_data()
(см. EVP_MD_CTX_copy_ex() при установке флага EVP_MD_CTX_FLAG_REUSE).
Поэтому указатель проверяется перед обращением к памяти, на которую он
ссылается.

\remark При копировании структур EVP_MD_CTX сначала механически копируются
пользовательские данные md_data, в том числе блобы. Механическое копирование
указателей приводит к ошибкам освобождения памяти. Поэтому в
EVP_MD_CTX_copy_blob() совпадение блобов проверяется. При совпадении создается
новая копия копируемого блоба. Похожая логика реализована в
EVP_CIPHER_CTX_copy_blob(), хотя в ней, по-видимому, нет необходимости.
*******************************************************************************
*/

blob_t EVP_CIPHER_CTX_get_blob(const EVP_CIPHER_CTX* ctx)
{
	return (blob_t)EVP_CIPHER_CTX_get_cipher_data(ctx);
}

int EVP_CIPHER_CTX_set_blob(EVP_CIPHER_CTX* ctx, const blob_t blob)
{
	EVP_CIPHER_CTX_set_cipher_data(ctx, blob);
	return 1;
}

int EVP_CIPHER_CTX_copy_blob(EVP_CIPHER_CTX* to, const EVP_CIPHER_CTX* from)
{
	blob_t blob_from = EVP_CIPHER_CTX_get_blob(from);
	blob_t blob_to = EVP_CIPHER_CTX_get_blob(to);
	blob_to = blobCopy(blob_from == blob_to ? 0 : blob_to, blob_from);
	if (blob_from && !blob_to)
		return 0;
	return EVP_CIPHER_CTX_set_blob(to, blob_to);
}

blob_t EVP_MD_CTX_get_blob(const EVP_MD_CTX* ctx)
{
	if (EVP_MD_CTX_md_data(ctx))
		return *(blob_t*)EVP_MD_CTX_md_data(ctx);
	return 0;
}

int EVP_MD_CTX_set_blob(EVP_MD_CTX* ctx, const blob_t blob)
{
	if (EVP_MD_CTX_md_data(ctx))
	{
		*(blob_t*)EVP_MD_CTX_md_data(ctx) = blob;
		return 1;
	}
	return 0;
}

int EVP_MD_CTX_copy_blob(EVP_MD_CTX* to, const EVP_MD_CTX* from)
{
	blob_t blob_from, blob_to;
	// блоб нельзя скопировать?
	if (EVP_MD_CTX_md_data(from) && !EVP_MD_CTX_md_data(to))
		return 0;
	// копировать
	blob_from = EVP_MD_CTX_get_blob(from);
	blob_to = EVP_MD_CTX_get_blob(to);
	blob_to = blobCopy(blob_from == blob_to ? 0 : blob_to, blob_from);
	if (blob_from && !blob_to)
		return 0;
	// установить
	return EVP_MD_CTX_set_blob(to, blob_to);
}

/*
*******************************************************************************
Интерфейс плагина

\remark Выдержка из https://eprint.iacr.org/2018/354:
- the bind() method is called by the OpenSSL built-in dynamic ENGINE upon
  load and is used to set the internal state of the ENGINE object and allocate
  needed resources, to set its id and name, and the pointers to the init(),
  finish(), and destroy() functions;
- the init() function is called to derive a fully initialized functional
  reference to the ENGINE from a structural reference;
- the finish() function is called when releasing an ENGINE functional
  reference, to free up any resource allocated to it;
- the destroy() function is called upon unloading the ENGINE, when the last
  structural reference to it is released, to cleanly free any resource
  allocated upon loading it into memory.
*******************************************************************************
*/

static int bee2evp_init(ENGINE* e)
{ 
	if (rngCreate(0, 0) != ERR_OK)
		return 0;
	return 1;
}

static int bee2evp_finish(ENGINE* e)
{ 
	evpBeltCipher_destroy();
	evpBeltMD_destroy();
	evpBelt_pmeth_destroy();
	evpBelt_ameth_destroy();
	evpBeltPBKDF_destroy();
	evpBeltTLS_destroy();
	evpBign_pmeth_destroy();
	evpBign_ameth_destroy();
	evpBash_destroy();
	rngClose();
	return 1;
}

static int bee2evp_destroy(ENGINE* e)
{ 
		return 1;
}

static const ENGINE_CMD_DEFN bee2evp_cmd_defns[] = 
{
	{0, 0, 0, 0},
};

static int bee2evp_ctrl(ENGINE* e, int cmd, long i, void* p, void (*f)(void))
{
	return 0;
}

/*
*******************************************************************************
Связывание

\remark Алгоритмы NID_bign_with_hspec, NID_bign_with_hbelt, 
NID_bign_with_bashXXX связываются с неопределенными алгоритмами хэширования. 
При этом навязывается вызов функций интерфейса 
EVP_PKEY_ASN1_METHOD::item_verify() и, как следствие, проверка параметров 
алгоритмов ЭЦП (см. комментарии к функции evpBign_item_verify()).
*******************************************************************************
*/

static int bee2evp_bind(ENGINE* e, const char* id)
{
	// другой идентификатор?
	if (id && strCmp(id, SN_bee2evp) != 0)
		return 0;
	// настроить плагин
	if (!ENGINE_set_id(e, SN_bee2evp) ||
		!ENGINE_set_name(e, LN_bee2evp) ||
		!ENGINE_set_init_function(e, bee2evp_init) ||
		!ENGINE_set_finish_function(e, bee2evp_finish) ||
		!ENGINE_set_destroy_function(e, bee2evp_destroy) ||
		!ENGINE_set_cmd_defns(e, bee2evp_cmd_defns) ||
		!ENGINE_set_ctrl_function(e, bee2evp_ctrl))
		return 0;
	// встроить модули
	if (!evpBeltCipher_bind(e) ||
		!evpBeltMD_bind(e) ||
		!evpBelt_ameth_bind(e) ||
		!evpBelt_pmeth_bind(e) ||
		!evpBeltPBKDF_bind(e) ||
		!evpBeltTLS_bind(e) ||
		!evpBign_ameth_bind(e) ||
		!evpBign_pmeth_bind(e) ||
		!evpBash_bind(e))
		return 0;
	// связать хэш + ЭЦП
	if (!OBJ_add_sigid(NID_bign_with_hbelt, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash256, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash384, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_bash512, NID_undef, NID_bign_pubkey) ||
		!OBJ_add_sigid(NID_bign_with_hspec, NID_undef, NID_bign_pubkey))
		return 0;
	// связать belt-pbkdf + belt-hmac
	if (!EVP_PBE_alg_add_type(EVP_PBE_TYPE_PRF, NID_belt_hmac, -1, 
		NID_belt_hash, evpBeltPBKDF_keyivgen))
		return 0;
	// все нормально
	return 1;
}

/*
*******************************************************************************
Загрузка в среде OpenSSL
*******************************************************************************
*/

#ifndef OPENSSL_NO_DYNAMIC_ENGINE
	IMPLEMENT_DYNAMIC_CHECK_FN()
	IMPLEMENT_DYNAMIC_BIND_FN(bee2evp_bind)
#endif

static ENGINE* ENGINE_bee2evp()
{
	ENGINE* ret = ENGINE_new();
	if(ret == 0)
		return 0;
	if (!bee2evp_bind(ret, SN_bee2evp))
	{
		ENGINE_free(ret);
		return 0;
	}
	return ret;
}

void ENGINE_load_bee2evp()
{
	ENGINE* e = ENGINE_bee2evp();
	if (e)
	{
		ENGINE_add(e);
		ENGINE_free(e);
		ERR_clear_error();
	}
}
