/*
*******************************************************************************
\file bee2evp.c
\project bee2evp [EVP-interfaces over bee2 / engine of OpenSSL]
\brief Registration of bee2evp in OpenSSL
\created 2014.11.06
\version 2021.01.27
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
Интерфейс плагина

\remark Команды не обрабатываются
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
	return 1;
}

static int bee2evp_destroy(ENGINE* e)
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
