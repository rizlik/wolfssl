/* psa.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_HAVE_PSA)

#include <wolfssl/wolfcrypt/psa/crypto.h>

#if !defined(NO_AES)
#include <wolfssl/wolfcrypt/aes.h>
#endif

static psa_key_attributes_t zero_key_attribute;
static int psa_initialized;
static psa_key_id_t psa_incremental_id;

/* max number of keys that can be used */
#define PSA_KEY_SLOTS 6

/** struct wc_psa_key
 * @attr: attributes of a key
 * @key: wolfssl native key used
 */
struct wc_psa_key {
    psa_key_attributes_t attr;
    void *key;
};

static wolfSSL_Mutex psa_key_slots_lock;
static struct wc_psa_key wc_psa_key_slots[PSA_KEY_SLOTS];

static struct wc_psa_key *psa_find_key(psa_key_id_t id)
{
    struct wc_psa_key *k;
    int i;

    if (id == PSA_KEY_ID_NULL)
        return NULL;

    if (id < PSA_KEY_ID_USER_MIN || id > PSA_KEY_ID_USER_MAX)
        return NULL;

    for (i = 0; i < PSA_KEY_SLOTS; ++i) {
        k = &wc_psa_key_slots[i];
        if (k->attr.id == id)
            return k;
    }

    return NULL;
}

static psa_key_id_t psa_get_new_id(void)
{
    int err;

    err = wc_LockMutex(&psa_key_slots_lock);
    if (err != 0)
        return PSA_KEY_ID_NULL;
    psa_incremental_id++;
    err = wc_UnLockMutex(&psa_key_slots_lock);

    if (psa_incremental_id > PSA_KEY_ID_USER_MAX)
        return PSA_KEY_ID_NULL;

    return psa_incremental_id;
}

static struct wc_psa_key *psa_find_free_slot(void)
{
    struct wc_psa_key *k;
    int err;
    int i;

    err = wc_LockMutex(&psa_key_slots_lock);
    if (err != 0)
        return NULL;

    for (i = 0; i < PSA_KEY_SLOTS; ++i) {
        k = &wc_psa_key_slots[i];
        if (k->attr.id == PSA_KEY_ID_NULL) {
            k->attr.id = PSA_KEY_ID_BUSY;
            wc_UnLockMutex(&psa_key_slots_lock);
            return k;
        }
    }

    wc_UnLockMutex(&psa_key_slots_lock);
    return NULL;
}

psa_key_attributes_t psa_key_attributes_init()
{
    return zero_key_attribute;
}

psa_status_t psa_crypto_init()
{
    int err;
    err = wc_InitMutex(&psa_key_slots_lock);
    if (err != 0)
        return PSA_ERROR_BAD_STATE;

    psa_initialized = 1;
    return PSA_SUCCESS;
}


psa_status_t psa_get_key_attributes(psa_key_id_t key,
                                    psa_key_attributes_t *attributes)
{
    struct wc_psa_key *_key;

    if (attributes == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    /* as for specs, clear attributes on failure  */
    psa_reset_key_attributes(attributes);

    if (psa_initialized == 0)
        return PSA_ERROR_BAD_STATE;

    _key = psa_find_key(key);
    if (_key == NULL)
        return PSA_ERROR_INVALID_HANDLE;

    XMEMCPY(attributes, &_key->attr, sizeof(*attributes));

    return PSA_SUCCESS;
}

void psa_reset_key_attributes(psa_key_attributes_t *attributes)
{
    if (attributes == NULL)
        return;

    XMEMSET(attributes, 0, sizeof(*attributes));
}


#if !defined(NO_AES)
static psa_status_t psa_aes_import_key(const psa_key_attributes_t *attributes,
                                       const uint8_t *data,
                                       size_t data_length,
                                       psa_key_id_t *key)
{
    struct wc_psa_key *k;
    psa_key_id_t key_id;
    psa_status_t ret;
    uint8_t *aes_key;

    if (data_length != AES_128_KEY_SIZE &&
        data_length != AES_192_KEY_SIZE &&
        data_length != AES_256_KEY_SIZE)
        return PSA_ERROR_INVALID_ARGUMENT;

    if (attributes->bits != 0 && attributes->bits != data_length * 8)
        return PSA_ERROR_INVALID_ARGUMENT;

    aes_key = XMALLOC(data_length, NULL, DYNAMIC_TYPE_AES);
    if (aes_key == NULL)
        return PSA_ERROR_INSUFFICIENT_MEMORY;

    key_id = psa_get_new_id();
    if (key_id == PSA_KEY_ID_NULL) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    XMEMCPY(aes_key, data, data_length);

    k = psa_find_free_slot();
    if (k == NULL) {
        ret = PSA_ERROR_BAD_STATE;
        goto out_free;
    }

    k->key = aes_key;
    k->attr.type = attributes->type;
    k->attr.bits = data_length * 8;
    k->attr.lifetime = attributes->lifetime;
    k->attr.usage_flags = attributes->usage_flags;
    k->attr.permitted_algs = attributes->permitted_algs;

    *key = key_id;
    k->attr.id = key_id;

    return PSA_SUCCESS;

out_free:
    free(aes_key);
    return ret;
}
#endif

psa_status_t psa_import_key(const psa_key_attributes_t *attributes,
                            const uint8_t *data,
                            size_t data_length,
                            psa_key_id_t *key)
{
    psa_key_type_t type;

    if (psa_initialized != 1)
        return PSA_ERROR_BAD_STATE;

    *key = PSA_KEY_ID_NULL;

   if (attributes == NULL)
        return PSA_ERROR_INVALID_ARGUMENT;

    type = attributes->type;
    if (type == PSA_KEY_TYPE_NONE)
        return PSA_ERROR_NOT_SUPPORTED;

    if (!PSA_KEY_LIFETIME_IS_VOLATILE(attributes->lifetime))
        return PSA_ERROR_NOT_SUPPORTED;

#if !defined(NO_AES)
    if (type == PSA_KEY_TYPE_AES)
        return psa_aes_import_key(attributes, data, data_length, key);
#endif

    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_destroy_key(psa_key_id_t key)
{
    struct wc_psa_key *k;

    if (psa_initialized != 1)
        return PSA_ERROR_BAD_STATE;

    if (key == PSA_KEY_ID_NULL)
        return PSA_SUCCESS;

    k = psa_find_key(key);
    if (k == NULL)
        return PSA_ERROR_INVALID_HANDLE;

#if !defined(NO_AES)
    if (k->attr.type == PSA_KEY_TYPE_AES) {
        free(k->key);
        psa_reset_key_attributes(&k->attr);
        return PSA_SUCCESS;
    }
#endif

    return PSA_ERROR_BAD_STATE;
}

#endif
