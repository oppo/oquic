/* ====================================================================
 *
 *
 *   BSD LICENSE
 *
 *   Copyright(c) 2021 Intel Corporation.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * ====================================================================
 */

/*****************************************************************************
 * @file qat_bssl.c
 *
 * This file provides and interface for undefined OpenSSL APIs in BoringSSL
 *
 *****************************************************************************/

/* macros defined to allow use of the cpu get and set affinity functions */
#ifndef _GNU_SOURCE
# define _GNU_SOURCE
#endif

#ifndef __USE_GNU
# define __USE_GNU
#endif

#ifdef QAT_BORINGSSL
# include <string.h>

# include "qat_bssl.h"
# include "e_qat.h"
# include "qae_mem_utils.h"
# include <openssl/rsa.h>
# include <openssl/base.h>
# include <openssl/ssl.h>
# include <openssl/rand.h>

ENGINE_QAT_PTR_DEFINE

/* Refers to openssl/crypto/rsa/rsa_local.h */
typedef struct bssl_rsa_app_data {
    char *name;
    int (*rsa_pub_enc) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_pub_dec) (int flen, const unsigned char *from,
                        unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_enc) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
    int (*rsa_priv_dec) (int flen, const unsigned char *from,
                         unsigned char *to, RSA *rsa, int padding);
} BSS_RSA_APPDATA;

static RSA_METHOD *qat_rsa_method = NULL;
static RSA_METHOD *qat_rsa_bsslmd = NULL;

RSA_METHOD *RSA_meth_new(const char *name, int flags)
{
    RSA_METHOD *meth = OPENSSL_zalloc(sizeof(*meth));

    if (meth != NULL) {
        /* Initilize qat_rsa_bsslmd */
        BSS_RSA_APPDATA *appd = OPENSSL_zalloc(sizeof(*appd));
        if (appd != NULL) {
            qat_rsa_bsslmd = meth;
            qat_rsa_bsslmd->app_data = appd;
        }

        /* Initilize qat_rsa_method and return new meth */
        if (NULL != (meth = OPENSSL_zalloc(sizeof(*meth)))) {
            meth->flags = flags;

            appd = OPENSSL_zalloc(sizeof(*appd));
            if (appd != NULL) {
                meth->app_data = appd;
                qat_rsa_method = meth;
                return meth;
            }
            OPENSSL_free(meth);
        }
        OPENSSL_free(qat_rsa_bsslmd);
    }

    return NULL;
}

void RSA_meth_free(RSA_METHOD *meth)
{
    if (meth != NULL) {
        OPENSSL_free(meth->app_data);
        OPENSSL_free(meth);
        OPENSSL_free(qat_rsa_bsslmd->app_data);
        OPENSSL_free(qat_rsa_bsslmd);
        qat_rsa_method = NULL;
        qat_rsa_bsslmd = NULL;
    }
}

const RSA_METHOD *RSA_PKCS1_BSS(void)
{
    return qat_rsa_method;
}

const RSA_METHOD *RSA_PKCS1_OpenSSL()
{
    return qat_rsa_bsslmd;
}

static int bssl_rsa_priv_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    return RSA_private_encrypt(flen, from, to, rsa, padding);
}
static int bssl_rsa_priv_dec(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    return RSA_private_decrypt(flen, from, to, rsa, padding);
}

static int bssl_rsa_pub_enc(int flen, const unsigned char *from,
                            unsigned char *to, RSA *rsa, int padding)
{
    return RSA_public_encrypt(flen, from, to, rsa, padding);
}

static int bssl_rsa_pub_dec(int flen, const unsigned char *from,
                           unsigned char *to, RSA *rsa, int padding)
{
    return RSA_public_decrypt(flen, from, to, rsa, padding);
}

int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    if (meth) {
        BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
        return appd->rsa_pub_enc;
    }

    return 0;
}

int RSA_meth_set_pub_enc(RSA_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
    appd->rsa_pub_enc = pub_enc;

    appd = (BSS_RSA_APPDATA *)qat_rsa_bsslmd->app_data;
    if (appd->rsa_pub_enc == NULL) {
        return RSA_meth_set_pub_enc(qat_rsa_bsslmd, bssl_rsa_pub_enc);
    }

    return 1;
}

int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    if (meth) {
        BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
        return appd->rsa_pub_dec;
    }

    return 0;
}

int RSA_meth_set_pub_dec(RSA_METHOD *meth,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding))
{
    BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
    appd->rsa_pub_dec = pub_dec;

    appd = (BSS_RSA_APPDATA *)qat_rsa_bsslmd->app_data;
    if (appd->rsa_pub_dec == NULL) {
        return RSA_meth_set_pub_dec(qat_rsa_bsslmd, bssl_rsa_pub_dec);
    }

    return 1;
}

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    if (meth) {
        BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
        return appd->rsa_priv_enc;
    }

    return 0;
}

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
    appd->rsa_priv_enc = priv_enc;

    appd = (BSS_RSA_APPDATA *)qat_rsa_bsslmd->app_data;
    if (appd->rsa_priv_enc == NULL) {
        return RSA_meth_set_priv_enc(qat_rsa_bsslmd, bssl_rsa_priv_enc);
    }

    return 1;
}

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding)
{
    if (meth) {
        BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
        return appd->rsa_priv_dec;
    }

    return 0;
}

int RSA_meth_set_priv_dec(RSA_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding))
{
    BSS_RSA_APPDATA *appd = (BSS_RSA_APPDATA *)meth->app_data;
    appd->rsa_priv_dec = priv_dec;

    appd = (BSS_RSA_APPDATA *)qat_rsa_bsslmd->app_data;
    if (appd->rsa_priv_dec == NULL) {
        return RSA_meth_set_priv_dec(qat_rsa_bsslmd, bssl_rsa_priv_dec);
    }

    return 1;
}

/* Copy from OpenSSL or BoringSSL  because of these functions not exported
 * using OPENSSL_EXPORT  or not defined in BoringSSL
 */
#define RSA_PKCS1_PADDING_SIZE 11

static int rand_nonzero(uint8_t *out, size_t len) {
  if (!RAND_bytes(out, len)) {
    return 0;
  }

  for (size_t i = 0; i < len; i++) {
    while (out[i] == 0) {
      if (!RAND_bytes(out + i, 1)) {
        return 0;
      }
    }
  }

  return 1;
}

/* OpenSSL declaration
 *int RSA_padding_add_none(unsigned char *to, int tlen, const unsigned char *f,
 *                        int fl);
 * BoringSSL declaration
 *int RSA_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
 *                        size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int RSA_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
                         size_t from_len) {
  if (from_len > to_len) {
    return 0;
  }

  if (from_len < to_len) {
    return 0;
  }

  memcpy(to, from, from_len);
  return 1;
}

/* Ported from openssl/crypto/rsa/rsa_none.c */
int RSA_padding_check_none(unsigned char *to, int tlen,
                           const unsigned char *from, int flen, int num)
{

    if (flen > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }

    memset(to, 0, tlen - flen);
    memcpy(to + tlen - flen, from, flen);
    return tlen;
}

/* OpenSSL declaration
 *int RSA_padding_add_PKCS1_type_1(unsigned char *to, int tlen,
 *                                const unsigned char *f, int fl);
 * BoringSSL declaration
 *int RSA_padding_add_PKCS1_type_1(uint8_t *to, size_t to_len,
 *                                const uint8_t *from, size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int RSA_padding_add_PKCS1_type_1(uint8_t *to, size_t to_len,
                                 const uint8_t *from, size_t from_len) {
  // See RFC 8017, section 9.2.
  if (to_len < RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }

  if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DIGEST_TOO_BIG_FOR_RSA_KEY);
    return 0;
  }

  to[0] = 0;
  to[1] = 1;
  memset(to + 2, 0xff, to_len - 3 - from_len);
  to[to_len - from_len - 1] = 0;
  memcpy(to + to_len - from_len, from, from_len);
  return 1;
}

/* OpenSSL declaration
 *int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
 *                                  const unsigned char *f, int fl,
 *                                  int rsa_len);
 * BoringSSL declaration
 *int RSA_padding_check_PKCS1_type_1(uint8_t *out, size_t *out_len,
 *                                  size_t max_out, const uint8_t *from,
 *                                  size_t from_len);
 * Ported from openssl openssl/crypto/rsa/rsa_pk1.c but replace RSAerr by 
 * OPENSSL_PUT_ERROR
 */
int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num)
{
    int i, j;
    const unsigned char *p;

    p = from;

    /*
     * The format is
     * 00 || 01 || PS || 00 || D
     * PS - padding string, at least 8 bytes of FF
     * D  - data.
     */

    if (num < RSA_PKCS1_PADDING_SIZE)
        return -1;

    /* Accept inputs with and without the leading 0-byte. */
    if (num == flen) {
        if ((*p++) != 0x00) {
            return -1;
        }
        flen--;
    }

    if ((num != (flen + 1)) || (*(p++) != 0x01)) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BLOCK_TYPE_IS_NOT_01);
        return -1;
    }

    /* scan over padding data */
    j = flen - 1;               /* one for type. */
    for (i = 0; i < j; i++) {
        if (*p != 0xff) {       /* should decrypt to 0xff */
            if (*p == 0) {
                p++;
                break;
            } else {
                OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_FIXED_HEADER_DECRYPT);
                return -1;
            }
        }
        p++;
    }

    if (i == j) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_NULL_BEFORE_BLOCK_MISSING);
        return -1;
    }

    if (i < 8) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_BAD_PAD_BYTE_COUNT);
        return -1;
    }
    i++;                        /* Skip over the '\0' */
    j -= i;
    if (j > tlen) {
        OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE);
        return -1;
    }
    memcpy(to, p, (unsigned int)j);

    return j;
}

/* OpenSSL declaration
 *int RSA_padding_add_PKCS1_type_2(unsigned char *to, int tlen,
 *                                const unsigned char *f, int fl);
 * BoringSSL declaration
 *int RSA_padding_add_PKCS1_type_2(uint8_t *to, size_t to_len,
 *                                const uint8_t *from, size_t from_len);
 * Ported from boringssl/crypto/fipsmodule/rsa/padding.c
 */
int RSA_padding_add_PKCS1_type_2(uint8_t *to, size_t to_len,
                                 const uint8_t *from, size_t from_len) {
  // See RFC 8017, section 7.2.1.
  if (to_len < RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_KEY_SIZE_TOO_SMALL);
    return 0;
  }

  if (from_len > to_len - RSA_PKCS1_PADDING_SIZE) {
    OPENSSL_PUT_ERROR(RSA, RSA_R_DATA_TOO_LARGE_FOR_KEY_SIZE);
    return 0;
  }

  to[0] = 0;
  to[1] = 2;

  size_t padding_len = to_len - 3 - from_len;
  if (!rand_nonzero(to + 2, padding_len)) {
    return 0;
  }

  to[2 + padding_len] = 0;
  memcpy(to + to_len - from_len, from, from_len);
  return 1;
}

/* Although OpenSSL or BoringSSL implemented parts of these functions ,
 * we still decide to not port them because it's pretty complex to port
 * Do nothing currently
 */
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len) { return 0; }

int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl, int rsa_len,
                                 const unsigned char *p, int pl) { return 0; }

int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *f, int fl)
                           { return 1; }

int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *f, int fl, int rsa_len)
                             { return 0; }

int RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f,
                         int fl) { return 1; }

int RSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len)
                           { return 0; }

void *qat_openssl_malloc(size_t size) {
     void *addr = NULL;
     if ((addr = OPENSSL_malloc(size)) != NULL)
        memset(addr, 0, size);
     return addr;
}

void bssl_free_result(void* r){
	CpaFlatBuffer* result = (CpaFlatBuffer*)r;
    if (result) {
        if (result->pData) {
            qaeCryptoMemFree((void **)&result->pData);
        }
        OPENSSL_free(result);
    }
}

void bssl_copy_result(void* r, void* out){
	CpaFlatBuffer* result = (CpaFlatBuffer*)r;
	memcpy(out, result->pData, result->dataLenInBytes);
}

size_t bssl_get_result_len(void* r){
	CpaFlatBuffer* result = (CpaFlatBuffer*)r;
	return result->dataLenInBytes;
}

#endif //QAT_BORINGSSL
