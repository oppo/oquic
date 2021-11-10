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
 * @file qat_bssl.h
 *
 * This file provides and interface for undefined OpenSSL APIs in BoringSSL
 *
 *****************************************************************************/
#ifndef QAT_BSSL_H
# define QAT_BSSL_H

/* Standard Includes */
# include <pthread.h>
# include <errno.h>

/* OpenSSL Includes */
# include <openssl/mem.h>
# include <openssl/bn.h>
# include <openssl/err.h>

# define ENGINE_QAT_PTR_DEFINE                    ENGINE *qat_engine_ptr = NULL;
# define ENGINE_QAT_PTR_RESET()                   qat_engine_ptr = NULL
# define ENGINE_QAT_PTR_SET(pt)                   qat_engine_ptr = pt
# define ENGINE_QAT_PTR_GET()                     qat_engine_ptr
# define ENGINE_QAT_PTR_EXPORT                    extern ENGINE *qat_engine_ptr;

ENGINE_QAT_PTR_EXPORT

/* Copy from openssl/crypto/async/async_local.h */
struct async_wait_ctx_st {
    struct fd_lookup_st *fds;
    size_t numadd;
    size_t numdel;
};

/* Copy from openssl/include/openssl/async.h */
typedef struct async_wait_ctx_st ASYNC_WAIT_CTX;

typedef void ASYNC_JOB;

/* Copy from openssl/include/openssl/async.h */
#if defined(_WIN32)
# if defined(BASETYPES) || defined(_WINDEF_H)
/* application has to include <windows.h> to use this */
#define OSSL_ASYNC_FD       HANDLE
#define OSSL_BAD_ASYNC_FD   INVALID_HANDLE_VALUE
# endif
#else
#define OSSL_ASYNC_FD       int
#define OSSL_BAD_ASYNC_FD   -1
#endif

/* These all AYNC macros used to instead of the APIs that defined in OpenSSL but
 * no defination in BoringSSL
 */
#define ASYNC_DEFAULT_VAL                                                1
#define ASYNC_DEFAULT_PRT                                             NULL
#define ASYNC_get_current_job(void)                      ASYNC_DEFAULT_PRT
#define ASYNC_get_wait_ctx(job)                          ASYNC_DEFAULT_PRT
#define ASYNC_WAIT_CTX_get_fd(ctx, key, fd, custom_data) \
    custom_data==NULL?ASYNC_DEFAULT_VAL:ASYNC_DEFAULT_VAL
#define ASYNC_WAIT_CTX_set_wait_fd(ctx, key, fd, custom_data, cleanup) \
    custom_data==NULL?ASYNC_DEFAULT_VAL:ASYNC_DEFAULT_VAL

#define ASYNC_WAIT_CTX_get_changed_fds(ctx, addfd, numaddfds, delfd, numdelfds) \
    numdelfds==0?ASYNC_DEFAULT_VAL:ASYNC_DEFAULT_VAL
#define ASYNC_WAIT_CTX_clear_fd(ctx, key)                ASYNC_DEFAULT_VAL

#define ASYNC_pause_job(void)                            ASYNC_DEFAULT_VAL

# define ENGINE_DEFAULT (1)

/* These all macros used to instead of the APIs that defined in OpenSSL but
 * no defination in BoringSSL
 */
#ifdef QAT_HW
# define ENGINE_set_id(e, id)              ENGINE_DEFAULT
# define ENGINE_set_name(e, name)          ENGINE_DEFAULT
# define ENGINE_set_RSA(e, rsa_get_method) rsa_get_method
# define ENGINE_set_DSA(e, rsa)            ENGINE_DEFAULT
# define ENGINE_set_DH(e, dh)              ENGINE_DEFAULT
# define ENGINE_set_EC(e, ec)              ENGINE_DEFAULT
# define ENGINE_set_pkey_meths(e, pkey)    ENGINE_DEFAULT
# define ENGINE_set_ciphers(e, ciphers)    ENGINE_DEFAULT
# define qat_create_ciphers()
#endif

# define ENGINE_set_destroy_function(e, destroy)    ENGINE_DEFAULT
/* Called qat_engine_init in ENGINE_set_init_function when binding engine */
# define ENGINE_set_init_function(e, init)          (init(e))
# define ENGINE_set_ctrl_function(e, ctrl)          ENGINE_DEFAULT
# define ENGINE_set_finish_function(e, finish)      ENGINE_DEFAULT
# define ENGINE_set_cmd_defns(e, cmd_defns)         ENGINE_DEFAULT

# define ENGINE_by_id(id)                           (qat_engine_ptr)
# define ENGINE_add(add)                            {}
# define ENGINE_set_inline_polling(val)             enable_inline_polling = val
# define OPENSSL_zalloc(size)                       qat_openssl_malloc(size)

void ENGINE_load_qat(void);
void ENGINE_unload_qat(void);

/* Defined a function as variant memory allocation interface with memset used
 * for no OPENSSL_zalloc() in BoringSSL
 */
void *qat_openssl_malloc(size_t size);

/* Redefine all functions related to RSA methods that defined in OpenSSL but 
 * not in BoringSSL
 */

/* No effect, just to pass compilation when BoringSSL enabled */
# define RSA_SSLV23_PADDING      2
# define RSA_X931_PADDING        5

# define RSA_METH_RET_DEFAULT (1)
# define RSA_meth_set_mod_exp(meth, mod_exp) \
    RSA_METH_RET_DEFAULT
# define RSA_meth_set_bn_mod_exp(meth, bn_mod_exp) \
    RSA_METH_RET_DEFAULT
# define RSA_meth_set_init(meth, init) \
    RSA_METH_RET_DEFAULT
# define RSA_meth_set_finish(meth, finish) \
    RSA_METH_RET_DEFAULT
/*
 * The default interval in microseconds used for the inline polling thread
 */
# define QAT_INLINE_POLL_PERIOD_IN_US 1

/*
 * Used to sleep for QAT_INLINE_POLL_PERIOD_IN_US microseconds after one time
 * inline polling, purpose to reduce the high CPU usage in performance tests
 */
# define RSA_INLINE_POLLING_USLEEP()           \
    do {                                       \
        usleep(QAT_INLINE_POLL_PERIOD_IN_US);  \
    } while(0)

RSA_METHOD *RSA_meth_new(const char *name, int flags);

void RSA_meth_free(RSA_METHOD *meth);

const RSA_METHOD *RSA_PKCS1_BSS(void);

const RSA_METHOD *RSA_PKCS1_OpenSSL();

int (*RSA_meth_get_pub_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding);

int RSA_meth_set_pub_enc(RSA_METHOD *meth,
                         int (*pub_enc) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding));

int (*RSA_meth_get_pub_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding);

int RSA_meth_set_pub_dec(RSA_METHOD *meth,
                         int (*pub_dec) (int flen, const unsigned char *from,
                                         unsigned char *to, RSA *rsa,
                                         int padding));

int (*RSA_meth_get_priv_enc(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding);

int RSA_meth_set_priv_enc(RSA_METHOD *meth,
                          int (*priv_enc) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding));

int (*RSA_meth_get_priv_dec(const RSA_METHOD *meth))
    (int flen, const unsigned char *from,
     unsigned char *to, RSA *rsa, int padding);

int RSA_meth_set_priv_dec(RSA_METHOD *meth,
                          int (*priv_dec) (int flen, const unsigned char *from,
                                           unsigned char *to, RSA *rsa,
                                           int padding));

int RSA_padding_add_none(uint8_t *to, size_t to_len, const uint8_t *from,
                         size_t from_len);

int RSA_padding_check_none(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len);

int RSA_padding_add_PKCS1_type_1(uint8_t *to, size_t to_len,
                                 const uint8_t *from, size_t from_len);

int RSA_padding_check_PKCS1_type_1(unsigned char *to, int tlen,
                                   const unsigned char *from, int flen,
                                   int num);

int RSA_padding_add_PKCS1_type_2(uint8_t *to, size_t to_len,
                                 const uint8_t *from, size_t from_len);

/* RSA_padding_add_PKCS1_OAEP defined in boring/decrepit/rsa/rsa_decrepit.c,
 * but built into boringssl/build/decrepit/libdecrepit not libcrypto or libssl
 * One option is to redefine this or link to libdecrepit.so in built system
 */
/* int RSA_padding_add_PKCS1_OAEP(uint8_t *to, size_t to_len,
 *                              const uint8_t *from, size_t from_len,
 *                              const uint8_t *param, size_t param_len);
 */

/* Not porting */
int RSA_padding_check_PKCS1_type_2(unsigned char *to, int tlen,
                                   const unsigned char *f, int fl,
                                   int rsa_len);
int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *f, int fl, int rsa_len,
                                 const unsigned char *p, int pl);
int RSA_padding_add_SSLv23(unsigned char *to, int tlen,
                           const unsigned char *f, int fl);
int RSA_padding_check_SSLv23(unsigned char *to, int tlen,
                             const unsigned char *f, int fl, int rsa_len);
int RSA_padding_add_X931(unsigned char *to, int tlen, const unsigned char *f,
                         int fl);
int RSA_padding_check_X931(unsigned char *to, int tlen,
                           const unsigned char *f, int fl, int rsa_len);

void bssl_free_result(void *result);
void bssl_copy_result(void *result, void *out);
size_t bssl_get_result_len(void *result);
#endif
