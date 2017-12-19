/* sha.h
 *
 * Copyright (C) 2006-2017 wolfSSL Inc.
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


#ifndef WOLF_CRYPT_SHA_H
#define WOLF_CRYPT_SHA_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_SHA

#ifdef HAVE_FIPS
#define wc_Sha             Sha
#define WC_SHA             SHA
#define WC_SHA_BLOCK_SIZE  SHA_BLOCK_SIZE
#define WC_SHA_DIGEST_SIZE SHA_DIGEST_SIZE
#define WC_SHA_PAD_SIZE    SHA_PAD_SIZE

/* for fips @wc_fips */
#include <cyassl/ctaocrypt/sha.h>
#endif

#ifdef FREESCALE_LTC_SHA
    #include "fsl_ltc.h"
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* avoid redefining structs */

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#ifndef NO_OLD_WC_NAMES
    #define Sha             wc_Sha
    #define SHA             WC_SHA
    #define SHA_BLOCK_SIZE  WC_SHA_BLOCK_SIZE
    #define SHA_DIGEST_SIZE WC_SHA_DIGEST_SIZE
    #define SHA_PAD_SIZE    WC_SHA_PAD_SIZE
#endif

/* in bytes */
enum {
    WC_SHA              =  1,    /* hash type unique */
    WC_SHA_BLOCK_SIZE   = 64,
    WC_SHA_DIGEST_SIZE  = 20,
    WC_SHA_PAD_SIZE     = 56
};


#ifndef WOLFSSL_TI_HASH
/* Sha digest */
typedef struct wc_Sha {
    #ifdef FREESCALE_LTC_SHA
        ltc_hash_ctx_t ctx;
    #else
        word32  buffLen;   /* in bytes          */
        word32  loLen;     /* length in bytes   */
        word32  hiLen;     /* length in bytes   */
        word32  buffer[WC_SHA_BLOCK_SIZE  / sizeof(word32)];
    #ifdef WOLFSSL_PIC32MZ_HASH
        word32  digest[PIC32_DIGEST_SIZE / sizeof(word32)];
    #else
        word32  digest[WC_SHA_DIGEST_SIZE / sizeof(word32)];
    #endif
        void*   heap;
    #ifdef WOLFSSL_PIC32MZ_HASH
        hashUpdCache cache; /* cache for updates */
    #endif
    #if defined(STM32_HASH) && defined(WOLFSSL_STM32_CUBEMX)
        HASH_HandleTypeDef hashHandle;
    #endif
    #ifdef WOLFSSL_ASYNC_CRYPT
        WC_ASYNC_DEV asyncDev;
    #endif /* WOLFSSL_ASYNC_CRYPT */
#endif /* FREESCALE_LTC_SHA */
} wc_Sha;

#else
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#endif /* WOLFSSL_TI_HASH */


#endif /* HAVE_FIPS */

/*!
    \ingroup SHA
    
    \brief This function initializes SHA. This is automatically called by wc_ShaHash.
    
    \return 0 Returned upon successfully initializing
    
    \param sha pointer to the sha structure to use for encryption
    
    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode
    
    \sa wc_ShaHash
    \sa wc_ShaUpdate
    \sa wc_ShaFinal
*/
WOLFSSL_API int wc_InitSha(wc_Sha*);
WOLFSSL_API int wc_InitSha_ex(wc_Sha* sha, void* heap, int devId);
/*!
    \ingroup SHA
    
    \brief Can be called to continually hash the provided byte array of length len.
    
    \return 0 Returned upon successfully adding the data to the digest.
    
    \param sha pointer to the sha structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed
    
    _Example_
    \code
    Sha sha[1];
    byte data[] = { // Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode
    
    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
WOLFSSL_API int wc_ShaUpdate(wc_Sha*, const byte*, word32);
/*!
    \ingroup SHA
    
    \brief Finalizes hashing of data. Result is placed into hash.  Resets state of sha struct.
    
    \return 0 Returned upon successfully finalizing.
    
    \param sha pointer to the sha structure to use for encryption
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    Sha sha[1];
    byte data[] = { Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitSha(sha)) != 0) {
       WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
       wc_ShaUpdate(sha, data, len);
       wc_ShaFinal(sha, hash);
    }
    \endcode
    
    \sa wc_ShaHash
    \sa wc_InitSha
    \sa wc_ShaGetHash
*/
WOLFSSL_API int wc_ShaFinal(wc_Sha*, byte*);
WOLFSSL_API void wc_ShaFree(wc_Sha*);

/*!
    \ingroup SHA
    
    \brief Gets hash data. Result is placed into hash.  Does not reset state of sha struct.
    
    \return 0 Returned upon successfully finalizing.
    
    \param sha pointer to the sha structure to use for encryption
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    Sha sha[1];
    if ((ret = wc_InitSha(sha)) != 0) {
    WOLFSSL_MSG("wc_InitSha failed");
    }
    else {
        wc_ShaUpdate(sha, data, len);
        wc_ShaGetHash(sha, hash);
    }
    \endcode
    
    \sa wc_ShaHash
    \sa wc_ShaFinal
    \sa wc_InitSha
*/
WOLFSSL_API int wc_ShaGetHash(wc_Sha*, byte*);
WOLFSSL_API int wc_ShaCopy(wc_Sha*, wc_Sha*);

#ifdef WOLFSSL_PIC32MZ_HASH
WOLFSSL_API void wc_ShaSizeSet(wc_Sha* sha, word32 len);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_SHA */
#endif /* WOLF_CRYPT_SHA_H */

