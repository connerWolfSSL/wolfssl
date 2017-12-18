/* md5.h
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


#ifndef WOLF_CRYPT_MD5_H
#define WOLF_CRYPT_MD5_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_MD5

#ifdef HAVE_FIPS
    #define wc_InitMd5   InitMd5
    #define wc_Md5Update Md5Update
    #define wc_Md5Final  Md5Final
    #define wc_Md5Hash   Md5Hash
#endif

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef NO_OLD_WC_NAMES
    #define Md5             wc_Md5
    #define MD5             WC_MD5
    #define MD5_BLOCK_SIZE  WC_MD5_BLOCK_SIZE
    #define MD5_DIGEST_SIZE WC_MD5_DIGEST_SIZE
    #define WC_MD5_PAD_SIZE WC_MD5_PAD_SIZE
#endif

/* in bytes */
enum {
    WC_MD5             =  0,      /* hash type unique */
    WC_MD5_BLOCK_SIZE  = 64,
    WC_MD5_DIGEST_SIZE = 16,
    WC_MD5_PAD_SIZE    = 56
};

#ifdef WOLFSSL_MICROCHIP_PIC32MZ
    #include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

#ifdef WOLFSSL_TI_HASH
    #include "wolfssl/wolfcrypt/port/ti/ti-hash.h"
#else

/* MD5 digest */
typedef struct wc_Md5 {
    word32  buffLen;   /* in bytes          */
    word32  loLen;     /* length in bytes   */
    word32  hiLen;     /* length in bytes   */
    word32  buffer[WC_MD5_BLOCK_SIZE  / sizeof(word32)];
#ifdef WOLFSSL_PIC32MZ_HASH
    word32  digest[PIC32_DIGEST_SIZE / sizeof(word32)];
#else
    word32  digest[WC_MD5_DIGEST_SIZE / sizeof(word32)];
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
} wc_Md5;

#endif /* WOLFSSL_TI_HASH */
/*!
    \ingroup MD5
    
    \brief This function initializes md5. This is automatically called by wc_Md5Hash.
    
    \return 0 Returned upon successfully initializing.
    \return BAD_FUNC_ARG Returned if the Md5 structure is passed as a NULL value.
    
    \param md5 pointer to the md5 structure to use for encryption
    
    _Example_
    \code
    Md5 md5;
    byte* hash;
    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Failure Case.
       }
       ret = wc_Md5Final(&md5, hash);
      if (ret != 0) {
    	// Md5 Final Failure Case.
      }
    }
    \endcode
    
    \sa wc_Md5Hash
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
WOLFSSL_API int wc_InitMd5(wc_Md5*);
WOLFSSL_API int wc_InitMd5_ex(wc_Md5*, void*, int);
/*!
    \ingroup MD5
    
    \brief Can be called to continually hash the provided byte array of length len.
    
    \return 0 Returned upon successfully adding the data to the digest.
    \return BAD_FUNC_ARG Returned if the Md5 structure is NULL or if data is NULL and len is greater than zero. The function should not return an error if the data parameter is NULL and len is zero.

    \param md5 pointer to the md5 structure to use for encryption
    \param data the data to be hashed
    \param len length of data to be hashed
    
    _Example_
    \code
    Md5 md5;
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(&md5, data, len);
       if (ret != 0) {
    	 // Md5 Update Error Case.
       }
       ret = wc_Md5Final(&md5, hash);
       if (ret != 0) {
    	// Md5 Final Error Case.
       }
    }
    \endcode
    
    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
WOLFSSL_API int wc_Md5Update(wc_Md5*, const byte*, word32);
/*!
    \ingroup MD5
    
    \brief Finalizes hashing of data. Result is placed into hash. Md5 Struct is reset. Note: This function will also return the result of calling IntelQaSymMd5() in the case that HAVE_INTEL_QA is defined.
    
    \return 0 Returned upon successfully finalizing.
    \return BAD_FUNC_ARG Returned if the Md5 structure or hash pointer is passed in NULL.
    
    \param md5 pointer to the md5 structure to use for encryption
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    md5 md5[1];
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       ret = wc_Md5Update(md5, data, len);
       if (ret != 0) {
    	// Md5 Update Failure Case.
       }
      ret = wc_Md5Final(md5, hash);
       if (ret != 0) {
	    // Md5 Final Failure Case.
       }
    }
    \endcode
    
    \sa wc_Md5Hash
    \sa wc_InitMd5
    \sa wc_Md5GetHash
*/
WOLFSSL_API int wc_Md5Final(wc_Md5*, byte*);
/*!
    \ingroup MD5
    
    \brief Resets the Md5 structure.  Note: this is only supported if you have WOLFSSL_TI_HASH defined.

    \return none No returns.
    
    \param md5 Pointer to the Md5 structure to be reset.

    _Example_
    \code
    Md5 md5;
    byte data[] = { /* Data to be hashed };
    word32 len = sizeof(data);

    if ((ret = wc_InitMd5(&md5)) != 0) {
        WOLFSSL_MSG("wc_InitMd5 failed");
    }
    else {
        wc_Md5Update(&md5, data, len);
        wc_Md5Final(&md5, hash);
        wc_Md5Free(&md5);
    }
    \endcode
    
    \sa wc_InitMd5
    \sa wc_Md5Update
    \sa wc_Md5Final
*/
WOLFSSL_API void wc_Md5Free(wc_Md5*);

/*!
    \ingroup MD5
    
    \brief Gets hash data. Result is placed into hash.  Md5 struct is not reset.
    
    \return none No returns
    
    \param md5 pointer to the md5 structure to use for encryption.
    \param hash Byte array to hold hash value.
    
    _Example_
    \code
    md5 md5[1];
    if ((ret = wc_InitMd5(md5)) != 0) {
       WOLFSSL_MSG("wc_Initmd5 failed");
    }
    else {
       wc_Md5Update(md5, data, len);
       wc_Md5GetHash(md5, hash);
    }
    \endcode
    
    \sa wc_Md5Hash
    \sa wc_Md5Final
    \sa wc_InitMd5
*/
WOLFSSL_API int  wc_Md5GetHash(wc_Md5*, byte*);
WOLFSSL_API int  wc_Md5Copy(wc_Md5*, wc_Md5*);

#ifdef WOLFSSL_PIC32MZ_HASH
WOLFSSL_API void wc_Md5SizeSet(wc_Md5* md5, word32 len);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_MD5 */
#endif /* WOLF_CRYPT_MD5_H */
