/* blake2.h
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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




#ifndef WOLF_CRYPT_BLAKE2_H
#define WOLF_CRYPT_BLAKE2_H

#include <wolfssl/wolfcrypt/settings.h>

#ifdef HAVE_BLAKE2

#include <wolfssl/wolfcrypt/blake2-int.h>

/* call old functions if using fips for the sake of hmac @wc_fips */
#ifdef HAVE_FIPS
    /* Since hmac can call blake functions provide original calls */
    #define wc_InitBlake2b   InitBlake2b
    #define wc_Blake2bUpdate Blake2bUpdate
    #define wc_Blake2bFinal  Blake2bFinal
#endif

#ifdef __cplusplus
    extern "C" {
#endif

/* in bytes, variable digest size up to 512 bits (64 bytes) */
enum {
    BLAKE2B_ID  = 7,   /* hash type unique */
    BLAKE2B_256 = 32   /* 256 bit type, SSL default */
};


/* BLAKE2b digest */
typedef struct Blake2b {
    blake2b_state S[1];         /* our state */
    word32        digestSz;     /* digest size used on init */
} Blake2b;


/*!
    \ingroup wolfCrypt
    
    \brief This function initializes a Blake2b structure for use with the Blake2 hash function.
    
    \return 0 Returned upon successfully initializing the Blake2b structure and setting the digest size.

    \param b2b pointer to the Blake2b structure to initialize
    \param digestSz length of the blake 2 digest to implement
    
    _Example_
    \code
    Blake2b b2b;
    wc_InitBlake2b(&b2b, 64); // initialize Blake2b structure with 64 byte digest
    \endcode
    
    \sa wc_Blake2bUpdate
*/
WOLFSSL_API int wc_InitBlake2b(Blake2b*, word32);
/*!
    \ingroup wolfCrypt
    
    \brief This function updates the Blake2b hash with the given input data. This function should be called after wc_InitBlake2b, and repeated until one is ready for the final hash: wc_Blake2bFinal.
    
    \return 0 Returned upon successfully update the Blake2b structure with the given data
    \return -1 Returned if there is a failure while compressing the input data
    
    \param b2b pointer to the Blake2b structure to update
    \param data pointer to a buffer containing the data to append
    \param sz length of the input data to append
    
    _Example_
    \code
    int ret;
    Blake2b b2b;
    wc_InitBlake2b(&b2b, 64); // initialize Blake2b structure with 64 byte digest

    byte plain[] = { // initialize input };

    ret = wc_Blake2bUpdate(&b2b, plain, sizeof(plain));
    if( ret != 0) {
    	// error updating blake2b
    }
    \endcode
    
    \sa wc_InitBlake2b
    \sa wc_Blake2bFinal
*/
WOLFSSL_API int wc_Blake2bUpdate(Blake2b*, const byte*, word32);
/*!
    \ingroup wolfCrypt
    
    \brief This function computes the Blake2b hash of the previously supplied input data. The output hash will be of length requestSz, or, if requestSz==0, the digestSz of the b2b structure. This function should be called after wc_InitBlake2b and wc_Blake2bUpdate has been processed for each piece of input data desired.
    
    \return 0 Returned upon successfully computing the Blake2b hash
    \return -1 Returned if there is a failure while parsing the Blake2b hash
    
    \param b2b pointer to the Blake2b structure to update
    \param final pointer to a buffer in which to store the blake2b hash. Should be of length requestSz
    \param requestSz length of the digest to compute. When this is zero, b2b->digestSz will be used instead
    
    _Example_
    \code
    int ret;
    Blake2b b2b;
    byte hash[64];
    wc_InitBlake2b(&b2b, 64); // initialize Blake2b structure with 64 byte digest
    ... // call wc_Blake2bUpdate to add data to hash

    ret = 2c_Blake2bFinal(&b2b, hash, 64);
    if( ret != 0) {
    	// error generating blake2b hash
    }
    \endcode
    
    \sa wc_InitBlake2b
    \sa wc_Blake2bUpdate
*/
WOLFSSL_API int wc_Blake2bFinal(Blake2b*, byte*, word32);



#ifdef __cplusplus
    }
#endif

#endif  /* HAVE_BLAKE2 */
#endif  /* WOLF_CRYPT_BLAKE2_H */

