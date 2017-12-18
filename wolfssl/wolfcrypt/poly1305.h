/* poly1305.h
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


#ifndef WOLF_CRYPT_POLY1305_H
#define WOLF_CRYPT_POLY1305_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef HAVE_POLY1305

#ifdef __cplusplus
    extern "C" {
#endif

/* auto detect between 32bit / 64bit */
#if defined(__SIZEOF_INT128__) && defined(__LP64__)
#define WC_HAS_SIZEOF_INT128_64BIT
#endif

#if defined(_MSC_VER) && defined(_M_X64)
#define WC_HAS_MSVC_64BIT
#endif

#if (defined(__GNUC__) && defined(__LP64__) && \
        ((__GNUC__ > 4) || ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 4))))
#define WC_HAS_GCC_4_4_64BIT
#endif

#ifdef USE_INTEL_SPEEDUP
#elif (defined(WC_HAS_SIZEOF_INT128_64BIT) || defined(WC_HAS_MSVC_64BIT) ||  \
       defined(WC_HAS_GCC_4_4_64BIT))
#define POLY130564
#else
#define POLY130532
#endif

enum {
    POLY1305 = 7,
    POLY1305_BLOCK_SIZE = 16,
    POLY1305_DIGEST_SIZE = 16,
};

#define WC_POLY1305_PAD_SZ 16
#define WC_POLY1305_MAC_SZ 16

/* Poly1305 state */
typedef struct Poly1305 {
#ifdef USE_INTEL_SPEEDUP
    word64 r[3];
    word64 h[3];
    word64 pad[2];
    word64 hh[14];
    word32 r0[8];
    word32 r1[8];
    word32 r2[8];
    word32 r3[8];
    word32 r4[8];
    word32* rp[4];
    word64 hibit[4];
    size_t leftover;
    unsigned char buffer[4*POLY1305_BLOCK_SIZE];
    unsigned char finished;
    unsigned char started;
#else
#if defined(POLY130564)
    word64 r[3];
    word64 h[3];
    word64 pad[2];
#else
    word32 r[5];
    word32 h[5];
    word32 pad[4];
#endif
    size_t leftover;
    unsigned char buffer[POLY1305_BLOCK_SIZE];
    unsigned char finished;
#endif
} Poly1305;

/* does init */

/*!
    \ingroup Poly1305
    
    \brief This function sets the key for a Poly1305 context structure, initializing it for hashing. Note: A new key should be set after generating a message hash with wc_Poly1305Final to ensure security.
    
    \return 0 Returned on successfully setting the key and initializing the Poly1305 structure
    \return BAD_FUNC_ARG Returned if the given key is not 32 bytes long, or the Poly1305 context is NULL
    
    \param ctx pointer to a Poly1305 structure to initialize
    \param key pointer to the buffer containing the key to use for hashing
    \param keySz size of the key in the buffer. Should be 32 bytes

    _Example_
    \code
    Poly1305 enc;
    byte key[] = { /* initialize with 32 byte key to use for hashing };
    wc_Poly1305SetKey(&enc, key, sizeof(key));
    \endcode
    
    \sa wc_Poly1305Update
    \sa wc_Poly1305Final
*/
WOLFSSL_API int wc_Poly1305SetKey(Poly1305* poly1305, const byte* key,
                                  word32 kySz);
/*!
    \ingroup Poly1305
    
    \brief This function updates the message to hash with the Poly1305 structure.
    
    \return 0 Returned on successfully updating the message to hash
    \return BAD_FUNC_ARG Returned if the Poly1305 structure is NULL

    \param ctx pointer to a Poly1305 structure for which to update the message to hash
    \param m pointer to the buffer containing the message which should be added to the hash
    \param bytes size of the message to hash

    _Example_
    \code
    Poly1305 enc;
    byte key[] = { /* initialize with 32 byte key to use for encryption };

    byte msg[] = { /* initialize with message to hash };
    wc_Poly1305SetKey(&enc, key, sizeof(key));

    if( wc_Poly1305Update(key, msg, sizeof(msg)) != 0 ) {
	    // error updating message to hash
    }
    \endcode
    
    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Final
*/
WOLFSSL_API int wc_Poly1305Update(Poly1305* poly1305, const byte*, word32);
/*!
    \ingroup Poly1305
    
    \brief This function calculates the hash of the input messages and stores the result in mac. After this is called, the key should be reset.
    
    \return 0 Returned on successfully computing the final MAC
    \return BAD_FUNC_ARG Returned if the Poly1305 structure is NULL
    
    \param ctx pointer to a Poly1305 structure with which to generate the MAC
    \param mac pointer to the buffer in which to store the MAC. Should be POLY1305_DIGEST_SIZE (16 bytes) wide
    
    _Example_
    \code
    Poly1305 enc;
    byte mac[POLY1305_DIGEST_SIZE]; // space for a 16 byte mac

    byte key[] = { /* initialize with 32 byte key to use for encryption };

    byte msg[] = { /* initialize with message to hash };
    wc_Poly1305SetKey(&enc, key, sizeof(key));
    wc_Poly1305Update(key, msg, sizeof(msg));

    if ( wc_Poly1305Final(&enc, mac) != 0 ) {
    	// error computing final MAC
    }
    \endcode
    
    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Update
*/
WOLFSSL_API int wc_Poly1305Final(Poly1305* poly1305, byte* tag);
/*!
    \ingroup Poly1305
    
    \brief Takes in an initialized Poly1305 struct that has a key loaded and creates a MAC (tag) using recent TLS AEAD padding scheme.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returned if ctx, input, or tag is null or if additional is null and addSz is greater than 0 or if tagSz is less than WC_POLY1305_MAC_SZ.
    
    \param ctx Initialized Poly1305 struct to use
    \param additional Additional data to use
    \param addSz Size of additional buffer
    \param input Input buffer to create tag from
    \param sz Size of input buffer
    \param tag Buffer to hold created tag
    \param tagSz Size of input tag buffer (must be at least WC_POLY1305_MAC_SZ(16))
    
    _Example_
    \code
    Poly1305 ctx;
    byte key[] = { /* initialize with 32 byte key to use for hashing };
    byte additional[] = { /* initialize with additional data }
    byte msg[] = { /* initialize with message }
    byte tag[16];

    wc_Poly1305SetKey(&ctx, key, sizeof(key));
    if(wc_Poly1305_MAC(&ctx, additional, sizeof(additional), (byte*)msg, 
    sizeof(msg), tag, sizeof(tag)) != 0)
    {
        // Handle the error
    }
    \endcode
    
    \sa wc_Poly1305SetKey
    \sa wc_Poly1305Update
    \sa wcPoly1305Final
*/
WOLFSSL_API int wc_Poly1305_MAC(Poly1305* ctx, byte* additional, word32 addSz,
                               byte* input, word32 sz, byte* tag, word32 tagSz);
#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* HAVE_POLY1305 */
#endif /* WOLF_CRYPT_POLY1305_H */

