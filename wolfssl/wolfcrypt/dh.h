/* dh.h
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


#ifndef WOLF_CRYPT_DH_H
#define WOLF_CRYPT_DH_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_DH

#include <wolfssl/wolfcrypt/integer.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif
typedef struct DhParams {
    const byte* p;
    word32      p_len;
    const byte* g;
    word32      g_len;
} DhParams;

/* Diffie-Hellman Key */
typedef struct DhKey {
    mp_int p, g;                            /* group parameters  */
    void* heap;
#ifdef WOLFSSL_ASYNC_CRYPT
    WC_ASYNC_DEV asyncDev;
#endif
} DhKey;


#ifdef HAVE_FFDHE_2048
WOLFSSL_API const DhParams* wc_Dh_ffdhe2048_Get(void);
#endif
#ifdef HAVE_FFDHE_3072
WOLFSSL_API const DhParams* wc_Dh_ffdhe3072_Get(void);
#endif
#ifdef HAVE_FFDHE_4096
WOLFSSL_API const DhParams* wc_Dh_ffdhe4096_Get(void);
#endif
#ifdef HAVE_FFDHE_6144
WOLFSSL_API const DhParams* wc_Dh_ffdhe6144_Get(void);
#endif
#ifdef HAVE_FFDHE_8192
WOLFSSL_API const DhParams* wc_Dh_ffdhe8192_Get(void);
#endif

/*!
    \ingroup wolfCrypt
    
    \brief This function initializes a Diffie-Hellman key for use in negotiating a secure secret key with the Diffie-Hellman exchange protocol.
    
    \return none No returns.
    
    \param key pointer to the DhKey structure to initialize for use with secure key exchanges
    
    _Example_
    \code
    DhKey key;
    wc_InitDhKey(&key); // initialize DH key
    \endcode
    
    \sa wc_FreeDhKey
    \sa wc_DhGenerateKeyPair
*/
WOLFSSL_API int wc_InitDhKey(DhKey* key);
WOLFSSL_API int wc_InitDhKey_ex(DhKey* key, void* heap, int devId);
/*!
    \ingroup wolfCrypt
    
    \brief This function frees a Diffie-Hellman key after it has been used to negotiate a secure secret key with the Diffie-Hellman exchange protocol.
    
    \return none No returns.
    
    \param key pointer to the DhKey structure to free
    
    _Example_
    \code
    DhKey key; 
    // initialize key, perform key exchange

    wc_FreeDhKey(&key); // free DH key to avoid memory leaks
    \endcode
    
    \sa wc_InitDhKey
*/
WOLFSSL_API void wc_FreeDhKey(DhKey* key);

/*!
    \ingroup wolfCrypt
    
    \brief This function generates a public/private key pair based on the Diffie-Hellman public parameters, storing the private key in priv and the public key in pub. It takes an initialized Diffie-Hellman key and an initialized rng structure.
    
    \return BAD_FUNC_ARG Returned if there is an error parsing one of the inputs to this function
    \return RNG_FAILURE_E Returned if there is an error generating a random number using rng 
    \return MP_INIT_E May be returned if there is an error in the math library while generating the public key
    \return MP_READ_E May be returned if there is an error in the math library while generating the public key
    \return MP_EXPTMOD_E May be returned if there is an error in the math library while generating the public key
    \return MP_TO_E May be returned if there is an error in the math library while generating the public key
    
    \param key pointer to the DhKey structure from which to generate the key pair
    \param rng pointer to an initialized random number generator (rng) with which to generate the keys
    \param priv pointer to a buffer in which to store the private key
    \param privSz will store the size of the private key written to priv
    \param pub pointer to a buffer in which to store the public key
    \param pubSz will store the size of the private key written to pub

    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte pub[256];
    word32 privSz, pubSz;

    wc_InitDhKey(&key); // initialize key
    // Set DH parameters using wc_DhSetKey or wc_DhKeyDecode
    RNG rng;
    wc_InitRng(&rng); // initialize rng
    ret = wc_DhGenerateKeyPair(&key, &rng, priv, &privSz, pub, &pubSz);
    \endcode
    
    \sa wc_InitDhKey
    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
WOLFSSL_API int wc_DhGenerateKeyPair(DhKey* key, WC_RNG* rng, byte* priv,
                                 word32* privSz, byte* pub, word32* pubSz);
/*!
    \ingroup wolfCrypt
    
    \brief This function generates an agreed upon secret key based on a local private key and a received public key. If completed on both sides of an exchange, this function generates an agreed upon secret key for symmetric communication. On successfully generating a shared secret key, the size of the secret key written will be stored in agreeSz.
    
    \return 0 Returned on successfully generating an agreed upon secret key
    \return MP_INIT_E May be returned if there is an error while generating the shared secret key
    \return MP_READ_E May be returned if there is an error while generating the shared secret key
    \return MP_EXPTMOD_E May be returned if there is an error while generating the shared secret key
    \return MP_TO_E May be returned if there is an error while generating the shared secret key
    
    \param key pointer to the DhKey structure to use to compute the shared key
    \param agree pointer to the buffer in which to store the secret key
    \param agreeSz will hold the size of the secret key after successful generation
    \param priv pointer to the buffer containing the local secret key
    \param privSz size of the local secret key
    \param otherPub pointer to a buffer containing the received public key
    \param pubSz size of the received public key
    
    _Example_
    \code
    DhKey key;
    int ret;
    byte priv[256];
    byte agree[256];
    word32 agreeSz;

    // initialize key, set key prime and base
    // wc_DhGenerateKeyPair -- store private key in priv
    byte pub[] = { // initialized with the received public key };
    ret = wc_DhAgree(&key, agree, &agreeSz, priv, sizeof(priv), pub, sizeof(pub));
    if ( ret != 0 ) {
    	// error generating shared key
    }
    \endcode
    
    \sa wc_DhGenerateKeyPair
*/
WOLFSSL_API int wc_DhAgree(DhKey* key, byte* agree, word32* agreeSz,
                       const byte* priv, word32 privSz, const byte* otherPub,
                       word32 pubSz);

/*!
    \ingroup wolfCrypt
    
    \brief This function decodes a Diffie-Hellman key from the given input buffer containing the key in DER format. It stores the result in the DhKey structure.
    
    \return 0 Returned on successfully decoding the input key
    \return ASN_PARSE_E Returned if there is an error parsing the sequence of the input
    \return ASN_DH_KEY_E Returned if there is an error reading the private key parameters from the parsed input

    \param input pointer to the buffer containing the DER formatted Diffie-Hellman key
    \param inOutIdx pointer to an integer in which to store the index parsed to while decoding the key
    \param key pointer to the DhKey structure to initialize with the input key
    \param inSz length of the input buffer. Gives the max length that may be read

    _Example_
    \code
    DhKey key;
    word32 idx = 0;

    byte keyBuff[1024]; 
    // initialize with DER formatted key
    wc_DhKeyInit(&key);
    ret = wc_DhKeyDecode(keyBuff, &idx, &key, sizeof(keyBuff));

    if ( ret != 0 ) {
    	// error decoding key
    }
    \endcode
    
    \sa wc_DhSetKey
*/
WOLFSSL_API int wc_DhKeyDecode(const byte* input, word32* inOutIdx, DhKey* key,
                           word32);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the key for a DhKey structure using the input private key parameters. Unlike wc_DhKeyDecode, this function does not require that the input key be formatted in DER format, and instead simply accepts the parsed input parameters p (prime) and g (base).
    
    \return 0 Returned on successfully setting the key
    \return BAD_FUNC_ARG Returned if any of the input parameters evaluate to NULL
    \return MP_INIT_E Returned if there is an error initializing the key parameters for storage 
    \return ASN_DH_KEY_E Returned if there is an error reading in the DH key parameters p and g

    \param key pointer to the DhKey structure on which to set the key
    \param p pointer to the buffer containing the prime for use with the key
    \param pSz length of the input prime
    \param g pointer to the buffer containing the base for use with the key
    \param gSz length of the input base
    
    _Example_
    \code
    DhKey key;

    byte p[] = { // initialize with prime };
    byte g[] = { // initialize with base };
    wc_DhKeyInit(&key);
    ret = wc_DhSetKey(key, p, sizeof(p), g, sizeof(g));

    if ( ret != 0 ) {
    	// error setting key
    }
    \endcode
    
    \sa wc_DhKeyDecode
*/
WOLFSSL_API int wc_DhSetKey(DhKey* key, const byte* p, word32 pSz, const byte* g,
                        word32 gSz);
/*!
    \ingroup wolfCrypt
    
    \brief This function loads the Diffie-Hellman parameters, p (prime) and g (base) out of the given input buffer, DER formatted.
    
    \return 0 Returned on successfully extracting the DH parameters
    \return ASN_PARSE_E Returned if an error occurs while parsing the DER formatted DH certificate
    \return BUFFER_E Returned if there is inadequate space in p or g to store the parsed parameters

    \parma input pointer to a buffer containing a DER formatted Diffie-Hellman certificate to parse
    \parma inSz size of the input buffer
    \parma p pointer to a buffer in which to store the parsed prime
    \parma pInOutSz pointer to a word32 object containing the available size in the p buffer. Will be overwritten with the number of bytes written to the buffer after completing the function call
    \parma g pointer to a buffer in which to store the parsed base
    \parma gInOutSz pointer to a word32 object containing the available size in the g buffer. Will be overwritten with the number of bytes written to the buffer after completing the function call

    _Example_
    \code
    byte dhCert[] = { /* initialize with DER formatted certificate /* };
    byte p[MAX_DH_SIZE];
    byte g[MAX_DH_SIZE];
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;

    ret = wc_DhParamsLoad(dhCert, sizeof(dhCert), p, &pSz, g, &gSz);
    if ( ret != 0 ) {
    	// error parsing inputs
    }
    \endcode
    
    \sa wc_DhSetKey
    \sa wc_DhKeyDecode
*/
WOLFSSL_API int wc_DhParamsLoad(const byte* input, word32 inSz, byte* p,
                            word32* pInOutSz, byte* g, word32* gInOutSz);
WOLFSSL_API int wc_DhCheckPubKey(DhKey* key, const byte* pub, word32 pubSz);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* NO_DH */
#endif /* WOLF_CRYPT_DH_H */

