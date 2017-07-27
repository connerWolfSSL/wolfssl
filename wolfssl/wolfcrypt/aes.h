/* aes.h
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

/*!
    \file aes.h
    \brief Header file containing AES encryption API
*/

#ifndef WOLF_CRYPT_AES_H
#define WOLF_CRYPT_AES_H

#include <wolfssl/wolfcrypt/types.h>

#ifndef NO_AES

/* included for fips @wc_fips */
#ifdef HAVE_FIPS
#include <cyassl/ctaocrypt/aes.h>
#if defined(CYASSL_AES_COUNTER) && !defined(WOLFSSL_AES_COUNTER)
    #define WOLFSSL_AES_COUNTER
#endif
#if !defined(WOLFSSL_AES_DIRECT) && defined(CYASSL_AES_DIRECT)
    #define WOLFSSL_AES_DIRECT
#endif
#endif

#ifndef HAVE_FIPS /* to avoid redefinition of macros */

#ifdef WOLFSSL_AESNI

#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>

#endif /* WOLFSSL_AESNI */

#endif /* HAVE_FIPS */

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef HAVE_FIPS /* to avoid redefinition of structures */

#ifdef WOLFSSL_ASYNC_CRYPT
    #include <wolfssl/wolfcrypt/async.h>
#endif

enum {
    AES_ENC_TYPE   = 1,   /* cipher unique type */
    AES_ENCRYPTION = 0,
    AES_DECRYPTION = 1,
    KEYWRAP_BLOCK_SIZE = 8,
    AES_BLOCK_SIZE = 16
};


typedef struct Aes {
    /* AESNI needs key first, rounds 2nd, not sure why yet */
    ALIGN16 word32 key[60];
    word32  rounds;
    int     keylen;

    ALIGN16 word32 reg[AES_BLOCK_SIZE / sizeof(word32)];      /* for CBC mode */
    ALIGN16 word32 tmp[AES_BLOCK_SIZE / sizeof(word32)];      /* same         */

#ifdef HAVE_AESGCM
    ALIGN16 byte H[AES_BLOCK_SIZE];
#ifdef GCM_TABLE
    /* key-based fast multiplication table. */
    ALIGN16 byte M0[256][AES_BLOCK_SIZE];
#endif /* GCM_TABLE */
#endif /* HAVE_AESGCM */
#ifdef WOLFSSL_AESNI
    byte use_aesni;
#endif /* WOLFSSL_AESNI */
#ifdef WOLFSSL_ASYNC_CRYPT
    word32 asyncKey[AES_MAX_KEY_SIZE/8/sizeof(word32)]; /* raw key */
    word32 asyncIv[AES_BLOCK_SIZE/sizeof(word32)]; /* raw IV */
    WC_ASYNC_DEV asyncDev;
#endif /* WOLFSSL_ASYNC_CRYPT */
#ifdef WOLFSSL_AES_COUNTER
    word32  left;            /* unused bytes left from last call */
#endif
#ifdef WOLFSSL_PIC32MZ_CRYPT
    word32 key_ce[AES_BLOCK_SIZE*2/sizeof(word32)] ;
    word32 iv_ce [AES_BLOCK_SIZE  /sizeof(word32)] ;
#endif
    void*  heap; /* memory hint to use */
} Aes;


#ifdef HAVE_AESGCM
typedef struct Gmac {
    Aes aes;
} Gmac;
#endif /* HAVE_AESGCM */
#endif /* HAVE_FIPS */


/* Authenticate cipher function prototypes */
typedef int (*wc_AesAuthEncryptFunc)(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
typedef int (*wc_AesAuthDecryptFunc)(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);

/* AES-CBC */
/*!
    \ingroup wolfCrypt
    \brief This function initializes an AES structure by setting the key and then setting the initialization vector.
    
    \return 0 On successfully setting key and initialization vector.
    \return BAD_FUNC_ARG Returned if key length is invalid.
    
    \param aes pointer to the AES structure to modify
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in
    \param iv pointer to the initialization vector used to initialize the key
    \param dir Cipher direction. Set AES_ENCRYPTION to encrypt,  or AES_DECRYPTION to decrypt.
    
    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24 or 32 byte key };
    byte iv[]  = { some 16 byte iv };
    if (ret = wc_AesSetKey(&enc, key, AES_BLOCK_SIZE, iv, AES_ENCRYPTION) != 0) {
	// failed to set aes key
    }
    \endcode
    
    \sa wc_AesSetKeyDirect
    \sa wc_AesSetIV
*/
WOLFSSL_API int  wc_AesSetKey(Aes* aes, const byte* key, word32 len,
                              const byte* iv, int dir);
/*!
    \ingroup wolfCrypt
    \brief This function sets the initialization vector for a particular AES object. The AES object should be initialized before calling this function.
    
    \return 0 On successfully setting initialization vector.
    \return BAD_FUNC_ARG Returned if AES pointer is NULL.
    
    \param aes pointer to the AES structure on which to set the initialization vector
    \param iv initialization vector used to initialize the AES structure. If the value is NULL, the default action initializes the iv to 0.
    
    _Example_
    \code
    Aes enc;
    // set enc key
    byte iv[]  = { some 16 byte iv };
    if (ret = wc_AesSetIV(&enc, iv) != 0) {
	// failed to set aes iv
    }
    \endcode
    
    \sa wc_AesSetKeyDirect
    \sa wc_AesSetKey
*/
WOLFSSL_API int  wc_AesSetIV(Aes* aes, const byte* iv);
/*!
    \ingroup wolfCrypt
    \brief Encrypts a plaintext message from the input buffer in, and places the resulting cipher text in the output buffer out using cipher block chaining with AES. This function requires that the AES object has been initialized by calling AesSetKey before a message is able to be encrypted. This function assumes that the input message is AES block length aligned. PKCS#7 style padding should be added beforehand. This differs from the OpenSSL AES-CBC methods which add the padding for you. To make the wolfSSL function and equivalent OpenSSL functions interoperate, one should specify the -nopad option in the OpenSSL command line function so that it behaves like the wolfSSL AesCbcEncrypt method and does not add extra padding during encryption.

    \return 0 On successfully encrypting message.
    \return BAD_ALIGN_E: Returned on block align error
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the ciphertext of the encrypted message
    \param in pointer to the input buffer containing message to be encrypted
    \param sz size of input message
    
    _Example_
    \code
    Aes enc;
    int ret = 0;
    // initialize enc with AesSetKey, using direction AES_ENCRYPTION
    byte msg[AES_BLOCK_SIZE * n]; // multiple of 16 bytes
    // fill msg with data
    byte cipher[AES_BLOCK_SIZE * n]; // Some multiple of 16 bytes
    if ((ret = wc_AesCbcEncrypt(&enc, cipher, message, sizeof(msg))) != 0 ) {
	// block align error
    }
    \endcode
    
    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcDecrypt
*/
WOLFSSL_API int  wc_AesCbcEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
/*!
    \ingroup wolfCrypt 
    \brief Decrypts a cipher from the input buffer in, and places the resulting plain text in the output buffer out using cipher block chaining with AES. This function requires that the AES structure has been initialized by calling AesSetKey before a message is able to be decrypted. This function assumes that the original message was AES block length aligned. This differs from the OpenSSL AES-CBC methods which do not require alignment as it adds PKCS#7 padding automatically. To make the wolfSSL function and equivalent OpenSSL functions interoperate, one should specify the -nopad option in the OpenSSL command line function so that it behaves like the wolfSSL AesCbcEncrypt method and does not create errors during decryption.

    \return 0 On successfully decrypting message.
    \return BAD_ALIGN_E Returned on block align error.
    
    \param aes pointer to the AES object used to decrypt data.
    \param out pointer to the output buffer in which to store the plain text of the decrypted message.
    \param in pointer to the input buffer containing cipher text to be decrypted.
    \param sz size of input message.
    
    _Example_
    \code
    Aes dec;
    int ret = 0;
    // initialize dec with AesSetKey, using direction AES_DECRYPTION
    byte cipher[AES_BLOCK_SIZE * n]; // some multiple of 16 bytes
    // fill cipher with cipher text
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecrypt(&dec, plain, cipher, sizeof(cipher))) != 0 ) {
	// block align error
    }
    \endcode
    
    \sa wc_AesSetKey
    \sa wc_AesCbcEncrypt
*/
WOLFSSL_API int  wc_AesCbcDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);

#ifdef HAVE_AES_ECB
WOLFSSL_API int wc_AesEcbEncrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
WOLFSSL_API int wc_AesEcbDecrypt(Aes* aes, byte* out,
                                  const byte* in, word32 sz);
#endif

/* AES-CTR */
#ifdef WOLFSSL_AES_COUNTER
/*!
    \ingroup wolfCrypt
    \brief Encrypts/Decrypts a message from the input buffer in, and places the resulting cipher text in the output buffer out using CTR mode with AES. This function is only enabled if WOLFSSL_AES_COUNTER is enabled at compile time. The AES structure should be initialized through AesSetKey before calling this function. Note that this function is used for both decryption and encryption.
    
    _NOTE:_ Regarding using same API for encryption and decryption.
    User should differentiate between Aes structures for encrypt/decrypt.
    
    \return none
    
    \param aes pointer to the AES object used to decrypt data
    \param out pointer to the output buffer in which to store the cipher text of the encrypted message
    \param in pointer to the input buffer containing plain text to be encrypted
    \param sz size of the input plain text
    
    _Example_
    \code
    Aes enc;
    Aes dec;
    // initialize enc and dec with AesSetKeyDirect, using direction AES_ENCRYPTION
    // since the underlying API only calls Encrypt and by default calling encrypt on
    // a cipher results in a decryption of the cipher
    
    byte msg[AES_BLOCK_SIZE * n]; //n being a positive integer making msg some multiple of 16 bytes
    // fill plain with message text
    byte cipher[AES_BLOCK_SIZE * n];
    byte decrypted[AES_BLOCK_SIZE * n];
    wc_AesCtrEncrypt(&enc, cipher, msg, sizeof(msg)); // encrypt plain
    wc_AesCtrEncrypt(&dec, decrypted, cipher, sizeof(cipher)); // decrypt cipher text
    \endcode
    
    \sa wc_AesSetKey
*/
 WOLFSSL_API void wc_AesCtrEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz);
#endif
/* AES-DIRECT */
#if defined(WOLFSSL_AES_DIRECT)
/*!
    \ingroup wolfCrypt
    \brief This function is a one-block encrypt of the input block, in, into the output block, out. It uses the key and iv (initialization vector) of the provided AES structure, which should be initialized with wc_AesSetKey before calling this function. It is only enabled if the configure option WOLFSSL_AES_DIRECT is enabled.
    
    __Warning:__ In nearly all use cases ECB mode is considered to be less secure. Please avoid using ECB API’s directly whenever possible
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text of the encrypted message
    \param in pointer to the input buffer containing plain text to be encrypted
    
    _Example_
    \code
    Aes enc;
    // initialize enc with AesSetKey, using direction AES_ENCRYPTION
    byte msg [AES_BLOCK_SIZE]; // 16 bytes
    // initialize msg with plain text to encrypt
    byte cipher[AES_BLOCK_SIZE];
    wc_AesEncryptDirect(&enc, cipher, msg);
    \endcode
    
    \sa wc_AesDecryptDirect
    \sa wc_AesSetKeyDirect
*/
 WOLFSSL_API void wc_AesEncryptDirect(Aes* aes, byte* out, const byte* in);
 /*!
    \ingroup wolfCrypt
    \brief This function is a one-block decrypt of the input block, in, into the output block, out. It uses the key and iv (initialization vector) of the provided AES structure, which should be initialized with wc_AesSetKey before calling this function. It is only enabled if the configure option WOLFSSL_AES_DIRECT is enabled, and there is support for direct AES encryption on the system in question.
    
    __Warning:__ In nearly all use cases ECB mode is considered to be less secure. Please avoid using ECB API’s directly whenever possible
    
    \return none
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the plain text of the decrypted cipher text
    \param in pointer to the input buffer containing cipher text to be decrypted
    
    _Example_
    \code
    Aes dec;
    // initialize enc with AesSetKey, using direction AES_DECRYPTION
    byte cipher [AES_BLOCK_SIZE]; // 16 bytes
    // initialize cipher with cipher text to decrypt
    byte msg[AES_BLOCK_SIZE];
    wc_AesDecryptDirect(&dec, msg, cipher);
    \endcode
    
    \sa wc_AesEncryptDirect
    \sa wc_AesSetKeyDirect
 */
 WOLFSSL_API void wc_AesDecryptDirect(Aes* aes, byte* out, const byte* in);
 /*!
    \ingroup wolfCrypt
    \brief This function is used to set the AES keys for CTR mode with AES. It initializes an AES object with the given key, iv (initialization vector), and encryption dir (direction). It is only enabled if the configure option WOLFSSL_AES_DIRECT is enabled. Currently wc_AesSetKeyDirect uses wc_AesSetKey internally.
    
    __Warning:__ In nearly all use cases ECB mode is considered to be less secure. Please avoid using ECB API’s directly whenever possible
    
    \return 0 On successfully setting the key.
    \return BAD_FUNC_ARG Returned if the given key is an invalid length.
    
    \param aes pointer to the AES object used to encrypt data
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in
    \param iv initialization vector used to initialize the key
    \param dir Cipher direction. Set AES_ENCRYPTION to encrypt,  or AES_DECRYPTION to decrypt. (See enum in wolfssl/wolfcrypt/aes.h) (NOTE: If using wc_AesSetKeyDirect with Aes Counter mode (Stream cipher) only use AES_ENCRYPTION for both encrypting and decrypting)
    
    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24, or 32 byte key };
    byte iv[]  = { some 16 byte iv };
    if (ret = wc_AesSetKeyDirect(&enc, key, sizeof(key), iv, AES_ENCRYPTION) != 0) {
	// failed to set aes key
    }
    \endcode
    
    \sa wc_AesEncryptDirect
    \sa wc_AesDecryptDirect
    \sa wc_AesSetKey
 */
 WOLFSSL_API int  wc_AesSetKeyDirect(Aes* aes, const byte* key, word32 len,
                                const byte* iv, int dir);
#endif
#ifdef HAVE_AESGCM
/*!
    \ingroup wolfCrypt
    \brief This function is used to set the key for AES GCM (Galois/Counter Mode). It initializes an AES object with the given key. It is only enabled if the configure option HAVE_AESGCM is enabled at compile time.
    
    \return 0 On successfully setting the key.
    \return BAD_FUNC_ARG Returned if the given key is an invalid length.
    
    \param aes pointer to the AES object used to encrypt data
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param len length of the key passed in
    
    _Example_
    \code
    Aes enc;
    int ret = 0;
    byte key[] = { some 16, 24,32 byte key };
    if (ret = wc_AesGcmSetKey(&enc, key, sizeof(key)) != 0) {
	// failed to set aes key
    }
    \endcode
    
    \sa wc_AesGcmEncrypt
    \sa wc_AesGcmDecrypt
*/
 WOLFSSL_API int  wc_AesGcmSetKey(Aes* aes, const byte* key, word32 len);
 /*!
    \ingroup wolfCrypt
    \brief This function encrypts the input message, held in the buffer in, and stores the resulting cipher text in the output buffer out. It requires a new iv (initialization vector) for each call to encrypt. It also encodes the input authentication vector, authIn, into the authentication tag, authTag.
    
    \return 0 On successfully encrypting the input message
    
    \param aes - pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    \param in pointer to the input buffer holding the message to encrypt
    \param sz length of the input message to encrypt
    \param iv pointer to the buffer containing the initialization vector
    \param ivSz length of the initialization vector
    \param authTag pointer to the buffer in which to store the authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input authentication vector
    \param authInSz length of the input authentication vector
    
    _Example_
    \code
    Aes enc;
    // initialize aes structure by calling wc_AesGcmSetKey

    byte plain[AES_BLOCK_LENGTH * n]; //n being a positive integer making plain some multiple of 16 bytes
    // initialize plain with msg to encrypt
    byte cipher[sizeof(plain)];
    byte iv[] = // some 16 byte iv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // Authentication Vector

    wc_AesGcmEncrypt(&enc, cipher, plain, sizeof(cipher), iv, sizeof(iv),
			authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode
    
    \sa wc_AesGcmSetKey
    \sa wc_AesGcmDecrypt
 */
 WOLFSSL_API int  wc_AesGcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 /*!
    \ingroup wolfCrypt
    \brief This function decrypts the input cipher text, held in the buffer in, and stores the resulting message text in the output buffer out. It also checks the input authentication vector, authIn, against the supplied authentication tag, authTag.
    
    \return 0 On successfully decrypting the input message
    \return AES_GCM_AUTH_E If the authentication tag does not match the supplied authentication code vector, authTag.
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the message text
    \param in pointer to the input buffer holding the cipher text to decrypt
    \param sz length of the cipher text to decrypt
    \param iv pointer to the buffer containing the initialization vector
    \param ivSz length of the initialization vector
    \param authTag pointer to the buffer containing the authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input authentication vector
    \param authInSz length of the input authentication vector
    
    _Example_
    \code
    Aes enc; //can use the same struct as was passed to wc_AesGcmEncrypt 
    // initialize aes structure by calling wc_AesGcmSetKey if not already done

    byte cipher[AES_BLOCK_LENGTH * n]; //n being a positive integer making cipher some multiple of 16 bytes
    // initialize cipher with cipher text to decrypt
    byte output[sizeof(cipher)];
    byte iv[] = // some 16 byte iv
    byte authTag[AUTH_TAG_LENGTH];
    byte authIn[] = // Authentication Vector

    wc_AesGcmDecrypt(&enc, output, cipher, sizeof(cipher), iv, sizeof(iv),
			authTag, sizeof(authTag), authIn, sizeof(authIn));
    \endcode
    
    \sa wc_AesGcmSetKey
    \sa wc_AesGcmEncrypt
 */
 WOLFSSL_API int  wc_AesGcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 sz,
                                   const byte* iv, word32 ivSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 
 /*!
    \ingroup wolfCrypt
    \brief This function initializes and sets the key for a GMAC object to be used for Galois Message Authentication.
    
    \return 0 On successfully setting the key
    \return BAD_FUNC_ARG Returned if key length is invalid.
    
    \param gmac pointer to the gmac object used for authentication
    \param key 16, 24, or 32 byte secret key for authentication
    \param len length of the key
    
    _Example_
    \code
    Gmac gmac;
    key[] = { some 16, 24, or 32 byte length key };
    wc_GmacSetKey(&gmac, key, sizeof(key));
    \endcode
    
    \sa wc_GmacUpdate
 */
 WOLFSSL_API int wc_GmacSetKey(Gmac* gmac, const byte* key, word32 len);
 /*!
    \ingroup wolfCrypt
    \brief This function generates the Gmac hash of the authIn input and stores the result in the authTag buffer. After running wc_GmacUpdate, one should compare the generated authTag to a known authentication tag to verify the authenticity of a message.
    
    \return 0 On successfully computing the Gmac hash.
    
    \param gmac pointer to the gmac object used for authentication
    \param iv initialization vector used for the hash
    \param ivSz size of the initialization vector used
    \param authIn pointer to the buffer containing the authentication vector to verify
    \param authInSz size of the authentication vector
    \param authTag pointer to the output buffer in which to store the Gmac hash
    \param authTagSz the size of the output buffer used to store the Gmac hash
    
    _Example_
    \code
    Gmac gmac;
    key[] = { some 16, 24, or 32 byte length key };
    iv[] = { some 16 byte length iv };

    wc_GmacSetKey(&gmac, key, sizeof(key));
    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE]; // will store authentication code

    wc_GmacUpdate(&gmac, iv, sizeof(iv), authIn, sizeof(authIn), tag, sizeof(tag));
    \endcode
    
    \sa wc_GmacSetKey
 */
 WOLFSSL_API int wc_GmacUpdate(Gmac* gmac, const byte* iv, word32 ivSz,
                               const byte* authIn, word32 authInSz,
                               byte* authTag, word32 authTagSz);
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
/*!
    \ingroup wolfCrypt
    \brief This function sets the key for an AES object using CCM (Counter with CBC-MAC). It takes a pointer to an AES structure and initializes it with supplied key.
    
    \return none
    
    \param aes aes structure in which to store the supplied key
    \param key 16, 24, or 32 byte secret key for encryption and decryption
    \param keySz size of the supplied key
    
    _Example_
    \code
    Aes enc;
    key[] = { some 16, 24, or 32 byte length key };

    wc_AesCcmSetKey(&aes, key, sizeof(key));
    \endcode
    
    \sa wc_AesCcmEncrypt
    \sa wc_AesCcmDecrypt
*/
 WOLFSSL_API int  wc_AesCcmSetKey(Aes* aes, const byte* key, word32 keySz);
 /*!
    \ingroup wolfCrypt
    \brief This function encrypts the input message, in, into the output buffer, out, using CCM (Counter with CBC-MAC). It subsequently calculates and stores the authorization tag, authTag, from the authIn input.
    
    \return none
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    \param in pointer to the input buffer holding the message to encrypt
    \param sz length of the input message to encrypt
    \param nonce pointer to the buffer containing the nonce (number only used once)
    \param nonceSz length of the nonce
    \param authTag pointer to the buffer in which to store the authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input authentication vector
    \param authInSz length of the input authentication vector
    
    _Example_
    \code
    Aes enc;
    // initialize enc with wc_AesCcmSetKey

    nonce[] = { initialize nonce };
    plain[] = { some plain text message };
    cipher[sizeof(plain)];

    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE]; // will store authentication code

    wc_AesCcmEncrypt(&enc, cipher, plain, sizeof(plain), nonce, sizeof(nonce),
			tag, sizeof(tag), authIn, sizeof(authIn));
    \endcode
    
    \sa wc_AesCcmSetKey
    \sa wc_AesCcmDecrypt
 */
 WOLFSSL_API int  wc_AesCcmEncrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
 /*!
    \ingroup wolfCrypt
    \brief This function decrypts the input cipher text, in, into the output buffer, out, using CCM (Counter with CBC-MAC). It subsequently calculates the authorization tag, authTag, from the authIn input. If the authorization tag is invalid, it sets the output buffer to zero and returns the error: AES_CCM_AUTH_E.
    
    \return 0 On successfully decrypting the input message
    \return AES_CCM_AUTH_E If the authentication tag does not match the supplied authentication code vector, authTag.
    
    \param aes pointer to the AES object used to encrypt data
    \param out pointer to the output buffer in which to store the cipher text
    \param in pointer to the input buffer holding the message to encrypt
    \param sz length of the input cipher text to decrypt
    \param nonce pointer to the buffer containing the nonce (number only used once)
    \param nonceSz length of the nonce
    \param authTag pointer to the buffer in which to store the authentication tag
    \param authTagSz length of the desired authentication tag
    \param authIn pointer to the buffer containing the input authentication vector
    \param authInSz length of the input authentication vector
    
    _Example_
    \code
    Aes dec;
    // initialize dec with wc_AesCcmSetKey

    nonce[] = { initialize nonce };
    cipher[] = { encrypted message };
    plain[sizeof(cipher)];

    authIn[] = { some 16 byte authentication input };
    tag[AES_BLOCK_SIZE] = { authentication tag received for verification };

    int return = wc_AesCcmDecrypt(&dec, plain, cipher, sizeof(cipher), nonce, sizeof(nonce),tag, sizeof(tag), authIn, sizeof(authIn));
    if(return != 0) {
	// decrypt error, invalid authentication code
    }
    \endcode
    
    \sa wc_AesCcmSetKey
    \sa wc_AesCcmEncrypt
 */
 WOLFSSL_API int  wc_AesCcmDecrypt(Aes* aes, byte* out,
                                   const byte* in, word32 inSz,
                                   const byte* nonce, word32 nonceSz,
                                   const byte* authTag, word32 authTagSz,
                                   const byte* authIn, word32 authInSz);
#endif /* HAVE_AESCCM */
#ifdef HAVE_AES_KEYWRAP
 WOLFSSL_API int  wc_AesKeyWrap(const byte* key, word32 keySz,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
 WOLFSSL_API int  wc_AesKeyUnWrap(const byte* key, word32 keySz,
                                const byte* in, word32 inSz,
                                byte* out, word32 outSz,
                                const byte* iv);
#endif /* HAVE_AES_KEYWRAP */

WOLFSSL_API int wc_AesGetKeySize(Aes* aes, word32* keySize);

WOLFSSL_API int  wc_AesInit(Aes*, void*, int);
WOLFSSL_API void wc_AesFree(Aes*);

#ifdef __cplusplus
    } /* extern "C" */
#endif


#endif /* NO_AES */
#endif /* WOLF_CRYPT_AES_H */
