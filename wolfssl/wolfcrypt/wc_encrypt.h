/* wc_encrypt.h
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



#ifndef WOLF_CRYPT_ENCRYPT_H
#define WOLF_CRYPT_ENCRYPT_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef NO_AES
WOLFSSL_API int  wc_AesCbcEncryptWithKey(byte* out, const byte* in, word32 inSz,
                                         const byte* key, word32 keySz,
                                         const byte* iv);
/*!
    \ingroup wolfCrypt
    \brief Decrypts a cipher from the input buffer in, and places the resulting plain text in the output buffer out using cipher block chaining with AES. This function does not require an AES structure to be initialized. Instead, it takes in a key and an iv (initialization vector) and uses these to initialize an AES object and then decrypt the cipher text.
    
    \return 0 On successfully decrypting message
    \return BAD_ALIGN_E Returned on block align error
    \return BAD_FUNC_ARG Returned if key length is invalid or AES object is null during AesSetIV
    \return MEMORY_E Returned if WOLFSSL_SMALL_STACK is enabled and XMALLOC fails to instantiate an AES object.
    
    \param out pointer to the output buffer in which to store the plain text of the decrypted message
    \param in pointer to the input buffer containing cipher text to be decrypted
    \param inSz size of input message
    \param key 16, 24, or 32 byte secret key for decryption
    \param keySz size of key used for decryption
    
    _Example_
    \code
    int ret = 0;
    byte key[] = { some 16, 24, or 32 byte key };
    byte iv[]  = { some 16 byte iv };
    byte cipher[AES_BLOCK_SIZE * n]; //n being a positive integer making cipher some multiple of 16 bytes
    // fill cipher with cipher text
    byte plain [AES_BLOCK_SIZE * n];
    if ((ret = wc_AesCbcDecryptWithKey(plain, cipher, AES_BLOCK_SIZE, key, AES_BLOCK_SIZE, iv)) != 0 ) {
	// Decrypt Error
    }
    \endcode
    
    \sa wc_AesSetKey
    \sa wc_AesSetIV
    \sa wc_AesCbcEncrypt
    \sa wc_AesCbcDecrypt
*/
WOLFSSL_API int  wc_AesCbcDecryptWithKey(byte* out, const byte* in, word32 inSz,
                                         const byte* key, word32 keySz,
                                         const byte* iv);
#endif /* !NO_AES */


#ifndef NO_DES3
WOLFSSL_API int  wc_Des_CbcDecryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);
WOLFSSL_API int  wc_Des_CbcEncryptWithKey(byte* out,
                                          const byte* in, word32 sz,
                                          const byte* key, const byte* iv);
WOLFSSL_API int  wc_Des3_CbcEncryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);
WOLFSSL_API int  wc_Des3_CbcDecryptWithKey(byte* out,
                                           const byte* in, word32 sz,
                                           const byte* key, const byte* iv);
#endif /* !NO_DES3 */

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ENCRYPT_H */

