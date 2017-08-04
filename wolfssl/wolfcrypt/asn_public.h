/* asn_public.h
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



#ifndef WOLF_CRYPT_ASN_PUBLIC_H
#define WOLF_CRYPT_ASN_PUBLIC_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* guard on redeclaration */
#ifndef WC_ECCKEY_TYPE_DEFINED
    typedef struct ecc_key ecc_key;
    #define WC_ECCKEY_TYPE_DEFINED
#endif
#ifndef WC_ED25519KEY_TYPE_DEFINED
    typedef struct ed25519_key ed25519_key;
    #define WC_ED25519KEY_TYPE_DEFINED
#endif
#ifndef WC_RSAKEY_TYPE_DEFINED
    typedef struct RsaKey RsaKey;
    #define WC_RSAKEY_TYPE_DEFINED
#endif
#ifndef WC_RNG_TYPE_DEFINED
    typedef struct WC_RNG WC_RNG;
    #define WC_RNG_TYPE_DEFINED
#endif

/* Certificate file Type */
enum CertType {
    CERT_TYPE       = 0,
    PRIVATEKEY_TYPE,
    DH_PARAM_TYPE,
    DSA_PARAM_TYPE,
    CRL_TYPE,
    CA_TYPE,
    ECC_PRIVATEKEY_TYPE,
    DSA_PRIVATEKEY_TYPE,
    CERTREQ_TYPE,
    DSA_TYPE,
    ECC_TYPE,
    RSA_TYPE,
    PUBLICKEY_TYPE,
    RSA_PUBLICKEY_TYPE,
    ECC_PUBLICKEY_TYPE,
    TRUSTED_PEER_TYPE,
    EDDSA_PRIVATEKEY_TYPE,
    ED25519_TYPE
};


/* Signature type, by OID sum */
enum Ctc_SigType {
    CTC_SHAwDSA      = 517,
    CTC_MD2wRSA      = 646,
    CTC_MD5wRSA      = 648,
    CTC_SHAwRSA      = 649,
    CTC_SHAwECDSA    = 520,
    CTC_SHA224wRSA   = 658,
    CTC_SHA224wECDSA = 527,
    CTC_SHA256wRSA   = 655,
    CTC_SHA256wECDSA = 524,
    CTC_SHA384wRSA   = 656,
    CTC_SHA384wECDSA = 525,
    CTC_SHA512wRSA   = 657,
    CTC_SHA512wECDSA = 526,
    CTC_ED25519      = 256
};

enum Ctc_Encoding {
    CTC_UTF8       = 0x0c, /* utf8      */
    CTC_PRINTABLE  = 0x13  /* printable */
};

enum Ctc_Misc {
    CTC_COUNTRY_SIZE  =     2,
    CTC_NAME_SIZE     =    64,
    CTC_DATE_SIZE     =    32,
    CTC_MAX_ALT_SIZE  = 16384,   /* may be huge */
    CTC_SERIAL_SIZE   =     8,
#ifdef WOLFSSL_CERT_EXT
    /* AKID could contains: hash + (Option) AuthCertIssuer,AuthCertSerialNum
     * We support only hash */
    CTC_MAX_SKID_SIZE = 32, /* SHA256_DIGEST_SIZE */
    CTC_MAX_AKID_SIZE = 32, /* SHA256_DIGEST_SIZE */
    CTC_MAX_CERTPOL_SZ = 64,
    CTC_MAX_CERTPOL_NB = 2 /* Max number of Certificate Policy */
#endif /* WOLFSSL_CERT_EXT */
};


#ifdef WOLFSSL_CERT_GEN

typedef struct CertName {
    char country[CTC_NAME_SIZE];
    char countryEnc;
    char state[CTC_NAME_SIZE];
    char stateEnc;
    char locality[CTC_NAME_SIZE];
    char localityEnc;
    char sur[CTC_NAME_SIZE];
    char surEnc;
    char org[CTC_NAME_SIZE];
    char orgEnc;
    char unit[CTC_NAME_SIZE];
    char unitEnc;
    char commonName[CTC_NAME_SIZE];
    char commonNameEnc;
    char email[CTC_NAME_SIZE];  /* !!!! email has to be last !!!! */
} CertName;


/* for user to fill for certificate generation */
typedef struct Cert {
    int      version;                   /* x509 version  */
    byte     serial[CTC_SERIAL_SIZE];   /* serial number */
    int      sigType;                   /* signature algo type */
    CertName issuer;                    /* issuer info */
    int      daysValid;                 /* validity days */
    int      selfSigned;                /* self signed flag */
    CertName subject;                   /* subject info */
    int      isCA;                      /* is this going to be a CA */
    /* internal use only */
    int      bodySz;                    /* pre sign total size */
    int      keyType;                   /* public key type of subject */
#ifdef WOLFSSL_ALT_NAMES
    byte     altNames[CTC_MAX_ALT_SIZE]; /* altNames copy */
    int      altNamesSz;                 /* altNames size in bytes */
    byte     beforeDate[CTC_DATE_SIZE];  /* before date copy */
    int      beforeDateSz;               /* size of copy */
    byte     afterDate[CTC_DATE_SIZE];   /* after date copy */
    int      afterDateSz;                /* size of copy */
#endif
#ifdef WOLFSSL_CERT_EXT
    byte    skid[CTC_MAX_SKID_SIZE];     /* Subject Key Identifier */
    int     skidSz;                      /* SKID size in bytes */
    byte    akid[CTC_MAX_AKID_SIZE];     /* Authority Key Identifier */
    int     akidSz;                      /* AKID size in bytes */
    word16  keyUsage;                    /* Key Usage */
    char    certPolicies[CTC_MAX_CERTPOL_NB][CTC_MAX_CERTPOL_SZ];
    word16  certPoliciesNb;              /* Number of Cert Policy */
#endif
#ifdef WOLFSSL_CERT_REQ
    char     challengePw[CTC_NAME_SIZE];
#endif
    void*   heap; /* heap hint */
} Cert;


/* Initialize and Set Certificate defaults:
   version    = 3 (0x2)
   serial     = 0 (Will be randomly generated)
   sigType    = SHA_WITH_RSA
   issuer     = blank
   daysValid  = 500
   selfSigned = 1 (true) use subject as issuer
   subject    = blank
   isCA       = 0 (false)
   keyType    = RSA_KEY (default)
*/
/*!
    \ingroup wolfCrypt
    
    \brief This function initializes a default cert, with the default options: version = 3 (0x2), serial = 0, sigType = SHA_WITH_RSA, issuer = blank, daysValid = 500, selfSigned = 1 (true) use subject as issuer, subject = blank
    
    \return none No returns.
    
    \param cert pointer to an uninitialized cert structure to initialize
    
    _Example_
    \code
    Cert myCert;
    wc_InitCert(&myCert);
    \endcode
    
    \sa wc_MakeCert
    \sa wc_MakeCertReq
*/
WOLFSSL_API int wc_InitCert(Cert*);
WOLFSSL_API int  wc_MakeCert_ex(Cert* cert, byte* derBuffer, word32 derSz,
                                int keyType, void* key, WC_RNG* rng);
/*!
    \ingroup wolfCrypt
    
    \brief Used to make CA signed certs. Called after the subject information has been entered. This function makes an x509 Certificate v3 RSA or ECC from a cert input. It then writes this cert to derBuffer. It takes in either an rsaKey or an eccKey to generate the certificate.  The certificate must be initialized with wc_InitCert before this method is called.
    
    \return Success On successfully making an x509 certificate from the specified input cert, returns the size of the cert generated.
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the provided derBuffer is too small to store the generated certificate
    \return Others Additional error messages may be returned if the cert generation is not successful.

    \param cert pointer to an initialized cert structure 
    \param derBuffer pointer to the buffer in which to hold the generated cert
    \param derSz size of the buffer in which to store the cert
    \param rsaKey pointer to an RsaKey structure containing the rsa key used to generate the certificate
    \param eccKey pointer to an EccKey structure containing the ecc key used to generate the certificate
    \param rng pointer to the random number generator used to make the cert
    
    _Example_
    \code
    Cert myCert;
    wc_InitCert(&myCert); 
    RNG rng;
    //initialize rng;
    RsaKey key;
    //initialize key;
    byte * derCert = malloc(FOURK_BUF);
    word32 certSz;
    certSz = wc_MakeCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeCertReq
*/
WOLFSSL_API int  wc_MakeCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*,
                             ecc_key*, WC_RNG*);
#ifdef WOLFSSL_CERT_REQ
    WOLFSSL_API int  wc_MakeCertReq_ex(Cert*, byte* derBuffer, word32 derSz,
                                       int, void*);
/*!
    \ingroup wolfCrypt
    
    \brief This function makes a certificate signing request using the input certificate and writes the output to derBuffer. It takes in either an rsaKey or an eccKey to generate the certificate request. wc_SignCert() will need to be called after this function to sign the certificate request.  Please see the wolfCrypt test application (./wolfcrypt/test/test.c) for an example usage of this function.
    
    \return Success On successfully making an X.509 certificate request from the specified input cert, returns the size of the certificate request generated.
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the provided derBuffer is too small to store the generated certificate
    \return Other Additional error messages may be returned if the certificate request generation is not successful.
    
    \param cert pointer to an initialized cert structure 
    \param derBuffer pointer to the buffer in which to hold the generated certificate request
    \param derSz size of the buffer in which to store the certificate request
    \param rsaKey pointer to an RsaKey structure containing the rsa key used to generate the certificate request
    \param eccKey pointer to an EccKey structure containing the ecc key used to generate the certificate request

    _Example_
    \code
    Cert myCert;
    // initialize myCert
    EccKey key;
    //initialize key;
    byte* derCert = (byte*)malloc(FOURK_BUF);

    word32 certSz;
    certSz = wc_MakeCertReq(&myCert, derCert, FOURK_BUF, NULL, &key);
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeCert
*/
    WOLFSSL_API int  wc_MakeCertReq(Cert*, byte* derBuffer, word32 derSz,
                                    RsaKey*, ecc_key*);
#endif
WOLFSSL_API int  wc_SignCert_ex(int requestSz, int sType, byte* buffer,
                                word32 buffSz, int keyType, void* key,
                                WC_RNG* rng);
/*!
    \ingroup wolfCrpy
    
    \brief This function signs buffer and adds the signature to the end of buffer. It takes in a signature type. Must be called after wc_MakeCert() or wc_MakeCertReq() if creating a CA signed cert.
    
    \return Success On successfully signing the certificate, returns the new size of the cert (including signature).
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the provided buffer is too small to store the generated certificate
    \return Other Additional error messages may be returned if the cert generation is not successful.
    
    \param requestSz the size of the certificate body we’re requesting to have signed
    \param sType Type of signature to create. Valid options are: CTC_MD5wRSA, CTC_SHAwRSA, CTC_SHAwECDSA, CTC_SHA256wECDSA, andCTC_SHA256wRSA
    \param buffer pointer to the buffer containing the certificate to be signed.  On success: will hold the newly signed certificate
    \param buffSz the (total) size of the buffer in which to store the newly signed certificate
    \param rsaKey pointer to an RsaKey structure containing the rsa key to used to sign the certificate
    \param eccKey pointer to an EccKey structure containing the ecc key to used to sign the certificate
    \param rng pointer to the random number generator used to sign the certificate
    
    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // initialize myCert, derCert
    RsaKey key;
    // initialize key;
    RNG rng;
    // initialize rng

    word32 certSz;
    certSz = wc_SignCert(myCert.bodySz, myCert.sigType,derCert,FOURK_BUF, &key, NULL, 
&rng);
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeCert
*/
WOLFSSL_API int  wc_SignCert(int requestSz, int sigType, byte* derBuffer,
                             word32 derSz, RsaKey*, ecc_key*, WC_RNG*);
/*!
    \ingroup wolfCrypt
    
    \brief This function is a combination of the previous two functions, wc_MakeCert and wc_SignCert for self signing (the previous functions may be used for CA requests). It makes a certificate, and then signs it, generating a self-signed certificate.
    
    \return Success On successfully signing the certificate, returns the new size of the cert.
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the provided buffer is too small to store the generated certificate
    \return Other Additional error messages may be returned if the cert generation is not successful.
    
    \param cert pointer to the cert to make and sign
    \param buffer pointer to the buffer in which to hold the signed certificate
    \param buffSz size of the buffer in which to store the signed certificate
    \param key pointer to an RsaKey structure containing the rsa key to used to sign the certificate
    \param rng pointer to the random number generator used to generate and sign the certificate

    _Example_
    \code
    Cert myCert;
    byte* derCert = (byte*)malloc(FOURK_BUF);
    // initialize myCert, derCert
    RsaKey key;
    // initialize key;
    RNG rng;
    // initialize rng

    word32 certSz;
    certSz = wc_MakeSelfCert(&myCert, derCert, FOURK_BUF, &key, NULL, &rng);
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeCert
    \sa wc_SignCert
*/
WOLFSSL_API int  wc_MakeSelfCert(Cert*, byte* derBuffer, word32 derSz, RsaKey*,
                             WC_RNG*);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the issuer for a certificate to the issuer in the provided pem issuerFile. It also changes the certificate’s self-signed attribute to false.  The issuer specified in issuerFile is verified prior to setting the cert issuer.  This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the issuer for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the issuer
    \param issuerFile path of the file containing the pem formatted certificate
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetIssuer(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting issuer
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetSubject
    \sa wc_SetIssuerBuffer
*/
WOLFSSL_API int  wc_SetIssuer(Cert*, const char*);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the subject for a certificate to the subject in the provided pem subjectFile.  This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the issuer for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the issuer
    \param subjectFile path of the file containing the pem formatted certificate
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetSubject(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting subject
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetIssuer
*/
WOLFSSL_API int  wc_SetSubject(Cert*, const char*);
#ifdef WOLFSSL_ALT_NAMES
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the alternate names for a certificate to the alternate names in the provided pem file. This is useful in the case that one wishes to secure multiple domains with the same certificate. This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the alt names for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the alt names
    \param file path of the file containing the pem formatted certificate
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    if(wc_SetSubject(&myCert, ”./path/to/ca-cert.pem”) != 0) {
    	// error setting alt names
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetIssuer
*/
    WOLFSSL_API int  wc_SetAltNames(Cert*, const char*);
#endif
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the issuer for a certificate from the issuer in the provided der buffer. It also changes the certificate’s self-signed attribute to false.  This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the issuer for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the issuer
    \param der pointer to the buffer containing the der formatted certificate from which to grab the issuer
    \param derSz size of the buffer containing the der formatted certificate from which to grab the issuer
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetIssuerBuffer(&myCert, der, FOURK_BUF) != 0) {
	    // error setting issuer
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetIssuer
*/
WOLFSSL_API int  wc_SetIssuerBuffer(Cert*, const byte*, int);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the subject for a certificate from the subject in the provided der buffer. This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the subject for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the subject
    \param der pointer to the buffer containing the der formatted certificate from which to grab the subject
    \param derSz size of the buffer containing the der formatted certificate from which to grab the subject
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetSubjectBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetSubject
*/
WOLFSSL_API int  wc_SetSubjectBuffer(Cert*, const byte*, int);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the alternate names for a certificate from the alternate names in the provided der buffer. This is useful in the case that one wishes to secure multiple domains with the same certificate.  This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the alternate names for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the alternate names
    \param der pointer to the buffer containing the der formatted certificate from which to grab the alternate names
    \param derSz size of the buffer containing the der formatted certificate from which to grab the alternate names
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetAltNamesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_SetAltNames
*/
WOLFSSL_API int  wc_SetAltNamesBuffer(Cert*, const byte*, int);
/*!
    \ingroup wolfCrypt
    
    \brief This function sets the dates for a certificate from the date range in the provided der buffer. This method is used to set fields prior to signing.
    
    \return 0 Returned on successfully setting the dates for the certificate
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_PARSE_E Returned if there is an error parsing the cert header file
    \return ASN_OBJECT_ID_E Returned if there is an error parsing the encryption type from the cert
    \return ASN_EXPECT_0_E Returned if there is a formatting error in the encryption specification of the cert file
    \return ASN_BEFORE_DATE_E Returned if the date is before the certificate start date
    \return ASN_AFTER_DATE_E Returned if the date is after the certificate expiration date
    \return ASN_BITSTR_E Returned if there is an error parsing a bit string from the certificate
    \return ASN_NTRU_KEY_E Returned if there is an error parsing the NTRU key from the certificate
    \return ECC_CURVE_OID_E Returned if there is an error parsing the ECC key from the certificate
    \return ASN_UNKNOWN_OID_E Returned if the certificate is using an unknown key object id
    \return ASN_VERSION_E Returned if the ALLOW_V1_EXTENSIONS option is not defined and the certificate is a V1 or V2 certificate
    \return BAD_FUNC_ARG Returned if there is an error processing the certificate extension
    \return ASN_CRIT_EXT_E Returned if an unfamiliar critical extension is encountered in processing the certificate
    \return ASN_SIG_OID_E Returned if the signature encryption type is not the same as the encryption type of the certificate in the provided file
    \return ASN_SIG_CONFIRM_E Returned if confirming the certification signature fails
    \return ASN_NAME_INVALID_E Returned if the certificate’s name is not permitted by the CA name constraints
    \return ASN_NO_SIGNER_E Returned if there is no CA signer to verify the certificate’s authenticity
    
    \param cert pointer to the cert for which to set the dates
    \param der pointer to the buffer containing the der formatted certificate from which to grab the date range
    \param derSz size of the buffer containing the der formatted certificate from which to grab the date range
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    byte* der;
    der = (byte*)malloc(FOURK_BUF);
    // initialize der
    if(wc_SetDatesBuffer(&myCert, der, FOURK_BUF) != 0) {
    	// error setting subject
    }
    \endcode
    
    \sa wc_InitCert
*/
WOLFSSL_API int  wc_SetDatesBuffer(Cert*, const byte*, int);

#ifdef WOLFSSL_CERT_EXT
WOLFSSL_API int wc_SetAuthKeyIdFromPublicKey_ex(Cert *cert, int keyType,
                                                void* key);
/*!
    \ingroup wolfCrypt
    
    \brief Set AKID from either an RSA or ECC public key. note: Only set one of rsakey or eckey, not both.
    
    \return 0 Success
    \return BAD_FUNC_ARG Either cert is null or both rsakey and eckey are null.
    \return MEMORY_E Error allocating memory.
    \return PUBLIC_KEY_E Error writing to the key.
    
    \param cert Pointer to the certificate to set the SKID.
    \param rsakey Pointer to the RsaKey struct to read from.
    \param eckey Pointer to the ecc_key to read from. 
    
    _Example_
    \code
    Cert myCert;
    RsaKey keypub;

    wc_InitRsaKey(&keypub, 0);

    if (wc_SetAuthKeyIdFromPublicKey(&myCert, &keypub, NULL) != 0)
    {
        // Handle error
    }
    \endcode
    
    \sa wc_SetSubjectKeyId
    \sa wc_SetAuthKeyId
    \sa wc_SetAuthKeyIdFromCert
*/
WOLFSSL_API int wc_SetAuthKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey,
                                             ecc_key *eckey);
/*!
    \ingroup wolfCrypt
    
    \brief Set AKID from from DER encoded certificate.
    
    \return 0 Success
    \return BAD_FUNC_ARG Error if any argument is null or derSz is less than 0.
    \return MEMORY_E Error if problem allocating memory.
    \return ASN_NO_SKID No subject key ID found.
    
    \param cert The Cert struct to write to.
    \param der The DER encoded certificate buffer.
    \param derSz Size of der in bytes.

    _Example_
    \code
    Cert some_cert;
    byte some_der[] = { // Initialize a DER buffer };
    wc_InitCert(&some_cert);
    if(wc_SetAuthKeyIdFromCert(&some_cert, some_der, sizeof(some_der) != 0)
    {
        // Handle error
    }
    \endcode
    
    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyId
*/
WOLFSSL_API int wc_SetAuthKeyIdFromCert(Cert *cert, const byte *der, int derSz);
/*!
    \ingroup wolfCrypt
    
    \brief Set AKID from certificate file in PEM format.
    
    \return 0 Success
    \return BAD_FUNC_ARG Error if cert or file is null.
    \return MEMORY_E Error if problem allocating memory.
    
    \param cert Cert struct you want to set the AKID of.
    \param file Buffer containing PEM cert file.

    _Example_
    \code
    char* file_name = "/path/to/file";
    cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetAuthKeyId(&some_cert, file_name) != 0)
    {
        // Handle Error
    }
    \endcode
    
    \sa wc_SetAuthKeyIdFromPublicKey
    \sa wc_SetAuthKeyIdFromCert
*/
WOLFSSL_API int wc_SetAuthKeyId(Cert *cert, const char* file);
WOLFSSL_API int wc_SetSubjectKeyIdFromPublicKey_ex(Cert *cert, int keyType,
                                                   void* key);
/*!
    \ingroup wolfCrypt
    
    \brief Set SKID from RSA or ECC public key.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returned if cert or rsakey and eckey is null.
    \return MEMORY_E Returned if there is an error allocating memory.
    \return PUBLIC_KEY_E Returned if there is an error getting the public key.
    
    \param cert Pointer to a Cert structure to be used.
    \param rsakey Pointer to an RsaKey structure 
    \param eckey Pointer to an ecc_key structure

    _Example_
    \code
    Cert some_cert;
    RsaKey some_key;
    wc_InitCert(&some_cert);
    wc_InitRsaKey(&some_key);

    if(wc_SetSubjectKeyIdFromPublicKey(&some_cert,&some_key, NULL) != 0)
    {
        // Handle Error
    }
    \endcode
    
    \sa wc_SetSubjectKeyId
    \sa wc_SetSubjectKeyIdFromNtruPublicKey
*/
WOLFSSL_API int wc_SetSubjectKeyIdFromPublicKey(Cert *cert, RsaKey *rsakey,
                                                ecc_key *eckey);
/*!
    \ingroup wolfCrypt
    
    \brief Set SKID from public key file in PEM format.  Both arguments are required.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returns if cert or file is null.
    \return MEMORY_E Returns if there is a problem allocating memory for key.
    \return PUBLIC_KEY_E Returns if there is an error decoding the public key.
    
    \param cert Cert structure to set the SKID of.
    \param file Contains the PEM encoded file.
    
    _Example_
    \code
    const char* file_name = "path/to/file";
    Cert some_cert;
    wc_InitCert(&some_cert);

    if(wc_SetSubjectKeyId(&some_cert, file_name) != 0)
    {
        // Handle Error 
    }
    \endcode
    
    \sa wc_SetSubjectKeyIdFromNtruPublicKey
    \sa wc_SetSubjectKeyIdFromPublicKey
*/
WOLFSSL_API int wc_SetSubjectKeyId(Cert *cert, const char* file);

#ifdef HAVE_NTRU
/*!
    \ingroup wolfCrypt
    
    \brief Set SKID from NTRU public key.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returned if cert or ntruKey is null.
    \return MEMORY_E Returned if there is an error allocating memory.
    \return PUBLIC_KEY_E Returned if there is an error getting the public key.
    
    \param cert Pointer to a Cert structure to be used.
    \param ntruKey Pointer to the NTRU public key in a byte array.
    \param ntruKeySz Size of the NTRU byte array.
    
    _Example_
    \code
    Cert some_cert;
    wc_InitCert(&some_cert);
    byte some_ntru_key[] = { // Load an NTRU key  };
    word32 ntru_size = sizeof(some_ntru_key);

    if(wc_SetSubjectKeyIdFromNtruPublicKey(&some_cert, 
    some_ntru_key, ntru_size) != 0)
    {
        // Handle error
    }
    \endcode
    
    \sa SetKeyIdFromPublicKey
*/
WOLFSSL_API int wc_SetSubjectKeyIdFromNtruPublicKey(Cert *cert, byte *ntruKey,
                                                    word16 ntruKeySz);
#endif

/* Set the KeyUsage.
 * Value is a string separated tokens with ','. Accepted tokens are :
 * digitalSignature,nonRepudiation,contentCommitment,keyCertSign,cRLSign,
 * dataEncipherment,keyAgreement,keyEncipherment,encipherOnly and decipherOnly.
 *
 * nonRepudiation and contentCommitment are for the same usage.
 */
 /*!
    \ingroup wolfCrypt
    
    \brief This function allows you to set the key usage using a comma delimited string of tokens. Accepted tokens are: digitalSignature, nonRepudiation, contentCommitment, keyCertSign, cRLSign, dataEncipherment, keyAgreement, keyEncipherment, encipherOnly, decipherOnly. Example: "digitalSignature,nonRepudiation" nonRepudiation and contentCommitment are for the same usage.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returned when either arg is null.
    \return MEMORY_E Returned when there is an error allocating memory.
    \return KEYUSAGE_E Returned if an unrecognized token is entered.
    
    \param cert Pointer to initialized Cert structure.
    \param value Comma delimited string of tokens to set usage.
    
    _Example_
    \code
    Cert cert;
    wc_InitCert(&cert);

    if(wc_SetKeyUsage(&cert, "cRLSign,keyCertSign") != 0)
    {
        // Handle error
    }
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeRsaKey
 */
WOLFSSL_API int wc_SetKeyUsage(Cert *cert, const char *value);

#endif /* WOLFSSL_CERT_EXT */

    #ifdef HAVE_NTRU
/*!
    \ingroup wolfCrypt
    
    \brief Used to make CA signed certs.  Called after the subject information has been entered. This function makes an NTRU Certificate from a cert input. It then writes this cert to derBuffer. It takes in an ntruKey and a rng to generate the certificate.  The certificate must be initialized with wc_InitCert before this method is called.
    
    \return Success On successfully making a NTRU certificate from the specified input cert, returns the size of the cert generated.
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the provided derBuffer is too small to store the generated certificate
    \return Other Additional error messages may be returned if the cert generation is not successful.

    \param cert pointer to an initialized cert structure
    \param derBuffer pointer to the buffer in which to store the generated certificate
    \param derSz size of the buffer in which to store the generated  certificate 
    \param ntruKey pointer to the key to be used to generate the NTRU certificate
    \param keySz size of the key used to generate the NTRU certificate
    \param rng pointer to the random number generator used to generate the NTRU certificate
    
    _Example_
    \code
    Cert myCert;
    // initialize myCert
    RNG rng;
    //initialize rng;
    byte ntruPublicKey[NTRU_KEY_SIZE];
    //initialize ntruPublicKey; 
    byte * derCert = malloc(FOURK_BUF);

    word32 certSz;
    certSz = wc_MakeNtruCert(&myCert, derCert, FOURK_BUF, &ntruPublicKey, NTRU_KEY_SIZE, &rng);
    \endcode
    
    \sa wc_InitCert
    \sa wc_MakeCert
*/
        WOLFSSL_API int  wc_MakeNtruCert(Cert*, byte* derBuffer, word32 derSz,
                                     const byte* ntruKey, word16 keySz,
                                     WC_RNG*);
    #endif

#endif /* WOLFSSL_CERT_GEN */

#if defined(WOLFSSL_CERT_EXT) || defined(WOLFSSL_PUB_PEM_TO_DER)
    #ifndef WOLFSSL_PEMPUBKEY_TODER_DEFINED
        #ifndef NO_FILESYSTEM
        /* forward from wolfssl */
        WOLFSSL_API int wolfSSL_PemPubKeyToDer(const char* fileName,
                                               unsigned char* derBuf, int derSz);
        #endif

        /* forward from wolfssl */
        WOLFSSL_API int wolfSSL_PubKeyPemToDer(const unsigned char*, int,
                                               unsigned char*, int);
        #define WOLFSSL_PEMPUBKEY_TODER_DEFINED
    #endif /* WOLFSSL_PEMPUBKEY_TODER_DEFINED */
#endif /* WOLFSSL_CERT_EXT || WOLFSSL_PUB_PEM_TO_DER */

#if defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN) || !defined(NO_DSA) \
                             || defined(OPENSSL_EXTRA)
/*!
    \ingroup wolfCrpyt
    
    \brief This function converts a der formatted input certificate, contained in the der buffer, into a pem formatted output certificate, contained in the output buffer. It should be noted that this is not an in place conversion, and a separate buffer must be utilized to store the pem formatted output.
    
    \return Success On successfully making a pem certificate from the input der cert, returns the size of the pem cert generated.
    \return BAD_FUNC_ARG Returned if there is an error parsing the der file and storing it as a pem file
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_INPUT_E Returned in the case of a base 64 encoding error
    \return BUFFER_E May be returned if the output buffer is too small to store the pem formatted certificate
    
    \param der pointer to the buffer of the certificate to convert
    \param derSz size of the the certificate to convert 
    \param output pointer to the buffer in which to store the pem formatted certificate
    \param outSz size of the buffer in which to store the pem formatted certificate
    \param type the type of certificate to generate. Valid types are: CERT_TYPE, PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE, and CERTREQ_TYPE.
    
    _Example_
    \code
    byte* der;
    // initialize der with certificate
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    pemSz = wc_DerToPem(der, derSz,pemFormatted,FOURK_BUF, CERT_TYPE);
    \endcode
    
    \sa wolfSSL_PemCertToDer
*/
    WOLFSSL_API int wc_DerToPem(const byte* der, word32 derSz, byte* output,
                                word32 outputSz, int type);
/*!
    \ingroup wolfCrypt
    
    \brief This function converts a der formatted input certificate, contained in the der buffer, into a pem formatted output certificate, contained in the output buffer. It should be noted that this is not an in place conversion, and a separate buffer must be utilized to store the pem formatted output.  Allows setting cipher info.
    
    \return Success On successfully making a pem certificate from the input der cert, returns the size of the pem cert generated.
    \return BAD_FUNC_ARG Returned if there is an error parsing the der file and storing it as a pem file
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return ASN_INPUT_E Returned in the case of a base 64 encoding error
    \return BUFFER_E May be returned if the output buffer is too small to store the pem formatted certificate
    
    \param der pointer to the buffer of the certificate to convert
    \param derSz size of the the certificate to convert 
    \param output pointer to the buffer in which to store the pem formatted certificate
    \param outSz size of the buffer in which to store the pem formatted certificate
    \param cipher_inf Additional cipher information.
    \param type the type of certificate to generate. Valid types are: CERT_TYPE, PRIVATEKEY_TYPE, ECC_PRIVATEKEY_TYPE, and CERTREQ_TYPE.
    
    _Example_
    \code
    byte* der;
    // initialize der with certificate
    byte* pemFormatted[FOURK_BUF];

    word32 pemSz;
    byte* cipher_info[] { Additional cipher info. }
    pemSz = wc_DerToPemEx(der, derSz,pemFormatted,FOURK_BUF, ,CERT_TYPE);
    \endcode
    
    \sa wolfSSL_PemCertToDer
*/
    WOLFSSL_API int wc_DerToPemEx(const byte* der, word32 derSz, byte* output,
                                word32 outputSz, byte *cipherIno, int type);
#endif

#ifdef HAVE_ECC
    /* private key helpers */
/*!
    \ingroup wolfCrypt
    
    \brief This function reads in an ECC private key from the input buffer, input, parses the private key, and uses it to generate an ecc_key object, which it stores in key.
    
    \return 0 On successfully decoding the private key and storing the result in the ecc_key struct
    \return ASN_PARSE_E: Returned if there is an error parsing the der file and storing it as a pem file
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the certificate to convert is large than the specified max certificate size
    \return ASN_OBJECT_ID_E Returned if the certificate encoding has an invalid object id
    \return ECC_CURVE_OID_E Returned if the ECC curve of the provided key is not supported
    \return ECC_BAD_ARG_E Returned if there is an error in the ECC key format
    \return NOT_COMPILED_IN Returned if the private key is compressed, and no compression key is provided
    \return MP_MEM Returned if there is an error in the math library used while parsing the private key 
    \return MP_VAL Returned if there is an error in the math library used while parsing the private key 
    \return MP_RANGE Returned if there is an error in the math library used while parsing the private key
    
    \param input pointer to the buffer containing the input private key
    \param inOutIdx pointer to a word32 object containing the index in the buffer at which to start
    \param key pointer to an initialized ecc object, on which to store the decoded private key
    \param inSz size of the input buffer containing the private key
    
    _Example_
    \code
    int ret, idx=0;
    ecc_key key; // to store key in 

    byte* tmp; // tmp buffer to read key from
    tmp = (byte*) malloc(FOURK_BUF);

    int inSz;
    inSz = fread(tmp, 1, FOURK_BUF, privateKeyFile); 
    // read key into tmp buffer

    wc_ecc_init(&key); // initialize key
    ret = wc_Ecc_PrivateKeyDecode(tmp, &idx, &key, (word32)inSz);
    if(ret < 0) {
        // error decoding ecc key
    }
    \endcode
    
    \sa wc_RSA_PrivateKeyDecode
*/
    WOLFSSL_API int wc_EccPrivateKeyDecode(const byte*, word32*,
                                           ecc_key*, word32);
/*!
    \ingroup wolfCrypt
    
    \brief This function writes a private ECC key to der format.
    
    \return Success On successfully writing the ECC key to der format, returns the length written to the buffer
    \return BAD_FUNC_ARG Returned if key or output is null, or inLen equals zero
    \return MEMORY_E Returned if there is an error allocating memory with XMALLOC
    \return BUFFER_E Returned if the converted certificate is too large to store in the output buffer
    \return ASN_UNKNOWN_OID_E Returned if the ECC key used is of an unknown type
    \return MP_MEM Returned if there is an error in the math library used while parsing the private key 
    \return MP_VAL Returned if there is an error in the math library used while parsing the private key 
    \return MP_RANGE Returned if there is an error in the math library used while parsing the private key
    
    \param key pointer to the buffer containing the input ecc key
    \param output pointer to a buffer in which to store the der formatted key
    \param inLen the length of the buffer in which to store the der formatted key
    
    _Example_
    \code
    int derSz;
    ecc_key key;
    // initialize and make key
    byte der[FOURK_BUF];
    // store der formatted key here

    derSz = wc_EccKeyToDer(&key, der, FOURK_BUF);
    if(derSz < 0) {
        // error converting ecc key to der buffer
    }
    \endcode
    
    \sa wc_RsaKeyToDer
*/
    WOLFSSL_API int wc_EccKeyToDer(ecc_key*, byte* output, word32 inLen);
    WOLFSSL_API int wc_EccPrivateKeyToDer(ecc_key* key, byte* output,
                                          word32 inLen);

    /* public key helper */
/*!
    \ingroup wolfCrypt
    
    \brief Decodes an ECC public key from an input buffer.  It will parse an ASN sequence to retrieve the ECC key.
    
    \return 0 Success
    \return BAD_FUNC_ARG Returns if any arguments are null.
    \return ASN_PARSE_E Returns if there is an error parsing 
    \return ASN_ECC_KEY_E Returns if there is an error importing the key.  See wc_ecc_import_x963 for possible reasons.
    
    \param input Buffer containing DER encoded key to decode.
    \param inOutIdx Index to start reading input buffer from.  On output, index is set to last position parsed of input buffer.
    \param key Pointer to ecc_key struct to store the public key.
    \param inSz Size of the input buffer.
    
    _Example_
    \code
    int ret;
    word32 idx = 0;
    byte buff[] = { // initialize with key };
    ecc_key pubKey;
    wc_ecc_init_key(&pubKey);
    if ( wc_EccPublicKeyDecode(buff, &idx, &pubKey, sizeof(buff)) != 0) {
            // error decoding key
    }
    \endcode
    
    \sa wc_ecc_import_x963
*/
    WOLFSSL_API int wc_EccPublicKeyDecode(const byte*, word32*,
                                              ecc_key*, word32);
    #if (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
/*!
    \ingroup wolfCrypt
    
    \brief This function converts the ECC public key to DER format. It returns the size of buffer used. The public ECC key in DER format is stored in output buffer. with_AlgCurve is a flag for when to include a header that has the Algorithm and Curve information.
    
    \return >0 Success, size of buffer used
    \return BAD_FUNC_ARG Returned if output or key is null.
    \return LENGTH_ONLY_E Error in getting ECC public key size.
    \return BUFFER_E Returned when output buffer is too small.
    
    \param key Pointer to ECC key
    \param output Pointer to output buffer to write to.
    \param inLen Size of buffer.
    \param with_AlgCurve a flag for when to include a header that has the Algorithm and Curve information.
    
    _Example_
    \code
    ecc_key key;
    wc_ecc_init(&key);
    WC_RNG rng;
    wc_InitRng(&rng);
    wc_ecc_make_key(&rng, 24, &key);
    int derSz = // Some appropriate size for der;
    byte der[derSz];

    if(wc_EccPublicKeyToDer(&key, der, derSz, 1) < 0)
    {
        // Error converting ECC public key to der
    }
    \endcode
    
    \sa wc_EccKeyToDer
    \sa wc_EccPrivateKeyDecode
*/
        WOLFSSL_API int wc_EccPublicKeyToDer(ecc_key*, byte* output,
                                               word32 inLen, int with_AlgCurve);
    #endif
#endif

#ifdef HAVE_ED25519
    /* private key helpers */
    WOLFSSL_API int wc_Ed25519PrivateKeyDecode(const byte*, word32*,
                                               ed25519_key*, word32);
    WOLFSSL_API int wc_Ed25519KeyToDer(ed25519_key* key, byte* output,
                                       word32 inLen);
    WOLFSSL_API int wc_Ed25519PrivateKeyToDer(ed25519_key* key, byte* output,
                                              word32 inLen);

    /* public key helper */
    WOLFSSL_API int wc_Ed25519PublicKeyDecode(const byte*, word32*,
                                              ed25519_key*, word32);
    #if (defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_KEY_GEN))
        WOLFSSL_API int wc_Ed25519PublicKeyToDer(ed25519_key*, byte* output,
                                               word32 inLen, int with_AlgCurve);
    #endif
#endif

/* DER encode signature */
/*!
    \ingroup wolfCrypt
    
    \brief This function encodes a digital signature into the output buffer, and returns the size of the encoded signature created.
    
    \return Success On successfully writing the encoded signature to output, returns the length written to the buffer
    
    \param out pointer to the buffer where the encoded signature will be written
    \param digest pointer to the digest to use to encode the signature
    \param digSz the length of the buffer containing the digest
    \param hashOID OID identifying the hash type used to generate the signature. Valid options, depending on build configurations, are: SHAh, SHA256h, SHA384h, SHA512h, MD2h, MD5h, DESb, DES3b, CTC_MD5wRSA, CTC_SHAwRSA, CTC_SHA256wRSA, CTC_SHA384wRSA, CTC_SHA512wRSA, CTC_SHAwECDSA, CTC_SHA256wECDSA, CTC_SHA384wECDSA, and CTC_SHA512wECDSA. 

    \endcode
    \code
    int signSz;
    byte encodedSig[MAX_ENCODED_SIG_SZ];
    Sha256 sha256;
    // initialize sha256 for hashing

    byte* dig = = (byte*)malloc(SHA256_DIGEST_SIZE);
    // perform hashing and hash updating so dig stores SHA-256 hash
    // (see wc_InitSha256, wc_Sha256Update and wc_Sha256Final)
    signSz = wc_EncodeSignature(encodedSig, dig, SHA256_DIGEST_SIZE,SHA256h);
    \endcode

    \sa none
*/
WOLFSSL_API word32 wc_EncodeSignature(byte* out, const byte* digest,
                                      word32 digSz, int hashOID);
/*!
    \ingroup wolfCrypt
    
    \brief This function returns the hash OID that corresponds to a hashing type. For example, when given the type: SHA512, this function returns the identifier corresponding to a SHA512 hash, SHA512h.
    
    \return Success On success, returns the OID corresponding to the appropriate hash to use with that encryption type.
    \return 0 Returned if an unrecognized hash type is passed in as argument.
    
    \param type the hash type for which to find the OID. Valid options, depending on build configuration, include: MD2, MD5, SHA, SHA256, SHA512, SHA384, and SHA512.
    
    _Example_
    \code
    int hashOID;

    hashOID = wc_GetCTC_HashOID(SHA512);
    if (hashOID == 0) {
	    // WOLFSSL_SHA512 not defined
    }
    \endcode
    
    \sa none
*/
WOLFSSL_API int wc_GetCTC_HashOID(int type);

WOLFSSL_API int wc_GetPkcs8TraditionalOffset(byte* input,
                                             word32* inOutIdx, word32 sz);
WOLFSSL_API int wc_CreatePKCS8Key(byte* out, word32* outSz,
       byte* key, word32 keySz, int algoID, const byte* curveOID, word32 oidSz);

/* Time */
/* Returns seconds (Epoch/UTC)
 * timePtr: is "time_t", which is typically "long"
 * Example:
    long lTime;
    rc = wc_GetTime(&lTime, (word32)sizeof(lTime));
*/
WOLFSSL_API int wc_GetTime(void* timePtr, word32 timeSize);

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_ASN_PUBLIC_H */

