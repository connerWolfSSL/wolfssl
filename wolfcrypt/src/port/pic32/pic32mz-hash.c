/* pic32mz-hash.c
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


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_MICROCHIP_PIC32MZ

#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h>

#ifdef WOLFSSL_PIC32MZ_HASH
#include <wolfssl/wolfcrypt/md5.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#endif


#ifdef WOLFSSL_PIC32MZ_HASH

#if PIC32_BLOCK_SIZE < PIC32MZ_MIN_BLOCK
    #error Encryption block size must be at least 64 bytes.
#endif

static uint8_t dataBuffer[PIC32MZ_MAX_BD][PIC32_BLOCK_SIZE] __attribute__((aligned (4), coherent));

static void reset_engine(pic32mz_desc *desc, int algo)
{
    int i;
    pic32mz_desc* uc_desc = KVA0_TO_KVA1(desc);

    CECON = 1 << 6;
    while (CECON);
    CEINTSRC = 0xF;     // Clear the interrupt flags

    /* Make sure everything is clear first before we make settings. */
    XMEMSET(&uc_desc->sa, 0, sizeof(uc_desc->sa));

    /* Set up the security association */
    uc_desc->sa.SA_CTRL.ALGO = algo;
    uc_desc->sa.SA_CTRL.LNC = 1;
    uc_desc->sa.SA_CTRL.FB = 1;
    uc_desc->sa.SA_CTRL.ENCTYPE = 1;
    uc_desc->sa.SA_CTRL.LOADIV = 1;

    /* Set up the buffer descriptor */
    uc_desc->err = 0;
    for (i = 0; i < PIC32MZ_MAX_BD; i++)
    {
        XMEMSET((void*)&uc_desc->bd[i], 0, sizeof(uc_desc->bd[i]));
        uc_desc->bd[i].BD_CTRL.LAST_BD = 1;
        uc_desc->bd[i].BD_CTRL.LIFM = 1;
        uc_desc->bd[i].BD_CTRL.PKT_INT_EN = 1;
        uc_desc->bd[i].SA_ADDR = KVA_TO_PA(&uc_desc->sa);
        uc_desc->bd[i].SRCADDR = KVA_TO_PA(&dataBuffer[i]);
        if (PIC32MZ_MAX_BD > i+1)
            uc_desc->bd[i].NXTPTR = KVA_TO_PA(&uc_desc->bd[i+1]);
        else
            uc_desc->bd[i].NXTPTR = KVA_TO_PA(&uc_desc->bd[0]);
        XMEMSET(&dataBuffer[i], 0, PIC32_BLOCK_SIZE);
    }
    uc_desc->bd[0].BD_CTRL.SA_FETCH_EN = 1; /* Fetch the security association on the first BD */
    desc->dbPtr = 0;
    desc->currBd = 0;
    desc->msgSize = 0;
    desc->processed = 0;
    CEBDPADDR = KVA_TO_PA(&desc->bd[0]);

    CEPOLLCON = 10;

#if PIC32_NO_OUT_SWAP
    CECON = 0x27;
#else
    CECON = 0xa7; /* bit 7 = enable out swap */
#endif
}

static int update_engine(pic32mz_desc *desc, int algo,
    const byte *input, word32 len, word32 *hash)
{
    int ret = 0;
    int total;
    pic32mz_desc* uc_desc = KVA0_TO_KVA1(desc);

    if (!desc->engine_ready) {

        ret = wolfSSL_CryptHwMutexLock();
        if (ret != 0)
            return ret;

        reset_engine(desc, algo);
        desc->engine_ready = 1;
    }

    uc_desc->bd[desc->currBd].UPDPTR = KVA_TO_PA(hash);
    /* Add the data to the current buffer. If the buffer fills, start processing
       it and fill the next one. */
    while (len)
    {
        if (desc->msgSize)
        {
            /* If we've been given the message size, we can process along the
               way. We might have buffered something previously. Fill as needed
               and process. */
			if (desc->dbPtr)
			{
				// Copy enough data to fill the buffer, as possible.
                total = (PIC32_BLOCK_SIZE - desc->dbPtr);
				if (total > len) total = len;
                XMEMCPY(&dataBuffer[desc->currBd][desc->dbPtr], input, total);
				uc_desc->bd[desc->currBd].SRCADDR =
                    KVA_TO_PA(&dataBuffer[desc->currBd]);
			}
			else
			{
                /* Make sure we are a multiple of 4 before going straight to
                 * the engine */
                if ((len >= PIC32_BLOCK_SIZE) || ((len % 4) == 0))
				{
					/* point the current buffer descriptor to the input data
                       and set the size. */
					uc_desc->bd[desc->currBd].SRCADDR = KVA_TO_PA(input);
					total = (len > PIC32MZ_MAX_BLOCK ? PIC32MZ_MAX_BLOCK : len);
				}
				else	/* Otherwise, we have to buffer it */
				{
					XMEMCPY(&dataBuffer[desc->currBd][desc->dbPtr], input, len);
					total = len;
				}
			}
			desc->dbPtr += total;
			len -= total;
			input += total;
			desc->processed += total;
			/* Fill in the details in the buffer descriptor */
            uc_desc->bd[desc->currBd].MSGLEN = desc->msgSize;
            uc_desc->bd[desc->currBd].UPDPTR = KVA_TO_PA(hash);
			uc_desc->bd[desc->currBd].BD_CTRL.BUFLEN = desc->dbPtr;
			uc_desc->bd[desc->currBd].BD_CTRL.LAST_BD = 0;
			uc_desc->bd[desc->currBd].BD_CTRL.LIFM = 0;

			/* If we are not the last buffer descriptor, enable it
			   and advance to the next one */
			if ((len || (desc->processed != desc->msgSize)) &&
                                                    (desc->dbPtr % 4 == 0)) {
                uc_desc->bd[desc->currBd].BD_CTRL.DESC_EN = 1;
                desc->currBd++;
                if (desc->currBd >= PIC32MZ_MAX_BD)
                    desc->currBd = 0;
    			while (uc_desc->bd[desc->currBd].BD_CTRL.DESC_EN);
                uc_desc->bd[desc->currBd].BD_CTRL.SA_FETCH_EN = 0;
                desc->dbPtr = 0;
			}
        }
        else
        {
            /* We have to buffer everything and keep track of how much has been
               added in order to get a total size. If the buffer fills, we move
               to the next one. If we try to add more when the last buffer is
               full, we error out. */
            if (desc->dbPtr == PIC32_BLOCK_SIZE)
            {
                /* We filled the last BD buffer, so move on to the next one */
                uc_desc->bd[desc->currBd].BD_CTRL.LAST_BD = 0;
                uc_desc->bd[desc->currBd].BD_CTRL.LIFM = 0;
                uc_desc->bd[desc->currBd].BD_CTRL.BUFLEN = PIC32_BLOCK_SIZE;
                desc->dbPtr = 0;
                desc->currBd++;
                if (desc->currBd >= PIC32MZ_MAX_BD)
                {
                    desc->err = 1;
                }
				else
					uc_desc->bd[desc->currBd].UPDPTR = KVA_TO_PA(hash);
            }
            if (len > PIC32_BLOCK_SIZE - desc->dbPtr)
            {
                /* We have more data than can be put in the buffer. Fill what
                   we can. */
                total = PIC32_BLOCK_SIZE - desc->dbPtr;
                XMEMCPY(&dataBuffer[desc->currBd][desc->dbPtr], input, total);
                len -= total;
                desc->processed += total;
                desc->dbPtr = PIC32_BLOCK_SIZE;
                input += total;
            }
            else
            {
                /* Fill up what we have */
                XMEMCPY(&dataBuffer[desc->currBd][desc->dbPtr], input, len);
                desc->dbPtr += len;
                desc->processed += len;
                len = 0;
            }
        }
    }

    return ret;
}

static void start_engine(pic32mz_desc *desc) {
    /* Wrap up the last buffer descriptor and enable it */
    int i;
    int bufferLen;
    pic32mz_desc* uc_desc = KVA0_TO_KVA1(desc);

    bufferLen = desc->dbPtr;
    if (bufferLen % 4)
        bufferLen = (bufferLen + 4) - (bufferLen % 4);
    uc_desc->bd[desc->currBd].BD_CTRL.BUFLEN = bufferLen;
    uc_desc->bd[desc->currBd].BD_CTRL.LAST_BD = 1;
    uc_desc->bd[desc->currBd].BD_CTRL.LIFM = 1;
    if (desc->msgSize == 0)
    {
        /* We were not given the size, so now we have to go through every BD
           and give it what will be processed, and enable them. */
        for (i = desc->currBd; i >= 0; i--)
        {
            uc_desc->bd[i].MSGLEN = desc->processed;
            uc_desc->bd[i].BD_CTRL.PKT_INT_EN = 1;
            uc_desc->bd[i].BD_CTRL.DESC_EN = 1;
        }
    }
    else
    {
        uc_desc->bd[desc->currBd].BD_CTRL.PKT_INT_EN = 1;
        uc_desc->bd[desc->currBd].BD_CTRL.DESC_EN = 1;
    }
}

void wait_engine(pic32mz_desc *desc, char *hash, int hash_sz)
{
    unsigned int i;
#if PIC32_NO_OUT_SWAP
    unsigned int *intptr;
#endif
    pic32mz_desc* uc_desc = KVA0_TO_KVA1(desc);
    unsigned int engineRunning = 1;

    while (engineRunning)
    {
        engineRunning = 0;
        for (i = 0; i < PIC32MZ_MAX_BD; i++)
            engineRunning = engineRunning || uc_desc->bd[i].BD_CTRL.DESC_EN;
    }
    XMEMCPY(hash, KVA0_TO_KVA1(hash), hash_sz);

#if PIC32_NO_OUT_SWAP
    for (i = 0, intptr = (unsigned int *)hash; i < hash_sz/sizeof(unsigned int);
                                                                  i++, intptr++)
    {
        *intptr = ntohl(*intptr);
    }
#endif

    desc->engine_ready = 0;
    wolfSSL_CryptHwMutexUnLock();
}


#ifndef NO_MD5
int wc_InitMd5_ex(Md5* md5, void* heap, int devId)
{
    if (md5 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(md5, 0, sizeof(Md5));
    md5->heap = heap;
    (void)devId;
    return 0;
}

int wc_Md5Update(Md5* md5, const byte* data, word32 len)
{
     return update_engine(&md5->desc, PIC32_ALGO_MD5,
        data, len, md5->digest);
}

int wc_Md5Final(Md5* md5, byte* hash)
{
    start_engine(&md5->desc);
    wait_engine(&md5->desc, (char *)md5->digest, MD5_DIGEST_SIZE);
    XMEMCPY(hash, md5->digest, MD5_DIGEST_SIZE);
    return wc_InitMd5(md5);  /* reset state */
}

void wc_Md5SizeSet(Md5* md5, word32 len)
{
    md5->desc.msgSize = len;
}
#endif /* !NO_MD5 */

#ifndef NO_SHA
int wc_InitSha_ex(Sha* sha, void* heap, int devId)
{
    if (sha == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha, 0, sizeof(Sha));
    sha->heap = heap;
    (void)devId;
    return 0;
}

int wc_ShaUpdate(Sha* sha, const byte* data, word32 len)
{
    return update_engine(&sha->desc, PIC32_ALGO_SHA1,
        data, len, sha->digest);
}

int wc_ShaFinal(Sha* sha, byte* hash)
{
    start_engine(&sha->desc);
    wait_engine(&sha->desc, (char *)sha->digest, SHA_DIGEST_SIZE);
    XMEMCPY(hash, sha->digest, SHA_DIGEST_SIZE);
    return wc_InitSha(sha);  /* reset state */
}

void wc_ShaSizeSet(Sha* sha, word32 len)
{
    sha->desc.msgSize = len;
}
#endif /* !NO_SHA */

#ifndef NO_SHA256
int wc_InitSha256_ex(Sha256* sha256, void* heap, int devId)
{
    if (sha256 == NULL)
        return BAD_FUNC_ARG;

    XMEMSET(sha256, 0, sizeof(Sha256));
    sha256->heap = heap;
    (void)devId;
    return 0;
}

int wc_Sha256Update(Sha256* sha256, const byte* data, word32 len)
{
    return update_engine(&sha256->desc, PIC32_ALGO_SHA256,
        data, len, sha256->digest);
}

int wc_Sha256Final(Sha256* sha256, byte* hash)
{
    start_engine(&sha256->desc);
    wait_engine(&sha256->desc, (char *)sha256->digest, SHA256_DIGEST_SIZE);
    XMEMCPY(hash, sha256->digest, SHA256_DIGEST_SIZE);
    return wc_InitSha256(sha256);  /* reset state */
}

void wc_Sha256SizeSet(Sha256* sha256, word32 len)
{
    sha256->desc.msgSize = len;
}

#endif /* !NO_SHA256 */

#endif /* WOLFSSL_PIC32MZ_HASH */
#endif /* WOLFSSL_MICROCHIP_PIC32MZ */
