/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
/*----------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                         */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
 * This file contains the interfaces for applications to use the cryptolib via mbedtls
 * $Author: NXP $
 * $Revision: $
 * $Date: 2020-11-4 $
 *
 * History:
 *
 */

/** Revision History:
 * # _____________________________________________________________________________
 * #
 * # 00.01.00         : Initial implementation
 * #                  : - <details about changes in this version>
 * # _____________________________________________________________________________
 */

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "string.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#include "aes_alt.h"
/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Global Static variables
 ****************************************************************************/


/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Private functions declaration
 ****************************************************************************/


/*****************************************************************************
 * Global functions implementation
 ****************************************************************************/
void mbedtls_aes_init ( mbedtls_aes_context *ctx )
{
   memset(ctx, 0, sizeof( mbedtls_aes_context ) );
}

void mbedtls_aes_free( mbedtls_aes_context *ctx )
{
   PN76_mbedtls_aes_free(ctx);
}

int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits )
{
   return mbedtls_aes_setkey_stz(ctx, key, keybits);
}

int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx, const unsigned char *key, unsigned int keybits)
{
	int result;
	result = mbedtls_aes_setkey_stz(ctx, key, keybits);
   return result;
}

/*
 * AES-ECB block encryption/decryption
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] )
{
   return mbedtls_aes_crypt_ecb_stz(ctx, mode, input, output);
}



/*
 * AES-CBC buffer encryption/decryption
 */
int mbedtls_aes_crypt_cbc(mbedtls_aes_context *ctx,
                          int mode,
                          size_t length,
                          unsigned char iv[16],
                          const unsigned char *input,
                          unsigned char *output)
{
   mbedtls_aes_crypt_cbc_params_t mbedtls_aes_crypt_cbc_params;
   mbedtls_aes_crypt_cbc_params.ctx = ctx;
   mbedtls_aes_crypt_cbc_params.mode = mode;
   mbedtls_aes_crypt_cbc_params.length = length;
   mbedtls_aes_crypt_cbc_params.iv = iv;
   mbedtls_aes_crypt_cbc_params.input = input;
   mbedtls_aes_crypt_cbc_params.output = output;


   return mbedtls_aes_crypt_cbc_stz(&mbedtls_aes_crypt_cbc_params);
}

/*
 * AES-CTR buffer encryption/decryption
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output )
{
   mbedtls_aes_crypt_ctr_params_t mbedtls_aes_crypt_ctr_params;
   mbedtls_aes_crypt_ctr_params.ctx = ctx;
   mbedtls_aes_crypt_ctr_params.length = length;
   mbedtls_aes_crypt_ctr_params.nc_off = nc_off;
   mbedtls_aes_crypt_ctr_params.nonce_counter = nonce_counter;
   mbedtls_aes_crypt_ctr_params.stream_block = stream_block;
   mbedtls_aes_crypt_ctr_params.input = input;
   mbedtls_aes_crypt_ctr_params.output = output;

   return mbedtls_aes_crypt_ctr_stz(&mbedtls_aes_crypt_ctr_params);

}
/*
 * Initialize context
 */
void mbedtls_ccm_init( mbedtls_ccm_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_ccm_context ) );
}

void mbedtls_ccm_free( mbedtls_ccm_context *ctx )
{
   PN76_mbedtls_ccm_free(ctx);
}

int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
   return mbedtls_ccm_setkey_stz(ctx, cipher, key, keybits);
}

int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len )
{
   mbedtls_aes_crypt_ccm_params_t mbedtls_aes_crypt_ccm_params;
   mbedtls_aes_crypt_ccm_params.ctx = ctx;
   mbedtls_aes_crypt_ccm_params.length = length;
   mbedtls_aes_crypt_ccm_params.iv = iv;
   mbedtls_aes_crypt_ccm_params.iv_len = iv_len;
   mbedtls_aes_crypt_ccm_params.add = add;
   mbedtls_aes_crypt_ccm_params.add_len = add_len;
   mbedtls_aes_crypt_ccm_params.input = input;
   mbedtls_aes_crypt_ccm_params.output = output;
   mbedtls_aes_crypt_ccm_params.tag = tag;
   mbedtls_aes_crypt_ccm_params.tag_len = tag_len;
   mbedtls_aes_crypt_ccm_params.bMode = MBEDTLS_AES_ENCRYPT;

   return(mbedtls_ccm_encrypt_decrypt_and_tag_stz(&mbedtls_aes_crypt_ccm_params));
}

int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len )
{
   mbedtls_aes_crypt_ccm_params_t mbedtls_aes_crypt_ccm_params;
   mbedtls_aes_crypt_ccm_params.ctx = ctx;
   mbedtls_aes_crypt_ccm_params.length = length;
   mbedtls_aes_crypt_ccm_params.iv = iv;
   mbedtls_aes_crypt_ccm_params.iv_len = iv_len;
   mbedtls_aes_crypt_ccm_params.add = add;
   mbedtls_aes_crypt_ccm_params.add_len = add_len;
   mbedtls_aes_crypt_ccm_params.input = input;
   mbedtls_aes_crypt_ccm_params.output = output;
   mbedtls_aes_crypt_ccm_params.tag = (unsigned char *)tag;
   mbedtls_aes_crypt_ccm_params.tag_len = tag_len;
   mbedtls_aes_crypt_ccm_params.bMode = MBEDTLS_AES_DECRYPT;

   return(mbedtls_ccm_encrypt_decrypt_and_tag_stz(&mbedtls_aes_crypt_ccm_params));
}

/*
 * Initialize a context
 */
void mbedtls_gcm_init( mbedtls_gcm_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_gcm_context ) );
}

void mbedtls_gcm_free( mbedtls_gcm_context *ctx )
{
   PN76_mbedtls_gcm_free(ctx);
}

int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
   return mbedtls_gcm_setkey_stz(ctx, cipher, key, keybits);
}

int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag )
{
   mbedtls_aes_crypt_gcm_params_t mbedtls_aes_crypt_gcm_params;
   mbedtls_aes_crypt_gcm_params.ctx = ctx;
   mbedtls_aes_crypt_gcm_params.mode = mode;
   mbedtls_aes_crypt_gcm_params.length = length;
   mbedtls_aes_crypt_gcm_params.iv = iv;
   mbedtls_aes_crypt_gcm_params.iv_len = iv_len;
   mbedtls_aes_crypt_gcm_params.add = add;
   mbedtls_aes_crypt_gcm_params.add_len = add_len;
   mbedtls_aes_crypt_gcm_params.input = input;
   mbedtls_aes_crypt_gcm_params.output = output;
   mbedtls_aes_crypt_gcm_params.tag_len = tag_len;
   mbedtls_aes_crypt_gcm_params.tag = tag;

   return mbedtls_gcm_crypt_and_tag_stz(&mbedtls_aes_crypt_gcm_params);
}

int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output )
{
   mbedtls_aes_decrypt_gcm_params_t mbedtls_aes_decrypt_gcm_params;
   mbedtls_aes_decrypt_gcm_params.ctx = ctx;
   mbedtls_aes_decrypt_gcm_params.length = length;
   mbedtls_aes_decrypt_gcm_params.iv = iv;
   mbedtls_aes_decrypt_gcm_params.iv_len =  iv_len;
   mbedtls_aes_decrypt_gcm_params.add = add;
   mbedtls_aes_decrypt_gcm_params.add_len = add_len;
   mbedtls_aes_decrypt_gcm_params.tag = (unsigned char *)tag;
   mbedtls_aes_decrypt_gcm_params.tag_len = tag_len;
   mbedtls_aes_decrypt_gcm_params.input = input;
   mbedtls_aes_decrypt_gcm_params.output = output;

   return mbedtls_gcm_auth_decrypt_stz(&mbedtls_aes_decrypt_gcm_params);

}

/*
 * Initialize context
 */
void mbedtls_eax_init(mbedtls_eax_context *ctx)
{
   memset( ctx, 0, sizeof(mbedtls_eax_context) );
}

void mbedtls_eax_free(mbedtls_eax_context *ctx)
{
   PN76_mbedtls_eax_free(ctx);
}

int mbedtls_eax_setkey(mbedtls_eax_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits )
{
   return mbedtls_eax_setkey_stz(ctx, cipher, key, keybits);
}

int mbedtls_eax_encrypt_and_tag(mbedtls_eax_context *ctx, size_t nBlocks,
                         const unsigned char *input, size_t length,
                         const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *header, size_t header_len,
                         unsigned char *tag, size_t tag_len,
                         unsigned char *output)
{
   mbedtls_aes_crypt_eax_params_t mbedtls_aes_crypt_eax_params;
   mbedtls_aes_crypt_eax_params.bMode = MBEDTLS_AES_ENCRYPT;
   mbedtls_aes_crypt_eax_params.nBlocks = nBlocks;
   mbedtls_aes_crypt_eax_params.input = input;
   mbedtls_aes_crypt_eax_params.length = length;
   mbedtls_aes_crypt_eax_params.nonce = nonce;
   mbedtls_aes_crypt_eax_params.nonce_len = nonce_len;
   mbedtls_aes_crypt_eax_params.header = header;
   mbedtls_aes_crypt_eax_params.header_len = header_len;
   mbedtls_aes_crypt_eax_params.tag = tag;
   mbedtls_aes_crypt_eax_params.tag_len = tag_len;
   mbedtls_aes_crypt_eax_params.output = output;

   return(mbedtls_eax_encrypt_decrypt_and_tag_stz(&mbedtls_aes_crypt_eax_params));
}

int mbedtls_eax_auth_decrypt(mbedtls_eax_context *ctx, size_t nBlocks,
                         const unsigned char *input, size_t length,
                         const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *header, size_t header_len,
                         const unsigned char *tag, size_t tag_len,
                         unsigned char *output)
{
   mbedtls_aes_crypt_eax_params_t mbedtls_aes_crypt_eax_params;
   mbedtls_aes_crypt_eax_params.bMode = MBEDTLS_AES_DECRYPT;
   mbedtls_aes_crypt_eax_params.nBlocks = nBlocks;
   mbedtls_aes_crypt_eax_params.input = input;
   mbedtls_aes_crypt_eax_params.length = length;
   mbedtls_aes_crypt_eax_params.nonce = nonce;
   mbedtls_aes_crypt_eax_params.nonce_len = nonce_len;
   mbedtls_aes_crypt_eax_params.header = header;
   mbedtls_aes_crypt_eax_params.header_len = header_len;
   mbedtls_aes_crypt_eax_params.tag = (uint8_t *)tag;
   mbedtls_aes_crypt_eax_params.tag_len = tag_len;
   mbedtls_aes_crypt_eax_params.output = output;

   return(mbedtls_eax_encrypt_decrypt_and_tag_stz(&mbedtls_aes_crypt_eax_params));
}

/*****************************************************************************
 * Private functions
 ****************************************************************************/




