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

#include "sha_alt.h"
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

int mbedtls_SecureSha256_starts_ret( void )
{
   return mbedtls_SecureSha256_starts_ret_stz();
}

int mbedtls_SecureSha256_update_ret( const unsigned char *input,
                               size_t ilen )
{
   return mbedtls_SecureSha256_update_ret_stz(input, ilen);
}

int mbedtls_SecureSha256_finish_ret( unsigned char output[32] )
{
   return mbedtls_SecureSha256_finish_ret_stz(output);
}

int mbedtls_SecureSha256( const unsigned char *input,
                        size_t ilen,
                        unsigned char output[32] )
{
   return mbedtls_SecureSha256_stz(input, ilen, output);
}

int mbedtls_SecureSha512_starts_ret( uint8_t is384 )
{
   return mbedtls_SecureSha512_starts_ret_stz( is384 );
}

int mbedtls_SecureSha512_update_ret( const unsigned char *input,
                               size_t ilen )
{
   return mbedtls_SecureSha512_update_ret_stz(input, ilen);
}

int mbedtls_SecureSha512_finish_ret( unsigned char output[64] )
{
   return mbedtls_SecureSha512_finish_ret_stz(output);
}

int mbedtls_SecureSha512( const unsigned char *input,
                    size_t ilen,
                    unsigned char output[64],
                    uint8_t is384)
{
   return mbedtls_SecureSha512_stz(input, ilen, output, is384);
}

void mbedtls_md_init( mbedtls_md_context_t *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
}

void mbedtls_md_free( mbedtls_md_context_t *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
}

int mbedtls_md_hmac_starts( mbedtls_md_context_t *ctx, const unsigned char *key, size_t keylen )
{
   memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
   return mbedtls_md_hmac_starts_stz(key, keylen);
}

int mbedtls_md_hmac_update( mbedtls_md_context_t *ctx, const unsigned char *input, size_t ilen )
{
   memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
   return mbedtls_md_hmac_update_stz(input, ilen);
}

int mbedtls_md_hmac_finish( mbedtls_md_context_t *ctx, unsigned char *output )
{
   memset( ctx, 0, sizeof( mbedtls_md_context_t ) );
   return mbedtls_md_hmac_finish_stz(output);
}

int mbedtls_md_hmac( const mbedtls_md_info_t *md_info,
                     const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char *output )
{

   mbedtls_md_hmac_params_t mbedtls_md_hmac_params;
   mbedtls_md_hmac_params.key = key;
   mbedtls_md_hmac_params.keylen = keylen;
   mbedtls_md_hmac_params.input = input;
   mbedtls_md_hmac_params.ilen = ilen;
   mbedtls_md_hmac_params.output = output;

   return mbedtls_md_hmac_stz(&mbedtls_md_hmac_params);
}

int mbedtls_hkdf_extract( const mbedtls_md_info_t *md,
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk )
{
   mbedtls_hkdf_extract_params_t mbedtls_hkdf_extract_params;
   mbedtls_hkdf_extract_params.salt = salt;
   mbedtls_hkdf_extract_params.salt_len = salt_len;
   mbedtls_hkdf_extract_params.ikm = ikm;
   mbedtls_hkdf_extract_params.ikm_len = ikm_len;
   mbedtls_hkdf_extract_params.prk = prk;

   return mbedtls_hkdf_extract_stz(&mbedtls_hkdf_extract_params);
}

int mbedtls_hkdf_expand( const mbedtls_md_info_t *md, const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len )
{
   mbedtls_hkdf_expand_params_t mbedtls_hkdf_expand_params;
   mbedtls_hkdf_expand_params.prk = prk;
   mbedtls_hkdf_expand_params.prk_len = prk_len;
   mbedtls_hkdf_expand_params.info = info;
   mbedtls_hkdf_expand_params.info_len = info_len;
   mbedtls_hkdf_expand_params.okm = okm;
   mbedtls_hkdf_expand_params.okm_len = okm_len;

   return mbedtls_hkdf_expand_stz(&mbedtls_hkdf_expand_params);
}

int mbedtls_hkdf( const mbedtls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len )
{
   mbedtls_hkdf_params_t mbedtls_hkdf_params;
   mbedtls_hkdf_params.salt = salt;
   mbedtls_hkdf_params.salt_len = salt_len;
   mbedtls_hkdf_params.ikm = ikm;
   mbedtls_hkdf_params.ikm_len = ikm_len;
   mbedtls_hkdf_params.info = info;
   mbedtls_hkdf_params.info_len = info_len;
   mbedtls_hkdf_params.okm = okm;
   mbedtls_hkdf_params.okm_len = okm_len;

   return mbedtls_hkdf_stz(&mbedtls_hkdf_params);
}

