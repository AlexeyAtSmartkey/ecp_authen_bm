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

#include "des_alt.h"
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



void mbedtls_des3_init( mbedtls_des3_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
}

void mbedtls_des3_free( mbedtls_des3_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
}

int mbedtls_des3_set2key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_set2key_enc_stz(key);
}

int mbedtls_des3_set2key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 2] )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_set2key_dec_stz(key);
}

int mbedtls_des3_set3key_enc( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_set3key_enc_stz(key);
}

int mbedtls_des3_set3key_dec( mbedtls_des3_context *ctx,
                      const unsigned char key[MBEDTLS_DES_KEY_SIZE * 3] )
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_set3key_dec_stz(key);
}

int mbedtls_des3_unloadkey(void)
{
   return mbedtls_des3_unloadkey_stz();
}

int mbedtls_des3_crypt_ecb( mbedtls_des3_context *ctx,
                     const unsigned char input[8],
                     unsigned char output[8] )
{
   return mbedtls_des3_crypt_ecb_stz(input, output, ctx->mode);
}

int mbedtls_des3_crypt_cbc( mbedtls_des3_context *ctx,
                     int mode,
                     size_t length,
                     unsigned char iv[8],
                     const unsigned char *input,
                     unsigned char *output )
{
   mbedtls_des3_cbc_context_t des_cbc;
   des_cbc.input = input;
   des_cbc.iv = iv;
   des_cbc.length = length;
   des_cbc.mode = mode;
   des_cbc.output = output;

   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_crypt_cbc_stz(&des_cbc);
}

int mbedtls_des3_crypt_cbc_cmac(mbedtls_des3_context *ctx, const uint8_t * input, uint8_t *cmacoutput, size_t length)
{
   memset( ctx, 0, sizeof( mbedtls_des3_context ) );
   return mbedtls_des3_crypt_cbc_cmac_stz(input, cmacoutput, length);
}
