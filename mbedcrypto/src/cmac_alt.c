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
/* Copyright 2021 NXP                                                         */
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
 * This file contains the interfaces for mbedtls cmac alt implementation
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
#include "cmac_alt.h"

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

int mbedtls_cipher_cmac_starts( mbedtls_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits )
{
   mbedtls_cmac_context_t stCtx_CMAC;

   stCtx_CMAC.bKeyIndex = ctx->key_index;
   stCtx_CMAC.bMode = ctx->mode;
   stCtx_CMAC.bReloadKey = ctx->reloadKey;
   stCtx_CMAC.bBlockSize = (uint8_t) ((ctx->mode == MBEDTLS_CMAC_MODE_AES) ? MBEDTLS_AES_BLOCK_SIZE : MBEDTLS_DES_BLOCK_SIZE);
   return mbedtls_cmac_start_stz(&stCtx_CMAC, key, keybits);
}


int mbedtls_cipher_cmac_update( mbedtls_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen )
{
   mbedtls_cmac_context_t stCtx_CMAC;

   stCtx_CMAC.bKeyIndex = ctx->key_index;
   stCtx_CMAC.bMode = ctx->mode;
   stCtx_CMAC.bBlockSize = (uint8_t) ((ctx->mode == MBEDTLS_CMAC_MODE_AES) ? MBEDTLS_AES_BLOCK_SIZE : MBEDTLS_DES_BLOCK_SIZE);
   return mbedtls_cmac_update_stz(&stCtx_CMAC, input, ilen);
}

int mbedtls_cipher_cmac_finish( mbedtls_cipher_context_t *ctx,
                                unsigned char *output )
{
   mbedtls_cmac_context_t stCtx_CMAC;

   stCtx_CMAC.bKeyIndex = ctx->key_index;
   stCtx_CMAC.bMode = ctx->mode;
   stCtx_CMAC.bBlockSize = (uint8_t) ((ctx->mode == MBEDTLS_CMAC_MODE_AES) ? MBEDTLS_AES_BLOCK_SIZE : MBEDTLS_DES_BLOCK_SIZE);
   return mbedtls_cmac_finalize_stz(&stCtx_CMAC, output);
}

int mbedtls_cipher_cmac_reset( mbedtls_cipher_context_t *ctx )
{
   mbedtls_cmac_context_t stCtx_CMAC;
   return mbedtls_cmac_reset_stz(&stCtx_CMAC);
}

int mbedtls_cipher_cmac( const mbedtls_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output )
{
   mbedtls_cmac_context_t stCtx_CMAC;
   int32_t dwStatus = 0;

   stCtx_CMAC.bKeyIndex = cipher_info->key_index;
   stCtx_CMAC.bMode = cipher_info->mode;
   stCtx_CMAC.bBlockSize = (uint8_t) ((cipher_info->mode == MBEDTLS_CMAC_MODE_AES) ? MBEDTLS_AES_BLOCK_SIZE : MBEDTLS_DES_BLOCK_SIZE);

   /* Starts CMAC operation by setting the key. */
   dwStatus = mbedtls_cmac_start_stz(&stCtx_CMAC, key, keylen);
   if(dwStatus != 0)
      return dwStatus;

   /* Performs CMAC operation on the input provided. */
   dwStatus = mbedtls_cmac_update_stz(&stCtx_CMAC, input, ilen);
   if(dwStatus != 0)
      return dwStatus;

   /* Finalizes CMAC operation on the input provided. */
   dwStatus = mbedtls_cmac_finalize_stz(&stCtx_CMAC, output);
   if(dwStatus != 0)
      return dwStatus;

   return dwStatus;
}
