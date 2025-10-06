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
 * Alternate implementation of mbedtls SHA-256 and SHA-224 functions using HW Crypto blocks
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

#include "sha256_alt.h"
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

void mbedtls_sha256_init( mbedtls_sha256_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
}

void mbedtls_sha256_free( mbedtls_sha256_context *ctx )
{
   memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
}

int mbedtls_sha256_starts_ret( mbedtls_sha256_context *ctx, int is224 )
{
   memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
   return mbedtls_sha256_starts_ret_stz(is224);
}

int mbedtls_sha256_update_ret( mbedtls_sha256_context *ctx,
                               const unsigned char *input,
                               size_t ilen )
{
   memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
   return mbedtls_sha256_update_ret_stz(input, ilen);
}

int mbedtls_sha256_finish_ret( mbedtls_sha256_context *ctx,
                               unsigned char output[32] )
{
   memset( ctx, 0, sizeof( mbedtls_sha256_context ) );
   return mbedtls_sha256_finish_ret_stz(output);
}

int mbedtls_sha256_ret( const unsigned char *input,
                        size_t ilen,
                        unsigned char output[32],
                        int is224 )
{
   return mbedtls_sha256_ret_stz(input, ilen, output, is224);
}

