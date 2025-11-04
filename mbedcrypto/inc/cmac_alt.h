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


/** @file
 * Alternate implementation of mbedtls cmac
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef _CMAC_ALT_H_
#define _CMAC_ALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#include "PN76_Cmacalt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*!
 * @brief The CMAC context-type definition.
 */
typedef struct mbedtls_cipher_context
{
   uint8_t mode;           /**< Mode to check whether CMAC is for AES or DES */
   uint8_t key_index;      /**< The index of the secure key store from which the key is to be loaded */
   uint8_t sec_options;    /**< Security options RFU. */
   uint8_t reloadKey;      /**< Reloads the Key if the current key is updated by other crypto operations.
                            *   Note this should be used only if the key is updated up previous crypto operations.
                            *   When set, loads the key provided.
                            *   When Not set, loads the key and clears the internal buffers.
                            *   This flag is application when \ref mbedtls_cipher_cmac_starts "CMAC Start" is called.
                            */
} mbedtls_cipher_context_t;

/*!
 * @brief The CMAC cipher info, it would be same as context since for ALT implementation we dont require cipher info
 */
typedef struct mbedtls_cipher_info
{
   uint8_t mode;      /**< Mode to check whether CMAC is for AES or DES */
   uint8_t key_index; /**< The index of the secure key store from which the key is to be loaded */
   uint8_t sec_options; /**< Security options RFU*/
} mbedtls_cipher_info_t;

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/**
 * \brief               This function sets the CMAC key, and prepares to authenticate
 *                      the input data.
 *                      Must be called with an initialized cipher context.
 *
 * \note                When the CMAC implementation is supplied by an alternate
 *                      implementation (through #MBEDTLS_CMAC_ALT), some ciphers
 *                      may not be supported by that implementation, and thus
 *                      return an error. Alternate implementations must support
 *                      AES-128 and AES-256, and may support AES-192 and 3DES.
 *
 * \param ctx           The cipher context used for the CMAC operation, initialized
 *                      as one of the following types: MBEDTLS_CIPHER_AES_128_ECB,
 *                      MBEDTLS_CIPHER_AES_192_ECB, MBEDTLS_CIPHER_AES_256_ECB,
 *                      or MBEDTLS_CIPHER_DES_EDE3_ECB.
 * \param key           The CMAC key.
 * \param keybits       The length of the CMAC key in bits.
 *                      Must be supported by the cipher.
 *
 * \return              \c 0 on success.
 * \return              A cipher-specific error code on failure.
 */
int mbedtls_cipher_cmac_starts( mbedtls_cipher_context_t *ctx,
                                const unsigned char *key, size_t keybits );

/**
 * \brief               This function feeds an input buffer into an ongoing CMAC
 *                      computation.
 *
 *                      It is called between mbedtls_cipher_cmac_starts() or
 *                      mbedtls_cipher_cmac_reset(), and mbedtls_cipher_cmac_finish().
 *                      Can be called repeatedly.
 *
 * \param ctx           The cipher context used for the CMAC operation.
 * \param input         The buffer holding the input data.
 * \param ilen          The length of the input data.
 *
 * \return             \c 0 on success.
 * \return             #MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                     if parameter verification fails.
 */
int mbedtls_cipher_cmac_update( mbedtls_cipher_context_t *ctx,
                                const unsigned char *input, size_t ilen );

/**
 * \brief               This function finishes the CMAC operation, and writes
 *                      the result to the output buffer.
 *
 *                      It is called after mbedtls_cipher_cmac_update().
 *                      It can be followed by mbedtls_cipher_cmac_reset() and
 *                      mbedtls_cipher_cmac_update(), or mbedtls_cipher_free().
 *
 * \param ctx           The cipher context used for the CMAC operation.
 * \param output        The output buffer for the CMAC checksum result.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int mbedtls_cipher_cmac_finish( mbedtls_cipher_context_t *ctx,
                                unsigned char *output );

/**
 * \brief               This function prepares the authentication of another
 *                      message with the same key as the previous CMAC
 *                      operation.
 *
 *                      It is called after mbedtls_cipher_cmac_finish()
 *                      and before mbedtls_cipher_cmac_update().
 *
 * \param ctx           The cipher context used for the CMAC operation.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int mbedtls_cipher_cmac_reset( mbedtls_cipher_context_t *ctx );

/**
 * \brief               This function calculates the full generic CMAC
 *                      on the input buffer with the provided key.
 *
 *                      The function allocates the context, performs the
 *                      calculation, and frees the context.
 *
 *                      The CMAC result is calculated as
 *                      output = generic CMAC(cmac key, input buffer).
 *
 * \note                When the CMAC implementation is supplied by an alternate
 *                      implementation (through #MBEDTLS_CMAC_ALT), some ciphers
 *                      may not be supported by that implementation, and thus
 *                      return an error. Alternate implementations must support
 *                      AES-128 and AES-256, and may support AES-192 and 3DES.
 *
 * \param cipher_info   The cipher information.
 * \param key           The CMAC key.
 * \param keylen        The length of the CMAC key in bits.
 * \param input         The buffer holding the input data.
 * \param ilen          The length of the input data.
 * \param output        The buffer for the generic CMAC result.
 *
 * \return              \c 0 on success.
 * \return              #MBEDTLS_ERR_MD_BAD_INPUT_DATA
 *                      if parameter verification fails.
 */
int mbedtls_cipher_cmac( const mbedtls_cipher_info_t *cipher_info,
                         const unsigned char *key, size_t keylen,
                         const unsigned char *input, size_t ilen,
                         unsigned char *output );

#ifdef __cplusplus
}
#endif

#endif /* _CMAC_ALT_H_ */
