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
/* Copyright 2021-2022 NXP                                                    */
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
 * Alternate implementation of mbedtls 3DES functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_DESALT_H_
#define PN76_DESALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/** @addtogroup PN76SYSSYMMETRICDES
 *
 * @brief System Service DES API's
 *
 * This module briefs about the implementation of various DES Algorithms.
 *
 * This module implements PN76SYSSYMMETRICDES interface in the ROM code
 *
 * @{
 *
 */

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/
#define MBEDTLS_ERR_DES_BAD_INPUT_DATA                    -0x0031  /**< Invalid input data. */

#ifndef MBEDTLS_ERR_DES_HW_ACCEL_FAILED
#define MBEDTLS_ERR_DES_HW_ACCEL_FAILED                   -0x0035  /**< AES hardware accelerator failed. */
#endif

/*This is number of block processed at once */
#define DES_BLOCKS_AT_ONCE      1
#define MBEDTLS_DES_ENCRYPT     1
#define MBEDTLS_DES_DECRYPT     0
#define MBEDTLS_DES_KEY_SIZE    8

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/**
 * \brief          Triple-DES CBC context structure
 */
typedef struct mbedtls_des3_cbc_context
{
   uint8_t mode;
   size_t length;
   uint8_t * iv;

   const uint8_t * input;
   uint8_t *output;
}
mbedtls_des3_cbc_context_t;

/**
 * \brief          Triple-DES CMAC context structure
 */
typedef struct mbedtls_des3_cbc_cmac_context
{
   size_t length;
   const uint8_t * input;
   uint8_t *cmacoutput;
}
mbedtls_des3_cbc_cmac_context_t;

/**
 * \brief          DES context structure
 *
 * \warning        DES is considered a weak cipher and its use constitutes a
 *                 security risk. We recommend considering stronger ciphers
 *                 instead.
 */
typedef struct mbedtls_des_context
{
   uint8_t keyindex;  /**< RFU */
}
mbedtls_des_context;

/**
 * \brief          Triple-DES context structure
 */
typedef struct mbedtls_des3_context
{
   uint8_t keyindex;  /**< RFU */
   uint8_t mode;      /* 1 == Encrypt else Decrypt */
}
mbedtls_des3_context;

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/**
 * \brief          Triple-DES key schedule (112-bit, encryption)
 *
 * \param key      16-byte secret key
 *
 * \return         0
 */
int32_t mbedtls_des3_set2key_enc_stz(const uint8_t * key);

/**
 * \brief          Triple-DES key schedule (112-bit, decryption)
 *
 * \param key      16-byte secret key
 *
 * \return         0
 */
int32_t mbedtls_des3_set2key_dec_stz(const uint8_t * key);

/**
 * \brief          Triple-DES key schedule (168-bit, encryption)
 *
 * \param key      24-byte secret key
 *
 * \return         0
 */
int32_t mbedtls_des3_set3key_enc_stz(const uint8_t * key);

/**
 * \brief          Triple-DES key schedule (168-bit, decryption)
 *
 * \param key      24-byte secret key
 *
 * \return         0
 */
int32_t mbedtls_des3_set3key_dec_stz(const uint8_t * key);

/**
 * \brief          Triple-DES unload key
 *
 *
 * \return         0
 */
int32_t mbedtls_des3_unloadkey_stz(void);

/**
 * \brief          3DES-ECB block encryption/decryption
 *
 * \param input    input blob
 * \param output   output blob
 * \param mode     MBEDTLS_DES_ENCRYPT or MBEDTLS_DES_DECRYPT
 *
 * \return         0 if successful
 */
int32_t mbedtls_des3_crypt_ecb_stz(const uint8_t * input, uint8_t *output, uint8_t mode);

/**
 * \brief          3DES-CBC buffer encryption/decryption
 *
 * \param des_cbc  Context and other for cbc crypto parameters #mbedtls_des3_cbc_context_t
 *
 * \return         0 if successful, or MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH
 */
int32_t mbedtls_des3_crypt_cbc_stz(mbedtls_des3_cbc_context_t * des_cbc );

/**
 * \brief          3DES-CBC CMAC generation
 *
 * \note
 * \param input    buffer holding the input data
 * \param cmacoutput   buffer holding the output cmac data
 * \param length   length of the input data
 *
 * \return         0 if successful, or MBEDTLS_ERR_DES_INVALID_INPUT_LENGTH
 */

int32_t mbedtls_des3_crypt_cbc_cmac_stz(const uint8_t * input, uint8_t *cmacoutput, size_t length);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_DESALT_H_ */
