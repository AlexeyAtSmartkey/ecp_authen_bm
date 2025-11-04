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


/** @file
 * Alternate implementation of mbedtls SHA and secure SHA functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef _EDDSA_ALT_H_
#define _EDDSA_ALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#include "PN76_Eddsaalt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief           This function generates the EdDsa key pair
 *
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 *
 * \param privkeyindex                         The key index will be used to fetch internal private key from key store  when the private key is not provided
 * \param pEncPublicKeyTwEd                    Pointer to encoded twisted Edwards curve public point (output) (b-bit encoded; buffer size minimal to store b bits)
 *                                                   The encoded point is exported via a call to the export function specified by pCallExportBigEndianParamFromCL
 * \param pPrivateKey                          Pointer to the b-bit private key k (input/output) (buffer size minimal to store b bits)
 *                                                   If private key k is imported, it is imported via a call to the import function specified by pCallSecureHashSecureImportFunction
 *                                                   If private key k is generated, it is exported via a call to the export function specified by pCallExportParamSecureFromCL
 * \param pPrivateKeyHash                      brief Pointer to the b-bits (h_b,...,h_{2b-1}) of the hashed private key k (output) (buffer size minimal to store b bits)
 *                                                   It is exported via a call to the export function specified by pCallExportParamSecureFromCL
 * \param pSubPrivateKey                       brief Pointer to the sub-private key s (output)
 * \param phmbedcrypto_eddsa_keygen_option     Option for choosing the key generation output type
 * \param phmbedcrypto_eddsa_hash_option       Option for choosing the hash type
 */
int phmbedcrypto_EdDSA_KeyGen(uint8_t  privkeyindex, uint8_t *pEncPublicKeyTwEd ,uint8_t *pPrivateKey, uint8_t *pPrivateKeyHash,
            uint8_t *pSubPrivateKey, phmbedcrypto_eddsa_keygen_option_t phmbedcrypto_eddsa_keygen_option,
            phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option);

/*!
 * @brief           This function generates the EdDsa signature
 *
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_ECP_BAD_INPUT_DATA
 * \return          MBEDTLS_ERR_ECP_HW_ACCEL_FAILED
 * \param pDigest;                              Digest of the message (input)
 * \param digestlength;                         Length of the digest
 * \param pEncPublicKeyTwEd;                    Pointer to the encoded twisted Edwards curve public point (input)
 * \param pPrivateKey;                          Pointer to the encoded twisted Edwards curve private key (input)
 * \param pSigR;                                Pointer to the first part of the signature (input) (Encoded twisted Edwards point)
 * \param pSigS;                                Pointer to the second part of the signature (input) (integer)
 * \param pcontextstring;                       Context string internally prepended to the message before hashing (input)
 * \param phmbedcrypto_eddsa_hash_option;       Option for choosing the hash type
 * \param phmbedcrypto_eddsa_sign_option;       Option for choosing the signature output type
 * \param privkeyindex;                         The key index will be used to fetch internal private key from key store when the private key is not provided
 *
 */
int phmbedcrypto_EdDSA_Sign(uint8_t *pDigest, uint32_t digestlength, uint8_t *pEncPublicKeyTwEd, uint8_t *pPrivateKey,
            uint8_t *pSigR, uint8_t *pSigS, MPInt_t *pcontextstring,
            phmbedcrypto_eddsa_hash_option_t phmbedcrypto_eddsa_hash_option, phmbedcrypto_eddsa_sign_option_t phmbedcrypto_eddsa_sign_option, uint8_t privkeyindex);

/*!
 * @brief           This function verifies the EdDSA signature
 *
 *
 * \param pDigest       Digest of the message
 *
 * \param digestlength  Length of the digest
 * \param pcontextString Pointer to context string for hashing
 * \param pPublickey    Pointer to the encoded twisted Edwards curve public point
 *                      The public key to use for verification. This must be
 *                      initialized and setup.
 * \param pSigR         Pointer to the first part of the signature
 *
 * \param pSigS         The second integer of the signature.
 *
 *
 * \return          \c 0 on success.
 * \return          1 on failure
 */
int phmbedcrypto_EdDSA_Verify(uint8_t *pDigest, uint32_t digestlength , MPInt_t *pcontextString, uint8_t *pPublickey, uint8_t *pSigR,uint8_t *pSigS);

int phmbedcrypto_EdDSA_MontDhKeyGen(uint8_t *pPublicKey, uint8_t *pPrivateKey);

int phmbedcrypto_EdDSA_MontDhKeyExchange(uint8_t *pPublicKey, uint8_t *pPrivateKey, uint8_t *pCommonSecret, uint8_t privkeyindex);




#ifdef __cplusplus
}
#endif

#endif /* _EDDSA_ALT_H_ */
