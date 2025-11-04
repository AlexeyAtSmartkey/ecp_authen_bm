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
/* Copyright 2021-2023 NXP                                                    */
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
 * Alternate implementation of mbedtls cmac functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_CMACALT_H_
#define PN76_CMACALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"

/** @addtogroup PN76SYSSYMMETRICCMAC
 *
 * @brief System Service CMAC API's
 *
 * This module briefs about the implementation of CMAC algorithms for AES and 3DES Algorithms.
 *
 * \section PN76SYSSYMMETRICCMAC_NOTE Note regarding the use of the AES keys stored in hardware keystore
	If the AES keys stored in hardware keystore to be used for encryption/decryption, only
	\ref SKM_KEY_TYPE_APP_MASTER or \ref SKM_KEY_TYPE_APP_FIXED must be used.
	
	If \ref SKM_KEY_TYPE_APP_MASTER is used, then a encryption/decryption key is derived from this key 
	with the derivation message stored in EEPROM configuration \ref PN76_SKM_EncrDecrDerMsg.
	
	If \ref SKM_KEY_TYPE_APP_FIXED is used, then the key itself is a encryption/decryption key.
	
	\note Further if the key to be used from hardware keystore, that key must be provisioned.
 
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
#define MBEDTLS_CMAC_MODE_AES    0
#define MBEDTLS_CMAC_MODE_DES    1

#define MBEDTLS_DES_BLOCK_SIZE   8
#define MBEDTLS_AES_BLOCK_SIZE   16

#define MBEDTLS_ERR_CMAC_BAD_INPUT_DATA                    -0x0031  /**< Invalid input data. */

#define MBEDTLS_ERR_CMAC_HW_ACCEL_FAILED                   -0x0035  /**< AES hardware accelerator failed. */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/**
 * \brief          CMAC context structure
 */
typedef struct mbedtls_cmac_context
{
   uint8_t bMode;
   uint8_t bKeyIndex;
   uint8_t bBlockSize;
   uint8_t bReloadKey;
}
mbedtls_cmac_context_t;

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/**
 * \brief          CMAC Start. This API only loads the key onto the SGI.
 *
 * \param pCtx Pointer holding the CMAC context structure
 * \param pKey Pointer holding the key
 * \param wKeyBits Value holding the key length in bits
 *
 * \return         0
 
 * \note           If key stored in hardware key store to be used, the parameter \b key must be NULL.
 *                 \n The value in \ref mbedtls_cmac_context_t.bKeyIndex must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICCMAC_NOTE

 */
int32_t mbedtls_cmac_start_stz(mbedtls_cmac_context_t * pCtx, const uint8_t *pKey, size_t wKeyBits);

/**
 * \brief          CMAC update. This function feeds an input buffer into an ongoing CMAC computation.
 *
 * \param pCtx Pointer holding the CMAC context structure
 * \param pInput Pointer holding the input data blob
 * \param dwInputLen Value holding the input length
 *
 * \return         0
 */
int32_t mbedtls_cmac_update_stz(mbedtls_cmac_context_t * pCtx, const uint8_t *pInput, size_t dwInputLen);

/**
 * \brief          CMAC complete. This function finishes an ongoing CMAC operation, and
 *                 writes the result to the output buffer.
 *
 * \param pCtx Pointer holding the CMAC context structure
 * \param pOutput Pointer holding the output data blob
 *
 * \return         0
 */
int32_t mbedtls_cmac_finalize_stz(mbedtls_cmac_context_t * pCtx, uint8_t *pOutput);

/**
 * \brief          Resets the initialization vector to zero and any local buffer being used.
 *                 Start the CMAC with fresh inputs. This is help full to restart the CMAC
 *                 operation using the key that was used during \ref mbedtls_cmac_start_stz
 *                 "CMAC-Start". Should be called after \ref mbedtls_cmac_finalize_stz
 *                 "CMAC-Finalize".
 *
 * \param pCtx Pointer holding the CMAC context structure
 *
 * \return         0
 */
int32_t mbedtls_cmac_reset_stz(mbedtls_cmac_context_t * pCtx);


#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_CMACALT_H_ */
