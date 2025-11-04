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
 * Main Initialization API's for the crypto
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_CRYPTO_H_
#define PN76_CRYPTO_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/** @addtogroup PN76SYSCRYPTO
 *
 * @brief System Service Crypto generic API's
 *
 * This module briefs about the implementation of Crypto module initialization and de-initialization.
 *
 * This module implements PN76SYSCRYPTO interface in the ROM code
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

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/

/*!
 * @brief          This function initializes crypto modules
 *
 *                 This API initializes the crypto HW modules necessary and the keystore uses.
 *                 This API is a MUST call from any application space before using any of the
 *                 crypto functionality. This function also initializes the RNG hardware.
 *                 The behavior of the other crypto API's are undefined if this API is not called
 *                 beforehand. For the non-crypto devices this API will return as non-supported
 *                 crypto device.
 *
 *
 * \return         #PH_STATUS_SUCCESS on success.
 * \return         #PH_STATUS_INTERNAL_ERROR on SKT Initialization or RNG Initialization failure.
 * \return         #PH_STATUS_NOT_FOUND_ERROR Crypto is not supported in this derivative.
 */
int32_t phmbedcrypto_Init_stz( void );


/*!
 * @brief          This function de-initializes crypto modules
 *
 *                 This API must be called only if no crypto operations are being done.
 *                 Can be called when the device is going to sleep or deep sleep or
 *                 shut down mode. Re-initializing the crypto functionality is MUST
 *                 when this API is executed.
 *
 */
void phmbedcrypto_DeInit_stz( void );

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_CRYPTO_H_ */
