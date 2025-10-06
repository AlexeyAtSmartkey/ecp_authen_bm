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
 * Alternate implementation of mbedtls functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2020-11-04 $
 *
 * History:
 *
 */

#ifndef _CRYPTO_HELPER_H
#define _CRYPTO_HELPER_H

/** @addtogroup mbedcrypto_symm_wrap
 *
 * @brief Implementation of mbedtls functions using HW Crypto blocks of PN76 NFC Controller
 *
 * This module briefs all the prototypes of mbedtls functions that uses HW Crypto blocks of PN76 NFC Controller.
 *
 * @{
 *
 */


/*****************************************************************************
 * System Includes
 ****************************************************************************/


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
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief          This function initializes crypto modules
 *
 *                 It must be the first API called before using
 *                 crypto.
 *
 *
 */
int32_t phmbedcrypto_Init( void );


/*!
 * @brief          This function de-initializes crypto modules
 *
 *                 This API must be called only if no crypto operations
 *                 are being done.
 *
 *
 *
 */
void phmbedcrypto_DeInit( void );

#ifdef __cplusplus
}
#endif
/** @} */
#endif /* _CRYPTO_HELPER_H */
