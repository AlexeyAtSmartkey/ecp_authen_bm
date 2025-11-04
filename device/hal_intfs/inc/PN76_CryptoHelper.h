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
 * Alternate implementation of mbedtls AES functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_CRYPTOHELPER_H_
#define PN76_CRYPTOHELPER_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
#include "PN76_aesalt.h"

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
 * Public functions declaration
 ****************************************************************************/

/** @} */

/** @addtogroup PN76mbedcryptohashcryptintfinternal
 *
 * Internal interfaces.
 *
 * This module briefs all the prototypes of HW Crypto Interfaces.
 *
 *
 * @{
 *
 */

/*!
 * @brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 *                 If this is \c NULL, this function does nothing.
 *                 Otherwise, the context must have been at least initialized.
 */
void PN76_mbedtls_aes_free( mbedtls_aes_context *ctx );

/*!
 * @brief   This function releases and clears the specified CCM context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The CCM context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void PN76_mbedtls_ccm_free( mbedtls_ccm_context *ctx );

/*!
 * @brief           This function clears a GCM context
 *
 * \param ctx       The GCM context to clear. If this is \c NULL, the call has
 *                  no effect. Otherwise, this must be initialized.
 */
void PN76_mbedtls_gcm_free( mbedtls_gcm_context *ctx );

/*!
 * @brief   This function releases and clears the specified eax context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The eax context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void PN76_mbedtls_eax_free( mbedtls_eax_context *ctx );

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_CRYPTOHELPER_H_ */
