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
#include "PN76_Crypto.h"
#include "PN76_aesalt.h"
#include "PN76_Desalt.h"
#include "PN76_Shaalt.h"
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
int32_t phmbedcrypto_Init (void)
{
   return phmbedcrypto_Init_stz();
}

void phmbedcrypto_DeInit (void)
{
   phmbedcrypto_DeInit_stz();
}

/*****************************************************************************
 * Private functions
 ****************************************************************************/




