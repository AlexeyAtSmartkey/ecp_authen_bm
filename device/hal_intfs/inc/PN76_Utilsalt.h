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
/* Copyright 2023 NXP                                                         */
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
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_UTILSALT_H_
#define PN76_UTILSALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "ph_Datatypes.h"
#include "string.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/
/*
 * Utils Error codes
 */
#define MBEDTLS_ERR_UTILS_BAD_INPUT_DATA                    -0x8080  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_UTILS_HW_ACCEL_FAILED                   -0x8580  /**< The RSA hardware accelerator failed. */


/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/**
 * \brief Structure for multi-precision integer used into asymetric cryptography
 * */
typedef struct phClw_MPInt_t
{
  uint8_t *pMPInt; /**< Pointer to the multi precision integer. */
  uint16_t wNumBytes; /**< Length in bytes of multi precision integer. */
} phClw_MPInt_t;

/**
 * \brief Structure for ECC domain parameter.
 */
typedef struct mbedtls_utils_ecp_group
{
    phClw_MPInt_t* P;      /**< \brief Prime of the underlying field p */
    phClw_MPInt_t* N;      /**< \brief Base point order n */
    uint8_t* A;            /**< \brief Pointer to curve parameter a, element of GF(p) */
    uint8_t* B;            /**< \brief Pointer to curve parameter b, element of GF(p) */
    uint8_t* G;            /**< \brief Pointer to base point G */
    uint8_t *pPoint1;      /**< \brief Pointer to EC point P. */
    uint8_t *pPoint2;      /**< \brief Pointer to EC point Q. */
}
mbedtls_utils_ecp_group_t;

/**
 * \brief Enum for UTILS Math Operations
 */
typedef enum phClUtilsMath_Operations_t
{
   PH_MATH_OPERATION_DIVIDE = 0,
   PH_MATH_OPERATION_SECUREMODMULT,
   PH_MATH_OPERATION_SECUREMODSUB,
   PH_MATH_OPERATION_SECUREMODADD,
   PH_MATH_OPERATION_SECUREMODINV,
   PH_MATH_OPERATION_SECUREADD,
   PH_MATH_OPERATION_SECURECOMPARE
} phClUtilsMath_Operations_t;

/*!
 * @brief Util Maths group.
 *
 */
typedef struct phClUtilsMath_Operations_Grp
{
   phClw_MPInt_t *pOperandA;       /* pOperandA: operand buffer */
   phClw_MPInt_t *pOperandB;       /* pOperandB: operand buffer */
   phClw_MPInt_t *pModulus;        /* pModulus:  modulus buffer */
   uint8_t bOperation;             /* Operation to be performed */
   uint8_t *pCalculatedResult;     /* R: result buffer          */
}
phClUtilsMath_Operations_Grp_t;
/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/**
 * \brief This function implements the ECC GF(p) point addition
 *
 * \param [in]  grp          grp Pointer to a parameter structure
 * \param [out] pResult      Pointer to the resulting point R = P + Q.Every coordinate of the result is exported via a call to the export function specified by pCallExportBigEndianParamSecureFromCL
 *
 * \returns Status of the operation
 *
 * \retval ::PH_STATUS_SUCCESS                          Point addition was successful.
 * \retval ::MBEDTLS_ERR_UTILS_BAD_INPUT_DATA           Bad input parameters to function.
 * \retval ::MBEDTLS_ERR_UTILS_HW_ACCEL_FAILED          The RSA hardware accelerator failed.
 * \retval ::PH_STATUS_BUSY                             Operation buys
 *
 */
int32_t Utils_EccGfp_PointAdd_stz(mbedtls_utils_ecp_group_t *grp, uint8_t *pResult);
/**
 * \brief
 * This function implements the arithmetic operations listed below
 * The parameters shall be passed using the structure
 * The parameter field pParams->operation defines the Operation depending on its value:
 * #PH_MATH_OPERATION_DIVIDE
 * #PH_MATH_OPERATION_SECUREMODMULT
 * #PH_MATH_OPERATION_SECUREMODSUB
 * #PH_MATH_OPERATION_SECUREMODADD
 * #PH_MATH_OPERATION_SECUREMODINV
 * #PH_MATH_OPERATION_SECUREADD
 * #PH_MATH_OPERATION_SECURECOMPARE
 *
 * \param [in] UtilMathsGrp Pointer to a parameter structure
 *
 * \returns Status of the operation
 *
 * \retval ::PH_STATUS_SUCCESS                          Point addition was successful.
 * \retval ::MBEDTLS_ERR_UTILS_BAD_INPUT_DATA           Bad input parameters to function.
 * \retval ::MBEDTLS_ERR_UTILS_HW_ACCEL_FAILED          The RSA hardware accelerator failed.
 * \retval ::PH_STATUS_BUSY                             Operation buys
 *
 */
int32_t Utils_Math_Operation_stz(phClUtilsMath_Operations_Grp_t *UtilMathsGrp);
#endif /* PN76_UTILSALT_H_ */
