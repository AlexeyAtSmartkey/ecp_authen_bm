/*----------------------------------------------------------------------------*/
/* Copyright 2020-2022 NXP                                                    */
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
 *
 * Implementation of RNG interface functions for non-secure code execution
 *
 * $Author: $
 * $Revision: $ (01.01.00)
 *
 */

#ifndef _PN76_RNG_H_
#define _PN76_RNG_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALRng
 *
 * @brief System Service Random Number Generator HAL APIs
 *
 * This module briefs all the prototypes of RNG hal.
 *
 * This module implements PN76SYSHALRng interface Flash code HAL, specific to RNG module.
 *
 * @{
 *
 */

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
 * @brief This function initializes random number generator.
 * @retval  nothing
 */
void PN76_Sys_Hal_RNG_Init(void);

/*!
 * @brief    This function generates CHI SQUARE tested random numbers in the passed buffer.
 *
 * @param *pBuffer : Pointer to generated random number data message structure.
 * @param dwDataLength : Length of \a pBuffer in bytes.
 *
 * @retval PN76_STATUS_SUCCESS on successful RNG Generation
 * @retval PN76_STATUS_PARAMETER_ERROR error code due to wrong parameter
 * @note  Value of RNG is 8-bit, but it is placed in 32-bit register.
 * @note  This function will first enable RNG, calculate RNG and then disable RNG
 * @note There will be constant value(0x19AC3F74U) in the buffer in case of an RNG HW failure.
 */
PN76_Status_t PN76_Sys_Hal_RNG_GenerateSecureRng(
    uint8_t *pBuffer,     /**< [Out]  Pointer to generated random number data message structure. */
    uint32_t dwDataLength /**< [In] Length of data message structure in bytes. */
);

/*!
 * @brief    This function generates random numbers buffer.
 *
 * @param *pBuffer : Pointer to generated random number data message structure.
 * @param dwDataLength :  Length of data message structure in bytes
 *
 * @retval PN76_STATUS_SUCCESS on successful RNG Generation
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter error
 * @note  Once started RNG will be enabled all the time and will continuously generate random numbers.
 * @note  Value of RNG is 8-bit, but it is placed in 32-bit register.
 * @note There will be constant value(0x19AC3F74U) in the buffer in case of an RNG HW failure.
 */
PN76_Status_t PN76_Sys_Hal_RNG_GenerateRng(
    uint8_t *pBuffer,     /**< [In] Pointer to generated random number data message structure. */
    uint32_t dwDataLength /**< [In] Length of data message structure in bytes */
);

/*!
 * @brief    This function generates random numbers buffer.
 *
 * @param *pBuf : Pointer to generated random number data message structure.
 * @param dwLen : Length of data message structure in bytes.
 *
 * @retval PN76_STATUS_SUCCESS on successful PRNG Generation
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter error
 * @note  Once started RNG will be enabled all the time and will continuously generate random numbers
 * @note  Value of RNG is 8-bit, but it is placed in 32-bit register.
 * @note There will be constant value(0x19AC3F74U) in the buffer in case of an RNG HW failure.
 */
PN76_Status_t PN76_Sys_Hal_RNG_GeneratePrng(
    uint8_t *pBuf, /**< [Out] Pointer to generated random number data message structure. */
    uint32_t dwLen /**< [In] Length of data message structure in bytes */
);

/*!
 * @brief    This function generates CHI SQUARE tested random numbers in the passed buffer.
 *
 * @param *pbiRngBuffer  : Pointer to generated random number data message structure
 * @param dRNrLength : Length of data message structure in bytes
 *
 * @retval PN76_STATUS_SUCCESS on successful Secure PRNG generated.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter error
 * @note  This function is generic and not dependent on any RTOS
 * @note  This function will first enable RNG, calculate RNG and then disable RNG
 * @note There will be constant value(0x19AC3F74U) in the buffer in case of an RNG HW failure.
 */
PN76_Status_t PN76_Sys_Hal_RNG_GenerateSecurePrng(
    uint8_t *pbiRngBuffer, /**< [In] Pointer to generated random number data message structure */
    uint32_t dRNrLength    /**< [In]Length of data message structure in bytes */
);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_RNG_H_ */
