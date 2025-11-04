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
 *
 * Implementation of OPT CONFIGS HAL interface functions.
 *
 * $Author: $
 * $Revision: $ (01.01.00)
 *
 */

#ifndef _PN76_OTPCONFIGS_H_
#define _PN76_OTPCONFIGS_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/** @addtogroup PN76SYSHALOTPConfigs
 *
 * @brief SYS OTP configs HAL APIs
 *
 * This module implements PN76SYSHALOTPConfigs interface Flash code HAL, specific to OTP configs module.
 * NOTE: All the configurations are One Time Programmable
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
 * @brief This instruction is used to set timeout for download request pin less boot.
 *
 * @param dwTimeOut Maximum wait timeout before switching to Normal Operation Mode in flash (One unit is 5.66 Micro sec).
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_RESOURCE_ERROR download request pin less feature NOT available.
 * @retval PN76_STATUS_PARAMETER_ERROR In case the PinLess feature is NOT enabled.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory read/write operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_DwnldReqLessBoot(uint32_t dwTimeOut);

/*!
 * @brief This instruction is used to set the PVDD source settings.
 *
 * @param bPvddSrc Source of Pad Voltage. If 0 --> External, Non-Zero/1 --> Internal.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_SetPvddSource(uint8_t bPvddSrc);

/*!
 * @brief This instruction is used to configure the low powermode selection between HPD or OFF states when VEN pin goes low.
 *
 * @param bHPDOffSelection 0: OFF -> OFF power mode, Non-Zero/1: ON -> Hard power down (HPD) mode.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_HPDOffSelection(uint8_t bHPDOffSelection);

/*!
 * @brief This instruction is used to set internal VEN state in case of invalid VDDIO.
 *
 * @param bVENInternal 1/Non-Zero: HW will not check for external VEN pin.\n
 *                     0: HW will check for external VEN pin before entering HPD/PMU off based on bHPDOffSelection settings.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_InternalVENSelection(uint8_t bVENInternal);

/*!
 * @brief This instruction is used to disable the Testbus feature.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_DisableTestBus(void);

/*!
 * @brief This instruction disables the customer debug facility.
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Sys_OTPConfigs_DisableSwdDebug(void);

/*!
 * @brief This instruction disables the NS Ram execution. This function cannot be called from NS Ram.
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Sys_OTPConfigs_DisableNSRamExecution(void);

/*!
 * @brief This instruction enables the Code read protection. Through CL EDL it will not allow reading the customer code/data.
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Sys_OTPConfigs_EnableCRP(void);

/*!
 * @brief OPT: Enables the Code write protection. Through USB DL it will not allow writing the customer code/data.
 *
 * @return  Status code of execution
 * @retval PN76_STATUS_SUCCESS Operation successful
 * @retval PN76_STATUS_MEMORY_ERROR Write/Read/Internal error
 */
PN76_Status_t PN76_Sys_OTPConfigs_EnableCWP(void);

/*!
 * @brief This instruction is used to LOCK the configurations done by all above OTP interfaces and shall not allow further modification.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_LockSettings(void);

/*!
 * @brief This instruction is used to enable the DWL_REQ pin-less download mode, where DWL_REQ pin is not used to enter into secure download or SKM mode.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR NO access permissions to do the requested settings.
 * @retval PN76_STATUS_MEMORY_ERROR Flash/EE memory operation failed.
 */
PN76_Status_t PN76_Sys_OTPConfigs_EnableDwnldReqLessBoot(void);
#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _PN76_OTPCONFIGS_H_ */
