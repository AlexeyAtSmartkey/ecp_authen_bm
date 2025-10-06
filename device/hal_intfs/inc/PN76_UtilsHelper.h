/*----------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                    */
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
 * Implementation of Helper functions.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_UTILSHELPER_H_
#define _PN76_UTILSHELPER_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALUTILS
 *
 * @brief System Services for getting application flash, ram area information and secure wait functions.
 *
 * This module contains the helper interfaces to get application flash and ram area details and secure wait (poll) functions.
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
 * Public functions declarations
 ****************************************************************************/

/*!
 * @brief   This API will return the Non-Secure Flash start address and the length of Non-secure flash area.
 *
 * @param   *pdwNSFlashStartAddr   Pointer to uint32_t, where the Non-secure flash start address to be stored.
 * @param   *pdwLen                Pointer to uint32_t, where the Non-secure flash area length to be stored.
 *
 * @retval  PN76_STATUS_SUCCESS When proper values are stored in the parameters.
 * @retval  Other values Indicates an error occurred and data present in parameter is invalid. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_Get_NSFlash_Addr_Len(
            uint32_t *pdwNSFlashStartAddr,
            uint32_t *pdwLen);

/*!
 * @brief   This API will return the Non-Secure RAM start address and the length of Non-secure RAM area.
 *
 * @param   *pdwNSRamStartAddr     Pointer to uint32_t, where the Non-secure RAM start address to be stored.
 * @param   *pdwLen                Pointer to uint32_t, where the Non-secure RAM area length to be stored.
 *
 * @retval  PN76_STATUS_SUCCESS When proper values are stored in the parameters.
 * @retval  Other values Indicates an error occurred and data present in parameter is invalid. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_Get_NSRam_Addr_Len(
            uint32_t *pdwNSRamStartAddr,
            uint32_t *pdwLen);

/*!
 * @brief   This API will simply wait for the timeout given in terms of multiples of 1 micro-seconds.
 *
 * @param   dwTimeoutIn1us     Timeout value in terms of 1 micro-seconds to wait
 *
 */
void PN76_Common_Wait(
            uint32_t dwTimeoutIn1us);

/*!
 * @brief   This API will Provide a option to set HIF Timeout value.
 *          Timeout will be considered only when Pin less mode is enabled.
 *          After this time the IC will exit from pin less download mode and enter to normal mode of operation.
 *          Maximum timeout can be achieved = ~5.94 seconds.
 *
 * @param   dwTimeOutValue     Timeout value in terms of 1u = 5,66us (ex: 1000 means 5,66ms).
 *                             Max Value 0xFFFFFUL; // e.i. ~5.94 seconds.
 *                             Min Value 0x1B9B; // e.i. ~40 millisecond. value below this will set to default Min value e.i. 0x1B9B;
 *                             Bits description :
 *                              0-20 bits = Timeout value
 *                             21-32 bits = RFU
 *
 * @retval  PN76_STATUS_SUCCESS When HIF Timeout set properly.
 * @retval  Other values Indicates an error occurred and data present in parameter is invalid. Please refer to \ref PN76_Status_t enum.
 * @note This API must be executed in a stable power environment. 
 */
PN76_Status_t PN76_Sys_Set_HIF_Timeout( uint32_t dwTimeOutValue );
/*!
 * @brief   This API will Provide a option to get HIF Timeout value.
 *          Timeout will be considered only when Pin less mode is enabled.
 *          After this time the IC will exit from pin less download mode and enter to normal mode of operation.
 *
 * @param   dwTimeOutValue     Pointer to uint32_t, where the Timeout value to be stored.
 *
 * @retval  PN76_STATUS_SUCCESS When proper values are stored in the parameters.
 * @retval  Other values Indicates an error occurred and data present in parameter is invalid. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Sys_Get_HIF_Timeout( uint32_t *pdwTimeOutValue );
#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_UTILSHELPER_H_ */


