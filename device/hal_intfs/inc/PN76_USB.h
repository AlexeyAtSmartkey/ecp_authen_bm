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
 *
 * Implementation of USB Suspend and resume mode for compliance.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_USB_H_
#define _PN76_USB_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "ph_Datatypes.h"
#include "PN76_Status.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/


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
 * @brief This function configures PCRM registers, LDO, CLIF and GPIOs to put USB in suspend mode (current reduction mode)
 * @retval  nothing
 */
PN76_Status_t PN76_Sys_Hal_USB_Suspend( void );

#endif /* _PN76_USB_H_ */
