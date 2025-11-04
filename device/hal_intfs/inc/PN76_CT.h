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
 *
 * Implementation of Secure Key Mode (SKM) Interfaces for for non-secure code execution.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_CT_H_
#define _PN76_CT_H_

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
 * @brief This function initializes PCRM secure registers to enable CT clock
 * @retval  nothing
 */
void PN76_Sys_Hal_CT_PCRM_Init( void );

/*!
 * @brief This function initializes USB_PLL and VDD settings needed for enbaling CT clock
 * @retval  nothing
 */
void PN76_Sys_Hal_CT_USB_PLL_On( void );


#endif /* _PN76_CT_H_ */
