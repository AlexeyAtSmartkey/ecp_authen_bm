/*----------------------------------------------------------------------------*/
/* Copyright 2025 Smartphonekey System Inc.                                   */
/*                                                                            */
/* Smartphonekey System Inc. Confidential. This software is owned or          */
/* controlled by Smartphonekey System Inc. and may only be used strictly      */
/* in accordance with the applicable license terms.                           */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms.  															  */
/* If you do not agree to be bound by the applicable license   				  */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* Header for Google Wallet pass read.
*
* $Author:   $(Smartphonekey System Inc.)
* $Revision: $(v01.00.00)
* $Date:     $(2025-07-20)
*/


#ifndef GWPASSMNGR_H
#define GWPASSMNGR_H

#include <ph_Status.h>
#include <phacDiscLoop.h>

#include "ApduEx.h"
#include "nrf_comm_protocol.h"
#include "nrf_comm.h"

phStatus_t ProcessGoogleWallet(phacDiscLoop_Sw_DataParams_t *pDiscLoop);


#endif /* NFCRDLIBEX2_ECP_H */
