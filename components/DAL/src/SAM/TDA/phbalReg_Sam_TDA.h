/*----------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                         */
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
* SAM (Secure Access Module) internal implementation via TDA interface for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHBALREG_SAM_TDA_H
#define PHBALREG_SAM_TDA_H

#include <ph_Status.h>
#include <phbalReg.h>

#ifdef NXPBUILD__PHBAL_REG_SAM

#ifndef _WIN32
#include "phhalCt.h"
#include "phpalCt.h"

phStatus_t phbalReg_Sam_TDA_Init(phbalReg_Sam_DataParams_t * pDataParams, phpalCt_DATAParams_t apPal_Ct[PHAPP_MAX_CT_SLOT_SUPPORTED],
    phhalCt_SlotType_t Slot_type, uint8_t * pAtrBuffer, uint16_t wAtrBufSize);
#endif /* _WIN32 */

phStatus_t phbalReg_Sam_ActivateSam_TDA(phbalReg_Sam_DataParams_t * pDataParams);

phStatus_t phbalReg_Sam_Pps_TDA(phbalReg_Sam_DataParams_t * pDataParams);

phStatus_t phbalReg_Sam_DeActivateSam_TDA(phbalReg_Sam_DataParams_t * pDataParams);

phStatus_t phbalReg_Sam_TransmitData_TDA(phbalReg_Sam_DataParams_t * pDataParams, uint8_t * pTxBuffer, uint16_t wTxBufLen,
    uint16_t wRxBufSize, uint8_t * pRxBuffer, uint16_t * pRxBufLen);

#endif /* NXPBUILD__PHBAL_REG_SAM */

#endif /* PHBALREG_SAM_TDA_H */
