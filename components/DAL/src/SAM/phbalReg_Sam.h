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
* SAM (Secure Access Module) implementation for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHBALREG_SAM_H
#define PHBALREG_SAM_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHBAL_REG_SAM

phStatus_t phbalReg_Sam_GetPortList(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wPortBufSize, uint8_t * pPortNames,
    uint16_t * pNumOfPorts);

phStatus_t phbalReg_Sam_SetPort(phbalReg_Sam_DataParams_t * pDataParams, uint8_t * pPortName);

phStatus_t phbalReg_Sam_OpenPort(phbalReg_Sam_DataParams_t * pDataParams);

phStatus_t phbalReg_Sam_ClosePort(phbalReg_Sam_DataParams_t * pDataParams);

phStatus_t phbalReg_Sam_Exchange(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pTxBuffer,
    uint16_t wTxBufLen, uint16_t wRxBufSize, uint8_t * pRxBuffer, uint16_t * pRxBufLen);

phStatus_t phbalReg_Sam_SetConfig(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue );

phStatus_t phbalReg_Sam_GetConfig( phbalReg_Sam_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

#endif /* NXPBUILD__PHBAL_REG_SAM */
#endif /* PHBALREG_SAM_H */
