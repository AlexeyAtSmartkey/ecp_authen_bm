/*----------------------------------------------------------------------------*/
/* Copyright 2009-2014, 2024 NXP                                              */
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
* Sam NonX MIFARE(R) Ultralight Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALMFUL_SAM_NON_X_H
#define PHALMFUL_SAM_NON_X_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFUL_SAM_NONX

phStatus_t phalMful_Sam_NonX_UlcAuthenticate(void * pDataParams, uint8_t bOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMful_Sam_NonX_AuthenticateAES(phalMful_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bRamKeyNo, uint8_t bRamKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivLen);

phStatus_t phalMful_Sam_NonX_Read(void * pDataParams, uint8_t bAddress, uint8_t * pData);

phStatus_t phalMful_Sam_NonX_Write(void * pDataParams, uint8_t bAddress, uint8_t * pData);

phStatus_t phalMful_Sam_NonX_FastWrite(void * pDataParams, uint8_t * pData);

phStatus_t phalMful_Sam_NonX_CompatibilityWrite(void * pDataParams, uint8_t bAddress, uint8_t * pData);

phStatus_t phalMful_Sam_NonX_IncrCnt(void * pDataParams, uint8_t bCntNum, uint8_t * pCnt);

phStatus_t phalMful_Sam_NonX_ReadCnt(void * pDataParams, uint8_t bCntNum, uint8_t * pCntValue);

phStatus_t phalMful_Sam_NonX_PwdAuth(void * pDataParams, uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t * pDivInput,
    uint8_t bDivInputLen, uint8_t * pPwd, uint8_t * pPack);

phStatus_t phalMful_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVersion);

phStatus_t phalMful_Sam_NonX_FastRead(void * pDataParams, uint8_t  bStartAddr, uint8_t bEndAddr,
    uint8_t ** pData, uint16_t * pNumBytes);

phStatus_t phalMful_Sam_NonX_SectorSelect(void * pDataParams, uint8_t bSecNo);

phStatus_t phalMful_Sam_NonX_ReadSign(void * pDataParams, uint8_t bAddr, uint8_t ** pSignature, uint16_t * pDataLen);

phStatus_t phalMful_Sam_NonX_ChkTearingEvent(void * pDataParams, uint8_t bCntNum, uint8_t * pValidFlag);

phStatus_t phalMful_Sam_NonX_WriteSign(void * pDataParams, uint8_t bAddress, uint8_t * pSignature);

phStatus_t phalMful_Sam_NonX_LockSign(void * pDataParams, uint8_t bLockMode);

phStatus_t phalMful_Sam_NonX_VirtualCardSelect(void * pDataParams, uint8_t * pVCIID, uint8_t bVCIIDLen, uint8_t * pVCTID);

phStatus_t phalMful_Sam_NonX_ReadTTStatus(void * pDataParams, uint8_t bAddr, uint8_t * pData);

#ifdef NXPBUILD__PHAL_MFUL_SAMAV3_NONX
phStatus_t phalMful_Sam_NonX_GetConfig(void * pDataParams,uint16_t wConfig,uint16_t * pValue);

phStatus_t phalMful_Sam_NonX_SetConfig(void * pDataParams,uint16_t wConfig,uint16_t wValue);

phStatus_t phalMful_Sam_NonX_CalculateSunCMAC(void * pDataParams, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t * pInData, uint16_t wInDataLen, uint8_t * pRespMac);
#endif /* NXPBUILD__PHAL_MFUL_SAMAV3_NONX */

#endif /* NXPBUILD__PHAL_MFUL_SAM_NONX */

#endif /* PHALMFUL_SAM_NON_X_H */
