/*----------------------------------------------------------------------------*/
/* Copyright 2009-2020, 2024 NXP                                              */
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
* Sam S Virtual Card Architecture(R) Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALVCA_SAM_NONX_H
#define PHALVCA_SAM_NONX_H

#include <ph_Status.h>

#define PHAL_VCA_SAMAV3_FCI_DATA_LEN                36U   /**< FCI data length. */
#define PHAL_VCA_SAMAV3_TRUNCATED_MAC_SIZE          8U    /**< Size of the truncated MAC. */

#define PHAL_VCA_SAMAV3_PC_RND_LEN                  8U    /**< Random data Length. */


#ifdef NXPBUILD__PHAL_VCA_SAMAV3_NONX
phStatus_t phalVca_Sam_NonX_IsoSelect(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bSelectionControl, uint8_t bOption,
    uint8_t bDFnameLen, uint8_t * pDFname, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t bEncKeyNo, uint8_t bEncKeyVer,
    uint8_t bMacKeyNo, uint8_t bMacKeyVer, uint8_t * pResponse, uint16_t * pRespLen);

phStatus_t phalVca_Sam_NonX_IsoExternalAuthenticate(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pInData);

phStatus_t phalVca_Sam_NonX_ProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bGenerateRndC,
    uint8_t * pPrndC, uint8_t bNumSteps, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pDivInput, uint8_t bDivInputLen,
    uint8_t * pOption, uint8_t * pPubRespTime, uint8_t * pResponse, uint16_t * pRespLen, uint8_t * pCumRndRC);

phStatus_t phalVca_Sam_NonX_PrepareProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pOption,
    uint8_t * pPubRespTime, uint8_t * pResponse, uint16_t * pRespLen);

phStatus_t phalVca_Sam_NonX_ExecuteProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bGenerateRndC,
    uint8_t * pPrndC, uint8_t * pPubRespTime, uint8_t bNumSteps, uint8_t * pCumRndRC);

phStatus_t phalVca_Sam_NonX_VerifyProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pMac,
    uint8_t * pResponse, uint16_t * pRespLen);

phStatus_t phalVca_Sam_NonX_SetConfig(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phalVca_Sam_NonX_GetConfig(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phalVca_Sam_NonX_SendISOWrappedCmd(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pCmdBuffer, uint8_t bLc,
    uint8_t ** pResponse, uint16_t * pRespLen);

phStatus_t phalVca_Sam_NonX_ComputeErrorResponse_Extended(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wStatus);
#endif /* NXPBUILD__PHAL_VCA_SAMAV3_NONX */

#endif /* PHALVCA_SAM_NONX_H */
