/*----------------------------------------------------------------------------*/
/* Copyright 2015, 2024 NXP                                                   */
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
* SAM NonX (S) MIFARE Plus EVx (Ev1, and future versions) Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALMFPEVX_SAM_NONX_H
#define PHALMFPEVX_SAM_NONX_H

/***************************************************************************************************************************************/
/* Mifare Plus EVx command for personalization.                                                                                        */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_WritePerso(void * pDataParams, uint8_t bLayer4Comm, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pValue);

phStatus_t phalMfpEVx_Sam_NonX_CommitPerso(void * pDataParams, uint8_t bOption, uint8_t bLayer4Comm);



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for authentication.                                                                                         */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_AuthenticateMfc(void * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t * pUid, uint8_t bUidLen);

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL0(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2);

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL1(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2);

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL3(void * pDataParams, uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2);

phStatus_t phalMfpEVx_Sam_NonX_SSAuthenticate(void * pDataParams, uint8_t bOption, uint16_t wSSKeyBNr, uint16_t wSSKeyNr,
    uint16_t wSSKeyVer, uint8_t bLenDivInputSSKey, uint8_t * pDivInputSSKey, uint8_t bSecCount, uint16_t *pSectorNos,
    uint16_t *pKeyNo, uint16_t *pKeyVer, uint8_t bLenDivInputSectorKeyBs, uint8_t * pDivInputSectorKeyBs);

phStatus_t phalMfpEVx_Sam_NonX_AuthenticatePDC(void * pDataParams, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bUpgradeInfo);



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for data operations.                                                                                        */
/***************************************************************************************************************************************/

phStatus_t phalMfpEVx_Sam_NonX_Write(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced, uint16_t wBlockNr,
    uint8_t bNumBlocks, uint8_t * pBlocks, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_Read(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t bNumBlocks, uint8_t * pBlocks);



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for value operations.                                                                                       */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_WriteValue(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced,
    uint16_t wBlockNr, uint8_t * pValue, uint8_t bAddr, uint8_t * pTMC, uint8_t * pTMV );

phStatus_t phalMfpEVx_Sam_NonX_ReadValue(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t * pValue, uint8_t * pAddr);

phStatus_t phalMfpEVx_Sam_NonX_Increment(void * pDataParams, uint8_t bIncrementMaced, uint16_t wBlockNr, uint8_t * pValue);

phStatus_t phalMfpEVx_Sam_NonX_Decrement(void * pDataParams, uint8_t bDecrementMaced, uint16_t wBlockNr, uint8_t * pValue);

phStatus_t phalMfpEVx_Sam_NonX_IncrementTransfer(void * pDataParams, uint8_t bIncrementTransferMaced, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_DecrementTransfer(void * pDataParams, uint8_t bDecrementTransferMaced, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_Transfer(void * pDataParams, uint8_t bTransferMaced, uint16_t wBlockNr, uint8_t * pTMC,
    uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_Restore(void * pDataParams, uint8_t bRestoreMaced, uint16_t wBlockNr);



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for special opeations.                                                                                      */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVerInfo, uint8_t * pVerLen);

phStatus_t phalMfpEVx_Sam_NonX_ReadSign(void * pDataParams, uint8_t bLayer4Comm, uint8_t bAddr, uint8_t ** pSignature);

phStatus_t phalMfpEVx_Sam_NonX_ResetAuth(void * pDataParams);

phStatus_t phalMfpEVx_Sam_NonX_PersonalizeUid(void * pDataParams, uint8_t bUidType);

phStatus_t phalMfpEVx_Sam_NonX_SetConfigSL1(void * pDataParams, uint8_t bOption);

phStatus_t phalMfpEVx_Sam_NonX_ReadSL1TMBlock(void * pDataParams, uint16_t wBlockNr, uint8_t * pBlocks);

phStatus_t phalMfpEVx_Sam_NonX_VCSupportLastISOL3(void * pDataParams, uint8_t * pIid, uint8_t * pPcdCapL3, uint8_t * pInfo);

phStatus_t phalMfpEVx_Sam_NonX_ChangeKey(void * pDataParams, uint8_t bChangeKeyMaced, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput);

phStatus_t phalMfpEVx_Sam_NonX_CommitReaderID(void * pDataParams, uint16_t wBlockNr, uint8_t * pEncTMRI);



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for utility operations.                                                                                     */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_ResetSecMsgState(void * pDataParams);

phStatus_t phalMfpEVx_Sam_NonX_SetConfig(void * pDataParams, uint16_t wOption, uint16_t wValue);

phStatus_t phalMfpEVx_Sam_NonX_GetConfig(void * pDataParams, uint16_t wOption, uint16_t * pValue);

phStatus_t phalMfpEVx_Sam_NonX_CalculateTMV(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pTMI, uint16_t wTMILen, uint8_t * pTMV);

phStatus_t phalMfpEVx_Sam_NonX_DecryptReaderID(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pEncTMRI, uint8_t * pTMRIPrev);
#endif /* PHALMFPEVX_SAMAV3_NONX_H */
