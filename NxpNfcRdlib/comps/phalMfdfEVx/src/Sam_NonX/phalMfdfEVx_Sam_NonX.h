/*----------------------------------------------------------------------------*/
/* Copyright 2013-2020, 2024 NXP                                              */
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

/*
* \file
* Software MIFARE DESFire contactless IC Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALMFDFEVX_SAMAV3_NONX_H
#define PHALMFDFEVX_SAMAV3_NONX_H

/* MIFARE DESFire EVx contactless IC secure messaging related commands. ---------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_Authenticate(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateISO(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateAES(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateEv2(void *pDataParams, uint8_t bFirstAuth, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pPcdCapsIn,
    uint8_t bPcdCapsInLen, uint8_t * pPcdCapsOut, uint8_t * pPdCapsOut);




/* MIFARE DESFire EVx Memory and Configuration mamangement commands. ------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_FreeMem(void * pDataParams, uint8_t * pMemInfo);

phStatus_t phalMfdfEVx_Sam_NonX_FormatPICC(void * pDataParams);

phStatus_t phalMfdfEVx_Sam_NonX_SetConfiguration(void * pDataParams, uint8_t bOption, uint8_t * pData, uint8_t bDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVerInfo, uint8_t * pVerLen);

phStatus_t phalMfdfEVx_Sam_NonX_GetCardUID(void * pDataParams, uint8_t bExchangeOption, uint8_t bOption, uint8_t * pUid,
    uint8_t * pUidLen);


/* MIFARE DESFire EVx Key mamangement commands. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ChangeKey(void * pDataParams, uint16_t wOption, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer,
    uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_ChangeKeyEv2(void * pDataParams, uint16_t wOption, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer,
    uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeySetNo, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_InitializeKeySet(void * pDataParams,uint8_t bKeySetNo, uint8_t bKeySetType);

phStatus_t phalMfdfEVx_Sam_NonX_FinalizeKeySet(void * pDataParams, uint8_t bKeySetNo, uint8_t bKeySetVer);

phStatus_t phalMfdfEVx_Sam_NonX_RollKeySet(void * pDataParams, uint8_t bKeySetNo);

phStatus_t phalMfdfEVx_Sam_NonX_GetKeySettings(void * pDataParams, uint8_t * pKeySettings, uint8_t * pKeySettingLen);

phStatus_t phalMfdfEVx_Sam_NonX_ChangeKeySettings(void * pDataParams, uint8_t bKeySettings);

phStatus_t phalMfdfEVx_Sam_NonX_GetKeyVersion(void * pDataParams, uint8_t bKeyNo, uint8_t bKeySetNo, uint8_t * pKeyVersion,
    uint8_t * pKeyVerLen);


/* MIFARE DESFire EVx Application mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateApplication(void * pDataParams, uint8_t bOption, uint8_t * pAid, uint8_t bKeySettings1,
    uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t * pISOFileId, uint8_t * pISODFName,
    uint8_t bISODFNameLen);

phStatus_t phalMfdfEVx_Sam_NonX_DeleteApplication(void * pDataParams, uint8_t * pAid, uint8_t * pDAMMAC, uint8_t bDAMMAC_Len);

phStatus_t phalMfdfEVx_Sam_NonX_CreateDelegatedApplication(void  * pDataParams, uint8_t bOption, uint8_t * pAid,
    uint8_t * pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues,
    uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen, uint8_t * pEncK, uint8_t * pDAMMAC);

phStatus_t phalMfdfEVx_Sam_NonX_SelectApplication(void * pDataParams, uint8_t bOption, uint8_t * pAppId, uint8_t * pAppId2);

phStatus_t phalMfdfEVx_Sam_NonX_GetApplicationIDs(void * pDataParams, uint8_t bOption, uint8_t ** ppAidBuff,
    uint8_t * pNumAIDs);

phStatus_t phalMfdfEVx_Sam_NonX_GetDFNames(void * pDataParams, uint8_t bOption, uint8_t * pDFBuffer, uint8_t * bSize);

phStatus_t phalMfdfEVx_Sam_NonX_GetDelegatedInfo(void * pDataParams, uint8_t * pDAMSlot, uint8_t * pDamSlotVer,
    uint8_t * pQuotaLimit, uint8_t * pFreeBlocks, uint8_t * pAid);


/* MIFARE DESFire EVx File mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateStdDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize);

phStatus_t phalMfdfEVx_Sam_NonX_CreateBackupDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize);

phStatus_t phalMfdfEVx_Sam_NonX_CreateValueFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t * pLowerLmit, uint8_t * pUpperLmit, uint8_t * pValue, uint8_t bLimitedCredit);

phStatus_t phalMfdfEVx_Sam_NonX_CreateLinearRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfdfEVx_Sam_NonX_CreateCyclicRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec);

phStatus_t phalMfdfEVx_Sam_NonX_CreateTransactionMacFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint16_t wKeyNo, uint8_t bKeyVer, uint8_t bTMKeyOption, uint8_t * pKey, uint8_t * pDivInput,
    uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_DeleteFile(void * pDataParams, uint8_t bFileNo);

phStatus_t phalMfdfEVx_Sam_NonX_GetFileIDs(void * pDataParams, uint8_t * pFid, uint8_t * pNumFid);

phStatus_t phalMfdfEVx_Sam_NonX_GetISOFileIDs(void * pDataParams, uint8_t * pFidBuffer, uint8_t * pNumFid);

phStatus_t phalMfdfEVx_Sam_NonX_GetFileSettings(void * pDataParams, uint8_t bFileNo, uint8_t * pFSBuffer,
    uint8_t * bBufferLen);

phStatus_t phalMfdfEVx_Sam_NonX_GetFileCounters(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pResponse,
    uint8_t * pRespLen);

phStatus_t phalMfdfEVx_Sam_NonX_ChangeFileSettings(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t bAddInfoLen, uint8_t * pAddInfo);


/* MIFARE DESFire EVx Data mamangement commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ReadData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pOffset,
    uint8_t * pLength, uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdfEVx_Sam_NonX_WriteData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_GetValue(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdfEVx_Sam_NonX_Credit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdfEVx_Sam_NonX_Debit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdfEVx_Sam_NonX_LimitedCredit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue);

phStatus_t phalMfdfEVx_Sam_NonX_ReadRecords(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pRecCount, uint8_t * pRecSize, uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdfEVx_Sam_NonX_WriteRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_UpdateRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_ClearRecordFile(void * pDataParams, uint8_t bFileNo);


/* MIFARE DESFire EVx Transaction mamangement commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CommitTransaction(void * pDataParams, uint8_t bOption, uint8_t * pTMC, uint8_t * pTMV);

phStatus_t phalMfdfEVx_Sam_NonX_AbortTransaction(void * pDataParams);

phStatus_t phalMfdfEVx_Sam_NonX_CommitReaderID(void * pDataParams, uint8_t * pTMRI, uint8_t * pEncTMRI);


/* MIFARE DESFire EVx ISO7816-4 commands. ---------------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_IsoSelectFile(void * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid,
    uint8_t * pDFname, uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t ** ppFCI, uint16_t * pFCILen);

phStatus_t phalMfdfEVx_Sam_NonX_IsoReadBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint32_t dwBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint32_t * pBytesRead);

phStatus_t phalMfdfEVx_Sam_NonX_IsoUpdateBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint32_t dwDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_IsoReadRecords(void * pDataParams, uint8_t bRecNo, uint8_t bReadAllFromP1, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint32_t * pBytesRead);

phStatus_t phalMfdfEVx_Sam_NonX_IsoAppendRecord(void * pDataParams, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint32_t dwDataLen);

phStatus_t phalMfdfEVx_Sam_NonX_IsoGetChallenge(void * pDataParams, uint8_t bExtendedLenApdu, uint32_t dwLe,
    uint8_t * pRPICC1);

phStatus_t phalMfdfEVx_Sam_NonX_IsoExternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen,
    uint8_t bExtendedLenApdu, uint8_t * pDataOut, uint8_t * pOutLen);

phStatus_t phalMfdfEVx_Sam_NonX_IsoInternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen,
    uint8_t bExtendedLenApdu);

phStatus_t phalMfdfEVx_Sam_NonX_IsoAuthenticate(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t bIsPICCkey);


/* MIFARE DESFire EVx Originality Check functions. ------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ReadSign(void * pDataParams, uint8_t bAddr, uint8_t ** ppSignature);


/* MIFARE DESFire EVx MIFARE Classic contactless IC functions. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateMFCMapping(void * pDataParams, uint8_t bComOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pMFCBlockList, uint8_t bMFCBlocksLen, uint8_t bRestoreSource, uint8_t * pMFCLicense, uint8_t bMFCLicenseLen,
    uint8_t * pMFCLicenseMAC);

phStatus_t phalMfdfEVx_Sam_NonX_RestoreTransfer(void * pDataParams, uint8_t bCommOption, uint8_t bTargetFileNo,
    uint8_t bSourceFileNo);

phStatus_t phalMfdfEVx_Sam_NonX_RestrictMFCUpdate(void * pDataParams, uint8_t bOption, uint8_t * pMFCConfig,
    uint8_t bMFCConfigLen, uint8_t * pMFCLicense, uint8_t bMFCLicenseLen, uint8_t * pMFCLicenseMAC);


/* MIFARE DESFire EVx POST Delivery Configuration function. ---------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_AuthenticatePDC(void * pDataParams, uint8_t bRfu, uint8_t bKeyNoCard, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bUpgradeInfo);


/* MIFARE DESFire EVx Miscellaneous functions. ----------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_GetConfig(void * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phalMfdfEVx_Sam_NonX_SetConfig(void * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phalMfdfEVx_Sam_NonX_ResetAuthStatus(void * pDataParams);

phStatus_t phalMfdfEVx_Sam_NonX_GenerateDAMEncKey(void * pDataParams, uint16_t wKeyNoDAMEnc, uint16_t wKeyVerDAMEnc,
    uint16_t wKeyNoAppDAMDefault, uint16_t wKeyVerAppDAMDefault, uint8_t bAppDAMDefaultKeyVer, uint8_t * pDAMEncKey);

phStatus_t phalMfdfEVx_Sam_NonX_GenerateDAMMAC(void * pDataParams, uint8_t bOption, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint8_t * pAid, uint8_t * pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2,
    uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen,
    uint8_t * pEncK, uint8_t * pDAMMAC);

phStatus_t phalMfdfEVx_Sam_NonX_CalculateTMV(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pTMI, uint32_t dwTMILen, uint8_t * pTMV);

phStatus_t phalMfdfEVx_Sam_NonX_DecryptReaderID(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer,
    uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pEncTMRI,
    uint8_t * pTMRIPrev);

phStatus_t phalMfdfEVx_Sam_NonX_ComputeMFCLicenseMAC(void * pDataParams, uint16_t wOption, uint16_t wMFCLicenseMACKeyNo,
    uint16_t wMFCLicenseMACKeyVer, uint8_t * pInput, uint16_t wInputLen, uint8_t * pDivInput, uint8_t bDivInputLen,
    uint8_t * pMFCLicenseMAC);

phStatus_t phalMfdfEVx_Sam_NonX_CalculateMACSDM(void * pDataParams, uint8_t bSdmOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr,
    uint8_t * pInData, uint16_t wInDataLen, uint8_t * pMac);

phStatus_t phalMfdfEVx_Sam_NonX_DecryptSDMENCFileData(void * pDataParams, uint8_t bSdmOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr,
    uint8_t * pEncdata, uint16_t wEncDataLen, uint8_t * pPlainData);

phStatus_t phalMfdfEVx_Sam_NonX_DecryptSDMPICCData(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pEncdata,
    uint16_t wEncDataLen, uint8_t * pPlainData);
#endif /* PHALMFDFEVX_SAMAV3_NONX_H */
