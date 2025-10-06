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

/** \file
* MIFARE DESFire EVx application's Sam NonX layer's internal component of Reader Library framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHALMFDFEVX_SAM_NONX_INT_H
#define PHALMFDFEVX_SAM_NONX_INT_H

#include <phalMfdfEVx.h>
#include <phhalHw_SamAV3_Cmd.h>

/** MIFARE DESFire EVx contactless IC frame lengths */
#define PHALMFDFEVX_SAM_DATA_FRAME_LENGTH                   224U     /* Maximum data that can be exchanged in case of secure messaging computation by SAM. */

/** MIFARE DESFire EVx ISO 7816-4 wrapped response information */
#define PHALMFDFEVX_RESP_WRAPPED_MSB_BYTE                   0x9100U  /* MSB response information in case of Iso7816 wrapping of Native commands. */

/** MIFARE DESFire EVx Sam Non X command options. This flag will be used to compute the response. */
#define PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE                0U       /**< Command option as None. This flag is used to discard the processing of last command exchange. */
#define PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE            1U       /**< Command option as complete. This flag is used to check the response other than AF. */
#define PHALMFDFEVX_SAM_NONX_CMD_OPTION_PENDING             2U       /**< Command option as complete. This flag is used to check for AF response. */

/** MIFARE DESFire EVx Sam Non X command options. This flag will be used to compute the MAc on command or not. */
#define PHALMFDFEVX_SAM_NONX_NO_MAC_ON_CMD                  0x00U    /**< Mac on command is not available. */
#define PHALMFDFEVX_SAM_NONX_MAC_ON_CMD                     0x01U    /**< Mac on command is available. */
#define PHALMFDFEVX_SAM_NONX_EXCHANGE_DATA_PICC             0x02U    /**< Exchange the data to PICC. */
#define PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS           0x10U    /**< Exchange the status. */
#define PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS         0x20U    /**< Return the chaining status to the user if available. */
#define PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM            0x40U    /**< Exchange the information to / from PICC with Secure messaging in command or response. */
#define PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED            0x80U    /**< The PICC status is wrapped. */

#define PHAL_MFDFEVX_IGNORE_PICC_STATUS_CHECK               0x0080U  /**< This flag specifies the generic internal wrapping interface not to validate the PICC error codes. */
#define PHAL_MFDFEVX_SAM_NONX_SESSION_TMAC_ENC              0x01U    /**< Option to perform generate the TMAC session encryption keys. */
#define PHAL_MFDFEVX_SAM_NONX_SESSION_TMAC_MAC              0x02U    /**< Option to perform generate the TMAC session MAC keys. */
#define PHAL_MFDFEVX_SAM_NONX_SESSION_ENC                   0x01U    /**< Option to perform generate the SDM session encryption keys. */
#define PHAL_MFDFEVX_SAM_NONX_SESSION_MAC                   0x02U    /**< Option to perform generate the SDM session MAC keys. */

#define PHAL_MFDFEVX_RESP_PD_CHAL_SIZE                      16U      /**< MFDFEVX Authenticate First response buffer size. */

/* Resolves the component to be used. */
#define PHAL_MFDFEVX_RESOLVE_DATAPARAMS(DataParams) ((phalMfdfEVx_SamAV3_NonX_DataParams_t *) DataParams)

/* Resolves the Hal component to be used for communicating with Sam hardware in NonX mode. */
#define PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(DataParams)                                                                                             \
            (((*(uint16_t *)(DataParams)) & 0xFF) == PHAL_MFDFEVX_SAMAV3_NONX_ID) ? ((phalMfdfEVx_SamAV3_NonX_DataParams_t *) DataParams)->pHalSamDataParams : \
            NULL


/* APP level keys are invalid between 0x0D to 0x21. */
#define IS_INVALID_APP_KEY(keyNo) ((((keyNo) & 0x7FU) > 0x0DU)    && (((keyNo) & 0x7FU) < 0x21U))

/* VC keys are invalid after 0x23. */
#define IS_INVALID_VC_KEY(keyNo)    (((keyNo) & 0x7FU) > 0x23U)


phStatus_t phalMfdfEVx_Sam_NonX_Int_ValidateResponse(void * pDataParams, uint16_t wStatus, uint16_t wPiccRetCode);

phStatus_t phalMfdfEVx_Sam_NonX_Int_CardExchange(void * pDataParams, uint16_t wBufferOption, uint8_t bCmdOption,
    uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRespLen,
    uint8_t * pPiccErrCode);

phStatus_t phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(void * pDataParams, uint8_t bAuthType, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pPcdCapsIn,
    uint8_t bPcdCapsInLen, uint8_t * pPCDCap2, uint8_t * pPDCap2);

phStatus_t phalMfdfEVx_Sam_NonX_Int_AuthenticatePDC(void * pDataParams, uint8_t bRfu, uint8_t bKeyNoCard, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bUpgradeInfo);

phStatus_t phalMfdfEVx_Sam_NonX_Int_ChangeKeyPICC(void * pDataParams, uint8_t bCmdType, uint16_t wOption, uint8_t bKeySetNo,
    uint8_t bKeyNoCard, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_GenerateSM(void * pDataParams, uint16_t wOption, uint8_t bIsWriteCmd, uint8_t bIsReadCmd,
    uint8_t bCommMode, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppOutBuffer,
    uint16_t * pOutBufLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_VerifySM(void * pDataParams, uint16_t wOption, uint8_t bCommMode, uint32_t dwLength,
    uint8_t * pResponse, uint16_t wRespLen, uint8_t bPiccStat, uint8_t * pRespMac, uint16_t wRespMacLen,
    uint8_t ** ppOutBuffer, uint16_t * pOutBufLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_ReadData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint32_t dwLength, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t ** ppResponse,
    uint16_t * pRespLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_WriteData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint8_t bResetAuth, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t * pData, uint32_t dwDataLen,
    uint8_t ** ppResponse, uint16_t * pRespLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_CreateTMFilePICC(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t bTMKeyOption, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t * pTMKey, uint8_t * pDivInput,
    uint8_t bDivInputLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(void * pDataParams);

phStatus_t phalMfdfEVx_Sam_NonX_Int_GetFrameLen(void * pDataParams, uint16_t * pFrameLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_GetKeyInfo(void * pDataParams, uint8_t bKeyNo, uint16_t * pKeyType, uint16_t * pSET,
    uint16_t * pExtSET);

phStatus_t phalMfdfEVx_Sam_NonX_Int_ComputeTMACSessionVectors(void * pDataParams, uint8_t bOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen);

phStatus_t phalMfdfEVx_Sam_NonX_Int_ComputeSDMSessionVectors(void * pDataParams, uint8_t bOption, uint8_t bSdmOption,
    uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr);

phStatus_t phalMfdfEVx_Sam_NonX_Int_LoadSDMInitVector(void * pDataParams, uint8_t * pSDMReadCtr);

#endif /* PHALMFDFEVX_SAM_NONX_INT_H */
