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

/**
* \file
* MIFARE DESFire EVx contactless IC application SamAV3 NonX component of Reader Library framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <ph_TypeDefs.h>
#include <phhalHw.h>
#include <phpalMifare.h>
#include <string.h>
#include <phCryptoSym.h>
#include <phCryptoRng.h>
#include <phKeyStore.h>
#ifdef NXPBUILD__PHAL_MFDFEVX_SAM_NONX

#include "../phalMfdfEVx_Int.h"
#include "phalMfdfEVx_Sam_NonX.h"
#include "phalMfdfEVx_Sam_NonX_Int.h"
#include <phhalHw_SamAV3_Cmd.h>

phStatus_t phalMfdfEVx_SamAV3_NonX_Init(phalMfdfEVx_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wSizeOfDataParams,
    phhalHw_SamAV3_DataParams_t * pHalSamDataParams, void * pPalMifareDataParams, phTMIUtils_t * pTMIDataParams,
    uint8_t * pTmpBuffer, uint16_t wTmpBufSize)
{
    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_MFDFEVX);
    PH_ASSERT_NULL_PARAM(pHalSamDataParams, PH_COMP_AL_MFDFEVX);
    PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_MFDFEVX);
    PH_ASSERT_NULL_PARAM(pTMIDataParams, PH_COMP_AL_MFDFEVX);
    PH_ASSERT_NULL_PARAM(pTmpBuffer, PH_COMP_AL_MFDFEVX);

    /* Data Params size Check. */
    if (sizeof(phalMfdfEVx_SamAV3_NonX_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFDFEVX);
    }

    /* Temporary Buffer size check. */
    if(wTmpBufSize < 256U )
    {
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_SIZE, PH_COMP_AL_MFDFEVX);
    }

    /* Initialize dataparams structure members. */
    pDataParams->wId                    = PH_COMP_AL_MFDFEVX | PHAL_MFDFEVX_SAMAV3_NONX_ID;
    pDataParams->pHalSamDataParams      = pHalSamDataParams;
    pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
    pDataParams->pTMIDataParams         = pTMIDataParams;
    pDataParams->pTmpBuffer             = pTmpBuffer;
    pDataParams->wTmpBufSize            = wTmpBufSize;
    pDataParams->bKeyNo                 = 0xFFU;
    pDataParams->bAuthMode              = PHAL_MFDFEVX_NOT_AUTHENTICATED;
    pDataParams->bWrappedMode           = PH_OFF;
    pDataParams->wAdditionalInfo        = 0x0000;
    pDataParams->bCmdCode               = PHAL_MFDFEVX_CMD_INVALID;
    pDataParams->bReturn_FabID          = PH_OFF;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx contactless IC secure messaging related commands. ------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_Authenticate(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(
        pDataParams,
        PHAL_MFDFEVX_CMD_AUTHENTICATE,
        wOption,
        wKeyNo,
        wKeyVer,
        bKeyNoCard,
        pDivInput,
        bDivInputLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateISO(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(
        pDataParams,
        PHAL_MFDFEVX_CMD_AUTHENTICATE_ISO,
        wOption,
        wKeyNo,
        wKeyVer,
        bKeyNoCard,
        pDivInput,
        bDivInputLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateAES(void * pDataParams, uint16_t wOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(
        pDataParams,
        PHAL_MFDFEVX_CMD_AUTHENTICATE_AES,
        wOption,
        wKeyNo,
        wKeyVer,
        bKeyNoCard,
        pDivInput,
        bDivInputLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_AuthenticateEv2(void *pDataParams, uint8_t bFirstAuth, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pPcdCapsIn,
    uint8_t bPcdCapsInLen, uint8_t * pPcdCapsOut, uint8_t * pPdCapsOut)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bAuthMode = 0;

    /* Check if First Auth parameter do not contain invalid values. */
    if(bFirstAuth > 1U)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Add First or following Auth to wOption parameter. */
    bAuthMode = (uint8_t) (bFirstAuth ? PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_FIRST : PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_NON_FIRST);

    /* Exchange the commands between Card and SAM hardware to complete Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(
        pDataParams,
        bAuthMode,
        wOption,
        wKeyNo,
        wKeyVer,
        bKeyNoCard,
        pDivInput,
        bDivInputLen,
        pPcdCapsIn,
        bPcdCapsInLen,
        pPcdCapsOut,
        pPdCapsOut));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Memory and Configuration management commands. ------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_FreeMem(void * pDataParams, uint8_t * pMemInfo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_FREE_MEM;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_FREE_MEM;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.FreeMem information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        0,
        pCmdBuff,
        1U,
        &pMemInfo,
        &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_FormatPICC(void * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_FORMAT;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_FORMAT_PICC;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.Format information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        0,
        pCmdBuff,
        1U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_SetConfiguration(void * pDataParams, uint8_t bOption, uint8_t * pData, uint8_t bDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_SET_CONFIG;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_SET_CONFIG;
    pCmdBuff[1U] = bOption;

    /* Exchange Cmd.SetConfiguration information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        2U,
        pData,
        bDataLen,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVerInfo, uint8_t * pVerLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmdBuffLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    (void) memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t));

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_VERSION;

    /* Frame the command information. */
    pCmdBuff[bCmdBuffLen++] = PHAL_MFDFEVX_CMD_GET_VERSION;

    /* Append Return of Option information. */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bReturn_FabID == PH_ON)
    {
        pCmdBuff[bCmdBuffLen++] = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bReturn_FabID;
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetVersion information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        0,
        pCmdBuff,
        bCmdBuffLen,
        &pVerInfo,
        &wRespLen));

    *pVerLen = (uint8_t) wRespLen;
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_SetConfig(pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO, wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetCardUID(void * pDataParams, uint8_t bExchangeOption, uint8_t bOption, uint8_t * pUid,
    uint8_t * pUidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t     PH_MEMLOC_REM bUidLen = 0;
    uint8_t     PH_MEMLOC_REM bUidOffset = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Check if UID length is provided. */
    bUidLen = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo != 4U) &&
                         (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo != 7U) &&
                         (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo != 10U) ? 7U :
                         PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo);

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_CARD_UID;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_CARD_UID;

    if (bExchangeOption)
    {
        pCmdBuff[wCmdLen++] = bOption;

        /* Update UID Length if there is NUID available. */
        bUidLen = (uint8_t) ((bOption == PHAL_MFDFEVX_GET_CARD_UID_OPTION_NUID_RETURNED) ? (bUidLen + 4U) : bUidLen);
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_ENC : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetCardUID information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        bUidLen,
        pCmdBuff,
        wCmdLen,
        &pUid,
        &wRespLen));

    /* Response will be received as
    * 1. 7 byte UID
    * 2. [1 Byte UID Format] + [1 byte UID Length(0x04)] + 4 byte UID
    * 3. [1 Byte UID Format] + [1 byte UID Length(0x0A)] + 10 byte UID
    */
    if (!bExchangeOption)
    {
        if (((wRespLen != PHAL_MFDFEVX_DEFAULT_UID_LENGTH) &&
            (wRespLen != PHAL_MFDFEVX_10B_UID_LENGTH) &&
            (wRespLen != PHAL_MFDFEVX_4B_UID_LENGTH)))
        {
            return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
    }

    if (((wRespLen == PHAL_MFDFEVX_10B_UID_LENGTH) || (wRespLen == PHAL_MFDFEVX_4B_UID_LENGTH)) && !bExchangeOption )
    {
        /* In case of 4B/10B UID, strip out first 2 bytes as it contains UID format and UID length */
        wRespLen -= 2U;

        *pUidLen = (uint8_t) wRespLen;

        /* Validate UIDFormat (0x00) for 4byte and 7Byte UID and UIDLength to be equal to real UID */
        if ((pUid[0] != 0x00) || (pUid[1U] != *pUidLen))
        {
            return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
        }
        memcpy(pUid, &pUid[2U], *pUidLen);
    }
    else
    {
        *pUidLen = (uint8_t) wRespLen;

        /* Compute the UIDOffset. */
        bUidOffset = (uint8_t)(((wRespLen == PHAL_MFDFEVX_DEFAULT_UID_LENGTH) || (wRespLen == (PHAL_MFDFEVX_DEFAULT_UID_LENGTH + 4U))) ? 0 : 2U);
    }

    /* Update the UID information to the dataparams. */
    memcpy(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bUid, &pUid[bUidOffset], *pUidLen - bUidOffset);
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bUidLength = *pUidLen - bUidOffset;

    /* Set the card Length in wAdditionalInfo. This is done to assist C# wrapper as it will not be able
     * to recognize the card UID Length.
     */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_SetConfig(pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO, wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Key management commands. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ChangeKey(void * pDataParams, uint16_t wOption, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer,
    uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to Change Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ChangeKeyPICC(
        pDataParams,
        PHAL_MFDFEVX_CMD_CHANGE_KEY,
        wOption,
        0,
        bKeyNoCard,
        wCurrKeyNo,
        wCurrKeyVer,
        wNewKeyNo,
        wNewKeyVer,
        pDivInput,
        bDivInputLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ChangeKeyEv2(void * pDataParams, uint16_t wOption, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer,
    uint16_t wNewKeyNo, uint16_t wNewKeyVer, uint8_t bKeySetNo, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Exchange the commands between Card and SAM hardware to Change Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ChangeKeyPICC(
        pDataParams,
        PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2,
        wOption,
        bKeySetNo,
        bKeyNoCard,
        wCurrKeyNo,
        wCurrKeyVer,
        wNewKeyNo,
        wNewKeyVer,
        pDivInput,
        bDivInputLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_InitializeKeySet(void * pDataParams, uint8_t bKeySetNo, uint8_t bKeySetType)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;

    /* Validate the parameters. */
    if (((bKeySetNo & 0x7FU) > 0x0FU) || (bKeySetType > PHAL_MFDFEVX_KEY_TYPE_AES128))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_INITIALIZE_KEY_SET;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_INITIALIZE_KEY_SET;
    pCmdBuff[wCmdLen++] = bKeySetNo;
    pCmdBuff[wCmdLen++] = bKeySetType;

    /* Frame the Crypto information. */
    bComMode = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
    if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
       (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
       ( PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
    {
        bComMode = PHAL_MFDFEVX_COMMUNICATION_MACD;
    }

    /* Exchange Cmd.InitializeKeySet information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_FinalizeKeySet(void * pDataParams, uint8_t bKeySetNo, uint8_t bKeySetVer)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;

    /* Validate the parameters. */
    if ((bKeySetNo & 0x7FU) > 0x0FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_FINALIZE_KEY_SET;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_FINALIZE_KEY_SET;
    pCmdBuff[wCmdLen++] = bKeySetNo;
    pCmdBuff[wCmdLen++] = bKeySetVer;

    /* Frame the Crypto information. */
    bComMode = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
    if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
       (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
       ( PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
    {
        bComMode = PHAL_MFDFEVX_COMMUNICATION_MACD;
    }

    /* Exchange Cmd.FinalizeKeySet information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_RollKeySet(void * pDataParams, uint8_t bKeySetNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;

    /* Validate the parameters. */
    if ((bKeySetNo & 0x7FU) > 0x0FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ROLL_KEY_SET;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ROLL_KEY_SET;
    pCmdBuff[wCmdLen++] = bKeySetNo;

    /* Frame the Crypto information. */
    bComMode = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
    if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
       (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
       ( PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
    {
        bComMode = PHAL_MFDFEVX_COMMUNICATION_MACD;
    }

    /* Exchange Cmd.RollKeySet information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_ON,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetKeySettings(void * pDataParams, uint8_t * pKeySettings, uint8_t * pKeySettingLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_KEY_SETTINGS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_KEY_SETTINGS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetKeySettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        0,
        pCmdBuff,
        1U,
        &pKeySettings,
        &wRespLen));

    *pKeySettingLen = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ChangeKeySettings(void * pDataParams, uint8_t bKeySettings)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CHANGE_KEY_SETTINGS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_CHANGE_KEY_SETTINGS;
    pCmdBuff[1U] = bKeySettings;

    /* Exchange Cmd.ChangeKeySettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        &pCmdBuff[0],
        1U,
        &pCmdBuff[1U],
        1U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetKeyVersion(void * pDataParams, uint8_t bKeyNo, uint8_t bKeySetNo, uint8_t * pKeyVersion,
    uint8_t * pKeyVerLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Only if seleted Aid is 0x000000. */
    if ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[0] != 0) &&
        (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[1U] != 0) &&
        (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[2U] != 0) &&
        ((bKeyNo & 0x0FU) > 0x0DU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_KEY_VERSION;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_KEY_VERSION;
    pCmdBuff[wCmdLen++] = bKeyNo;

    /* Add KeySet number if set in KeyNo bit 6. */
    if(bKeyNo & PHAL_MFDFEVX_KEYSETVERSIONS)
    {
        pCmdBuff[wCmdLen++] = bKeySetNo;
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetKeyVersion information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bComMode,
        0,
        pCmdBuff,
        wCmdLen,
        &pKeyVersion,
        &wRespLen));

    *pKeyVerLen = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Application management commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateApplication(void * pDataParams, uint8_t bOption, uint8_t * pAid, uint8_t bKeySettings1,
    uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t * pISOFileId, uint8_t * pISODFName,
    uint8_t bISODFNameLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Check for valid ISO DFName */
    if ((bISODFNameLen > 16U) || (bOption == 0x02U) || (bOption > 0x03U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_APPLN;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pAid, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Buffer Key settings information to command frame. */
    pCmdBuff[wCmdLen++] = bKeySettings1;
    pCmdBuff[wCmdLen++] = bKeySettings2;

    /* Check if KeySettings 3 to be passed */
    if (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)
    {
        pCmdBuff[wCmdLen++] = bKeySettings3;

        /* Buffer key set values if required. */
        if ((bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT) && pKeySetValues != NULL)
        {
            memcpy(&pCmdBuff[wCmdLen], pKeySetValues, 4U); /* PRQA S 3200 */
            wCmdLen += 4U;
        }
    }

    /* Buffer ISO FileID to exchange buffer. */
    if ((bOption & 0x01U ) == 0x01U)
    {
        pCmdBuff[wCmdLen++] = pISOFileId[0];
        pCmdBuff[wCmdLen++] = pISOFileId[1U];
    }

    /* Buffer ISO DFName to exchange buffer. */
    if ((bOption & 0x02U) == 0x02U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISODFName, bISODFNameLen); /* PRQA S 3200 */
        wCmdLen += bISODFNameLen;
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_DeleteApplication(void * pDataParams, uint8_t * pAid, uint8_t * pDAMMAC, uint8_t bDAMMAC_Len)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t     PH_MEMLOC_REM bResetAuth = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_DELETE_APPLN;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_DELETE_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pAid, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Append the DAMMAC */
    if(bDAMMAC_Len)
    {
        memcpy(&pCmdBuff[wCmdLen], pDAMMAC, bDAMMAC_Len); /* PRQA S 3200 */
        wCmdLen += bDAMMAC_Len;
    }

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /*
     * At APP level, the MAC is not returned. The authenticate state should be reset.
     * At PICC level, 8 bytes MAC is returned. The authenticate state should not be reset.
     * So to check whether its in APP level or PICC level. To do this, check for pDataParams->pAid. If its 0x00, then its PICC level
     * else its in APP level.
     */
    bResetAuth = PH_ON;
    if ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[0] == 0) &&
        (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[1U] == 0) &&
        (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid[2U] == 0))
    {
        bResetAuth = PH_OFF;
    }

    /* Exchange Cmd.DeleteApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        bResetAuth,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    /* Copy the AID to the params. */
    memcpy(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, pAid, 3U); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateDelegatedApplication(void  * pDataParams, uint8_t bOption, uint8_t * pAid,
    uint8_t * pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2, uint8_t bKeySettings3, uint8_t * pKeySetValues,
    uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen, uint8_t * pEncK, uint8_t * pDAMMAC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Check for valid ISO DFName */
    if ((bISODFNameLen > 16U) || (bOption == 0x02U) || (bOption > 0x03U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pAid, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Buffer DAM param to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pDamParams, 5U); /* PRQA S 3200 */
    wCmdLen += 5U;

    /* Buffer Key settings information to command frame. */
    pCmdBuff[wCmdLen++] = bKeySettings1;
    pCmdBuff[wCmdLen++] = bKeySettings2;

    /* Check if KeySettings 3 to be passed */
    if (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)
    {
        pCmdBuff[wCmdLen++] = bKeySettings3;

        /* Buffer key set values if required. */
        if ((bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT) && pKeySetValues != NULL)
        {
            memcpy(&pCmdBuff[wCmdLen], pKeySetValues, 4U); /* PRQA S 3200 */
            wCmdLen += 4U;
        }
    }

    /* Buffer ISO FileID to exchange buffer. */
    if ((bOption & 0x01U ) == 0x01U)
    {
        pCmdBuff[wCmdLen++] = pISOFileId[0];
        pCmdBuff[wCmdLen++] = pISOFileId[1U];
    }

    /* Buffer ISO DFName to exchange buffer. */
    if ((bOption & 0x02U) == 0x02U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISODFName, bISODFNameLen); /* PRQA S 3200 */
        wCmdLen += bISODFNameLen;
    }

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateApplication information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_TXCHAINING | PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS),
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL);

    /* Check for Chaining status. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus;
    }

    /* Frame second part of command information. */
    wCmdLen = 0;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;

    memcpy(&pCmdBuff[wCmdLen], pEncK, 32U); /* PRQA S 3200 */
    wCmdLen += 32U;

    memcpy(&pCmdBuff[wCmdLen], pDAMMAC, 8U); /* PRQA S 3200 */
    wCmdLen += 8U;

    /* Exchange DAMMAC information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_DATA_PICC),
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        1U,
        &pCmdBuff[1U],
        (uint16_t) (wCmdLen - 1U),
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_SelectApplication(void * pDataParams, uint8_t bOption, uint8_t * pAppId, uint8_t * pAppId2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Reset the Auth states. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_SELECT_APPLN;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_SELECT_APPLN;

    /* Buffer Application identifier to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pAppId, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Add the secondary application identifier */
    if(bOption)
    {
        memcpy(&pCmdBuff[wCmdLen], pAppId2, 3U); /* PRQA S 3200 */
        wCmdLen += 3U;
    }

    /* Exchange Cmd.SelectApplication information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    /* Copy the AID to the params. */
    memcpy(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, pAppId, 3U); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetApplicationIDs(void * pDataParams, uint8_t bOption, uint8_t ** ppAidBuff,
    uint8_t * pNumAIDs)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameter. */
    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_APPLN_IDS;

    /* Frame the command information. */
    pCmdBuff[0] = (uint8_t) (((bOption & 0x0FU) == PH_EXCHANGE_DEFAULT) ? PHAL_MFDFEVX_CMD_GET_APPLN_IDS : PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME);

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetApplicationIds information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint8_t) (bOption | PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS),
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        1U,
        &pResponse,
        &wRespLen);

    /* Copy the data to the parameter */
    if((wStatus == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        *ppAidBuff = pResponse;
        *pNumAIDs = (uint8_t) (wRespLen / 3U);
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_GetDFNames(void * pDataParams, uint8_t bOption, uint8_t * pDFBuffer, uint8_t * bSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameter. */
    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_DF_NAMES;

    /* Frame the command information. */
    pCmdBuff[0] = (uint8_t) (((bOption & 0x0FU) == PH_EXCHANGE_DEFAULT) ? PHAL_MFDFEVX_CMD_GET_DF_NAMES : PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME);

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetDFNames information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint8_t) (bOption | PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS),
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        1U,
        &pDFBuffer,
        &wRespLen);

    /* Copy the data to the parameter */
    if((wStatus == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
    {
        *bSize = (uint8_t) wRespLen;
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_GetDelegatedInfo(void * pDataParams, uint8_t * pDAMSlot, uint8_t * pDamSlotVer,
    uint8_t * pQuotaLimit, uint8_t * pFreeBlocks, uint8_t * pAid)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_DELEGATED_INFO;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_GET_DELEGATED_INFO;

    /* Buffer DMSlot number to the command frame. */
    memcpy(&pCmdBuff[wCmdLen], pDAMSlot, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetApplicationIds information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        wCmdLen,
        &pResponse,
        &wRespLen));

    /* Copy the data to the parameter */
    memcpy(pDamSlotVer, &pResponse[0], 1U); /* PRQA S 3200 */
    memcpy(pQuotaLimit, &pResponse[1U], 2U); /* PRQA S 3200 */
    memcpy(pFreeBlocks, &pResponse[3U], 2U); /* PRQA S 3200 */
    memcpy(pAid, &pResponse[5U], 3U); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx File management commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateStdDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pISOFileId,
    uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bOption > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_STD_DATAFILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_STD_DATAFILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISOFileId, 2U); /* PRQA S 3200 */
        wCmdLen += 2U;
    }

    /* Append communication settings */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Append FileSize. */
    memcpy(&pCmdBuff[wCmdLen], pFileSize, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateStdDataFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateBackupDataFile(void * pDataParams, uint8_t bOption, uint8_t bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pFileSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bOption > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_BKUP_DATAFILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_BKUP_DATAFILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISOFileId, 2U); /* PRQA S 3200 */
        wCmdLen += 2U;
    }

    /* Append communication settings */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Append FileSize. */
    memcpy(&pCmdBuff[wCmdLen], pFileSize, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateBackupDataFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateValueFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t * pLowerLmit, uint8_t * pUpperLmit, uint8_t * pValue, uint8_t bLimitedCredit)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_VALUE_FILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_VALUE_FILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Append communication settings */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Append lower limit. */
    memcpy(&pCmdBuff[wCmdLen], pLowerLmit, 4U); /* PRQA S 3200 */
    wCmdLen += 4U;

    /* Append upper limit. */
    memcpy(&pCmdBuff[wCmdLen], pUpperLmit, 4U); /* PRQA S 3200 */
    wCmdLen += 4U;

    /* Append value. */
    memcpy(&pCmdBuff[wCmdLen], pValue, 4U); /* PRQA S 3200 */
    wCmdLen += 4U;

    /* Append LimitedCreditEnabled information. */
    pCmdBuff[wCmdLen++] = bLimitedCredit;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateValueFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateLinearRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bOption > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_LINEAR_RECFILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_LINEAR_RECFILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISOFileId, 2U); /* PRQA S 3200 */
        wCmdLen += 2U;
    }

    /* Append communication settings */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Append RecordSize. */
    memcpy(&pCmdBuff[wCmdLen], pRecordSize, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Append maximum number of records. */
    memcpy(&pCmdBuff[wCmdLen], pMaxNoOfRec, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateLinearRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateCyclicRecordFile(void * pDataParams, uint8_t bOption, uint8_t  bFileNo,
    uint8_t * pISOFileId, uint8_t bFileOption, uint8_t * pAccessRights, uint8_t * pRecordSize, uint8_t * pMaxNoOfRec)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bOption > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_CYCLIC_RECFILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_CYCLIC_RECFILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Append ISOFileID is available. */
    if (bOption == 0x01U)
    {
        memcpy(&pCmdBuff[wCmdLen], pISOFileId, 2U); /* PRQA S 3200 */
        wCmdLen += 2U;
    }

    /* Append communication settings */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Append RecordSize. */
    memcpy(&pCmdBuff[wCmdLen], pRecordSize, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Append maximum number of records. */
    memcpy(&pCmdBuff[wCmdLen], pMaxNoOfRec, 3U); /* PRQA S 3200 */
    wCmdLen += 3U;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CreateCyclicRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CreateTransactionMacFile(void * pDataParams, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint16_t wKeyNo, uint8_t bKeyVer, uint8_t bTMKeyOption, uint8_t * pKey, uint8_t * pDivInput,
    uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* VAlidate the parameters */
    if ((bFileNo > 0x1FU) || (bTMKeyOption != PHAL_MFDFEVX_KEY_TYPE_AES128))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Exchange the commands between Card and SAM hardware to create Transaction MAC file. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_CreateTMFilePICC(
        pDataParams,
        (uint8_t) (bDivInputLen ? PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON : PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF),
        bFileNo,
        bFileOption,
        pAccessRights,
        bTMKeyOption,
        (uint8_t)(wKeyNo & 0xFF),
        bKeyVer,
        pKey,
        pDivInput,
        bDivInputLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_DeleteFile(void * pDataParams, uint8_t bFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_DELETE_FILE;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_DELETE_FILE;
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.DeleteFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetFileIDs(void * pDataParams, uint8_t * pFid, uint8_t * pNumFid)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_IDS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_FILE_IDS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetFileIDs information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        1U,
        &pFid,
        &wRespLen));

    *pNumFid = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetISOFileIDs(void * pDataParams, uint8_t * pFidBuffer, uint8_t * pNumFid)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_ISO_FILE_IDS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_ISO_FILE_IDS;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetISOFileIDs information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        1U,
        &pFidBuffer,
        &wRespLen));

    /* Update the length. */
    *pNumFid = (uint8_t) (wRespLen / 2U);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetFileSettings(void * pDataParams, uint8_t bFileNo, uint8_t * pFSBuffer,
    uint8_t * bBufferLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_SETTINGS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_FILE_SETTINGS;
    pCmdBuff[1U] = bFileNo;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetFileSettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        0,
        pCmdBuff,
        2U,
        &pFSBuffer,
        &wRespLen));

    /* Update the length. */
    *bBufferLen = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetFileCounters(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t * pResponse,
    uint8_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameters */
    if ((bOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_ENC))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

        /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_FILE_COUNTERS;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_FILE_COUNTERS;
    pCmdBuff[1U] = bFileNo;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((bOption == PHAL_MFDFEVX_COMMUNICATION_ENC) ? PHAL_MFDFEVX_COMMUNICATION_MACD :
        PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.GetFileCounters information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        bOption,
        0,
        pCmdBuff,
        2U,
        &pResponse,
        &wRespLen));

    /* Update the length. */
    *pRespLen = (uint8_t) wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ChangeFileSettings(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t bAddInfoLen, uint8_t * pAddInfo)
{
     phStatus_t PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t     PH_MEMLOC_REM bAddARsLen = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_PLAIN >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_ENC >> 4U)) &&
        ((bFileOption & 0x03U) != (PHAL_MFDFEVX_COMMUNICATION_MACD >> 4U)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CHANGE_FILE_SETTINGS;

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CHANGE_FILE_SETTINGS;
    pCmdBuff[wCmdLen++] = bFileNo;
    pCmdBuff[wCmdLen++] = bFileOption;
    pCmdBuff[wCmdLen++] = pAccessRights[0];
    pCmdBuff[wCmdLen++] = pAccessRights[1U];

    if (bOption & PHAL_MFDFEVX_EXCHANGE_ADD_INFO_BUFFER_COMPLETE)
    {
        /* SDM buffer in command buffer if Bit6 of File Option is SET.  */
        memcpy(&pCmdBuff[wCmdLen], pAddInfo, bAddInfoLen);
        wCmdLen += bAddInfoLen;
    }
    else
    {
        if (bFileOption & PHAL_MFDFEVX_FILE_OPTION_ADDITIONAL_AR_PRESENT)
        {
            /* Compute the Additional ACCESS Rights length. */
            if(bFileOption & PHAL_MFDFEVX_FILE_OPTION_TMCLIMIT_PRESENT)
            {
                if(bAddInfoLen > 4U)
                {
                   bAddARsLen = bAddInfoLen - 4U;
                }
                else
                {
                    bAddARsLen = 0;
                }
            }
            else
            {
               bAddARsLen =  bAddInfoLen;
            }

            pCmdBuff[wCmdLen++] = bAddARsLen;
            memcpy(&pCmdBuff[wCmdLen], pAddInfo, (((uint8_t)bAddARsLen * 2U) & 0xFF)); /* PRQA S 3200 */
            wCmdLen = ((wCmdLen + ((bAddARsLen * 2U) & 0xFF)) & 0xFFFF);
        }

        /* TMCLimit buffer in command buffer if Bit5 of File Option is SET. */
        if (bFileOption & PHAL_MFDFEVX_FILE_OPTION_TMCLIMIT_PRESENT)
        {
            memcpy(&pCmdBuff[wCmdLen], &pAddInfo[bAddARsLen], 4U); /* PRQA S 3200 */
            wCmdLen = ((wCmdLen + 4U) & 0xFFFF);
        }
    }

    /* Frame the Crypto information. */
    bComMode = (uint8_t) (((bOption & 0x30U) == PHAL_MFDFEVX_COMMUNICATION_ENC) ?
        PHAL_MFDFEVX_COMMUNICATION_ENC : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.ChangeFileSettings information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        (uint8_t) ((bComMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD),
        PH_OFF,
        pCmdBuff,
        (uint16_t) ((bComMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ? wCmdLen : 2U),
        &pCmdBuff[2U],
        (uint16_t) ((bComMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ? 0 : (wCmdLen - 2U)),
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Data management commands. --------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ReadData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo, uint8_t * pOffset,
    uint8_t * pLength, uint8_t ** ppResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t    PH_MEMLOC_REM wOption = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;

    uint8_t     PH_MEMLOC_REM bTMIOption = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameter. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bIns > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        ((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        ((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_READ_DATA_ISO :
        PHAL_MFDFEVX_CMD_READ_DATA);

    /* Compute the length. */
    dwLength = pLength[2U];
    dwLength = dwLength << 8U | pLength[1U];
    dwLength = dwLength << 8U | pLength[0];

    /* Frame the command information based on the option. */
    if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING)
    {
        /* Frame additional frame code. */
        pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
    }
    else
    {
        /* Frame the command information. */
        pCmdBuff[wCmdLen++] = (uint8_t) ((bIns) ? PHAL_MFDFEVX_CMD_READ_DATA_ISO : PHAL_MFDFEVX_CMD_READ_DATA);
        pCmdBuff[wCmdLen++] = bFileNo;

        memcpy(&pCmdBuff[wCmdLen], pOffset, 3U); /* PRQA S 3200 */
        wCmdLen += 3U;

        memcpy(&pCmdBuff[wCmdLen], pLength, 3U); /* PRQA S 3200 */
        wCmdLen += 3U;

        /* Get the TMI Status. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
            &dwTMIStatus));

        /* Check TMI Collection Status */
        if (dwTMIStatus)
        {
            /* Frame the Option. */
            bTMIOption = (uint8_t)(dwLength ? PH_TMIUTILS_ZEROPAD_CMDBUFF : (PH_TMIUTILS_READ_INS | PH_TMIUTILS_ZEROPAD_CMDBUFF));

            /* Buffer the Command information to TMI buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                bTMIOption, pCmdBuff, wCmdLen, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
        }
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t) (bOption & 0xF0U);
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) ||
        (bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_MACD)) ? PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = (uint8_t) (bOption & 0xF0U);

    /* Frame Option parameter. */
    wOption = (uint16_t) (bOption & 0x0FU) ;

    /* Exchange Cmd.ReadData information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint8_t) (wOption | (bIns ? 0 : PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS)),
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        dwLength,
        pCmdBuff,
        wCmdLen,
        ppResponse,
        pRespLen);

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Frame the Option. */
        bTMIOption = (uint8_t) (dwLength ? 0 : PH_TMIUTILS_READ_INS);
        bTMIOption = (uint8_t) ((wStatus == PH_ERR_SUCCESS) ? (bTMIOption | PH_TMIUTILS_ZEROPAD_DATABUFF) : bTMIOption);

        /* Collect the data received. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            bTMIOption, NULL, 0, *ppResponse, *pRespLen, PHAL_MFDFEVX_BLOCK_SIZE));

        /* Reset the TMI buffer Offset. */
        if (!dwLength && (wStatus == PH_ERR_SUCCESS))
        {
            /* Reset wOffsetInTMI */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_SetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                PH_TMIUTILS_TMI_OFFSET_LENGTH, 0));
        }
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_WriteData(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint32_t    PH_MEMLOC_REM dwDataLen = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bIns > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
    if ((bOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_WRITE_DATA_ISO :
        PHAL_MFDFEVX_CMD_WRITE_DATA);

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_WRITE_DATA_ISO : PHAL_MFDFEVX_CMD_WRITE_DATA);
    pCmdBuff[wCmdLen++] = bFileNo;

    memcpy(&pCmdBuff[wCmdLen], pOffset, 3U);
    wCmdLen += 3U;

    memcpy(&pCmdBuff[wCmdLen], pDataLen, 3U);
    wCmdLen += 3U;

    /* Set the lengths. */
    dwDataLen = ((uint32_t)pDataLen[0] | ((uint32_t)pDataLen[1U] << 8U) | ((uint32_t)pDataLen[2U] << 16U));

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF), pCmdBuff, wCmdLen, pData, dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t) (bOption & 0xF0U);

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.WriteData information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pData,
        dwDataLen,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GetValue(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bCommOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_GET_VALUE;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_GET_VALUE;
    pCmdBuff[1U] = bFileNo;

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING, pCmdBuff, 2U, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) ||
        (bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_MACD)) ? PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = bCommOption;

    /* Exchange Cmd.GetValue information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        4U,
        pCmdBuff,
        2U,
        &pValue,
        &wRespLen));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_DATABUFF, NULL, 0, pValue, wRespLen, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Credit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREDIT;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_CREDIT;
    pCmdBuff[1U] = bFileNo;

   /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_DATABUFF, pCmdBuff, 2U, pValue, 4U, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.Credit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        2U,
        pValue,
        4U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Debit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_DEBIT;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_DEBIT;
    pCmdBuff[1U] = bFileNo;

   /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_DATABUFF, pCmdBuff, 2U, pValue, 4U, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.Debit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        2U,
        pValue,
        4U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_LimitedCredit(void * pDataParams, uint8_t bCommOption, uint8_t bFileNo, uint8_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if ((bFileNo & 0x3FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        ((bCommOption & 0x3FU) != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_LIMITED_CREDIT;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_LIMITED_CREDIT;
    pCmdBuff[1U] = bFileNo;

   /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_DATABUFF, pCmdBuff, 2U, pValue, 4U, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = bCommOption;

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        (bCommOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.LimitedCredit information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        2U,
        pValue,
        4U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ReadRecords(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pRecCount, uint8_t * pRecSize, uint8_t ** ppResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint16_t    PH_MEMLOC_REM wOption = 0;
    uint32_t    PH_MEMLOC_REM dwLength = 0;
    uint32_t    PH_MEMLOC_REM dwNumRec = 0;
    uint32_t    PH_MEMLOC_REM dwRecLen = 0;

    uint8_t     PH_MEMLOC_REM bTMIOption = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameter. */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bIns > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        ((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        ((bOption & 0xF0U) != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((bOption & 0x0FU) != PH_EXCHANGE_DEFAULT) && ((bOption & 0x0FU) != PH_EXCHANGE_RXCHAINING))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_READ_RECORDS_ISO :
        PHAL_MFDFEVX_CMD_READ_RECORDS);

    /* Frame the command information based on the option. */
    if ((bOption & 0x0FU) == PH_EXCHANGE_RXCHAINING)
    {
        /* Frame additional frame code. */
        pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
    }
    else
    {
        /* Compute the length. */
        dwLength = pRecSize[2U];
        dwLength = dwLength << 8U | pRecSize[1U];
        dwLength = dwLength << 8U | pRecSize[0];

        /* Frame the command information. */
        pCmdBuff[wCmdLen++] = (uint8_t) ((bIns) ? PHAL_MFDFEVX_CMD_READ_RECORDS_ISO : PHAL_MFDFEVX_CMD_READ_RECORDS);
        pCmdBuff[wCmdLen++] = bFileNo;

        memcpy(&pCmdBuff[wCmdLen], pRecNo, 3U); /* PRQA S 3200 */
        wCmdLen += 3U;

        memcpy(&pCmdBuff[wCmdLen], pRecCount, 3U); /* PRQA S 3200 */
        wCmdLen += 3U;

        /* Get the TMI Status. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
            &dwTMIStatus));

        /* Check TMI Collection Status */
        if (dwTMIStatus)
        {
            /* Compute the number of records. */
            dwNumRec = pRecCount[2U];
            dwNumRec = dwNumRec << 8U | pRecCount[1U];
            dwNumRec = dwNumRec << 8U | pRecCount[0];

            /* Compute the record length. */
            dwRecLen = pRecSize[2U];
            dwRecLen = dwRecLen << 8U | pRecSize[1U];
            dwRecLen = dwRecLen << 8U | pRecSize[0];

            /* Should should provide atleast wRecLen / wNumRec to update in TIM collection */
            if(!dwRecLen && !dwNumRec)
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
            }

            /* Buffer the Command information to TMI buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                (PH_TMIUTILS_READ_INS | PH_TMIUTILS_ZEROPAD_CMDBUFF), pCmdBuff, wCmdLen, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
        }
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t) (bOption & 0xF0U);
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) ||
        (bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_MACD)) ? PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);
    bCmd_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bCmd_ComMode);

    /* Frame the SM to be applied for response. */
    bResp_ComMode = (uint8_t) (bOption & 0xF0U);

    /* Frame Option parameter. */
    wOption = (uint16_t) (bOption & 0x0FU) ;

    /* Exchange Cmd.ReadRecords information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint8_t) (wOption | (bIns ? 0 : PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS)),
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        dwLength,
        pCmdBuff,
        wCmdLen,
        ppResponse,
        pRespLen);

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Frame the Option. */
        bTMIOption = (uint8_t) ((wStatus == PH_ERR_SUCCESS) ? PH_TMIUTILS_ZEROPAD_DATABUFF : PH_TMIUTILS_NO_PADDING);

        /* Collect the data received. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            bTMIOption, NULL, 0, *ppResponse, *pRespLen, PHAL_MFDFEVX_BLOCK_SIZE));

        /* Reset the TMI buffer Offset. */
        if (!dwLength && (wStatus == PH_ERR_SUCCESS))
        {
            /* Reset wOffsetInTMI */
            PH_CHECK_SUCCESS_FCT(wStatus1, phTMIUtils_SetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                PH_TMIUTILS_TMI_OFFSET_LENGTH, 0));
        }
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_WriteRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint32_t    PH_MEMLOC_REM dwDataLen = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bIns > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
    if ((bOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO :
        PHAL_MFDFEVX_CMD_WRITE_RECORD);

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO : PHAL_MFDFEVX_CMD_WRITE_RECORD);
    pCmdBuff[wCmdLen++] = bFileNo;

    memcpy(&pCmdBuff[wCmdLen], pOffset, 3U);
    wCmdLen += 3U;

    memcpy(&pCmdBuff[wCmdLen], pDataLen, 3U);
    wCmdLen += 3U;

    /* Set the lengths. */
    dwDataLen = ((uint32_t)pDataLen[0] | ((uint32_t)pDataLen[1U] << 8U) | ((uint32_t)pDataLen[2U] << 16U));

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF), pCmdBuff, wCmdLen, pData, dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t) (bOption & 0xF0U);

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.WriteRecord information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pData,
        dwDataLen,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_UpdateRecord(void * pDataParams, uint8_t bOption, uint8_t bIns, uint8_t bFileNo,
    uint8_t * pRecNo, uint8_t * pOffset, uint8_t * pData, uint8_t * pDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint32_t    PH_MEMLOC_REM dwDataLen = 0;
    uint8_t     PH_MEMLOC_REM bCmd_ComMode = 0;
    uint8_t     PH_MEMLOC_REM bResp_ComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters */
    if (((bFileNo & 0x7FU) > 0x1FU) || (bIns > 0x01U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }
    if ((bOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_ENC) &&
        (bOption != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO :
        PHAL_MFDFEVX_CMD_UPDATE_RECORD);

    /* Frame the command information. */
    pCmdBuff[wCmdLen++] = (uint8_t) (bIns ? PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO : PHAL_MFDFEVX_CMD_UPDATE_RECORD);
    pCmdBuff[wCmdLen++] = bFileNo;

    memcpy(&pCmdBuff[wCmdLen], pRecNo, 3U);
    wCmdLen += 3U;

    memcpy(&pCmdBuff[wCmdLen], pOffset, 3U);
    wCmdLen += 3U;

    memcpy(&pCmdBuff[wCmdLen], pDataLen, 3U);
    wCmdLen += 3U;

    /* Set the lengths. */
    dwDataLen = (((uint8_t)pDataLen[0]) | ((uint8_t)pDataLen[1U] << 8U) | ((uint8_t)pDataLen[2U] << 16U));

    /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            (PH_TMIUTILS_ZEROPAD_CMDBUFF | PH_TMIUTILS_ZEROPAD_DATABUFF), pCmdBuff, wCmdLen, pData, dwDataLen,
            PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the SM to be applied for command. */
    bCmd_ComMode = (uint8_t) (bOption & 0xF0U);

    /* Frame the SM to be applied for command. */
    bResp_ComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ?
        PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD);
    bResp_ComMode = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
        ((bOption & 0xF0U) == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : bResp_ComMode);

    /* Exchange Cmd.UpdateRecord information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmd_ComMode,
        bResp_ComMode,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pData,
        dwDataLen,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ClearRecordFile(void * pDataParams, uint8_t bFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Validate the parameters. */
    if ((bFileNo & 0x7FU) > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CLEAR_RECORD_FILE;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_CLEAR_RECORDS_FILE;
    pCmdBuff[1U] = bFileNo;

   /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF, pCmdBuff, 2U, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.ClearRecordFile information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        2U,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}




/* MIFARE DESFire EVx Transaction management commands. -------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CommitTransaction(void * pDataParams, uint8_t bOption, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameters. */
    if (bOption > 0x01U)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    bCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_COMMIT_TXN;

    /* Frame the command information. */
    pCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_COMMIT_TXN;

    if(bOption)
    {
        pCmdBuff[bCmdLen++] = bOption;
    }

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.CommitTransaction information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        bCmdLen,
        NULL,
        0,
        &pResponse,
        &wRespLen));

    /* Copy the data to the parameter */
    if(bOption)
    {
        memcpy(pTMC, &pResponse[0], 4U); /* PRQA S 3200 */
        memcpy(pTMV, &pResponse[4U], 8U); /* PRQA S 3200 */
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_AbortTransaction(void * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ABORT_TXN;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_ABORT_TXN;

    /* Frame the Crypto information. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_MACD : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.AbortTransaction information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        1U,
        NULL,
        0,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CommitReaderID(void * pDataParams, uint8_t * pTMRI, uint8_t * pEncTMRI)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Sam = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Sam = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Exchange the details to SAM hardware and get the TMRI and MAC. */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED)
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part1(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_DESFIRE,
            0,
            &pResp_Sam,
            &wRespLen_Sam);

        /* Verify if Success chaining response is received from SAM. */
        if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
            return wStatus;
    }
    else
    {
        pResp_Sam = pTMRI;
        wRespLen_Sam = 16U;
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_COMMIT_READER_ID;

    /* Frame the command and send it to card. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_COMMIT_READER_ID;

    /* Add the TMRI to command buffer. */
    memcpy(&pCmdBuff[wCmdLen], pResp_Sam, wRespLen_Sam );   /* PRQA S 3200 */
    wCmdLen += wRespLen_Sam;

    /* Buffer command information. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE,
        wCmdLen,
        PH_ON,
        pCmdBuff,
        wCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    /*Exchange the response received from card to SAM hardware */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED)
    {
        if(wRespLen_Card > 0U)
        {
            wStatus = phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part2(
                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                bPiccErrCode,
                pResp_Card,
                (uint8_t) wRespLen_Card,
                &bPiccRetCode);

            /* validate the error code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, bPiccErrCode));
        }

        /*
         * Kill PICC Authentication for next SAM call to proceed further
         * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
         * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
         */
        else
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_PARTIAL));
        }
    }

    /* Update the ppEncTMRI parameter. */
    wRespLen_Card = (uint16_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED) ?
        16U : wRespLen_Card);
    memcpy(pEncTMRI, pResp_Card, wRespLen_Card );   /* PRQA S 3200 */

    /* Do a Set Config of ADDITIONAL_INFO to set  the length(wLength) of the received TMRI */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_SetConfig(pDataParams, PHAL_MFDFEVX_ADDITIONAL_INFO, wRespLen_Card));

   /* Get the TMI Status. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* Buffer the Command and Data information to TMI buffer. */
        if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED)
        {
            /* If authenticated, Cmd.CommitReaderID shall update the Transaction MAC Input TMI as follows:
             * TMI = TMI || Cmd || TMRICur || EncTMRI || ZeroPadding
             */
            PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                PH_TMIUTILS_ZEROPAD_DATABUFF, pCmdBuff, 17U, pEncTMRI, 16U, PHAL_MFDFEVX_BLOCK_SIZE));
        }
        else
        {
            /* If not authenticated, Cmd.CommitReaderID shall update the Transaction MAC Input TMI as follows:
             * TMI = TMI || Cmd || TMRICur || ZeroPadding
             */
            PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
                PH_TMIUTILS_ZEROPAD_CMDBUFF, pCmdBuff, 17U, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));

            pEncTMRI = '\0';
        }
    }

    return wStatus;
}

/* MIFARE DESFire EVx ISO7816-4 commands. ---------------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_IsoSelectFile(void * pDataParams, uint8_t bOption, uint8_t bSelector, uint8_t * pFid,
    uint8_t * pDFname, uint8_t bDFnameLen, uint8_t bExtendedLenApdu, uint8_t ** ppFCI, uint16_t * pFCILen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM aFileId[3U] = {'\0'};
    uint16_t    PH_MEMLOC_REM wVal = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;
    uint8_t     PH_MEMLOC_REM aPiccDfName[7U] = {0xD2U, 0x76U, 0x00, 0x00, 0x85U, 0x01U, 0x00};

    /* Validate the parameters. */
    if( (bDFnameLen > 16U) || ((bOption != 0x00) && (bOption != 0x0CU)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if(bSelector > 0x04U)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_SELECT_FILE;

    /* Frame the command. */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_SELECT_FILE;
    pCmdBuff[wCmdLen++] = bSelector;
    pCmdBuff[wCmdLen++] = bOption;

    /* Append LC. */
    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = 0;
        pCmdBuff[wCmdLen++] = 0;
    }

    /* Append the payload and LC. */
    if(bSelector == 0x04U)
    {
        /* Append LC. */
        pCmdBuff[wCmdLen++] = bDFnameLen;

        memcpy(&pCmdBuff[wCmdLen], pDFname, bDFnameLen); /* PRQA S 3200 */
        wCmdLen += bDFnameLen;
    }
    else
    {
        /* Append LC. */
        pCmdBuff[wCmdLen++] = 2U;

        /* Select MF, DF or EF, by file identifier
         * Select child DF
         * Select EF under the current DF, by file identifier
         * Select parent DF of the current DF
         */
        aFileId[1U] = pCmdBuff[wCmdLen++] = pFid[1U];
        aFileId[0] = pCmdBuff[wCmdLen++] = pFid[0];
        aFileId[2U] = 0;
    }

    /* Append LE. */
    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = 0;
    }
    pCmdBuff[wCmdLen++] = 0;

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOSelectFile information to PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_OFF,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0U,
        NULL,
        NULL);

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    if((wStatus & PH_ERR_MASK) == PHAL_MFDFEVX_ERR_DF_7816_GEN_ERROR)
    {
        wVal = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo;
    }

    if((wStatus == PH_ERR_SUCCESS) || (wVal == PHAL_MFDFEVX_ISO7816_ERR_LIMITED_FUNCTIONALITY_INS))
    {
        /* Reset Authentication should not be targeted for elementary file selection using file ID */
        if(bSelector !=  0x02U)
        {
            /* Reset Authentication Status here */
            phalMfdfEVx_Sam_NonX_ResetAuthStatus(pDataParams);
        }

        /* ISO wrapped mode is on */
        PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_ON;

        /* once the selection Success, update the File Id to master data structure if the selection is done through AID */
        if((bSelector ==  0x00) || (bSelector == 0x01U) || (bSelector == 0x02U))
        {
            memcpy(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aFileId, sizeof(aFileId));   /* PRQA S 3200 */
        }
        else if((bSelector ==  0x04U))
        {
            /* Update the file ID to all zeros if DF Name is of PICC. */
            if(memcmp( pDFname, aPiccDfName, 7U) == 0)
            {
                aFileId[0] = 0x00;
                aFileId[1U] = 0x00;
                aFileId[2U] = 0x00;
            }
            else
            {
                aFileId[0] = 0xFFU;
                aFileId[1U] = 0xFFU;
                aFileId[2U] = 0xFFU;
            }

            memcpy(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aFileId, sizeof(aFileId));   /* PRQA S 3200 */
        }
        else
        {
            /* Nothing for Secector 0x03. */
        }
    }
    else
    {
        return wStatus;
    }

    /* Copy the response to the buffer */
    *ppFCI = pResponse;
    *pFCILen = wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoReadBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint32_t dwBytesToRead,
    uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint32_t * pBytesRead)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;

    /* Validate the parameter. */
    if (bSfid & 0x80U)
    {
        /* Short file id is supplied */
        if ((bSfid & 0x7FU) > 0x1FU)
        {
            /* Error condition */
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
        }
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_READ_BINARY;

    /* Frame the command information based on the option. */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_READ_BINARY;
    pCmdBuff[wCmdLen++] = bSfid;
    pCmdBuff[wCmdLen++] = bOffset;

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwBytesToRead & 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwBytesToRead & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) (dwBytesToRead & 0x000000FFU);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOReadBinary information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        0,
        pCmdBuff,
        wCmdLen,
        ppResponse,
        &wRespLen);

    *pBytesRead = wRespLen;

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoUpdateBinary(void * pDataParams, uint8_t bOffset, uint8_t bSfid, uint8_t bExtendedLenApdu,
    uint8_t * pData, uint32_t dwDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;

    /* Validate the parameters */
    if (bSfid & 0x80U)
    {
        /* Short file id is supplied */
        if ((bSfid & 0x7FU) > 0x1FU)
        {
            /* Error condition */
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
        }
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Frame the command. */
    pCmdBuff[wCmdLen++] = 0x00;                                     /* CLA */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_UPDATE_BINARY;   /* INS */
    pCmdBuff[wCmdLen++] = bSfid;                                    /* P1 */
    pCmdBuff[wCmdLen++] = bOffset;

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwDataLen & 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwDataLen & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) (dwDataLen & 0x000000FFU);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOUpdateBinary information to PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pData,
        dwDataLen,
        NULL,
        NULL);

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoReadRecords(void * pDataParams, uint8_t bRecNo, uint8_t bReadAllFromP1, uint8_t bSfid,
    uint32_t dwBytesToRead, uint8_t bExtendedLenApdu, uint8_t ** ppResponse, uint32_t * pBytesRead)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameter. */
    if (bSfid > 0x1FU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_READ_RECORDS;

    /* Frame the command information based on the option. */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_READ_RECORDS;
    pCmdBuff[wCmdLen++] = bRecNo;
    pCmdBuff[wCmdLen++] = (uint8_t) ((bSfid <<= 3) | (bReadAllFromP1 ? 0x05U : 0x04U));

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwBytesToRead & 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwBytesToRead & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) (dwBytesToRead & 0x000000FFU);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOReadRecord information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        0,
        pCmdBuff,
        wCmdLen,
        ppResponse,
        &wRespLen);

    *pBytesRead = wRespLen;

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoAppendRecord(void * pDataParams, uint8_t bSfid, uint8_t bExtendedLenApdu, uint8_t * pData,
    uint32_t dwDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;

    /* Short file id is supplied */
    if ((bSfid & 0x7FU) > 0x1FU)
    {
        /* Error condition */
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_APPEND_RECORD;

    /* Frame the command. */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_APPEND_RECORD;
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = (uint8_t) (bSfid << 3U);

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwDataLen & 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwDataLen & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) (dwDataLen & 0x000000FF);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOAppendRecord information to PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pData,
        dwDataLen,
        NULL,
        NULL);

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoGetChallenge(void * pDataParams, uint8_t bExtendedLenApdu, uint32_t dwLe,
    uint8_t * pRPICC1)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_GET_CHALLENGE;

    /* Frame the command information based on the option. */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_GET_CHALLENGE;
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = 0x00;

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwLe & 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) ((dwLe & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) (dwLe & 0x000000FFU);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOGetChallange information to Sam and PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        0,
        pCmdBuff,
        wCmdLen,
        &pRPICC1,
        &wRespLen);

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoExternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen,
    uint8_t bExtendedLenApdu, uint8_t * pDataOut, uint8_t * pOutLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bInOffset = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;
    uint8_t     PH_MEMLOC_REM bIsDFkey = 0;
    uint8_t     PH_MEMLOC_REM bKeyNoCard = 0;
    uint8_t     PH_MEMLOC_REM bRndLen = 0;
    uint16_t    PH_MEMLOC_REM wKeyNo = 0;
    uint16_t    PH_MEMLOC_REM wKeyVer = 0;
    uint8_t     PH_MEMLOC_REM aRPICC1[16U];
    uint8_t     PH_MEMLOC_REM aRPCD2[16U];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM bWrappedMode = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Validate the parameters. */
    if ((bInputLen != 16U) && (bInputLen != 24U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Extract the information from Input buffer. */
    bAlgo       = pDataIn[bInOffset++];
    bIsDFkey    = pDataIn[bInOffset++];
    bKeyNoCard  = pDataIn[bInOffset++];
    bRndLen     = pDataIn[bInOffset++];

    if (bKeyNoCard > 0x0DU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if ((bAlgo != 0x00) && (bAlgo != 0x02U) && (bAlgo != 0x04U) && (bAlgo != 0x09U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    memcpy(aRPICC1, &pDataIn[bInOffset], bRndLen); /* PRQA S 3200 */
    bInOffset = ((bInOffset + bRndLen) & 0xFF);

    memcpy(&wKeyNo, &pDataIn[bInOffset], 2U); /* PRQA S 3200 */
    bInOffset = ((bInOffset + 2U) & 0xFF);

    memcpy(&wKeyVer, &pDataIn[bInOffset], 2U); /* PRQA S 3200 */
    bInOffset = ((bInOffset + 2U) & 0xFF);

/* Exchange the input information to SAM ------------------------------------------------------------------------------------- */
    wStatus1 = phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part1(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF,
        (uint8_t)(wKeyNo & 0xFF),
        (uint8_t)(wKeyVer & 0xFF),
        NULL,
        0x00,
        aRPICC1,
        bRndLen,
        &pResponse,
        &wRespLen);

    if ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
        return wStatus1;
    }

    /* Copy RPDC2 received from Sam. */
    memcpy(aRPCD2, &pResponse[wRespLen - bRndLen], bRndLen); /* PRQA S 3200 */

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_EXT_AUTHENTICATE;

/* Exchange the information to PICC ------------------------------------------------------------------------------------------ */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_EXT_AUTHENTICATE;
    pCmdBuff[wCmdLen++] = bAlgo;
    pCmdBuff[wCmdLen++] = (uint8_t) ((bIsDFkey << 7U) | bKeyNoCard);

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = (uint8_t) (((wRespLen - bRndLen)& 0x00FF0000U) >> 16U);
        pCmdBuff[wCmdLen++] = (uint8_t) (((wRespLen - bRndLen) & 0x0000FF00U) >> 8U);
    }
    pCmdBuff[wCmdLen++] = (uint8_t) ((wRespLen - bRndLen) & 0x000000FFU);

    /* Backup the existing information. */
    bWrappedMode = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOExternalAuthenticate information to PICC. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        pResponse,
        (wRespLen - bRndLen),
        &pResponse,
        &wRespLen);

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = bWrappedMode;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    /* Copy RPCD2 to output buffer. */
    if(wStatus == PH_ERR_SUCCESS)
    {
        memcpy(pDataOut, aRPCD2, bRndLen); /* PRQA S 3200 */
        *pOutLen = bRndLen;
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoInternalAuthenticate(void * pDataParams, uint8_t * pDataIn, uint8_t bInputLen,
    uint8_t bExtendedLenApdu)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM bInOffset = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;
    uint8_t     PH_MEMLOC_REM bIsDFkey = 0;
    uint8_t     PH_MEMLOC_REM bKeyNoCard = 0;
    uint8_t     PH_MEMLOC_REM bRndLen = 0;
    uint16_t    PH_MEMLOC_REM wKeyNo = 0;
    uint16_t    PH_MEMLOC_REM wKeyVer = 0;
    uint8_t     PH_MEMLOC_REM aData[16U];
    uint8_t     PH_MEMLOC_REM bDataLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint16_t    PH_MEMLOC_REM wHostMode = 0;
    uint8_t     PH_MEMLOC_REM bKeyType = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Validate the parameters. */
    if ((bInputLen != 16U) && (bInputLen != 24U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Extract the information from Input buffer. */
    bAlgo       = pDataIn[bInOffset++];
    bIsDFkey    = pDataIn[bInOffset++];
    bKeyNoCard  = pDataIn[bInOffset++];
    bRndLen     = pDataIn[bInOffset++];

    if (bKeyNoCard > 0x0DU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if ((bAlgo != 0x00) && (bAlgo != 0x02U) && (bAlgo != 0x04U) && (bAlgo != 0x09U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    memcpy(aData, &pDataIn[bInOffset], bRndLen); /* PRQA S 3200 */
    bInOffset = ((bInOffset + bRndLen) & 0xFF);

    memcpy(&wKeyNo, &pDataIn[bInOffset], 2U); /* PRQA S 3200 */
    bInOffset = ((bInOffset + 2U) & 0xFF);

    memcpy(&wKeyVer, &pDataIn[bInOffset], 2U); /* PRQA S 3200 */
    bInOffset = ((bInOffset + 2U) & 0xFF);

    /* Clear the command buffer and length. */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_ISO7816_INT_AUTHENTICATE;

/* Exchange the information to PICC ------------------------------------------------------------------------------------------ */
    pCmdBuff[wCmdLen++] = 0x00;
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_ISO7816_INT_AUTHENTICATE;
    pCmdBuff[wCmdLen++] = bAlgo;
    pCmdBuff[wCmdLen++] = (((bIsDFkey << 7U) | bKeyNoCard) & 0xFF);

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = 0x00;
        pCmdBuff[wCmdLen++] = 0x00;
    }
    pCmdBuff[wCmdLen++] = bRndLen;

    memcpy(&pCmdBuff[wCmdLen], aData, bRndLen); /* PRQA S 3200 */
    wCmdLen += bRndLen;

    if(bExtendedLenApdu)
    {
        pCmdBuff[wCmdLen++] = 0;
    }
    pCmdBuff[wCmdLen++] = 0;

    /* Disable the wrapping because internally it should be exchanged in non wrapped mode. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_OFF;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = PH_OFF;

    /* Exchange Cmd.ISOExternalAuthenticate information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM | PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED),
        PH_ON,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PHAL_MFDFEVX_COMMUNICATION_PLAIN,
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        NULL,
        0,
        &pResponse,
        &wRespLen));

    /* Restore the backedup information. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_ON;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = bExtendedLenApdu;

    /* Reset the Authentication. */
    if(wStatus != PH_ERR_SUCCESS)
    {
        PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
        return wStatus;
    }

/* Exchange the information to SAM ------------------------------------------------------------------------------------------- */
    wStatus = phhalHw_SamAV3_Cmd_SAM_IsoAuthenticatePICC_Part2(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        pResponse,
        (uint8_t) wRespLen);

    /* Return error. */
    if(wStatus != PH_ERR_SUCCESS)
    {
        if((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_CRYPTO)
        {
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFDFEVX);
        }
        else
        {
            return wStatus;
        }
    }

    /* Get the Host mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
        &wHostMode));

    /* Getkey entry from SAM to switch the key type */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t) wKeyNo,
        (uint8_t) ((wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE) ? PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW :
        PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2),
        aData,
        &bDataLen));

    /* Extract the Keytype. */
    bKeyType = (uint8_t) ((aData[(wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE) ? (bDataLen - 6U) : (bDataLen - 3U)] & 0x38U) >> 3U);

    /* Set the authentication based on the keytype. */
    switch(bKeyType)
    {
        case 0x00:
        case 0x03U:
            /* 2K3DES keys or 3K3DES */
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
            break;

        case 0x04U:
            /* AES KEYS */
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEAES;
            break;

        default:
            break;
    }

    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo = bKeyNoCard;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_ON;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_IsoAuthenticate(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyNoCard,
    uint8_t bIsPICCkey)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wHostMode = 0;
    uint8_t     PH_MEMLOC_REM bKeyType = 0;
    uint8_t     PH_MEMLOC_REM aRnd[16U];
    uint8_t     PH_MEMLOC_REM aData[25U];
    uint8_t     PH_MEMLOC_REM bDataLen = 0;
    uint8_t     PH_MEMLOC_REM bRndLen = 0;
    uint8_t     PH_MEMLOC_REM bAlgo = 0;

    /* Validate the parameters */
    if ((bKeyNoCard > 0x0DU) || (wKeyNo > 0x7FU) || (wKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Host mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
        &wHostMode));

    /* Getkey entry from SAM to switch the key type */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t) wKeyNo,
        (uint8_t) ((wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE) ? PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW :
        PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2),
        aData,
        &bDataLen));

    /* Extract the Keytype. */
    if(wHostMode != PHHAL_HW_SAMAV3_HC_AV3_MODE)
    {
        if(bDataLen >= 3U)
        {
            bKeyType = (uint8_t)((aData[(bDataLen - 3U)] & 0x38U) >> 3U);
        }
        else
        {
            bKeyType = 0xFF; /* INVALID KEY TYPE */
        }
    }
    else
    {
        if(bDataLen >= 6U)
        {
            bKeyType = (uint8_t)((aData[(bDataLen - 6U)] & 0x38U) >> 3U);
        }
        else
        {
            bKeyType = 0xFF; /* INVALID KEY TYPE */
        }
    }

    /* Set the random length. */
    switch(bKeyType)
    {
        case 0x00:
            bAlgo = 0x02U;
            bRndLen = 8U;
            break;

        case 0x03U:
            bAlgo = 0x04U;
            bRndLen = 16U;
            break;

        case 0x04U:
            bAlgo = 0x09U;
            bRndLen = 16U;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
    }

    /* Perform ISOGetChallange ----------------------------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_IsoGetChallenge(
        pDataParams,
        PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu,
        bRndLen,
        aRnd));

    /* Perform ISOExternalAuthenticate --------------------------------------------------------------------------------------- */
    bDataLen = 0;
    aData[bDataLen++] = bAlgo;
    aData[bDataLen++] = !bIsPICCkey;
    aData[bDataLen++] = bKeyNoCard;
    aData[bDataLen++] = bRndLen;

    memcpy(&aData[bDataLen], aRnd, bRndLen); /* PRQA S 3200 */
    bDataLen += bRndLen;

    memcpy(&aData[bDataLen], &wKeyNo, 2U); /* PRQA S 3200 */
    bDataLen += 2U;

    memcpy(&aData[bDataLen], &wKeyVer, 2U); /* PRQA S 3200 */
    bDataLen += 2U;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_IsoExternalAuthenticate(
        pDataParams,
        aData,
        bDataLen,
        PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu,
        aRnd,
        &bDataLen));

    /* Perform ISOInternalAuthenticate --------------------------------------------------------------------------------------- */
    bDataLen = 0;
    aData[bDataLen++] = bAlgo;
    aData[bDataLen++] = !bIsPICCkey;
    aData[bDataLen++] = bKeyNoCard;
    aData[bDataLen++] = bRndLen;

    memcpy(&aData[bDataLen], aRnd, bRndLen); /* PRQA S 3200 */
    bDataLen += bRndLen;

    memcpy(&aData[bDataLen], &wKeyNo, 2U); /* PRQA S 3200 */
    bDataLen += 2U;

    memcpy(&aData[bDataLen], &wKeyVer, 2U); /* PRQA S 3200 */
    bDataLen += 2U;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_IsoInternalAuthenticate(
        pDataParams,
        aData,
        bDataLen,
        PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu));

    /* Set the authentication based on the keytype. */
    switch(bKeyType)
    {
        case 0x00:
        case 0x03U:
            /* 2K3DES keys or 3K3DES */
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEISO;
            break;

        case 0x04U:
            /* AES KEYS */
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEAES;
            break;

        default:
            break;
    }

    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo = bKeyNoCard;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = PH_ON;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Originality Check functions. ------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_ReadSign(void * pDataParams, uint8_t bAddr, uint8_t ** ppSignature)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_READ_SIG;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_READ_SIG;
    pCmdBuff[1U] = bAddr;

    /* Frame the communication mode to be applied. */
    bComMode = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ?
        PHAL_MFDFEVX_COMMUNICATION_ENC : PHAL_MFDFEVX_COMMUNICATION_PLAIN);

    /* Exchange Cmd.ReadSign information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ReadData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComMode,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        56U,
        pCmdBuff,
        2U,
        ppSignature,
        &wRespLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx MIFARE Classic contactless IC functions. ---------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_CreateMFCMapping(void * pDataParams, uint8_t bComOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pMFCBlockList, uint8_t bMFCBlocksLen, uint8_t bRestoreSource, uint8_t * pMFCLicense, uint8_t bMFCLicenseLen,
    uint8_t * pMFCLicenseMAC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;

    /* Validate the parameters. */
    if((bComOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bComOption != PHAL_MFDFEVX_COMMUNICATION_ENC))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    bCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_MFC_MAPPING;

    /* Frame the command information. */
    pCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_MFC_MAPPING;
    pCmdBuff[bCmdLen++] = bFileNo;
    pCmdBuff[bCmdLen++] = bFileOption;
    pCmdBuff[bCmdLen++] = bMFCBlocksLen;

    /* Copy the MFCBlockList to command buffer. */
    memcpy(&pCmdBuff[bCmdLen], pMFCBlockList, bMFCBlocksLen); /* PRQA S 3200 */
    bCmdLen = ((bMFCBlocksLen + bCmdLen) & 0xFF);

    /* Copy RestoreSource to command buffer. */
    if(bFileOption & 0x04U)
    {
        pCmdBuff[bCmdLen] = bRestoreSource;
        bCmdLen = ((bCmdLen + 1U) & 0xFF);
    }

    /* Copy the MFCLicense to command buffer. */
    memcpy(&pCmdBuff[bCmdLen], pMFCLicense, bMFCLicenseLen); /* PRQA S 3200 */
    bCmdLen = ((bCmdLen + bMFCLicenseLen) & 0xFF);

    /* Exchange Cmd.CreateMFCMapping information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        bComOption,
        (uint8_t) ((bComOption == PHAL_MFDFEVX_COMMUNICATION_PLAIN) ? PHAL_MFDFEVX_COMMUNICATION_PLAIN : PHAL_MFDFEVX_COMMUNICATION_MACD),
        PH_OFF,
        pCmdBuff,
        bCmdLen,
        pMFCLicenseMAC,
        8U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_RestoreTransfer(void * pDataParams, uint8_t bCommOption, uint8_t bTargetFileNo,
    uint8_t bSourceFileNo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    if ((bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
        (bCommOption != PHAL_MFDFEVX_COMMUNICATION_PLAIN_1) &&
        (bCommOption != PHAL_MFDFEVX_COMMUNICATION_MACD))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer. */
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_RESTORE_TRANSFER;

    /* Frame the command information. */
    pCmdBuff[0] = PHAL_MFDFEVX_CMD_RESTORE_TRANSFER;
    pCmdBuff[1U] = bTargetFileNo;
    pCmdBuff[2U] = bSourceFileNo;

    /* Frame the Crypto information. */
    bComMode = PHAL_MFDFEVX_COMMUNICATION_PLAIN;
    if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
       (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
       ( PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
    {
        bComMode = PHAL_MFDFEVX_COMMUNICATION_MACD;
    }

    /* Exchange Cmd.FinalizeKeySet information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCommOption,
        bComMode,
        PH_OFF,
        pCmdBuff,
        1U,
        &pCmdBuff[1U],
        2U,
        NULL,
        NULL));

    /* Get the status of the TMI */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
        PH_TMIUTILS_TMI_STATUS, &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus == PH_ON)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_ZEROPAD_CMDBUFF, pCmdBuff, 3U, NULL, 0, PHAL_MFDFEVX_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_RestrictMFCUpdate(void * pDataParams, uint8_t bOption, uint8_t * pMFCConfig,
    uint8_t bMFCConfigLen, uint8_t * pMFCLicense, uint8_t bMFCLicenseLen, uint8_t * pMFCLicenseMAC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    bCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_RESTRICT_MFC_UPDATE;

    /* Frame the command information. */
    pCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_RESTRICT_MFC_UPDATE;
    pCmdBuff[bCmdLen++] = bOption;

    /* Copy the MFCBlockList to command buffer. */
    memcpy(&pCmdBuff[bCmdLen], pMFCConfig, bMFCConfigLen); /* PRQA S 3200 */
    bCmdLen = ((bCmdLen + bMFCConfigLen) & 0xFF);

    /* Copy the MFCLicense to command buffer. */
    memcpy(&pCmdBuff[bCmdLen], pMFCLicense, bMFCLicenseLen); /* PRQA S 3200 */
    bCmdLen = ((bCmdLen + bMFCLicenseLen) & 0xFF);

    /* Exchange Cmd.CreateMFCMapping information to Sam and PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_WriteData(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        PHAL_MFDFEVX_COMMUNICATION_ENC,
        PHAL_MFDFEVX_COMMUNICATION_MACD,
        PH_OFF,
        pCmdBuff,
        bCmdLen,
        pMFCLicenseMAC,
        8U,
        NULL,
        NULL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx POST Delivery Configuration function. ---------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_AuthenticatePDC(void * pDataParams, uint8_t bRfu, uint8_t bKeyNoCard, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bUpgradeInfo)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;

    /* Perform Post Delivery Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_AuthenticatePDC(pDataParams, bRfu, bKeyNoCard, wKeyNum, wKeyVer, bUpgradeInfo));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

/* MIFARE DESFire EVx Miscellaneous functions. ----------------------------------------------------------------------------------------- */
phStatus_t phalMfdfEVx_Sam_NonX_GetConfig(void * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    switch (wConfig)
    {
        case PHAL_MFDFEVX_ADDITIONAL_INFO:
            *pValue = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo;
            break;

        case PHAL_MFDFEVX_WRAPPED_MODE:
            *pValue = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;
            break;

        case PHAL_MFDFEVX_RETURN_FAB_ID:
            *pValue = (uint8_t) PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bReturn_FabID;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_SetConfig(void * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    switch (wConfig)
    {
        case PHAL_MFDFEVX_ADDITIONAL_INFO:
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wAdditionalInfo = wValue;
            break;

        case PHAL_MFDFEVX_WRAPPED_MODE:
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = (wValue & 0xFF);
            break;

        case PHAL_MFDFEVX_RETURN_FAB_ID:
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bReturn_FabID = (wValue & 0xFF);
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ResetAuthStatus(void * pDataParams)
{
    (void)phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GenerateDAMEncKey(void * pDataParams, uint16_t wKeyNoDAMEnc, uint16_t wKeyVerDAMEnc,
    uint16_t wKeyNoAppDAMDefault, uint16_t wKeyVerAppDAMDefault, uint8_t bAppDAMDefaultKeyVer, uint8_t * pDAMEncKey)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bKeyLen = 0;
    uint8_t *   PH_MEMLOC_REM pInputBuff = NULL;
    uint8_t     PH_MEMLOC_REM bInputBuffLen = 0;
    uint16_t    PH_MEMLOC_REM bInputBuffSize = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint16_t    PH_MEMLOC_REM wSET = 0;
    uint16_t    PH_MEMLOC_REM wExtSET = 0;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    /* Validate the key information. */
    if (((wKeyNoDAMEnc > 0x7FU) || (wKeyVerDAMEnc > 0xFFU)) ||
        (wKeyNoAppDAMDefault > 0x7FU) || ((wKeyVerAppDAMDefault > 0x7FU) || (bAppDAMDefaultKeyVer > 0xFFU)))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the KeyInformation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_GetKeyInfo(
        pDataParams,
        (uint8_t) wKeyNoAppDAMDefault,
        &wKeyType,
        &wSET,
        &wExtSET));

    /* Validate the KeyType. */
    if((wKeyType != 0x0030U) && (wKeyType != 0x0020U) &&
        (wKeyType != 0x0018U) && (wKeyType != 0x0000U))
    {
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
    }

    /* Check if DumpSecretKey is enabled. */
    if(!(wExtSET & 0x0008U))
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

    /* Get the KeyInformation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_GetKeyInfo(
        pDataParams,
        (uint8_t) wKeyNoDAMEnc,
        &wKeyType,
        &wSET,
        &wExtSET));

    /* Validate the KeyType. */
    if((wKeyType != 0x0030U) && (wKeyType != 0x0020U) &&
        (wKeyType != 0x0018U) && (wKeyType != 0x0000))
    {
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pInputBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    bInputBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    memset(pInputBuff, 0x00, bInputBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Add the Random number. */
    bInputBuffLen = 7U;
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetRandom(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bInputBuffLen,
        pInputBuff));

    /* Append the Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DumpSecretKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_DUMP_MODE_PLAIN,
        (uint8_t) wKeyNoAppDAMDefault,
        (uint8_t) wKeyVerAppDAMDefault,
        NULL,
        0,
        &pInputBuff[bInputBuffLen],
        &bKeyLen));
    bInputBuffLen += bKeyLen;

    /* Append the key version. */
    pInputBuff[bInputBuffLen] = bAppDAMDefaultKeyVer;

    /* Set the Input length to 32 bytes default. */
    bInputBuffLen = 32U;

    /* Validate the KeyType. */
    if((wKeyType != 0x0030U) && (wKeyType != 0x0020U) &&
        (wKeyType != 0x0018U) && (wKeyType != 0x0000))
    {
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
    }

    /* Perform Offline activation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wKeyNoDAMEnc,
        (uint8_t) wKeyVerDAMEnc,
        NULL,
        0));

    /* Encrypt the Plaindata. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherOfflineData(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        pInputBuff,
        bInputBuffLen,
        &pResponse,
        &wRespLen));

    /* Copy the response to the parameter. */
    memcpy(pDAMEncKey, pResponse, wRespLen); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_GenerateDAMMAC(void * pDataParams, uint8_t bOption, uint16_t wKeyNoDAMMAC,
    uint16_t wKeyVerDAMMAC, uint8_t * pAid, uint8_t * pDamParams, uint8_t bKeySettings1, uint8_t bKeySettings2,
    uint8_t bKeySettings3, uint8_t * pKeySetValues, uint8_t * pISOFileId, uint8_t * pISODFName, uint8_t bISODFNameLen,
    uint8_t * pEncK, uint8_t * pDAMMAC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pInputBuff = NULL;
    uint8_t     PH_MEMLOC_REM bInputBuffLen = 0;
    uint16_t    PH_MEMLOC_REM bInputBuffSize = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint16_t    PH_MEMLOC_REM wSET = 0;
    uint16_t    PH_MEMLOC_REM wExtSET = 0;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    /* Validate the key information. */
    if ((wKeyNoDAMMAC > 0x7FU) || (wKeyVerDAMMAC > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the KeyInformation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_GetKeyInfo(
        pDataParams,
        (uint8_t) wKeyNoDAMMAC,
        &wKeyType,
        &wSET,
        &wExtSET));

    /* Validate the KeyType. */
    if((wKeyType != 0x0030U) && (wKeyType != 0x0020U) &&
        (wKeyType != 0x0018U) && (wKeyType != 0x0000))
    {
        return PH_ADD_COMPCODE(PH_ERR_KEY, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pInputBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    bInputBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    bInputBuffLen = 0;
    memset(pInputBuff, 0x00, bInputBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Frame the Input */
    pInputBuff[bInputBuffLen++] = PHAL_MFDFEVX_CMD_CREATE_DELEGATED_APPLN;

    if((bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION) == PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION)
        pInputBuff[0] = PHAL_MFDFEVX_CMD_DELETE_APPLN;

    /* Append Application Identifier */
    memcpy(&pInputBuff[bInputBuffLen], pAid, 3U);    /* PRQA S 3200 */
    bInputBuffLen += 3U;

    if(!(bOption & PHAL_MFDFEVX_GENERATE_DAMMAC_DELETE_APPLICATION))
    {
        /* Append DAMParams */
        memcpy(&pInputBuff[bInputBuffLen], pDamParams, 5U);  /* PRQA S 3200 */
        bInputBuffLen += 5U;

        /* Append KeySetting Information */
        pInputBuff[bInputBuffLen++] = bKeySettings1;
        pInputBuff[bInputBuffLen++] = bKeySettings2;
        if (bKeySettings2 & PHAL_MFDFEVX_KEYSETT3_PRESENT)
        {
            pInputBuff[bInputBuffLen++] = bKeySettings3;
            if (bKeySettings3 & PHAL_MFDFEVX_KEYSETVALUES_PRESENT && pKeySetValues != NULL)
            {
                memcpy(&pInputBuff[bInputBuffLen], pKeySetValues, 4U); /* PRQA S 3200 */
                bInputBuffLen += 4U;
            }
        }

        /* Append FileID Information */
        if (bOption & PHAL_MFDFEVX_ISO_FILE_ID_AVAILABLE)
        {
            memcpy(&pInputBuff[bInputBuffLen], pISOFileId, 2U); /* PRQA S 3200 */
            bInputBuffLen += 2U;
        }

        /* Append DFName Information */
        if (bOption & PHAL_MFDFEVX_ISO_DF_NAME_AVAILABLE)
        {
            memcpy(&pInputBuff[bInputBuffLen], pISODFName, bISODFNameLen); /* PRQA S 3200 */
            bInputBuffLen += bISODFNameLen;
        }

        /* Append EncK Information. */
        memcpy(&pInputBuff[bInputBuffLen], pEncK, 32U);  /* PRQA S 3200 */
        bInputBuffLen += 32U;
    }

    /* Perform Offline activation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wKeyNoDAMMAC,
        (uint8_t) wKeyVerDAMMAC,
        NULL,
        0));

    /* Generate the MAC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP,
        pInputBuff,
        bInputBuffLen,
        &pResponse,
        &wRespLen));

    /* Copy the MAC to parameter. */
    memcpy(pDAMMAC, pResponse, wRespLen);   /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_CalculateTMV(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pTMI, uint32_t dwTMILen, uint8_t * pTMV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint8_t *   PH_MEMLOC_REM pMac = NULL;
    uint16_t    PH_MEMLOC_REM wMacLen = 0;

    uint16_t    PH_MEMLOC_REM wBuffOption = PH_EXCHANGE_DEFAULT;
    uint8_t     PH_MEMLOC_REM bExchangeLen = 0;
    uint32_t    PH_MEMLOC_REM dwRemLen = 0;
    uint16_t    PH_MEMLOC_REM wTMIOffset = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Derive Transaction MAC (KSesTMMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ComputeTMACSessionVectors(
        pDataParams,
        PHAL_MFDFEVX_SAM_NONX_SESSION_TMAC_MAC,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pTMC,
        pUid,
        bUidLen));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0));

    /* Perform MAC verification. */
    dwRemLen = (uint16_t) dwTMILen;
    wBuffOption = PH_EXCHANGE_TXCHAINING;

    do
    {
        /* Update the finished flag and buffering option. */
        if(dwRemLen <= PHALMFDFEVX_SAM_DATA_FRAME_LENGTH)
        {
            bFinished = PH_ON;
            wBuffOption = PH_EXCHANGE_DEFAULT;
            bExchangeLen = (uint8_t) dwRemLen;
        }
        else
        {
            bExchangeLen = PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
            dwRemLen = (uint16_t) (dwRemLen - PHALMFDFEVX_SAM_DATA_FRAME_LENGTH);
        }

        /* Exchange the TMI information to SAM. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            wBuffOption,
            PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP,
            &pTMI[wTMIOffset],
            bExchangeLen,
            &pMac,
            &wMacLen);

        /* Validate the response. */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            bFinished = PH_ON;
        }

        /* Update the TMI offset information. */
        wTMIOffset += PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;

    }while(!bFinished);

    /* Copy the Mac to the parameter. */
    memcpy(pTMV, pMac, wMacLen);    /* PRQA S 3200 */

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_DecryptReaderID(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer,
    uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pEncTMRI,
    uint8_t * pTMRIPrev)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Derive Transaction MAC (KSesTMMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ComputeTMACSessionVectors(
        pDataParams,
        PHAL_MFDFEVX_SAM_NONX_SESSION_TMAC_ENC,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pTMC,
        pUid,
        bUidLen));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0));

    /* Exchange the TMI information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        pEncTMRI,
        16U,
        &pResponse,
        &wRespLen));

    /* Copy the decrypted information to the parameter. */
    memcpy(pTMRIPrev, pResponse, wRespLen); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_ComputeMFCLicenseMAC(void * pDataParams, uint16_t wOption, uint16_t wMFCLicenseMACKeyNo,
    uint16_t wMFCLicenseMACKeyVer, uint8_t * pInput, uint16_t wInputLen, uint8_t * pDivInput, uint8_t bDivInputLen,
    uint8_t * pMFCLicenseMAC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    uint8_t     PH_MEMLOC_REM bOption = PH_OFF;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint16_t    PH_MEMLOC_REM wBuffOption = PH_EXCHANGE_DEFAULT;
    uint8_t     PH_MEMLOC_REM bExchangeLen = 0;
    uint16_t    PH_MEMLOC_REM wRemLen = 0;
    uint16_t    PH_MEMLOC_REM wInputOffset = 0;

    /* Validate the key information. */
    if ((wMFCLicenseMACKeyNo > 0x7FU) || (wMFCLicenseMACKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Frame the Option parameter. */
    bOption = (uint8_t) ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) ? PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON :
        PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF);

    /* Perform Offline activation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bOption,
        (uint8_t) wMFCLicenseMACKeyNo,
        (uint8_t) wMFCLicenseMACKeyVer,
        pDivInput,
        bDivInputLen));

    /* Perform MAC generation. */
    wRemLen = wInputLen;
    wBuffOption = PH_EXCHANGE_TXCHAINING;

    do
    {
        /* Update the finished flag and buffering option. */
        if(wRemLen <= PHALMFDFEVX_SAM_DATA_FRAME_LENGTH)
        {
            bFinished = PH_ON;
            wBuffOption = PH_EXCHANGE_DEFAULT;
            bExchangeLen = (uint8_t) wRemLen;
        }
        else
        {
            bExchangeLen = PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
            wRemLen = (uint16_t) (wRemLen - PHALMFDFEVX_SAM_DATA_FRAME_LENGTH);
        }

        /* Exchange the Input information to SAM. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            wBuffOption,
            PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP,
            &pInput[wInputOffset],
            bExchangeLen,
            &pResponse,
            &wRespLen);

        /* Validate the response. */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            bFinished = PH_ON;
        }

        /* Update the TMI offset information. */
        wInputOffset += PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;

    }while(!bFinished);

    /* Copy the Mac to the parameter. */
    memcpy(pMFCLicenseMAC, pResponse, wRespLen);    /* PRQA S 3200 */

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_CalculateMACSDM(void * pDataParams, uint8_t bSdmOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr,
    uint8_t * pInData, uint16_t wInDataLen, uint8_t * pMac)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    uint16_t    PH_MEMLOC_REM wBuffOption = PH_EXCHANGE_DEFAULT;
    uint8_t     PH_MEMLOC_REM bExchangeLen = 0;
    uint16_t    PH_MEMLOC_REM wRemLen = 0;
    uint16_t    PH_MEMLOC_REM wInputOffset = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Derive SDM MAC (KSesSDMFileReadMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ComputeSDMSessionVectors(
        pDataParams,
        PHAL_MFDFEVX_SAM_NONX_SESSION_MAC,
        bSdmOption,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pUid,
        bUidLen,
        pSDMReadCtr));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0));

    /* Perform MAC generation. */
    wRemLen = wInDataLen;
    wBuffOption = PH_EXCHANGE_TXCHAINING;

    do
    {
        /* Update the finished flag and buffering option. */
        if(wRemLen <= PHALMFDFEVX_SAM_DATA_FRAME_LENGTH)
        {
            bFinished = PH_ON;
            wBuffOption = PH_EXCHANGE_DEFAULT;
            bExchangeLen = (uint8_t) wRemLen;
        }
        else
        {
            bExchangeLen = PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
            wRemLen = (uint16_t) (wRemLen - PHALMFDFEVX_SAM_DATA_FRAME_LENGTH);
        }

        /* Exchange the Input information to SAM. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            wBuffOption,
            PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP,
            &pInData[wInputOffset],
            bExchangeLen,
            &pResponse,
            &wRespLen);

        /* Validate the response. */
        if(((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            bFinished = PH_ON;
        }

        /* Update the TMI offset information. */
        wInputOffset += PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;

    }while(!bFinished);

    /* Copy the Mac to the parameter. */
    memcpy(pMac, pResponse, wRespLen);  /* PRQA S 3200 */

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_DecryptSDMENCFileData(void * pDataParams, uint8_t bSdmOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint16_t wDstKeyVer, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr,
    uint8_t * pEncdata, uint16_t wEncDataLen, uint8_t * pPlainData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Derive SDM MAC (KSesSDMFileReadMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ComputeSDMSessionVectors(
        pDataParams,
        PHAL_MFDFEVX_SAM_NONX_SESSION_ENC,
        bSdmOption,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pUid,
        bUidLen,
        pSDMReadCtr));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0));

    /* Load the IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_LoadSDMInitVector(
        pDataParams,
        pSDMReadCtr));

    /* Exchange the Encrypted information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        pEncdata,
        (uint8_t) wEncDataLen,
        &pResponse,
        &wRespLen));

    /* Copy the decrypted information to the parameter. */
    memcpy(pPlainData, pResponse, wRespLen);    /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_DecryptSDMPICCData(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pEncdata,
    uint16_t wEncDataLen, uint8_t * pPlainData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bEncDataOffset = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t)(wKeyNo & 0xFF),
        (uint8_t)(wKeyVer & 0xFF),
        NULL,
        0));

    /* Perform DecipherDataOffline. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        &pEncdata[bEncDataOffset],
        (uint8_t) (wEncDataLen - bEncDataOffset),
        &pResponse,
        &wRespLen));

    /* Copy the decrypted information to the parameter. */
    memcpy(pPlainData, pResponse, wRespLen);    /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}
#endif /* NXPBUILD__PHAL_MFDFEVX_SAM_NONX */
