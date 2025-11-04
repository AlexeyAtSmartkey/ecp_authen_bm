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
* Software MIFARE DESFire contactless IC Application Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phhalHw.h>
#include <phCryptoSym.h>
#include <phCryptoRng.h>
#include <phKeyStore.h>
#include <ph_RefDefs.h>
#include <string.h>
#include <ph_TypeDefs.h>

#ifdef NXPBUILD__PHAL_MFDFEVX_SAM_NONX
#include "../phalMfdfEVx_Int.h"
#include "phalMfdfEVx_Sam_NonX_Int.h"

phStatus_t phalMfdfEVx_Sam_NonX_Int_ValidateResponse(void * pDataParams, uint16_t wStatus, uint16_t wPiccRetCode)
{
    /* Evaluate the response. */
    if ((wStatus == PH_ERR_SUCCESS) ||
        ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN) ||
        ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN))
    {
        /* Validate the PICC Status. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, (uint16_t) (wPiccRetCode & 0x00FFU)));
    }
    else
    {
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
        {
            wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_AL_MFDFEVX);
        }

        PH_CHECK_SUCCESS(wStatus);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_CardExchange(void * pDataParams, uint16_t wBufferOption, uint8_t bCmdOption,
    uint16_t wTotDataLen, uint8_t bExchangeLE, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRespLen,
    uint8_t * pPiccErrCode)
{
    phStatus_t      PH_MEMLOC_REM wStatus = 0;
    phStatus_t      PH_MEMLOC_REM wPICCStatus = 0;
    uint8_t         PH_MEMLOC_REM bPICCStatLen = 0;
    uint16_t        PH_MEMLOC_REM wLc = 0;
    uint16_t        PH_MEMLOC_REM wRespLen = 0;
    uint8_t*        PH_MEMLOC_REM pResponse = NULL;

    uint8_t         PH_MEMLOC_REM aLc[3U] = {0x00, 0x00, 0x00};
    uint8_t         PH_MEMLOC_REM aLe[3U] = {0x00, 0x00, 0x00};
    uint8_t         PH_MEMLOC_REM bLcLen = 0;
    uint8_t         PH_MEMLOC_REM aISO7816Header[8U] = {PHAL_MFDFEVX_WRAPPEDAPDU_CLA, 0x00, PHAL_MFDFEVX_WRAPPEDAPDU_P1, PHAL_MFDFEVX_WRAPPEDAPDU_P2};
    uint8_t         PH_MEMLOC_REM bISO7816HeaderLen = 4U;
    uint8_t         PH_MEMLOC_REM bIsIsoChainnedCmd = PH_OFF;
    static uint8_t  PH_MEMLOC_REM bLeLen;

    /* Exchange the command in Iso7816 wrapped format. ----------------------------------------------------------------- */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode)
    {
        if((wBufferOption == PH_EXCHANGE_BUFFER_FIRST) || (wBufferOption == PH_EXCHANGE_DEFAULT))
        {
            /* Set the flag for data operation commands. */
            bIsIsoChainnedCmd = (uint8_t) (((pData[0] == PHAL_MFDFEVX_CMD_READ_DATA_ISO) || (pData[0] == PHAL_MFDFEVX_CMD_READ_RECORDS_ISO) ||
                (pData[0] == PHAL_MFDFEVX_CMD_WRITE_DATA_ISO) || (pData[0] == PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO) ||
                (pData[0] == PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO)) ? PH_ON : PH_OFF);

            bLeLen = 1U;

            /* Set the LC information. */
            wLc = ((wTotDataLen - (uint16_t)1U) & 0xFFFF);  /* Excluding the command code. */

            /* Update the command code to Iso7816 header */
            aISO7816Header[1U] = pData[0];

            /* Add the ISO 7816 header to layer 4 buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                &aISO7816Header[0],
                bISO7816HeaderLen,
                NULL,
                NULL));

            /* Add Lc if available */
            if(wLc)
            {
                /* Update Lc bytes according to Extended APDU option. */
                if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu || bIsIsoChainnedCmd)
                {
                    aLc[bLcLen++] = 0x00;
                    aLc[bLcLen++] = (uint8_t) ((wLc & 0xFF00U) >> 8U);

                    /* Le length is updated to two if Lc is present and the APDU is extended. */
                    bLeLen = 2U;
                }

                aLc[bLcLen++] = (uint8_t) (wLc & 0x00FFU);

                /* Add the Lc to layer 4 buffer. */
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                    PH_EXCHANGE_BUFFER_CONT,
                    &aLc[0],
                    bLcLen,
                    NULL,
                    NULL));

                /* Add the data to layer 4 buffer. */
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                    PH_EXCHANGE_BUFFER_CONT,
                    &pData[1U],  /* Exclude the command code because it is added to INS. */
                    ((((uint16_t)wDataLen - 1) < 0)? 0 : (uint16_t)((wDataLen - 1) & 0xFFFF)),
                    NULL,
                    NULL));
            }
            else
            {
                /* Update Le count */
                if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu)
                {
                    bLeLen = 3U;
                }
            }
        }

        if(wBufferOption == PH_EXCHANGE_BUFFER_CONT)
        {
            /* Add the data to layer 4 buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_CONT,
                pData,
                wDataLen,
                NULL,
                NULL));
        }

        if((wBufferOption == PH_EXCHANGE_BUFFER_LAST) || (wBufferOption == PH_EXCHANGE_DEFAULT))
        {
            if(wBufferOption == PH_EXCHANGE_BUFFER_LAST)
            {
                /* Add the data to layer 4 buffer. */
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                    PH_EXCHANGE_BUFFER_CONT,
                    pData,
                    wDataLen,
                    NULL,
                    NULL));
            }

            /* Add Le to L4 buffer and exchange the command. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                &aLe[0],
                (uint8_t) (bExchangeLE ?  bLeLen : 0),
                &pResponse,
                &wRespLen));

            /* Combine Sw1 and Sw2 status codes. */
            wPICCStatus = (uint16_t) ((pResponse[wRespLen - 2U] << 8U) | pResponse[wRespLen - 1U]);

            /* Evaluate the response. */
            wStatus = phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, wPICCStatus);

            /* Create memory for updating the response of ISO 14443 format. */
            *ppResponse = pResponse;

            /* Update the response buffer length excluding SW1SW2. */
            *pRespLen = wRespLen - 2U;

            /* Copy the second byte of response (SW2) to RxBuffer */
            *pPiccErrCode = pResponse[wRespLen - 1U];
        }

        if(wBufferOption == PH_EXCHANGE_RXCHAINING)
        {
            /* Exchange the command */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                wBufferOption,
                pData,
                wDataLen,
                &pResponse,
                &wRespLen));

            if(wRespLen != 0)
            {
                /* Combine Sw1 and Sw2 status codes. */
                wPICCStatus = (uint16_t) ((pResponse[wRespLen - 2U] << 8U) | pResponse[wRespLen - 1U]);

                /* Evaluate the response. */
                wStatus = phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, wPICCStatus);

                /* Create memory for updating the response of ISO 14443 format. */
                *ppResponse = pResponse;

                /* Update the response buffer length excluding SW1SW2. */
                *pRespLen = wRespLen - 2U;

                /* Copy the second byte of response (SW2) to RxBuffer */
                *pPiccErrCode = pResponse[wRespLen - 1U];
            }
        }
    }

    /* Exchange the command in Native format. -------------------------------------------------------------------------- */
    else
    {
        /* Exchange the data to the card in Native format. */
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
            PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
            wBufferOption,
            pData,
            wDataLen,
            &pResponse,
            &wRespLen));

        /* Verify the received data and update the response buffer with received data. */
        if((bCmdOption & PHALMFDFEVX_SAM_NONX_CMD_OPTION_PENDING) ||
            (bCmdOption & PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE))
        {
            if(bCmdOption & PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED)
            {
                /* Combine Sw1 and Sw2 status codes. */
                wPICCStatus = (uint16_t) ((pResponse[wRespLen - 2U] << 8U) | pResponse[wRespLen - 1U]);
                bPICCStatLen = 2U;
            }
            else
            {
                wPICCStatus = pResponse[0];
                bPICCStatLen = 1U;
            }

            /* Evaluate the response. */
            wStatus = phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, wPICCStatus);

            /* Add the status code. */
            *pPiccErrCode = pResponse[(bCmdOption & PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED) ? (wRespLen - 1U) : 0];

            /* Update the response buffer length excluding CHAINING(0xAF). */
            *pRespLen = wRespLen - bPICCStatLen;

            /* Add the Response data excluding the status code. */
            *ppResponse = &pResponse[(bCmdOption & PHALMFDFEVX_SAM_NONX_PICC_STATUS_WRAPPED) ? 0 : 1U];
        }
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_AuthenticatePICC(void * pDataParams, uint8_t bAuthType, uint16_t wOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pPcdCapsIn,
    uint8_t bPcdCapsInLen, uint8_t * pPCDCap2, uint8_t * pPDCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bAuthMode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffLen = 0;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t *   PH_MEMLOC_REM pCardResponse = NULL;
    uint16_t    PH_MEMLOC_REM wCardRespLen = 0;
    uint8_t*    PH_MEMLOC_REM pSamResponse = NULL;
    uint16_t    PH_MEMLOC_REM wSamRespLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM aAppId[3U] = {0x00, 0x00, 0x00};

    /* Check for valid card key number. */
    if ((bKeyNoCard & 0x0FU) > 0x0DU)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Check for valid SAM keystore number and version. */
    if ((wKeyNo > 0x7FU) || (wKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Change for valid diversification options. */
    if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) &&
        (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)) &&
        (wOption != (PH_CRYPTOSYM_DIV_MODE_DESFIRE | PH_CRYPTOSYM_DIV_OPTION_2K3DES_FULL)) &&
        (wOption != PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Validate diversification input length. */
    if ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) && (bDivInputLen > 31U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Reset the Authentication state. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_NOT_AUTHENTICATED;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo = 0xFFU;

    /* Clear the command buffer and length. */
    wCmdBuffLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

/* Frame the command buffer to be exchanged with PICC---------------------------------------------------------------------------------- */

    /* Add the Auth code to Command Buffer . */
    pCmdBuff[wCmdBuffLen++] = bAuthType;
    pCmdBuff[wCmdBuffLen++] = bKeyNoCard;

    /* Append PCD input capabilities in case of EV2 First auth. */
    if (bAuthType == PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_FIRST)
    {
        /* Append LenCap Byte. */
        pCmdBuff[wCmdBuffLen++] = bPcdCapsInLen;

        memcpy(&pCmdBuff[wCmdBuffLen], pPcdCapsIn, bPcdCapsInLen);  /* PRQA S 3200 */
        wCmdBuffLen += bPcdCapsInLen;
    }

    /* Exchange the command with the card. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_PENDING,
        wCmdBuffLen,
        PH_ON,
        pCmdBuff,
        wCmdBuffLen,
        &pCardResponse,
        &wCardRespLen,
        &bPiccErrCode);

    /* Validate the response for chaining. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus;
    }

/* First part of Exchange with Sam hardware. ------------------------------------------------------------------------------------------- */

    /* Set Auth Type. */
    bAuthMode = (uint8_t) ((bAuthType == PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_FIRST) ? PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_FIRST_AUTH :
                           (bAuthType == PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_NON_FIRST) ? PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2_NON_FIRST_AUTH :
                            PHHAL_HW_CMD_SAMAV3_AUTH_MODE_D40_EV1);

    /* Set Auth mode with diversification enabled. */
    bAuthMode |= (uint8_t) ((wOption != PHAL_MFDFEVX_NO_DIVERSIFICATION) ? PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_ON :
        PHHAL_HW_CMD_SAMAV3_KEY_DIVERSIFICATION_OFF);

    /* Set Diversification flags.
     * For AV1 compatibility mode key diversification methods, TDEA Key, diversified using one encryption round
     */
    if (wOption == PH_CRYPTOSYM_DIV_OPTION_2K3DES_HALF)
    {
        bAuthMode |= (uint8_t) PHHAL_HW_CMD_SAMAV3_KDF_AV1_SINGLE_ENCRYPTION;
    }

    /* Set Diversification flags.
     * AV2 compatibility mode key diversification methods, 3TDEA, AES key
     */
    if (wOption == PH_CRYPTOSYM_DIV_MODE_MIFARE_PLUS)
    {
        bAuthMode |= (uint8_t) PHHAL_HW_CMD_SAMAV3_KDF_AV2;
    }

    /* Set the secure messaging. */
    if((bKeyNoCard >= PHAL_MFDFEVX_ORIGINALITY_KEY_FIRST) && (bKeyNoCard <= PHAL_MFDFEVX_ORIGINALITY_KEY_LAST) &&
        (memcmp(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aAppId, 3) == 0x00))
    {
        bAuthMode = (uint8_t) (bAuthMode | PHHAL_HW_CMD_SAMAV3_SUPPRESS_SECURE_MESSAGING);
    }

    wStatus1 = phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part1(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bAuthMode,
        (uint8_t) wKeyNo,
        (uint8_t) wKeyVer,
        PHHAL_HW_CMD_SAMAV3_AUTH_MODE_EV2,
        pDivInput,
        bDivInputLen,
        pCardResponse,
        (uint8_t) wCardRespLen,
        &pSamResponse,
        &wSamRespLen);

    /* Check for the Chaining active */
    if ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus1;
    }

/* Second part of Exchange with card. -------------------------------------------------------------------------------------------------- */
    wCmdBuffLen = 0;
    bPiccErrCode = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Frame the command for Exchange to card. */
    pCmdBuff[wCmdBuffLen++] = PHAL_MFDFEVX_CMD_AUTHENTICATE_PART2;

    /* Copy the response received from SAM to Command buffer. */
    memcpy(&pCmdBuff[wCmdBuffLen], pSamResponse, wSamRespLen);  /* PRQA S 3200 */
    wCmdBuffLen += wSamRespLen;

    /* Exchange the command with the card. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE,
        wCmdBuffLen,
        PH_ON,
        pCmdBuff,
        wCmdBuffLen,
        &pCardResponse,
        &wCardRespLen,
        &bPiccErrCode);

    /* Second part of Exchange with Sam hardware. ----------------------------------------------------------------- */
    if((bPiccErrCode != 0U) || (wCardRespLen > 0U))
    {
        wStatus1 = phhalHw_SamAV3_Cmd_SAM_AuthenticatePICC_Part2(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pCardResponse,
            (uint8_t) wCardRespLen,
            pPDCap2,
            pPCDCap2,
            &bPiccErrCode);

        if(wStatus1 != PH_ERR_SUCCESS)
        {
            wStatus = (phStatus_t) (((wStatus1 & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_DESFIRE_GEN) ? wStatus : wStatus1);
        }
        else
        {
            /* Do not update the auth state if originality keys are used. */
            if((bKeyNoCard >= PHAL_MFDFEVX_ORIGINALITY_KEY_FIRST) && (bKeyNoCard <= PHAL_MFDFEVX_ORIGINALITY_KEY_LAST) &&
                (memcmp(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aAppId, 3U) == 0x00))
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            }
            else
            {
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo = bKeyNoCard;
                PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = bAuthType;

                if(bAuthType == PHAL_MFDFEVX_CMD_AUTHENTICATE_EV2_NON_FIRST)
                {
                    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFDFEVX_AUTHENTICATEEV2;
                }
            }
        }
    }

    /*
     * Kill PICC Authentication for next SAM call to proceed further
     * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
     * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
     */
    else
    {
        /* Kill the PICC Authentication in Sam hardware. */
        wStatus1 = phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_AuthenticatePDC(void * pDataParams, uint8_t bRfu, uint8_t bKeyNoCard, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bUpgradeInfo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Clear the command buffer and length. */
    bCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_AUTH_PDC;

    /* Frame the command*/
    bCmdLen = 0;
    pCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_AUTH_PDC;
    pCmdBuff[bCmdLen++] = bRfu,
    pCmdBuff[bCmdLen++] = bKeyNoCard,
    pCmdBuff[bCmdLen++] = 0x01U;                                 /* Upgrade Info Length */
    pCmdBuff[bCmdLen++] = bUpgradeInfo;                         /* Upgrade Info value */

/* Exchange First part of authentication command to card. --------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_CardExchange (
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmdLen,
        PH_ON,
        pCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode));

    /* Check if response consists of correct data size. */
    if (wRespLen_Card != PHAL_MFDFEVX_RESP_PD_CHAL_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFDFEVX);
    }

/* Exchange the First part of AuthenticatePDC command to SAM hardware. ----------------------------------- */
    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part1(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_PDC_AUTH_DERIVE_UPGRADE_KEY,
        (uint8_t) wKeyNum,
        (uint8_t) wKeyVer,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        &bUpgradeInfo,
        0x01U,
        NULL,
        0,
        &pResp_SAM,
        &wRespLen_SAM);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus;
    }

/* Form the command for second part of the authentication sequence. ------------------------------------- */
    bCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    pCmdBuff[bCmdLen++] = PHAL_MFDFEVX_CMD_AUTH2;

    /* Copy the received data from SAM hardware to command buffer. */
    memcpy(&pCmdBuff[bCmdLen], pResp_SAM, wRespLen_SAM);    /* PRQA S 3200 */
    bCmdLen += (uint8_t) wRespLen_SAM;

    /* Exchange second part of authentication command to card. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange (
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        bCmdLen,
        PH_ON,
        pCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    /* Exchange the Second part of Authenticate command to SAM hardware. ------------------------------------- */
    if((bPiccErrCode != 0U) || (wRespLen_Card > 0U))
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part2(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            &bPiccRetCode);

        /* Return the error code. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN)
        {
            /* Compute the response code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Int_ComputeErrorResponse(pDataParams, bPiccErrCode));
        }
    }

    /*
     * Kill PICC Authentication for next SAM call to proceed further
     * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
     * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
     */
    else
    {
        /* Kill the PICC Authentication in Sam hardware. */
        wStatus1 = phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_ChangeKeyPICC(void * pDataParams, uint8_t bCmdType, uint16_t wOption, uint8_t bKeySetNo,
    uint8_t bKeyNoCard, uint16_t wCurrKeyNo, uint16_t wCurrKeyVer, uint16_t wNewKeyNo, uint16_t wNewKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bKeyCompMeth = 0;
    uint8_t     PH_MEMLOC_REM bCfg = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdBuffLen = 0;
    uint8_t *   PH_MEMLOC_REM pCardResponse = NULL;
    uint16_t    PH_MEMLOC_REM wCardRespLen = 0;
    uint16_t    PH_MEMLOC_REM wSamRespLen = 0;
    uint8_t *   PH_MEMLOC_REM pSamResponse = NULL;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM aAppId[3U] = {0x00, 0x00, 0x00};

    /* Only if selected Aid is 0x000000. */
    if (memcmp(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aAppId, 3U) == 0x00)
    {
        if(bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY)
        {
            /* Master key */
            if((bKeyNoCard & 0x3FU) != 0x00)
            {
                /* Invalid card key number supplied */
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
            }
        }
        else
        {
            if(bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2)
            {
                    /* PICC Master key */
                if (((bKeyNoCard & 0x3FU) != 0x00) &&

                    /* PICC DAMAuthKey, DAMMACKey, DAMEncKey */
                    ((bKeyNoCard & 0x3FU) != 0x10U) && ((bKeyNoCard & 0x3FU) != 0x11U) && ((bKeyNoCard & 0x3FU) != 0x12U) &&

                    /* PICC VCConfigurationKey, VCProximityKey, VCSelectMACKey, VCSelectENCKey */
                    ((bKeyNoCard & 0x3FU) != 0x20U) && ((bKeyNoCard & 0x3FU) != 0x21U) && ((bKeyNoCard & 0x3FU) != 0x22U) && ((bKeyNoCard & 0x3FU) != 0x23U) &&

                    /* PICC VCPollingEncKey, VCPollingMACKey */
                    ((bKeyNoCard & 0x3FU) != 0x30U) && ((bKeyNoCard & 0x3FU) != 0x31U) &&

                    /* MFCKillKey, MFCLicenseMACKey */
                    ((bKeyNoCard & 0x3FU) != 0x31U) && ((bKeyNoCard & 0x3FU) != 0x32U))
                {
                    /* Invalid card key number supplied */
                    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
                }
            }
        }
    }
    else
    {
        if(bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2)
        {
            /* Key numbers between 0D and 21 are not allowed for App level, also key numbers above 23 are not allowed.
               if AID 0x000000 is not selected,At application level, VC keys 0x21, 0x22 and 0x23 can be enabled at application creation,
               Refer reference architecture version 13 */
            if (IS_INVALID_APP_KEY(bKeyNoCard) || IS_INVALID_VC_KEY(bKeyNoCard))
            {
                /* Invalid application key specified */
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
            }
        }
        else
        {
            if(bKeyNoCard > 0x0DU)
            {
                /* Invalid application key specified */
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
            }
        }
    }

    /* Validate Keyset number. */
    if ((bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2) && (bKeySetNo > 0x0FU))
    {
        /* Invalid KeySetNo specified */
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Check for valid SAM key number and version. */
    if ((wCurrKeyNo > 0x7FU) || (wCurrKeyVer > 0xFFU) || (wNewKeyNo > 0x7FU) || (wNewKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }


/* Command Exchange with SAM. ---------------------------------------------------------------------------------------------------------- */
    /* Set the key compilation method. */
    if(wOption == PHAL_MFDFEVX_NO_DIVERSIFICATION)
    {
        bKeyCompMeth = 0x00;
    }
    else
    {
        /* Validate diversification input length. */
        if (bDivInputLen > 31U)
        {
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
        }

        /* Validate option information. */
        if(!(wOption & 0x003EU))
        {
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
        }

        /* Assign the option to local variable. */
        bKeyCompMeth = (uint8_t) wOption;
    }

    /* Set if PICC targeted key equal to PICC authenticated key. */
    if ((bKeyNoCard & 0x3FU) == PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo)
    {
        bKeyCompMeth = (uint8_t) (bKeyCompMeth | PHHAL_HW_CMD_SAMAV3_CRYPTO_MODE_SAME_KEY);
    }

    /* Include the key type in the cryptogram for Master Key */
    if ((memcmp(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pAid, aAppId, 3U) == 0x00) &&
        ((bKeyNoCard & 0x3FU) == 0x00))
    {
        bCfg = PHHAL_HW_CMD_SAMAV3_MASTER_KEY_UPDATE_INCLUDE_KEYTYPE;
    }

    /* Set the type of ChagneKey command. */
    bCfg |= (uint8_t) ((bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2) ? PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY_EV2 :
        PHHAL_HW_CMD_SAMAV3_CMD_TYPE_CHANGE_KEY);

    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyPICC(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bKeyCompMeth,
        bCfg,
        bKeySetNo,
        (uint8_t) (0x3FU & bKeyNoCard),
        (uint8_t) wCurrKeyNo,
        (uint8_t) wCurrKeyVer,
        (uint8_t) wNewKeyNo,
        (uint8_t) wNewKeyVer,
        pDivInput,
        bDivInputLen,
        &pSamResponse,
        &wSamRespLen));

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Command Exchange with Card. -------------------------------------------------------------------------------- */
    wCmdBuffLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Frame the command information with command type. */
    pCmdBuff[wCmdBuffLen++] = bCmdType;

    /* Add KeySetNo to command buffer. */
    if (bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2)
    {
        pCmdBuff[wCmdBuffLen++] = bKeySetNo;
    }

    /* Add CardKey number to command buffer. */
    pCmdBuff[wCmdBuffLen++] = bKeyNoCard;

    /* Copy the response received from SAM to Command buffer. */
    memcpy(&pCmdBuff[wCmdBuffLen], pSamResponse, wSamRespLen);  /* PRQA S 3200 */
    wCmdBuffLen += wSamRespLen;

    /* Exchange the command with the card. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE,
        wCmdBuffLen,
        PH_ON,
        pCmdBuff,
        wCmdBuffLen,
        &pCardResponse,
        &wCardRespLen,
        &bPiccErrCode);

    /* Evaluate the response. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus, bPiccErrCode);

    /* Reset the Auth state. */
    if(wStatus != PH_ERR_SUCCESS)
    {
        if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE)
        {
            PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
        }

        return wStatus;
    }
    else
    {
        /* Verify the MAC. */
        if(wCardRespLen)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_VerifySM(
                pDataParams,
                (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS),
                PHAL_MFDFEVX_COMMUNICATION_MACD,
                0,
                NULL,
                0,
                bPiccErrCode,
                pCardResponse,
                wCardRespLen,
                &pSamResponse,
                &wSamRespLen));
        }

        /* Reset authentication status only if the key authenticated with is changed. */
        if (bCmdType == PHAL_MFDFEVX_CMD_CHANGE_KEY_EV2)
        {
            if (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)) && ((bKeySetNo & 0x0FU) == 0))
            {
                PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            }
        }
        else
        {
            if (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo & 0x3FU) == (bKeyNoCard & 0x3FU)))
            {
                PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            }
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_GenerateSM(void * pDataParams, uint16_t wOption, uint8_t bIsWriteCmd, uint8_t bIsReadCmd,
    uint8_t bCommMode, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t * pData, uint16_t wDataLen, uint8_t ** ppOutBuffer,
    uint16_t * pOutBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bOffset = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption = 0;

    /* Exchange the information to Sam hardware to get the MAC information.
     * This computed MAC might not be exchanged. This is computed to initial crypto information in SAM which will be used for MAC verification.
     */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED)
    {
        /* Call the new secure messaging computation interface for EV2 authenticated state. */
        if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
        {
            if(bCommMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN)
            {
                /* Buffer command counter information to SAM. */
                if(pCmdBuff[0] != 0xAFU)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ApplySM(
                        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                        PH_EXCHANGE_DEFAULT,
                        bCommMode,
                        0x00,
                        0x01U,
                        NULL,
                        0,
                        ppOutBuffer,
                        pOutBufLen));
                }
            }
            else
            {
                /* Set the buffering option. */
                wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
                wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);

                /* Compute the Offset to be exchanged. */
                if((bCommMode == PHAL_MFDFEVX_COMMUNICATION_ENC) && (pCmdBuff[0] != 0xAFU))
                {
                    bOffset = (wCmdLen & 0xFF);
                    wBuffOption |= PHHAL_HW_SAMAV3_CMD_APPLY_SM_INCLUDE_OFFSET;
                }

                /* Buffer command information to SAM. */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ApplySM(
                    PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                    wBuffOption,
                    bCommMode,
                    bOffset,
                    0x00,
                    pCmdBuff,
                    (uint8_t) ((pCmdBuff[0] != 0xAFU) ? (wCmdLen & 0xFF) : 0),
                    ppOutBuffer,
                    pOutBufLen));

                /* Buffer data information to SAM and exchange the information to received the SM information. */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ApplySM(
                    PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                    PH_EXCHANGE_BUFFER_LAST,
                    bCommMode,
                    0,
                    0,
                    pData,
                    (uint8_t) wDataLen,
                    ppOutBuffer,
                    pOutBufLen));
            }
        }
        else
        {
            /* Encipher the data. */
            if (bCommMode == PHAL_MFDFEVX_COMMUNICATION_ENC)
            {
                if(!bIsReadCmd)
                {
                    /* Set the buffering flag to Default. */
                    wBuffOption = PH_EXCHANGE_DEFAULT;

                    /* Set the buffering flag to Default. */
                    wBuffOption = (uint16_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) ?
                        PH_EXCHANGE_BUFFER_FIRST : PH_EXCHANGE_DEFAULT);
                    wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);

                    /* If authmode is 0x0A, CRC is needed only on the data */
                    if (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE)
                    {
                        /* Buffer Cmd + Params information to SAM buffer. */
                        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherData(
                            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                            wBuffOption,
                            pCmdBuff,
                            (uint8_t)(wCmdLen & 0xFF),
                            (uint8_t)(wCmdLen & 0xFF),
                            ppOutBuffer,
                            pOutBufLen));

                        /* Update the Buffering flag. */
                        wBuffOption = PH_EXCHANGE_BUFFER_LAST;
                    }

                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherData(
                        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                        wBuffOption,
                        pData,
                        (uint8_t)(wDataLen & 0xFF),
                        0x00,
                        ppOutBuffer,
                        pOutBufLen));
                }
            }
            else
            {
                /* Generate the MAC for AES and DES3K3 key types only. */
                if (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATEEV2)
                {
                    if(bIsWriteCmd || (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE))
                    {
                        /* Set the buffering flag to Default. */
                        wBuffOption = (uint16_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) ?
                            PH_EXCHANGE_BUFFER_FIRST : PH_EXCHANGE_DEFAULT);
                        wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);
                        wBuffOption |= PHHAL_HW_SAMAV3_GENERATE_MAC_INCLUDE_LC;

                        /* Buffer command information. */
                        if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE)
                        {
                            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
                                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                                wBuffOption,
                                0x00, /* Mac based on the Keytype. */
                                pCmdBuff,
                                ((pCmdBuff[0] != 0xAFU) ? (wCmdLen & 0xFF) : 0),
                                ppOutBuffer,
                                pOutBufLen));

                            /* Update the Buffering flag. */
                            wBuffOption = PH_EXCHANGE_BUFFER_LAST;
                        }

                        /* Buffer command information. */
                        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
                            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                            wBuffOption,
                            0x00, /* Mac based on the Keytype. */
                            pData,
                            (uint8_t)(wDataLen & 0xFF),
                            ppOutBuffer,
                            pOutBufLen));
                    }
                }
            }
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_VerifySM(void * pDataParams, uint16_t wOption, uint8_t bCommMode, uint32_t dwLength,
    uint8_t * pResponse, uint16_t wRespLen, uint8_t bPiccStat, uint8_t * pRespMac, uint16_t wRespMacLen,
    uint8_t ** ppOutBuffer, uint16_t * pOutBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bExchangeStatus = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption = 0;
    uint8_t     PH_MEMLOC_REM aLength[3U];

    /* Exchange the information to Sam hardware to get the MAC information. */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED)
    {
        /* Call the new secure messaging verification interface for EV2 authenticated state. */
        if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
            ((bCommMode != PHAL_MFDFEVX_COMMUNICATION_PLAIN)))
        {
            /* Set the buffering flag to Default. */
            wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
            wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);

            /* Set PICC Status to be exchanged for the first frame. */
            if(((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS) &&
                (bPiccStat == PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME))
            {
                bPiccStat = PHAL_MFDFEVX_RESP_OPERATION_OK;
            }

            /* Buffer the PICC status information to Sam buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_RemoveSM(
                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                wBuffOption,
                bCommMode,
                (uint8_t *)&bPiccStat,
                (uint8_t) (((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS)  ? 1U : 0),
                NULL,
                NULL));

            /* Buffer the Plain response information to Sam buffer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_RemoveSM(
                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                PH_EXCHANGE_BUFFER_CONT,
                bCommMode,
                pResponse,
                (uint8_t) wRespLen,
                NULL,
                NULL));

            /* Buffer Mac and Exchange the buffered information to Sam hardware. */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_RemoveSM(
                PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                PH_EXCHANGE_BUFFER_LAST,
                0x00,
                pRespMac,
                (uint8_t) wRespMacLen,
                ppOutBuffer,
                pOutBufLen));
        }
        else
        {
            /* Decipher the data. */
            if(bCommMode == PHAL_MFDFEVX_COMMUNICATION_ENC)
            {
                /* Set the buffering flag to Default. */
                wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
                wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);

                /* Set whether to exchange Status or not. */
                bExchangeStatus = (uint8_t) (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE ? PH_ON : PH_OFF);
                bExchangeStatus = (uint8_t) (((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) != PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS) ? PH_OFF : bExchangeStatus);

                /* Set the Length to be exchanged. */
                if((bCommMode == PHAL_MFDFEVX_COMMUNICATION_ENC) && (dwLength != 0))
                {
                    aLength[0] = (dwLength & 0xFF);
                    aLength[1U] = ((dwLength >> 8U) & 0xFF);
                    aLength[2U] = ((dwLength >> 16U) & 0xFF);
                    wBuffOption |= PHHAL_HW_SAMAV3_DECIPHER_LENGTH_INCLUDE;
                }

                /* Buffer initial set of response. */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherData(
                    PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                    wBuffOption,
                    pResponse,
                    (uint8_t)(wRespLen & 0xFF),
                    aLength,
                    ppOutBuffer,
                    pOutBufLen));

                /* Buffer the final set of response. */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherData(
                    PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                    PH_EXCHANGE_BUFFER_CONT,
                    pRespMac,
                    (uint8_t) wRespMacLen,
                    0,
                    ppOutBuffer,
                    pOutBufLen));

                /* Buffer Status information. */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherData(
                    PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                    PH_EXCHANGE_BUFFER_LAST,
                    &bPiccStat,
                    (uint8_t) (bExchangeStatus ? 1U : 0),
                    0,
                    ppOutBuffer,
                    pOutBufLen));
            }
            else
            {
                if ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATE) &&
                    (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATEEV2))
                {
                    /* Set the buffering flag to Default. */
                    wBuffOption = PH_EXCHANGE_BUFFER_FIRST;
                    wBuffOption |= (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) ? wBuffOption : PH_EXCHANGE_TXCHAINING);

                    /* Buffer the Plain response information to Sam buffer. */
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_VerifyMAC(
                        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                        wBuffOption,
                        0x00, /* Mac based on the Keytype. */
                        pResponse,
                        (uint8_t)(wRespLen & 0xFF)));

                    /* Buffer the PICC status information to Sam buffer. */
                    if((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS)
                    {
                        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_VerifyMAC(
                            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                            PH_EXCHANGE_BUFFER_CONT,
                            0x00, /* Mac based on the Keytype. */
                            &bPiccStat,
                            1U));
                    }

                    /* Buffer Mac and Exchange the buffered information to Sam hardware. */
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_VerifyMAC(
                        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
                        PH_EXCHANGE_BUFFER_LAST,
                        0x00, /* Mac based on the Keytype. */
                        pRespMac,
                        (uint8_t) wRespMacLen));
                }
            }
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_ReadData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint32_t dwLength, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t ** ppResponse,
    uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption = 0;
    uint16_t    PH_MEMLOC_REM wBuffOption1 = 0;
    uint8_t     PH_MEMLOC_REM bFirstFrame = 0;
    uint8_t     PH_MEMLOC_REM bLastFrame = 0;
    uint8_t     PH_MEMLOC_REM bLargeData = 0;
    uint8_t     PH_MEMLOC_REM bFinished = 0;
    uint8_t     PH_MEMLOC_REM bFinished1 = 0;
    uint8_t     PH_MEMLOC_REM bExchangeMac = 0;
    uint8_t *   PH_MEMLOC_REM pMac = NULL;
    uint16_t    PH_MEMLOC_REM wMacLen = 0;
    uint16_t    PH_MEMLOC_REM wOffset = 0;
    uint16_t    PH_MEMLOC_REM wTotLen = 0;
    uint16_t    PH_MEMLOC_REM wRemData = 0;
    uint8_t *   PH_MEMLOC_REM pCardResponse = NULL;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wCardRespLen = 0;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;

    if ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) && (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED))
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
    }

    /* Secure the information to be exchanged. */
    if(((wOption & 0xFF0FU) == PH_EXCHANGE_DEFAULT) && !(wOption & PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM))
    {
         PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_GenerateSM(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            bIsDataCmd,
            bCmd_ComMode,
            pCmdBuff,
            wCmdLen,
            NULL,
            0,
            &pMac,
            &wMacLen));
    }

    /* Set if Mac on command is required. */
    bExchangeMac = (uint8_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? PHALMFDFEVX_SAM_NONX_MAC_ON_CMD :
        PHALMFDFEVX_SAM_NONX_NO_MAC_ON_CMD);

    /* Frame the total length. */
    wTotLen = ((wCmdLen + (bExchangeMac ? wMacLen : 0)) & 0xFFFF);

    /* Set exchange option to First. */
    wBuffOption = (uint16_t) (((wOption & 0xFF0FU) == PH_EXCHANGE_RXCHAINING) ?
        (wOption & 0xFF0FU) : PH_EXCHANGE_BUFFER_FIRST);

    /* Set PICC error validation flag. */
    bOption = (uint8_t) ((wBuffOption == PH_EXCHANGE_RXCHAINING) ? PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE : PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE);

    do
    {
        /* Buffer the command information. */
        wStatus1 = phalMfdfEVx_Sam_NonX_Int_CardExchange(
            pDataParams,
            (uint16_t) ((wBuffOption == PH_EXCHANGE_RXCHAINING) ? PH_EXCHANGE_DEFAULT : wBuffOption),
            bOption,
            wTotLen,
            PH_ON,
            pCmdBuff,
            wCmdLen,
            &pCardResponse,
            &wCardRespLen,
            &bPiccErrCode);

        /* Buffer the Mac information and exchange the complete information to PICC. */
        if((wBuffOption != PH_EXCHANGE_DEFAULT) && ((wBuffOption != PH_EXCHANGE_RXCHAINING)))
        {
            wStatus1 = phalMfdfEVx_Sam_NonX_Int_CardExchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                (uint8_t) (PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE | (wOption & PH_EXCHANGE_CUSTOM_BITS_MASK)),
                0,
                PH_ON,
                pMac,
                (uint16_t) (bExchangeMac ? wMacLen : 0),
                &pCardResponse,
                &wCardRespLen,
                &bPiccErrCode);

            /* Update PICC error validation flag. */
            bOption = (uint8_t) (PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE | (wOption & PH_EXCHANGE_CUSTOM_BITS_MASK));

            /* Set First Frame. */
            bFirstFrame = PH_ON;

            /* Subtract the total length with MAC. */
            wTotLen -= (uint16_t) (bExchangeMac ? wMacLen : 0);
        }

        /* Evaluate the response. */
        wStatus1 = phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus1, bPiccErrCode);

        /* Set the last frame to end the looping. */
        bLastFrame = (uint8_t) ((wStatus1 == PH_ERR_SUCCESS) ? PH_ON : PH_OFF);

        /* Update command information. */
        pCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
        wCmdLen = 1U;

        /* Set the exchange option to RxChaining if there is still more information to be exchanged. */
        wBuffOption = PH_EXCHANGE_DEFAULT;

        /* Update the variables and parameters. */
        if(ppResponse != NULL)
        {
            if(ppResponse[0] != NULL)
            {
                memcpy(&ppResponse[0][wOffset], pCardResponse, (bLastFrame ? (wCardRespLen - wMacLen ) : wCardRespLen));    /* PRQA S 3200 */
            }
            else
            {
                ppResponse[0] = pCardResponse;
            }

            *pRespLen = ((*pRespLen + wCardRespLen) & 0xFFFF);
            wOffset = ((wOffset + wCardRespLen) & 0xFFFF);
        }

        /* Set Largedata flag. */
        bLargeData = (uint8_t) ((wCardRespLen > PHALMFDFEVX_SAM_DATA_FRAME_LENGTH) ? PH_ON : PH_OFF);

        /* Reset the Auth state of PICC only. */
        if((wStatus1 != PH_ERR_SUCCESS) && ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            bFinished = PH_ON;
        }
        else
        {
            /* Perform Secure messaging verification only if required. */
            if(!(wOption & PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM))
            {
                /* Exchange the data to SAM in chunks in case of large amount of data. */
                if(bLargeData)
                {
                    bFirstFrame = PH_ON;
                    bLastFrame = PH_OFF;
                    wTotLen = wCardRespLen;
                    wRemData = wTotLen;
                    wOffset = 0;
                    wCardRespLen = PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
                }

                do
                {
                    /* Set the information for the last frame to be exchanged. */
                    if(bLargeData)
                    {
                        if(wRemData < PHALMFDFEVX_SAM_DATA_FRAME_LENGTH)
                        {
                            wCardRespLen = wRemData;
                            bLastFrame = PH_ON;
                            bFinished1 = PH_ON;
                        }
                    }
                    else
                    {
                        bFinished1 = PH_ON;
                    }

                    /* Set the buffering options. */
                    wBuffOption1 = (uint16_t) (bLastFrame ? PH_EXCHANGE_DEFAULT : PH_EXCHANGE_RXCHAINING);

                    /* Set the PICC status utilization. */
                    if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) && bFirstFrame)
                    {
                        wBuffOption1 |= (uint16_t) PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS;
                    }
                    else
                    {
                        if((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_AUTHENTICATEEV2) && bLastFrame)
                        {
                            wBuffOption1 |= (uint16_t) PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS;
                        }
                    }

                    /* Set the Mac Length. */
                    if(bResp_ComMode != PHAL_MFDFEVX_COMMUNICATION_ENC)
                    {
                        wMacLen = (uint16_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ||
                            (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED) ||
                            ((wOption & 0xFF0FU) == PH_EXCHANGE_RXCHAINING) && !bLastFrame) ? 0 : 8U);

                        /* Set the Mac length for read related command. */
                        if(bIsDataCmd)
                        {
                            wMacLen = (uint16_t) (((bResp_ComMode != PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
                                (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE)) ?
                                4U : wMacLen);

                            /* Set Mac length for EV2 Authenticate state. */
                            wMacLen = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) &&
                                (bResp_ComMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN)) ? 0 : wMacLen);
                        }
                    }

                    /* Verify the security of the received information. */
                    wStatus = phalMfdfEVx_Sam_NonX_Int_VerifySM(
                        pDataParams,
                        wBuffOption1,
                        bResp_ComMode,
                        (bFirstFrame ? dwLength : 0),
                        &pCardResponse[bLargeData ? wOffset : 0],
                        ((wCardRespLen - (bLastFrame ? wMacLen : 0)) & 0xFFFF),
                        bPiccErrCode,
                        &pCardResponse[bLargeData ? (wTotLen - (bLastFrame ? wMacLen : 0)) : (wCardRespLen - (bLastFrame ? wMacLen : 0))],
                        (uint16_t) (bLastFrame ? wMacLen : 0),
                        &pResponse,
                        &wRespLen);

                    /* Copy the response to the buffer. */
                    if((wStatus == PH_ERR_SUCCESS) || ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
                    {
                        if(bResp_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC)
                        {
                            /* Reset the length buffer. */
                            if(bFirstFrame || ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS))
                            {
                                *pRespLen = 0;
                            }

                            memcpy(&ppResponse[0][*pRespLen], pResponse, wRespLen);
                            *pRespLen = (uint16_t) (bLargeData ? (*pRespLen + wRespLen) : wRespLen);
                        }
                    }

                    /* Subtract if Mac is available. */
                    if(pRespLen != NULL)
                    {
                        *pRespLen -= (uint16_t) ((bLastFrame && (bResp_ComMode != PHAL_MFDFEVX_COMMUNICATION_ENC)) ? wMacLen : 0);
                    }

                    /* Validate the status. */
                    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
                    {
                        PH_CHECK_SUCCESS(wStatus);
                    }

                    /* Update offset for large amount of data only. */
                    if(bLargeData)
                    {
                        /* Update the offsets and length. */
                        wOffset = ((wOffset + PHALMFDFEVX_SAM_DATA_FRAME_LENGTH) & 0xFFFF);

                        /* Set the remaining data length to be exchanged. */
                        wRemData -= PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
                    }

                    /* Clear First Frame. */
                    bFirstFrame = PH_OFF;
                }while(!bFinished1);
            }
        }

        /* Set finished flag. */
        if((wStatus1 == PH_ERR_SUCCESS) || ((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS))
        {
            bFinished = PH_ON;
        }
    }while(!bFinished);

    return wStatus1;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_WriteData(void * pDataParams, uint16_t wOption, uint8_t bIsDataCmd, uint8_t bCmd_ComMode,
    uint8_t bResp_ComMode, uint8_t bResetAuth, uint8_t * pCmdBuff, uint16_t wCmdLen, uint8_t * pData, uint32_t dwDataLen,
    uint8_t ** ppResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint16_t    PH_MEMLOC_REM wTotLen = 0;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen_Tmp= 0;
    uint8_t     PH_MEMLOC_REM bExchangeMac = 0;
    uint8_t *   PH_MEMLOC_REM pSMData = NULL;
    uint16_t    PH_MEMLOC_REM wSMDataLen = 0;
    uint8_t *   PH_MEMLOC_REM pCardResponse = NULL;
    uint16_t    PH_MEMLOC_REM wCardRespLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint16_t    PH_MEMLOC_REM wPICCFrameLen = 0;
    uint8_t     PH_MEMLOC_REM bFirstFrame = PH_ON;
    uint8_t     PH_MEMLOC_REM bLastFrame = PH_OFF;
    uint8_t     PH_MEMLOC_REM bDataLen = 0;
    uint8_t     PH_MEMLOC_REM bIns = 0;
    uint8_t     PH_MEMLOC_REM bCmdOption = 0;
    uint8_t     PH_MEMLOC_REM bIsLargeData = 0;
    uint32_t    PH_MEMLOC_REM dwRemLen = 0;
    uint8_t     PH_MEMLOC_REM bAddLen = 0;

    uint16_t    PH_MEMLOC_REM wBuffOption_PICC = 0;
    uint8_t     PH_MEMLOC_REM bFinished_PICC = PH_OFF;
    uint8_t     PH_MEMLOC_REM bPiccExchangeComplete = PH_OFF;
    uint32_t    PH_MEMLOC_REM dwOffset_PICC = 0;

    uint16_t    PH_MEMLOC_REM wBuffOption_SAM = 0;
    uint8_t     PH_MEMLOC_REM bFrameLen_SAM = 0;
    uint32_t    PH_MEMLOC_REM dwOffset_SAM = 0;
    uint32_t    PH_MEMLOC_REM dwRemLen_SAM = 0;
    uint8_t     PH_MEMLOC_REM bSamExchangeComplete = PH_OFF;
    uint8_t     PH_MEMLOC_REM bFinished_SAM = PH_OFF;

    if ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) && (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED))
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_AL_MFDFEVX);
    }

    /* Save the Command code. */
    bCmdCode = pCmdBuff[0];

    /* Save the command information and it length because in course . */
    wCmdLen_Tmp = wCmdLen;

    /* Set the Initial Frame length. */
    bFrameLen_SAM = (dwDataLen & 0xFF);
    dwRemLen_SAM = dwDataLen;
    dwRemLen = dwDataLen;

    /* Get the PICC Frame length. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_GetFrameLen(
        pDataParams,
        &wPICCFrameLen));

    /* Set INS flag if Write command are ISO chaining based.*/
    bIns = (uint8_t) (((bCmdCode == PHAL_MFDFEVX_CMD_WRITE_DATA_ISO) || (bCmdCode == PHAL_MFDFEVX_CMD_WRITE_RECORD_ISO) ||
                       (bCmdCode == PHAL_MFDFEVX_CMD_UPDATE_RECORD_ISO) || (bCmdCode == PHAL_MFDFEVX_CMD_CREATE_MFC_MAPPING)) ? PH_ON : PH_OFF);

    do
    {
        /* Encrypt the information. */
        if(!(wOption & PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM) && (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode != PHAL_MFDFEVX_NOT_AUTHENTICATED))
        {
            if((dwRemLen_SAM > PHALMFDFEVX_SAM_DATA_FRAME_LENGTH))
            {
                bFrameLen_SAM = PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
                wBuffOption_SAM = PH_EXCHANGE_TXCHAINING;
            }
            else
            {
                bFrameLen_SAM = (uint8_t) dwRemLen_SAM;
                wBuffOption_SAM = (uint16_t) ((wOption & PH_EXCHANGE_TXCHAINING) ? PH_EXCHANGE_TXCHAINING : PH_EXCHANGE_DEFAULT);
                bFinished_SAM = PH_ON;
            }

            wStatus = phalMfdfEVx_Sam_NonX_Int_GenerateSM(
                pDataParams,
                wBuffOption_SAM,
                bIsDataCmd,
                PH_OFF,
                bCmd_ComMode,
                pCmdBuff,
                wCmdLen_Tmp,
                &pData[dwOffset_SAM],
                bFrameLen_SAM,
                &pSMData,
                &wSMDataLen);

            /* Validate the status. */
            if((wStatus != PH_ERR_SUCCESS) && ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
            {
                return wStatus;
            }
            else
            {
                if(wStatus == PH_ERR_SUCCESS)
                {
                    /* Set Sam complete exchange flag. */
                    bSamExchangeComplete = PH_ON;

                    if(wSMDataLen < wPICCFrameLen)
                    {
                        bIsLargeData = PH_OFF;
                        dwRemLen = (uint8_t) ((wOption & PHALMFDFEVX_SAM_NONX_EXCHANGE_DATA_PICC) ? dwDataLen : 0);

                        /* Set if Mac on command is required. */
                        bExchangeMac = (uint8_t) ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_MACD) ? PHALMFDFEVX_SAM_NONX_MAC_ON_CMD :
                            PHALMFDFEVX_SAM_NONX_NO_MAC_ON_CMD);
                    }
                    else
                    {
                        bFirstFrame = (uint8_t) ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? PH_ON : PH_OFF);
                    }
                }
            }

            /* Update the lengths. */
            dwRemLen_SAM = dwRemLen_SAM - PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
            dwOffset_SAM += PHALMFDFEVX_SAM_DATA_FRAME_LENGTH;
        }
        else
        {
            bFinished_SAM = PH_ON;
            bSamExchangeComplete = PH_ON;
        }

        /* Set First Frame. */
        if(bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC)
        {
            bFirstFrame = PH_ON;
        }

        if(!bPiccExchangeComplete)
        {
            do
            {
                if(bIsDataCmd)
                {
                    /* Get the frame size that can be transmitted to PICC. */
                    if(bFirstFrame)
                    {
                        /* Set the lengths. */
                        dwRemLen = (bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? wSMDataLen : dwDataLen;

                        /* Check if large amount of data needs to be exchanged. */
                        bIsLargeData = (uint8_t) ((((wCmdLen_Tmp + dwRemLen) > wPICCFrameLen) && !bIns) ? PH_ON : PH_OFF);
                    }

                    /* Performing chunk exchange if large data flag is set. */
                    if(bIsLargeData)
                    {
                        bDataLen = (uint8_t) (wPICCFrameLen - wCmdLen_Tmp);
                        bDataLen = (uint8_t) (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode ? (bDataLen - 6U) : bDataLen);

                        /* Set the completion flag. */
                        if(dwRemLen <= bDataLen)
                        {
                            bDataLen = (uint8_t) dwRemLen;
                            bFinished_PICC = PH_ON;
                            bLastFrame = PH_ON;
                            dwRemLen = 0;
                        }
                    }
                    else
                    {
                        bFinished_PICC = PH_ON;
                        bLastFrame = PH_ON;
                        bDataLen = (uint8_t) dwRemLen;
                    }

                    /* Set PICC Exchange complete for MAC and PLAIN communication. */
                    bPiccExchangeComplete = (uint8_t) ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? PH_OFF : PH_ON);

                    /* Set the command communication mode. */
                    bCmd_ComMode = (uint8_t) (((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_PLAIN) &&
                        ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
                        (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES))) ?
                        PH_OFF : bCmd_ComMode);
                }
                else
                {
                    bFinished_PICC = PH_ON;
                    bLastFrame = PH_ON;
                    bDataLen = (uint8_t) dwRemLen;

                    if(!bIsDataCmd && (bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC))
                    {
                        bDataLen = (uint8_t) wSMDataLen;
                    }
                }

                /* Frame the total length. */
                wTotLen = 0;
                wTotLen = (uint16_t) (wCmdLen_Tmp + ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? bDataLen : dwDataLen));
                wTotLen = (uint16_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode && !bIns) ? ( wCmdLen_Tmp + bDataLen) : wTotLen);
                wTotLen = (uint16_t) ((bExchangeMac && bLastFrame) ? ( wTotLen + wSMDataLen) : wTotLen);

                /* Update the total length. */
                if(bIns)
                {
                    if(bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_MACD)
                    {
                        wTotLen = (uint16_t) (wCmdLen_Tmp + dwRemLen);
                        wTotLen = (uint16_t) ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ? (wTotLen + 4U)  : (wTotLen + 8U));
                    }

                    if(bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC)
                    {
                        bAddLen = (uint8_t) (((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATE) ||
                            (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO)) ? 8U :
                            (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2) ? 24U : 16U);

                        wTotLen = ( uint16_t ) (bIsDataCmd ? (wCmdLen_Tmp + bAddLen + dwDataLen) : (wCmdLen_Tmp + wSMDataLen));
                    }
                }

                /* Set the Buffering option. */
                wBuffOption_PICC = PH_EXCHANGE_BUFFER_FIRST;
                wBuffOption_PICC = (uint16_t) ((bIns && !wCmdLen_Tmp) ? PH_EXCHANGE_BUFFER_CONT : wBuffOption_PICC);

                /* Buffer the command information. */
                PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_CardExchange(
                    pDataParams,
                    wBuffOption_PICC,
                    PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE,
                    wTotLen,
                    PH_OFF,
                    pCmdBuff,
                    wCmdLen_Tmp,
                    NULL,
                    NULL,
                    NULL));

                /* Buffer the data information. */
                if(bCmd_ComMode != PHAL_MFDFEVX_COMMUNICATION_ENC)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_CardExchange(
                        pDataParams,
                        PH_EXCHANGE_BUFFER_CONT,
                        PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE,
                        0,
                        PH_OFF,
                        &pData[dwOffset_PICC],
                        (uint16_t) (bIsLargeData ? bDataLen : dwRemLen),
                        NULL,
                        NULL,
                        NULL));
                }

                /* Set the Buffering option. */
                wBuffOption_PICC = (uint16_t) ((bIns && bLastFrame && bSamExchangeComplete) ? PH_EXCHANGE_BUFFER_LAST : PH_EXCHANGE_BUFFER_CONT);
                wBuffOption_PICC = (uint16_t) (bIns ? wBuffOption_PICC : PH_EXCHANGE_BUFFER_LAST);

                /* Set the PICC status verification. */
                bCmdOption = (uint8_t) ((wBuffOption_PICC == PH_EXCHANGE_BUFFER_LAST) ? PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE :
                    PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE);
                bCmdOption |= (uint8_t) (wOption & PH_EXCHANGE_CUSTOM_BITS_MASK);

                /* Buffer the Mac information exchange the complete information to PICC. */
                wStatus1 = phalMfdfEVx_Sam_NonX_Int_CardExchange(
                    pDataParams,
                    wBuffOption_PICC,
                    bCmdOption,
                    0,
                    PH_ON,
                    &pSMData[(bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? dwOffset_PICC : 0],
                    (uint16_t) ((bCmd_ComMode == PHAL_MFDFEVX_COMMUNICATION_ENC) ? bDataLen : ((bLastFrame && bExchangeMac) ? wSMDataLen : 0)),
                    &pCardResponse,
                    &wCardRespLen,
                    &bPiccErrCode);

                /* Validate the status. */
                if((wStatus1 != PH_ERR_SUCCESS) && ((wStatus1 & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING))
                {
                    bFinished_PICC = PH_ON;
                }

                /* Complete the Exchange and return the status to caller. */
                if(((wOption & PH_EXCHANGE_CUSTOM_BITS_MASK) == PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS) &&
                   ((wStatus1 & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING))
                {
                    bFinished_PICC = PH_ON;
                }

                /* Reset the command information. */
                wCmdLen_Tmp = 0;
                pCmdBuff[0] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;

                if(bIsDataCmd && bIsLargeData)
                {
                    /* Clear the First frame flag. */
                    bFirstFrame = PH_OFF;

                    /* Update length. */
                    dwOffset_PICC += bDataLen;
                    dwRemLen = (uint32_t) (dwRemLen - bDataLen);

                    if(!bIns)
                    {
                        wCmdLen_Tmp++;
                    }
                }
            }while(!bFinished_PICC);

            /* Reset the variables. */
            dwOffset_PICC = 0;
            bDataLen = 0;
            bFinished_PICC = PH_OFF;
        }
        else
        {
            if(wSMDataLen && (bCmd_ComMode != PHAL_MFDFEVX_COMMUNICATION_PLAIN))
            {
                wCmdLen_Tmp = 0;

                /* Add the additional frame information. */
                wBuffOption_PICC = PH_EXCHANGE_BUFFER_LAST;
                if(!bIns)
                {
                    pCmdBuff[wCmdLen_Tmp++] = PHAL_MFDFEVX_RESP_ADDITIONAL_FRAME;
                    wBuffOption_PICC = PH_EXCHANGE_DEFAULT;
                }

                /* Copy the MAC information */
                memcpy(&pCmdBuff[wCmdLen_Tmp], pSMData, wSMDataLen);    /* PRQA S 3200 */
                wCmdLen_Tmp += wSMDataLen;

                /* Buffer the command information. */
                wStatus1 = phalMfdfEVx_Sam_NonX_Int_CardExchange(
                    pDataParams,
                    wBuffOption_PICC,
                    PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE,
                    wCmdLen_Tmp,
                    PH_ON,
                    pCmdBuff,
                    wCmdLen_Tmp,
                    &pCardResponse,
                    &wCardRespLen,
                    &bPiccErrCode);
            }
        }
    }while(!bFinished_SAM);

    /* Perform Secure messaging verification only if required. */
    if(!(wOption & PHALMFDFEVX_SAM_NONX_EXCHANGE_WITHOUT_SM) && !(wOption & PHALMFDFEVX_SAM_NONX_RETURN_CHAINING_STATUS))
    {
        /* Reset the Authentication. */
        if(bResetAuth && (wStatus1 == PH_ERR_SUCCESS))
        {
            if ((PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEISO) ||
                (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEAES) ||
                (PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2))
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            }
        }

        /* Verify the security of the received information. */
        else
        {
            /* Reset the Authentication state if there is an error. */
            if(wStatus1 != PH_ERR_SUCCESS)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
            }
            else
            {
                if(bResp_ComMode != PHAL_MFDFEVX_COMMUNICATION_PLAIN)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_VerifySM(
                        pDataParams,
                        (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS),
                        bResp_ComMode,
                        0,
                        ((bCmdCode == PHAL_MFDFEVX_CMD_COMMIT_TXN) && (wCmdLen == 2U)) ? pCardResponse : NULL,
                        (uint16_t) (((bCmdCode == PHAL_MFDFEVX_CMD_COMMIT_TXN) && (wCmdLen == 2U)) ? 12U : 0),
                        bPiccErrCode,
                        ((bCmdCode == PHAL_MFDFEVX_CMD_COMMIT_TXN) && (wCmdLen == 2U)) ? &pCardResponse[12U] : pCardResponse,
                        (uint16_t) (((bCmdCode == PHAL_MFDFEVX_CMD_COMMIT_TXN) && (wCmdLen == 2U)) ? (wCardRespLen - 12U) : wCardRespLen),
                        ppResponse,
                        pRespLen));

                    if((pRespLen != NULL) && (bResp_ComMode != PHAL_MFDFEVX_COMMUNICATION_ENC))
                    {
                        *ppResponse = pCardResponse;
                        *pRespLen = wCardRespLen;
                    }
                }
            }
        }

        /* Evaluate the response. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_ValidateResponse(pDataParams, wStatus1, bPiccErrCode));
    }
    else
    {
        if(pRespLen != NULL)
        {
            *ppResponse = pCardResponse;
            *pRespLen = wCardRespLen;
        }
    }

    return wStatus1;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_CreateTMFilePICC(void * pDataParams, uint8_t bOption, uint8_t bFileNo, uint8_t bFileOption,
    uint8_t * pAccessRights, uint8_t bTMKeyOption, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t * pTMKey, uint8_t * pDivInput,
    uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t *   PH_MEMLOC_REM pCmdBuff = NULL;
    uint16_t    PH_MEMLOC_REM wCmdBuffSize = 0;
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint16_t    PH_MEMLOC_REM wCardRespLen = 0;
    uint16_t    PH_MEMLOC_REM wSamRespLen = 0;
    uint8_t     PH_MEMLOC_REM bComMode = 0;

    uint8_t*    PH_MEMLOC_REM pCardResponse = NULL;
    uint8_t*    PH_MEMLOC_REM pSamResponse = NULL;

    /* Get the Global parameters. */
    pCmdBuff = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pTmpBuffer;
    wCmdBuffSize = PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->wTmpBufSize;

    /* Command Exchange with Card. -------------------------------------------------------------------------------- */
    wCmdLen = 0;
    memset(pCmdBuff, 0x00, wCmdBuffSize * sizeof(uint8_t)); /* PRQA S 3200 */

    /* Set the dataparams with command code. */
    ((phalMfdfEVx_SamAV3_NonX_DataParams_t *)pDataParams)->bCmdCode = PHAL_MFDFEVX_CMD_CREATE_TRANSTN_MACFILE;

    /* Add the command code. */
    pCmdBuff[wCmdLen++] = PHAL_MFDFEVX_CMD_CREATE_TRANSTN_MACFILE;

    /* Add the file number to command buffer. */
    pCmdBuff[wCmdLen++] = bFileNo;

    /* Add the file options to command buffer. */
    pCmdBuff[wCmdLen++] = bFileOption;

    /* Append access rights. */
    memcpy(&pCmdBuff[wCmdLen], pAccessRights, 2U); /* PRQA S 3200 */
    wCmdLen += 2U;

    /* Add the TM key options to command buffer. */
    pCmdBuff[wCmdLen++] = bTMKeyOption;

    /* Add the key information for not authenticated state. */
    if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_NOT_AUTHENTICATED)
    {
        /* Copy the Transaction MAC key to command buffer. */
        memcpy(&pCmdBuff[wCmdLen], pTMKey, 16U); /* PRQA S 3200 */
        wCmdLen += 16U;

        /* Add key version to command buffer. */
        pCmdBuff[wCmdLen++] = bKeyVer;
    }

    /* Add the information received from SAM. */
    else
    {
        /* Command Exchange with SAM. ----------------------------------------------------------------------------- */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CreateTMFilePICC(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bOption,
            bKeyNo,
            bKeyVer,
            bFileNo,
            bFileOption,
            pAccessRights,
            bTMKeyOption,
            pDivInput,
            bDivInputLen,
            &pSamResponse,
            &wSamRespLen));
    }

    /* Buffer the data. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_NONE,
        (uint16_t) (wCmdLen + wSamRespLen),
        PH_OFF,
        pCmdBuff,
        wCmdLen,
        &pCardResponse,
        &wCardRespLen,
        &bPiccErrCode));

    /* Add the response received from SAM and perform final exchange with the card. */
    wStatus = phalMfdfEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        PHALMFDFEVX_SAM_NONX_CMD_OPTION_COMPLETE,
        0,
        PH_ON,
        pSamResponse,
        wSamRespLen,
        &pCardResponse,
        &wCardRespLen,
        &bPiccErrCode);

    /* Verify the MAC. */
    if(wStatus != PH_ERR_SUCCESS)
    {
        /* Reset the Authentication States. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(pDataParams));
    }
    else
    {
        /* Frame the communication mode to be used. */
        if(PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFDFEVX_AUTHENTICATEEV2)
        {
            bComMode = (uint8_t) (((bFileOption << 4U) == PHAL_MFDFEVX_COMMUNICATION_ENC) ? PHAL_MFDFEVX_COMMUNICATION_MACD : (bFileOption << 4U));
        }
        else
        {
            bComMode = (uint8_t) (bFileOption >> 4U);
        }

        PH_CHECK_SUCCESS_FCT(wStatus, phalMfdfEVx_Sam_NonX_Int_VerifySM(
            pDataParams,
            (uint16_t) (PH_EXCHANGE_DEFAULT | PHALMFDFEVX_SAM_NONX_EXCHANGE_PICC_STATUS),
            bComMode,
            0,
            NULL,
            0,
            bPiccErrCode,
            pCardResponse,
            wCardRespLen,
            &pSamResponse,
            &wSamRespLen));
    }

    return wStatus;
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_ResetAuthStatus(void * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Reset the Authmode and Key number */
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = 0xFFU;
    PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->bKeyNo = 0xFFU;

    /* Kill the PICC Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_PARTIAL));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_GetFrameLen(void * pDataParams, uint16_t * pFrameLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wFrameLen = 0;

    /* Get the frame size that can be transmitted to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_GetConfig(
        PHAL_MFDFEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
        0x04U, /* Get the frame length of PICC and PCD. */
        &wFrameLen));

    /* Update the parameter. */
    switch((uint8_t) (wFrameLen & 0x000FU))
    {
        case 0: *pFrameLen = 16U; break;
        case 1: *pFrameLen = 24U; break;
        case 2: *pFrameLen = 32U; break;
        case 3: *pFrameLen = 40U; break;
        case 4: *pFrameLen = 48U; break;
        case 5: *pFrameLen = 64U; break;
        case 6: *pFrameLen = 96U; break;
        case 7: *pFrameLen = 128U; break;
        case 8: *pFrameLen = 256U; break;

        default:
            break;
    }

    /* Remove the ISO header. */
    *pFrameLen -= 4U;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_GetKeyInfo(void * pDataParams, uint8_t bKeyNo, uint16_t * pKeyType, uint16_t * pSET,
    uint16_t * pExtSET)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wHostMode = 0;
    uint8_t     PH_MEMLOC_REM bIsAV3 = 0;
    uint8_t     PH_MEMLOC_REM bIsRamKey = 0;
    uint8_t     PH_MEMLOC_REM bMode = 0;
    uint8_t     PH_MEMLOC_REM bOffset = 0;
    uint8_t     PH_MEMLOC_REM aKeyEntry[16U];
    uint8_t     PH_MEMLOC_REM bKeyEntryLen = 0;

    /* Get the HostMode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CONFIG_HOSTMODE,
        &wHostMode));

    /* Set the flag. */
    bIsAV3 = (uint8_t) ((wHostMode == PHHAL_HW_SAMAV3_HC_AV3_MODE) ? PH_ON : PH_OFF);
    bIsRamKey = (uint8_t) ((bKeyNo >= 0xE0U) && (bKeyNo <= 0xE3U)) ? PH_ON : PH_OFF;

    /* Set the Mode. */
    bMode = PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_NEW;
    bMode = (uint8_t) (!bIsAV3 ? PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_KEY_ENTRY_SAM_AV2 : bMode);
    bMode = (uint8_t) (bIsRamKey ? PHHAL_HW_SAMAV3_CMD_SAM_GET_KEY_ENTRY_RAM_KEY : bMode);

    /* Get the KeyInformation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bKeyNo,
        bMode,
        aKeyEntry,
        &bKeyEntryLen));

    /* Extract SET configuration. */
    bOffset = (uint8_t) (bIsAV3 ? ((bKeyEntryLen - (uint8_t)6U) & 0xFF) : ((bKeyEntryLen - (uint8_t)3U) & 0xFF));
    *pSET = ((((uint16_t)aKeyEntry[bOffset + 1U] << 8U) | aKeyEntry[bOffset]) & 0xFFFF);

    /* Extract ExtSET configuration. */
    bOffset = (uint8_t) (bIsAV3 ? ((bKeyEntryLen - (uint8_t)4U) & 0xFF) : ((bKeyEntryLen - (uint8_t)1U) & 0xFF));
    *pExtSET = (uint16_t) (((bIsAV3 ? ((uint16_t)aKeyEntry[bOffset + 1U] << 8U) : 0) | aKeyEntry[bOffset]) & 0xFFFF);

    /* Extract the KeyType. */
    *pKeyType = (uint16_t) (*pSET & 0x0078U);

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_ComputeTMACSessionVectors(void * pDataParams, uint8_t bOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aSV[16U];
    uint8_t     PH_MEMLOC_REM aIV[16U];
    uint8_t     PH_MEMLOC_REM bSvLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMC = 0;

    /* Convert TMC to Uint32. */
    dwTMC = ((uint32_t)pTMC[0] | ((uint32_t)pTMC[1U] << 8U) | ((uint32_t)pTMC[2U] << 16U) | ((uint32_t)pTMC[3U] << 24U));

    /* If TMC is 0xFFFFFFFF, then return error */
    if (dwTMC == 0xFFFFFFFFU)
    {
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFDFEVX);
    }

    /* Increment the TMC by 1. */
    dwTMC++;

    /* Clear the session vector SV. */
    memset(aSV, 0, 16U);     /* PRQA S 3200 */
    memset(aIV, 0, 16U);     /* PRQA S 3200 */

    /* Compute the session vector. */
    aSV[bSvLen++] = (uint8_t) ((bOption == PHAL_MFDFEVX_SAM_NONX_SESSION_TMAC_ENC) ? 0xA5U : 0x5AU);
    aSV[bSvLen++] = 0x00;
    aSV[bSvLen++] = 0x01U;
    aSV[bSvLen++] = 0x00;
    aSV[bSvLen++] = 0x80U;

    /* Append the TMC information. */
    aSV[bSvLen++] = (uint8_t) (dwTMC & 0xFFU);
    aSV[bSvLen++] = (uint8_t) ((dwTMC & 0xFF00U) >> 8U);
    aSV[bSvLen++] = (uint8_t) ((dwTMC & 0xFF0000U) >> 16U);
    aSV[bSvLen++] = (uint8_t) ((dwTMC & 0xFF000000U) >> 24U);

    /* Append the UID information. */
    memcpy(&aSV[bSvLen], pUid, bUidLen);    /* PRQA S 3200 */
    bSvLen = 16U;

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        16U));

    /* Exchange the session vector information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DeriveKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t)(wSrcKeyNo & 0xFF),
        (uint8_t)(wSrcKeyVer & 0xFF),
        (uint8_t)(wDstKeyNo & 0xFF),
        aSV,
        16U));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_ComputeSDMSessionVectors(void * pDataParams, uint8_t bOption, uint8_t bSdmOption,
    uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pUid, uint8_t bUidLen, uint8_t * pSDMReadCtr)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aSV[32U];
    uint8_t     PH_MEMLOC_REM bSvLen = 0;
    uint32_t    PH_MEMLOC_REM dwSDMReadCtr = 0;

    /* Validate the Counter value. */
    if(pSDMReadCtr != NULL)
    {
        dwSDMReadCtr = ((uint32_t)pSDMReadCtr[0] | ((uint32_t)pSDMReadCtr[1U] << 8U) | ((uint32_t)pSDMReadCtr[2U] << 16U) | ((uint32_t)pSDMReadCtr[3U] << 24U));
        if (dwSDMReadCtr == 0xFFFFFFU)
        {
            return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFDFEVX);
        }
    }

    /* Clear the session vector SV. */
    memset(aSV, 0, sizeof(aSV));    /* PRQA S 3200 */

    /* Frame the default values in session vector. */
    aSV[bSvLen++] = (uint8_t) ((bOption == PHAL_MFDFEVX_SESSION_ENC) ? 0xC3U : 0x3CU);
    aSV[bSvLen++] = (uint8_t) ((bOption == PHAL_MFDFEVX_SESSION_ENC) ? 0x3CU : 0xC3U);
    aSV[bSvLen++] = 0x00;
    aSV[bSvLen++] = 0x01U;
    aSV[bSvLen++] = 0x00;
    aSV[bSvLen++] = 0x80U;

    /* Append the UID */
    if (bSdmOption & PHAL_MFDFEVX_VCUID_PRESENT)
    {
        if(pUid != NULL)
        {
            memcpy(&aSV[bSvLen], pUid, bUidLen);    /* PRQA S 3200 */
            bSvLen = ((bSvLen + bUidLen) & 0xFF);
        }
        else
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFDFEVX);
    }

    /* Append the SDM ReadCtr information. */
    if (bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT)
    {
        if(dwSDMReadCtr != 0U)
        {
            aSV[bSvLen] = (uint8_t) (dwSDMReadCtr & 0xFFU);
            bSvLen = ((bSvLen + 1U) & 0xFF);
            aSV[bSvLen] = (uint8_t) ((dwSDMReadCtr & 0xFF00U) >> 8U);
            bSvLen = ((bSvLen + 1U) & 0xFF);
            aSV[bSvLen] = (uint8_t) ((dwSDMReadCtr & 0xFF0000U) >> 16U);
            bSvLen = ((bSvLen + 1U) & 0xFF);
        }
    }

    /* Update the SV length */
    if((bSdmOption & PHAL_MFDFEVX_RDCTR_PRESENT) && (bSvLen > 16U))
        bSvLen = 32U;
    else
        bSvLen = 16U;

    /* Exchange the session vector information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DeriveKey(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t)(wSrcKeyNo & 0xFF),
        (uint8_t)(wSrcKeyVer & 0xFF),
        (uint8_t)(wDstKeyNo & 0xFF),
        aSV,
        bSvLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}

phStatus_t phalMfdfEVx_Sam_NonX_Int_LoadSDMInitVector(void * pDataParams, uint8_t * pSDMReadCtr)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint8_t     PH_MEMLOC_REM aIV[16U];
    uint8_t *   PH_MEMLOC_REM pIV = NULL;
    uint16_t    PH_MEMLOC_REM wIvLen = 0;

    /* Clear the Initialization Vector. */
    memset(aIV, 0, 16U);     /* PRQA S 3200 */

    /* IV computation is E(KSesSDMFileReadENC; SDMReadCtr || 0x00000000000000000000000000) */
    memcpy(&aIV[wIvLen], pSDMReadCtr, 3U);   /* PRQA S 3200 */

    /* Set the IV length to 16. */
    wIvLen = 16U;

    /* Encrypt the IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherOfflineData(
        PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        aIV,
        (uint8_t) wIvLen,
        &pIV,
        &wIvLen));

    /* Copy the enciphered data to local buffer. */
    memcpy(aIV, pIV, wIvLen);       /* PRQA S 3200 */
    pIV = NULL;

    /* Set the Option. */
    bOption = PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV;

    /* Load the IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
            PHAL_MFDFEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bOption,
            aIV,
            (uint8_t) wIvLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFDFEVX);
}
#endif /* NXPBUILD__PHAL_MFDFEVX_SAM_NONX */
