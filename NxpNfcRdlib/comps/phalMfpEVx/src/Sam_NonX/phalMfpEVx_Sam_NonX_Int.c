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
* Mifare Plus EVx application's Sam NonX layer's internal component of Reader Library framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phhalHw.h>
#include <ph_RefDefs.h>
#include <string.h>
#include <ph_TypeDefs.h>
#include <phpalMifare.h>
#include <phalMfpEVx.h>

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX

#include "../phalMfpEVx_Int.h"
#include "phalMfpEVx_Sam_NonX_Int.h"

phStatus_t phalMfpEVx_Sam_NonX_Int_ResetSecMsgState(void * pDataParams)
{
    PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bSMMode = (uint8_t)PHAL_MFPEVX_SECURE_MESSAGE_EV0;

    /* State machine should be handled in a way where L3 activation or L4 activation should not be lost */
    if((PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED) ||
       (PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
       (PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_NOT_AUTHENTICATED_L4))
    {
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFPEVX_NOT_AUTHENTICATED_L4;
    }
    else if((PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_NOT_AUTHENTICATED_L3) ||
            (PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED))
    {
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode =  PHAL_MFPEVX_NOT_AUTHENTICATED_L3;
    }
    else
    {
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = PHAL_MFPEVX_NOTAUTHENTICATED;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_CardExchange(void * pDataParams, uint16_t wOption, uint8_t bIsoLayer, uint8_t bLc,
    uint8_t * pPayload, uint16_t wPayloadLen, uint8_t ** ppResponse, uint16_t * pRespLen, uint8_t * pPiccErrCode)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;

    /* Exchange the command to card based on activation level. */
    if(bIsoLayer)
    {
        /* Check if ISO 7816-4 wrapping is required */
        if(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode)
        {
            /* Exchange the command in ISO14443 L4 activated state with ISO7816 wrapping. */
            wStatus = phalMfpEVx_Int_Send7816Apdu(
                PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                (uint16_t) (wOption | PHAL_MFPEVX_IGNORE_PICC_STATUS_CHECK),
                bLc,
                PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu,
                pPayload,
                wPayloadLen,    /* Command code is included as part of length. */
                &pResponse,
                pRespLen);

            /* Send the error code to the user if its not a PICC error. */
            if(pRespLen != NULL)
            {
                if((*pRespLen == 0U) && ((wOption == PH_EXCHANGE_BUFFER_LAST) || (wOption == PH_EXCHANGE_DEFAULT) ||
                    (wOption == PH_EXCHANGE_RXCHAINING)))
                {
                    return wStatus;
                }
            }
        }
        else
        {
            /* Exchange the command in ISO14443 L4 activated state. */
            wStatus = phpalMifare_ExchangeL4(
                PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
                wOption,
                pPayload,
                wPayloadLen,
                &pResponse,
                pRespLen);

            if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
            {
                PH_CHECK_SUCCESS(wStatus);
            }
        }
    }
    else
    {
        /* Exchange the command in ISO14443 L3 activated state. */
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
            PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
            wOption,
            pPayload,
            wPayloadLen,
            &pResponse,
            pRespLen));
    }

    if((wOption == PH_EXCHANGE_DEFAULT) || (wOption == PH_EXCHANGE_BUFFER_LAST) || (wOption == PH_EXCHANGE_RXCHAINING))
    {
        /* Copy the response for Read command only. Other Mifare Classic command will return ACK / NACK / NoResponse / TMC_TMV. */
        if(!bIsoLayer && ((*pRespLen == PHAL_MFPEVX_DATA_BLOCK_SIZE) || (*pRespLen == (PHAL_MFPEVX_SIZE_TMC + PHAL_MFPEVX_SIZE_TMV))))
        {
            /* Add the Response data excluding the status code. */
            *ppResponse = &pResponse[0U];

            /* Update the PICC status code to zero. */
            *pPiccErrCode = 0U;
        }
        else
        {
            if(wOption != PH_EXCHANGE_RXCHAINING)
            {
                /* Add the status code. */
                *pPiccErrCode = pResponse[0U];

                /* Decrement the response length to discard status code. */
                (*pRespLen)--;
            }

            /* Add the Response data excluding the status code. */
            *ppResponse = &pResponse[(wOption == PH_EXCHANGE_RXCHAINING) ? 0U : 1U];

            /* Remove the check if PICC status is not 0xAF. */
            if (wOption != PH_EXCHANGE_RXCHAINING)
            {
                PH_CHECK_SUCCESS_FCT(wStatus1, phalMfpEVx_Int_ComputeErrorResponse(1U, pResponse[0U], bIsoLayer));
            }
        }
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_Int_WriteExtMfc(void * pDataParams, uint8_t bCmdCode, uint8_t bBlockNo, uint8_t * pData,
    uint16_t wDataLen, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2U];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t     PH_MEMLOC_REM aTmpData[4U] = { 0x00, 0x00, 0x00, 0x00 };
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Build command frame */
    aCmdBuff[bCmdLen++] = bCmdCode;
    aCmdBuff[bCmdLen++] = bBlockNo;

    /* Exchange the command frame (first part) */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        0U /* Passing zero because Iso7816 wrapping is not valid for Iso14443-3 protocol. */,
        aCmdBuff,
        bCmdLen,
        &pResponse,
        &wRespLen,
        &bPiccErrCode));

    if((bCmdCode == PHAL_MFPEVX_CMD_MFC_WRITE) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_INCREMENT) ||
        (bCmdCode == PHAL_MFPEVX_CMD_MFC_DECREMENT) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE))
    {
        if(bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE)
        {
            pData = aTmpData;
            wDataLen = 4U;
        }

        /* Exchange the data (second part) */
        bPiccErrCode = 0;
        wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_OFF,
            0U /* Passing zero because Iso7816 wrapping is not valid for Iso14443-3 protocol. */,
            pData,
            wDataLen,
            &pResponse,
            &wRespLen,
            &bPiccErrCode);
    }

    if(bCmdCode == PHAL_MFPEVX_CMD_MFC_RESTORE)
    {
        pData = NULL;
        wDataLen = 0U;
    }

    /* Check for success in the response.
     * The error handling will be performed as follows.
     *    1. If TMC and TMV is not returned, the wRespLen will be one and the error handling will be processed.
     *    2. If TMC and TMV is returned, the wRxLenth will be greater than one. So there will be no error handling
     *       processed rather it will just return.
    */
    if((wStatus &PH_ERR_MASK) != PH_ERR_IO_TIMEOUT)
    {
        /*
         * For Write and transfer commands there will be data in response in case of TM Protected block.
         * If that's the case then the status validation should not be carried out.
         */
        if(wRespLen == 1U)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponseMfc(1U, bPiccErrCode));
        }
    }

    /* Check if TMV and TMC is returned for Write and Transfer command. */
    if((bCmdCode == PHAL_MFPEVX_CMD_MFC_WRITE) || (bCmdCode == PHAL_MFPEVX_CMD_MFC_TRANSFER))
    {
        /* If TMC and TMV is returned the RxLength will be greater than 1. */
        if(wRespLen > 1U)
        {
            /* Check if response equals to sum of TMC and TMV size. */
            if( wRespLen != (PHAL_MFPEVX_SIZE_TMC + PHAL_MFPEVX_SIZE_TMV) )
            {
                return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
            }

            /* Check if NULL is passed for TMC parameter. */
            if( pTMC == NULL )
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
            }

            /* Check if NULL is passed for TMV parameter. */
            if( pTMV == NULL )
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
            }

            memcpy(pTMC, pResponse, PHAL_MFPEVX_SIZE_TMC);  /* PRQA S 3200 */
            memcpy(pTMV, &pResponse[PHAL_MFPEVX_SIZE_TMC], PHAL_MFPEVX_SIZE_TMV);   /* PRQA S 3200 */
        }
        else
        {
            if((pTMC != NULL) && (pTMV != NULL))
            {
                (void) memset(pTMC, 0x00U, PHAL_MFPEVX_SIZE_TMC);
                (void) memset(pTMV, 0x00U, PHAL_MFPEVX_SIZE_TMV);
            }
        }
    }

    /* Get the status for TMI Collection. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Update the contents to TMI buffer. */
    if (dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            aCmdBuff, bCmdLen, pData, wDataLen, PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_ReadExtMfc(void * pDataParams, uint8_t bBlockNo, uint8_t * pBlockData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2U];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Frame the command buffer. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_MFC_READ;
    aCmdBuff[bCmdLen++] = bBlockNo;

    /* Exchange the command. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_OFF,
        0U /* Passing zero because Iso7816 wrapping is not valid for Iso14443-3 protocol. */,
        aCmdBuff,
        bCmdLen,
        &pResponse,
        &wRespLen,
        &bPiccErrCode));

    /* Copy the data to the local buffer. */
    memcpy(pBlockData, pResponse, wRespLen);

    /* Get the status for TMI Collection. */
    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Update the contents to TMI buffer. */
    if (dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            aCmdBuff, bCmdLen, pBlockData, wRespLen, PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMfc(void * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t * pUid, uint8_t bUidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Parameter validation. */
    PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFPEVX);

    /* Authenticate in MFC in Non X mode using Sam layer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_MfcAuthenticateKeyNo(
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pHalSamDataParams,
        bBlockNo,
        bKeyType,
        wKeyNo,
        wKeyVer,
        &pUid[((bUidLen > (uint8_t)4U) ? (bUidLen - (uint8_t)4U) : 0)]));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMFP(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint8_t bKdf,
    uint16_t wBlockNr, uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen,
    uint8_t * pPcdCap2In, uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint8_t     PH_MEMLOC_REM aPcdCap2In[PHAL_MFPEVX_CAPABILITY_SIZE];
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_AUTH_CMD_SIZE];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;

    /* Reset the PCDCap2In buffer to default data if user has not passed any information.  */
    if(pPcdCap2In == NULL)
    {
        (void) memset(aPcdCap2In, 0x00U, sizeof(aPcdCap2In));
        pPcdCap2In = &aPcdCap2In[0U];
    }

    /* Check if PCDCap2[0] consists of value for EV0 and EV1 secure message.
     * If PcdCap[0] = 0x00, then EV0 secure messaging applies.
     * If PcdCap[0] = 0x01, then EV1 secure messaging applies.
     */
    if(pPcdCap2In[0U] > PHAL_MFPEVX_SECURE_MESSAGE_EV1)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Check if bPcdCap2InLen data is not greater than 6. */
    if (bPcdCap2InLen > PHAL_MFPEVX_CAPABILITY_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* In case of first auth or layer 3 communication we need to reset the secure messaging layer */
    if ((bFirstAuth) || (!bLayer4Comm))
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ResetSecMsgState(pDataParams));
    }

    /* Update the Secure messaging data to internal dataparams. */
    if(bFirstAuth)
    {
        ((phalMfpEVx_SamAV3_NonX_DataParams_t *) pDataParams)->bSMMode = pPcdCap2In[0U];
    }

/* Frame the First part of Authenticate command to be sent to card. */
    /* Reset the command buffer and length. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Add the Authentication command code to command buffer. */
    if (bFirstAuth)
    {
        aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_FIRST;
    }
    else
    {
        aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_NON_FIRST;
    }

    /* Append the block number. */
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */

    /* Append PCD Capibilites to command buffer in case of First authentication and Layer 3 / 4 Activated state. */
    if(bFirstAuth)
    {
        /* Update the PCD capability length as zero to command buffer by default. */
        aCmdBuff[bCmdLen++] = 0U;

        if(bLayer4Comm)
        {
            /* Update the PCD capability length to command buffer. */
            aCmdBuff[bCmdLen - 1U] = bPcdCap2InLen;

            memcpy(&aCmdBuff[bCmdLen], pPcdCap2In, bPcdCap2InLen);  /* PRQA S 3200 */
            bCmdLen += bPcdCap2InLen;
        }
    }

/* Exchange First part of authentication command to card ============================================================================= */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange (
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        bLayer4Comm,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode));

    /* Check if response consists of correct data size. */
    if (wRespLen_Card != PHAL_MFPEVX_RESP_PD_CHAL_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

/* Exchange the First part of Authenticate command to SAM hardware ------------------------------------------------------------------- */
    /* Update the option variable with proper authentication type and input PCD Caps. */
    if (!bFirstAuth)
    {
        bOption |= PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_NON_FIRST;
        bPcdCap2InLen = 0U;
    }

    /* Update the option variable with proper diversification information. */
    if (bDivInputLen)
        bOption |= PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_ON;

    /* Update the option variable with key derivation information. */
    bOption |= bKdf;

    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part1(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bOption,
        (uint8_t) wKeyNum,
        (uint8_t) wKeyVer,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        pDivInput,
        bDivInputLen,
        &pResp_SAM,
        &wRespLen_SAM);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        /* Kill the PICC Authentication in Sam hardware. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams), 0x01U));

        /* Return the status. */
        return wStatus;
    }

    /* Check if the response received from SAM is not of required size. */
    if(wRespLen_SAM != PHAL_MFPEVX_RESP_PCD_CHAL_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

/* Exchange Second part of Authentication command (PCDChalResp) to Card ============================================================== */
    /* Reset the command buffer and length. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Frame the command. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_CONTINUE;

    /* Append PCD Challenge response received from SAM. */
    (void) memcpy(&aCmdBuff[1U], pResp_SAM, wRespLen_SAM);
    bCmdLen += (uint8_t) wRespLen_SAM;

    /* Exchange the data. */
    bPiccErrCode = 0U;
    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        bLayer4Comm,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    /* Exchange the Second part of Authenticate command to SAM hardware ------------------------------------------------------------------ */
    if((bPiccErrCode != 0U) && (bLayer4Comm == PH_ON))
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part2(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            &pPdCap2,
            &pPcdCap2Out,
            &bPiccRetCode);

        /* Return the error code. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
        {
            /* Compute the response code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1, bPiccRetCode, bLayer4Comm));
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
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticateMFP_Ext(void * pDataParams, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint8_t     PH_MEMLOC_REM aPcdCap2In[PHAL_MFPEVX_CAPABILITY_SIZE];
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_AUTH_CMD_SIZE];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;
    uint8_t     PH_MEMLOC_REM bValidBits = 0;

    /* Reset the PCDCap2In buffer to default data if user has not passed any information.  */
    if(pPcdCap2In == NULL)
    {
        memset(aPcdCap2In, 0x00, sizeof(aPcdCap2In));   /* PRQA S 3200 */
        pPcdCap2In =  &aPcdCap2In[0];
    }

    /* Check if PCDCap2[0] consists of value for EV0 and EV1 secure message.
     * If PcdCap[0] = 0x00, then EV0 secure messaging applies.
     * If PcdCap[0] = 0x01, then EV1 secure messaging applies.
     */
    if(pPcdCap2In[0U] > PHAL_MFPEVX_SECURE_MESSAGE_EV1)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Check if bPcdCap2InLen data is not greater than 6. */
    if (bPcdCap2InLen > PHAL_MFPEVX_CAPABILITY_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Update the Secure messaging data to internal dataparams. */
    if(bFirstAuth)
    {
        ((phalMfpEVx_SamAV3_NonX_DataParams_t *) pDataParams)->bSMMode = pPcdCap2In[0U];
    }

/* Frame the First part of Authenticate command to be sent to card. */
    /* Reset the command buffer and length. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Add the Authentication command code to command buffer. */
    if (bFirstAuth)
    {
        aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_FIRST;
    }
    else
    {
        aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_NON_FIRST;
    }

    /* Append the block number. */
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */

    /* Append PCD Capabilities to command buffer in case of First authentication and Layer 3 / 4 Activated state. */
    if(bFirstAuth)
    {
        /* Update the PCD capability length as zero to command buffer by default. */
        aCmdBuff[bCmdLen++] = 0U;
    }

/* Exchange First part of authentication command to card ============================================================================= */
    /* Perform L3 exchange to get the data before CRYPTO1 processing. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeRaw(
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT | PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT,
        aCmdBuff,
        bCmdLen,
        bValidBits,
        &pResp_Card,
        &wRespLen_Card,
        &bValidBits));

    /* NACK Handling */
    if ((wRespLen_Card == 1U) && (bValidBits == 4U))
    {
        /*
         * Special case. If only 4 bit status is received, we need the actual decrypted value
         * Perform actual deciphering
         */
        wStatus = phhalHw_SamAV3_Cmd_SAM_DecipherData(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PH_EXCHANGE_DEFAULT,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            NULL,
            &pResp_SAM,
            &wRespLen_SAM);

        /* Bail out on Error */
        if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
        {
            return wStatus;
        }

        PH_CHECK_SUCCESS_FCT(wStatus1, phalMfpEVx_Int_ComputeErrorResponse(wRespLen_Card, pResp_SAM[0], PH_OFF));
    }

/* Exchange the First part of Authenticate command to SAM hardware ------------------------------------------------------------------- */
    /* Update the option variable with proper authentication type and input PCD Caps. */
    if (!bFirstAuth)
    {
        bOption |= PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_NON_FIRST;
        bPcdCap2InLen = 0U;
    }

    /* Update the option variable with proper diversification information. */
    if (bDivInputLen)
        bOption |= PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_DIVERSIFICATION_ON;

    /* Update the option variable with key derivation information. */
    bOption |= PHAL_MFPEVX_SECURITY_LEVEL_1_KDF;

    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part1(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bOption,
        (uint8_t) wKeyNum,
        (uint8_t) wKeyVer,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        pDivInput,
        bDivInputLen,
        &pResp_SAM,
        &wRespLen_SAM);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        /* Kill the PICC Authentication in Sam hardware. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams), 0x01U));

        /* Return the status. */
        return wStatus;
    }

/* Exchange Second part of Authentication command (PCDChalResp) to Card ============================================================== */

    /* Perform L3 exchange to get the data before CRYPTO1 processing. */
    bValidBits = 3U;
    wStatus = phpalMifare_ExchangeRaw(
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT | PHHAL_HW_SAMAV3_EXCHANGE_NO_ENCIPHERING_BIT | PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT,
        pResp_SAM,
        wRespLen_SAM,
        bValidBits,
        &pResp_Card,
        &wRespLen_Card,
        &bValidBits);

    /* NACK Handling */
    if ((wRespLen_Card == 1U) && (bValidBits == 4U))
    {
        PH_CHECK_SUCCESS_FCT(wStatus1, phalMfpEVx_Int_ComputeErrorResponse(wRespLen_Card, pResp_Card[0U], PH_OFF));
    }


    /* Validate the status. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        /* Kill the PICC Authentication in Sam hardware. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams), 0x01U));

        /* Return the status. */
        return wStatus;
    }

/* Exchange the Second part of Authenticate command to SAM hardware ------------------------------------------------------------------ */
    /* Set the PICC error code to 0x90 as the next command requires a SUCCESS code. */
    bPiccErrCode = PHAL_MFPEVX_RESP_ACK_ISO4;

    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticateMFP_Part2(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bPiccErrCode,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        &pPdCap2,
        &pPcdCap2Out,
        &bPiccRetCode);

    /* Return the error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
    {
        /* Compute the response code. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccRetCode, PH_ON));
    }
    else
    {
        /* Return the error code other than success.*/
        if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
        {
            /* Kill the PICC Authentication in Sam hardware. */
            PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams), 0x01U));

            /* Return the status. */
            return wStatus;
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthSectorSwitchMFP(void * pDataParams, uint8_t bOption, uint16_t wSSKeyBNr,
    uint16_t wSSKeyNr, uint16_t wSSKeyVer, uint8_t bLenDivInputSSKey, uint8_t * pDivInputSSKey, uint8_t bSecCount,
    uint16_t *pSectorNos, uint16_t *pKeyNo, uint16_t *pKeyVer, uint8_t bLenDivInputSectorKeyBs,
    uint8_t * pDivInputSectorKeyBs)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[35U];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;
    uint8_t     PH_MEMLOC_REM bIteration = 0;
    uint8_t     PH_MEMLOC_REM aKeyBlocks[256U];
    uint8_t     PH_MEMLOC_REM bKeyBlocksLen = 0;
    uint8_t     PH_MEMLOC_REM aDivInput[65U];
    uint8_t     PH_MEMLOC_REM bDivInputLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;

/* Frame the First part command and send it to Card. ------------------------------------------------------------------ */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_SSAUTH;
    aCmdBuff[bCmdLen++] = (uint8_t)(wSSKeyBNr & 0x00FFU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)((wSSKeyBNr & 0xFF00U) >> 8U);   /* MSB */
    aCmdBuff[bCmdLen++] = (uint8_t)(bSecCount);

    /* Buffer the command information to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PH_ON,
        (((bCmdLen - 1U /* Excluding the command code. */) + (bSecCount * 2U)) & 0xFFU),
        aCmdBuff,
        bCmdLen,
        NULL,
        NULL,
        NULL));

    /* Buffer Sector numbers to exchange buffer and exchange the buffered information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        PH_ON,
        0U,
        (uint8_t *) pSectorNos,
        (uint16_t) (bSecCount * 2U),
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode));

    /* Verify the received data length. */
    if (wRespLen_Card != PHAL_MFPEVX_RESP_PD_CHAL_SIZE )
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

/* Exchange the response received from card to SAM. ------------------------------------------------------------------- */
    /* Reset KeyBlocks buffer and its length variable. */
    bKeyBlocksLen = 0U;
    (void) memset(aKeyBlocks, 0x00U, sizeof(aKeyBlocks));

    /* Add Sector numbers and its KeyNo and KeyVer. */
    for(bIteration = 0U; bIteration < bSecCount; bIteration++)
    {
        aKeyBlocks[bKeyBlocksLen++] = (uint8_t) ((pSectorNos[bIteration]) & 0x00FFU);
        aKeyBlocks[bKeyBlocksLen++] = (uint8_t) ((pSectorNos[bIteration] & 0xFF00U) >> 8U);

        if((bOption & 0x04U) != 0x04U /* Master Key disabled. */)
        {
            aKeyBlocks[bKeyBlocksLen++] = (uint8_t) pKeyNo[bIteration];
            aKeyBlocks[bKeyBlocksLen++] = (uint8_t) pKeyVer[bIteration];
        }
    }

    /* Reset DivInput buffer and its length variable. */
    bDivInputLen = 0U;
    (void) memset(aDivInput, 0x00U, sizeof(aDivInput));

    /* Add Sector Switch Key diversification input. */
    if(bOption & 0x01U)
    {
        /* Add the length information. */
        aDivInput[bDivInputLen++] = bLenDivInputSSKey;

        /* Add the diversification input. */
        memcpy(&aDivInput[bDivInputLen], pDivInputSSKey, bLenDivInputSSKey); /* PRQA S 3200 */
        bDivInputLen += bLenDivInputSSKey;
    }

    if(bOption & 0x02U)
    {
        /* Adding the length information because diversification input for Sector keys are different. */
        if(bLenDivInputSectorKeyBs)
        {
            aDivInput[bDivInputLen++] = bLenDivInputSectorKeyBs;
        }

        /* Adding the length information as zero because diversification input for Sector keys are same. */
        else
        {
            aDivInput[bDivInputLen++] = 0x00U;
        }

        memcpy(&aDivInput[bDivInputLen], pDivInputSectorKeyBs, bLenDivInputSectorKeyBs); /* PRQA S 3200 */
        bDivInputLen += bLenDivInputSectorKeyBs;
    }

    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part1(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bOption,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        wSSKeyBNr,
        (uint8_t) wSSKeyNr,
        (uint8_t) wSSKeyVer,
        (uint8_t) pKeyNo[0U],
        (uint8_t) pKeyVer[0U],
        bSecCount,
        aKeyBlocks,
        bKeyBlocksLen,
        aDivInput,
        bDivInputLen,
        &pResp_SAM,
        &wRespLen_SAM);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus;
    }

    /* Frame the Second part command and send it to Card. ----------------------------------------------------------------- */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Frame second part of SSAuthenticate command. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_SSAUTHC;

    /* Append the PCD challenge received from SAM. */
    (void) memcpy(&aCmdBuff[1U], pResp_SAM, wRespLen_SAM);
    bCmdLen += (uint8_t) wRespLen_SAM;

    /* Exchange the framed data to card. */
    bPiccErrCode = 0U;
    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    /* Exchange the response received from card to SAM. ------------------------------------------------------------------- */
    if(bPiccErrCode != 0U)
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_AuthSectorSwitchMFP_Part2(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            &bPiccRetCode);

        /* Return the error code. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
        {
            /* Compute the response code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1, bPiccRetCode, PH_ON));
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
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_Int_AuthenticatePDC(void * pDataParams, uint16_t wBlockNr, uint16_t wKeyNum, uint16_t wKeyVer,
    uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bUpgradeInfo)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[39U];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;

    /* Reset the command buffer and its length variable. */
    bCmdLen = 0;
    memset(aCmdBuff, 0x00, sizeof(aCmdBuff));   /* PRQA S 3200 */

    /* Frame the command*/
    bCmdLen = 0U;
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH_PDC;
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr & 0x00FFU);            /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)((wBlockNr & 0xFF00U) >> 8U);    /* MSB */
    aCmdBuff[bCmdLen++] = 0x01U;                                    /* Upgrade Info Length */
    aCmdBuff[bCmdLen++] = bUpgradeInfo;                         /* Upgrade Info value */

/* Exchange First part of authentication command to card. --------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange (
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode));

    /* Check if response consists of correct data size. */
    if (wRespLen_Card != PHAL_MFPEVX_RESP_PD_CHAL_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
    }

/* Exchange the First part of AuthenticatePDC command to SAM hardware. ----------------------------------- */
    wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part1(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_PDC_AUTH_DERIVE_UPGRADE_KEY,
        (uint8_t) wKeyNum,
        (uint8_t) wKeyVer,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        &bUpgradeInfo,
        0x01U,
        pDivInput,
        bDivInputLen,
        &pResp_SAM,
        &wRespLen_SAM);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        return wStatus;
    }

    /* Form the command for second part of the authentication sequence. -------------------------------------- */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_AUTH2;

    /* Copy the received data from SAM hardware to command buffer. */
    (void) memcpy(&aCmdBuff[bCmdLen], pResp_SAM, wRespLen_SAM);
    bCmdLen += (uint8_t) wRespLen_SAM;

    /* Exchange second part of authentication command to card. */
    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange (
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    if(bPiccErrCode != 0U)
    {
        /* Exchange the Second part of Authenticate command to SAM hardware. ------------------------------------- */
        wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticatePDC_Part2(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            &bPiccRetCode);

        /* Return the error code. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN)
        {
            /* Compute the response code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1, bPiccErrCode, PH_ON));
        }
    }

    /*
     * Kill PICC Authentication for next SAM call to proceed further
     * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
     * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
     */
    else
    {
        wStatus1 = phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(void * pDataParams, uint8_t bCmdCode, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pData, uint8_t bDataLen, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_COMBINED_WRITE_CMD_SIZE + 1 /* Allocate Ext */];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_SAM = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_SAM = 0;

    uint8_t     PH_MEMLOC_REM bTMIBufLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Reset the command buffer and its length variable. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

/* Frame the command and send it to card and SAM. ---------------------------------------------------------------------------- */
    aCmdBuff[bCmdLen++] = bCmdCode;
    aCmdBuff[bCmdLen++] = (uint8_t)(wSrcBlockNr & 0xFFU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)(wSrcBlockNr >> 8U);   /* MSB */

    if ((bCmdCode == PHAL_MFPEVX_CMD_INCRTR) || (bCmdCode == PHAL_MFPEVX_CMD_INCRTR_M) ||
        (bCmdCode == PHAL_MFPEVX_CMD_DECRTR) || (bCmdCode == PHAL_MFPEVX_CMD_DECRTR_M))
    {
        aCmdBuff[bCmdLen++] = (uint8_t)(wDstBlockNr & 0xFFU); /* LSB */
        aCmdBuff[bCmdLen++] = (uint8_t)(wDstBlockNr >> 8U);   /* MSB */
    }

    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        /* For Write commands. */
        if ((bCmdCode == PHAL_MFPEVX_CMD_WRITE_EM) || (bCmdCode == PHAL_MFPEVX_CMD_WRITE_EN) ||
            (bCmdCode == PHAL_MFPEVX_CMD_WRITE_PM) || (bCmdCode == PHAL_MFPEVX_CMD_WRITE_PN))
        {
            /* For TMI buffering. */
            aCmdBuff[bCmdLen] = (uint8_t) (bDataLen / PHAL_MFPEVX_DATA_BLOCK_SIZE);

            /* Update the TMI Buffer length. */
            bTMIBufLen = (uint8_t) (bCmdLen + 1U);
        }

        /* For Value commands. */
        else
        {
            /* Update the TMI Buffer length. */
            bTMIBufLen = bCmdLen;
        }

        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            aCmdBuff, bTMIBufLen, pData, bDataLen, PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

/* Send the command buffer to SAM for encrypting the data and calculating the MAC if required. ------------------------------ */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_BUFFER_FIRST | PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_COMMAND,
        aCmdBuff,
        bCmdLen,
        NULL,
        NULL,
        NULL));

    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_BUFFER_LAST,
        pData,
        bDataLen,
        &pResp_SAM,
        &wRespLen_SAM,
        NULL));

/* Exchange the data received from SAM to the card. ------------------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        PH_ON,
        (uint8_t) ((bCmdLen - 1U /* Excluding the command code. */) + wRespLen_SAM),
        aCmdBuff,
        bCmdLen,
        NULL,
        NULL,
        NULL));

    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        PH_ON,
        0U /* Passing zero because the complete information is passes in the previous exchange. */,
        pResp_SAM,
        wRespLen_SAM,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    /* Update the parameters to actual response. */
    if(wRespLen_Card > PHAL_MFPEVX_TRUNCATED_MAC_SIZE)
    {
        (void) memcpy(pTMC, &pResp_Card[0U], PHAL_MFPEVX_SIZE_TMC);
        (void) memcpy(pTMV, &pResp_Card[PHAL_MFPEVX_SIZE_TMC], PHAL_MFPEVX_SIZE_TMV);
    }

/* Send the received data to SAM for processing the MAC is available. -------------------------------------------------------- */
    /* Clear the command buffer. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Append the Response code. */
    aCmdBuff[bCmdLen++] = bPiccErrCode;

    /* Exchange the command to SAM for MAC verification if MAC is returned by the Card. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_BUFFER_FIRST | PHHAL_HW_SAMAV3_OPTION_COMBINED_WRITE_MFP_RESPONSE,
        aCmdBuff,
        bCmdLen,
        &pResp_SAM,
        &wRespLen_SAM,
        &bPiccErrCode));

    wStatus = phhalHw_SamAV3_Cmd_SAM_CombinedWriteMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_BUFFER_LAST,
        pResp_Card,
        (uint8_t) wRespLen_Card,
        &pResp_SAM,
        &wRespLen_SAM,
        &bPiccRetCode);

    /* Return the error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
    {
        /* Compute the response code. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccRetCode, PH_ON));
    }
    else
    {
        /* Return the error code other than success.*/
        if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
        {
            return wStatus;
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_CombinedReadMFP(void * pDataParams, uint8_t bCmdCode, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pBlocks)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_COMBINED_READ_CMD_SIZE];
    uint8_t     PH_MEMLOC_REM bFinished = 0;
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Sam = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Sam = 0;
    uint8_t     PH_MEMLOC_REM bPayloadType = 0;
    uint8_t     PH_MEMLOC_REM bLFI = 0x00;
    uint16_t    PH_MEMLOC_REM wOption = PH_EXCHANGE_DEFAULT;
    uint16_t    PH_MEMLOC_REM wRemBytes = 0;
    uint16_t    PH_MEMLOC_REM wDataLen = 0;
    uint16_t    PH_MEMLOC_REM wOffset = 0;
    uint16_t    PH_MEMLOC_REM wOffset1 = 0;
    uint8_t     PH_MEMLOC_REM bMacLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Compute the Payload Type information. */
    if (bCmdCode < PHAL_MFPEVX_CMD_READ_ENU /* Command code from which the MacOnCmd is not available. */ )
    {
        /* This payload type will be used if Cmd.SAM_CombinedRead called for Mac On Command calculation.
         * Which means the PICC command information will first be exchanged with Sam, then with PICC and
         * at last again to the Sam.
         *
         * For this type the following will be applicable.
         *      First exchange will be performed with Sam to receive MAC. Then the MAC will be appended with
         *      command and will be exchange with PICC. The PICC response will then be exchange with SAM again.
         *      If the data is encrypted, Sam will decrypt the data and respond the plain data.
         *      If the data is not encrypted, Sam will not respond back the data.
         */
        bPayloadType = PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE;
    }
    else
    {
        /* This payload type will be used if Cmd.SAM_CombinedRead is not called for Mac On Command calculation.
         * Which means the PICC command information will first be exchanged with PICC and at last it will be
         * exchanged with Sam.
         *
         * For this type the following will be applicable.
         *      First exchange will be performed with PICC and the data will be received. The received data along
         *      with command information and PICC status code will be exchanged with SAM.
         *      If the data is encrypted, Sam will decrypt the data and respond the plain data.
         *      If the data is not encrypted, Sam will not respond back the data.
         */
        bPayloadType = PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH;
    }

    /* Update the variable if MacOnResponse is available. This variable is used to remove the Mac if
     * PICC response data is PLAIN as SAM will not respond back the data.
     */
    if(bCmdCode & 0x01U)
    {
        bMacLen = 8U;
    }

    /* Reset the command buffer and its length variable. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = bCmdCode;
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr & 0xFFU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t)(wBlockNr >> 8U);   /* MSB */
    aCmdBuff[bCmdLen++] = bNumBlocks;

    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING, aCmdBuff, bCmdLen, NULL, 0U, PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

/* Exchange the command information to Sam for MAC reception ------------------------------------------------------------------------- */
    if (bPayloadType == PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE )
    {
        /* Get the Mac for command information from Sam hardware. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME,
            PH_EXCHANGE_DEFAULT | PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_COMMAND,
            aCmdBuff,
            bCmdLen,
            &pResp_Sam,
            &wRespLen_Sam,
            &bPiccErrCode));
    }

/* Exchange the command information to PICC ========================================================================================== */
    wOption = PH_EXCHANGE_BUFFER_LAST;
    do
    {
        /* Buffer the command information to exchange buffer. */
        if(wOption != PH_EXCHANGE_RXCHAINING)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CardExchange(
                pDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                PH_ON,
                (((bCmdLen - 1U /* Excluding the command code. */) + wRespLen_Sam) & 0xFF),
                aCmdBuff,
                bCmdLen,
                NULL,
                NULL,
                NULL));
        }

        /* Buffer the SAM's response information to exchange buffer and exchange the bufferred information card. */
        wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
            pDataParams,
            wOption,
            PH_ON,
            0U /* Passing zero because the complete information is passes in the previous exchange. */,
            pResp_Sam,
            (uint16_t) ((wOption == PH_EXCHANGE_RXCHAINING) ? 0U : wRespLen_Sam),
            &pResp_Card,
            &wRespLen_Card,
            &bPiccErrCode);

        memcpy(&pBlocks[wOffset], pResp_Card, wRespLen_Card);  /* PRQA S 3200 */

        /* Update the Buffering Option to Chaining. */
        if((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_CHAINING)
        {
            wOption = PH_EXCHANGE_RXCHAINING;
        }
        else
        {
            bFinished = PH_ON;
        }

        /* Set the offset. */
        wOffset += wRespLen_Card;

    }while(!bFinished);

    /* Check the response if Mac On Cmd is not executed. */
    if (bPayloadType == PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH )
    {
        /* Check the response only if status is not AF. */
        if ( bPiccErrCode != PHAL_MFPEVX_RESP_ADDITIONAL_FRAME )
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccErrCode, PH_ON));
        }
    }

    /* Update the variables. */
    wRemBytes = wOffset;
    wDataLen = wOffset;

    /* Update buffering option to First. */
    wOption = PH_EXCHANGE_BUFFER_FIRST;

    /* Update LFI in case if there are more than one frame. */
    if(wRemBytes > PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE)
    {
        /* Update the remaining bytes. */
        wDataLen = PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE;

        bLFI = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
    }

/* Exchange the information to SAM --------------------------------------------------------------------------------------------------- */
    /* Add the command information to Sam exchange buffer if the payload is BOTH. */
    if(bPayloadType == PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_BOTH)
    {
        /* Buffer command information to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bLFI,
            wOption | bPayloadType,
            aCmdBuff,
            bCmdLen,
            NULL,
            NULL,
            NULL));

        /* Update buffering option to CONT. */
        wOption = PH_EXCHANGE_BUFFER_CONT;
    }

    /* Buffer Picc error code to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        bLFI,
        wOption | bPayloadType,
        &bPiccErrCode,
        1U,
        NULL,
        NULL,
        NULL));

    /* Update buffering option to Last. */
    wOption = PH_EXCHANGE_BUFFER_LAST;

    /* Clear PICC error variable. */
    bPiccErrCode = 0U;

    /* Start the chaining loop */
    wOffset = 0U;
    do
    {
        /* Buffer Picc response data to exchange buffer. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bLFI,
            wOption | bPayloadType,
            &pBlocks[wOffset],
            (uint8_t) wDataLen,
            &pResp_Sam,
            &wRespLen_Sam,
            &bPiccRetCode);

        /* Check for chaining response. */
        if(bLFI == PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME)
        {
            /* Check if chaining status is returned from HAL. */
            if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
            {
                /* Clear the memory in case of error. */
                (void) memset(pBlocks, 0U, bNumBlocks * 16U);

                return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFPEVX);
            }
        }
        /* Check for PICC status information. */
        else if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
        {
            /* Clear the memory in case of error. */
            (void) memset(pBlocks, 0U, bNumBlocks * 16U);

            /* Compute the PICC error response. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccRetCode, PH_ON));
        }
        /* Check for other status information. */
        else
        {
            if(wStatus != PH_ERR_SUCCESS)
            {
                /* Clear the memory in case of error. */
                (void) memset(pBlocks, 0U, bNumBlocks * 16U);
            }

            PH_CHECK_SUCCESS(wStatus);
        }

        /* Copy the data to the parameter. */
        memcpy(&pBlocks[wOffset1], pResp_Sam, wRespLen_Sam);  /* PRQA S 3200 */
        wOffset1 += (uint16_t) wRespLen_Sam;

        /* Update the variables. */
        wOffset += PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE;
        wRemBytes = (uint16_t) (wRemBytes - PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE);

        /* Update buffering option to DEFAULT. */
        wOption = PH_EXCHANGE_DEFAULT;

        /* Reset the Payload Type. */
        bPayloadType = 0U;

        /* Update LFI in case if there are more than one frame. */
        if(wRemBytes > PHAL_MFPEVX_SAM_COMBINED_READ_MAX_FRAME_SIZE)
        {
            bLFI = PHHAL_HW_SAMAV3_ISO7816_CHAINED_FRAME;
        }
        /* Update the LFI flag if last frame. */
        else
        {
            wDataLen = wRemBytes;
            bLFI = PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME;
        }

    } while (wStatus != (PH_ERR_MASK & PH_ERR_SUCCESS));

    /* Clear the MAC information. */
    (void) memset(&pBlocks[bNumBlocks * 16U], 0U, 8U);

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams,
            PH_TMIUTILS_NO_PADDING, NULL, 0U, pBlocks, (bNumBlocks * 16U), PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFP);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_ChangeKeyMFP(void * pDataParams, uint8_t bCommand, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bOption = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_CHANGE_KEY_CMD_SIZE];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM aPayload[36U];
    uint8_t     PH_MEMLOC_REM bPayloadLen = 0;

    /* Reset the payload buffer and its length variable. */
    bPayloadLen = 0U;
    (void) memset(aPayload, 0x00U, sizeof(aPayload));

    /* Frame the payload to be sent to Sam hardware. */
    aPayload[bPayloadLen++] = bCommand;
    aPayload[bPayloadLen++] = (uint8_t) (wBlockNr & 0x00FFU);
    aPayload[bPayloadLen++] = (uint8_t) ((wBlockNr & 0xFF00U) >> 8U);
    aPayload[bPayloadLen++] = (uint8_t)(wKeyNum & 0xFF);
    aPayload[bPayloadLen++] = (uint8_t)(wKeyVer & 0xFF);

    /* Update option variable with diversification off flag. */
    bOption = PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_OFF;

    /* Add Diversification input to command buffer. */
    if(bDivInputLen)
    {
        bOption = PHHAL_HW_SAMAV3_MFP_CHANGE_KEY_DIVERSIFICATION_ON;

        /* Add the DivInput information to command buffer. */
        memcpy(&aPayload[bPayloadLen], pDivInput, bDivInputLen);    /* PRQA S 3200 */
        bPayloadLen = ((bPayloadLen + bDivInputLen) & 0xFF);
    }

    /* Exchange the details to SAM hardware and get the protected data --------------------------------------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ChangeKeyMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t) (PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_COMMAND | bOption),
        aPayload,
        bPayloadLen,
        &pResponse,
        &wRespLen,
        NULL));

    /* Exchange the command information to the card ================================================================================== */

    /* Reset the command buffer and its length variable. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = bCommand;
    aCmdBuff[bCmdLen++] = (uint8_t) (wBlockNr & 0xffU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t) (wBlockNr >> 8U);   /* MSB */

    /* Append the protected data to command buffer. */
    memcpy(&aCmdBuff[bCmdLen], pResponse, wRespLen);    /* PRQA S 3200 */
    bCmdLen += (uint8_t) wRespLen;

    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResponse,
        &wRespLen,
        &bPiccErrCode);

    /*Exchange the response received from card to SAM hardware ----------------------------------------------------------------------- */

    /* Reset the payload buffer and its length variable. */
    bPayloadLen = 0U;
    (void) memset(aPayload, 0x00U, sizeof(aPayload));

    /* Add Picc return code. */
    aPayload[bPayloadLen++] = bPiccErrCode;

    /* Add the response received from PICC. */
    memcpy(&aPayload[bPayloadLen], pResponse, wRespLen);    /* PRQA S 3200 */
    bPayloadLen += (uint8_t) wRespLen;

    /* Reset the buffers and variables. */
    pResponse = NULL;
    wRespLen = 0U;
    bPiccErrCode = 0U;

    /* Exchange the details to SAM hardware and get the protected data. */
    wStatus = phhalHw_SamAV3_Cmd_SAM_ChangeKeyMFP(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_OPTION_MFP_CHANGE_KEY_RESPONSE,
        aPayload,
        bPayloadLen,
        &pResponse,
        &wRespLen,
        &bPiccRetCode);

    /* Return the error code. */
    if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
    {
        /* Compute the response code. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccRetCode, PH_ON));
    }
    else
    {
        /* Return the error code other than success.*/
        if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
        {
            return wStatus;
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_CommitReaderID(void * pDataParams, uint16_t wBlockNr, uint8_t * pEncTMRI)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_MFPEVX_COMMIT_READER_ID_CMD_SIZE];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Sam = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Sam = 0;
    uint32_t    PH_MEMLOC_REM dwTMIStatus = 0;

    /* Exchange the details to SAM hardware and get the TMRI and MAC. */
    wStatus = phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part1(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_CMD_SAMAV3_COMMIT_READER_ID_PICC_STATE_MFP,
        wBlockNr,
        &pResp_Sam,
        &wRespLen_Sam);

    /* Verify if Success chaining response is received from SAM. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
        return wStatus;

    /* Reset the command buffer and its length variable. */
    bCmdLen = 0U;
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_COMMIT_READER_ID;
    aCmdBuff[bCmdLen++] = (uint8_t) (wBlockNr & 0xffU); /* LSB */
    aCmdBuff[bCmdLen++] = (uint8_t) (wBlockNr >> 8U);   /* MSB */

    /* Append TMRI and MAC information received from SAM to command buffer. */
    memcpy(&aCmdBuff[bCmdLen], pResp_Sam, wRespLen_Sam);    /* PRQA S 3200 */
    bCmdLen += (uint8_t) wRespLen_Sam;

    /* Exchange the command information to card. */
    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        PH_ON,
        (uint8_t) (bCmdLen - 1U /* Excluding the command code. */),
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

    if(bPiccErrCode != 0U)
    {
        /*Exchange the response received from card to SAM hardware. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_CommitReaderID_Part2(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            bPiccErrCode,
            pResp_Card,
            (uint8_t) wRespLen_Card,
            &bPiccRetCode);

        /* Return the error code. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN)
        {
            /* Compute the response code. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1, bPiccRetCode, PH_ON));
        }
    }

    /*
     * Kill PICC Authentication for next SAM call to proceed further
     * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
     * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
     */
    else
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            0x01U);
    }

    /* Update the pEncTMRI parameter. */
    memcpy(pEncTMRI, pResp_Card, 16U);  /* PRQA S 3200 */

    PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_GetConfig(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_TMI_STATUS,
        &dwTMIStatus));

    /* Check TMI Collection Status */
    if (dwTMIStatus)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phTMIUtils_CollectTMI(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pTMIDataParams, PH_TMIUTILS_NO_PADDING,
            aCmdBuff, (uint16_t) (bCmdLen - 8U /* Removing the MAC */), pEncTMRI, PHAL_MFPEVX_SIZE_ENCTMRI, PHAL_MFPEVX_DATA_BLOCK_SIZE));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Int_ComputeTMACSessionVectors(void * pDataParams, uint8_t bOption, uint16_t wSrcKeyNo,
    uint16_t wSrcKeyVer, uint16_t wDstKeyNo, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aSV[16];
    uint8_t     PH_MEMLOC_REM aIV[16];
    uint8_t     PH_MEMLOC_REM bSvLen = 0;
    uint32_t    PH_MEMLOC_REM dwTMC = 0;

    /* Convert TMC to Uint32. */
    dwTMC = ((uint32_t)pTMC[0U] | ((uint32_t)pTMC[1U] << 8U) | ((uint32_t)pTMC[2U] << 16U) | ((uint32_t)pTMC[3U] << 24U));

    /* If TMC is 0xFFFFFFFF, then return error */
    if (dwTMC == 0xFFFFFFFFU)
    {
        return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_AL_MFPEVX);
    }

    /* Increment the TMC by 1. */
    dwTMC++;

    /* Clear the session vector SV. */
    (void) memset(aSV, 0U, 16U);
    (void) memset(aIV, 0U, 16U);

    /* Compute the session vector. */
    aSV[bSvLen++] = (uint8_t) ((bOption == PHAL_MFPEVX_SAM_NONX_SESSION_TMAC_ENC) ? 0xA5U : 0x5AU);
    aSV[bSvLen++] = 0x00U;
    aSV[bSvLen++] = 0x01U;
    aSV[bSvLen++] = 0x00U;
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
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        16U));

    /* Exchange the session vector information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DeriveKey(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        (uint8_t)(wSrcKeyNo & 0xFF),
        (uint8_t)(wSrcKeyVer & 0xFF),
        (uint8_t)(wDstKeyNo & 0xFF),
        aSV,
        bSvLen));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */
