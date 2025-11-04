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

#include <ph_Status.h>
#include <phhalHw.h>
#include <phalVca.h>
#include <phpalMifare.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHAL_VCA_SAM_NONX

#include "../phalVca_Int.h"
#include "phalVca_Sam_NonX.h"


#ifdef NXPBUILD__PHAL_VCA_SAMAV3_NONX
#include <phhalHw_SamAV3_Cmd.h>
#endif /* NXPBUILD__PHAL_VCA_SAMAV3_NONX */


#ifdef NXPBUILD__PHAL_VCA_SAMAV3_NONX
phStatus_t phalVca_SamAV3_NonX_Init(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, phhalHw_SamAV3_DataParams_t * pSamHal,
    void * pPalMifareDataParams)
{
    if(sizeof(phalVca_SamAV3_NonX_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_VCA);
    }

    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_AL_VCA);
    PH_ASSERT_NULL_PARAM(pPalMifareDataParams, PH_COMP_AL_VCA);
    PH_ASSERT_NULL_PARAM(pSamHal, PH_COMP_AL_VCA);

    /* init private data */
    pDataParams->wId = PH_COMP_AL_VCA | PHAL_VCA_SAMAV3_NONX_ID;
    pDataParams->pPalMifareDataParams = pPalMifareDataParams;
    pDataParams->pSamHal = pSamHal;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_IsoSelect(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bSelectionControl, uint8_t bOption, uint8_t bDFnameLen,
    uint8_t * pDFname, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t bEncKeyNo, uint8_t bEncKeyVer, uint8_t bMacKeyNo, uint8_t bMacKeyVer,
    uint8_t * pResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_VCA_CMD_SIZE];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM aLE[2];
    uint8_t *   PH_MEMLOC_REM pPICC_Response = NULL;
    uint16_t    PH_MEMLOC_REM wPICC_RespLen = 0;
    uint8_t *   PH_MEMLOC_REM pSAM_Response = NULL;
    uint16_t    PH_MEMLOC_REM wSAM_RespLen = 0;

    if((pDFname == NULL) || (bDFnameLen > 16))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_VCA);
    }
    if(bSelectionControl != 0x04)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_VCA);
    }

    /* Clear the buffers. */
    memset(aCmdBuff, 0x00, sizeof(aCmdBuff));   /* PRQA S 3200 */
    memset(aLE, 0x00, sizeof(aLE)); /* PRQA S 3200 */

    /* Frame the command buffer */
    aCmdBuff[wCmdLen++] = 0x00;
    aCmdBuff[wCmdLen++] = PHAL_VCA_CMD_ISOSVC;
    aCmdBuff[wCmdLen++] = bSelectionControl;
    aCmdBuff[wCmdLen++] = 0x00;

    if(pDataParams->bExtendedLenApdu)
    {
        aCmdBuff[wCmdLen++] = 0x00;
        aCmdBuff[wCmdLen++] = 0x00;
    }

    aCmdBuff[wCmdLen++] = bDFnameLen;

    /* Buffer the command inforamtion to exchange buffer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        aCmdBuff,
        wCmdLen,
        NULL,
        NULL));

    /* Buffer DFName and exchange the bufferred information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_CONT,
        pDFname,
        bDFnameLen,
        NULL,
        NULL));

    /* Command exchange with Le. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        aLE,
        (uint16_t) (pDataParams->bExtendedLenApdu ? 2 : 1),
        &pPICC_Response,
        &wPICC_RespLen));

    /* Compute the status from PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_ComputeErrorResponse_Extended(pDataParams,
        (uint16_t) ((pPICC_Response[wPICC_RespLen - 2] << 8) | pPICC_Response[wPICC_RespLen - 1])));

    /* AuthVCMandatory is set. */
    if(wPICC_RespLen == (PHAL_VCA_AUTH_RND_LEN + 6 /* TLV Header + Status*/))
    {
        /* Remove the status code. */
        wPICC_RespLen -= 2;

        if((pPICC_Response[0] == 0x6F) && (pPICC_Response[1] == 0x22) && (pPICC_Response[2] == 0x85) && (pPICC_Response[3] == 0x20))
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_SelectVC(
                pDataParams->pSamHal,
                bOption,
                bEncKeyNo,
                bEncKeyVer,
                bMacKeyNo,
                bMacKeyVer,
                &pPICC_Response[4 /* TLV Header */],
                (uint8_t) (wPICC_RespLen - 4 /* TLV Header */),
                pDivInput,
                bDivInputLen,
                &pSAM_Response,
                &wSAM_RespLen));

            /* Copy the VCData to the response buffer. */
            memcpy(pResponse, pSAM_Response, wSAM_RespLen); /* PRQA S 3200 */
            *pRespLen = wSAM_RespLen;
        }

        /* Case-3: [if TargetVC != NULL AND TargetVC.AuthVCMandatory == false AND (IID is DESFire application DF name)]
        * FCI[36] bytes shall be stored in file ID 31 of the DF */
        else
        {
            memcpy(pResponse, pPICC_Response, wPICC_RespLen);   /* PRQA S 3200 */
            *pRespLen = wPICC_RespLen;
        }
    }

    /* AuthVCMandatory flag is not set and IsoSelect is success */
    else if(wPICC_RespLen == 2)
    {
        *pRespLen = (uint16_t) (wPICC_RespLen - 2);
    }

    /* AuthVCMandatory flag is not set and FileID is returned */
    else
    {
        memcpy(pResponse, pPICC_Response, (wPICC_RespLen - 2)); /* PRQA S 3200 */
        *pRespLen = (wPICC_RespLen - 2);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_IsoExternalAuthenticate(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pInData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[PHAL_VCA_CMD_SIZE];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the parameter. */
    if(pInData == NULL)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_VCA);
    }

    /* Prepare "IsoExternlAuthenticate" command. */
    aCmdBuff[wCmdLen++] = 0x00;                     /* Class is always 0x00 */
    aCmdBuff[wCmdLen++] = PHAL_VCA_CMD_ISOEXT_AUTH; /* INS */
    aCmdBuff[wCmdLen++] = 0x00;                     /* P1 */
    aCmdBuff[wCmdLen++] = 0x00;                     /* P2 */

    if(pDataParams->bExtendedLenApdu)
    {
        aCmdBuff[wCmdLen++] = 0x00;
        aCmdBuff[wCmdLen++] = 0x00;
    }

    aCmdBuff[wCmdLen++] = 0x08; /* MAC length. */

    /* Copy the Input information to Command buffer. */
    memcpy(&aCmdBuff[wCmdLen], pInData, 8); /* PRQA S 3200 */
    wCmdLen += 8;

    /* Exchange the bufferred information to PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT,
        aCmdBuff,
        wCmdLen,
        &pResponse,
        &wRespLen));

    /* Compute the status from PICC. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_ComputeErrorResponse_Extended(pDataParams,
        (uint16_t) ((pResponse[wRespLen - 2] << 8) | pResponse[wRespLen - 1])));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_ProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bGenerateRndC, uint8_t * pPrndC,
    uint8_t bNumSteps, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pDivInput, uint8_t bDivInputLen, uint8_t * pOption,
    uint8_t * pPubRespTime, uint8_t * pResponse, uint16_t * pRespLen, uint8_t * pCumRndRC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aPPCData[10];
    uint8_t     PH_MEMLOC_REM bPPCDataLen = 0;
    uint8_t     PH_MEMLOC_REM aResponse[10];
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t *   PH_MEMLOC_REM pMac = NULL;
    uint8_t     PH_MEMLOC_REM bPiccRetCode = 0;

    /* Perform Prepare PC command execution with PICC */
    PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_PrepareProximityCheckNew(
        pDataParams,
        pOption,
        pPubRespTime,
        pResponse,
        pRespLen));

    /* Frame PPCData buffer. */
    aPPCData[bPPCDataLen++] = *pOption;
    aPPCData[bPPCDataLen++] = pPubRespTime[0];
    aPPCData[bPPCDataLen++] = pPubRespTime[1];

    /* Add [PPS1] || [ActBitRate] information to PPCData buffer if set in Option. */
    memcpy(&aPPCData[bPPCDataLen], pResponse, *pRespLen);   /* PRQA S 3200 */
    bPPCDataLen += (uint8_t) *pRespLen;

    /* Perform Proximity Check with PICC */
    PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_ExecuteProximityCheckNew(
        pDataParams,
        bGenerateRndC,
        pPrndC,
        pPubRespTime,
        bNumSteps,
        pCumRndRC));

    /* Perform Proximity check part 1 exchange with SAM */
    wStatus = phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part1(
        pDataParams->pSamHal,
        (uint8_t) (bDivInputLen ? PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_ON : PHHAL_HW_SAMAV3_CMD_PROXIMITY_CHECK_DIV_OFF),
        (uint8_t) wKeyNo,
        (uint8_t) wKeyVer,
        aPPCData,
        bPPCDataLen,
        pCumRndRC,
        16,
        pDivInput,
        bDivInputLen,
        &pMac,
        &wRespLen);

    /* Check if chaining status is returned from HAL. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        /* Return the status. */
        return wStatus;
    }

    /* Perform Verify PC with PICC */
    wStatus = phalVca_Sam_NonX_VerifyProximityCheckNew(
        pDataParams,
        pMac,
        aResponse,
        &wRespLen);

    /* Perform Proximity check part 2 exchange with SAM */
    if(wRespLen > 0U)
    {
        wStatus = phhalHw_SamAV3_Cmd_SAM_ProximityCheck_Part2(
            pDataParams->pSamHal,
            aResponse,
            (uint8_t) wRespLen,
            &bPiccRetCode);

        /* Validate the response. */
        if((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, bPiccRetCode));
        }
        else
        {
            PH_CHECK_SUCCESS(wStatus);
        }
    }

    /*
    * Kill PICC Authentication for next SAM call to proceed further
    * This code update is based on information mentioned in MIFARE SAM AV3 known deviations from specification
    * section 5.2, to overcome the issue where if there is no payload for PART-2 exchange.
    */
    else
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(
            pDataParams->pSamHal,
            PHHAL_HW_SAMAV3_CMD_SAM_KILL_AUTHENTICATION_PARTIAL));
    }

    return wStatus;
}

phStatus_t phalVca_Sam_NonX_PrepareProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pOption,
    uint8_t * pPubRespTime, uint8_t * pResponse, uint16_t * pRespLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pResponse_Tmp = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Tmp = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[] = {PHAL_VCA_CMD_PPC};
    uint8_t     PH_MEMLOC_REM bOffset = 0;

    /* Exchange the data in ISO7816 format. */
    if(pDataParams->bWrappedMode)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_SendISOWrappedCmd(
            pDataParams,
            aCmdBuff,
            0x00,   /* Lc Value */
            &pResponse_Tmp,
            &wRespLen_Tmp));

        /* Validate the status. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse_Tmp[wRespLen_Tmp - 1]));

        /* Adjusting the response length i.e. removing the status code. */
        wRespLen_Tmp -= 2;
    }

    /* Exchange the data in Native format. */
    else
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuff,
            1,
            &pResponse_Tmp,
            &wRespLen_Tmp));

        /* Validate the status. */
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse_Tmp[0]));

        /* Incrementing the Index to point the response data */
        pResponse_Tmp++;

        /* Adjusting the response length i.e. removing the status code. */
        wRespLen_Tmp--;
    }

    /* Save Option from response data. */
    *pOption = pResponse_Tmp[bOffset++];

    /* Save Published Response Time from response data. */
    pPubRespTime[0] = pResponse_Tmp[bOffset++];
    pPubRespTime[1] = pResponse_Tmp[bOffset++];

    /* Save PPS from response data */
    if(*pOption & 0x01)
    {
        *pResponse = pResponse_Tmp[bOffset];
        *pRespLen = 1;
    }

    /* Save ActBitRate from response data */
    if(*pOption & 0x02)
    {
        memcpy(pResponse, &pResponse_Tmp[bOffset], (wRespLen_Tmp - bOffset));
        *pRespLen = (uint8_t) (wRespLen_Tmp - bOffset);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_ExecuteProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bGenerateRndC,
    uint8_t * pPrndC, uint8_t * pPubRespTime, uint8_t bNumSteps, uint8_t * pCumRndRC)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bRndC[PHAL_VCA_SAMAV3_PC_RND_LEN];
    uint8_t     PH_MEMLOC_REM aCmdBuff[1 /* Command */ + 1 /* RndCLen */ + 8 /* RndC */];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint8_t     PH_MEMLOC_REM bPayloadLen = 0;
    uint8_t     PH_MEMLOC_REM bRndCLen = 0;
    uint8_t     PH_MEMLOC_REM bRndRCLen = 0;
    uint16_t    PH_MEMLOC_REM wValue = 0;
    uint16_t    PH_MEMLOC_REM wThresholdTimeUpperLimit = 0;
    uint16_t    PH_MEMLOC_REM wThresholdTimeLowerLimit = 0;

    /* Validate the parameters. */
    if (((bGenerateRndC == 0) && (pPrndC == NULL)) || (pCumRndRC == NULL))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_VCA);
    }

    /* Frame the command. */
    aCmdBuff[0] = PHAL_VCA_CMD_PC;

    /* Get the random number from SAM. */
    if (bGenerateRndC)
    {
        pPrndC = bRndC;

        /* Get the Random Number from SAM */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetRandom(pDataParams->pSamHal, 0x08, pPrndC));
    }

    /* Exchange the ProximityCheck information.
     * Steps = 1: Only one iteration is made, All 8 random bytes in one Cmd.ProxmityCheck.
     * Steps = 2: Sends the first 1 random bytes in one Cmd.ProxmityCheck and the remaining 7 random byte in another one.
     * Steps = 3: 1 in one Cmd.ProxmityCheck, 1 in Second and remaining 6 in Third.
     * Steps = 4: 1 in one Cmd.ProxmityCheck, 1 in Second, 1 in third and remaining 6 in Foruth.
     * Steps = 5: 1 in one Cmd.ProxmityCheck, 1 in Second, 1 in third, 1 in fourth and remaining 4 in Fifth.
     * Steps = 6: 1 in one Cmd.ProxmityCheck, 1 in Second, 1 in third, 1 in fourth, 1 in Fifth and remaining 4 in Fifth.
     * Steps = 7: 1 in one Cmd.ProxmityCheck, 1 in Second, 1 in third, 1 in fourth, 1 in Fifth, 1 in Sixth and remaining 2 in Fifth.
     * Steps = 8: Sends 8 Cmd.ProxmityCheck with one random byte for each Exchange.
     */
    while (bNumSteps)
    {
    	bNumSteps = ((bNumSteps - 1U) & 0xFF);

        /* RndC length */
        if (bNumSteps)
        {
            bPayloadLen = 1;
        }
        else
        {
            bPayloadLen = PHAL_VCA_SAMAV3_PC_RND_LEN - bRndCLen;
        }

        /* Length */
        aCmdBuff[1] = bPayloadLen;

        /* RndC */
        memcpy(&aCmdBuff[2], &pPrndC[bRndCLen], bPayloadLen);   /* PRQA S 3200 */

        /* Get the bOption value for the checking the timing measurement ON/OFF */
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_GetConfig(pDataParams, PHAL_VCA_TIMING_MODE, &wValue));

        /* Start collecting the RC timeout. */
        if(wValue & 0x01)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pSamHal, PHHAL_HW_CONFIG_TIMING_MODE, PHHAL_HW_TIMING_MODE_FDT));
        }

        /* Exchange the data in ISO7816 format. */
        if(pDataParams->bWrappedMode)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_SendISOWrappedCmd(
                pDataParams,
                aCmdBuff,
                (uint8_t) (1 + bPayloadLen),   /* bPayloadLen + RndC */
                &pResponse,
                &wRespLen));

            PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse[wRespLen - 1]));

            /* Adjusting the response length i.e. removing the status code. */
            wRespLen -= 2;
        }

        /* Exchange the command in Native format. */
        else
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_DEFAULT,
                aCmdBuff,
                (uint16_t)2U + bPayloadLen,    /* (INS + bPayloadLen) + RndC */
                &pResponse,
                &wRespLen));

            /*
             * Response validation should not be performed in case if the length is
             *      1 byte  : One byte can be either a valid response or a error code which is difficult to identify
             *      0 byte  : If there is response, the passed value will be any number from the pointer which will
             *                result in false errors.
             */
            if ((wRespLen != bPayloadLen) && (bPayloadLen != 0) && (bPayloadLen != 1))
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Int_ComputeErrorResponse_Extended(pDataParams, pResponse[wRespLen - 1]));
            }
        }

        /* Copy RndR */
        memcpy(&pCumRndRC[bRndRCLen], pResponse, wRespLen);         /* PRQA S 3200 */
        bRndRCLen = bRndRCLen + (uint8_t) wRespLen;

        /* Copy RndC */
        memcpy(&pCumRndRC[bRndRCLen], &pPrndC[bRndCLen], wRespLen);  /* PRQA S 3200 */
        bRndRCLen = bRndRCLen + (uint8_t) wRespLen;
        bRndCLen = bRndCLen + (uint8_t) wRespLen;

        /* Get the bOption value for the checking the timing measurement ON/OFF */
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_GetConfig(pDataParams, PHAL_VCA_TIMING_MODE, &wValue));
        if(wValue & 0x01)
        {
            /* Compute threshold time from PubRespTime. Threshold time = pubRespTime + 10% of pubRespTime */
            wThresholdTimeUpperLimit = pPubRespTime[0];
            wThresholdTimeUpperLimit <<= 8;
            wThresholdTimeUpperLimit |= pPubRespTime[1];

            /* As per the ref arch V0.17, the threshold time should not be 20% beyond the Lower bound of PubResp Time. */
            wThresholdTimeLowerLimit = (wThresholdTimeUpperLimit * 80) / 100;

            /* Get the last command execution time */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pSamHal, PHHAL_HW_CONFIG_TIMING_US, &wValue));

            /* If the response is not received within the threshold time, return internal error */
            if(wValue > wThresholdTimeUpperLimit || wValue < wThresholdTimeLowerLimit)
            {
                return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_AL_VCA);
            }
        }
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_VerifyProximityCheckNew(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pMac,
    uint8_t * pResponse, uint16_t * pRespLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[9];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse_Tmp = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Frame the command. */
    aCmdBuff[bCmdLen++] = PHAL_VCA_CMD_VPC;

    /* Append MAC to command buffer. */
    memcpy(&aCmdBuff[bCmdLen], pMac, PHAL_VCA_SAMAV3_TRUNCATED_MAC_SIZE);
    bCmdLen += PHAL_VCA_SAMAV3_TRUNCATED_MAC_SIZE;

    /* Exchange the data in ISO7816 format. */
    if(pDataParams->bWrappedMode)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalVca_Sam_NonX_SendISOWrappedCmd(
            pDataParams,
            aCmdBuff,
            (uint8_t) (bCmdLen - 1), /* Cmd Code excluded. */
            &pResponse_Tmp,
            &wRespLen));

        /* Adjusting the response length i.e. removing the status code. */
        if(wRespLen > 2)
        {
            wRespLen -= 2;
        }
        else
        {
            wRespLen -= 1;
            pResponse_Tmp++;
        }
    }

    /* Exchange the command in Native format. */
    else
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
            pDataParams->pPalMifareDataParams,
            PH_EXCHANGE_DEFAULT,
            aCmdBuff,
            bCmdLen,
            &pResponse_Tmp,
            &wRespLen));

        /* Adjusting the response length i.e. removing the status code. */
        if(wRespLen > 1)
        {
            wRespLen -= 1;
            pResponse_Tmp++;
        }
    }

    /* Copy the response to the parameter. */
    memcpy(pResponse, pResponse_Tmp, wRespLen); /* PRQA S 3200 */
    *pRespLen = wRespLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_SetConfig(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    switch(wConfig)
    {
        case PHAL_VCA_ADDITIONAL_INFO:
            pDataParams->wAdditionalInfo = wValue;
        break;

        case PHAL_VCA_WRAPPED_MODE:
            pDataParams->bWrappedMode = (wValue & 0xFF);
            break;

        case PHAL_VCA_PC_EXTENDED_APDU:
            pDataParams->bExtendedLenApdu = (wValue & 0xFF);
            break;

        case PHAL_VCA_TIMING_MODE:
            pDataParams->bOption = (wValue & 0xFF);
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_VCA);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_GetConfig(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    switch(wConfig)
    {
        case PHAL_VCA_ADDITIONAL_INFO:
            *pValue = pDataParams->wAdditionalInfo;
        break;

        case PHAL_VCA_WRAPPED_MODE:
            *pValue = pDataParams->bWrappedMode;
            break;

        case PHAL_VCA_PC_EXTENDED_APDU:
            *pValue = pDataParams->bExtendedLenApdu;
            break;

        case PHAL_VCA_TIMING_MODE:
            *pValue = pDataParams->bOption;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_VCA);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_SendISOWrappedCmd(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint8_t * pCmdBuff, uint8_t bLc,
    uint8_t ** pResponse, uint16_t * pRespLen)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;
    uint8_t    PH_MEMLOC_REM bApduLen = 4;  /* Initializing with 4 since Length of the Data(Lc) starts from 4th element of pApdu[] */
    uint8_t    PH_MEMLOC_REM pApdu[8] = {0x90 /* CLS */, 0x00 /* INS */, 0x00 /* P1 */, 0x00 /* P2 */, 0x00 , 0x00, 0x00 /* Lc */, 0x00 /* Le */};

    /* Check for permissible CmdBuff size */
    if(bLc > PHAL_VCA_MAXWRAPPEDAPDU_SIZE)
    {
        return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_AL_MFDFEVX);
    }

    pApdu[1] = pCmdBuff[0];  /* Proximity Check Command Code. */

    switch(pApdu[1])
    {
        case PHAL_VCA_CMD_PPC:
            pApdu[4] = 0x00;    /* These bytes will be treated as Le */
            pApdu[5] = 0x00;    /* For extended length Apdu support */

            /* Exchange the information to PICC. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_DEFAULT,
                pApdu,
                (uint16_t)pDataParams->bExtendedLenApdu ? 7U : 5U,  /* 2 bytes Le should be passed in case of Extended Length Apdu since Lc field is not present */
                pResponse,
                pRespLen));
            break;

        case PHAL_VCA_CMD_PC:
        case PHAL_VCA_CMD_VPC:
            /* To Note: Extended APDU will be used,
             *  When user forces the 'length' to be sent as Extended length APDU. */
            if(!pDataParams->bExtendedLenApdu)
            {
                /* Encode 'Length' in Short APDU format */
                pApdu[bApduLen++] = (uint8_t) bLc; /* Set Data Length. */
            }
            else
            {
                /* Encode 'Length' in extended Length format */
                pApdu[bApduLen++] = 0x00;
                pApdu[bApduLen++] = 0x00;
                pApdu[bApduLen++] = (uint8_t) bLc; /* Set Data Length. */
            }

            /* Exchange the information to PICC. */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_FIRST,
                pApdu,
                bApduLen,
                pResponse,
                pRespLen));

            /* Check for Lc value */
            if(bLc > 0)
            {
                /* Transmit data as continued buffer */
                PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                    pDataParams->pPalMifareDataParams,
                    PH_EXCHANGE_BUFFER_CONT,
                    &pCmdBuff[1],
                    bLc,
                    pResponse,
                    pRespLen));
            }

            /* Resetting bApduLen for further use in case of Le */
            bApduLen = 0;
            if(!pDataParams->bExtendedLenApdu)
            {
                /* Encode 'Length' in Short APDU format */
                pApdu[bApduLen++] = 0x00; /* Set the expected data length as full. */
            }
            else
            {
                /* Encode 'Length' in extended Length format */
                pApdu[bApduLen++] = 0x00;
                pApdu[bApduLen++] = 0x00; /* Set the expected data length as full. */
            }
            /* Transmit Le as buffer Last */
            PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL4(
                pDataParams->pPalMifareDataParams,
                PH_EXCHANGE_BUFFER_LAST,
                pApdu,
                bApduLen,
                pResponse,
                pRespLen));
            break;
        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_AL_VCA);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_VCA);
}

phStatus_t phalVca_Sam_NonX_ComputeErrorResponse_Extended(phalVca_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wStatus)
{
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM statusTmp;
    switch (wStatus)
    {
    case PHAL_VCA_RESP_ACK_ISO4:
    case PHAL_VCA_ISO7816_SUCCESS:
    case PHAL_VCA_ISO7816_PC_SUCCESS:
        status = PH_ERR_SUCCESS;
        break;
    case PHAL_VCA_RESP_ERR_CMD_INVALID:
        status = PHAL_VCA_ERR_CMD_INVALID;
        break;
    case PHAL_VCA_RESP_ERR_FORMAT:
        status = PHAL_VCA_ERR_FORMAT;
        break;
    case PHAL_VCA_RESP_ERR_GEN:
        status = PHAL_VCA_ERR_GEN;
        break;
    case PHAL_VCA_RESP_ERR_CMD_OVERFLOW:
        status = PHAL_VCA_ERR_CMD_OVERFLOW;
        break;
    case PHAL_VCA_ISO7816_ERR_WRONG_LENGTH:
    case PHAL_VCA_ISO7816_ERR_WRONG_LE:
    case PHAL_VCA_ISO7816_ERR_FILE_NOT_FOUND:
    case PHAL_VCA_ISO7816_ERR_WRONG_PARAMS:
    case PHAL_VCA_ISO7816_ERR_WRONG_LC:
    case PHAL_VCA_ISO7816_ERR_NO_PRECISE_DIAGNOSTICS:
    case PHAL_VCA_ISO7816_ERR_EOF_REACHED:
    case PHAL_VCA_ISO7816_ERR_FILE_ACCESS:
    case PHAL_VCA_ISO7816_ERR_FILE_EMPTY:
    case PHAL_VCA_ISO7816_ERR_MEMORY_FAILURE:
    case PHAL_VCA_ISO7816_ERR_INCORRECT_PARAMS:
    case PHAL_VCA_ISO7816_ERR_WRONG_CLA:
    case PHAL_VCA_ISO7816_ERR_UNSUPPORTED_INS:
        status = PHAL_VCA_ERR_7816_GEN_ERROR;
        /* Set the error code to VC param structure*/
        PH_CHECK_SUCCESS_FCT(statusTmp, phalVca_SetConfig(pDataParams, PHAL_VCA_ADDITIONAL_INFO, wStatus));
        break;
    default:
        status = PH_ERR_PROTOCOL_ERROR;
        break;
    }
    return PH_ADD_COMPCODE(status, PH_COMP_AL_VCA);
}
#endif /* NXPBUILD__PHAL_VCA_SAMAV3_NONX */

#endif /* NXPBUILD__PHAL_VCA_SAM_NONX */
