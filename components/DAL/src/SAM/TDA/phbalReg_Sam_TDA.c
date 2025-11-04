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
* SAM (Secure Access Module) internal implementation via TDA interface for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHBAL_REG_SAM

#include "phbalReg_Sam_TDA.h"
#include "../phbalReg_Sam_Int.h"

#ifndef _WIN32
phhalTda_DATAParams_t      TdaDataParams[PHAPP_MAX_CT_SLOT_SUPPORTED];
phhalCt_DATAParams_t       sHal_Ct;
#else
/* Supported Fi/Di values */
static const uint8_t PH_MEMLOC_CONST_ROM PH_MEMLOC_CONST_ROM gaphbalReg_Sam_SupportedFiDiValues[] =
{
    0x11,
    0x12,
    0x13,
    0x18,
    0x95,
    0x96
};
#endif /* _WIN32 */

#ifndef _WIN32
phStatus_t phbalReg_Sam_TDA_Init(phbalReg_Sam_DataParams_t * pDataParams, phpalCt_DATAParams_t apPal_Ct[PHAPP_MAX_CT_SLOT_SUPPORTED],
    phhalCt_SlotType_t Slot_type, uint8_t * pAtrBuffer, uint16_t wAtrBufSize)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    pDataParams->Slot_type = Slot_type;

    for(uint8_t i = 0; i < PHAPP_MAX_CT_SLOT_SUPPORTED; i++ )
    {
        apPal_Ct[i].sAtrParams.pbAtrBuffer = pAtrBuffer;
        apPal_Ct[i].sAtrParams.bSizeOfATRbuffer = (wAtrBufSize & 0xFF);
        sHal_Ct.phhalCt_Params[i].pTDAPins = &(TdaDataParams[i]);
        apPal_Ct[i].phalDataParams = &sHal_Ct;

        /* CT Pal Init */
        (void) phpalCt_Init(&apPal_Ct[i]);
    }

    /* CT Hal Init */
    wStatus = phhalCt_Init(apPal_Ct[0].phalDataParams, Slot_type);

    return PH_ADD_COMPCODE(wStatus, PH_COMP_BAL);
}
#endif /* _WIN32 */

phStatus_t phbalReg_Sam_ActivateSam_TDA(phbalReg_Sam_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint8_t *   PH_MEMLOC_REM pAtr = NULL;
    uint16_t    PH_MEMLOC_REM wAtrLen = 0;

#ifdef _WIN32
    uint8_t     PH_MEMLOC_REM * pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Set PCSC mode in case if Pegoda - 2 reader is configured. */
    if(PH_GET_COMPID(pDataParams->pLowerBalDataParams) == PHBAL_REG_PCSCWIN_ID)
    {
        /* Perform Mode change */
        PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_Exchange(
            pDataParams,
            PHBAL_SAM_CMD_READER_OPERATION,
            PHBAL_SAM_CONFIG_RD_OPS_SET_PCSC_MODE,
            NULL,
            0U,
            &pResponse,
            &wRspLen));
    }
    else
    {
        /* PCSC Mode setting is not required. */
    }

    /* Perform Activate Contact Card */
    wStatus = phbalReg_Sam_Int_Exchange(
        pDataParams,
        PHBAL_SAM_COMM_TYPE_TDA,
        PHBAL_SAM_CMD_ACTIVATE,
        NULL,
        0U,
        &pAtr,
        &wAtrLen);

    /* Perform Cold Reset in case if Activate Fails. */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_Exchange(
            pDataParams,
            PHBAL_SAM_COMM_TYPE_TDA,
            PHBAL_SAM_CMD_COLD_RESET,
            NULL,
            0U,
            &pAtr,
            &wAtrLen));
    }

#else
    phpalCt_DATAParams_t * PH_MEMLOC_REM phpalCt_DATAParams = (phpalCt_DATAParams_t *) pDataParams->pLowerBalDataParams;

    /* Activate the card */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalCt_ActivateCard(&phpalCt_DATAParams[pDataParams->Slot_type]));

    /* Update ATR Buff Address */
    pAtr = phpalCt_DATAParams[pDataParams->Slot_type].sAtrParams.pbAtrBuffer;
    wAtrLen = phpalCt_DATAParams[pDataParams->Slot_type].sAtrParams.bAtrReceivedLength;

#endif /* _WIN32 */

    /* Store ATR */
    if(wAtrLen < pDataParams->wMaxAtrBufSize)
    {
        (void) memcpy(pDataParams->pAtrBuffer, pAtr, wAtrLen);
        pDataParams->wAtrBufSize = wAtrLen;
    }
    else
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_BAL);
    }

    return wStatus;
}

phStatus_t phbalReg_Sam_Pps_TDA(phbalReg_Sam_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

#ifdef _WIN32
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint8_t     PH_MEMLOC_REM bIndex = 0;
    uint8_t     PH_MEMLOC_REM bPps1 = 0;
    uint8_t     PH_MEMLOC_REM bSpecificMode = 0;
    uint8_t     PH_MEMLOC_REM bDoPps = 0;
    uint8_t     PH_MEMLOC_REM * pResponse = NULL;

    /* Set PCSC mode in case if Pegoda - 2 reader is configured. */
    if(PH_GET_COMPID(pDataParams->pLowerBalDataParams) == PHBAL_REG_PCSCWIN_ID)
    {
        /* Parse ATR */
        PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_ParseAtr(pDataParams->pAtrBuffer, pDataParams->wAtrBufSize,
            &bPps1, &bSpecificMode));

        if((!bSpecificMode) && (bPps1 != 0x11))
        {
            /* Check if Fi/Di values are supported */
            for(bIndex = 0; bIndex < sizeof(gaphbalReg_Sam_SupportedFiDiValues); ++bIndex)
            {
                if(gaphbalReg_Sam_SupportedFiDiValues[bIndex] == bPps1)
                {
                    bDoPps = 1;
                    break;
                }
            }
        }

        /* Perform PPS if necessary */
        if(bDoPps)
        {
            /* Perform PPS */
            PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_Exchange(
                pDataParams,
                PHBAL_SAM_COMM_TYPE_TDA,
                PHBAL_SAM_CMD_SEND_PPS,
                &bPps1,
                1U,
                &pResponse,
                &wRspLen));
        }
    }
    else
    {
        /* PCSC Mode setting is not required. */
    }

#endif /* _WIN32 */

    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);

    return wStatus;
}

phStatus_t phbalReg_Sam_DeActivateSam_TDA(phbalReg_Sam_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

#ifdef _WIN32
    uint8_t     PH_MEMLOC_REM * pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;

    /* Perform De-Activate Contact Card */
    wStatus = phbalReg_Sam_Int_Exchange(
        pDataParams,
        PHBAL_SAM_COMM_TYPE_TDA,
        PHBAL_SAM_CMD_DEACTIVATE,
        NULL,
        0U,
        &pResponse,
        &wRspLen);

    /* Payload length should be 0 */
    if(wRspLen != 0)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_BAL);
    }
    else
    {
        /* Forcing status to SUCCESS as post De-Activate, there will be no response from reader. */
        wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
    }
#else
    phpalCt_DATAParams_t * PH_MEMLOC_REM phpalCt_DATAParams = (phpalCt_DATAParams_t *) pDataParams->pLowerBalDataParams;

    PH_CHECK_SUCCESS_FCT(wStatus, phhalCt_DeactivateCard(phpalCt_DATAParams[pDataParams->Slot_type].phalDataParams));
#endif /* _WIN32 */

    return wStatus;
}

phStatus_t phbalReg_Sam_TransmitData_TDA(phbalReg_Sam_DataParams_t * pDataParams, uint8_t * pTxBuffer, uint16_t wTxBufLen,
    uint16_t wRxBufSize, uint8_t * pRxBuffer, uint16_t * pRxBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

#ifdef _WIN32
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;

    /* Perform command exchange */
    PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_Exchange(
        pDataParams,
        PHBAL_SAM_COMM_TYPE_TDA,
        PHBAL_SAM_CMD_TRANSMIT_DATA,
        pTxBuffer,
        wTxBufLen,
        &pResponse,
        &wRspLen));

    /* Check if RxBuffer is big enough */
    if(wRxBufSize < wRspLen)
    {
        return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_BAL);
    }

    /* Copy received contents */
    (void) memcpy(pRxBuffer, pResponse, wRspLen);
    *pRxBufLen = wRspLen;
#else
    phpalCt_DATAParams_t * PH_MEMLOC_REM phpalCt_DATAParams = (phpalCt_DATAParams_t *) pDataParams->pLowerBalDataParams;

    PH_CHECK_SUCCESS_FCT(wStatus, phpalCt_Transceive(&phpalCt_DATAParams[pDataParams->Slot_type], pTxBuffer, wTxBufLen,
        pRxBuffer, pRxBufLen, E_PHPAL_CT_TXRX_DEFAULT));

#endif /* _WIN32 */

    return wStatus;
}

#endif /* NXPBUILD__PHBAL_REG_SAM */
