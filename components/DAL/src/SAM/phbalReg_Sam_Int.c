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
* SAM (Secure Access Module) internal implementation for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phbalReg.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHBAL_REG_SAM

#ifdef _WIN32
#include "phbalReg_Sam_Int.h"

phStatus_t phbalReg_Sam_Int_Exchange(phbalReg_Sam_DataParams_t * pDataParams, uint8_t bCommType, uint8_t bCmd, uint8_t * pData,
    uint16_t wDataLen, uint8_t ** ppResponse, uint16_t * pRspLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint16_t    PH_MEMLOC_REM wOption = 0;
    uint16_t    PH_MEMLOC_REM wCmd = 0;
    uint16_t    PH_MEMLOC_REM wTotRespLen = 0;
    uint16_t    PH_MEMLOC_REM wRemRespLen = 0;
    uint16_t    PH_MEMLOC_REM wTxLen = 0;
    uint16_t    PH_MEMLOC_REM wReadLen = 0;
    uint16_t    PH_MEMLOC_REM wRspLen = 0;
    uint8_t     PH_MEMLOC_REM bRetries = 0U;
    uint8_t     PH_MEMLOC_REM bExchangeTx = PH_ON;
    uint8_t     PH_MEMLOC_REM bSplitRead = PH_OFF;

    /* Clear Transmit and Receive buffer */
    (void) memset(pDataParams->pTxBuffer, 0x00U, pDataParams->wTxBufSize);
    (void) memset(pDataParams->pRxBuffer, 0x00U, pDataParams->wRxBufSize);

    /* Add command to Tx buffer. */
    pDataParams->pTxBuffer[wTxLen++] = bCommType;
    pDataParams->pTxBuffer[wTxLen++] = bCmd;

    /* Add additional info to TxBuffer based on command. */
    switch(bCmd)
    {
        case PHBAL_SAM_CONFIG_RD_OPS_SET_PCSC_MODE:
            pDataParams->pTxBuffer[wTxLen++] = 0x01U;
            pDataParams->pTxBuffer[wTxLen++] = 0x00U;
            pDataParams->pTxBuffer[wTxLen++] = 0x01U;
            break;

        case PHBAL_SAM_CMD_ACTIVATE:
        case PHBAL_SAM_CMD_DEACTIVATE:
        case PHBAL_SAM_CMD_COLD_RESET:
            pDataParams->pTxBuffer[wTxLen++] = 0x00U;
            pDataParams->pTxBuffer[wTxLen++] = 0x00U;
            break;

        case PHBAL_SAM_CMD_SEND_PPS:
            pDataParams->pTxBuffer[wTxLen++] = 0x03U;
            pDataParams->pTxBuffer[wTxLen++] = 0x00U;
            pDataParams->pTxBuffer[wTxLen++] = 0x00U;
            pDataParams->pTxBuffer[wTxLen++] = 0x11U;
            break;

        case PHBAL_SAM_CMD_TRANSMIT_DATA:
            pDataParams->pTxBuffer[wTxLen++] = (uint8_t) (wDataLen & 0xFF);
            pDataParams->pTxBuffer[wTxLen++] = (uint8_t) (wDataLen >> 8U);
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
    }

    /* Add data if applicable. */
    (void) memcpy(&pDataParams->pTxBuffer[wTxLen], pData, wDataLen);
    wTxLen += wDataLen;

    /* Frame the actual command. */
    wCmd = (uint16_t) ((bCommType << 8U) | bCmd);

    /* Set Option info to be provided for lower Bal. */
    wOption = (uint16_t) PH_EXCHANGE_DEFAULT;

    /* Update information based on Lower BAL. */
    if(PH_GET_COMPID(pDataParams->pLowerBalDataParams) == PHBAL_REG_SERIALWIN_ID)
    {
        wOption |= (uint16_t) PHBAL_REG_SERIALWIN_SUPRESS_CHECKS;

        /* Read the Header Information. */
        wRemRespLen = PHBAL_SAM_FRAME_HEADER_LEN;

        /* Set Loop Termination flag. */
        bSplitRead = PH_ON;
    }
    else
    {
        /* Read complete information. */
        wRemRespLen = pDataParams->wRxBufSize;

        /* Set Loop Termination flag. */
        bSplitRead = PH_OFF;
    }

    do
    {
        wStatus = phbalReg_Exchange(
            pDataParams->pLowerBalDataParams,
            wOption,
            bExchangeTx ? pDataParams->pTxBuffer : NULL,
            (uint16_t) (bExchangeTx ? wTxLen : 0U),
            wRemRespLen,
            &pDataParams->pRxBuffer[wTotRespLen],
            &wRspLen);

        wTotRespLen += wRspLen;
        wRemRespLen -= wRspLen;
        bExchangeTx = PH_OFF;

        /* Break the loop in case of error and max retries reached. */
        bRetries += (uint8_t) ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS);
        if((bRetries == 10U) || (bSplitRead == PH_OFF))
            break;

    } while(wTotRespLen != PHBAL_SAM_FRAME_HEADER_LEN);

    /* Update the remaining bytes to read. */
    wRemRespLen = (uint16_t) (pDataParams->pRxBuffer[4] | (pDataParams->pRxBuffer[5] << 8U));
    wReadLen = wRemRespLen;

    /* Read the payload is available. */
    if((wRemRespLen != 0U) && (bSplitRead == PH_ON))
    {
        do
        {
            wStatus = phbalReg_Exchange(
                pDataParams->pLowerBalDataParams,
                wOption,
                NULL,
                0U,
                wReadLen,
                &pDataParams->pRxBuffer[wTotRespLen],
                &wRspLen);

            wTotRespLen += wRspLen;
            wReadLen -= wRspLen;
        } while(((wTotRespLen - PHBAL_SAM_FRAME_HEADER_LEN) != wRemRespLen) && (wReadLen > 0U));
    }

    /* Check response */
    PH_CHECK_SUCCESS_FCT(wStatus, phbalReg_Sam_Int_CheckResponse(
        wCmd,
        pDataParams->pRxBuffer,
        wTotRespLen,
        NULL,
        &wRspLen));

    /* Move the response to parameters. */
    *ppResponse = &pDataParams->pRxBuffer[PHBAL_SAM_FRAME_HEADER_LEN];
    *pRspLen = wRspLen;

    return wStatus;
}

phStatus_t phbalReg_Sam_Int_CheckResponse(uint16_t wCmd, uint8_t * pRxBuffer, uint16_t wRxBuffLen, uint8_t ** ppData,
    uint16_t * pDataLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint16_t    PH_MEMLOC_REM wDataLen = 0;

    /* Reset data length */
    if(ppData != NULL)
    {
        *ppData = NULL;
    }
    if(pDataLen != NULL)
    {
        *pDataLen = 0;
    }

    /* Frame has to be at least 6 bytes */
    if(wRxBuffLen < PHBAL_SAM_FRAME_HEADER_LEN)
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_BAL);
    }
    else
    {
        /* Retrieve length */
        wDataLen = pRxBuffer[PHBAL_SAM_FRAME_LEN_POS];
        wDataLen |= ((uint16_t) pRxBuffer[PHBAL_SAM_FRAME_LEN_POS + 1] << 8);

        /* Length should match */
        if((wRxBuffLen - PHBAL_SAM_FRAME_HEADER_LEN) != wDataLen)
        {
            return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_BAL);
        }
        else
        {
            /* Command Code should match */
            if((pRxBuffer[PHBAL_SAM_FRAME_CMD_POS] != (uint8_t) ((uint16_t) wCmd >> 8)) ||
                (pRxBuffer[PHBAL_SAM_FRAME_CMD_POS + 1] != ((uint8_t) wCmd | 0x80)))
            {
                return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_BAL);
            }
        }
    }

    /* Retrieve wStatus */
    wStatus = PH_ADD_COMPCODE((uint16_t) pRxBuffer[PHBAL_SAM_FRAME_STATUS_POS],
        ((uint16_t) pRxBuffer[PHBAL_SAM_FRAME_STATUS_POS + 1] << 8));

    /* Return data pointer */
    if(ppData != NULL)
    {
        *ppData = &pRxBuffer[PHBAL_SAM_FRAME_PAYLOAD_POS];
    }

    /* Return data length  */
    if(pDataLen != NULL)
    {
        *pDataLen = wDataLen;
    }

    return wStatus;
}

phStatus_t phbalReg_Sam_Int_ParseAtr(uint8_t * pAtr, uint16_t wAtrLen, uint8_t * pTa1, uint8_t * pSpecificMode)
{
    uint16_t PH_MEMLOC_REM wY;
    uint16_t PH_MEMLOC_REM wIndex = 0;

    /* Length Check */
    if(wAtrLen < 2)
    {
        return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_BAL);
    }

    /* Skip TS */
    ++wIndex;

    /* Retrieve Y1 */
    wY = pAtr[wIndex++];

    /* Parse TA1 (Fi and Di) */
    if(wY & 0x10)
    {
        *pTa1 = pAtr[wIndex++];
    }

    /* Default Di and Di */
    else
    {
        *pTa1 = 0x11;
    }

    /* Ignore TB1 */
    if(wY & 0x20)
    {
        ++wIndex;
    }

    /* Ignore TC1 */
    if(wY & 0x40)
    {
        ++wIndex;
    }

    /* Parse TD1 */
    if(wY & 0x80)
    {
        /* Retrieve Y2 */
        wY = pAtr[wIndex++];

        /* Parse TA2 */
        if(wY & 0x10)
        {
            *pSpecificMode = (uint8_t) ((pAtr[wIndex] & 0x80) ? 1 : 0);
        }
        else
        {
            *pSpecificMode = 0;
        }
    }
    else
    {
        *pSpecificMode = 0;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

#endif /* _WIN32 */

#endif /* NXPBUILD__PHBAL_REG_SAM */
