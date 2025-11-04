/*----------------------------------------------------------------------------*/
/* Copyright 2009-2013, 2024 NXP                                              */
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
* Secure Messaging Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#include <phbalReg.h>
#include <phhalHw.h>
#include <phCryptoSym.h>
#include <ph_RefDefs.h>
#include <phTools.h>

#include "phhalHw_SamAV3.h"
#include <phhalHw_SamAV3_Cmd.h>
#include "HSM_AES/phhalHw_SamAV3_HSM_AES.h"
#include "Utils/phhalHw_SamAV3_HcUtils.h"


phStatus_t phhalHw_SamAV3_Init(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pReaderHalDataParams,
    void * pKeyStoreDataParams, void * pCryptoENCDataParams, void * pCryptoMACDataParams, void * pCryptoRngDataParams, void * pPLUpload_CryptoENCDataParams,
    void * pPLUpload_CryptoMACDataParams, uint8_t bOpMode, uint8_t bLogicalChannel, uint8_t* pTxBuffer, uint16_t wTxBufSize, uint8_t* pRxBuffer, uint16_t wRxBufSize,
    uint8_t* pPLUploadBuf)
{
    if (sizeof(phhalHw_SamAV3_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_HAL);
    }

    PH_ASSERT_NULL (pDataParams);
    PH_ASSERT_NULL (pCryptoENCDataParams);
    PH_ASSERT_NULL (pCryptoMACDataParams);
    PH_ASSERT_NULL (pCryptoRngDataParams);
    PH_ASSERT_NULL (pTxBuffer);
    PH_ASSERT_NULL (pRxBuffer);

    pDataParams->wId                            = PH_COMP_HAL | PHHAL_HW_SAMAV3_ID;
    pDataParams->pReaderHalDataParams           = pReaderHalDataParams;
    pDataParams->pKeyStoreDataParams            = pKeyStoreDataParams;
    pDataParams->pENCCryptoDataParams           = pCryptoENCDataParams;
    pDataParams->pMACCryptoDataParams           = pCryptoMACDataParams;
    pDataParams->pCryptoRngDataParams           = pCryptoRngDataParams;
    pDataParams->pPLUpload_ENCCryptoDataParams  = pPLUpload_CryptoENCDataParams;
    pDataParams->pPLUpload_MACCryptoDataParams  = pPLUpload_CryptoMACDataParams;
    pDataParams->Cmd_Ctr                        = 0;
    pDataParams->bHostMode                      = PHHAL_HW_SAMAV3_HC_AV2_MODE;
    pDataParams->bAuthType                      = 0x00;
    pDataParams->bPendingEncCmdDataLength       = 0;
    pDataParams->bPendingMacCmdDataLength       = 0;
    pDataParams->bPendingMacRespDataLength      = 0;
    pDataParams->bCmdSM                         = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bRespSM                        = PHHAL_HW_SAMAV3_HSM_AES_NO_SM;
    pDataParams->bCommandChaining               = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;
    pDataParams->bResponseChaining              = PHHAL_HW_SAMAV3_HSM_AES_NO_CHAINING;
    pDataParams->bMasterKeyCmacMode             = PH_OFF;
    pDataParams->bOpMode                        = bOpMode;
    pDataParams->bLogicalChannel                = bLogicalChannel;
    pDataParams->pTxBuffer                      = pTxBuffer;
    pDataParams->wTxBufSize                     = wTxBufSize;
    pDataParams->wTxBufLen                      = 0;
    pDataParams->pRxBuffer                      = pRxBuffer;
    pDataParams->wRxBufSize                     = wRxBufSize;
    pDataParams->wRxBufLen                      = 0;
    pDataParams->wRxBufStartPos                 = 0;
    pDataParams->wTxBufStartPos                 = 0;
    pDataParams->bCardType                      = PHHAL_HW_CARDTYPE_ISO14443A;
    pDataParams->bTimeoutUnit                   = PHHAL_HW_TIME_MICROSECONDS;
    pDataParams->wFieldOffTime                  = PHHAL_HW_FIELD_OFF_DEFAULT;
    pDataParams->wFieldRecoveryTime             = PHHAL_HW_FIELD_RECOVERY_DEFAULT;
    pDataParams->wAdditionalInfo                = 0;
    pDataParams->wTimingMode                    = PHHAL_HW_TIMING_MODE_OFF;
    pDataParams->dwTimingUs                     = 0;
    pDataParams->bMifareCryptoDisabled          = PH_ON;
    pDataParams->bRfResetAfterTo                = PH_OFF;
    pDataParams->bDisableNonXCfgMapping         = PH_OFF;
    pDataParams->pPLUploadBuf                   = pPLUploadBuf;
    pDataParams->wPLUploadBufLen                = 0;

    /* Verify exchange buffers */
    if ((wTxBufSize <= PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN) || (wRxBufSize <= PHHAL_HW_SAMAV3_RESERVED_RX_BUFFER_LEN))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Verify operation mode */
    if (bOpMode != PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Verify NonX reader HAL pointer */
    if (pReaderHalDataParams == NULL)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_Exchange(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pTxBuffer, uint16_t wTxLength,
    uint8_t ** ppRxBuffer, uint16_t * pRxLength)
{
    phStatus_t  PH_MEMLOC_REM status = 0;
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint16_t    PH_MEMLOC_REM wValidBits;
    uint16_t    PH_MEMLOC_REM wParity = PH_OFF;
    uint16_t    PH_MEMLOC_REM wCrc = PH_OFF;
    uint8_t *   PH_MEMLOC_REM pRxBuffer = NULL;
    uint16_t    PH_MEMLOC_REM wRxLength;

    /* Check options */
    if (wOption & ~((PH_EXCHANGE_BUFFERED_BIT | PH_EXCHANGE_LEAVE_BUFFER_BIT | PHHAL_HW_SAMAV3_EXCHANGE_NO_ENCIPHERING_BIT | PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT) & 0xFFFF))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Parameter check */
    if ((wOption & PH_EXCHANGE_BUFFERED_BIT) && (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] > 0))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Check if caller has provided valid RxBuffer */
    if (ppRxBuffer == NULL)
    {
        ppRxBuffer = &pRxBuffer;
    }
    if (pRxLength == NULL)
    {
        pRxLength = &wRxLength;
    }

    *pRxLength = 0;
    pDataParams->wRxBufLen = pDataParams->wRxBufStartPos;
    pDataParams->wAdditionalInfo = 0;

    /* Data enciphering  */
    if (!(pDataParams->bMifareCryptoDisabled))
    {
        wRxLength = wTxLength;

        /* Non-X Mode: Sync. RxStartPos with Reader */
        if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(
                pDataParams->pReaderHalDataParams,
                PHHAL_HW_CONFIG_RXBUFFER_STARTPOS,
                (uint16_t * UNALIGNED)&pDataParams->wRxBufLen));
        }

        if (!(wOption & PHHAL_HW_SAMAV3_EXCHANGE_NO_ENCIPHERING_BIT))
        {
            /* Encipher transmission data */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherData(
                pDataParams,
				wOption & ((~(uint16_t)PH_EXCHANGE_CUSTOM_BITS_MASK) & 0xFFFF),
                pTxBuffer,
                (uint8_t)(wTxLength & 0xFF),
                0x00,
                &pTxBuffer,
                &wTxLength));
        }

        /* Return after buffering */
        if (wOption & PH_EXCHANGE_BUFFERED_BIT)
        {
            return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
        }
        /* Else perform default exchange since buffering has already been done */
        else
        {
            wOption &= PH_EXCHANGE_CUSTOM_BITS_MASK;
        }

        /* Get amount of complete bytes */
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] = (uint8_t)(wTxLength % 9);
        if (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] != 0x00)
        {
            --pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS];
        }

        /* Non-X Mode : Modify Parity and CRC settings */
        if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
        {
            /* Retrieve Parity-setting */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, &wParity));

            /* Disable Parity */
            if (wParity != PH_OFF)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, PH_OFF));
            }

            /* Disable TxCrc */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_TXCRC, PH_OFF));

            /* Retrieve RxCrc-setting */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, &wCrc));

            /* Disable RxCrc */
            if (wCrc != PH_OFF)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, PH_OFF));
            }

            /* Set TxLastBits */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_TXLASTBITS, (uint16_t)pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS]));
        }
        /* X-Mode: Retrieve RxCrc status (for Mfc Decipher later on) */
        else
        {
            wCrc = pDataParams->wCfgShadow[PHHAL_HW_CONFIG_RXCRC];
        }
    }

    /* Non-X Mode : Exchange via Reader HAL */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        /* Perform Exchange */
        status = phhalHw_Exchange(
            pDataParams->pReaderHalDataParams,
            wOption & ((~(uint16_t)PH_EXCHANGE_CUSTOM_BITS_MASK) & 0xFFFF),
            pTxBuffer,
            wTxLength,
            ppRxBuffer,
            pRxLength);

        /* do not perform real exchange, just fill the global TxBuffer */
        if (wOption & PH_EXCHANGE_BUFFERED_BIT)
        {
            return status;
        }

        /* Restore Parity-setting again since many PAL layers expect it */
        if (wParity != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, PH_ON));
        }

        /* Restore RxCRC-setting again */
        if (wCrc != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, PH_ON));
        }

        /* Retrieve RxLastBits */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXLASTBITS, &wValidBits));
        pDataParams->wAdditionalInfo = (wValidBits & 0xFF);

        /* Clear TxLastBits */
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] = 0;

        /* status check */
        if ((status & PH_ERR_MASK) != PH_ERR_SUCCESS_INCOMPLETE_BYTE)
        {
            PH_CHECK_SUCCESS(status);
        }
    }

    /* If no deciphering required. Just return the buffer */
    if (!(pDataParams->bMifareCryptoDisabled) &&
        (wOption & PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT))
    {
        return status;
    }
    else
    {
        /* Data deciphering  */
        if (!(pDataParams->bMifareCryptoDisabled) &&
            (!(wOption & PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT) ||
            ((*pRxLength == 1) && (pDataParams->wAdditionalInfo == 4))))
        {
            /* Non-X Mode: RxStartPos is RxLength in this case */
            if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
            {
                pDataParams->wRxBufStartPos = pDataParams->wRxBufLen;
            }

            /* Ignore data before RxStartPos for decryption */
            *ppRxBuffer += pDataParams->wRxBufStartPos;
            *pRxLength = (uint16_t)((*pRxLength - pDataParams->wRxBufStartPos) & 0xFFFF);

            /* Perform actual deciphering */
            wStatus = phhalHw_SamAV3_Cmd_SAM_DecipherData(
                pDataParams,
                PH_EXCHANGE_DEFAULT,
                *ppRxBuffer,
                (uint8_t)(*pRxLength & 0xFF),
                NULL,
                ppRxBuffer,
                pRxLength);

            /* Bail out on Error */
            if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS)
            {
                /* In NonX-Mode, reset RxStartPos */
                if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
                {
                    pDataParams->wRxBufStartPos = 0;
                    pDataParams->wRxBufLen = 0;
                }
                return wStatus;
            }

            /* Received streams which are not ACK / NACK */
            if ((*pRxLength != 1)  || (pDataParams->wAdditionalInfo != 4))
            {
                /* DecipherData removes CRC, so calculate it again if it is expected */
                if (wCrc == PH_OFF)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, phTools_CalculateCrc16(
                        PH_TOOLS_CRC_OPTION_DEFAULT,
                        PH_TOOLS_CRC16_PRESET_ISO14443A,
                        PH_TOOLS_CRC16_POLY_ISO14443,
                        *ppRxBuffer,
                        *pRxLength,
                        &wCrc));

                    (*ppRxBuffer)[(*pRxLength)++] = (uint8_t)(wCrc);
                    (*ppRxBuffer)[(*pRxLength)++] = (uint8_t)(wCrc >> 8);
                }

                /* Always byte-aligned after decryption */
                pDataParams->wAdditionalInfo = 0;
                status = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
            }

            /* Always return complete buffer on exchange */
            *pRxLength = *pRxLength + pDataParams->wRxBufStartPos;
            *ppRxBuffer = pDataParams->pRxBuffer;
            pDataParams->wRxBufLen = *pRxLength;

            /* In NonX-Mode, reset RxStartPos */
            if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
            {
                pDataParams->wRxBufStartPos = 0;
            }
        }
    }
    return status;
}

phStatus_t phhalHw_SamAV3_DetectMode(phhalHw_SamAV3_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aVersion[PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_LENGTH];
    uint8_t     PH_MEMLOC_REM bVerLen = 0;
    uint8_t     PH_MEMLOC_REM aKeyEntryBuffer[PHHAL_HW_SAMAV3_KEYENTRY_SIZE];
    uint8_t     PH_MEMLOC_REM bKeyEntryLen = 0;
    uint8_t     PH_MEMLOC_REM bSet1 = 0;

    /* Issue GetVersion command */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetVersion(
        pDataParams,
        aVersion,
        &bVerLen));

    /* Check length of received response */
    if (bVerLen == PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_LENGTH)
    {
        /* Retrieve Host-Mode */
        switch (aVersion[PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_HOSTMODE_POS])
        {
        case 0xA2: /* Sam AV2 Activated State. */
            pDataParams->bHostMode = PHHAL_HW_SAMAV3_HC_AV2_MODE;
            break;

        case 0x03:  /* Unactivated State. */
        case 0xA3:  /* Activate State. */
            pDataParams->bHostMode = PHHAL_HW_SAMAV3_HC_AV3_MODE;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_INTERFACE_ERROR, PH_COMP_HAL);
        }
    }
    else
    {
        return PH_ADD_COMPCODE(PH_ERR_LENGTH_ERROR, PH_COMP_HAL);
    }

    /* Store the UID globally */
    memcpy(pDataParams->bUid, &aVersion[PHHAL_HW_SAMAV3_CMD_GET_VERSION_RESPONSE_UID_OFFSET], PHHAL_HW_SAMAV3_HC_SAM_UID_SIZE); /* PRQA S 3200 */


    /* Retrieve status of MasterKey */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetKeyEntry(
        pDataParams,
        0x00,
        0x00,
        aKeyEntryBuffer,
        &bKeyEntryLen
    ));

    bSet1 = aKeyEntryBuffer[bKeyEntryLen - 2];
    /* Check if CMAC mode is enabled */
    if (bSet1 & 0x01)
    {
        pDataParams->bMasterKeyCmacMode = PH_ON;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_SetConfig(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* In case of Non-X mode, the SetConfig is directly redirected to the Reader IC if not disabled. */
    /* Exceptions are: Crypto1 and custom configs. */
    if (pDataParams->bDisableNonXCfgMapping == PH_OFF)
    {
        if ((pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X) &&
            (wConfig != PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1) &&
            (wConfig != PHHAL_HW_SAMAV3_CONFIG_HOSTMODE) &&
            (wConfig != PHHAL_HW_SAMAV3_CONFIG_DISABLE_NONX_CFG_MAPPING))
        {
            return phhalHw_SetConfig(pDataParams->pReaderHalDataParams, wConfig, wValue);
        }
    }

    switch (wConfig)
    {
        case PHHAL_HW_CONFIG_TXLASTBITS:

            /* check parameter */
            if (wValue > 7)
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* Write config data into shadow */
            pDataParams->wCfgShadow[wConfig] = wValue;
            break;

        case PHHAL_HW_CONFIG_TIMING_MODE:

            /* Check supported option bits */
            switch (wValue & PHHAL_HW_TIMING_MODE_OPTION_MASK)
            {
            case PHHAL_HW_TIMING_MODE_OPTION_DEFAULT:
            case PHHAL_HW_TIMING_MODE_OPTION_AUTOCLEAR:
                break;
            default:
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* Check supported timing modes */
            switch (wValue & ~((PHHAL_HW_TIMING_MODE_OPTION_MASK) & 0xFFFF))
            {
            case PHHAL_HW_TIMING_MODE_OFF:
            case PHHAL_HW_TIMING_MODE_FDT:
                pDataParams->dwTimingUs = 0;
                pDataParams->wTimingMode = wValue;
                break;
            case PHHAL_HW_TIMING_MODE_COMM:
                return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
            default:
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            break;

        case PHHAL_HW_CONFIG_FIELD_OFF_TIME:

            /* Parameter Check */
            if ((wValue == 0) || (wValue > 0xFF))
            {
                return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* Store config data */
            pDataParams->wFieldOffTime = wValue;
            break;

        case PHHAL_HW_CONFIG_FIELD_RECOVERY_TIME:

            /* Store config data */
            pDataParams->wFieldRecoveryTime = wValue;
            break;

        case PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1:

            pDataParams->bMifareCryptoDisabled = (wValue & 0xFF);
            if (wValue != PH_OFF)
            {
                /* We also need to reset the authentication inside of the SAM */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams, PH_ON));
            }
            break;

        case PHHAL_HW_CONFIG_ADDITIONAL_INFO:

            /* Modify additional info parameter */
            pDataParams->wAdditionalInfo = wValue;
            break;

        case PHHAL_HW_CONFIG_RXBUFFER_STARTPOS:

            /* Boundary check */
            if ((PHHAL_HW_SAMAV3_RESERVED_RX_BUFFER_LEN + wValue) >= pDataParams->wRxBufSize)
            {
                return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            /* Set start position */
            pDataParams->wRxBufStartPos = wValue;
            pDataParams->wRxBufLen = wValue;

            /* Preserve RxBuffer contents if needed */
            if (pDataParams->pTxBuffer == pDataParams->pRxBuffer)
            {
                pDataParams->wTxBufStartPos = pDataParams->wRxBufStartPos;
            }
            else
            {
                pDataParams->wTxBufStartPos = 0;
            }
            break;

        case PHHAL_HW_CONFIG_TXBUFFER_LENGTH:

            /* Needed for MIFARE Encrypted buffered data */
            if (pDataParams->wTxBufLen_Cmd >= (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1))
            {
                /* Check parameter */
                if (((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + pDataParams->wTxBufStartPos + wValue) > pDataParams->wTxBufSize)
                {
                    return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
                }

                /* set buffer length */
                pDataParams->wTxBufLen_Cmd = (((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + wValue) & 0xFFFF);
            }
            /* Normal Exchange */
            else
            {
                /* Check parameter */
                if ((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wTxBufStartPos + wValue) > pDataParams->wTxBufSize)
                {
                    return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
                }

                /* set buffer length */
                pDataParams->wTxBufLen = ((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + wValue) & 0xFFFF);
            }
            break;

        case PHHAL_HW_CONFIG_TXBUFFER:

            /* Needed for MIFARE Encrypted buffered data */
            if (pDataParams->wTxBufLen_Cmd >= (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1))
            {
                /* Check additional info parameter */
                if (((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo) >= pDataParams->wTxBufSize)
                {
                    return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
                }

                /* Modify TxBuffer byte */
                pDataParams->pTxBuffer[(PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo] = (wValue & 0xFF);
            }
            /* Normal Exchange */
            else
            {
                /* Check additional info parameter */
                if ((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo) >= pDataParams->wTxBufSize)
                {
                    return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
                }

                /* Modify TxBuffer byte */
                pDataParams->pTxBuffer[PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo] = (wValue & 0xFF);
            }
            break;

        case PHHAL_HW_CONFIG_RFRESET_ON_TIMEOUT:

            if (wValue == PH_OFF)
            {
                pDataParams->bRfResetAfterTo = PH_OFF;
            }
            else
            {
                pDataParams->bRfResetAfterTo = PH_ON;
            }
            break;

        case PHHAL_HW_SAMAV3_CONFIG_HOSTMODE:

            pDataParams->bHostMode = (wValue & 0xFF);
            break;

        case PHHAL_HW_SAMAV3_CONFIG_DISABLE_NONX_CFG_MAPPING:

            if (wValue != PH_OFF)
            {
                pDataParams->bDisableNonXCfgMapping = PH_ON;
            }
            else
            {
                pDataParams->bDisableNonXCfgMapping = PH_OFF;
            }
            break;

        case PHHAL_HW_CONFIG_SETMINFDT:

            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_SetMinFDT(pDataParams, wValue));
            break;

    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_GetConfig(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    /* In case of Non-X mode, the GetConfig is directly redirected to the Reader IC if not disabled. */
    /* Exceptions are: RxLastbits, Crypto1 and custom configs. */
    if (pDataParams->bDisableNonXCfgMapping == PH_OFF)
    {
        if ((pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X) &&
            (wConfig != PHHAL_HW_CONFIG_RXLASTBITS) &&
            (wConfig != PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1) &&
            (wConfig != PHHAL_HW_SAMAV3_CONFIG_HOSTMODE) &&
            (wConfig != PHHAL_HW_SAMAV3_CONFIG_DISABLE_NONX_CFG_MAPPING))
        {
            /* Also do not forward if TxBufferLen is requested and MfCrypto is enabled (buffering is done in this HAL) */
            if (!((wConfig == PHHAL_HW_CONFIG_TXBUFFER_LENGTH) && (!pDataParams->bMifareCryptoDisabled)))
            {
                return phhalHw_GetConfig(pDataParams->pReaderHalDataParams, wConfig, pValue);
            }
        }
    }

    switch (wConfig)
    {
    case PHHAL_HW_CONFIG_PARITY:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_TXCRC:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_RXCRC:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_TXLASTBITS:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_ADDITIONAL_INFO:
    case PHHAL_HW_CONFIG_RXLASTBITS:

        *pValue = pDataParams->wAdditionalInfo;
        break;

    case PHHAL_HW_CONFIG_RXWAIT_US:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_CLEARBITSAFTERCOLL:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_TXDATARATE_FRAMING:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_RXDATARATE_FRAMING:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_MODINDEX:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_ASK100:

        /* Read config from shadow */
        *pValue = pDataParams->wCfgShadow[wConfig];
        break;

    case PHHAL_HW_CONFIG_TIMEOUT_VALUE_US:

        if (pDataParams->bTimeoutUnit == PHHAL_HW_TIME_MICROSECONDS)
        {
            *pValue = pDataParams->wCfgShadow[wConfig];
        }
        else
        {
            if (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS] > (0xFFFF / 1000))
            {
                return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
            }
            *pValue = ((pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS] * 1000) & 0xFFFF);
        }
        break;

    case PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS:

        if (pDataParams->bTimeoutUnit == PHHAL_HW_TIME_MILLISECONDS)
        {
            *pValue = pDataParams->wCfgShadow[wConfig];
        }
        else
        {
            *pValue = pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_US] / 1000;
        }
        break;

    case PHHAL_HW_CONFIG_TIMING_MODE:

        *pValue = pDataParams->wTimingMode;
        break;

    case PHHAL_HW_CONFIG_TIMING_US:

        if (pDataParams->dwTimingUs > 0xFFFF)
        {
            return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
        }

        *pValue = (uint16_t)pDataParams->dwTimingUs;
        pDataParams->dwTimingUs = 0;
        break;

    case PHHAL_HW_CONFIG_TIMING_MS:

        if (pDataParams->dwTimingUs > (0xFFFF * 1000))
        {
            pDataParams->dwTimingUs = 0;
            return PH_ADD_COMPCODE(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
        }

        *pValue = (uint16_t)(pDataParams->dwTimingUs / 1000);
        pDataParams->dwTimingUs = 0;
        break;

    case PHHAL_HW_CONFIG_FIELD_OFF_TIME:

        *pValue = pDataParams->wFieldOffTime;
        break;

    case PHHAL_HW_CONFIG_FIELD_RECOVERY_TIME:

        *pValue = pDataParams->wFieldRecoveryTime;
        break;

    case PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1:

        *pValue = pDataParams->bMifareCryptoDisabled;
        break;

    case PHHAL_HW_CONFIG_RXBUFFER_STARTPOS:

        /* Return parameter */
        *pValue = pDataParams->wRxBufStartPos;
        break;

    case PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE:

        /* Return parameter */
        *pValue =((pDataParams->wRxBufSize - PHHAL_HW_SAMAV3_RESERVED_RX_BUFFER_LEN) & 0xFFFF);
        break;

    case PHHAL_HW_CONFIG_TXBUFFER_BUFSIZE:

        /* Return parameter */
        *pValue = ((pDataParams->wTxBufSize - (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wTxBufStartPos)) & 0xFFFF);
        break;

    case PHHAL_HW_CONFIG_TXBUFFER_LENGTH:

        /* Needed for MIFARE Encrypted buffered data */
        if (pDataParams->wTxBufLen_Cmd >= (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1))
        {
            *pValue = pDataParams->wTxBufLen_Cmd - (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1);
        }
        else
        {
            /* Normal Exchange */
            if (pDataParams->wTxBufLen >= PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN)
            {
                *pValue = pDataParams->wTxBufLen - PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN;
            }
            else
            {
                *pValue = 0;
            }
        }
        break;

    case PHHAL_HW_CONFIG_TXBUFFER:

        /* Needed for MIFARE Encrypted buffered data */
        if (pDataParams->wTxBufLen_Cmd >= (PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1))
        {
            /* Check additional info parameter */
            if (((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + pDataParams->wAdditionalInfo) >= pDataParams->wTxBufSize)
            {
                return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            /* Return TxBuffer byte */
            *pValue = (uint16_t)pDataParams->pTxBuffer[(PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN - 1) + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo];
        }
        /* Normal Exchange */
        else
        {
            /* Check additional info parameter */
            if ((PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wAdditionalInfo) >= pDataParams->wTxBufSize)
            {
                return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            /* Return TxBuffer byte */
            *pValue = (uint16_t)pDataParams->pTxBuffer[PHHAL_HW_SAMAV3_RESERVED_TX_BUFFER_LEN + pDataParams->wTxBufStartPos + pDataParams->wAdditionalInfo];
        }
        break;

    case PHHAL_HW_CONFIG_RFRESET_ON_TIMEOUT:

        *pValue = (uint16_t)pDataParams->bRfResetAfterTo;
        break;

    case PHHAL_HW_CONFIG_CARD_TYPE:
        /* Return parameter */
        *pValue = (uint16_t)pDataParams->bCardType;
        break;

    case PHHAL_HW_SAMAV3_CONFIG_HOSTMODE:

        *pValue = pDataParams->bHostMode;
        break;

    case PHHAL_HW_SAMAV3_CONFIG_DISABLE_NONX_CFG_MAPPING:
        *pValue = pDataParams->bDisableNonXCfgMapping;
        break;


    default:
        return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_SetMinFDT(phhalHw_SamAV3_DataParams_t * pDataParams, uint16_t wValue)
{
    phStatus_t PH_MEMLOC_REM status = 0;
    uint16_t   PH_MEMLOC_REM wTimer = 0;
    uint16_t   PH_MEMLOC_REM wTxRate = 0;

    if (wValue == PH_ON)
    {
        /*Backup the old Timer values and set min FDT*/
        PH_CHECK_SUCCESS_FCT(status, phhalHw_SamAV3_GetConfig(pDataParams,
            PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS, &wTimer));
        pDataParams->dwFdtPc = wTimer;
        /* Get the data rate */
        PH_CHECK_SUCCESS_FCT(status, phhalHw_SamAV3_GetConfig(pDataParams,
                PHHAL_HW_CONFIG_TXDATARATE_FRAMING, &wTxRate));
        switch(wTxRate)
        {
            case PHHAL_HW_RF_DATARATE_106:
                wTimer = PHHAL_HW_MINFDT_106_US;
                break;
            case PHHAL_HW_RF_DATARATE_212:
                wTimer = PHHAL_HW_MINFDT_212_US;
                break;
            case PHHAL_HW_RF_DATARATE_424:
                wTimer = PHHAL_HW_MINFDT_424_US;
                break;
            case PHHAL_HW_RF_DATARATE_848:
                wTimer = PHHAL_HW_MINFDT_848_US;
                break;
            default:
                break;
        }
    }
    else if (wValue == PH_OFF)
    {
    }
    else
    {
        /* Do nothing*/
    }
    return status;
}

phStatus_t phhalHw_SamAV3_ApplyProtocolSettings(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bCardType)
{

    /* MIFARE Crypto1 state is disabled by default */
    pDataParams->bMifareCryptoDisabled = PH_ON;

    /* In case of Non-X mode, the ApplyProtocolSettings is directly redirected to the Reader IC */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return phhalHw_ApplyProtocolSettings(pDataParams->pReaderHalDataParams, bCardType);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_ReadRegister(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bAddress, uint8_t * pValue)
{
#ifdef _WIN32
    /* In case of Non-X mode, the ReadRegister is directly redirected to the Reader IC */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return phhalHw_ReadRegister(pDataParams->pReaderHalDataParams, bAddress, pValue);
    }

    /* perform command */
    return phhalHw_SamAV3_Cmd_RC_ReadRegister(pDataParams, &bAddress, 1, pValue);
#else
    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* ifdef _WIN32 */
}

phStatus_t phhalHw_SamAV3_WriteRegister(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bAddress, uint8_t bValue)
{
#ifdef _WIN32
    uint8_t PH_MEMLOC_REM aData[2];

    /* In case of Non-X mode, the WriteRegister is directly redirected to the Reader IC */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return phhalHw_WriteRegister(pDataParams->pReaderHalDataParams, bAddress, bValue);
    }

    aData[0] = bAddress;
    aData[1] = bValue;

    /* perform command */
    return phhalHw_SamAV3_Cmd_RC_WriteRegister(pDataParams, aData, 2);
#else
    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* ifdef _WIN32 */
}

phStatus_t phhalHw_SamAV3_FieldReset(phhalHw_SamAV3_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* In case of Non-X mode, the FieldReset is directly redirected to the Reader */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return phhalHw_FieldReset(pDataParams->pReaderHalDataParams);
    }

    /* Perform field reset */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_RC_RFControl(pDataParams, ((pDataParams->wFieldOffTime) & 0xFF)));

    /* Wait recovery time */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Wait(
        pDataParams,
        PHHAL_HW_TIME_MILLISECONDS,
        pDataParams->wFieldRecoveryTime));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_FieldOn(phhalHw_SamAV3_DataParams_t * pDataParams)
{
    /* In case of Non-X mode, the FieldOn is directly redirected to the Reader IC */
    if (pDataParams->bOpMode == PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        return phhalHw_FieldOn(pDataParams->pReaderHalDataParams);
    }

    return phhalHw_SamAV3_Cmd_RC_RFControl(pDataParams,1);
}

phStatus_t phhalHw_SamAV3_Wait(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bUnit, uint16_t wTimeout)
{
    switch (pDataParams->bOpMode)
    {
        /* In case of Non-X mode, the Wait is directly redirected to the Reader IC */
    case PHHAL_HW_SAMAV3_OPMODE_NON_X:
        return phhalHw_Wait(pDataParams->pReaderHalDataParams, bUnit, wTimeout);

    default:
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }
}

phStatus_t phhalHw_SamAV3_MfcAuthenticate(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bBlockNo, uint8_t bKeyType,
    uint8_t * pKey, uint8_t * pUid)
{
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(bBlockNo);
    PH_UNUSED_VARIABLE(bKeyType);
    PH_UNUSED_VARIABLE(pKey);
    PH_UNUSED_VARIABLE(pUid);

    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
}

phStatus_t phhalHw_SamAV3_MfcAuthenticateKeyNo(phhalHw_SamAV3_DataParams_t * pDataParams, uint8_t bBlockNo, uint8_t bKeyType,
    uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pUid)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatusTmp = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[5];
    uint8_t *   PH_MEMLOC_REM pToken = NULL;
    uint16_t    PH_MEMLOC_REM wTokenLen = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    uint16_t    PH_MEMLOC_REM wParity = 0;
    uint16_t    PH_MEMLOC_REM wRxCrc = 0;

    /* Parameter check */
    if ((wKeyNo > 0xFF) || (wKeyVer > 0xFF))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Prepare first part of authenticate command */
    if (PHHAL_HW_MFC_KEYA == (bKeyType & 0x0F))
    {
        bKeyType = PHHAL_HW_MFC_KEYA;
    }
    else if (PHHAL_HW_MFC_KEYB == (bKeyType & 0x0F))
    {
        bKeyType = PHHAL_HW_MFC_KEYB;
    }
    else
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* In case of X mode, we directly call MFC Authenticate */
    if (pDataParams->bOpMode != PHHAL_HW_SAMAV3_OPMODE_NON_X)
    {
        /* Perform authentication */
        wStatus = phhalHw_SamAV3_Cmd_MF_Authenticate(
            pDataParams,
            PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_OFF,
            pUid,
            (uint8_t) wKeyNo,
            (uint8_t) wKeyVer,
            bKeyType,
            bBlockNo,
            0);

        /* Map invalid key stuff to invalid parameter */
        if (((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_REF_NO_INVALID) ||
            ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_KUC_NO_INVALID) ||
            ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_VERSION_INVALID))
        {
            return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
        }
        /* Check for error */
        else
        {
            if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_GEN)
            {
                return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
            }
            else
            {
                PH_CHECK_SUCCESS(wStatus);
            }
        }
    }
    /* Non-X mode */
    else
    {
        /* Build Authentication command */
        if (bKeyType == PHHAL_HW_MFC_KEYA)
        {
            aCmdBuff[0] = PHHAL_HW_SAMAV3_AUTHMODE_KEYA;
        }
        else
        {
            aCmdBuff[0] = PHHAL_HW_SAMAV3_AUTHMODE_KEYB;
        }
        aCmdBuff[1] = bBlockNo;

        /* Retrieve RxCrc-setting */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, &wRxCrc));

        /* Disable RxCrc */
        if (wRxCrc != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, PH_OFF));
        }

        /* Exchange AUTH1 command */
        wStatus = phhalHw_SamAV3_Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT | PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT,
            aCmdBuff,
            2,
            &pResponse,
            &wRespLen);

        /* Check status, allow incomplete byte return code */
        if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS_INCOMPLETE_BYTE)
        {
            /* Bytelength must be 5 */
            if (wRespLen != 5)
            {
                return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
            }
        }
        else
        {
            PH_CHECK_SUCCESS(wStatus);

            /* Bytelength must be 4 */
            if (wRespLen != 4)
            {
                return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_HAL);
            }

            /* Force last byte to zero */
            aCmdBuff[4] = 0x00;
        }

        /* Copy response */
        memcpy(aCmdBuff, pResponse, wRespLen);  /* PRQA S 3200 */

        /* Process authentication part 1 */
        wStatus = phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part1(
            pDataParams,
            PHHAL_HW_SAMAV3_CMD_AUTHENTICATE_MIFARE_DIV_OFF,
            pUid,
            (uint8_t) wKeyNo,
            (uint8_t) wKeyVer,
            bKeyType,
            bBlockNo,
            0x00,
            aCmdBuff,
            5,
            &pToken,
            &wTokenLen);

        /* Return code should be chaining */
        if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
        {
            if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            {
                return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
            }
            else
            {
                /* Map invalid key stuff to invalid parameter */
                if (((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_REF_NO_INVALID) ||
                    ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_KUC_NO_INVALID) ||
                    ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_KEY_VERSION_INVALID))
                {
                    return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
                }
                else
                {
                    return wStatus;
                }
            }
        }

        /* Disable TxCrc */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_TXCRC, PH_OFF));

        /* Retrieve Parity-setting */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_GetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, &wParity));

        /* Disable Parity */
        if (wParity != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, PH_OFF));
        }

        /* Exchange AUTH2 command */
        wStatus = phhalHw_SamAV3_Exchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT | PHHAL_HW_SAMAV3_EXCHANGE_NO_ENCIPHERING_BIT | PHHAL_HW_SAMAV3_EXCHANGE_NO_DECIPHERING_BIT,
            pToken,
            wTokenLen,
            &pResponse,
            &wRespLen);

        /* Restore Parity-setting again since many PAL layers expect it */
        if (wParity != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatusTmp, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_PARITY, PH_ON));
        }

        /* Restore RxCrc */
        if (wRxCrc != PH_OFF)
        {
            PH_CHECK_SUCCESS_FCT(wStatusTmp, phhalHw_SetConfig(pDataParams->pReaderHalDataParams, PHHAL_HW_CONFIG_RXCRC, PH_ON));
        }

        /* Exchange error */
        if ((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_INCOMPLETE_BYTE)
        {
            /* finish SAM chaining with KillAuthenticate command */
            /* Kill only card Auth */
            PH_CHECK_SUCCESS_FCT(wStatusTmp, phhalHw_SamAV3_Cmd_SAM_KillAuthentication(pDataParams, 0x01));

            /* return error */
            if ((wStatus & PH_ERR_MASK) == PH_ERR_SUCCESS)
            {
                return PH_ADD_COMPCODE(PH_ERR_INTERNAL_ERROR, PH_COMP_HAL);
            }
            else
            {
                return wStatus;
            }
        }

        /* Process authentication part 2 */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_AuthenticateMIFARE_Part2(pDataParams, pResponse, (uint8_t) wRespLen));
    }

    /* MIAFRE Crypto is now enabled */
    pDataParams->bMifareCryptoDisabled = PH_OFF;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_HAL);
}
#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */
