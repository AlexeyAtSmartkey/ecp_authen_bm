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

#include <ph_Status.h>
#include <ph_RefDefs.h>
#include <ph_TypeDefs.h>
#include <phTMIUtils.h>
#include <phpalMifare.h>
#include <phalMfpEVx.h>

#ifdef NXPBUILD__PHAL_MFPEVX_SAM_NONX
#include <phhalHw_SamAV3_Cmd.h>
#include "../phalMfpEVx_Int.h"
#include "phalMfpEVx_Sam_NonX.h"
#include "phalMfpEVx_Sam_NonX_Int.h"

phStatus_t phalMfpEVx_SamAV3_NonX_Init(phalMfpEVx_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wSizeOfDataParams,
    phhalHw_SamAV3_DataParams_t * pHalSamDataParams, void * pPalMifareDataParams, phTMIUtils_t * pTMIDataParams)
{
    PH_ASSERT_NULL_DATA_PARAM (pDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_DATA_PARAM (pHalSamDataParams, PH_COMP_AL_MFPEVX);
    PH_ASSERT_NULL_DATA_PARAM (pPalMifareDataParams, PH_COMP_AL_MFPEVX);

    /* Data param check */
    if (sizeof(phalMfpEVx_SamAV3_NonX_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFPEVX);
    }

    pDataParams->wId                    = PH_COMP_AL_MFPEVX | PHAL_MFPEVX_SAMAV3_NONX_ID;
    pDataParams->pHalSamDataParams      = pHalSamDataParams;
    pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
    pDataParams->pTMIDataParams         = pTMIDataParams;
    pDataParams->bWrappedMode           = PH_OFF;       /* Use native mode by default */
    pDataParams->bExtendedLenApdu       = PH_OFF;       /* Use short length APDU by default */
    pDataParams->bAuthMode              = (uint8_t) PHAL_MFPEVX_NOTAUTHENTICATED;
    pDataParams->bSMMode                = (uint8_t) PHAL_MFPEVX_SECURE_MESSAGE_EV0;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for personalization.                                                                                        */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_WritePerso(void * pDataParams, uint8_t bLayer4Comm, uint16_t wBlockNr, uint8_t bNumBlocks,
    uint8_t * pValue)
{
    return phalMfpEVx_Int_WritePerso(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, bLayer4Comm,
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode, PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu,
        wBlockNr, bNumBlocks, pValue);
}

phStatus_t phalMfpEVx_Sam_NonX_CommitPerso(void * pDataParams, uint8_t bOption, uint8_t bLayer4Comm)
{
    return phalMfpEVx_Int_CommitPerso(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, bOption, bLayer4Comm,
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode, PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for authentication.                                                                                         */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_AuthenticateMfc(void * pDataParams, uint8_t bBlockNo, uint8_t bKeyType, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t * pUid, uint8_t bUidLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Parameter validation. */
    PH_ASSERT_NULL_PARAM(pUid, PH_COMP_AL_MFPEVX);

    /* Authenticate in MFC in Non X mode. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_AuthenticateMfc(pDataParams, bBlockNo, bKeyType, wKeyNo,
        wKeyVer, pUid, bUidLen));

    /* Update the Auth Mode to MIFARE Authenticated. */
    PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = (uint8_t) PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL0(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;

    /* Perform Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_AuthenticateMFP(pDataParams,  bLayer4Comm, bFirstAuth,
        PHAL_MFPEVX_SECURITY_LEVEL_0_KDF, wBlockNr, wKeyNum, wKeyVer, bDivInputLen, pDivInput, bPcdCap2InLen,
        pPcdCap2In, pPcdCap2Out, pPdCap2));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL1(void * pDataParams, uint8_t bLayer4Comm, uint8_t bFirstAuth, uint16_t wBlockNr,
    uint16_t wKeyNum, uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bKdf = PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL3_KDF;

    /* Update the KDF. */
    if(((wBlockNr == PHAL_MFPEVX_SL1CARDAUTHKEY) && (bLayer4Comm == PHAL_MFPEVX_ISO14443_L3)) ||
       ((wBlockNr >= PHAL_MFPEVX_ORIGINALITY_KEY_FIRST) && (wBlockNr <= PHAL_MFPEVX_ORIGINALITY_KEY_LAST)))
        bKdf = PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL1_NO_KDF;

    /* Perform MFP Authentication post MIFARE Authentication. */
    if(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == (uint8_t)PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED)
    {
        wStatus = phalMfpEVx_Sam_NonX_Int_AuthenticateMFP_Ext(pDataParams, bFirstAuth, wBlockNr, wKeyNum, wKeyVer, bDivInputLen,
            pDivInput, bPcdCap2InLen, pPcdCap2In, pPcdCap2Out, pPdCap2);
    }

    /* Perform MFP Authentication. */
    else
    {
        wStatus = phalMfpEVx_Sam_NonX_Int_AuthenticateMFP(pDataParams, bLayer4Comm, bFirstAuth, bKdf, wBlockNr, wKeyNum, wKeyVer,
            bDivInputLen, pDivInput, bPcdCap2InLen, pPcdCap2In, pPcdCap2Out, pPdCap2);
    }

    /* Update the Authentication states to internal member of dataparams. */
    if(wStatus == PH_ERR_SUCCESS)
    {
        /* Not updating the state in case authenticated using special keys. */
        if(((wBlockNr != PHAL_MFPEVX_SL1CARDAUTHKEY) || (bLayer4Comm != 0x00u)) &&
            (wBlockNr != PHAL_MFPEVX_L3SECTORSWITCHKEY) && (wBlockNr != PHAL_MFPEVX_L3SWITCHKEY) &&
            ((wBlockNr <= PHAL_MFPEVX_ORIGINALITY_KEY_FIRST) || (wBlockNr >= PHAL_MFPEVX_ORIGINALITY_KEY_LAST)))
        {
            /* Update the Auth Mode to MIFARE Authenticated. */
            PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = (uint8_t)PHAL_MFPEVX_SL1_MFP_AUTHENTICATED;
        }
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_AuthenticateSL3(void * pDataParams, uint8_t bFirstAuth, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bPcdCap2InLen, uint8_t * pPcdCap2In,
    uint8_t * pPcdCap2Out, uint8_t * pPdCap2)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;
    uint8_t     PH_MEMLOC_REM bKdf = PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL3_KDF;

    /* Update the KDF. */
    if((wBlockNr >= PHAL_MFPEVX_ORIGINALITY_KEY_FIRST) && (wBlockNr <= PHAL_MFPEVX_ORIGINALITY_KEY_LAST))
        bKdf = PHHAL_HW_SAMAV3_MFP_AUTHENTICATE_SL1_NO_KDF;

    /* Perform Authentication. */
    wStatus = phalMfpEVx_Sam_NonX_Int_AuthenticateMFP(pDataParams, PH_ON, bFirstAuth,
        bKdf, wBlockNr, wKeyNum, wKeyVer, bDivInputLen, pDivInput, bPcdCap2InLen,
        pPcdCap2In, pPcdCap2Out, pPdCap2);

    if(wStatus == PH_ERR_SUCCESS)
    {
        /* Update the Auth Mode to MIFARE Authenticated. */
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = (uint8_t)PHAL_MFPEVX_SL3_MFP_AUTHENTICATED;
    }

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_SSAuthenticate (void * pDataParams, uint8_t bOption, uint16_t wSSKeyBNr, uint16_t wSSKeyNr,
    uint16_t wSSKeyVer, uint8_t bLenDivInputSSKey, uint8_t * pDivInputSSKey, uint8_t bSecCount, uint16_t *pSectorNos,
    uint16_t *pKeyNo, uint16_t *pKeyVer, uint8_t bLenDivInputSectorKeyBs, uint8_t * pDivInputSectorKeyBs)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;

    /* Perform Sector Switch authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_AuthSectorSwitchMFP(pDataParams, bOption, wSSKeyBNr, wSSKeyNr,
        wSSKeyVer, bLenDivInputSSKey, pDivInputSSKey, bSecCount, pSectorNos, pKeyNo, pKeyVer, bLenDivInputSectorKeyBs,
        pDivInputSectorKeyBs));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_AuthenticatePDC(void * pDataParams, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput, uint8_t bUpgradeInfo)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;

    /* Perform Post Delivery Authentication. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_AuthenticatePDC(pDataParams, wBlockNr, wKeyNum, wKeyVer,
        bDivInputLen, pDivInput, bUpgradeInfo));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for data operations.                                                                                        */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_Write(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced, uint16_t wBlockNr,
    uint8_t bNumBlocks, uint8_t * pBlocks, uint8_t * pTMC, uint8_t * pTMV )
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;

    /* Perform Write according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform Writing of data in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_WRITE, (uint8_t) (wBlockNr & 0xFF),
                pBlocks, (uint16_t) ((bNumBlocks * PHAL_MFPEVX_DATA_BLOCK_SIZE) & 0xFFFF), pTMC, pTMV));
            break;

        /* Perform Writing of data in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:

            /* Evaluate the command code. */
            bCmdCode = (uint8_t) (PHAL_MFPEVX_CMD_WRITE_EN | ((!bEncrypted & 0x01U) << 1U) | bWriteMaced);

            /* Perform Write command. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, bCmdCode, wBlockNr, 0x00U, pBlocks,
                (uint8_t)((bNumBlocks * PHAL_MFPEVX_DATA_BLOCK_SIZE) & 0xFF), pTMC, pTMV));
            break;

        /* Return error in case of not authenticated in any one of the auth mode.*/
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Read(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t bNumBlocks, uint8_t * pBlocks)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;

    /* Perform Read according to the auth mode.*/
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform Reading of data in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ReadExtMfc(pDataParams, (uint8_t)(wBlockNr & 0xFF), pBlocks));
            break;

        /* Perform Reading of data in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:

            /* Evaluate the command code. */
            bCmdCode = (uint8_t) (PHAL_MFPEVX_CMD_READ_ENM | (((!bMacOnCmd & 0x01U) << 2U) | ((!bEncrypted & 0x01U) << 1U) | bReadMaced));

            /* Perform Read command. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedReadMFP(pDataParams, bCmdCode, wBlockNr, bNumBlocks, pBlocks));
            break;

        /* Return error in case if not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for value operations.                                                                                       */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_WriteValue(void * pDataParams, uint8_t bEncrypted, uint8_t bWriteMaced,
    uint16_t wBlockNr, uint8_t * pValue, uint8_t bAddr, uint8_t * pTMC, uint8_t * pTMV )
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;
    uint8_t     PH_MEMLOC_REM pBlock[PHAL_MFPEVX_DATA_BLOCK_SIZE];

    /* Form the value to be written in block format.
     *               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B |  0C  |    0D  |  0E  |   0F   |
     * Value Block = |    Value    |    ~Value   |    Value    | Addr | ~ Addr | Addr | ~ Addr |
     */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_CreateValueBlock(pValue, bAddr, pBlock));

    /* Perform Writing of value in MFC authenticated state or ISO14443 Layer 3 activated state. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_WRITE, (uint8_t)(wBlockNr & 0xFF),
                pBlock, PHAL_MFPEVX_DATA_BLOCK_SIZE, pTMC, pTMV));
            break;

        /* Perform Writing of value in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:

            /* Evaluate the command code. */
            bCmdCode = (uint8_t) (PHAL_MFPEVX_CMD_WRITE_EN | ((!bEncrypted & 0x01U) << 1U)| bWriteMaced);

            /* Perform Write command. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, bCmdCode, wBlockNr, 0x00U, pBlock,
                PHAL_MFPEVX_DATA_BLOCK_SIZE, pTMC, pTMV));
            break;

        /* Return error in case of not authenticated in any one of the auth mode.*/
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_ReadValue(void * pDataParams, uint8_t bEncrypted, uint8_t bReadMaced, uint8_t bMacOnCmd,
    uint16_t wBlockNr, uint8_t * pValue, uint8_t * pAddr)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bCmdCode = 0;
    uint8_t     PH_MEMLOC_REM pData[PHAL_MFPEVX_DATA_BLOCK_SIZE + 8U];

    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform Reading of value in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ReadExtMfc(pDataParams, (uint8_t)(wBlockNr & 0xFF), pData));
            break;

        /* Perform Reading of value in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:

            /* Evaluate the command code. */
            bCmdCode = (uint8_t) (PHAL_MFPEVX_CMD_READ_ENM | (((!bMacOnCmd & 0x01U) << 2U) | ((!bEncrypted & 0x01U) << 1U) | bReadMaced));

            /* Perform Read command. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedReadMFP(pDataParams, bCmdCode, wBlockNr, 0x01U, pData));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    /* Form the value to be referred back in block format.
     *               | 00 01 02 03 | 04 05 06 07 | 08 09 0A 0B |  0C  |    0D  |  0E  |   0F   |
     * Value Block = |    Value    |    ~Value   |    Value    | Addr | ~ Addr | Addr | ~ Addr |
     */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_CheckValueBlockFormat(pData));

    *pAddr = pData[12U];
    memcpy(pValue, pData, 4U); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Increment(void * pDataParams, uint8_t bIncrementMaced, uint16_t wBlockNr, uint8_t * pValue)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform increment according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value increment in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_INCREMENT, (uint8_t)(wBlockNr & 0xFF),
                pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));
            break;

        /* Perform value increment in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, (uint8_t) (PHAL_MFPEVX_CMD_INCR | bIncrementMaced),
                wBlockNr, 0x00U, pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Decrement(void * pDataParams, uint8_t bDecrementMaced, uint16_t wBlockNr, uint8_t * pValue)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform decrement according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value decrement in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_DECREMENT, (uint8_t)(wBlockNr & 0xFF),
                pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));
            break;

        /* Perform value decrement in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, (uint8_t) (PHAL_MFPEVX_CMD_DECR | bDecrementMaced),
                wBlockNr, 0x00U, pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_IncrementTransfer(void * pDataParams, uint8_t bIncrementTransferMaced, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform increment transfer according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value IncrementTransfer in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:

            /* Perform Value Increment. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_INCREMENT, (uint8_t)(wSrcBlockNr & 0xFF),
                pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));

            /* Perform Transfer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(
                pDataParams,
                PHAL_MFPEVX_CMD_MFC_TRANSFER,
                (uint8_t) wDstBlockNr,
                NULL,
                0U,
                pTMC,
                pTMV));
            break;

        /* Perform value IncrementTransfer in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, (uint8_t) (PHAL_MFPEVX_CMD_INCRTR | bIncrementTransferMaced),
                wSrcBlockNr, wDstBlockNr, pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, pTMC, pTMV));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_DecrementTransfer(void * pDataParams, uint8_t bDecrementTransferMaced, uint16_t wSrcBlockNr,
    uint16_t wDstBlockNr, uint8_t * pValue, uint8_t * pTMC, uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform decrement transfer according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value DecrementTransfer in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:

            /* Perform Value Decrement. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_DECREMENT, (uint8_t)(wSrcBlockNr & 0xFF),
                pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, NULL, NULL));

            /* Perform Transfer. */
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_TRANSFER, (uint8_t) wDstBlockNr,
                NULL, 0U, pTMC, pTMV));
            break;

        /* Perform value DecrementTransfer in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams,(uint8_t) (PHAL_MFPEVX_CMD_DECRTR | bDecrementTransferMaced),
                wSrcBlockNr, wDstBlockNr, pValue, PHAL_MFPEVX_VALUE_BLOCK_SIZE, pTMC, pTMV));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Transfer(void * pDataParams, uint8_t bTransferMaced, uint16_t wBlockNr, uint8_t * pTMC,
    uint8_t * pTMV)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform transfer according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value Transfer in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_TRANSFER, (uint8_t)(wBlockNr & 0xFF),
                NULL, 0U, pTMC, pTMV));
            break;

        /* Perform value Transfer in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, (uint8_t) (PHAL_MFPEVX_CMD_TRANS | bTransferMaced),
                wBlockNr, 0x00U, NULL, 0U, pTMC, pTMV));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_Restore(void * pDataParams, uint8_t bRestoreMaced, uint16_t wBlockNr)
{
    phStatus_t PH_MEMLOC_REM wStatus = 0;

    /* Perform restore according to the auth mode. */
    switch(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode)
    {
        /* Perform value Restore in MFC authenticated state or ISO14443 Layer 3 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L3:
        case PHAL_MFPEVX_SL1_MIFARE_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_WriteExtMfc(pDataParams, PHAL_MFPEVX_CMD_MFC_RESTORE, (uint8_t)(wBlockNr & 0xFF),
                NULL, 0U, NULL, NULL));
            break;

        /* Perform value Restore in MFP authenticated state or ISO14443 Layer 4 activated state. */
        case PHAL_MFPEVX_NOT_AUTHENTICATED_L4:
        case PHAL_MFPEVX_SL1_MFP_AUTHENTICATED:
        case PHAL_MFPEVX_SL3_MFP_AUTHENTICATED:
            PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CombinedWriteMFP(pDataParams, (uint8_t) (PHAL_MFPEVX_CMD_REST | bRestoreMaced),
                wBlockNr, 0x00U, NULL, 0U, NULL, NULL));
            break;

        /* Return error in case of not authenticated in any one of the auth mode. */
        default:
            return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for special operations.                                                                                     */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVerInfo, uint8_t * pVerLen)
{
    uint16_t    PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bAuthenticated = PH_OFF;
    uint8_t     PH_MEMLOC_REM aCmdBuff[9U /* Command Code + MAC. */];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t*    PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Sam = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Sam = 0;
    uint8_t     PH_MEMLOC_REM aVersion[PHAL_MFPEVX_VERSION_INFO_LENGTH + 8U /* MAC */];
    uint8_t     PH_MEMLOC_REM bVerLen = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;

    /* Check whether authenticate is performed or not. */
    if((PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
       (PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED))
    {
        bAuthenticated = PH_ON;
    }

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_GET_VERSION;

/* Exchange the command information to Sam for MAC reception ------------------------------------------------------------------------- */
    if (bAuthenticated)
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

        /* Copy the MA to command buffer .*/
        memcpy(&aCmdBuff[bCmdLen], pResp_Sam, wRespLen_Sam); /* PRQA S 3200 */
        bCmdLen = ((bCmdLen + (wRespLen_Sam & 0xFF)) & 0xFF);
    }

/* Exchange the command information to PICC ========================================================================================== */
    do
    {
        /* Buffer the command information to exchange buffer. */
        wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
            pDataParams,
            PH_EXCHANGE_DEFAULT,
            PH_ON,
            (uint8_t)((bCmdLen - (uint8_t)1U) & 0xFF), /* Excluding the command code. */
            aCmdBuff,
            bCmdLen,
            &pResp_Card,
            &wRespLen_Card,
            &bPiccErrCode);

        /* Check the status. */
        if((bPiccErrCode !=  PHAL_MFPEVX_RESP_ACK_ISO4) && (bPiccErrCode != PHAL_MFPEVX_RESP_ADDITIONAL_FRAME))
            break;

        /* Copy the Version A into version buffer and update the version buffer length .*/
        memcpy(&aVersion[bVerLen], pResp_Card, wRespLen_Card); /* PRQA S 3200 */
        bVerLen = ((bVerLen + (wRespLen_Card & 0xFF)) & 0xFF);

        /* Update the command information. */
        aCmdBuff[0U] = PHAL_MFPEVX_RESP_ADDITIONAL_FRAME;
        bCmdLen = 1U;
    }while(bPiccErrCode != PHAL_MFPEVX_RESP_ACK_ISO4);

/* Exchange the command to Sam if authenticated -------------------------------------------------------------------------------------- */
    if(bAuthenticated)
    {
        /* Buffer the Picc status information to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME,
            PH_EXCHANGE_BUFFER_FIRST | PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE,
            &bPiccErrCode,
            1U,
            NULL,
            NULL,
            NULL));

        bPiccErrCode = 0U;

        /* Buffer the version information to exchange buffer. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME,
            PH_EXCHANGE_BUFFER_LAST,
            aVersion,
            bVerLen,
            &pResp_Sam,
            &wRespLen_Sam,
            &bPiccErrCode);

        /* Check for PICC status information. */
        if ((wStatus & PH_ERR_MASK) != PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
        {
            PH_CHECK_SUCCESS(wStatus);
        }

        /* Check if Picc error is returned. */
        if(!bPiccErrCode)
        {
            /* Updating the status to ACK  */
            bPiccErrCode = PHAL_MFPEVX_RESP_ACK_ISO4;
        }

        /* Decrement the Version Length variable by 8 as MAC is appended in to it. */
        if(bVerLen >= (uint8_t)8U)
        {
            bVerLen = bVerLen - (uint8_t)8U;
        }
    }

    /* Check the response. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1U, bPiccErrCode, PH_ON));

    /* Copy the Version information to version parameter. */
    memcpy(pVerInfo, aVersion, bVerLen); /* PRQA S 3200 */
    *pVerLen = bVerLen;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_ReadSign(void * pDataParams, uint8_t bLayer4Comm, uint8_t bAddr, uint8_t ** pSignature)
{
    uint16_t    PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bAuthenticated = PH_OFF;
    uint8_t     PH_MEMLOC_REM aCmdBuff[10U /* Command Code + Address + MAC. */];
    uint8_t     PH_MEMLOC_REM bCmdLen = 0;
    uint8_t*    PH_MEMLOC_REM pResp_Card = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Card = 0;
    uint8_t *   PH_MEMLOC_REM pResp_Sam = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen_Sam = 0;
    uint8_t     PH_MEMLOC_REM bPiccErrCode = 0;

    /* Check whether authenticate is performed or not. */
    if((PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL1_MFP_AUTHENTICATED) ||
       (PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode == PHAL_MFPEVX_SL3_MFP_AUTHENTICATED))
    {
        bAuthenticated = PH_ON;
    }

    /* Frame the command information. */
    aCmdBuff[bCmdLen++] = PHAL_MFPEVX_CMD_READ_SIG;
    aCmdBuff[bCmdLen++] = bAddr;

/* Exchange the command information to Sam for MAC reception ------------------------------------------------------------------------- */
    if (bAuthenticated && bLayer4Comm)
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

        /* Copy the MA to command buffer .*/
        memcpy(&aCmdBuff[bCmdLen], pResp_Sam, wRespLen_Sam); /* PRQA S 3200 */
        bCmdLen = ((bCmdLen + (wRespLen_Sam & 0xFF)) & 0xFF);
    }

/* Exchange the command information to PICC ========================================================================================== */
    wStatus = phalMfpEVx_Sam_NonX_Int_CardExchange(
        pDataParams,
        PH_EXCHANGE_DEFAULT,
        bLayer4Comm,
        (uint8_t)((bCmdLen - (uint8_t)1U) & 0xFF), /* Excluding the command code. */
        aCmdBuff,
        bCmdLen,
        &pResp_Card,
        &wRespLen_Card,
        &bPiccErrCode);

/* Exchange the command to Sam if authenticated -------------------------------------------------------------------------------------- */
    if(bAuthenticated && bLayer4Comm)
    {
        /* Buffer the Picc status information to exchange buffer. */
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME,
            PH_EXCHANGE_BUFFER_FIRST | PHHAL_HW_SAMAV3_OPTION_COMBINED_READ_MFP_RESPONSE,
            &bPiccErrCode,
            1U,
            NULL,
            NULL,
            NULL));

        bPiccErrCode = 0U;

        /* Buffer the version information to exchange buffer. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_CombinedReadMFP(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
            PHHAL_HW_SAMAV3_ISO7816_LAST_FRAME,
            PH_EXCHANGE_BUFFER_LAST,
            pResp_Card,
            (uint8_t)(wRespLen_Card & 0xFF),
            &pResp_Sam,
            &wRespLen_Sam,
            &bPiccErrCode);

        /* Copy the response from sam. */
        memcpy(pResp_Card, pResp_Sam, wRespLen_Sam);    /* PRQA S 3200 */

        /* Check for PICC status information. */
        if ((wStatus & PH_ERR_MASK) == PHHAL_HW_SAMAV3_ERR_MIFARE_PLUS_GEN)
        {
            /* Updating the status to ACK. */
            bPiccErrCode = PHAL_MFPEVX_RESP_ACK_ISO4;
        }
        /* Check for other status information. */
        else
            PH_CHECK_SUCCESS(wStatus);


        /* Check if Picc error is returned. */
        if(!bPiccErrCode)
        {
            /* Updating the status to ACK  */
            bPiccErrCode = PHAL_MFPEVX_RESP_ACK_ISO4;
        }
    }
    else
    {
        PH_CHECK_SUCCESS (wStatus);
    }

    /* Check the response. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ComputeErrorResponse(1, bPiccErrCode, bLayer4Comm));

    /* Copy the Signature information to the parameter. */
    *pSignature = pResp_Card;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_ResetAuth(void * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    /* Perform ResetAuth. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Int_ResetAuth(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams,
        PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode, PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu));

    /* Reset the crypto layer. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_ResetSecMsgState(pDataParams));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_PersonalizeUid(void * pDataParams, uint8_t bUidType)
{
    return phalMfpEVx_Int_PersonalizeUid(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, bUidType);
}

phStatus_t phalMfpEVx_Sam_NonX_SetConfigSL1(void * pDataParams, uint8_t bOption)
{
    return phalMfpEVx_Int_SetConfigSL1(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, bOption);
}

phStatus_t phalMfpEVx_Sam_NonX_ReadSL1TMBlock(void * pDataParams, uint16_t wBlockNr, uint8_t * pBlocks)
{
    return phalMfpEVx_Int_ReadSL1TMBlock(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, wBlockNr, pBlocks);
}

phStatus_t phalMfpEVx_Sam_NonX_VCSupportLastISOL3(void * pDataParams, uint8_t * pIid, uint8_t * pPcdCapL3, uint8_t * pInfo)
{
    return phalMfpEVx_Int_VCSupportLastISOL3(PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->pPalMifareDataParams, pIid, pPcdCapL3,
        pInfo);
}

phStatus_t phalMfpEVx_Sam_NonX_ChangeKey(void * pDataParams, uint8_t bChangeKeyMaced, uint16_t wBlockNr, uint16_t wKeyNum,
    uint16_t wKeyVer, uint8_t bDivInputLen, uint8_t * pDivInput)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ChangeKeyMFP(pDataParams, (bChangeKeyMaced ? (uint8_t)PHAL_MFPEVX_CMD_WRITE_EM : (uint8_t)PHAL_MFPEVX_CMD_WRITE_EN),
        wBlockNr, wKeyNum, wKeyVer, bDivInputLen, pDivInput));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_CommitReaderID(void * pDataParams, uint16_t wBlockNr, uint8_t * pEncTMRI)
{
    phStatus_t  PH_MEMLOC_REM wStatus   = 0;

    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_CommitReaderID(pDataParams, wBlockNr, pEncTMRI));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}



/***************************************************************************************************************************************/
/* Mifare Plus EVx command for utility operations.                                                                                     */
/***************************************************************************************************************************************/
phStatus_t phalMfpEVx_Sam_NonX_ResetSecMsgState(void * pDataParams)
{
    return phalMfpEVx_Sam_NonX_Int_ResetSecMsgState(pDataParams);
}

phStatus_t phalMfpEVx_Sam_NonX_SetConfig(void * pDataParams, uint16_t wOption, uint16_t wValue)
{
    switch (wOption)
    {
        case PHAL_MFPEVX_WRAPPED_MODE:
            PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode = (wValue & 0xFF);
            break;

        case PHAL_MFPEVX_EXTENDED_APDU:
            PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu = (wValue & 0xFF);
            break;

        case PHAL_MFPEVX_AUTH_MODE:
            PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode = (wValue & 0xFF);
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_GetConfig(void *pDataParams, uint16_t wOption, uint16_t * pValue)
{
    switch (wOption)
    {
        case PHAL_MFPEVX_WRAPPED_MODE:
            *pValue = (uint16_t) PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bWrappedMode;
            break;

        case PHAL_MFPEVX_EXTENDED_APDU:
            *pValue = (uint16_t) PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bExtendedLenApdu;
            break;

        case PHAL_MFPEVX_AUTH_MODE:
            *pValue = (uint16_t) PHAL_MFPEVX_RESOLVE_DATAPARAMS(pDataParams)->bAuthMode;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}

phStatus_t phalMfpEVx_Sam_NonX_CalculateTMV(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pTMI, uint16_t wTMILen, uint8_t * pTMV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM bFinished = PH_OFF;
    uint8_t *   PH_MEMLOC_REM pMac = NULL;
    uint16_t    PH_MEMLOC_REM wMacLen = 0;

    uint16_t    PH_MEMLOC_REM wBuffOption = PH_EXCHANGE_DEFAULT;
    uint8_t     PH_MEMLOC_REM bExchangeLen = 0;
    uint16_t    PH_MEMLOC_REM wRemLen = 0;
    uint16_t    PH_MEMLOC_REM wTMIOffset = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Derive Transaction MAC (KSesTMMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ComputeTMACSessionVectors(
        pDataParams,
        PHAL_MFPEVX_SAM_NONX_SESSION_TMAC_MAC,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pTMC,
        pUid,
        bUidLen));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0U));

    /* Perform MAC verification. */
    wRemLen = (uint16_t) wTMILen;
    wBuffOption = PH_EXCHANGE_TXCHAINING;

    do
    {
        /* Update the finished flag and buffering option. */
        if(wRemLen <= PHAL_MFPEVX_SAM_DATA_FRAME_LENGTH)
        {
            bFinished = PH_ON;
            wBuffOption = PH_EXCHANGE_DEFAULT;
            bExchangeLen = (uint8_t) wRemLen;
        }
        else
        {
            bExchangeLen = PHAL_MFPEVX_SAM_DATA_FRAME_LENGTH;
            wRemLen = (uint16_t) (wRemLen - PHAL_MFPEVX_SAM_DATA_FRAME_LENGTH);
        }

        /* Exchange the TMI information to SAM. */
        wStatus = phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
            PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
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
        wTMIOffset += PHAL_MFPEVX_SAM_DATA_FRAME_LENGTH;

    }while(!bFinished);

    /* Copy the Mac to the parameter. */
    memcpy(pTMV, pMac, wMacLen);    /* PRQA S 3200 */

    return wStatus;
}

phStatus_t phalMfpEVx_Sam_NonX_DecryptReaderID(void * pDataParams, uint16_t wSrcKeyNo, uint16_t wSrcKeyVer, uint16_t wDstKeyNo,
    uint16_t wDstKeyVer, uint8_t * pTMC, uint8_t * pUid, uint8_t bUidLen, uint8_t * pEncTMRI, uint8_t * pTMRIPrev)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    /* Validate the key information. */
    if ((wSrcKeyNo > 0x7FU) || (wSrcKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    if (((wDstKeyNo < 0xE0U) || (wDstKeyNo > 0xE3U)) || (wDstKeyVer > 0xFFU))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFPEVX);
    }

    /* Derive Transaction MAC (KSesTMMAC) session key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMfpEVx_Sam_NonX_Int_ComputeTMACSessionVectors(
        pDataParams,
        PHAL_MFPEVX_SAM_NONX_SESSION_TMAC_ENC,
        wSrcKeyNo,
        wSrcKeyVer,
        wDstKeyNo,
        pTMC,
        pUid,
        bUidLen));

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t) wDstKeyNo,
        (uint8_t) wDstKeyVer,
        NULL,
        0U));

    /* Exchange the TMI information to SAM. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        PHAL_MFPEVX_RESOLVE_HAL_DATAPARAMS(pDataParams),
        PH_EXCHANGE_DEFAULT,
        pEncTMRI,
        16U,
        &pResponse,
        &wRespLen));

    /* Copy the decrypted information to the parameter. */
    memcpy(pTMRIPrev, pResponse, wRespLen); /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFPEVX);
}
#endif /* NXPBUILD__PHAL_MFPEVX_SAM_NONX */
