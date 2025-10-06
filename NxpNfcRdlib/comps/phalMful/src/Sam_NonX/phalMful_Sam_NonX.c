/*----------------------------------------------------------------------------*/
/* Copyright 2009-2014, 2024 NXP                                              */
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
* Sam NonX MIFARE(R) Ultralight Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>

#ifdef NXPBUILD__PHAL_MFUL_SAM_NONX

#include <phalMful.h>
#include <phpalMifare.h>
#include <ph_RefDefs.h>
#ifdef NXPBUILD__PH_CRYPTOSYM
#include <phCryptoSym.h>
#endif /* NXPBUILD__PH_CRYPTOSYM */
#ifdef NXPBUILD__PH_CRYPTORNG
#include <phCryptoRng.h>
#endif /* NXPBUILD__PH_CRYPTORNG */


#ifdef NXPBUILD__PHHAL_HW_SAMAV3
#include <phhalHw_SamAV3_Cmd.h>
#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */

#include "phalMful_Sam_NonX.h"
#include "phalMful_Sam_NonX_Int.h"
#include "../phalMful_Int.h"


#ifdef NXPBUILD__PHAL_MFUL_SAMAV3_NONX
phStatus_t phalMful_SamAV3_NonX_Init(phalMful_SamAV3_NonX_DataParams_t * pDataParams, uint16_t wSizeOfDataParams,
    phhalHw_SamAV3_DataParams_t * pHalSamDataParams, void * pPalMifareDataParams)
{
    if (sizeof(phalMful_SamAV3_NonX_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_AL_MFUL);
    }
    PH_ASSERT_NULL (pDataParams);
    PH_ASSERT_NULL (pHalSamDataParams);
    PH_ASSERT_NULL (pPalMifareDataParams);

    /* init private data */
    pDataParams->wId                    = PH_COMP_AL_MFUL | PHAL_MFUL_SAMAV3_NONX_ID;
    pDataParams->pHalSamDataParams      = pHalSamDataParams;
    pDataParams->pPalMifareDataParams   = pPalMifareDataParams;
#ifdef NXPBUILD__PHAL_MFUL_NDA
    pDataParams->bAuthMode              = PHAL_MFUL_NOT_AUTHENTICATED;
    pDataParams->bCMACReq               = PH_OFF;
    pDataParams->wCmdCtr                = 0x00U;
    pDataParams->bAdditionalInfo        = 0x00U;
#endif /* NXPBUILD__PHAL_MFUL_NDA */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}
#endif /* NXPBUILD__PHAL_MFUL_SAMAV3_NONX */

phStatus_t phalMful_Sam_NonX_UlcAuthenticate(void * pDataParams, uint8_t bOption, uint16_t wKeyNo, uint16_t wKeyVer,
    uint8_t * pDivInput, uint8_t bDivInputLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM aCmdBuff[2];
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;

    void *      PH_MEMLOC_REM pPalMifareDataParams = NULL;
    uint8_t *   PH_MEMLOC_REM pEncRndAB = NULL;
    uint16_t    PH_MEMLOC_REM wEncRndABLen = 0U;

    /* Reset the command buffer. */
    (void) memset(aCmdBuff, 0x00U, sizeof(aCmdBuff));

    /* Get the PAL DataParams. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMful_Int_GetPalMifareDataParams(pDataParams, &pPalMifareDataParams));

    /* Build the authentication request. */
    aCmdBuff[0U] = PHAL_MFUL_CMD_AUTH;
    aCmdBuff[1U] = 0x00U;

    /* Exchange first part of command information to PICC (MIFARE Ultralight card). -------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
        pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT,
        aCmdBuff,
        2U,
        &pResponse,
        &wRespLen));

    /* Check the format of the received data. */
    if((wRespLen != PHAL_MFUL_DES_BLOCK_SIZE + 1U) || (pResponse[0U] != PHAL_MFUL_PREAMBLE_TX))
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFUL);
    }

    /* Exchange first part of information received from PICC to Sam hardware.------ -------------------------------- */
    wStatus = phalMful_Sam_NonX_Int_UlcAuthenticate_Part1(
        pDataParams,
        bOption,
        (uint8_t) wKeyNo,
        (uint8_t) wKeyVer,
        pDivInput,
        bDivInputLen,
        &pResponse[1U],
        PHAL_MFUL_DES_BLOCK_SIZE,
        &pEncRndAB,
        &wEncRndABLen);

    /* Status should be chaining active */
    if((wStatus & PH_ERR_MASK) != PH_ERR_SUCCESS_CHAINING)
    {
        PH_CHECK_SUCCESS(wStatus);
    }

    /* Buffer the preamble. */
    aCmdBuff[0U] = PHAL_MFUL_PREAMBLE_TX;


    /* Exchange second part of command information to PICC (MIFARE Ultralight card). ------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
        pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        aCmdBuff,
        1U,
        &pResponse,
        &wRespLen));

    /* Append RndAB and send the stream. */
    wStatus = phpalMifare_ExchangeL3(
        pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pEncRndAB,
        wEncRndABLen,
        &pResponse,
        &wRespLen);

    /* Check if status is not SUCCESS.  */
    if(wStatus != PH_ERR_SUCCESS)
    {
        /* Kill the authentication. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_Sam_Cmd_SAM_KillAuthentication(pDataParams, 0x01U));

        /* Return the actual status returned from PICC. */
        return wStatus;
    }

    /* Check the format of the received data */
    if((wRespLen != PHAL_MFUL_DES_BLOCK_SIZE + 1U) || (pResponse[0U] != PHAL_MFUL_PREAMBLE_RX))
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFUL);
    }

    /* Exchange second part of information received from PICC to Sam hardware.------ ------------------------------- */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMful_Sam_NonX_Int_UlcAuthenticate_Part2(
        pDataParams,
        &pResponse[1U],
        PHAL_MFUL_DES_BLOCK_SIZE));

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}

phStatus_t phalMful_Sam_NonX_AuthenticateAES(phalMful_SamAV3_NonX_DataParams_t * pDataParams, uint8_t bOption, uint16_t wKeyNo,
    uint16_t wKeyVer, uint8_t bRamKeyNo, uint8_t bRamKeyVer, uint8_t bKeyNoCard, uint8_t * pDivInput, uint8_t bDivLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aRndA[PH_CRYPTOSYM_AES_BLOCK_SIZE];
    uint8_t     PH_MEMLOC_REM aRndB[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1];
    uint8_t     PH_MEMLOC_REM aIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];
    uint8_t     PH_MEMLOC_REM aCmdBuff[35];
    uint16_t    PH_MEMLOC_REM wCmdLen = 0;
    uint8_t     PH_MEMLOC_REM aSV[32];
    uint8_t *   PH_MEMLOC_REM pRecv = NULL;
    uint16_t    PH_MEMLOC_REM wRxlen = 0;

    /* Set the IV Buffer to zero. */
    memset(aIV,0x00,PH_CRYPTOSYM_AES_BLOCK_SIZE);

    /* Validate Card Key Number */
    if((bKeyNoCard > PHAL_MFUL_ORIGINALITY_KEY))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFUL);
    }

    /* Validate Diversification input length. */
    if((bOption == PHAL_MFUL_CMD_UL_AUTHENTICATE_DIV_ON) && (bDivLen > 31U))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFUL);
    }

    /* Perform Offline activation using SAM Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t)(wKeyNo & 0xFF),
        (uint8_t)(wKeyVer & 0xFF),
        pDivInput,
        bDivLen));

    /* Send the cmd and receive the encrypted RndB */
    aCmdBuff[wCmdLen++] = PHAL_MFUL_CMD_AUTH;
    aCmdBuff[wCmdLen++] = bKeyNoCard; /* key number card */

    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT,
        aCmdBuff,
        wCmdLen,
        &pRecv,
        &wRxlen));

    /* Verify the status. */
    if ((wRxlen != (PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U)) || (pRecv[0U] != PHAL_MFUL_PREAMBLE_TX))
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFUL);
    }

    /* Store the encrypted RndB */
    memcpy(aRndB, &pRecv[1U], PH_CRYPTOSYM_AES_BLOCK_SIZE); /* PRQA S 3200 */

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Decrypt the RndB received */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        pDataParams->pHalSamDataParams,
        PH_EXCHANGE_DEFAULT,
        aRndB,
        16U,
        &pRecv,
        &wRxlen));

    /* Store back the decrypted RndB */
    memcpy(aRndB, &pRecv[0U], PH_CRYPTOSYM_AES_BLOCK_SIZE); /* PRQA S 3200 */

    /* Generate RndA */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GetRandom(pDataParams->pHalSamDataParams, 0x10U, aRndA));

    /* Concat RndA and RndB' */
    aCmdBuff[0U] = PHAL_MFUL_PREAMBLE_TX;
    memcpy(&aCmdBuff[1U], aRndA, PH_CRYPTOSYM_AES_BLOCK_SIZE); /* PRQA S 3200 */
    memcpy(&aCmdBuff[PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U], &aRndB[1], (PH_CRYPTOSYM_AES_BLOCK_SIZE - 1U)); /* PRQA S 3200 */
    aCmdBuff[2U * PH_CRYPTOSYM_AES_BLOCK_SIZE] = aRndB[0U]; /* RndB left shifted by 8 bits */

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Encrypt RndA + RndB' */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_EncipherOfflineData(
        pDataParams->pHalSamDataParams,
        PH_EXCHANGE_DEFAULT,
        &aCmdBuff[1U],
        (uint8_t) (2U * PH_CRYPTOSYM_AES_BLOCK_SIZE),
        &pRecv,
        &wCmdLen));

    /* Copy to aCmdBuff */
     memcpy(&aCmdBuff[1U], &pRecv[0U], (2U * PH_CRYPTOSYM_AES_BLOCK_SIZE)); /* PRQA S 3200 */

    /* Update command length */
    wCmdLen = ((2U * PH_CRYPTOSYM_AES_BLOCK_SIZE ) + 1U);

    /* Get the encrypted RndA' */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
        pDataParams->pPalMifareDataParams,
        PH_EXCHANGE_DEFAULT,
        aCmdBuff,
        wCmdLen,
        &pRecv,
        &wRxlen));

    /* Verify the status. */
    if ((wRxlen != (PH_CRYPTOSYM_AES_BLOCK_SIZE + 1U)) || (pRecv[0U] != 0x00U))
    {
        return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFUL);
    }

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

     /* Decrypt RndA' */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DecipherOfflineData(
        pDataParams->pHalSamDataParams,
        PH_EXCHANGE_DEFAULT,
        &pRecv[1U],
        (uint8_t) (wRxlen - 1U),
        &pRecv,
        &wRxlen));

    /* Decrypted Data and Rotated */
    memcpy(&aCmdBuff[1U], &pRecv[0U], (2U * PH_CRYPTOSYM_AES_BLOCK_SIZE)); /* PRQA S 3200 */
    aCmdBuff[0U] = aCmdBuff[wRxlen];

    /* Compare RndA and buff */
    if (memcmp(aCmdBuff, aRndA, PH_CRYPTOSYM_AES128_KEY_SIZE) != 0U)
    {
        /* Authentication failed */
        return PH_ADD_COMPCODE(PH_ERR_AUTH_ERROR, PH_COMP_AL_MFUL);
    }

    /* Generate the session key SV
     *  SV = 0x5A||0xA5||0x00||0x01||0x00||0x80||RndA[15:14]|| (RndA[13::8] XOR RndB[15::10])||RndB[9::0]||RndA[7::0]
     */
    aSV[0U] = 0x5AU;
    aSV[1U] = 0xA5U;
    aSV[2U] = 0x00U;
    aSV[3U] = 0x01U;
    aSV[4U] = 0x00U;
    aSV[5U] = 0x80U;
    aSV[6U] = aRndA[0U];
    aSV[7U] = aRndA[1U];

    aSV[8U] = aRndA[2U] ^ aRndB[0U];
    aSV[9U] = aRndA[3U] ^ aRndB[1U];
    aSV[10U] = aRndA[4U] ^ aRndB[2U];
    aSV[11U] = aRndA[5U] ^ aRndB[3U];
    aSV[12U] = aRndA[6U] ^ aRndB[4U];
    aSV[13U] = aRndA[7U] ^ aRndB[5U];

    memcpy(&aSV[14U], &aRndB[6U], 10U);     /* PRQA S 3200 */
    memcpy(&aSV[24U], &aRndA[8U], 8U);     /* PRQA S 3200 */

    /* Perform Offline activation using Ram Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        bRamKeyNo,
        bRamKeyVer,
        NULL,
        0U));

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        pDataParams->pHalSamDataParams,
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Generate Session MAC */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_DeriveKey(
        pDataParams->pHalSamDataParams,
        (uint8_t) wKeyNo,
        (uint8_t) wKeyVer,
        bRamKeyNo,
        aSV,
        32U));

    /* Counter set to Zero */
    pDataParams->wCmdCtr = 0x0000U;

    /* Authentication Mode Set to AES */
    pDataParams->bAuthMode = PHAL_MFUL_CMD_AUTH;

    /* Set RAM Key No and Version*/
    pDataParams->bRamKeyNo = bRamKeyNo;
    pDataParams->bRamKeyVer = bRamKeyVer;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}

phStatus_t phalMful_Sam_NonX_Read(void * pDataParams, uint8_t bAddress, uint8_t * pData)
{
    return phalMful_Int_Read(pDataParams, bAddress, pData);
}

phStatus_t phalMful_Sam_NonX_Write(void * pDataParams, uint8_t bAddress, uint8_t * pData)
{
    return phalMful_Int_Write(pDataParams, bAddress, pData);
}

phStatus_t phalMful_Sam_NonX_FastWrite(void * pDataParams, uint8_t * pData)
{
    return phalMful_Int_FastWrite(pDataParams, pData);
}

phStatus_t phalMful_Sam_NonX_CompatibilityWrite(void * pDataParams, uint8_t bAddress, uint8_t * pData)
{
    return phalMful_Int_CompatibilityWrite(pDataParams, bAddress, pData);
}

phStatus_t phalMful_Sam_NonX_IncrCnt(void * pDataParams, uint8_t bCntNum, uint8_t * pCnt)
{
    return phalMful_Int_IncrCnt(pDataParams, bCntNum, pCnt);
}

phStatus_t phalMful_Sam_NonX_ReadCnt(void * pDataParams, uint8_t bCntNum, uint8_t * pCntValue)
{
    return phalMful_Int_ReadCnt(pDataParams, bCntNum, pCntValue);
}

phStatus_t phalMful_Sam_NonX_PwdAuth(void * pDataParams, uint8_t bOption, uint8_t bKeyNo, uint8_t bKeyVer, uint8_t * pDivInput,
    uint8_t bDivInputLen, uint8_t * pPwd, uint8_t * pPack)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    phStatus_t  PH_MEMLOC_REM wStatus1 = 0;
    uint8_t     PH_MEMLOC_REM bCommand = 0;
    uint8_t *   PH_MEMLOC_REM pResponse = NULL;
    uint16_t    PH_MEMLOC_REM wRespLen = 0;
    void *      PH_MEMLOC_REM pPalMifareDataParams = NULL;

    /* Validate parameter. */
    if(bOption > PHAL_MFUL_CMD_PWD_AUTH_DIV_ON)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_AL_MFUL);
    }

    /* Get the PAL DataParams. */
    PH_CHECK_SUCCESS_FCT(wStatus, phalMful_Int_GetPalMifareDataParams(pDataParams, &pPalMifareDataParams));

    /* Exchange the first part of information to Sam hardware. ------------------------------ */
    if(bOption != PHAL_MFUL_CMD_PWD_AUTH_DIV_OFF)
    {
        wStatus = phalMful_Sam_NonX_Int_PwdAuth_Part1(
            pDataParams,
            bKeyNo,
            bKeyVer,
            pDivInput,
            bDivInputLen,
            &pPwd,
            &wRespLen);

        /* Check for Chaining response. */
        if(wStatus != PH_ADD_COMPCODE(PH_ERR_SUCCESS_CHAINING, PH_COMP_HAL))
        {
            return PH_ADD_COMPCODE(PH_ERR_PROTOCOL_ERROR, PH_COMP_AL_MFUL);
        }
    }

    /* Build command frame */
    bCommand = PHAL_MFUL_CMD_PWD_AUTH;

    /* Transmit the command frame */
    PH_CHECK_SUCCESS_FCT(wStatus, phpalMifare_ExchangeL3(
        pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_FIRST,
        &bCommand,
        1U,
        NULL,
        NULL));

    /* Transmit the data */
    wStatus = phpalMifare_ExchangeL3(
        pPalMifareDataParams,
        PH_EXCHANGE_BUFFER_LAST,
        pPwd,
        PHAL_MFUL_WRITE_BLOCK_LENGTH,
        &pResponse,
        &wRespLen);

    /* Check if status is not SUCCESS.  */
    if(wStatus != PH_ERR_SUCCESS)
    {
        /* Kill the authentication. */
        PH_CHECK_SUCCESS_FCT(wStatus1, phhalHw_Sam_Cmd_SAM_KillAuthentication(pDataParams, 0x01U));

        /* Return the actual status returned from PICC. */
        return wStatus;
    }

    /* copy received data block */
    (void) memcpy(pPack, pResponse, wRespLen);

    /* Exchange the Second part of information to Sam hardware. ----------------------------- */
    if(bOption != PHAL_MFUL_CMD_PWD_AUTH_DIV_OFF)
    {
        PH_CHECK_SUCCESS_FCT(wStatus, phalMful_Sam_NonX_Int_PwdAuth_Part2(
            pDataParams,
            pPack));
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}

phStatus_t phalMful_Sam_NonX_GetVersion(void * pDataParams, uint8_t * pVersion)
{
    return phalMful_Int_GetVersion(pDataParams, pVersion);
}

phStatus_t phalMful_Sam_NonX_FastRead(void * pDataParams, uint8_t  bStartAddr, uint8_t bEndAddr,
    uint8_t ** pData, uint16_t * pNumBytes)
{
     return phalMful_Int_FastRead(pDataParams, bStartAddr,bEndAddr, pData, pNumBytes);
}

phStatus_t phalMful_Sam_NonX_SectorSelect(void * pDataParams, uint8_t bSecNo)
{
    return phalMful_Int_SectorSelect(pDataParams, bSecNo);
}

phStatus_t phalMful_Sam_NonX_ReadSign(void * pDataParams, uint8_t bAddr, uint8_t ** pSignature,uint16_t* pDataLen)
{
    return phalMful_Int_ReadSign(pDataParams, bAddr, pSignature, pDataLen);
}

phStatus_t phalMful_Sam_NonX_ChkTearingEvent(void * pDataParams, uint8_t bCntNum, uint8_t * pValidFlag)
{
    return phalMful_Int_ChkTearingEvent(pDataParams, bCntNum, pValidFlag);
}

phStatus_t phalMful_Sam_NonX_WriteSign(void * pDataParams, uint8_t bAddress, uint8_t * pSignature)
{
    return phalMful_Int_WriteSign(pDataParams, bAddress, pSignature);
}

phStatus_t phalMful_Sam_NonX_LockSign(void * pDataParams, uint8_t bLockMode)
{
    return phalMful_Int_LockSign(pDataParams, bLockMode);
}

phStatus_t phalMful_Sam_NonX_VirtualCardSelect(void * pDataParams, uint8_t * pVCIID, uint8_t bVCIIDLen, uint8_t * pVCTID)
{
    return phalMful_Int_VirtualCardSelect(pDataParams, pVCIID, bVCIIDLen, pVCTID);
}

phStatus_t phalMful_Sam_NonX_ReadTTStatus(void * pDataParams, uint8_t bAddr, uint8_t * pData)
{
    return phalMful_Int_ReadTTStatus(pDataParams, bAddr, pData);
}

#ifdef NXPBUILD__PHAL_MFUL_SAMAV3_NONX
phStatus_t phalMful_Sam_NonX_GetConfig(void *pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    switch (wConfig)
    {
        case PHAL_MFUL_CMAC_STATUS:
            *pValue = ((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->bCMACReq;
            break;

        case PHAL_MFUL_ADDITIONAL_INFO:
            *pValue = ((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->bAdditionalInfo;
            break;

        default:
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFUL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}

phStatus_t phalMful_Sam_NonX_SetConfig(void * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    switch (wConfig)
    {
        case PHAL_MFUL_CMAC_STATUS:
            ((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->bCMACReq = (uint8_t)(wValue & 0xFF);
            break;

        case PHAL_MFUL_ADDITIONAL_INFO:
            ((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->bAdditionalInfo = (uint8_t)(wValue & 0xFF);
            break;

        default:
            PH_UNUSED_VARIABLE(pDataParams);
            PH_UNUSED_VARIABLE(wValue);
            return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_AL_MFUL);
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}

phStatus_t phalMful_Sam_NonX_CalculateSunCMAC(void * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t * pInData,
    uint16_t wInDataLen, uint8_t * pRespMac)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t *   PH_MEMLOC_REM pMac = NULL;
    uint16_t    PH_MEMLOC_REM wMacLen = 0;
    uint8_t     PH_MEMLOC_REM aIV[PH_CRYPTOSYM_AES_BLOCK_SIZE];

    /* Load zero to IV */
    memset(aIV, 0x00U, PH_CRYPTOSYM_AES_BLOCK_SIZE);  /* PRQA S 3200 */

    /* Perform Offline activation. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_ActivateOfflineKey(
        (((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->pHalSamDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_AO_LRP_UPDATE_KEY_RFU,
        (uint8_t)(wKeyNo & 0xFF),
        (uint8_t)(wKeyVer & 0xFF),
        NULL,
        0U));

    /* Load zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_LoadInitVector(
        (((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->pHalSamDataParams),
        PHHAL_HW_SAMAV3_CMD_SAM_LOAD_IV_MODE_SET_IV,
        aIV,
        PH_CRYPTOSYM_AES_BLOCK_SIZE));

    /* Generate Mac. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SamAV3_Cmd_SAM_GenerateMAC(
        (((phalMful_SamAV3_NonX_DataParams_t *) pDataParams)->pHalSamDataParams),
        PH_EXCHANGE_DEFAULT,
        PHHAL_HW_SAMAV3_TRUNCATION_MODE_MFP,
        pInData,
        (uint8_t)wInDataLen,
        &pMac,
        &wMacLen));

    /* Copy Mac Data */
    memcpy(pRespMac, pMac, wMacLen);    /* PRQA S 3200 */

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_AL_MFUL);
}
#endif /* NXPBUILD__PHAL_MFUL_SAMAV3_NONX */
#endif /* NXPBUILD__PHAL_MFUL_SAM_NONX */
