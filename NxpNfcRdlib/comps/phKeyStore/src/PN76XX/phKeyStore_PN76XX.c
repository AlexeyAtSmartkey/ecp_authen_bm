/*----------------------------------------------------------------------------*/
/* Copyright 2022 NXP                                                         */
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
* PN76XX KeyStore Component of Reader Library Framework.
* $Author: Rajendran Kumar (nxp99556) $
* $Revision: 6424 $ (v07.10.00)
* $Date: 2021-10-05 23:02:00 +0530 (Tue, 05 Oct 2021) $
*
* History:
*  CHu: Generated 23. Jun 2022
*
*/

#include <ph_Status.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX

#include "phKeyStore_PN76XX.h"

phStatus_t phKeyStore_PN76XX_Init(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wSizeOfDataParams,
     phKeyStore_PN76XX_KeyEntry_t * pKeyEntries, uint16_t wNoOfKeyEntries)
{
    uint8_t     PH_MEMLOC_REM bIndex = 0;

    if(sizeof(phKeyStore_PN76XX_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_KEYSTORE);
    }
    PH_ASSERT_NULL(pDataParams);
    PH_ASSERT_NULL(pKeyEntries);

    /* Init private data */
    pDataParams->wId                  = PH_COMP_KEYSTORE | PH_KEYSTORE_PN76XX_ID;
    pDataParams->pKeyEntries          = pKeyEntries;
    pDataParams->wNoOfKeyEntries      = wNoOfKeyEntries;

    for(bIndex = 0; bIndex < pDataParams->wNoOfKeyEntries; bIndex++)
    {
        pDataParams->pKeyEntries[bIndex].wKeyType     = PH_KEYSTORE_INVALID_ID;
        pDataParams->pKeyEntries[bIndex].bKeyIndex    = (uint8_t) PH_KEYSTORE_INVALID_ID;
        pDataParams->pKeyEntries[bIndex].bKeyLen      = 0;

    }

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_PN76XX_DeInit(phKeyStore_PN76XX_DataParams_t * pDataParams)
{
    uint8_t     PH_MEMLOC_REM bIndex = 0;

    for(bIndex = 0; bIndex < pDataParams->wNoOfKeyEntries; bIndex++)
    {
        pDataParams->pKeyEntries[bIndex].wKeyType     = PH_KEYSTORE_INVALID_ID;
        pDataParams->pKeyEntries[bIndex].bKeyIndex    = (uint8_t) PH_KEYSTORE_INVALID_ID;
        pDataParams->pKeyEntries[bIndex].bKeyLen      = 0;

    }
    pDataParams->wNoOfKeyEntries = 0U;

    return PH_ERR_SUCCESS;
}





/* Common Interfaces ------------------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_PN76XX_FormatKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wNewKeyType)
{
    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    switch(wNewKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_AES128:
        case PH_KEYSTORE_KEY_TYPE_AES256:
        case PH_KEYSTORE_KEY_TYPE_DES:
        case PH_KEYSTORE_KEY_TYPE_2K3DES:
        case PH_KEYSTORE_KEY_TYPE_3K3DES:
        case PH_KEYSTORE_KEY_TYPE_MIFARE:

            /* Nothing to do here. */
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    pDataParams->pKeyEntries[wKeyNo].wKeyType = wNewKeyType;
    (void) memset(pDataParams->pKeyEntries[wKeyNo].aKey, 0x00, PH_KEYSTORE_MAX_KEY_SIZE);

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_PN76XX_SetKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wRefNoKUC)
{
    /* Satisfy compiler */
    if(pDataParams || wKeyNo || wRefNoKUC)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_GetKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t * pdwLimit,
    uint32_t * pdwCurVal)
{
    /* Satisfy compiler */
    if(pDataParams || wRefNoKUC || pdwLimit || pdwCurVal)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_ChangeKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t dwLimit)
{
    /* Satisfy compiler */
    if(pDataParams || wRefNoKUC || dwLimit)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_SetConfig(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    /* Satisfy compiler */
    if(pDataParams || wConfig || wValue)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_SetConfigStr(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint8_t *pBuffer,
    uint16_t wBufferLength)
{
    /* Satisfy compiler */
    if(pDataParams || wConfig || pBuffer || wBufferLength)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_GetConfig(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    /* Satisfy compiler */
    if(pDataParams || wConfig || pValue)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_GetConfigStr(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint8_t ** ppBuffer,
    uint16_t * pBufferLength)
{
    /* Satisfy compiler */
    if(pDataParams || wConfig || ppBuffer || pBufferLength)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}





/* Interfaces for Symmetric Keys ------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_PN76XX_SetKey(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVer)
{
    /* Satisfy the compiler. */
    if(wKeyVer)
    {
        ;/* Do nothing */
    }

    return phKeyStore_PN76XX_SetKeyAtPos(pDataParams, wKeyNo, pDataParams->pKeyEntries[wKeyNo].bKeyIndex, wKeyType, pNewKey, wNewKeyVer);
}

phStatus_t phKeyStore_PN76XX_SetKeyAtPos(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos, uint16_t wKeyType,
    uint8_t * pNewKey, uint16_t wNewKeyVer)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    /* Satisfy the compiler. */
    if(wNewKeyVer)
    {
        ;/* Do nothing */
    }

    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Check that Key type matches with current Key Type format */
    if(pDataParams->pKeyEntries[wKeyNo].wKeyType != wKeyType)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Load the Key */
    switch(wKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_AES128:
            /* Update the Key Index. */
            pDataParams->pKeyEntries[wKeyNo].bKeyIndex = (uint8_t) wPos;
            break;

        case PH_KEYSTORE_KEY_TYPE_AES256:
            /* Update the Key Index. */
            pDataParams->pKeyEntries[wKeyNo].bKeyIndex = (uint8_t) wPos;
            break;

        case PH_KEYSTORE_KEY_TYPE_DES:
        case PH_KEYSTORE_KEY_TYPE_2K3DES:
        case PH_KEYSTORE_KEY_TYPE_3K3DES:
        case PH_KEYSTORE_KEY_TYPE_MIFARE:
            /* Get the Key size. */
            pDataParams->pKeyEntries[wKeyNo].bKeyLen = phKeyStore_GetKeySize(wKeyType);
            pDataParams->pKeyEntries[wKeyNo].bKeyIndex = (uint8_t) PH_KEYSTORE_INVALID_ID;

            /* Copy the Key to DataParams. */
            (void) memcpy(pDataParams->pKeyEntries[wKeyNo].aKey, pNewKey, pDataParams->pKeyEntries[wKeyNo].bKeyLen);
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    return wStatus;
}

phStatus_t phKeyStore_PN76XX_SetFullKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wNoOfKeys, uint16_t wKeyNo,
    uint16_t wNewRefNoKUC, uint16_t wNewKeyType, uint8_t * pNewKeys, uint16_t * pNewKeyVerList)
{
    /* Satisfy compiler */
    if(pDataParams || wNoOfKeys || wKeyNo || wNewRefNoKUC || wNewKeyType || pNewKeys || pNewKeyVerList)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_GetKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVerBufSize,
    uint16_t * wKeyVer, uint16_t * wKeyVerLen, uint16_t * pKeyType)
{
    /* Satisfy compiler */
    if(pDataParams || wKeyNo || wKeyVerBufSize || wKeyVer || wKeyVerLen || pKeyType)
    {
        ;/* Do Nothing */
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}

phStatus_t phKeyStore_PN76XX_GetKey(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t bKeyBufSize,
    uint8_t * pKey, uint16_t * pKeyType)
{
    uint8_t     PH_MEMLOC_REM bCount = 0;

    /* Overflow checks */
    if(wKeyNo >= pDataParams->wNoOfKeyEntries)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    /* Overflow checks */
    if(bKeyBufSize < pDataParams->pKeyEntries[wKeyNo].bKeyLen)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_KEYSTORE);
    }

    /* Set the Key Type. */
    *pKeyType = pDataParams->pKeyEntries[wKeyNo].wKeyType;

    /* Set the Key. */
    switch(*pKeyType)
    {
        case PH_KEYSTORE_KEY_TYPE_AES128:
        case PH_KEYSTORE_KEY_TYPE_AES256:
            pKey[bCount++] = 'K'; pKey[bCount++] = 'I'; pKey[bCount++] = 'D';
            pKey[bCount++] = pDataParams->pKeyEntries[wKeyNo].bKeyIndex;
            break;

        case PH_KEYSTORE_KEY_TYPE_DES:
        case PH_KEYSTORE_KEY_TYPE_2K3DES:
        case PH_KEYSTORE_KEY_TYPE_3K3DES:
        case PH_KEYSTORE_KEY_TYPE_MIFARE:
            /* Copy the Key to DataParams. */
            (void) memcpy(pKey, pDataParams->pKeyEntries[wKeyNo].aKey, pDataParams->pKeyEntries[wKeyNo].bKeyLen);
            break;

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_PN76XX_CheckUpdateKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyUsageCtrNo)
{
    /* Satisfy compiler */
    if(pDataParams || wKeyUsageCtrNo)
    {
        ; /*Do Nothing*/
    }

    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_KEYSTORE);
}










#ifdef NXPBUILD__PH_KEYSTORE_PN76XX_NDA
phStatus_t phKeyStore_PN76XX_Provision_Init(phKeyStore_PN76XX_Provision_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pCryptoSymDataParams,
    uint16_t wOption, uint8_t *pTransportKey_AES128, uint8_t *pTransportKey_AES256, uint8_t *pAppRootKey_AES128, uint8_t *pAppRootKey_AES256,
    uint8_t *pExpDecData, uint8_t * pDervMsg, uint8_t * pWrapIV)
{
    phStatus_t  PH_MEMLOC_REM wStatus = 0;
    uint8_t     PH_MEMLOC_REM aWIV[16U];

    if(sizeof(phKeyStore_PN76XX_Provision_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_KEYSTORE);
    }
    PH_ASSERT_NULL(pDataParams);
    PH_ASSERT_NULL(pCryptoSymDataParams);
    PH_ASSERT_NULL(pAppRootKey_AES128);
    PH_ASSERT_NULL(pAppRootKey_AES256);
    PH_ASSERT_NULL(pExpDecData);
    PH_ASSERT_NULL(pDervMsg);

    /* Clear buffer */
    (void) memset(aWIV, 0x00, sizeof(aWIV));

    /* Copy WIV to local buffer. */
    if(pWrapIV != NULL)
    {
        (void) memcpy(aWIV, pWrapIV, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);
    }

    pDataParams->pCryptoSymDataParams = pCryptoSymDataParams;

    (void) memcpy(pDataParams->aAppRootKey_AES128, pAppRootKey_AES128, PH_KEYSTORE_KEY_TYPE_AES128_SIZE);
    (void) memcpy(pDataParams->aAppRootKey_AES256, pAppRootKey_AES256, PH_KEYSTORE_KEY_TYPE_AES256_SIZE);
    (void) memcpy(pDataParams->aExpDecData, pExpDecData, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);
    (void) memcpy(pDataParams->aDervMsg, pDervMsg, PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN);
    (void) memcpy(pDataParams->aWrapIV, aWIV, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);

    /* Provision AES128 and AES256 Application Root Keys. */
    if(wOption & PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_ENABLED)
    {
        /* Validate Parameters. */
        PH_ASSERT_NULL(pTransportKey_AES128);
        PH_ASSERT_NULL(pTransportKey_AES256);

        /* Provision AES128 Application Root Keys. */
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_ProvisionKey_AppRootKey(pCryptoSymDataParams, PH_KEYSTORE_PN76XX_APP_ROOT_KEY_INDEX,
            PH_KEYSTORE_PN76XX_AES_128_BIT_LEN, pTransportKey_AES128, pAppRootKey_AES128, pDervMsg, pExpDecData,
            aWIV));

        /* Provision AES256 Application Root Keys. */
        PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_ProvisionKey_AppRootKey(pCryptoSymDataParams, PH_KEYSTORE_PN76XX_APP_ROOT_KEY_INDEX,
            PH_KEYSTORE_PN76XX_AES_256_BIT_LEN, pTransportKey_AES256, pAppRootKey_AES256, pDervMsg, pExpDecData,
            aWIV));
    }
    else
    {
        /* Nothing to do here.
         * Status validation are handled in IF condition.
         */
    }

    return PH_ERR_SUCCESS;
}

void phKeyStore_PN76XX_Provision_DeInit(phKeyStore_PN76XX_Provision_DataParams_t * pDataParams)
{
    (void) memset(pDataParams->aAppRootKey_AES128, 0x00, PH_KEYSTORE_KEY_TYPE_AES128_SIZE);
    (void) memset(pDataParams->aAppRootKey_AES256, 0x00, PH_KEYSTORE_KEY_TYPE_AES256_SIZE);
    (void) memset(pDataParams->aExpDecData, 0x00, PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN);
    (void) memset(pDataParams->aDervMsg, 0x00, PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN);
    (void) memset(pDataParams->aWrapIV, 0x00, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);
}

phStatus_t phKeyStore_PN76XX_Provision_AppFixedKeys(phKeyStore_PN76XX_Provision_DataParams_t * pDataParams, uint8_t bKeyIndex, uint16_t wKeyType,
    uint8_t * pNewKey)
{
   phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

   /* Validate Key Index. */
   if((bKeyIndex < PH_KEYSTORE_PN76XX_APP_FIXED_KEY_INDEX_START) || (bKeyIndex > PH_KEYSTORE_PN76XX_APP_FIXED_KEY_INDEX_END))
   {
      return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
   }

   /* Load the Key */
   switch(wKeyType)
   {
       case PH_KEYSTORE_KEY_TYPE_AES128:
           /* Provision the Key. */
           PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_ProvisionKey_FixedKey(pDataParams->pCryptoSymDataParams, bKeyIndex,
               PH_KEYSTORE_PN76XX_AES_128_BIT_LEN, pDataParams->aAppRootKey_AES128, pNewKey, pDataParams->aDervMsg,
               pDataParams->aExpDecData, pDataParams->aWrapIV));
           break;

       case PH_KEYSTORE_KEY_TYPE_AES256:
           /* Provision the Key. */
           PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_ProvisionKey_FixedKey(pDataParams->pCryptoSymDataParams, bKeyIndex,
               PH_KEYSTORE_PN76XX_AES_256_BIT_LEN, pDataParams->aAppRootKey_AES256, pNewKey, pDataParams->aDervMsg,
               pDataParams->aExpDecData, pDataParams->aWrapIV));
           PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus((PN76_Status_t)wStatus));
           break;

       default:
           return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
   }

   return wStatus;

}

phStatus_t phKeyStore_PN76XX_SetConfig_Ext(phKeyStore_PN76XX_Provision_DataParams_t * pDataParams, uint16_t wConfig, uint8_t * pValue,
    uint16_t wValueLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    switch (wConfig)
    {
        case PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES128_BIT:
            if(wValueLen != PH_KEYSTORE_KEY_TYPE_AES128_SIZE)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);

            (void) memcpy(pDataParams->aAppRootKey_AES128, pValue, wValueLen);
            break;

        case PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES256_BIT:
            if(wValueLen != PH_KEYSTORE_KEY_TYPE_AES256_SIZE)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);

            (void) memcpy(pDataParams->aAppRootKey_AES256, pValue, wValueLen);
            break;

        case PH_KEYSTORE_CONFIG_DERIV_MSG:
            if(wValueLen != PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);

            (void) memcpy(pDataParams->aDervMsg, pValue, wValueLen);
            break;

        case PH_KEYSTORE_CONFIG_EXPECTED_DEC_DATA:
            if(wValueLen != PH_KEYSTORE_KEY_TYPE_AES128_SIZE)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);

            (void) memcpy(pDataParams->aExpDecData, pValue, wValueLen);
            break;

        case PH_KEYSTORE_CONFIG_WRAP_IV:
            if(wValueLen != PH_KEYSTORE_KEY_TYPE_AES128_SIZE)
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_SIZE, PH_COMP_KEYSTORE);

            (void) memcpy(pDataParams->aWrapIV, pValue, wValueLen);
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
            break;
    }

    return wStatus;
}

phStatus_t phKeyStore_PN76XX_GetConfig_Ext(phKeyStore_PN76XX_Provision_DataParams_t * pDataParams, uint16_t wConfig, uint8_t * pValue,
    uint16_t * pValueLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    switch (wConfig)
    {
        case PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES128_BIT:
            (void) memcpy(pValue, pDataParams->aAppRootKey_AES128, PH_KEYSTORE_KEY_TYPE_AES128_SIZE);
            *pValueLen = PH_KEYSTORE_KEY_TYPE_AES128_SIZE;
            break;

        case PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES256_BIT:
            (void) memcpy(pValue, pDataParams->aAppRootKey_AES256, PH_KEYSTORE_KEY_TYPE_AES256_SIZE);
            *pValueLen = PH_KEYSTORE_KEY_TYPE_AES256_SIZE;
            break;

        case PH_KEYSTORE_CONFIG_DERIV_MSG:
            (void) memcpy(pValue, pDataParams->aDervMsg, PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN);
            *pValueLen = PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN;
            break;

        case PH_KEYSTORE_CONFIG_EXPECTED_DEC_DATA:
            (void) memcpy(pValue, pDataParams->aExpDecData, PH_KEYSTORE_KEY_TYPE_AES128_SIZE);
            *pValueLen = PH_KEYSTORE_KEY_TYPE_AES128_SIZE;
            break;

        case PH_KEYSTORE_CONFIG_WRAP_IV:
            (void) memcpy(pValue, pDataParams->aWrapIV, PH_KEYSTORE_KEY_TYPE_AES128_SIZE);
            *pValueLen = PH_KEYSTORE_KEY_TYPE_AES128_SIZE;
            break;

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
            break;
    }

    return wStatus;
}

#endif /* NXPBUILD__PH_KEYSTORE_PN76XX_NDA */

#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */
