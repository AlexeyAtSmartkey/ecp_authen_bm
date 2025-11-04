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

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX_NDA

#include "phKeyStore_PN76XX_Int.h"

static uint8_t aZeroIV[16U] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

phStatus_t phKeyStore_PN76XX_ValidateStatus(PN76_Status_t wPN76_Status)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    switch(wPN76_Status)
    {
        case PH_KEYSTORE_PN76XX_SUCCESS:
            wStatus = PH_ERR_SUCCESS;
            break;

        case PH_KEYSTORE_PN76XX_ERR_BUSY:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_BUSY, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_PARAMETER_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_SKTU_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_SKTU_ERROR, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_SKTU_AUTH_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_AUTH_ERROR, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_LOCKED:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_LOCKED, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_SESSION_NOT_OPEN:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_SESSION_NOT_OPEN, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_KEY_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_KEY, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_LOCKED:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_APP_ROOT_KEY_LOCKED, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_NOT_INITIALIZED:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_NOT_INITIALIZED, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_INTEGRITY_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_ASYMM_HW_ACC_ERROR:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_ASYMM_HW_ACC_ERROR, PH_COMP_KEYSTORE);
            break;

        case PH_KEYSTORE_PN76XX_ERR_DP_NOT_SET:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_DP_NOT_SET, PH_COMP_KEYSTORE);
            break;

#ifdef NXPBUILD__PHHAL_HW_PN7642
        case PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_PROVISION:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_KEYSTORE_PN76XX_ERR_RSP_APP_ROOT_KEY_PROVISION, PH_COMP_KEYSTORE);
            break;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

        default:
            wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNKNOWN, PH_COMP_KEYSTORE);
            break;
    }

    return wStatus;
}

phStatus_t phKeyStore_PN76XX_ProvisionKey_AppRootKey(void * pCryptoSymDataParams, uint8_t bKeyIndex, uint8_t bKeyLen, uint8_t * pTransportKey,
    uint8_t * pAppRootKey, uint8_t *pDervMsg_Dec, uint8_t *pExpDecData, uint8_t * pWIV)
{
    phStatus_t                  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    PN76_Status_t               PH_MEMLOC_REM wPN76_Status = PN76_STATUS_SUCCESS;
    uint32_t                    PH_MEMLOC_REM dwDervProp = 0;
    uint8_t                     PH_MEMLOC_REM bKeyStoreStatus = 0;

    PN76_SKM_Data_SKM_Info_t    PH_MEMLOC_REM stSKM_Info;
    PN76_SKM_Data_OpenSession_t PH_MEMLOC_REM stSession;
    PN76_SKM_Data_RootKey_t     PH_MEMLOC_REM stRootKey;

#ifdef NXPBUILD__PHHAL_HW_PN7640
    uint8_t						PH_MEMLOC_REM bStatus = 0;
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

    /* Initialize the hardware KeyStore module. */
    wPN76_Status = PN76_Sys_SKM_Init();
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    /* Get Session State. */
    wPN76_Status = PN76_Sys_SKM_Get_SKM_Info(&stSKM_Info);
    PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

#ifdef NXPBUILD__PHHAL_HW_PN7640
    wPN76_Status = PN76_ReadEeprom(&bStatus, (uint16_t) (PH_KEYSTORE_PN76XX_EEPROM_APP_ROOT_KEY_LOC + bKeyLen), 1U);
    PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

    /* Check if Secure Key Module is not locked. */
    if((stSKM_Info.bSkmState & PH_KEYSTORE_PN76XX_SKM_STATE_LOCKED) != PH_KEYSTORE_PN76XX_SKM_STATE_LOCKED)
    {
        /* Check if Application root keys are not provisioned. */
#ifdef NXPBUILD__PHHAL_HW_PN7640
    	if(bStatus == PH_OFF)
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

#ifdef NXPBUILD__PHHAL_HW_PN7642
        if((stSKM_Info.bSkmState & PH_KEYSTORE_PN76XX_SKM_APP_ROOT_KEY_PROVISIONED) != PH_KEYSTORE_PN76XX_SKM_APP_ROOT_KEY_PROVISIONED)
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
        {
            /* Open session for Application Root Key. */
            stSession.bAuthType = PH_KEYSTORE_PN76XX_SKM_PROVISION_APP_ROOT_KEY;
            stSession.bKeyLen = bKeyLen;

            phKeyStore_PN76XX_CopyToUInt32(stSession.adwDerivMsgDecryptKey, pDervMsg_Dec, 6U);
            (void) memcpy(&stSession.abExpDecryptedData, pExpDecData, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);

            /* Generate the Open Session Encrypted Data. */
            dwDervProp = (PH_KEYSTORE_PN76XX_PROP_ENCRYPTION | PH_KEYSTORE_PN76XX_PROP_DECRYPTION |
                PH_KEYSTORE_PN76XX_PROP_LOCKED);
            PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateSessionInfo(
                pCryptoSymDataParams,
                stSKM_Info.dwCounter,
                dwDervProp,
                pTransportKey,
                bKeyLen,
                pDervMsg_Dec,
                pExpDecData,
                stSession.abEncryptedData));

            wStatus = PN76_Sys_SKM_OpenSession(&stSession);
            PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus((PN76_Status_t) wStatus));

            /* Provision Application Root Key. */
            stRootKey.bKeyLen = bKeyLen;
            phKeyStore_PN76XX_CopyToUInt32(stRootKey.adwDerivMsgWrappingKey, pDervMsg_Dec, 6U);

            /* Generate the wrapped key information for provisioning Application Root Key. */
            dwDervProp = (PH_KEYSTORE_PN76XX_PROP_LOCKED | PH_KEYSTORE_PN76XX_PROP_SEC_WORLD | PH_KEYSTORE_PN76XX_PROP_EXPORTED);
            PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateWrappedKey(
                pCryptoSymDataParams,
                dwDervProp,
                pTransportKey,
                pAppRootKey,
                bKeyLen,
                pDervMsg_Dec,
                pWIV,
                stRootKey.adwWrappedData));
            wStatus = PN76_Sys_SKM_Prov_App_RootKey(&stRootKey);
            PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus((PN76_Status_t) wStatus));

#ifdef NXPBUILD__PHHAL_HW_PN7640
            /* Update Key Provisioning status */
            bStatus = PH_ON;
            wPN76_Status = PN76_WriteEeprom(&bStatus, (uint16_t) (PH_KEYSTORE_PN76XX_EEPROM_APP_ROOT_KEY_LOC + bKeyLen), 1U);
            PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));
#endif /* NXPBUILD__PHHAL_HW_PN7640 */
        }

        /* Application Root Keys are already provisioned */
        else
        {
            wStatus = PH_ERR_SUCCESS;
        }
    }
    else
    {
        wStatus = PH_ERR_SUCCESS;
    }

    /* De-Initialize the hardware KeyStore module. */
    wPN76_Status = PN76_Sys_SKM_DeInit();
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    /* Perform Initialization of Crypto and other modules. */
    wPN76_Status = PN76_Sys_KeyStore_Init(&bKeyStoreStatus);
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    return wStatus;
}

phStatus_t phKeyStore_PN76XX_ProvisionKey_FixedKey(void * pCryptoSymDataParams, uint8_t bKeyIndex, uint8_t bKeyLen, uint8_t * pAppRootKey,
    uint8_t * pFixedKey, uint8_t * pDervMsg_Dec, uint8_t * pExpDecData, uint8_t * pWIV)
{
    phStatus_t                          PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    PN76_Status_t                       PH_MEMLOC_REM wPN76_Status = PN76_STATUS_SUCCESS;
    uint32_t                            PH_MEMLOC_REM dwDervProp = 0;
    uint8_t                             PH_MEMLOC_REM bKeyStoreStatus = 0;

    PN76_SKM_Data_SKM_Info_t            PH_MEMLOC_REM stSKM_Info;
    PN76_SKM_Data_OpenSession_t         PH_MEMLOC_REM stSession;
    PN76_SKM_Data_ProvUpd_FixedKey_t    PH_MEMLOC_REM stFixedKey;

#ifdef NXPBUILD__PHHAL_HW_PN7640
    uint8_t						PH_MEMLOC_REM bStatus = 0;
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

    /* Initialize the hardware KeyStore module. */
    wPN76_Status = PN76_Sys_SKM_Init();
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    /* Get Session State. */
    wPN76_Status = PN76_Sys_SKM_Get_SKM_Info(&stSKM_Info);
    PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

#ifdef NXPBUILD__PHHAL_HW_PN7640
    wPN76_Status = PN76_ReadEeprom(&bStatus, (uint16_t) (PH_KEYSTORE_PN76XX_EEPROM_APP_ROOT_KEY_LOC + bKeyLen), 1U);
    PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    if(bStatus == PH_ON)
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

#ifdef NXPBUILD__PHHAL_HW_PN7642
    /* Check if Application root keys are not provisioned. */
    if((stSKM_Info.bSkmState & PH_KEYSTORE_PN76XX_SKM_APP_ROOT_KEY_PROVISIONED) == PH_KEYSTORE_PN76XX_SKM_APP_ROOT_KEY_PROVISIONED)
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
    {
        /* Open session for Application Root Key. */
        stSession.bAuthType = PH_KEYSTORE_PN76XX_SKM_PROVISION_APP_FIXED_KEY;
        stSession.bKeyLen = bKeyLen;

        phKeyStore_PN76XX_CopyToUInt32(stSession.adwDerivMsgDecryptKey, pDervMsg_Dec, 6U);
        (void) memcpy(&stSession.abExpDecryptedData, pExpDecData, PH_KEYSTORE_PN76XX_KEY_DATA_LEN);

        /* Generate the Open Session Encrypted Data. */
        dwDervProp = (PH_KEYSTORE_PN76XX_PROP_ENCRYPTION | PH_KEYSTORE_PN76XX_PROP_DECRYPTION | PH_KEYSTORE_PN76XX_PROP_LOCKED);
        PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateSessionInfo(
            pCryptoSymDataParams,
            stSKM_Info.dwCounter,
            dwDervProp,
            pAppRootKey,
            bKeyLen,
            pDervMsg_Dec,
            pExpDecData,
            stSession.abEncryptedData));

        wPN76_Status = PN76_Sys_SKM_OpenSession(&stSession);
        PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

        /* Provision Application Fixed Key. */
        stFixedKey.bKeyLen = bKeyLen;
        stFixedKey.bKeyId = bKeyIndex;
        phKeyStore_PN76XX_CopyToUInt32(stFixedKey.adwDerivMsgWrappingKey, pDervMsg_Dec, 6U);

        /* Generate the wrapped key information for provisioning Application Fixed Key. */
        dwDervProp = (PH_KEYSTORE_PN76XX_PROP_LOCKED | PH_KEYSTORE_PN76XX_PROP_ENCRYPTION | PH_KEYSTORE_PN76XX_PROP_DECRYPTION);
        PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateWrappedKey(
            pCryptoSymDataParams,
            dwDervProp,
            pAppRootKey,
            pFixedKey,
            bKeyLen,
            pDervMsg_Dec,
            pWIV,
            stFixedKey.adwWrappedData));

        wPN76_Status = PN76_Sys_SKM_Update_App_FixedKey(&stFixedKey);

        /* Update Application Fixed key in case of failure. */
        if(wPN76_Status != PN76_STATUS_SUCCESS)
        {
            /* Get Session State. */
            wPN76_Status = PN76_Sys_SKM_Get_SKM_Info(&stSKM_Info);
            PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

            /* Generate the Open Session Encrypted Data. */
            dwDervProp = (PH_KEYSTORE_PN76XX_PROP_ENCRYPTION | PH_KEYSTORE_PN76XX_PROP_DECRYPTION |
                PH_KEYSTORE_PN76XX_PROP_LOCKED);
            PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateSessionInfo(
                pCryptoSymDataParams,
                stSKM_Info.dwCounter,
                dwDervProp,
                pAppRootKey,
                bKeyLen,
                pDervMsg_Dec,
                pExpDecData,
                stSession.abEncryptedData));

            wPN76_Status = PN76_Sys_SKM_OpenSession(&stSession);
            PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

            /* Provision Application Fixed Key. */
            stFixedKey.bKeyLen = bKeyLen;
            stFixedKey.bKeyId = bKeyIndex;
            phKeyStore_PN76XX_CopyToUInt32(stFixedKey.adwDerivMsgWrappingKey, pDervMsg_Dec, 6U);

            /* Generate the wrapped key information for provisioning Application Fixed Key. */
            dwDervProp = (PH_KEYSTORE_PN76XX_PROP_LOCKED | PH_KEYSTORE_PN76XX_PROP_ENCRYPTION | PH_KEYSTORE_PN76XX_PROP_DECRYPTION);
            PH_CHECK_SUCCESS_FCT_EXT(wStatus, phKeyStore_PN76XX_GenerateWrappedKey(
                pCryptoSymDataParams,
                dwDervProp,
                pAppRootKey,
                pFixedKey,
                bKeyLen,
                pDervMsg_Dec,
                pWIV,
                stFixedKey.adwWrappedData));

            wPN76_Status = PN76_Sys_SKM_Prov_App_FixedKey(&stFixedKey);
            PH_CHECK_SUCCESS_EXT(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));
        }
    }
    else
    {
        wStatus = PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_CRYPTOSYM);
    }

    /* De-Initialize the hardware KeyStore module. */
    wPN76_Status = PN76_Sys_SKM_DeInit();
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    /* Perform Initialization of Crypto and other modules. */
    wPN76_Status = PN76_Sys_KeyStore_Init(&bKeyStoreStatus);
    PH_CHECK_SUCCESS(phKeyStore_PN76XX_ValidateStatus(wPN76_Status));

    return wStatus;
}

phStatus_t phKeyStore_PN76XX_GenerateSessionInfo(void * pCryptoSymDataParams, uint32_t dwCounter, uint32_t dwDervProp_Options, uint8_t * pKey,
    uint8_t bKeyLen, uint8_t * pDervMsg_Dec, uint8_t * pExpDecData, uint8_t * pEncData)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;

    uint8_t     PH_MEMLOC_REM aEncDecKey[PH_KEYSTORE_KEY_TYPE_AES256_SIZE];

    /* Clear Buffers. */
    (void) memset(aEncDecKey, 0x00, sizeof(aEncDecKey));

    /* Generate Derived Key. */
    wKeyType = (uint16_t) ((bKeyLen == PH_KEYSTORE_PN76XX_AES_256_BIT_LEN) ? PH_CRYPTOSYM_KEY_TYPE_AES256 : PH_CRYPTOSYM_KEY_TYPE_AES128);
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_GenerateDerivedKey(
        pCryptoSymDataParams,
        PH_KEYSTORE_PN76XX_COUNTER_ENABLED,
        16U,
        4U,
        dwCounter,
        dwDervProp_Options,
        pKey,
        bKeyLen,
        wKeyType,
        pDervMsg_Dec,
        aEncDecKey));

    /* Generate the Challenge. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
        pCryptoSymDataParams,
        aEncDecKey,
        wKeyType));

    /* Load Zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(pCryptoSymDataParams, aZeroIV, (uint8_t) sizeof(aZeroIV)));

    /* Compute AES-ECB encryption on the expected Decrypted Data. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
        pCryptoSymDataParams,
        PH_CRYPTOSYM_CIPHER_MODE_ECB,
        pExpDecData,
        PH_KEYSTORE_PN76XX_KEY_DATA_LEN,
        pEncData));

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_PN76XX_GenerateWrappedKey(void * pCryptoSymDataParams, uint32_t dwKeyProp_Options, uint8_t * pTransport_APPKey,
    uint8_t * pProvisionKey, uint8_t bKeyLen, uint8_t * pDervMsg_Dec, uint8_t * pWIV, uint32_t * pWrappedKey)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint16_t    PH_MEMLOC_REM wKeyConfig = 0;
    uint16_t    PH_MEMLOC_REM wKeyType = 0;
    uint8_t     PH_MEMLOC_REM bIndex = 0;
    uint8_t     PH_MEMLOC_REM bMacLen = 0;

    uint8_t     PH_MEMLOC_REM aWrappingKey[PH_KEYSTORE_KEY_TYPE_AES256_SIZE];
    uint8_t     PH_MEMLOC_REM aKeyProp[PH_KEYSTORE_KEY_TYPE_AES128_SIZE];
    uint8_t     PH_MEMLOC_REM aWrappedKey[80U];

    /* Clear Buffers. */
    (void) memset(aWrappingKey, 0x00, sizeof(aWrappingKey));
    (void) memset(aKeyProp, 0x00, sizeof(aKeyProp));
    (void) memset(aWrappedKey, 0x00, sizeof(aWrappedKey));

    /* Generate Derived Key. */
    wKeyType = (uint16_t) ((bKeyLen == PH_KEYSTORE_PN76XX_AES_256_BIT_LEN) ? PH_CRYPTOSYM_KEY_TYPE_AES256 : PH_CRYPTOSYM_KEY_TYPE_AES128);
    PH_CHECK_SUCCESS_FCT(wStatus, phKeyStore_PN76XX_GenerateDerivedKey(
        pCryptoSymDataParams,
        PH_KEYSTORE_PN76XX_COUNTER_DISABLED,
        16U,
        8U,
        0U,
        (PH_KEYSTORE_PN76XX_PROP_LOCKED | PH_KEYSTORE_PN76XX_PROP_WRAPPING),
        pTransport_APPKey,
        bKeyLen,
        wKeyType,
        pDervMsg_Dec,
        aWrappingKey));

    /* Copy the provision key to Wrapped buffer.
     * This will convert 128-Bit key to 256-Bit key by adding zeros at last.
     */
    (void) memcpy(aWrappedKey, pProvisionKey, phKeyStore_GetKeySize(wKeyType));

    /* Generate Key Properties */
    if(dwKeyProp_Options & PH_KEYSTORE_PN76XX_PROP_EXPORTED) wKeyConfig |= (0x01U << 9U);
    if(dwKeyProp_Options & PH_KEYSTORE_PN76XX_PROP_LOCKED) wKeyConfig |= (0x01U << 8U);
    wKeyConfig |= ((bKeyLen + 1) << 6U);
    if(dwKeyProp_Options & PH_KEYSTORE_PN76XX_PROP_ENCRYPTION) wKeyConfig |= (0x01U << 3U);
    if(dwKeyProp_Options & PH_KEYSTORE_PN76XX_PROP_DECRYPTION) wKeyConfig |= (0x01U << 2U);
    if(dwKeyProp_Options & PH_KEYSTORE_PN76XX_PROP_WRAPPING) wKeyConfig |= (0x01U << 1U);
    wKeyConfig |= 0x01U; /* Key wrap always set to 1 */

    /* Convert to Array. */
    aKeyProp[14] = (uint8_t) ((wKeyConfig & 0xFF00) >> 8);
    aKeyProp[15] = (uint8_t) ((wKeyConfig & 0x00FF) >> 0);

    /* Generate Cipher Text. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
        pCryptoSymDataParams,
        aWrappingKey,
        wKeyType));

    /* Load WIV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(pCryptoSymDataParams, pWIV, PH_KEYSTORE_KEY_TYPE_AES128_SIZE));

    /* Compute AES-CBC encryption on the Actual Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
        pCryptoSymDataParams,
        (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_FIRST),
        aWrappedKey,
        PH_KEYSTORE_KEY_TYPE_AES256_SIZE,
        aWrappedKey));

    /* Compute AES-CBC encryption on the Key Configuration. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_Encrypt(
        pCryptoSymDataParams,
        (uint16_t) (PH_CRYPTOSYM_CIPHER_MODE_CBC | PH_EXCHANGE_BUFFER_LAST),
        aKeyProp,
        PH_KEYSTORE_KEY_TYPE_AES128_SIZE,
        &aWrappedKey[PH_KEYSTORE_KEY_TYPE_AES256_SIZE]));

    /* Perform XOR for the first 16 bytes of Wrapping Key. */
    for(bIndex = 0; bIndex < PH_KEYSTORE_KEY_TYPE_AES128_SIZE; bIndex++)
    {
        aWrappingKey[bIndex] ^= 0xFF;
    }

    /* Generate Cipher Text. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
        pCryptoSymDataParams,
        aWrappingKey,
        wKeyType));

    /* Load Zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(pCryptoSymDataParams, aZeroIV, PH_KEYSTORE_KEY_TYPE_AES128_SIZE));

    /* Compute Tag */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
        pCryptoSymDataParams,
        (uint16_t) (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_FIRST),
        pWIV,
        PH_KEYSTORE_KEY_TYPE_AES128_SIZE,
        &aWrappedKey[48U],
        &bMacLen));

    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
        pCryptoSymDataParams,
        (uint16_t) (PH_CRYPTOSYM_MAC_MODE_CMAC | PH_EXCHANGE_BUFFER_LAST),
        aWrappedKey,
        48U,
        &aWrappedKey[48U],
        &bMacLen));

    /* Add the Reversed IV to buffer. */
    for(bIndex = 0; bIndex < PH_KEYSTORE_KEY_TYPE_AES128_SIZE; bIndex++)
    {
        aWrappedKey[48U + bMacLen + bIndex] = pWIV[PH_KEYSTORE_KEY_TYPE_AES128_SIZE - (bIndex + 1)];
    }

    /* Convert bytes to uint32 format */
    phKeyStore_PN76XX_CopyToUInt32(pWrappedKey, aWrappedKey, 20);

    return PH_ERR_SUCCESS;
}

phStatus_t phKeyStore_PN76XX_GenerateDerivedKey(void * pCryptoSymDataParams, uint8_t bCtrEn, uint8_t bStart, uint8_t bLen, uint32_t dwCounter,
    uint32_t dwDervProp_Options, uint8_t * pKey, uint8_t bKeyLen, uint16_t wKeyType, uint8_t * pDervMsg_Dec, uint8_t * pDerivedKey)
{
    phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    uint32_t    PH_MEMLOC_REM dwDervProp = 0;
    uint32_t    PH_MEMLOC_REM dwConstant = 0;
    uint8_t     PH_MEMLOC_REM bDerivMsgLen = 0;
    uint8_t     PH_MEMLOC_REM bMacLen = 0;

    uint8_t     PH_MEMLOC_REM aDerivMsg[PH_KEYSTORE_KEY_TYPE_AES256_SIZE];

    /* Clear Buffers. */
    (void) memset(aDerivMsg, 0x00, sizeof(aDerivMsg));

    /* Generate the derivation properties. */
    if(dwDervProp_Options & PH_KEYSTORE_PN76XX_PROP_SEC_WORLD) dwDervProp |= ( 0x01U << 15U );
    dwDervProp |= ((bKeyLen + 1) << 9U);
    if(dwDervProp_Options & PH_KEYSTORE_PN76XX_PROP_ENCRYPTION) dwDervProp |= ( 0x01U << 6U );
    if(dwDervProp_Options & PH_KEYSTORE_PN76XX_PROP_DECRYPTION) dwDervProp |= ( 0x01U << 5U );
    if(dwDervProp_Options & PH_KEYSTORE_PN76XX_PROP_WRAPPING) dwDervProp |= ( 0x01U << 4U );
    if(dwDervProp_Options & PH_KEYSTORE_PN76XX_PROP_EXPORTED) dwDervProp |= ( 0x01U << 2U );

    /* Generate the Derived Message. */
    (void) memcpy(&aDerivMsg[bDerivMsgLen], &pDervMsg_Dec[bStart], bLen);
    bDerivMsgLen = bLen;

    if(bCtrEn == PH_KEYSTORE_PN76XX_COUNTER_ENABLED)
    {
        phKeyStore_PN76XX_CopyToBytes(&aDerivMsg[bDerivMsgLen], dwCounter);
        bDerivMsgLen += 4U;
    }

    (void) memcpy(&aDerivMsg[bDerivMsgLen], (uint8_t *) &dwConstant, 4U);
    bDerivMsgLen += 4U;

    phKeyStore_PN76XX_CopyToBytes(&aDerivMsg[bDerivMsgLen], dwDervProp);
    bDerivMsgLen += 4U;

    (void) memcpy(&aDerivMsg[bDerivMsgLen], &pDervMsg_Dec[0U], bStart);
    bDerivMsgLen += 16U;

    /* Load the Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadKeyDirect(
        pCryptoSymDataParams,
        pKey,
        wKeyType));

    /* Load Zero IV. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(pCryptoSymDataParams, aZeroIV, (uint8_t) sizeof(aZeroIV)));

    /* Compute Open Session AES Encryption / Decryption Key. */
    PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
        pCryptoSymDataParams,
        PH_CRYPTOSYM_MAC_MODE_CMAC,
        aDerivMsg,
        bDerivMsgLen,
        &pDerivedKey[0],
        &bMacLen));

    /* Generate next set of CMAC for AES 256-Bit Key. */
    if(bKeyLen == PH_KEYSTORE_PN76XX_AES_256_BIT_LEN)
    {
        aDerivMsg[15] |= 0x01;

        /* Load Zero IV. */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_LoadIv(pCryptoSymDataParams, aZeroIV, (uint8_t) sizeof(aZeroIV)));

        /* Compute Open Session AES Encryption / Decryption Key. */
        PH_CHECK_SUCCESS_FCT(wStatus, phCryptoSym_CalculateMac(
            pCryptoSymDataParams,
            PH_CRYPTOSYM_MAC_MODE_CMAC,
            aDerivMsg,
            bDerivMsgLen,
            &pDerivedKey[bMacLen],
            &bMacLen));
    }

    return PH_ERR_SUCCESS;
}

void phKeyStore_PN76XX_CopyToUInt32(uint32_t * pData, uint8_t * pBuffer, uint8_t bLen)
{
    uint8_t PH_MEMLOC_REM bIndex = 0;

    for(bIndex = 0; bIndex < bLen; bIndex++)
    {
        pData[bIndex] =
                (pBuffer[(bIndex * 4) + 0] << 24) |
                (pBuffer[(bIndex * 4) + 1] << 16) |
                (pBuffer[(bIndex * 4) + 2] << 8) |
                (pBuffer[(bIndex * 4) + 3] << 0);
    }
}

void phKeyStore_PN76XX_CopyToBytes(uint8_t * pBuffer, uint32_t dwData)
{
    pBuffer[0] = (uint8_t) ((dwData & 0xFF000000) >> 24);
    pBuffer[1] = (uint8_t) ((dwData & 0x00FF0000) >> 16);
    pBuffer[2] = (uint8_t) ((dwData & 0x0000FF00) >> 8);
    pBuffer[3] = (uint8_t) ((dwData & 0x000000FF) >> 0);
}

#endif /* NXPBUILD__PH_KEYSTORE_PN76XX_NDA */
