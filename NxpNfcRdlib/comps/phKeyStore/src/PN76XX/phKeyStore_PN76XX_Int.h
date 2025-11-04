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

#ifndef PHKEYSTORE_PN76XX_INT_H
#define PHKEYSTORE_PN76XX_INT_H

#include <ph_Status.h>

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX_NDA

#include <phKeyStore.h>
#include <phCryptoSym.h>
#include "PN76_SKM.h"

#ifdef NXPBUILD__PHHAL_HW_PN7642
#include <PN76_Status.h>
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#ifdef NXPBUILD__PHHAL_HW_PN7640
#include <PN76_Eeprom.h>
#include <ph_FlashInterface.h>
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

#define PH_KEYSTORE_PN76XX_AES_128_BIT_LEN                      0U
#define PH_KEYSTORE_PN76XX_AES_256_BIT_LEN                      1U

#define PH_KEYSTORE_PN76XX_COUNTER_ENABLED                      PH_ON
#define PH_KEYSTORE_PN76XX_COUNTER_DISABLED                     PH_OFF

/* SKM States */
#define PH_KEYSTORE_PN76XX_SKM_STATE_LOCKED                     0x01U
#define PH_KEYSTORE_PN76XX_SKM_APP_ROOT_KEY_PROVISIONED         0x50U

/* Auth Types */
#define PH_KEYSTORE_PN76XX_SKM_PROVISION_APP_ROOT_KEY           0x00U
#define PH_KEYSTORE_PN76XX_SKM_PROVISION_APP_FIXED_KEY          0x01U


/* Key Indexes */
#define PH_KEYSTORE_PN76XX_APP_ROOT_KEY_INDEX                   0x00U
#define PH_KEYSTORE_PN76XX_APP_FIXED_KEY_INDEX_START            0x10U
#define PH_KEYSTORE_PN76XX_APP_FIXED_KEY_INDEX_END              0x1AU


#define PH_KEYSTORE_PN76XX_DERIVATION_MSG_LEN                   24U
#define PH_KEYSTORE_PN76XX_KEY_DATA_LEN                         16U
#define PH_KEYSTORE_PN76XX_WRAP_DATA_LEN                        80U

/* Derivation properties. */
#define PH_KEYSTORE_PN76XX_PROP_SEC_WORLD                   0x0001U /* Sec world field is used for derivation */
#define PH_KEYSTORE_PN76XX_PROP_ENCRYPTION                  0x0080U /* Key can be used for encryption */
#define PH_KEYSTORE_PN76XX_PROP_DECRYPTION                  0x0100U /* Key can be used for decryption */
#define PH_KEYSTORE_PN76XX_PROP_WRAPPING                    0x0200U /* Key can be used for wrapping */
#define PH_KEYSTORE_PN76XX_PROP_EXPORTED                    0x0800U /* Key can be exported */
#define PH_KEYSTORE_PN76XX_PROP_LOCKED                      0x1000U /* Key is locked */

#ifdef NXPBUILD__PHHAL_HW_PN7640
/* EEPORM Location for APPLICATION ROOT Key Provision status. */
#define PH_KEYSTORE_PN76XX_EEPROM_APP_ROOT_KEY_LOC			0x0D00U
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

#define PH_CHECK_SUCCESS_EXT(status)            \
    {                                           \
        if ((status) != PH_ERR_SUCCESS)         \
        {                                       \
            PN76_Sys_SKM_DeInit();              \
            return (status);                    \
        }                                       \
    }

#define PH_CHECK_SUCCESS_FCT_EXT(status,fct)    \
    {                                           \
        (status) = (fct);                       \
        PH_CHECK_SUCCESS_EXT(status);           \
    }

phStatus_t phKeyStore_PN76XX_ValidateStatus(PN76_Status_t wPN76_Status);

phStatus_t phKeyStore_PN76XX_ProvisionKey_AppRootKey(void * pCryptoSymDataParams, uint8_t bKeyIndex, uint8_t bKeyLen, uint8_t * pTransportKey,
    uint8_t * pAppRootKey, uint8_t *pDervMsg_Dec, uint8_t *pExpDecData, uint8_t * pWIV);

phStatus_t phKeyStore_PN76XX_ProvisionKey_FixedKey(void * pCryptoSymDataParams, uint8_t bKeyIndex, uint8_t bKeyLen, uint8_t * pAppRootKey,
    uint8_t * pFixedKey, uint8_t * pDervMsg_Dec, uint8_t * pExpDecData, uint8_t * pWIV);

phStatus_t phKeyStore_PN76XX_GenerateSessionInfo(void * pCryptoSymDataParams, uint32_t dwCounter, uint32_t dwDervProp_Options, uint8_t * pKey,
    uint8_t bKeyLen, uint8_t * pDervMsg_Dec, uint8_t * pExpDecData, uint8_t * pEncData);

phStatus_t phKeyStore_PN76XX_GenerateWrappedKey(void * pCryptoSymDataParams, uint32_t dwKeyProp_Options, uint8_t * pTransport_APPKey,
    uint8_t * pProvisionKey, uint8_t bKeyLen, uint8_t * pDervMsg_Dec, uint8_t * pWIV, uint32_t * pWrappedKey);

phStatus_t phKeyStore_PN76XX_GenerateDerivedKey(void * pCryptoSymDataParams, uint8_t bCtrEn, uint8_t bStart, uint8_t bLen, uint32_t dwCounter,
    uint32_t dwDervProp_Options, uint8_t * pKey, uint8_t bKeyLen, uint16_t wKeyType, uint8_t * pDervMsg_Dec, uint8_t * pDerivedKey);

void phKeyStore_PN76XX_CopyToUInt32(uint32_t * pData, uint8_t * pBuffer, uint8_t bLen);

void phKeyStore_PN76XX_CopyToBytes(uint8_t * pBuffer, uint32_t dwData);

#endif /* NXPBUILD__PH_KEYSTORE_PN76XX_NDA */

#endif /* PHKEYSTORE_PN76XX_INT_H */
