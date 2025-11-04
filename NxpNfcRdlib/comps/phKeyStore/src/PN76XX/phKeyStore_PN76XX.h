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

#ifndef PHKEYSTORE_PN76XX_H
#define PHKEYSTORE_PN76XX_H

#include <ph_Status.h>

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX

#include <phKeyStore.h>
#include "phKeyStore_PN76XX_Int.h"

#include "PN76_SKM.h"
#ifdef NXPBUILD__PHHAL_HW_PN7642
#include <PN76_Status.h>
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#ifdef NXPBUILD__PHHAL_HW_PN7640
#include <ph_FlashInterface.h>
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

/* Common Interfaces ------------------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_PN76XX_FormatKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wNewKeyType);

phStatus_t phKeyStore_PN76XX_SetKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wRefNoKUC);

phStatus_t phKeyStore_PN76XX_GetKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t * pdwLimit,
    uint32_t * pdwCurVal);

phStatus_t phKeyStore_PN76XX_ChangeKUC(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wRefNoKUC, uint32_t dwLimit);

phStatus_t phKeyStore_PN76XX_SetConfig(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue);

phStatus_t phKeyStore_PN76XX_SetConfigStr(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint8_t *pBuffer,
    uint16_t wBufferLength);

phStatus_t phKeyStore_PN76XX_GetConfig(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue);

phStatus_t phKeyStore_PN76XX_GetConfigStr(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wConfig, uint8_t ** ppBuffer,
    uint16_t * pBufferLength);





/* Interfaces for Symmetric Keys ------------------------------------------------------------------------------------------------------- */
phStatus_t phKeyStore_PN76XX_SetKey(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVersion,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVersion);

phStatus_t phKeyStore_PN76XX_SetKeyAtPos(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wPos,
    uint16_t wKeyType, uint8_t * pNewKey, uint16_t wNewKeyVersion);

phStatus_t phKeyStore_PN76XX_SetFullKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wNoOfKeys, uint16_t wKeyNo,
    uint16_t wNewRefNoKUC, uint16_t wNewKeyType, uint8_t * pNewKeys, uint16_t * pNewKeyVersionList);

phStatus_t phKeyStore_PN76XX_GetKeyEntry(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVersionBufSize,
    uint16_t * wKeyVersion, uint16_t * wKeyVersionLength, uint16_t * pKeyType);

phStatus_t phKeyStore_PN76XX_GetKey(phKeyStore_PN76XX_DataParams_t * pDataParams, uint16_t wKeyNo, uint16_t wKeyVersion,
    uint8_t bKeyBufSize, uint8_t * pKey, uint16_t * pKeyType);






#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */

#endif /* PHKEYSTORE_PN76XX_H */
