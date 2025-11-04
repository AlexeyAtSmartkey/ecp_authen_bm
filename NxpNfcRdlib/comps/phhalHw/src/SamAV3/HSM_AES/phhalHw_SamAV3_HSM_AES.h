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

#ifndef PHHALHW_SAMAV3_HSM_AES_H
#define PHHALHW_SAMAV3_HSM_AES_H

#ifdef NXPBUILD__PHHAL_HW_SAMAV3

#include <ph_Status.h>

/** \defgroup phhalHw_SamAV3_HSM_AES AES Host Secure Messaging
 * \brief Provides a Secure Messaging interface for AES mode.
 * @{
 */

/**
 * \brief Perform Encryption using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_Encrypt(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to encrypt. */
		uint16_t wTxLength,													/**< [In] Length of data to encrypt. */
		uint16_t wBufferSize,												/**< [In] Size of the buffer. */
		uint16_t * pTxLength,												/**< [Out] Number of encrypted data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Perform Decryption using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_Decrypt(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to decrypt. */
		uint16_t wRxLength,													/**< [In] Length of data to decrypt. */
		uint16_t * pRxLength,												/**< [Out] Number of decrypted data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Append MAC to a data stream using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_AppendMac(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] Data to mac. */
		uint16_t wTxLength,													/**< [In] Length of data to mac. */
		uint16_t wBufferSize,												/**< [In] Size of the buffer. */
		uint16_t * pTxLength,												/**< [Out] Number of data bytes incl. MAC. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);

/**
 * \brief Remove Mac and verify it using SamAV3 Host Protocol
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlaying component.
 */
phStatus_t phhalHw_SamAV3_HSM_AES_VerifyRemoveMac(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t * pBuffer,													/**< [In] data to unmac. */
		uint16_t wRxLength,													/**< [In] length of data to unmac. */
		uint16_t * pRxLength,												/**< [Out] number of unmaced data bytes. */
		uint8_t bFirst,														/**< [In] Whether this is the first block. */
		uint8_t bLast														/**< [In] Whether this is the last block. */
	);


phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastCommand(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t bCmd,														/**< [In] Command code. */
		uint8_t bP1,														/**< [In] P1 of command. */
		uint8_t bP2,														/**< [In] P2 of command. */
		uint8_t * pFirstCmd,												/**< [Out] Whether this is the first block. */
		uint8_t * pLastCmd													/**< [Out] Whether this is the last block. */
	);

phStatus_t phhalHw_SamAV3_HSM_AES_GetFirstLastResponse(
		phhalHw_SamAV3_DataParams_t * pDataParams,							/**< [In] Pointer to this layer's parameter structure. */
		uint8_t bSw1,														/**< [In] SW1 of response. */
		uint8_t bSw2,														/**< [In] SW2 of response. */
		uint8_t * pFirstResponse,											/**< [Out] Whether this is the first block. */
		uint8_t * pLastResponse												/**< [Out] Whether this is the last block. */
	);

phStatus_t phhalHw_SamAV3_HSM_AES_InitAndLoadIV(
		phhalHw_SamAV3_DataParams_t * pDataParams,
		uint8_t* pIV,
		uint8_t encryptionIV
	);

/** @}
* end of phhalHw_SamAV3_HSM_AES group
*/

#endif /* NXPBUILD__PHHAL_HW_SAMAV3 */
#endif /* PHHALHW_SAMAV3_HSM_AES_H */
