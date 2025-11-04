/*----------------------------------------------------------------------------*/
/* Copyright 2021,2022 NXP                                                    */
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
*
* Pn76xx Generic HAL interface implementation.
*
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/

#ifndef PHHALHW_PN76XX_H
#define PHHALHW_PN76XX_H

#include <ph_Status.h>

#ifdef NXPBUILD__PHHAL_HW_PN76XX
#include <phhalHw.h>

#define A_MODE                               0x01U
#define B_MODE                               0x02U
#define F_MODE                               0x04U

#define ACTIVE_A_MODE                        0x0100U
#define ACTIVE_B_MODE                        0x0200U
#define ACTIVE_F_MODE                        0x0400U

#define PHHAL_HW_PN76XX_I18092MT_START_BYTE  0xF0U   /**< Start Byte to be added to the protocol header in case protocol ISO18092. */

/**
* \brief Pn76xx implementation of Exchange.
*
* \sa phhalHw_Exchange
*/
phStatus_t phhalHw_Pn76xx_Exchange(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,                                 /**< [In] Option parameter. */
    uint8_t * pTxBuffer,                              /**< [In] Data to transmit. */
    uint16_t wTxLength,                               /**< [In] Number of bytes to transmit. */
    uint8_t ** ppRxBuffer,                            /**< [Out] Pointer to received data. */
    uint16_t * pRxLength                              /**< [Out] Number of received data bytes. */
    );

/**
* \brief Pn76xx implementation of SetConfig.
*
* \sa phhalHw_SetConfig
*/
phStatus_t phhalHw_Pn76xx_SetConfig(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                                 /**< [In] Configuration Identifier. */
    uint16_t wValue                                   /**< [In] Configuration Value. */
    );

/**
* \brief Pn76xx implementation of GetConfig.
*
* \sa phhalHw_GetConfig
*/
phStatus_t phhalHw_Pn76xx_GetConfig(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                                 /**< [In] Configuration Identifier. */
    uint16_t * pValue                                 /**< [Out] Configuration Value. */
    );

/**
* \brief Pn76xx implementation of MfcAuthenticateKeyNo.
*
* \sa phhalHw_MfcAuthenticateKeyNo
*/
phStatus_t phhalHw_Pn76xx_MfcAuthenticateKeyNo(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bBlockNo,                                 /**< [In] Block-Number on card to authenticate to. */
    uint8_t bKeyType,                                 /**< [In] Either #PHHAL_HW_MFC_KEYA or #PHHAL_HW_MFC_KEYB. */
    uint16_t wKeyNo,                                  /**< [In] Key number to be used in authentication. */
    uint16_t wKeyVersion,                             /**< [In] Key version to be used in authentication. */
    uint8_t * pUid                                    /**< [In] Serial number of current cascade level; uint8_t[4]. */
    );

/**
* \brief Pn76xx implementation of MfcAuthenticate.
*
* \sa phhalHw_MfcAuthenticate
*/
phStatus_t phhalHw_Pn76xx_MfcAuthenticate(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bBlockNo,                                 /**< [In] Block number. */
    uint8_t bKeyType,                                 /**< [In] Key type to be used KEY_A or KEY_B. */
    uint8_t * pKey,                                   /**< [In] Key to be used for authentication. */
    uint8_t * pUid                                    /**< [In] UID of the tag to be authenticated. */
    );

/**
* \brief Pn76xx implementation of ApplyProtocolSettings.
*
* \sa phhalHw_ApplyProtocolSettings
*/
phStatus_t phhalHw_Pn76xx_ApplyProtocolSettings(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bCardType                                 /**< [In] Type of card for which the HAL should be configured for. */
    );

/**
* \brief Pn76xx implementation of FieldOn.
*
* \sa phhalHw_FieldOn
*/
phStatus_t phhalHw_Pn76xx_FieldOn(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of FieldOff.
*
* \sa phhalHw_FieldOff
*/
phStatus_t phhalHw_Pn76xx_FieldOff(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of FieldReset.
*
* \sa phhalHw_FieldReset
*/
phStatus_t phhalHw_Pn76xx_FieldReset(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of Wait.
*
* \sa phhalHw_Wait
*/
phStatus_t phhalHw_Pn76xx_Wait(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bUnit,                                    /**< [In] Unit of given timeout value (either #PHHAL_HW_TIME_MICROSECONDS or #PHHAL_HW_TIME_MILLISECONDS). */
    uint16_t wTimeout                                 /**< [In] Timeout value. */
    );


/**
* \brief Pn76xx implementation of Transmit.
*
* \sa phhalHw_Transmit
*/
phStatus_t phhalHw_Pn76xx_Transmit(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,                                 /**< [In] Option parameter. */
    uint8_t * pTxBuffer,                              /**< [In] Data to transmit. */
    uint16_t wTxLength                                /**< [In] Number of bytes to transmit. */
    );

/**
* \brief Pn76xx implementation of Receive.
*
* \sa phhalHw_Receive
*/
phStatus_t phhalHw_Pn76xx_Receive(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wOption,                                 /**< [In] Option parameter. */
    uint8_t ** ppRxBuffer,                            /**< [Out] Pointer to received data. */
    uint16_t * pRxLength                              /**< [Out] Number of received data bytes. */
    );

/**
* \brief Pn76xx implementation of Autocoll.
*
* \sa phhalHw_Autocoll
*/
phStatus_t phhalHw_Pn76xx_Autocoll(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wMode,                                   /**< [In] Autocoll Mode. */
    uint8_t ** ppRxBuffer,                            /**< [Out] Pointer to received data. */
    uint16_t * pRxLength,                             /**< [Out] Number of received data bytes. */
    uint16_t * pProtParams
    );


/**
* \brief Pn76xx implementation LPCD.
* Note: This API is applicable only for PN7642 variant.
*
* \sa phhalHw_Lpcd
*/
phStatus_t phhalHw_Pn76xx_Lpcd(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of abort command.
*
* \sa phhalHw_AsyncAbort
*/
phStatus_t phhalHw_Pn76xx_AsyncAbort(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of I18000p3m3Inventory command.
* Note: This API is applicable for only PN7642 variant.
*
* \sa phhalHw_I18000p3m3Inventory
*/
phStatus_t phhalHw_Pn76xx_I18000p3m3Inventory(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t * pSelCmd,                                /**< [In] ISO 18000p3m3 Select command frame. */
    uint8_t bSelCmdLen,                               /**< [In] Select command length in bytes- 1 to 39 bytes. */
    uint8_t bNumValidBitsinLastByte,                  /**< [In] Number of valid bits in last byte of pSelCmd. */
    uint8_t * pBeginRndCmd,                           /**< [In] ISO 18000p3m3 BeginRound command frame. This is 17bits i.e., 3 bytes are expected. CRC5 should not be provided. */
    uint8_t bTSprocessing,                            /**< [In] TimeSlot processing behavior. */
    uint8_t ** ppRxBuffer,                            /**< [In] Pointer to HAL RX Buffer containing response from single/multiple tags. */
    uint16_t * wRxBufferLen                           /**< [In] Length of response in HAL RX Buffer. */
    );

/**
* \brief Pn76xx implementation of I18000p3m3ResumeInventory command.
* Note: This API is applicable for only PN7642 variant.
*
* \sa phhalHw_I18000p3m3ResumeInventory
*/
phStatus_t phhalHw_Pn76xx_18000p3m3ResumeInventory(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** ppRxBuffer,                            /**< [In] Pointer to HAL RX Buffer containing response from single/multiple tags. */
    uint16_t * wRxBufferLen                           /**< [In] Length of response in HAL RX Buffer. */
    );

/**
* \brief Pn76xx implementation of EventWait command.
*
* \sa phhalHw_EventWait
*/
phStatus_t phhalHw_Pn76xx_EventWait(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint32_t dwEventTimeout                           /**< [In] Event time out. */
    );

/**
* \brief Pn76xx implementation of EventConsume command.
*
* \sa phhalHw_EventConsume
*/
phStatus_t phhalHw_Pn76xx_EventConsume(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

/**
* \brief Pn76xx implementation of DeInit command.
*
* \sa phhalHw_DeInit
*/
phStatus_t phhalHw_Pn76xx_DeInit(
    phhalHw_Pn76xx_DataParams_t * pDataParams         /**< [In] Pointer to this layer's parameter structure. */
    );

#endif /*NXPBUILD__PHHAL_HW_PN76XX*/
#endif  /* PHHALHW_PN76XX_H */
