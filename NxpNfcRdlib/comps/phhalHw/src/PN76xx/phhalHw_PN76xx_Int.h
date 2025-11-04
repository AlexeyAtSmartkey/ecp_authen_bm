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
* Internal functions and definitions for Pn76xx HAL.
*
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/

#ifndef PHHALHW_PN76XX_INT_H
#define PHHALHW_PN76XX_INT_H

#include <ph_Status.h>
#include <phhalHw.h>


/** \defgroup phhalHw_PN76xx_Int Internal
* \brief Pn76xx HAL Internal functions
* @{
*/

/**
* \name Timer config
*/
#define PHHAL_HW_PN76XX_MAX_FREQ                13560000U      /**< Pn76xx clk Maximum frequency = 13.56 MHz.*/
#define PHHAL_HW_PN76XX_MIN_FREQ                53000U         /**< Pn76xx clk Minimum frequency = 53 KHz.*/
#define PHHAL_HW_PN76XX_MAX_TIME_DELAY_MS       19784U         /**< Pn76xx Maximum Time Delay in milli second = 19.78443396226.*/
#define PHHAL_HW_PN76XX_MIN_TIME_DELAY_US       1U             /**< Pn76xx Minimum Time Delay in micro second = 0.00001886792.*/
#define PHHAL_HW_PN76XX_CONVERSION_MS_SEC       1000U          /**< MilliSec to Sec (In denominator for calculation purpose) --> 1000.*/
#define PHHAL_HW_PN76XX_CONVERSION_US_SEC       1000000U       /**< MicroSec to Sec (In denominator for calculation purpose) --> 1000000.*/
#define PHHAL_HW_PN76XX_TR_RX_PRESCALAR         0x7FU          /**< Tx and Rx Prescaler to 0x7F with 1 Etu ref */


/**
* \name Rf Datarate Values
*/
/*@{*/
#define PHHAL_HW_RF_DATARATE_NO_CHANGE          0x00FFU        /**< Data rate no change. */
/*@}*/


/**
* ISO 18000p3m3 Sub-carrier type
*/
#define PHHAL_HW_PN76XX_I18000P3M3_M_MANCHESTER_2     0x02U
#define PHHAL_HW_PN76XX_I18000P3M3_M_MANCHESTER_4     0x03U

/**
* ISO 18000p3m3 CRC-PRESET Values
*/
#define PHHAL_HW_PN76XX_I18000P3M3_SELECT_PRESET      0x03U
#define PHHAL_HW_PN76XX_I18000P3M3_NONSELECT_PRESET   0x04U

/**
* ISO 18000p3m3 Timeout constants
*/
#define PHHAL_HW_PN76XX_I18000P3M3_SW_T1_MAX_US       78U
#define PHHAL_HW_PN76XX_I18000P3M3_SW_T2_MIN_US       151U
#define PHHAL_HW_PN76XX_I18000P3M3_SW_T3_MIN_US       25U
#define PHHAL_HW_PN76XX_I18000P3M3_SW_T4_MIN_US       100U
#ifndef NXPBUILD__PHPAL_PR_ARTF32855
#define PHHAL_HW_PN76XX_I18000P3M3_SW_DELTA_MIN_US    10U
#endif /* NXPBUILD__PHPAL_PR_ARTF32855*/

/**
* ISO 18000p3m3 Command Codes
*/
#define PHHAL_HW_PN76XX_I18000P3M3_CMD_NEXT_SLOT      0x00U
#define PHHAL_HW_PN76XX_I18000P3M3_CMD_ACK            0x01U
#define PHHAL_HW_PN76XX_I18000P3M3_CMD_REQ_RN         0xC1U

/**
* \name Pn76xx Timeslot processing behavior.
*/
/*@{*/
#define PHHAL_HW_PN76XX_EPC_GEN2_TIMESLOT_FILL_BUFFER           0x00U  /**< EPC GEN2 inventory processes timeslots until buffer is full. */
#define PHHAL_HW_PN76XX_EPC_GEN2_TIMESLOT_SINGLE                0x01U  /**< EPC GEN2 inventory processes one timeslot only. */
#define PHHAL_HW_PN76XX_EPC_GEN2_TIMESLOT_SINGLE_SELECT_TAG     0x02U  /**< EPC GEN2 inventory processes one timeslot only. If timeslot contains a valid tag response, the tag is also selected. */


/**
* \name PN76xx EPC GEN2 custom definitions.
* To be used with
* #phhalHw_Pn76xx_Int_EpcGen2Inventory,
* #phhalHw_Pn76xx_Int_EpcGen2ResumeInventory.
*/
/*@{*/
#define PHHAL_HW_PN76XX_MIN_SELECT_COMMAND_LENGTH        1U    /**< Minimum length of Select command. */
#define PHHAL_HW_PN76XX_MAX_SELECT_COMMAND_LENGTH        39U   /**< Maximum length of Select command. */
#define PHHAL_HW_PN76XX_BEGIN_COMMAND_LENGTH             03U   /**< length of Begin command. */

#define PHHAL_HW_PN76XX_MAX_NUM_OF_BITS_FOR_LAST_BYTE    7U    /**< Maximum number of bits to be transmitted in the last byte of \p pSelectCommand. 0 in case all bits shall be transmitted, otherwise 1-7. */
#define PHHAL_HW_PN76XX_MAX_EPC_GEN2_TIMESLOT            (PHHAL_HW_PN76XX_EPC_GEN2_TIMESLOT_SINGLE_SELECT_TAG) /**< Maximum EPC GEN2 TIMESLOT parameter. */
/*@}*/

/* Returns the RxBuffer pointer, length and size */
phStatus_t phhalHw_Pn76xx_Int_GetRxBuffer(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** pRxBuffer,                             /**< [Out] Pointer to HAL RX buffer.*/
    uint16_t * pRxBufferLen,                          /**< [Out] Length of the buffer.*/
    uint16_t * pRxBufferSize                          /**< [Out] Size of the buffer.*/
    );

/* Returns the TxBuffer pointer, length and size */
phStatus_t phhalHw_Pn76xx_Int_GetTxBuffer(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** pTxBuffer,                             /**< [Out] Pointer to HAL TX buffer.*/
    uint16_t * pTxBufferLen,                          /**< [Out] Length of the buffer.*/
    uint16_t * pTxBufferSize                          /**< [Out] Size of the buffer.*/
    );

phStatus_t phhalHw_Pn76xx_Int_TimerStart(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint32_t wPrescaler,                              /**< [In] Pre-scalar value of Timer.*/
    uint32_t dwLoadValue                              /**< [In] Re-Load value of Timer.*/
    );

/**
* \brief Internal set config function.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval #PH_ERR_UNSUPPORTED_PARAMETER Configuration is not supported or invalid.
* \retval #PH_ERR_INVALID_PARAMETER Parameter value is invalid.
* \retval #PH_ERR_PARAMETER_OVERFLOW Setting the parameter value would lead to an overflow.
*/

phStatus_t phhalHw_Pn76xx_SetConfig_Int(
    phhalHw_Pn76xx_DataParams_t * pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                               /**< [In] SetConfig option. */
    uint16_t wValue                                 /**< [In] SetConfig value. */
    );

phStatus_t phhalHw_Pn76xx_Int_SetMinFdt(
    phhalHw_Pn76xx_DataParams_t * pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wValue                                 /**< [In] #PH_ON or #PH_OFF. */
    );

phStatus_t phhalHw_Pn76xx_Int_ClearNSetRegFields(
    phhalHw_Pn76xx_DataParams_t * pDataParams,      /**< [In] Pointer to this layer's parameter structure. */
    uint8_t bRegister,                              /**< [In] Register */
    uint32_t dwMask,                                /**< [In] Mask */
    uint32_t dwPos,                                 /**< [In] Position */
    uint16_t wValue                                 /**< [In] Set Register field value */
    );

/**
* \brief Starts the timer as part of the time out behaviour.
* \note uses timer 1
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phhalHw_Pn76xx_Int_SetTmo(
    phhalHw_Pn76xx_DataParams_t *pDataParams,              /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wTimeout,                                     /**< [In] Time out period. */
    uint8_t  bUnit                                         /**< [In] The unit unit used for specifying the delay. */
    );


/**
* \brief Apply card mode register settings (Tx and Rx Data Rate) according to given parameters.
* \return Status code
* \retval #PH_ERR_SUCCESS Operation successful.
* \retval Other Depending on implementation and underlying component.
*/
phStatus_t phhalHw_Pn76xx_Int_SetCardMode(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wTxDataRate,                             /**< [In] TX data rate to be used. */
    uint16_t wRxDataRate,                             /**< [In] RX data rate to be used. */
    uint16_t wSubcarrier                              /**< [In] Sub carrier to be used. */
    );

phStatus_t phhalHw_Pn76xx_Int_SetTxDataRateFraming(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                                 /**< [In] SetConfig option. */
    uint16_t wValue                                   /**< [In] SetConfig value. */
    );

phStatus_t phhalHw_Pn76xx_Int_SetRxDataRateFraming(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint16_t wConfig,                                 /**< [In] SetConfig option. */
    uint16_t wValue                                   /**< [In] SetConfig value. */
    );

#ifdef NXPBUILD__PHHAL_HW_PN7642
/**
* \brief Pn76xx internal implementation of EpcGen2Inventor command.
* Note: This API is applicable for only PN7642 variant.
*
* \sa phhalHw_Pn76xx_I18000p3m3Inventory
*/
phStatus_t phhalHw_Pn76xx_Int_EpcGen2Inventory(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t * pSelectCommand,                         /**< [In] ISO 18000p3m3 Select command frame. */
    uint8_t bSelectCommandLength,                     /**< [In] Select command length in bytes- 1 to 39 bytes. */
    uint8_t bSelectCommandBitsInLastByte,             /**< [In] Number of valid bits in last byte of pSelCmd. */
    uint8_t * pBeginRoundCommand,                     /**< [In] ISO 18000p3m3 BeginRound command frame. This is 17bits i.e., 3 bytes are expected. CRC5 should not be provided. */
    uint8_t bTimeslotProcessingBehavior,              /**< [In] TimeSlot processing behavior. */
    uint8_t ** ppRxBuffer,                            /**< [In] Pointer to HAL RX Buffer containing response from single/multiple tags. */
    uint16_t * pRxDataLength                          /**< [In] Length of response in HAL RX Buffer. */
    );

/**
* \brief Pn76xx internal implementation of EpcGen2ResumeInventory command.
* Note: This API is applicable for only PN7642 variant.
*
* \sa phhalHw_Pn76xx_18000p3m3ResumeInventory
*/
phStatus_t phhalHw_Pn76xx_Int_EpcGen2ResumeInventory(
    phhalHw_Pn76xx_DataParams_t * pDataParams,        /**< [In] Pointer to this layer's parameter structure. */
    uint8_t ** ppRxBuffer,                            /**< [In] Pointer to HAL RX Buffer containing response from single/multiple tags. */
    uint16_t * pRxDataLength                          /**< [In] Length of response in HAL RX Buffer. */
    );
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

/** @} */

#endif  /* PHHALHW_PN76XX_INT_H */
