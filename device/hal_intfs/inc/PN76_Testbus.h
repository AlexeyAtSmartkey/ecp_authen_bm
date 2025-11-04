/*----------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                    */
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

/** @file
 * Implementation of Testbus interface functions of PN76XX HAL.
 *
 * $Author: NXP $
 * $Revision: $ (02.02.00)
 * $Date: $
 */

#ifndef _PN76_TESTBUS_H_
#define _PN76_TESTBUS_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "ph_Datatypes.h"
#include "PN76_Status.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALTestbus
 *
 * @brief Testbus configuration and control HAL APIs
 *
 * This module implements PN76SYSHALTestbus interface to configure and control Contactless Test Signals (CTS) of PN76XX IC.
 *
 * Signal and Bit Index for Contactless Test Signals (CTS) and Testbus supported by PN76XX
 * \image html CTS_TESTBUS_Signals.png
 * @{
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/*!
 * @brief PN76 Digital Testbus configuration parameter structure.
 */
typedef struct
{
    uint8_t bSignal_Index;                    /**< Signal Index for PN76XX. */
    uint8_t bBit_Index;                       /**< Bit Index for PN76XX. */
    uint8_t bPad_Index;                       /**< Pad index for PN76XX.
                                                  | Pad index | Pad Used
                                                  |:--------: |:---------
                                                  |    0      | AUX1
                                                  |    1      | AUX2
                                                  |    2      | AUX3
                                                  |    3      | GPIO0
                                                  |    4      | GPIO1
                                                  |    5      | GPIO2
                                                  |    6      | GPIO3
                                                  |  Any other| Invalid
                                                  */
    uint8_t bTestbus_Select;                  /**< Note : This parameter only be used in  PN76_Sys_Configure_TestBus_Digital();
                                                          Neglected for PN76_Sys_Configure_TestBus_MultipleDigital();
                                                  |
                                                  | Select the CLIF TB to be connected for PN76XX.
                                                  |TestBus Sel | CLIF TB Used
                                                  |:--------:  |:---------
                                                  |    0       | TB0
                                                  |    1       | TB1
                                                  |    2       | TB2
                                                  |    3       | TB3
                                                  |    4       | Reset TB SEL
                                                  */

} Pn76xx_TestBus_Digital_t;

/*!
 * @brief PN76 Analog Testbus configuration parameter structure.
 */
typedef struct __attribute__ ((__packed__))
{
    uint8_t bConfig;                          /**< Configurable bits.
    
         | b7 | b6 | b5 | b4 | b3 | b2 | b1 | b0 |           Description                 |           Applicable to mode                  |
         |---:|:--:|:--:|:--:|:--:|:--:|:--:|:--:|:-------------------------------------:|:---------------------------------------------:| 
         | X  | X  |    |    |    |    |    |    | DAC1 output shift (Range – 0, 1, 2)   | Raw              | 
         |    |    | X  | X  |    |    |    |    | DAC0 output shift (Range – 0, 1, 2)   | Raw              | 
         |    |    |    |    | X  |    |    |    | In combined mode, signal on AUX1/AUX2 pin. 0 -> Signal on AUX1, 1 -> Signal on AUX2 | Combined |
         |    |    |    |    |    | X  |    |    | DAC1 input shift direction. 0 -> Shift right, 1 -> Shift left   | Raw | 
         |    |    |    |    |    |    | X  |    | DAC0 input shift direction. 0 -> Shift right, 1 -> Shift left   | Raw | 
         |    |    |    |    |    |    |    | X  | Mode. 0 -> Raw mode, 1 -> Combined mode | Raw/Combined | 
    */
    uint8_t bCombined_Signal;                 /**< 0 – ADCI/ADCQ, 1 – pcrm_if_rssi, 0x02-0xFF --> Reserved */
    uint8_t bTB_Index0;                       /**< Signal index of the analog signal. */
    uint8_t bTB_Index1;                       /**< Signal index of the analog signal. */
    uint8_t bShift_Index0;                    /**< DAC0 input shift positions. Direction will be decided by bit 0 in bConfig. */
    uint8_t bShift_Index1;                    /**< DAC0 input shift positions. Direction will be decided by bit 1 in bConfig. */
    uint8_t bMask0;                           /**< DAC0 mask */
    uint8_t bMask1;                           /**< DAC1 mask */
} Pn76xx_TestBus_Analog_t;

/*!
 * @brief PN76 CTS configuration parameter structure.
 *
 * User shall fill all the configuration parameters that are required
 * for \ref PN76_Sys_Cts_Configure in this data structure.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t   pre_trig_shift;      /**< Defines values to be programmed in CTS_PRE_TRIGGER_SHIFT field in CLIF_CTS_MAIN_CTRL_REG */
   uint8_t   trig_mode;           /**< Specifies Acquisition mode to be used. 0x00 - POST mode. 0x01 - COMB Mode. 0x02 - PRE-Mode. 0x03 - 0xFF - Invalid */
   uint8_t   ram_page_width;      /**< Defines value to be programmed in CTS_RAM_PAGE_WIDTH field in CLIF_CTS_SAMPLER_REGISTER. Note: FW might end up using a smaller value if the defined value is not feasible. */
   uint8_t   sample_clk_div;      /**< Defines Value to be programmed in CTS_SAMPLE_CLK_DIV field in CLIF_CTS_SAMPLER_REGISTER. Values > 0x7 are invalid. */
   uint8_t   sample_byte_sel;     /**< Defines Value to be programmed in CTS_SAMPLE_BYTE_SEL field in CLIF_CTS_SAMPLER_REGISTER. Values > 0x0F are invalid. */
   uint8_t   sample_mode_sel;     /**< Defines Value to be programmed in CTS_SAMPLE_MODE_SEL field in CLIF_CTS_SAMPLER_REGISTER. Values > 0x2 are invalid. */
   uint8_t   tb0;                 /**< Selects which Test bus to be connected to TB0. */
   uint8_t   tb1;                 /**< Selects which Test bus to be connected to TB1. */
   uint8_t   tb2;                 /**< Selects which Test bus to be connected to TB2. */
   uint8_t   tb3;                 /**< Selects which Test bus to be connected to TB3. */
   uint8_t   trig_tb_sel;         /**< Selects which CLIF Test bus to be connected to the trigger sources. */
   uint32_t  tbctrl_reg;          /**< Value to be programmed in CLIF_CTS_TBCTRL_REG. */
   uint32_t  hw0_trig0_reg;       /**< Value to be programmed in CLIF_CTS_HW0_TRIGGER0_REG. */
   uint32_t  hw0_trig1_reg;       /**< Value to be programmed in CLIF_CTS_HW0_TRIGGER1_REG. */
   uint32_t  hw0_trig2_reg;       /**< Value to be programmed in CLIF_CTS_HW0_TRIGGER2_REG. */
   uint32_t  hw1_trig0_reg;       /**< Value to be programmed in CLIF_CTS_HW1_TRIGGER0_REG. */
   uint32_t  hw1_trig1_reg;       /**< Value to be programmed in CLIF_CTS_HW1_TRIGGER1_REG. */
   uint32_t  hw1_trig2_reg;       /**< Value to be programmed in CLIF_CTS_HW1_TRIGGER2_REG. */
} Pn76xx_CtsRegConfig_t;

/*****************************************************************************
 * Public functions declarations
 ****************************************************************************/

/*!
 * @brief This API is used to enable/disable the CTS logging feature.
 *
 * Note: Call to PN76_Sys_Cts_Configure() needs to be successful prior to this API call.
 *
 * @param bEnable Enable/Disable the CTS logging feature. 0 - Disable. 1 - Enable.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_INTERNAL_ERROR PN76_Sys_Cts_Configure Operation has failed previously.
 * @retval PN76_STATUS_RESOURCE_ERROR When Testbus is disabled.
 */
PN76_Status_t PN76_Sys_Cts_Enable(uint8_t bEnable);

/*!
 * @brief This API is used to write configuration values to all the
 * required CTS Registers such as Triggers, Test Bus registers, Sampling
 * configuration etc.
 *
 * @param pCtsConfig Pointer to CTS configuration data structure, refer @ref Pn76xx_CtsRegConfig_t values.
 * @param pCTSbuffer CTS Buffer provided by user to store CTS Log data.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_RESOURCE_ERROR When Testbus is disabled.
 */
PN76_Status_t PN76_Sys_Cts_Configure(Pn76xx_CtsRegConfig_t* pCtsConfig, uint8_t* pCTSbuffer, uint16_t wCTSbuffLen);

/*!
 * @brief This API retrieves the Clif register dump on CTS Event.
 *
 * @param pRegDump Buffer provided by user to retrieve CTS register dump.
 * @param pRegDumpLen Input the length of /ref pRegDump Buffer and output shall be the length of retrieved Register data.
 * @param pCTSDumpLen CTS Log data length that needs to be used for retrieving the captured CTS data.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_RESOURCE_ERROR If the pRegDump buffer length is not sufficient to retrieve Register Dump.
 */
PN76_Status_t PN76_Sys_Cts_RetrieveLog(uint8_t* pRegDump, uint8_t* pRegDumpLen, uint32_t* pCTSDumpLen);

/*!
 * @brief This API is used to configure the digital test bus feature.
 *
 * @param pTestBusDigital Structure pointer to provide Digital Test bus configuration input.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_RESOURCE_ERROR When Testbus is disabled.
 */
PN76_Status_t PN76_Sys_Configure_TestBus_Digital(Pn76xx_TestBus_Digital_t * pTestBusDigital);

/*!
 * @brief This API is used to configure the analog test bus feature.
 *
 * @param pTestBusAnalog Structure pointer to provide Analog Test bus configuration input.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_RESOURCE_ERROR When Testbus is disabled.
 */
PN76_Status_t PN76_Sys_Configure_TestBus_Analog(Pn76xx_TestBus_Analog_t * pTestBusAnalog);

/*!
 * @brief This API is used to switch multiple available digital testbus signal on selected pad configurations
 *
 * @param pTestBusMultipleDigital Structure pointer to provide Multiple Digital Test bus configuration input.
 *
 * @return Status code
 * @retval PN76_STATUS_SUCCESS Operation successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 */
PN76_Status_t  PN76_Sys_Configure_TestBus_MultipleDigital(Pn76xx_TestBus_Digital_t *TestBusData1, Pn76xx_TestBus_Digital_t *TestBusData2);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_TESTBUS_H_ */
