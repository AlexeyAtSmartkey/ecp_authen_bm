/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                    */
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
 *
 * Implementation of PCRM interface functions for non-secure code execution
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_PCRM_H_
#define _PN76_PCRM_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALPcrm
 *
 * @brief System Power Control and Reset HAL APIs
 *
 * This module implements PN76SYSHALPcrm interface Flash code HAL, specific to Pcrm module.
 *
 * \section PCRM_EXT_ADC_READ Flow to read the digital equivalent value of ext AD1 pin
 This section will provide information about the flow of calls to be called by the application to read
 the digital equivalent value of the voltage level present on the external AD1 pin.
 Below diagram will show the flow of the calls.
@msc ADC read of AD1 pin
# Options section
    hscale = "2";
# The entities
    APP_NS, PN76xx_SECURE;
# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];
# Small gap before the boxes
    |||;
# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "For this API, it does not matter whether the session is opened or not, but but SKM should be initialized", URL="\ref PN76_Sys_SKM_Init()" ] ;
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_Gpadc_Init()" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Initializes the GPADC" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_Gpadc_Init() returns"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor)" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of the sensor in respective units (voltage, degC, Amperes etc..)" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor) returns.\n The value returned would be from the given sensor"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_PCRM_Init_ExtAnalog_ADC()" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Initializes the GPADC MUX for measuring the voltage value on AD1 pin" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_PCRM_Init_ExtAnalog_ADC() returns"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_PCRM_Read_OneShot_ExtAnalog_ADC()" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of voltage on AD1 pin (in counts. value range from: 0x00 to 0x03FF)" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_PCRM_Read_OneShot_ExtAnalog_ADC() returns.\n The value returned would be from the AD1 pin value"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT)" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of voltage on AD1 pin.." ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT) returns.\n The value returned would be from the AD1 pin value."];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValueOneShot(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT)" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of voltage on AD1 pin.." ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValueOneShot(senso=E_PN76_PCRM_GPADC_SENSOR_VBAT) returns.\n The value returned would be from the AD1 pin value."];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_PCRM_DeInit_ExtAnalog_ADC()" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "De-Initializes the GPADC MUX for measuring the voltage value on AD1 pin" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_PCRM_DeInit_ExtAnalog_ADC() returns"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT)" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of the sensor in respective units (voltage, degC, Amperes etc..)" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValue(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT) returns.\n The value returned would be from the VBAT."];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValueOneShot(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT)" ] ;
    PN76xx_SECURE->PN76xx_SECURE    [ label = "Reads the digital equivalent value of the sensor in respective units (voltage, degC, Amperes etc..)" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_Hal_PCRM_GpadcGetValueOneShot(sensor=E_PN76_PCRM_GPADC_SENSOR_VBAT) returns.\n The value returned would be from the VBAT."];
@endmsc
 *
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
/**
 * @brief  Enum for selection of the CLIF clock source
 */
typedef enum PN76_PCRM_ClifClk_Enum
{
   E_PN76_PCRM_CLKGEN_CLIFCLK_CLIF_SRC_HFO = 0,  /**< Clock from the PLL CLIF analog block, source = HFO */
   E_PN76_PCRM_CLKGEN_CLIFCLK_CLIF_SRC_EXT,      /**< Clock from the PLL CLIF analog block, source = XTAL or SYSCLK */
   E_PN76_PCRM_CLKGEN_CLIFCLK_SYSTEM             /**< System clock/2 (22.5 MHz). To be used as long as the RF PLL is not locked */
} PN76_PCRM_ClifClk_t;

/**
 * @brief  Enum for the XTAL control commands
 */
typedef enum PN76_PCRM_XtalPhase_Enum
{
   E_PN76_PCRM_CLKGEN_XTALPHASE_INIT = 0,                         /**< Initialize state variables */
   E_PN76_PCRM_CLKGEN_XTALPHASE_INITIAL_START,                    /**< Start the XTAL initial startup sequence (initial system boot) */
   E_PN76_PCRM_CLKGEN_XTALPHASE_ERROR_IT,                         /**< Process the XTAL ERROR interrupt */
   E_PN76_PCRM_CLKGEN_XTALPHASE_READY_IT,                         /**< Process the XTAL READY interrupt */
   E_PN76_PCRM_CLKGEN_XTALPHASE_WKUP_START,                       /**< Start the XTAL startup sequence after leaving standby power state */
   E_PN76_PCRM_CLKGEN_XTALPHASE_ENTER_STDBY_WITH_XTAL_AUTO_EN,    /**< Stop the XTAL and enable automatic restart when RFLD event is triggered */
   E_PN76_PCRM_CLKGEN_XTALPHASE_ENTER_STDBY_WITHOUT_XTAL_AUTO_EN, /**< Stop the XTAL and enable automatic restart when RFLD event is triggered */
   E_PN76_PCRM_CLKGEN_XTALPHASE_IS_READY,                         /**< Check if the XTAL is ready */
   E_PN76_PCRM_CLKGEN_XTALPHASE_WAIT_READY,                       /**< Wait until the XTAL is ready */
   E_PN76_PCRM_CLKGEN_XTALPHASE_INITIAL_STOP                      /**< Stop the XTAL oscillator */
} PN76_PCRM_XtalPhase_t;

/**
 * @brief  Enum for range of VDDPA voltages.
 * NOTE: Used when TXLDO_VDDPA_CONFIG register value field (TXLDO_VDDPA_CONFIG_VDDPA_CONFIG_MASK) is referred.
 */
#if (PHFL_CONFIG_TARGET_PLATFORM == PHFL_CONFIG_TARGET_PLATFORM_ARM) || defined(__QAC__)
typedef enum
#else
typedef enum __attribute__ ((__packed__))
#endif
{
   E_PN76_PCRM_VDDPA_1V50           = 0,
   E_PN76_PCRM_VDDPA_1V60, /**< 0x01 */
   E_PN76_PCRM_VDDPA_1V70, /**< 0x02 */
   E_PN76_PCRM_VDDPA_1V80, /**< 0x03 */
   E_PN76_PCRM_VDDPA_1V90, /**< 0x04 */
   E_PN76_PCRM_VDDPA_2V00, /**< 0x05 */
   E_PN76_PCRM_VDDPA_2V10, /**< 0x06 */
   E_PN76_PCRM_VDDPA_2V20, /**< 0x07 */
   E_PN76_PCRM_VDDPA_2V30, /**< 0x08 */
   E_PN76_PCRM_VDDPA_2V40, /**< 0x09 */
   E_PN76_PCRM_VDDPA_2V50, /**< 0x0A */
   E_PN76_PCRM_VDDPA_2V60, /**< 0x0B */
   E_PN76_PCRM_VDDPA_2V70, /**< 0x0C */
   E_PN76_PCRM_VDDPA_2V80, /**< 0x0D */
   E_PN76_PCRM_VDDPA_2V90, /**< 0x0E */
   E_PN76_PCRM_VDDPA_3V00, /**< 0x0F */
   E_PN76_PCRM_VDDPA_3V10, /**< 0x10 */
   E_PN76_PCRM_VDDPA_3V20, /**< 0x11 */
   E_PN76_PCRM_VDDPA_3V30, /**< 0x12 */
   E_PN76_PCRM_VDDPA_3V40, /**< 0x13 */
   E_PN76_PCRM_VDDPA_3V50, /**< 0x14 */
   E_PN76_PCRM_VDDPA_3V60, /**< 0x15 */
   E_PN76_PCRM_VDDPA_3V70, /**< 0x16 */
   E_PN76_PCRM_VDDPA_3V80, /**< 0x17 */
   E_PN76_PCRM_VDDPA_3V90, /**< 0x18 */
   E_PN76_PCRM_VDDPA_4V00, /**< 0x19 */
   E_PN76_PCRM_VDDPA_4V10, /**< 0x1A */
   E_PN76_PCRM_VDDPA_4V20, /**< 0x1B */
   E_PN76_PCRM_VDDPA_4V30, /**< 0x1C */
   E_PN76_PCRM_VDDPA_4V40, /**< 0x1D */
   E_PN76_PCRM_VDDPA_4V50, /**< 0x1E */
   E_PN76_PCRM_VDDPA_4V60, /**< 0x1F */
   E_PN76_PCRM_VDDPA_4V70, /**< 0x20 */
   E_PN76_PCRM_VDDPA_4V80, /**< 0x21 */
   E_PN76_PCRM_VDDPA_4V90, /**< 0x22 */
   E_PN76_PCRM_VDDPA_5V00, /**< 0x23 */
   E_PN76_PCRM_VDDPA_5V10, /**< 0x24 */
   E_PN76_PCRM_VDDPA_5V20, /**< 0x25 */
   E_PN76_PCRM_VDDPA_5V30, /**< 0x26 */
   E_PN76_PCRM_VDDPA_5V40, /**< 0x27 */
   E_PN76_PCRM_VDDPA_5V50, /**< 0x28 */
   E_PN76_PCRM_VDDPA_5V60, /**< 0x29 */
   E_PN76_PCRM_VDDPA_5V70, /**< 0x2A */
   E_PN76_PCRM_VDDPA_MAX     /**< Not to be used as voltage value, but to define the number of steps in the enumeration */
} PN76_PCRM_VddpaVoltage_t;

/**
 * @brief  Enum for TX DRIVER Configuration.
 */
typedef enum
{
   E_PN76_PCRM_TXDRIVER_STOP = 0x00,           /**< Stop TX driver */
   E_PN76_PCRM_TXDRIVER_START_RDR,             /**< Start TX driver in reader, initiator or target active mode */
   E_PN76_PCRM_TXDRIVER_START_CE,              /**< Start TX driver in CE mode */
   E_PN76_PCRM_TXDRIVER_STANDBY,               /**< Config of TXLDO before entering in standby */
   E_PN76_PCRM_TXDRIVER_START_LPCD,            /**< Start TX driver for LPCD */
   E_PN76_PCRM_TXDRIVER_PULSE                  /**< Only for 1st cold boot: Pulse to enable bypass of DCDC */
} PN76_PCRM_TxDriverConfig_t;

/**
 * @brief  Enum for Different General Purpose Analog to Digital Converter (GPADC) value types.
 */
typedef enum
{
   E_PN76_PCRM_GPADC_TYPE_VAL             = 0x00,    /**< Current value  */
   E_PN76_PCRM_GPADC_TYPE_MIN             = 0x01,    /**< Min value */
   E_PN76_PCRM_GPADC_TYPE_MAX             = 0x02,    /**< Max value */
   E_PN76_PCRM_GPADC_TYPE_IIR             = 0x03,    /**< IIR filtered value */
   E_PN76_PCRM_GPADC_TYPE_AVG             = 0x04,    /**< Average filtered value */
   /******************************/
   E_PN76_PCRM_GPADC_TYPE_CONV            = 0x00,    /**< Select converted values (with conversion to physical scale) */
   E_PN76_PCRM_GPADC_TYPE_GROSS           = 0x10,    /**< Select gross values (no conversion to physical scale) */
   /******************************/
   E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED    = 0x00,    /**< Single ended measurement */
   E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL    = 0x20,    /**< Differential measurement */
   /******************************/
   E_PN76_PCRM_GPADC_TYPE_CONV_GROSS_MASK   = 0x10,
   E_PN76_PCRM_GPADC_TYPE_VAL_MASK          = 0x0F,
   E_PN76_PCRM_GPADC_TYPE_MEASURE_TYPE_MASK = 0x20,
   /******************************/
   E_PN76_PCRM_GPADC_TYPE_VAL_CONV = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_VAL | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_MIN_CONV = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_MIN | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_MAX_CONV = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_MAX | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_IIR_CONV = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_IIR | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_AVG_CONV = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_AVG | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_VAL_GROSS = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_VAL | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_MIN_GROSS = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_MIN | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_MAX_GROSS = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_MAX | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_IIR_GROSS = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_IIR | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_AVG_GROSS = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_AVG | E_PN76_PCRM_GPADC_TYPE_SINGLE_ENDED,
   E_PN76_PCRM_GPADC_TYPE_VAL_CONV_DIFF = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_VAL | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_MIN_CONV_DIFF = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_MIN | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_MAX_CONV_DIFF = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_MAX | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_IIR_CONV_DIFF = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_IIR | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_AVG_CONV_DIFF = E_PN76_PCRM_GPADC_TYPE_CONV | E_PN76_PCRM_GPADC_TYPE_AVG | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_VAL_GROSS_DIFF = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_VAL | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_MIN_GROSS_DIFF = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_MIN | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_MAX_GROSS_DIFF = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_MAX | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_IIR_GROSS_DIFF = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_IIR | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL,
   E_PN76_PCRM_GPADC_TYPE_AVG_GROSS_DIFF = E_PN76_PCRM_GPADC_TYPE_GROSS | E_PN76_PCRM_GPADC_TYPE_AVG | E_PN76_PCRM_GPADC_TYPE_DIFFERENTIAL
} PN76_PCRM_GpadcValueType_t;

/**
 * @brief Enumeration for the sensor selection (low nibble: GPADC mux selection, high nibble : testmux selection)
 */
typedef enum
{
   E_PN76_PCRM_GPADC_SENSOR_RESERVED      = 0x00,    /**< Reserved sensor */
   E_PN76_PCRM_GPADC_SENSOR_RSSI_OUT      = 0x01,    /**< RX RSSI output sense */
   E_PN76_PCRM_GPADC_SENSOR_VBG_SNS       = 0x05,    /**< Trimmed Bandgap 0.9V */
   E_PN76_PCRM_GPADC_SENSOR_TEMP_PMU      = 0x06,    /**< Temperature sense PMU (in Celcius degrees) */
   E_PN76_PCRM_GPADC_SENSOR_TEMP_CLIF     = 0x07,    /**< Temperature sense CLIF */
   E_PN76_PCRM_GPADC_SENSOR_XTAL_PEAK_DET = 0x08,    /**< XTAL peak detector */
   E_PN76_PCRM_GPADC_SENSOR_VBAT          = 0x09,    /**< Battery voltage (in mV) */
   E_PN76_PCRM_GPADC_SENSOR_GROUND        = 0x04,    /**< Ground */
   E_PN76_PCRM_GPADC_SENSOR_VDDPA         = 0x84,    /**< VDDPA voltage  */
   E_PN76_PCRM_GPADC_SENSOR_ANY           = 0xFF     /**< Used to set the threshold of channel 0 (one shot channel) */
} PN76_PCRM_GpadcSensor_t;

#if 0
/**
 * @brief Type to install the callback for GPADC IRQ handler
 */
typedef void (*PN76_PCRM_GpadcCallback_t)(uint8_t bChannel, bool blIrqLow, bool blIrqHigh);
#endif

/**
 * @brief  Enum for different power state based on VDDIO voltages.
 */
typedef enum
{
   E_PN76_PCRM_FULLPOWER = 0,   /**< Vbat is above 3.0V/2.6V; VDDIO is present*/
   E_PN76_PCRM_LOWPOWER         /**< VDDIO is not present (Vbat is below 3.0V/2.6V and above 2.3V) */
} PN76_PCRM_PowerStatus_t;

/**
 * @brief  Enum of different module clocks.
 */
typedef enum
{
   E_PN76_PCRM_TIMERS_CLK  = 0,  /**< TIMER CLOCK */
   E_PN76_PCRM_RNG_CLK     = 1,  /**< RNG CLOCK */
   E_PN76_PCRM_HOSTIF_CLK  = 2,  /**< HOST IF CLOCK */
   E_PN76_PCRM_USB_CLK     = 3,  /**< USB IP CLOCK */
   E_PN76_PCRM_SPIM_CLK    = 4,  /**< SPIM IP CLOCK */
   E_PN76_PCRM_I2CM_CLK    = 5,  /**< I2CM IP CLOCK */
   E_PN76_PCRM_CT_CLK      = 6,  /**< CT IP CLOCK */
   E_PN76_PCRM_PWM_45M_CLK = 7,  /**< PWM_45M IP CLOCK */
   E_PN76_PCRM_PWM_CLK     = 8,  /**< PWM IP CLOCK */
   E_PN76_PCRM_LP_UART_CLK = 9,  /**< LP_UART IP CLOCK with HFO 90MHz as source clock. */
   E_PN76_PCRM_DMA_CLK     = 10, /**< DMA IP CLOCK */
   E_PN76_PCRM_LP_UART_USB_CLK      = 11, /**< LPUART IP CLOCK with USB PLL 48MHz as source clock.  */
   E_PN76_PCRM_LP_UART_XTAL_CLK     = 12, /**< LPUART IP CLOCK with XTAL 27.12MHz as source clock.  */
}PN76_PCRM_IP_Clocks_t;

/**
 * @brief  Host Interface configuration selection Enum.
 */
typedef enum
{
   E_PN76_PCRM_HIF_SEL_NONE = 0, /**< No HIF Selected */
   E_PN76_PCRM_HIF_SEL_I2C  = 1, /**< HIF I2C */
   E_PN76_PCRM_HIF_SEL_SPI  = 2, /**< HIF SPI */
   E_PN76_PCRM_HIF_SEL_HSU  = 3, /**< HIF LPUART */
   E_PN76_PCRM_HIF_SEL_I3C  = 4, /**< HIF I3C */
   E_PN76_PCRM_HIF_SEL_USB  = 5, /**< HIF USB */
}PN76_PCRM_HifSelect_t;

#if (PHFL_LPCD_DISABLE == 0)
/**
 * @brief LPCD Modes
 */
typedef enum
{
   E_PN76_LPCD_REFERENCE_BOOT = 0x05,   /**< Take measurements values with Boot configuration in order fill in reference data */
   E_PN76_LPCD_MEASUREMENT_BOOT = 0x06,  /**< Get values with Boot configuration that will be compared to reference data */
} PN76_PCRM_LPCD_Mode_t;
#endif

/**
 * \brief  Enum for selection of the USB PLL reference clock
 */
typedef enum
{
   E_PN76_USBPLLCLK_SRC_XTAL = 0, /**< 27.12MHz XTAL clock */
   E_PN76_USBPLLCLK_SRC_CLIFPLL   /**< 27.12MHz CLIF PLL clock */
} PN76_PCRM_UsbPllClk_t;

/** @brief Enumeration for the PVDD LDO Modes when using Internal PVDD LDO */
typedef enum
{
   E_PN76_PCRM_PVDD_LDO_OFF =  0x0,  /**< Internal PVDD LDO is disabled */
   E_PN76_PCRM_PVDD_LDO_ENABLE_LP =  0x1,  /**< Internal PVDD LDO is configured during Standby */
   E_PN76_PCRM_PVDD_LDO_ENABLE_HP =  0x3,  /**< Internal PVDD LDO is configured during ACTIVE */
} PN76_PCRM_PvddLdoConfig_t;

/**
 * @brief  Enum for selection of the Standby Wake Up Source
 */
typedef enum PN76_PCRM_LowPower_WakeUp_Config_Enum
{
   E_PN76_PCRM_WAKEUP_SOURCE_TIMER        = 0x00000001UL, /**< Standby wakeup source due to timeout. */
   E_PN76_PCRM_WAKEUP_SOURCE_HOST         = 0x00000002UL, /**< Standby wakeup source due to host interface communication. */
   E_PN76_PCRM_WAKEUP_SOURCE_RFFIELD      = 0x00000004UL, /**< Standby wakeup source due to detection of RF field. */
   E_PN76_PCRM_WAKEUP_SOURCE_TEMPSENSOR   = 0x00000008UL, /**< Standby wakeup source due to temperature sensor (when temperature is within the hysterisys). */
   E_PN76_PCRM_WAKEUP_SOURCE_VUP          = 0x00000010UL, /**< Standby wakeup source due to VUP. */
   E_PN76_PCRM_WAKEUP_SOURCE_VDDIO_LOSS   = 0x00000020UL, /**< Standby wakeup source due to loss of VDDIO. */
   E_PN76_PCRM_WAKEUP_SOURCE_VDDIO_START  = 0x00000080UL, /**< Standby wakeup source due to VDDIO start. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO0_HIGH   = 0x00000100UL, /**< Standby wakeup source due to GPIO0 transitioning to HIGH. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO1_HIGH   = 0x00000200UL, /**< Standby wakeup source due to GPIO0 transitioning to HIGH. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO2_HIGH   = 0x00000400UL, /**< Standby wakeup source due to GPIO0 transitioning to HIGH. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO3_HIGH   = 0x00000800UL, /**< Standby wakeup source due to GPIO0 transitioning to HIGH. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO0_LOW    = 0x00001000UL, /**< Standby wakeup source due to GPIO0 transitioning to LOW. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO1_LOW    = 0x00002000UL, /**< Standby wakeup source due to GPIO1 transitioning to LOW. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO2_LOW    = 0x00004000UL, /**< Standby wakeup source due to GPIO2 transitioning to LOW. */
   E_PN76_PCRM_WAKEUP_SOURCE_GPIO3_LOW    = 0x00008000UL, /**< Standby wakeup source due to GPIO3 transitioning to LOW. */
   E_PN76_PCRM_WAKEUP_SOURCE_CT_AUX       = 0x00010000UL  /**< Standby wakeup source due to CT insert. */
}PN76_PCRM_LowPower_WakeUp_Config_t;

/**
 * @brief  Enum for selection of the Ultra Low Power Standby Wake Up Source
 */
typedef enum PN76_PCRM_UltraLowPower_WakeUp_Config_Enum
{
   E_PN76_PCRM_ULP_WAKEUP_SOURCE_TIMER        = 0x00000001UL, /**< Wakeup from ultra low power standby when timer timed-out */
   E_PN76_PCRM_ULP_WAKEUP_SOURCE_RFFIELD      = 0x00000004UL, /**< Wakeup from ultra low power standby when RF field is detected */
}PN76_PCRM_UltraLowPower_WakeUp_Config_t;

/**
 * @brief  Enum for selection of the ULPCD(Ultra Low Power Card Detection) configuration
 */
typedef enum PN76_PCRM_ULPCD_Config_Enum
{
   E_PN76_PCRM_ULPCD_CARD_DETECTION             = 0x00000000UL, /**< ULPCD card detection configuration */
   E_PN76_PCRM_ULPCD_CALIBRATION                = 0x00000001UL  /**< ULPCD calibration configuration */
}PN76_PCRM_ULPCD_Config_t;

/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/

/* Secure interfaces for non-secure code */

/*!
 * @brief Performs Power Management Unit (PMU) Initialization.
 * This API will initialize the PMU and reads the TRIM Values from EEPROM USER Area and configures the IC with these TRIM values.
 *
 * @note This API performs PMU initialization and must be called before calling \ref PN76_Sys_Hal_PCRM_Smu_Init() and
 *       \ref PN76_Sys_Hal_PCRM_Clkgen_Init().
 *
 * @retval  Nothing to Return
 */
void PN76_Sys_Hal_PCRM_Pmu_Init(void);

/*!
 * @brief Performs System Management Unit (SMU) initialization.
 * This API initializes the SMU registers to configure Temp Sensor, Standby configurations.
 * It also reads and applies configuration from EEPROM USER Area.
 *
 * @retval  Nothing to Return
 */
void PN76_Sys_Hal_PCRM_Smu_Init(void);

/*!
 * @brief Performs Clock Module Initialization.
 * This API initialize XTAL, SYSTEM CLK (HFO) and also configures the clock to the CLIF Module as SYSTEM Clock till PLL is available/locked.
 *
 *  @retval  Nothing to Return
 */
void PN76_Sys_Hal_PCRM_Clkgen_Init(void);

/*!
 * @brief This function initializes the System clock to HFO and revert the CLIF Clock from XTAL/PLL to HFO before entering Standby/ULP Standby.
 * This function initializes the System clock to HFO and revert the CLIF Clock from XTAL/PLL to HFO before entering Standby/ULP Standby.
 * \note In order to set the system clock frequency to 90MHz, you must update the EEPROM configuration address 0xBE with value as \b 0x00 (for 90MHz), \b 0x01 (for 45MHz) with \ref E_PN76_EEPROM_IC_CONFIG using API \ref PN76_WriteEeprom().
 *
 * @retval  Nothing to Return
 */
void PN76_Sys_Hal_PCRM_SystemClockInit(void);

/*!
 * @brief This function shall be used to Start the Crystal oscillator (XTAL) in phases.
 *
 * @note This function should only be used when XTAL is used as the CLIF Clock source.
 *
 * @param  ePhase: startup phase \ref PN76_PCRM_XtalPhase_t values
 *
 * @retval Returns PN76_STATUS_SUCCESS: no error occurred, any other value if an error occurred.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_StartXtal(PN76_PCRM_XtalPhase_t ePhase);

/*!
 * @brief Performs GPADC Initialization. This function Initialized the GPADC by mapping the channels and performing calibration.
  *
 *  @retval  Returns PN76_STATUS_SUCCESS: no error occurred, any other value if an error occurred.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_Gpadc_Init(void);

/*!
 * @brief Performs GPADC De-Initialization. This function disabled the GPADC module.
  *
 *  @retval  Returns Nothing.
 */
void PN76_Sys_Hal_PCRM_Gpadc_Stop(void);

/*!
 * @brief This function shall starts the TXLDO used for RF Driver.
 *
 * @note : This function starts the TX driver supply based on the power configuration in the EEPROM.
 *
 * @param  eConfig: Config to start or stop TXLDO, \ref PN76_PCRM_TxDriverConfig_t values
 *
 * @retval  Returns PN76_STATUS_TXLDO_ERROR in case VUP is too high to turn off TXLDO or VUP too low to turn ON the TXLDO,
 *          Returns PN76_STATUS_SUCCESS on successful start of TXLDO.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_TxldoConfig(PN76_PCRM_TxDriverConfig_t eConfig);

/*!
 * @brief This function returns the mapped Channel number of the requested sensor.
 *
 * @param  eSensor: Sensor used to get General Purpose Analog to Digital Converter (GPADC) value, \ref PN76_PCRM_GpadcSensor_t.
 *
 * @retval  Returns channel number in range of 1-8.
 */
uint8_t PN76_Sys_Hal_PCRM_GpadcGetChannel(PN76_PCRM_GpadcSensor_t eSensor);


/*!
 * @brief This function returns the requested sensor value.
 * This API reads the requested sensor value based on the value type and applies trim(if required).
 *
 * @note   If the MUX is enabled for measuring the external AD1 pin value (\ref PN76_Sys_Hal_PCRM_GpadcGetValueOneShot()) then,
 *          even if \ref PN76_PCRM_GpadcSensor_t eSensor is \ref E_PN76_PCRM_GPADC_SENSOR_VBAT, then the equivalent value is read from external AD1 pin and not VBAT voltage.
 *
 * @param  eSensor: Sensor used to get General Purpose Analog to Digital Converter (GPADC) value, \ref PN76_PCRM_GpadcSensor_t.
 * @param  eType: type of acquisition (either gross value or real scale value) \ref PN76_PCRM_GpadcValueType_t values
 * @param  *pwValue: acquired value
 *
 * @retval  PN76_STATUS_SUCCESS On Success.
 * @retval  PN76_STATUS_INTERNAL_ERROR on wrong sensor acquisition request.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_GpadcGetValue(
            PN76_PCRM_GpadcSensor_t eSensor,
            PN76_PCRM_GpadcValueType_t eType,
            int16_t *pwValue);

/*!
 * @brief This function returns the instant value of requested sensor.
 * This API reads the sensor once and returns the value.(if required).
 *
 * @note   If the MUX is enabled for measuring the external AD1 pin value (\ref PN76_Sys_Hal_PCRM_GpadcGetValueOneShot()) then,
 *          even if \ref PN76_PCRM_GpadcSensor_t eSensor is \ref E_PN76_PCRM_GPADC_SENSOR_VBAT, then the equivalent value is read from external AD1 pin and not VBAT voltage.
 *
 * @param  eSensor: Sensor used to get General Purpose Analog to Digital Converter (GPADC) value, \ref PN76_PCRM_GpadcSensor_t.
 * @param  eType: type of acquisition (either gross value or real scale value) \ref PN76_PCRM_GpadcValueType_t values
 * @param  *pwValue: acquired value
 *
 * @retval  PN76_STATUS_SUCCESS On Success.
 * @retval  PN76_STATUS_INTERNAL_ERROR on wrong sensor acquisition request.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_GpadcGetValueOneShot(
            PN76_PCRM_GpadcSensor_t eSensor,
            PN76_PCRM_GpadcValueType_t eType,
            int16_t *pwValue);

/*!
 * @brief This function Sets the thresholds for requested sensor. It configures both high and low thresholds.
 *
 * @param  eSensor: Sensor whose threshold is to be configured, \ref PN76_PCRM_GpadcSensor_t.
 * @param  eType: type of threshold (either gross value or real scale value) \ref PN76_PCRM_GpadcValueType_t values
 * @param  wLowThreshold: Low threshold below which an interrupt will be triggered
 * @param  wHighThreshold: High threshold above which an interrupt will be triggered
 *
 * @retval  PN76_STATUS_SUCCESS On Success.
 * @retval  PN76_STATUS_INTERNAL_ERROR if the sensor is not mapped on any of the channels.
 * @retval  PN76_STATUS_PARAMETER_ERROR If E_PN76_PCRM_GPADC_SENSOR_RESERVED sensor is requested.
 * @retval  PN76_STATUS_PARAMETER_ERROR if E_PN76_PCRM_GPADC_SENSOR_ANY sensor is requested, since E_PN76_PCRM_GPADC_SENSOR_ANY has no support of real scale threshold
 *
 * @note    E_PN76_PCRM_GPADC_SENSOR_ANY Sensor to be used only to get One Shot value with PN76_Sys_Hal_PCRM_GpadcGetValueOneShot.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_GpadcSetThreshold(
            PN76_PCRM_GpadcSensor_t eSensor,
            PN76_PCRM_GpadcValueType_t eType,
            int16_t wLowThreshold,
            int16_t wHighThreshold);

/*!
 * @brief This function Reads the thresholds of requested sensor. It returns both high and low thresholds.
 *
 * @param  eSensor: Sensor whose threshold is to be acquired, \ref PN76_PCRM_GpadcSensor_t.
 * @param  eType: type of threshold (either gross value or real scale value) \ref PN76_PCRM_GpadcValueType_t values
 * @param  *wLowThreshold: Low threshold below which an interrupt will be triggered
 * @param  *wHighThreshold: High threshold above which an interrupt will be triggered
 *
 * @retval  PN76_STATUS_SUCCESS On Success.
 * @retval  PN76_STATUS_INTERNAL_ERROR if the sensor is not mapped on any of the channels.
 * @retval  PN76_STATUS_PARAMETER_ERROR if E_PN76_PCRM_GPADC_SENSOR_ANY sensor selected, since E_PN76_PCRM_GPADC_SENSOR_ANY has no support of real scale threshold
 *
 * @note    E_PN76_PCRM_GPADC_SENSOR_ANY Sensor to be used only to get One Shot value with PN76_Sys_Hal_PCRM_GpadcGetValueOneShot.
 */
PN76_Status_t PN76_Sys_Hal_PCRM_GpadcGetThreshold(
            PN76_PCRM_GpadcSensor_t eSensor,
            PN76_PCRM_GpadcValueType_t eType,
            int16_t *wLowThreshold,
            int16_t *wHighThreshold);

/*!
 * @brief This function reads the current temperature of PN76 IC.
 *
 * @retval  Returns Current Ambient temperature of the IC in Celsius.
 */
int32_t PN76_Sys_Hal_PCRM_GetTemperature(void);

/*!
 * @brief This function performs the SoftReset of the System.
 *
 * This function also stops the Crystal oscillator (if already started) and then performs a SoftReset.
 * All the clocks, LDOs, RF Drivers are reset except registers responsible for Low power states.
 *
 * @param bNormalModeEntryReq: Whether the entry to normal mode (application mode) or into HIF polling.
 *                           | Values   |     Description
                             |  -------:| :--------------------------------------------------------------
                             | 0x00     | HIF Polling entry is required on SOFTRESET.
                             | 0x01     | Normal mode entry is required on SOFTRESET.
                             | Other values     | Not applicable.
 * @retval Nothing to Return
 */
void PN76_Sys_Hal_SoftReset(uint8_t bNormalModeEntryReq);

/*!
 * @brief This function Performs a Hard Reset of the System.
 *
 * This function is equivalent to VEN Reset (registers responsible for Low power states shall also be reset).
 *
 * @retval Nothing to Return
 */
void PN76_Sys_Hal_HardReset(void);

/*!
 * @brief This function Returns the Pad power status. The function returns the current power status which can
 *  be FULL POWER (VBAT and VDDIO ON),LOW POWER(VBAT only, No VDDIO).
 *
 * @retval Return values are FULL POWER or LOW POWER \ref PN76_PCRM_PowerStatus_t
 */
PN76_PCRM_PowerStatus_t PN76_Sys_Hal_PCRM_GetPadPowerStatus(void);

/*!
 * @brief This function enables the clock to different IPs.
 *
 * @param bClk IP Clock/s to be enabled, \ref PN76_PCRM_IP_Clocks_t
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_ClockEnable(PN76_PCRM_IP_Clocks_t bClk);

/*!
 * @brief This function disables the clock to different IPs.
 *
 * @param bClk IP Clock/s to be disabled, \ref PN76_PCRM_IP_Clocks_t
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_ClockDisable(PN76_PCRM_IP_Clocks_t bClk);

/*!
 * @brief This function programs the given Host interface selection in the PCRM IP.
 *
 * @param bHifSelection Selected Host interface to be used, \ref PN76_PCRM_HifSelect_t
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_HifSelect(PN76_PCRM_HifSelect_t bHifSelection);

/*!
 * @brief This function returns the Host interface selected.
 *
 * @retval Returns the configured Host Interface, \ref PN76_PCRM_HifSelect_t
 */
PN76_PCRM_HifSelect_t PN76_Sys_PCRM_GetHifSelect(void);


/*!
 * @brief This function Runs the SW LPCD
 *
 * @param tLpcdMode: Reference mode or measurement mode
 *
 * @retval  PN76_STATUS_NO_TAG_DETECTED If Tag is not detected during LPCD.
 * @retval  PN76_STATUS_TAG_DETECTED. On Tag detection
 * @retval  PN76_STATUS_EXTERNAL_FIELD. In case of external RF detected during LPCD.
 *          Please refer to \ref PN76_Status_t for error codes details
 */
PN76_Status_t PN76_Sys_PCRM_LPCD_Start (PN76_PCRM_LPCD_Mode_t tLpcdMode);


/*!
 * @brief This function Returns the Reference value after LPCD calibration
 *
 * @retval Reference value.
 *
 * @note This is to be called only after LPCD calibration is performed.
 */
uint32_t PN76_Sys_PCRM_GetLpcdReference(void);


/**
 * @brief Select the USB PLL Reference Clock Source.
 *
 * @param   eSource Clock source for the USB PLL Reference Clock \ref PN76_PCRM_UsbPllClk_t.
 *
 * @retval  PN76_STATUS_SUCCESS Operation Successful
 * @retval  PN76_STATUS_PARAMETER_ERROR Invalid parameter
 */
PN76_Status_t PN76_Sys_PCRM_SetUsbPllClk(PN76_PCRM_UsbPllClk_t eSource);

/*!
 * @brief This function enables the USB PLL and returns after the PLL is Locked.
 *
 * @note Pre-Requisite for this function is that USB PLL reference clock source should be selected and running.
 *
 * @retval  PN76_STATUS_SUCCESS Operation Successful
 * @retval  PN76_STATUS_TIMEOUT Operation failed.
 */
PN76_Status_t PN76_Sys_PCRM_StartUsbPll(void);

/*!
 * @brief This function applies Trim values for Low power modes.
 *
 * @note This is mandatory to be called before entering ULP Standby and ULPCD.
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_ApplyLowPowerTrim(void);

/*!
 * @brief This function applies RF level detector settings for Standby from User EEPROM.
 *
 * @note This is mandatory to be called before entering Standby.
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_ApplyRFLevelDetectorSettings(void);

/**
 * @brief Configures the Internal Pad voltage (PVDD) LDO.
 *
 * @param ePvddLdoPower PVDD LDO power configuration, \ref PN76_PCRM_PvddLdoConfig_t
 *
 *
 *
 * @retval Nothing to Return
 */
void PN76_Sys_PCRM_ConfigurePvddLdo(PN76_PCRM_PvddLdoConfig_t ePvddLdoPower);




/*!
 * @brief   This API will execute the PVDD algorithm with the existing settings of PVDD configuration.
 *          The execution status is stored in the parameter referenced.
 *
 * @param   *pdwStatus   Pointer to uint32_t that stores the PVDD algorithm execution status.
 *                       The algorithm execution status is as below:
                 |Status Value  | Description
                 |--------------| :------------------------------------------------------------------
                 | 0x00         | PVDD algorithm not executed
                 | 0x01         | PVDD algorithm executed successfully with configuration as External. VDDIO is supplied.
                 | 0x02         | PVDD algorithm executed successfully with configuration as Internal. VDDIO is supplied.
                 | 0x81         | VDDIO is not present when PVDD configuration is External.
                 | 0x82         | VBAT is lesser than the required value to start the PVDD LDO when the configuration is Internal.  PVDD LDO is switched OFF.
                 | 0x83         | PVDD is not present even though PVDD LDO is enabled when configuration is Internal. PVDD LDO is switched OFF.
                 | 0x84         | PVDD LDO is experiencing PVDD current limit when configuration is Internal.  PVDD LDO is switched OFF.
 *
 *
 * @retval  PN76_STATUS_SUCCESS  PVDD algorithm is executed successfully.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 *
 */
PN76_Status_t PN76_Sys_Hal_PCRM_ExecPvddAlgo(uint32_t *pdwStatus);

/*!
 * @brief   This API will return the execution status the previous PVDD algorithm execution with the corresponding settings of PVDD configuration.
 *
 * @return  Returns the previously executed PVDD algorithm execution status.
                 |Return Value  | Description
                 |--------------| :------------------------------------------------------------------
                 | 0x00         | PVDD algorithm not executed
                 | 0x01         | PVDD algorithm executed successfully with configuration as External. VDDIO is supplied.
                 | 0x02         | PVDD algorithm executed successfully with configuration as Internal. VDDIO is supplied.
                 | 0x81         | VDDIO is not present when PVDD configuration is External.
                 | 0x82         | VBAT is lesser than the required value to start the PVDD LDO when the configuration is Internal.  PVDD LDO is switched OFF.
                 | 0x83         | PVDD is not present even though PVDD LDO is enabled when configuration is Internal. PVDD LDO is switched OFF.
                 | 0x84         | PVDD LDO is experiencing PVDD current limit when configuration is Internal.  PVDD LDO is switched OFF.
 *
 */
uint32_t PN76_Sys_Hal_PCRM_Get_PvddAlgoExec_Status( void );

/**
 * @brief Switch into standby mode.
 *
 * @note The function will never return if IC is switched into standby was successful.
 * @note In case the function returns, the standby prevention can be found in register \ref PCRM_SYS_BOOT2_STS. This register can be read using \ref PN76_Sys_ReadRegister().
 * @note Once the IC enters into standby, the configuration and values of GPIO0s will persist.
 *
 * @param   eWakeUpSource Selection of wake-up source in Enum \ref PN76_PCRM_LowPower_WakeUp_Config_t.
 * @param   dwWakeUpCntValue 10 bit wake-up counter value: resolution=2,63ms -> max time slot=2,57s. This is used only in case of TIMER as wakeup.
 *
 * @retval  PN76_STATUS_PARAMETER_ERROR Incase no wakeup Source is selected
 * @retval  PN76_STATUS_LOW_POWER_ENTRY_PREVENTED. Incase the Standby Entry is prevented. The reason for the prevention can be read from register \ref PCRM_SYS_BOOT2_STS. This register can be read using \ref PN76_Sys_ReadRegister().
 */
PN76_Status_t PN76_Sys_PCRM_EnterStandby(PN76_PCRM_LowPower_WakeUp_Config_t eWakeUpSource, uint32_t dwWakeUpCntValue);

/**
 * @brief Switch into Suspend mode.
 *
 * @note The function will return if Switch into Suspend and wakeup was successful.
 * @note The function returns, then the Suspend Wakeup is available or the prevention reason in available.
 *       Suspend Prevention reason is in register PCRM_SYS_BOOT2_STS. This register can be read using \ref PN76_Sys_ReadRegister().
 *
 * @param   eWakeUpSource Selection of wake-up source in Enum \ref PN76_PCRM_LowPower_WakeUp_Config_t.
 * @param   dwWakeUpCntValue 10 bit wake-up counter value: resolution=2,63ms -> max time slot=2,57s. This is used only in case of TIMER as wakeup.
 *
 * @retval  PN76_STATUS_SUCCESS : On successful entering Suspend and Waking Up from wakeup source.
 * @retval  PN76_STATUS_PARAMETER_ERROR Incase no wakeup Source is selected
 * @retval  PN76_STATUS_LOW_POWER_ENTRY_PREVENTED. Incase the Suspend Entry is prevented. The reason for the prevention can be read from register PCRM_SYS_BOOT2_STS. This register can be read using \ref PN76_Sys_ReadRegister().
 */
PN76_Status_t PN76_Sys_PCRM_EnterSuspend(PN76_PCRM_LowPower_WakeUp_Config_t eWakeUpSource, uint32_t dwWakeUpCntValue);

/**
 * @brief Switch into Ultra Low Power standby mode.
 *
 * @param   wWakeupSource Selection of wake-up source in Enum \ref PN76_PCRM_UltraLowPower_WakeUp_Config_t.
 * @param   dwWakeUpCntValue 12 bit wake-up counter value: resolution=1ms -> max time slot=4.096s. This is used as a wakeup time interval when wakeup source is TIMER. \n \note It is mandatory to have TIMER as wakeup source in all cases. \n If external RF is configured as wakeup source, the IC wakes up if there is no external RF within the wakeup counter interval. \n Higher priority for wakeup is always the Wakeup counter.
 *
 * @retval  PN76_STATUS_SUCCESS : SUCCESS is never returned as the system enters into Ultra low power in case of successful entry to ULP mode.
 * @retval  PN76_STATUS_PARAMETER_ERROR In case invalid wakeup source is selected or wake-up interval is more than 12bits
 *
 */
PN76_Status_t PN76_Sys_PCRM_EnterUlpStandby(PN76_PCRM_UltraLowPower_WakeUp_Config_t wWakeupSource, uint16_t dwWakeUpCntValue);

/**
 * @brief Switch into Ultra Low Power Card Calibration/Detection mode.
 *
 * @param   bUlpcdConfig Selection of ULPCD Configuration as in Enum \ref PN76_PCRM_ULPCD_Config_t.
 * @param   dwWakeUpCntValue 12 bit wake-up counter value: resolution=1ms -> max time slot=4.096s. This is interval defines the wakeup time during calibration phase and time between RF pings during card detection.
 * only in case of TIMER as wakeup.
 * @param   bUlpdetEnable Ultra low power RF detection enabled/Disabled. Value to be TRUE means 1 for ULPDET Enable or FALSE means 0 for ULPDET Disabled.
 *          Any other value is not considered for ULPDET .
 *
 * @retval  PN76_STATUS_SUCCESS : SUCCESS is never returned as the system enters into Ultra low power mode in case of successful entry to ULP mode.
 * @retval  PN76_STATUS_PARAMETER_ERROR Incase invalid wakeup source is selected or wake-up interval is more than 12bits
 */
PN76_Status_t PN76_Sys_PCRM_EnterULPCD(  PN76_PCRM_ULPCD_Config_t bUlpcdConfig, uint16_t dwWakeUpCntValue, uint8_t bUlpdetEnable);

/**
 * @brief Enable RF Detection.
 *
 * @note: LPDET IRQ should be enabled, when External RF is detected a PMU IRQ is triggered with LPDET_IRQ bit set.
 */
void PN76_Sys_PCRM_RfDetect_Start(void);

/**
 * @brief Disable RF Detection.
 *
 */
void PN76_Sys_PCRM_RfDetect_Stop(void);

/**
 * @brief Re-Enter Standby.
 *
 * @note: To be used in case of LPCD. GPREG6 holding LPCD state details is used.
 */
void PN76_Sys_PCRM_ReEnterStandby(void);

/*!
 * @brief   This API will initialize for the MUX that was enabled to measure the voltage on external ADC pin AD1.
 *
 * @retval  PN76_STATUS_SUCCESS :  Initialization of MUX for measurement on AD1 pin is successfull.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t  PN76_Sys_PCRM_Init_ExtAnalog_ADC( void );

/**
 * @brief This API provides the raw data read from the ADC, of the External Signal fed via AD1 Pin.
 *       This API will return the digital equivalent of the voltage value fed on AD1 pin.
 *
 * @note  This API must be called only after the \ref PN76_Sys_PCRM_Init_ExtAnalog_ADC() API.
 * @note  Only digital equivalent to the AD1 pin value is provided. The caller must convert this to absolute value.
 *
 * @param  *pwValue : Raw Data that is being read from the ADC. Will contain the value only if return value is \ref PN76_STATUS_SUCCESS.
 *
 * @retval  PN76_STATUS_SUCCESS :  GPADC One Shot mode is executed successfully and read data is stored in the parameter.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Sys_PCRM_Read_OneShot_ExtAnalog_ADC(int16_t *pwValue);

/**
 * @brief De-Initialize the GPADC after Disabling AD1 measurement for external Analog signal
 *
 */
void PN76_Sys_PCRM_DeInit_ExtAnalog_ADC(void);

/*!
 * @brief   This API will return the status of whether the MUX is enabled for measuring the
 *          external ADC pin AD1.
 *
 * @retval  0x01 Indicates that MUX is enabled to measure the voltage on AD1 pin.
 * @retval  0x00 Indicates that MUX is disabled to measure the voltage on AD1 pin.
 *
 *
 */
uint8_t PN76_Sys_PCRM_Get_EnableStatus_ExtAnalog_ADC(void);
/*!
 * @brief   This API will return the whether the GPADC is enabled or not enabled.
 *
 * @retval  0x01 Indicates that GPADC is enabled.
 * @retval  0x00 Indicates that GPADC is not enabled/initialized.
 *
 */
uint8_t PN76_Sys_Hal_PCRM_Is_Gpadc_Enabled( void );
/*!
 * @brief   This API will De-initialze the GPADC.
 *
 * @warning If GPADC is de-initialized, then RF functionality might be affected with DPC feature.
 *
 */
void PN76_Sys_Hal_PCRM_Gpadc_DeInit( void );

/**
 * @brief This API sets the delay to check the PVDD LDO status after it is enabled when the
 *       pad supply is from internal PVDD LDO.
 *
 * @note  If any value is less than 30us (3 in parameter), the default delay is set to 30us.
 * @note  It will take effect only after the PVDD algorithm is executed by either calling \ref PN76_Sys_Hal_PCRM_ExecPvddAlgo() or
 *        after a reset.
 * @note
 *
 * @param  bDelayIn10us : Delay interms of 10 microseconds.
 *
 * @retval  PN76_STATUS_SUCCESS :  Delay is successfully set.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Sys_PCRM_Set_PVDDMon_Delay(
            uint8_t bDelayIn10us);

/**
 * @brief This API gets the delay that is applied to check the PVDD LDO status after the PVDD LDO
 *       is enabled. The returned value is in-terms of 10 micro-seconds.
 *
 * @param  *pbDelayIn10us : PVDD LDO status check delay in-terms of 10micro-seconds. Will contain the valid value only if return value is \ref PN76_STATUS_SUCCESS.
 *
 * @retval  PN76_STATUS_SUCCESS :  PVDD LDO delay returned successfully.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Sys_PCRM_Get_PVDDMon_Delay(
            uint8_t * pbDelayIn10us);
#ifdef __cplusplus
}
#endif

/** @} */
#endif /* _PN76_PCRM_H_ */


