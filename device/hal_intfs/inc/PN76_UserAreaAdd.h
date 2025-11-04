/*----------------------------------------------------------------------------*/
/* Copyright 2018-2023  NXP                                                   */
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
 * Definitions for FLASH.
 * $Author:: NXP $
 * $Revision:$
 * History:
 */


#ifndef PH_USERAREA_ADD_H
#define PH_USERAREA_ADD_H

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"


/** @addtogroup PN76SYSHALUSERAREA_ADD
 *
 * @brief Structure definitions for user area configurations
 * This module contains the addresses user area configuration parameters with necessary information to be called using
 * APIs such as \ref PN76_WriteEeprom(), \ref PN76_ReadEeprom().
 *
 * @{
 *
 */


/**
 * @brief This structure contains additional digital delay to be provided for different technology and baud-rate combination.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note This structure is currently not used. If required the CLIF component of NS CLIF stack can use this configuration structure to include the additional delay in conjunction with FDT to be applied.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bDigitalDelay_En[1]; /**< Enable of additional digital delay to apply for the different technology and baud-rate combination
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | RFU                      | [7:1]     |             | Reserved
                        | Digital Delay enable     | [0]       |  0x00       | Additional digital delay is disabled
                        | ^                        | ^         |  0x01       |Additional digital delay is enabled. Additional digital delay are added for different technology and baud-rate combination.
                        */

   uint8_t bDigiDelay_A_848[1]; /**< Base digiDelay in usecs for type A 848 base, 424 = base*2, 212= Base*4, 106=Base*8 */
   uint8_t bDigiDelay_B_848[1]; /**< Base digiDelay in usecs for type B 848 base, 424 = base*2, 212= Base*4, 106=Base*8 */
   uint8_t bDigiDelay_F_424[1]; /**< Base digiDelay in usecs for type F 848 base, 424 = base*2, 212= Base*4, 106=Base*8 */
   uint8_t bDigiDelay_15693_fast_high[1]; /**< Base digiDelay in usecs for ISO15693 212= Base*4, 106=Base*8 */
   uint8_t bDigiDelay_18000_2_848[1]; /**< Base digiDelay in usecs for type 18000_2_848 */
   uint8_t bDigiDelay_18000_4_848[1]; /**< Base digiDelay in usecs for type 18000_4_848  */
}PN76_DIGITAL_DELAY_t;

/**
 * @brief This parameter provides the TX guard time to be applied.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note During CLIF send data, this guard timer is started after TX if it is enabled. If TX IRQ does not occur (TX is not complete), within this guard time, an error is responded indicating that TX did not complete.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwTXIRQ_GuardTime[4]; /**< TX IRQ guard time.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |TX IRQ guard time         | [31-0]    |  0x00       | TX IRQ guard time is disabled
                        | ^                        | ^         |  0x01-0xFFFFF| Enabled with guard time, where 1 unit corresponds to 1us. Maximum timeout of 1.048s. Default value = 0xF4240 (1s)
                        | ^                        | ^         |  others     | Reserved
                        */
}PN76_TXIRQ_GUARD_t;

/**
 * @brief This parameter provides the default FDT value to be applied when it is enabled.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note This parameter is used to configure the FDT in-case the host (in this case RdLib component) fails to configure the FDT using CLIF timer.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwFDT_DefaultVal[4];    /**< Default FDT value.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | Default FDT              | [31-0]    |  0x00       | Default FDT is disabled
                        | ^                        | ^         |  others     | FDT is enabled with this value. The value will be interms of 1 unit = 18.86us. Default fixed to 5.5seconds
                        */
}PN76_FDT_DEFAULT_t;

/**
 * @brief This parameter provides the RX guard time to be applied.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note During CLIF send data, this guard timer is started after TX is completed. If RX IRQ does not occur (frames not received), within this guard time, an error is responded indicating that RX failed.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwRXIRQ_GuardTime[4];   /**< RX IRQ guard time.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RX IRQ guard time         | [31-0]    |  0x00       | RX IRQ guard time is disabled
                        | ^                        | ^         |  0x01-0xFFFFF| Enabled with guard time, where 1 unit corresponds to 1us. Maximum timeout of 1.048s. Default value = 0xF4240 (1s)
                        | ^                        | ^         |  others     | Reserved
                        */
}PN76_RXIRQ_GUARD_t;

/**
 * @brief This parameter provides the RX frame length configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note This configuration is not used.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwClifRXFrameLen[4];  /**< CLIF RX frame length.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RFU                       | [31]      |       | RFU
                        | RX FRAME length          | [30-16]   |       | RX_FRAME_MAXLEN
                        |RFU                       | [15]      |       | RFU
                        | RX FRAME length          | [14-0]    |       | RX_FRAME_MINLEN
                        */
}PN76_CLIF_RX_FRAMELEN_CFG_t;

/**
 * @brief Reserved area for NXP usage.
 * @details Reserved area for NXP usage.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t Reserved[2]; /**< Reserved */
}PN76_UserArea_Reserved_t;

/**
 * @brief This structure contains default FDT value used in ISO18000 card communication.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wFdt_18000_DefVal[2]; /**< Timeout value for ISO18000. 16-bit value in little endian format.*/
}PN76_ISO18000_CFG_t;

/**
 * @brief This structure contains the ULPCD calibration completion status.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_USER_AREA region
 * @note This parameter must be used by the application to perform the ULPCD calibration when necessary and shall update this parameter to indicate the ULPCD calibration status.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bCalibDone[1]; /**< ULPCD calibration status completion. Must be handled by the application.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RFU                       | [7:1]     |       | RFU
                        |ULPCD calibration status  | [0]       | 0x00  | ULPCD calibration is not completed.
                        | ^                        | ^         | 0x01  | ULPCD calibration is completed.
                        */
}PN76_ULPCD_CALIB_STATUS_t;
/**
 * @brief Reserved area for NXP usage.
 * @details Reserved area for NXP usage.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bReserved_For_NXP[100]; /**< This area of 100 bytes is reserved for NXP For future updates to non-secure NXP deliverable components */
}PN76_Reserved_For_NXP_t;

/**
 * @brief This structure contains the IC power configuration parameter.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t PwrConfig[1]; /**< Power Configuration
                        |Function                  | bit     	| Values  	| Description
                        |-------------------------:|: ------:	|:-----------:|:------------------------------------
                        |DC-DC usage in card mode 	| [7]     	| 0x00  | DC-DC is not powered and set to bypass
                        | ^       					   | ^       	| 0x01  | DC-DC is powered and not bypassed
                        |DC-DC usage in reader mode| [6]  		| 0x00  | DC-DC is not powered and set to bypass
                        | ^       					   | ^         | 0x01  | DC-DC is powered and not bypassed
                        | RFU   					      | [5]  		|   	  | Do not touch. Default value is 0x01
                        |VUP input voltage 			| [4:0] 	   | 0x00  | Not connected or 0 V
                        | ^       					   | ^      	| 0x01  | No DC-DC and internal VDDPA_LDO: VUP supplied by VBAT / VBATPWR (pin VUP_TX connected to VBAT/VBATPWR)
                        | ^       					   | ^      	| 0x02  | Internal DC-DC: with auto by pass and variable boost w.r.t VDDPA (internal DPC controls VDDBOOST): DC-DC goes into 	pass through mode when the VDDPA goes below 3.3 V. When VDDPA is greater than 3.3 V, the DC-DC is configured to boost voltage in range of 3.3 V to 6 V. Internal DC-DC: with fixed VDDBOOST
                        | ^       					   | ^      	| 0x05 - 0x09  | RFU
                        | ^       					   | ^      	| 0x10  | No DC-DC and internal VDDPA_LDO: VUP supplied by external LDO (not connected to VBAT)

                        */
   uint8_t DcdcConfig[1];  /**< DCDC Configuration

                        |Function                  | bit       | Values      | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | RFU                      | [7:5]     |       | Reserved
                        |DC-DC pass through feature| [4]       | 0x00  | DC-DC pass through feature is not supported (Vout = 0v or +5v)
                        | ^                        | ^         | 0x01  | DC-DC pass through feature is supported (Vout = 0v or +5v)
                        |DC-DC for LPCD (Not ULPCD)| [3]       | 0x00  | Use of DC-DC for LPCD disabled (Not ULPCD)
                        | ^                        | ^         | 0x01  | Use of DC-DC for LPCD enabled (Not ULPCD)
                        | RFU                      | [2:0]     |       | Reserved

                        */
   uint8_t TxldoConfig[4];/**< Tx LDO/VDDPA Configuration
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | RFU                      | [31:2]    |       | Reserved
                        |Overcurrent protection    | [1]       | 0x00  | Overcurrent protection feature disabled
                        | ^                        | ^         | 0x01  | Overcurrent protection feature enabled
                        |Enable Tx-LDO             | [0]       | 0x00  | TxLDO is disabled. No voltage output of hte TXLDO
                        | ^                        | ^         | 0x01  | TxLDO is enabled. Regulated voltage output of hte TXLDO
                        | RFU                      | [2:0]     |       | Reserved

                        */
   uint8_t TxldoStartVddpa[1];/**<  VDDPA voltage when DCDC (internal or external) or external power source is used to feed TXLDO
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | VDDPA voltage level      | [7:0]     | 0x00 - 0x2A | Value 0 indicates 1.50v. Further VDDPA voltage would be 1.50+0.10v*this parameter value. Maximum value of 0x2A indicates for 5.70v

                        */
   uint8_t TxLdoVddpaMaxRdr[1];/**<  VDDPA maximum voltage to be set in reader mode (to by used by DPC)
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | VDDPA max voltage level  | [7:0]     | 0x00 - 0x2A | Value 0 indicates 1.50v. Further VDDPA voltage would be 1.50+0.10v*this parameter value. Maximum value of 0x2A indicates for 5.70v

                        */

   uint8_t TxLdoVddpaMaxCard[1];/**<  VDDPA maximum voltage to be set in card mode (to by used by DPC)
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | VDDPA max voltage level  | [7:0]     | 0x00 - 0x2A | Value 0 indicates 1.50v. Further VDDPA voltage would be 1.50+0.10v*this parameter value. Maximum value of 0x2A indicates for 5.70v

                        */
   uint8_t BoostDefaultVoltage[1];/**<  Default VDDBOOST output voltage in case of DC-DC with fixed VDDBOOST is enabled in \ref PwrConfig. In case of variable BOOT, the value is calculated based on VDDPA.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        | VDDBOOST output voltage  | [7:0]     | 0x00 - 0x1D | Value 0 indicates 3.1vv. Further VDDBOOST voltage would be 3.10+0.10v*this parameter value. Maximum value of 0x1D indicates for 6.00v
                        | ^                        | ^         | Other values| RFU

                        */

   uint8_t BoostVbatAuto[1];/**< Reserved. Do not modify */
   uint8_t StartupWait1[1]; /**< Reserved. Do not modify */
   uint8_t StartupWait2[1]; /**< Reserved. Do not modify */
   uint8_t StartupWait3[1]; /**< Reserved. Do not modify */
   uint8_t StartupWait4[1]; /**< Reserved. Do not modify */
}PN76_USER_PMU_t;

/**
 * @brief Configuration for the XTAL startup procedure.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bXtalConfig[1]; /**< Configuration for the XTAL startup procedure
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RFU                       | [7:1]     |       | RFU
                        | XTAL startup procedure   | [0]       |  0x00     | disable Crystal recalibration start after wake-up
                        | ^                        | ^         | 0x01  | enable Crystal recalibration start after wake-up

                        */


   uint8_t bXtalTimeOut[1]; /**< Timeout for XTAL to be ready
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |Configuration for XTAL startup procedure  | [7:0]     |       | Timeout for XTAL to be ready (in *128us). This configuration does not speed up the boot time.

                        */
}PN76_CLKGEN_t;

/**
 * @brief Configuration of RF clock.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bPLLClkInputFrq[1]; /**< Configuration for the PLL input clock frequency
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RFU                       | [7:4]     |       | RFU
                        | PLL clock configuration  | [3:0]     |  0x00     | 8MHz
                        | ^                        | ^         | 0x01  | 12MHz
                        | ^                        | ^         | 0x02  | 16MHz
                        | ^                        | ^         | 0x03  | 24MHz
                        | ^                        | ^         | 0x04  | 32MHz
                        | ^                        | ^         | 0x05  | 48MHz
                        | ^                        | ^         | 0x06  | RFU
                        | ^                        | ^         | 0x07  | 22.5MHz HFO
                        | ^                        | ^         | 0x08  | XTAL 27.12 MHz
                        | ^                        | ^         | others  | RFU

                        */
   uint8_t bXtalCheckDelay[1]; /**< Delay to check if XTAL is ready.
                        \note Correct Crystal clocking is detected by locking the crystal to the PLL. This allows the system to start quick independent from the crystal startup time. High-quality crystals will start up typically fast and allow by this optimized current consumption, e.g, during ULPCD.
                        \note A user needs to find an optimized balance between retry numbers of checking for a proper locking and the interval for checking for a locked PLL.
                        \note This allows to configure a timeout value for locking the crystal to the PLL. The timeout value is defined by Retry_number x Interval. If the timeout is reached, a clock error is raised.

                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:-----------:|:------------------------------------
                        |RFRetry_numberU           | [7:5]     |       | Max Number of retries before a clock error is raised
                        | Interval                 | [4:0]     |       | Interval which is used to check if XTAL is ready (unit is 256/fc, e.g. ~18.8 us). This is the time to try to lock the PLL, a stable crystal clock is required for locking. If the PLL is not locked, a next retry to lock the PLL will be done after this interval. This value can be used to optimize the startup time dependent on the crystal characteristics. This is important, e.g., for optimization of the LPCD and ULPCD.

                        */

}PN76_RF_CLOCK_CFG_t;

/**
 * @brief Configuration of standby voltage.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bStandbyVoltage[1]; /**< Reserved. Do not modify */

}PN76_USER_SMU_t;

/**
 * @brief Wave shaping configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bResidualAmplitudeLevel_A106[1]; /**< Residual amplitude level for A106
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |Residual amplitude level  | [7:0]     |  0x00     | 0% carrier
                        | ^                        | ^         | 0xFF  | 100% carrier
                        */
   uint8_t bEdgeType_A106[1]; /**< Edge type for A106
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |Edge transition style     | [7:4]     |       | Defines style of edge transition of falling edge, Defines style of edge transition:
                        | ^                        | ^         |       | Firmware based shaping
                        | ^                        | ^         | 0x01  | linear transition between two amplitude levels
                        | ^                        | ^         | 0x02  | two linear transitions between amplitude levels
                        | ^                        | ^         | 0x03  | three linear transitions between amplitude levels
                        | ^                        | ^         | Others  | RFU
                        | ^                        | ^         |       | Lookup table based shaping
                        | ^                        | ^         | 0x04  | lookup table-based transition, no automatic adaptation based on VDDPA
                        | ^                        | ^         | 0x05  | lookup table-based transition, automatic adaptation based on VDDPA including Correction
                        | ^                        | ^         | 0x06  | lookup table-based transition, automatic adaptation based on VDDPA but no Correction
                        | ^                        | ^         | Others  | RFU
                        |^                         | [3:0]     |       | Definition of edge transition style of rising edge, Defines style of edge transition:
                        | ^                        | ^         |       | Firmware based shaping
                        | ^                        | ^         | 0x01  | linear transition between two amplitude levels
                        | ^                        | ^         | 0x02  | two linear transitions between amplitude levels
                        | ^                        | ^         | 0x03  | three linear transitions between amplitude levels
                        | ^                        | ^         | Others  | RFU
                        | ^                        | ^         |       | Lookup table based shaping
                        | ^                        | ^         | 0x04  | lookup table-based transition, no automatic adaptation based on VDDPA
                        | ^                        | ^         | 0x05  | lookup table-based transition, automatic adaptation based on VDDPA including Correction
                        | ^                        | ^         | 0x06  | lookup table-based transition, automatic adaptation based on VDDPA but no Correction
                        | ^                        | ^         | Others  | RFU
                        */

   uint8_t bEdgeStyleConfiguration_A106[1]; /**< Time constant Edge style configuration for A106
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |RFU                       | [7]       |       | RFU
                        |Edge style configuration falling edge  | [6:4]     |       | Defines edge style configuration
                        | ^                        | ^         |       | For Firmware based shaping (\b bEdgeType_A106 is 1, 2, or 3: time constant configuration of falling edge (depends on edge style)
                        | ^                        | ^         |       | For lookup table based shaping (\b bEdgeType_A106 is 4, 5, or 6: This number is the lookup table which shall be used of falling edge (0,1,2,3)
                        |RFU                       | [3]       |       | RFU
                        |Edge style configuration rising edge  | [2:0]     |       | Defines edge style configuration
                        | ^                        | ^         |       | For Firmware based shaping (\b bEdgeType_A106 is 1, 2, or 3: time constant configuration of rising edge (depends on edge style)
                        | ^                        | ^         |       | For lookup table based shaping (\b bEdgeType_A106 is 4, 5, or 6: This number is the lookup table which shall be used of rising edge (0,1,2,3)
                        */
   uint8_t bEdgeLength_A106[1]; /**< Edge length for A106
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |Edge transition length    | [7]       |       | Scaling of edge transition by factor 2 of rising/falling edge (refers to both rising and falling edge at the same time)
                        | ^                        | ^         | 0x00  | disabled (1 transition state = one carrier cycle)
                        | ^                        | ^         | 0x01  | enabled (1 transition state = two carrier cycles)
                        | ^                        | [6:5]     |       | RFU
                        | ^                        | [4:0]     |       | Number of active transition states in rising and falling edge pattern (refers to both rising and falling edge at the same time)
                        */

   uint8_t bResidualAmplitudeLevel_A212[1]; /**< Passive reader mode TypeA-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_A212[1]; /**< Passive reader mode TypeA-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_A212[1]; /**< Passive reader mode TypeA-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_A212[1];  /**< Passive reader mode TypeA-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_A424[1]; /**< Passive reader mode TypeA-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_A424[1]; /**< Passive reader mode TypeA-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_A424[1]; /**< Passive reader mode TypeA-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_A424[1]; /**< Passive reader mode TypeA-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */

   uint8_t bResidualAmplitudeLevel_A848[1]; /**< Passive reader mode TypeA-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_A848[1]; /**< Passive reader mode TypeA-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_A848[1]; /**< Passive reader mode TypeA-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_A848[1]; /**< Passive reader mode TypeA-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_B106[1]; /**< Passive reader mode TypeB-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_B106[1]; /**< Passive reader mode TypeB-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_B106[1]; /**< Passive reader mode TypeB-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_B106[1]; /**< Passive reader mode TypeB-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_B212[1]; /**< Passive reader mode TypeB-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_B212[1]; /**< Passive reader mode TypeB-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_B212[1]; /**< Passive reader mode TypeB-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_B212[1]; /**< Passive reader mode TypeB-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */

   uint8_t bResidualAmplitudeLevel_B424[1]; /**< Passive reader mode TypeB-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_B424[1]; /**< Passive reader mode TypeB-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_B424[1]; /**< Passive reader mode TypeB-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_B424[1]; /**< Passive reader mode TypeB-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_B848[1]; /**< Passive reader mode TypeB-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_B848[1]; /**< Passive reader mode TypeB-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_B848[1];  /**< Passive reader mode TypeB-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_B848[1]; /**< Passive reader mode TypeB-848kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_F212[1]; /**< Passive reader mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_F212[1]; /**< Passive reader mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_F212[1];  /**< Passive reader mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_F212[1]; /**< Passive reader mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_F424[1]; /**< Passive reader mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_F424[1]; /**< Passive reader mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_F424[1]; /**< Passive reader mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_F424[1]; /**< Passive reader mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V100_26[1]; /**< Passive reader mode ISO 15693-100% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V100_26[1]; /**< Passive reader mode ISO 15693-100% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V100_26[1];  /**< Passive reader mode ISO 15693-100% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V100_26[1]; /**< Passive reader mode ISO 15693-100% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V100_53[1]; /**< Passive reader mode ISO 15693-100% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V100_53[1]; /**< Passive reader mode ISO 15693-100% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V100_53[1];  /**< Passive reader mode ISO 15693-100% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V100_53[1]; /**< Passive reader mode ISO 15693-100% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V100_106[1]; /**< Passive reader mode ISO 15693-100% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V100_106[1]; /**< Passive reader mode ISO 15693-100% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V100_106[1];  /**< Passive reader mode ISO 15693-100% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V100_106[1]; /**< Passive reader mode ISO 15693-100% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V100_212[1]; /**< Passive reader mode ISO 15693-100% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V100_212[1]; /**< Passive reader mode ISO 15693-100% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V100_212[1];  /**< Passive reader mode ISO 15693-100% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V100_212[1];/**< Passive reader mode ISO 15693-100% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V10_26[1]; /**< Passive reader mode ISO 15693-10% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V10_26[1]; /**< Passive reader mode ISO 15693-10% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V10_26[1];  /**< Passive reader mode ISO 15693-10% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V10_26[1]; /**< Passive reader mode ISO 15693-10% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V10_53[1]; /**< Passive reader modeISO 15693-10% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V10_53[1]; /**< Passive reader mode ISO 15693-10% modulation,53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V10_53[1];  /**< Passive reader mode ISO 15693-10% modulation, 53kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V10_53[1]; /**< Passive reader mode ISO 15693-10% modulation, 26kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V10_106[1]; /**< Passive reader mode ISO 15693-10% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V10_106[1]; /**< Passive reader mode ISO 15693-10% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V10_106[1];  /**< Passive reader mode ISO 15693-10% modulation, 106kbpss configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V10_106[1]; /**< Passive reader mode ISO 15693-10% modulation, 106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_V10_212[1]; /**< Passive reader mode ISO 15693-10% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_V10_212[1]; /**< Passive reader mode ISO 15693-10% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_V10_212[1];  /**< Passive reader mode ISO 15693-10% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_V10_212[1]; /**< Passive reader mode ISO 15693-10% modulation, 212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_180003m3_tari18p88[1]; /**< Passive reader mode ISO18000p3m3 with TARI 18.88us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_180003m3_tari18p88[1]; /**< Passive reader mode ISO18000p3m3 with TARI 18.88us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_180003m3_tari18p88[1];  /**< Passive reader mode ISO18000p3m3 with TARI 18.88us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_180003m3_tari18p88[1]; /**< Passive reader mode ISO18000p3m3 with TARI 18.88us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_180003m3_tari9p44[1]; /**< Passive reader mode ISO18000p3m3 with TARI 9.44us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_180003m3_tari9p44[1]; /**< Passive reader mode  ISO18000p3m3 with TARI 9.44us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_180003m3_tari9p44[1];  /**< Passive reader mode  ISO18000p3m3 with TARI 9.44us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_180003m3_tari9p44[1]; /**< Passive reader mode  ISO18000p3m3 with TARI 9.44us configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_B_prime106[1]; /**< Passive reader mode B-Prime card with 106kbps speed configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_B_prime106[1]; /**< Passive reader mode B-Prime card with 106kbps speed configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_B_prime106[1];  /**< Passive reader mode B-Prime card with 106kbps speed configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_B_prime106[1]; /**< Passive reader mode B-Prime card with 106kbps speed configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */

}PN76_RM_TECHNO_TX_SHAPING_t;

/**
 * @brief Configuration for the DPC parameters.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bConfig[1];  /**< DPC configuration
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |RFU                       | [7:3]     |       | RFU
                        |DPC in Active target mode | [2]       |       | DPC configuration in active target mode
                        | ^                        | ^         | 0x00  | disabled
                        | ^                        | ^         | 0x01  | enabled
                        |DPC in Active initiator mode | [1]    |       | DPC configuration in active initiator mode
                        | ^                        | ^         | 0x00  | disabled
                        | ^                        | ^         | 0x01  | enabled
                        |DPC in Reader/Passive Initiator mode  | [0]   |       | DPC configuration in Reader/ Passive Initiator mode
                        | ^                        | ^         | 0x00  | disabled
                        | ^                        | ^         | 0x01  | enabled
                        */
   uint8_t wTargetCurrent[2]; /**< DPC configuration unloaded VDDPA target current in mA
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |DPC in Active target mode | [15:0]    |       | VDDPA target current in mA. The target current +/- hysteresis defines the limiting maximum current for the DPC.

                        \note This configuration shall not exceed 350 mA - hysteresis.
                        \note The resulting current that is driven by the transmitter can be further reduced based on the current reduction lookup table entries.

                        */

   uint8_t bHysteresis[1]; /**< The hysteresis (\b bHysteresis and \b bHysteresis_Unloading) together with the target current (\b wTargetCurrent) defines the current limit, at which the DPC automatically decreases or
                                raises the VDDPA. The VDDPA is automatically reduced, as soon as the current exceeds the
                                 \b wTargetCurrent + \b bHysteresis, and the VDDPA is automatically increased again, as soon as the current is
                                 below \b wTargetCurrent – \b bHysteresis_Unloading.

                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |DPC hysteresis loading | [7:0]    |       | Absolute difference to current Target Current in mA that triggers a DPC update event during loading.

                        \note If the hysteresis is configured too small, it might cause an oscillation of the transmitted field.
                        \note In most application, the default values work well and do not need to be modified.
                        */
   uint8_t bTimerPeriod[1]; /**< DPC algorithm time interval between two consecutive current checks, unit = 128/13,56MHz (~9.44us) Default = 1ms */
   uint8_t bMaskingTime[1]; /**< Reserved. Do not modify */
   uint8_t bHysteresis_Unloading[1];  /**< The hysteresis (\b bHysteresis and \b bHysteresis_Unloading) together with the target current (\b wTargetCurrent) defines the current limit, at which the DPC automatically decreases or
                                          raises the VDDPA. The VDDPA is automatically reduced, as soon as the current exceeds the
                                          \b wTargetCurrent + \b bHysteresis, and the VDDPA is automatically increased again, as soon as the current is
                                          below \b wTargetCurrent – \b bHysteresis_Unloading.

                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |DPC hysteresis unloading | [7:0]    |       | Absolute difference to current Target Current in mA that triggers a DPC update event during unloading.

                        \note If the hysteresis is configured too small, it might cause an oscillation of the transmitted field.
                        \note In most application, the default values work well and do not need to be modified.
                        */
   uint8_t bTXLDOVDDPALow[1]; /**< VDDPA Low Limit for RDON */
   uint8_t bTXGSN[1]; /**< TXGSN configuration.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |DPC hysterisis loading | [7:0]    |  < 20      | resistance = 10 Ohm / (tx1_gsn + 1)
                        |^                      | ^        |  >= 20     | 20: resistance = 0.5 Ohm
                        */
   uint8_t bVDDPALowLimitcontrol[1]; /**< VDDPA low limit control (DPC_RDON_Control).
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |VDDPA low limit control   | [7:0]    |  0x00      | Disabled
                        |^                         | ^        |  0x01      | RdON Control
                        |^                         | ^        |  0x02      | PWM control
                        |^                         | ^        |  others    | RFU
                        */
   uint8_t bInitialRDOn_RFOn[1]; /**< Initial GSP TX1/TX2 value during FieldON */
   uint8_t wTxldoMaxDropOutCfg[2]; /**< At DPC start (on initial RF ON), if TXLDO drop out is higher to this value then VDDPA is reduced to: eVddpaSafe if no boost bypass on going else Vddpa is stopped.
Unit is mV. Default = E10h = 3600mV */
   uint8_t wBoostDropOut[2]; /**< Reserved. Do not modify */
   uint8_t wDPCWaitDuringFDT[2]; /**< Reserved. Do not modify */
   uint8_t bGuardTimeBeforeTx[1]; /**< DPC guard time configuration. Guard time before tx. 1unit = 1us.
                                       The DPC regulation is done once before TX and once after RX.
                                       The guard time parameter is the time between DPC regulation completion and TX start.
                                       The guard time parameter is the time between RX stop and DPC regulation start.
                                       The guard time is always enabled for TX
                                       \note Recommendation is not to modify the default value.
                                     */
   uint8_t bEnableDPCDuringFDT[1]; /**< DPC regulation enable during FDT.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |Disable DPC during FDT    | [7:0]    |  0x00      | DPC disabled during FDT (debug purpose only)
                        |^                         | ^        |  0x01      | DPC enabled during FDT (recommendation)
                        |^                         | ^        |  others    | RFU
                        */
   uint8_t bGuardTimeAfterRx[1]; /**< Enable DPC with guard time after RX
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |Enable DPC guard time after RX | [7:0]    |  0x00      | DPC disabled after RX (debug purpose only)
                        |^                         | ^        |  0x01      | DPC enabled after RX (recommendation)
                        |^                         | ^        |  others    | RFU
                        \note The guard time is always enabled for TX and cannot be disabled.
                        */
   uint8_t bLoSenseThreshold[1]; /**< Reserved. Do not modify */
   uint8_t bEntry_00[4]; /**< DPC lookup table. This entry is for 1.5V. Subsequent settings are for in steps of 100mV.
                        \note Voltage offset start = 1.5V
                        \note \b bEntry_00 = 1V5, \b bEntry_01 = 1V6 ... \b bEntry_42 = 5V7

                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |ENTRY 0                   | [31:0]    |           | This below details are for entry 0. Similar is for all other entries.
                        |Target current reduction  | [31:24]   |           | Byte 0. Target current reduction in mA (unsigned)
                        |AWC amp mod change        | [23:16]   |           | Byte 1. Relative change of modulated amplitude level (signed)
                        |AWC edge time constant for ASK100   | [15:8]    |           | Byte 2. Target current reduction in mA (unsigned)
                        |^                         | [15:12]   |            | ASK100, Relative change of rising edge time constant (signed)
                        |^                         | [11:8]    |            | ASK100, Relative change of falling edge time constant (signed)
                        |AWC edge time constant for ASK100   | [7:0]    |           | Byte 2. Target current reduction in mA (unsigned)
                        |^                         | [7:4]   |            | ASK10, Relative change of rising edge time constant (signed)
                        |^                         | [3:0]    |            | ASK10, Relative change of falling edge time constant (signed)
                        */

   uint8_t bEntry_01[4]; /**< Entry for 1V6. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_02[4]; /**< Entry for 1V7. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_03[4]; /**< Entry for 1V8. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_04[4]; /**< Entry for 1V9. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_05[4]; /**< Entry for 2V0. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_06[4]; /**< Entry for 2V1. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_07[4]; /**< Entry for 2V2. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_08[4]; /**< Entry for 2V3. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_09[4]; /**< Entry for 2V4. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_10[4]; /**< Entry for 2V5. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_11[4]; /**< Entry for 2V6. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_12[4]; /**< Entry for 2V7. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_13[4]; /**< Entry for 2V8. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_14[4]; /**< Entry for 2V9. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_15[4]; /**< Entry for 3V0. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_16[4]; /**< Entry for 3V1. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_17[4]; /**< Entry for 3V2. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_18[4]; /**< Entry for 3V3. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_19[4]; /**< Entry for 3V4. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_20[4]; /**< Entry for 3V5. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_21[4]; /**< Entry for 3V6. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_22[4]; /**< Entry for 3V7. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_23[4]; /**< Entry for 3V8. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_24[4]; /**< Entry for 3V9. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_25[4]; /**< Entry for 4V0. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_26[4]; /**< Entry for 4V1. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_27[4]; /**< Entry for 4V2. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_28[4]; /**< Entry for 4V3. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_29[4]; /**< Entry for 4V4. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_30[4]; /**< Entry for 4V5. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_31[4]; /**< Entry for 4V6. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_32[4]; /**< Entry for 4V7. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_33[4]; /**< Entry for 4V8. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_34[4]; /**< Entry for 4V9. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_35[4]; /**< Entry for 5V0. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_36[4]; /**< Entry for 5V1. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_37[4]; /**< Entry for 5V2. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_38[4]; /**< Entry for 5V3. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_39[4]; /**< Entry for 5V4. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_40[4]; /**< Entry for 5V5. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_41[4]; /**< Entry for 5V6. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
   uint8_t bEntry_42[4]; /**< Entry for 5V7. Refer to \ref PN76_DPC_SETTINGS_t.bEntry_00 above  */
}PN76_DPC_SETTINGS_t;

/**
 * @brief ARC settings configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bArcConfig[2]; /**< ARC settings configuration.
                        |Function                  | bit       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |ARC settings configuration| [7]       |  0x00     | ARC algorithm is disabled.
                        |^                         | ^         |  0x01     | ARC algorithm is enabled.
                        |^                         | [6:3]     |           | RFU
                        |^                         | [2:0]     |           | Number of entries in ARC table
                        |^                         | ^         |  0x00     | one entry
                        |^                         | ^         |  0x01     | two entries
                        |^                         | ^         |  0x02     | three entries
                        |^                         | ^         |  0x03     | four entries
                        |^                         | ^         |  0x04     | five entries
                        |^                         | ^         |  others   | RFU
                        */
   uint8_t wArcVddpa[5];  /**< VDDPA settings.
                        |Function                  | byte       | Values    | Description
                        |-------------------------:|: ------:  |:---------:|:------------------------------------
                        |VDDPA settings            | [4]       | See below note | VDDPA range_index 4: if VDDPA voltage between VDDPA_3 to ARC_VDDPA_4
                        |^                         | [3]       | ^           | VDDPA range_index 3: if VDDPA voltage between VDDPA_2 to ARC_VDDPA_3 - 0.1
                        |^                         | [2]       | ^           | VDDPA_range_index 2: if VDDPA voltage between VDDPA_1 to ARC_VDDPA_2 - 0.1
                        |^                         | [1]       | ^           | VDDPA_range_index 1: if VDDPA voltage between VDDPA_0 to (ARC_VDDPA_1 - 0.1)
                        |^                         | [0]       | ^           | VDDPA_range_index 0: if VDDPA voltage between 1.5 to (VDDPA_0 - 0.1)

                        \note: for above settings, value of 0x00 indicates for 1V50, 0x01 indicates for 1V60. Further increase with 100mV and value of 0x2A corresponds to 5V70.
                        */

   uint8_t wRmArcA_106[10]; /**< ARC table settings for reader mode Type A 106kbps
                        |Function                  | byte      | bits  |  Values    | Description
                        |-------------------------:|: ------:  |:-----:|:----------:|:--------------------------
                        | RM_RX_ARC_0              | [9:8]     | [15]  |            | ARC settings applicability. Settings will be taken into account only if bit[14] of this settings is set to '1'.
                        |^                         | ^         | ^     |   0x00     | ARC settings applicable always. bits [9:0] of ARC_RM_A106 are used.
                        |^                         | ^         | ^     |   0x01     | ARC settings applicable during FDT. bits [9:0] of ARM_RM_A106_FDT are used else bits[9:0] of table ARC_RM_A106 are used.
                        |^                         | ^         | [14]  |            | ARC enable/disable
                        |^                         | ^         | ^     |   0x00     | ARC disabled for this technology and baudrate
                        |^                         | ^         | ^     |   0x01     | ARC enabled for this technology and baudrate
                        |^                         | ^         | [13:10]|           | RFU
                        |^                         | ^         | [9]   |            | Enable the IIR filter
                        |^                         | ^         | [8:7] |            | MF_GAIN (this value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        |^                         | ^         | [6:0] |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        | RM_RX_ARC_1              | [7:6]     | [15]  |            | ARC settings applicability. Settings will be taken into account only if bit[14] of this settings is set to '1'.
                        |^                         | ^         | ^     |   0x00     | ARC settings applicable always. bits [9:0] of ARC_RM_A106 are used.
                        |^                         | ^         | ^     |   0x01     | ARC settings applicable during FDT. bits [9:0] of ARM_RM_A106_FDT are used else bits[9:0] of table ARC_RM_A106 are used.
                        |^                         | ^         | [14]  |            | RFU
                        |^                         | ^         | [13:10]|           | RFU
                        |^                         | ^         | [9]   |            | Enable the IIR filter
                        |^                         | ^         | [8:7] |            | MF_GAIN (this value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        |^                         | ^         | [6:0] |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        | RM_RX_ARC_2              | [5:4]     | [15]  |            | ARC settings applicability. Settings will be taken into account only if bit[14] of this settings is set to '1'.
                        |^                         | ^         | ^     |   0x00     | ARC settings applicable always. bits [9:0] of ARC_RM_A106 are used.
                        |^                         | ^         | ^     |   0x01     | ARC settings applicable during FDT. bits [9:0] of ARM_RM_A106_FDT are used else bits[9:0] of table ARC_RM_A106 are used.
                        |^                         | ^         | [14]  |            | RFU
                        |^                         | ^         | [13:10]|           | RFU
                        |^                         | ^         | [9]   |            | Enable the IIR filter
                        |^                         | ^         | [8:7] |            | MF_GAIN (this value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        |^                         | ^         | [6:0] |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        | RM_RX_ARC_3              | [3:2]     | [15]  |            | ARC settings applicability. Settings will be taken into account only if bit[14] of this settings is set to '1'.
                        |^                         | ^         | ^     |   0x00     | ARC settings applicable always. bits [9:0] of ARC_RM_A106 are used.
                        |^                         | ^         | ^     |   0x01     | ARC settings applicable during FDT. bits [9:0] of ARM_RM_A106_FDT are used else bits[9:0] of table ARC_RM_A106 are used.
                        |^                         | ^         | [14]  |            | RFU
                        |^                         | ^         | [13:10]|           | RFU
                        |^                         | ^         | [9]   |            | Enable the IIR filter
                        |^                         | ^         | [8:7] |            | MF_GAIN (this value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        |^                         | ^         | [6:0] |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        | RM_RX_ARC_4              | [1:0]     | [15]  |            | ARC settings applicability. Settings will be taken into account only if bit[14] of this settings is set to '1'.
                        |^                         | ^         | ^     |   0x00     | ARC settings applicable always. bits [9:0] of ARC_RM_A106 are used.
                        |^                         | ^         | ^     |   0x01     | ARC settings applicable during FDT. bits [9:0] of ARM_RM_A106_FDT are used else bits[9:0] of table ARC_RM_A106 are used.
                        |^                         | ^         | [14]  |            | RFU
                        |^                         | ^         | [13:10]|           | RFU
                        |^                         | ^         | [9]   |            | Enable the IIR filter
                        |^                         | ^         | [8:7] |            | MF_GAIN (this value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        |^                         | ^         | [6:0] |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        */

   uint8_t wRmArcA_212[10]; /**< Reader Mode TypeA 212kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcA_424[10]; /**< Reader Mode TypeA 424kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcA_848[10]; /**< Reader Mode TypeA 848kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcB_106[10]; /**< Reader Mode TypeB 106kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcB_212[10]; /**< Reader Mode TypeB 212kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcB_424[10]; /**< Reader Mode TypeB 424kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcB_848[10]; /**< Reader Mode TypeB 848kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcF_212[10]; /**< Reader Mode TypeF 212kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcF_424[10]; /**< Reader Mode TypeF 424kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcV_6p6[10]; /**< Reader Mode TypeV (ISO15693) 6.6kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcV_26[10]; /**< Reader Mode TypeV (ISO15693) 26kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcV_53[10]; /**< Reader Mode TypeV (ISO15693) 53kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcV_106[10]; /**< Reader Mode TypeV (ISO15693) 106kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArcV_212[10]; /**< Reader Mode TypeV (ISO15693) 212kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc180003m3_SC424_4Man[10]; /**< Reader Mode TypeV (ISO18000p3m3 424 kbps Manchestor 4 coding) Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc180003m3_SC424_2Man[10]; /**< Reader Mode TypeV (ISO18000p3m3 424 kbps Manchestor 2 coding) Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc180003m3_SC848_4Man[10]; /**< Reader Mode TypeV (ISO18000p3m3 848 kbps Manchestor 4 coding) Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc180003m3_SC848_2Man[10]; /**< Reader Mode TypeV (ISO18000p3m3 848 kbps Manchestor 2 coding) Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc_AI_106[10]; /**< Reader Mode active initiator type A 106 kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc_AI_212[10]; /**< Reader Mode active initiator type A 212 kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
   uint8_t wRmArc_AI_424[10]; /**< Reader Mode active initiator type A 424 kbps Refer to the byte/bit settings for member \ref PN76_ARC_SETTINGS_t.wRmArcA_106 */
}PN76_ARC_SETTINGS_t;


/**
 * @brief RSSI settings for card emulation only.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bRssiTimer[2];  /**< RSSI timer
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RSSI_TIMER               | [15:0]  |            | RSSI timer. Default: 423d.
                        */
   uint8_t bRssiTimerFirstPeriod[2]; /**< First period duration after Rf field ON.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RSSI                     | [15:0]  |            | First period duration after Rffield ON. Unit is 128/fc (106kHz) if set to 0 it means feature is not used 0D2 => ~2ms
                        */
   uint8_t bRssiCtrl_00_AB[1];  /**< RSSI control.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RSSI                     | [7:6] |            | Reserved
                        | ^                        | [5:0] |            | (APC_ID_REF_AB) ID of APC_TX entry that is equiv to RSSI = 0 (for Type AB)
                        */
   uint8_t bRssiNbEntriesAB[1];  /**< For Initial RF ON, CEA and CEB.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RSSI                     | [7:5] |            | Reserved
                        | ^                        | [4:0] |            | Number of entries in RSSI look up table (it refers to dwRssiEntryAB_01 to dwRssiEntryAB_X);
                        */

   uint8_t wRssiThresholdAB_01[2];   /**< Threshold value for APC algorithm for TypeA and TypeB. Format for each entry of is as below:
                        |Function                  | bits    |  Values    | Description
                        |-------------------------:|:-------:|:----------:|:--------------------------
                        | RSSI                     | [15:13] |            | Reserved
                        | ^                        | [12:0]  |            | RSSI Value

                        \note dwRssiEntryAB_00 = 0 (not in EEPROM) Signed phase compensation with 1/4 degree resolution: 16 bits signed value (using complement of 2)
                        */
   uint8_t wArbPhaseAB_01[2];   /**< Phase compensation value for APC algorithm for TypeA and TypeB. Format for each entry is as below:
                        |Function                  | bits    |  Values    | Description
                        |-------------------------:|:-------:|:----------:|:--------------------------
                        | RSSI                     | [15:0] |            | Signed phase compensation with 1/4 degree resolution:16 bits signed value (using complement of 2)
                        */
   uint8_t wRssiThresholdAB_02[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_02[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_03[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_03[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_04[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_04[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_05[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_05[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_06[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_06[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_07[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_07[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_08[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_08[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_09[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_09[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0A[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0A[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0B[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0B[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0C[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0C[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0D[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0D[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0E[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0E[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_0F[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_0F[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_10[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_10[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_11[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_11[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_12[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_12[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_13[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_13[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_14[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_14[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_15[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_15[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_16[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_16[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_17[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_17[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdAB_18[2]; /**< See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseAB_18[2];      /**< See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */

   uint8_t bRssiCtrl_00_F[1];     /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.bRssiCtrl_00_AB */
   uint8_t bRssiNbEntriesF[1];    /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.bRssiNbEntriesAB */
   uint8_t wRssiThresholdF_01[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_01[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_02[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_02[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_03[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_03[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_04[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_04[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_05[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_05[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_06[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_06[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_07[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_07[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_08[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_08[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_09[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_09[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0A[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0A[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0B[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0B[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0C[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0C[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0D[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0D[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0E[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0E[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_0F[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_0F[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_10[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_10[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_11[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_11[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_12[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_12[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_13[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_13[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_14[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_14[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_15[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_15[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_16[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_16[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_17[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_17[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
   uint8_t wRssiThresholdF_18[2]; /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wRssiThresholdAB_01 */
   uint8_t wArbPhaseF_18[2];      /**< For Type-F. For format of this field, See \ref PN76_APC_RSSI_t.wArbPhaseAB_01 */
}PN76_APC_RSSI_t;


/**
 * @brief APC algorithm table output settings TX_PARAM_ENTRY_TABLE. Applicable only for card emulation.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bTxParamEntry_00_ID[1]; /**< APC TX_PARAM_ENTRY for ID.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Driver count             | [7]   |            | Driver count (CLIF_TX_CONTROL_REG.TX_ALM_TYPE_SELECT):
                        | ^                        | ^     |  0x00      | Dual driver
                        | ^                        | ^     |  0x01      | Single driver
                        | BPSK mode                | [6]   |            | BPSK mode (CLIF_TX_CONTROL_REG.TX_ALM_BPSK_ENABLE):
                        | ^                        | ^     |  0x00      | Dual driver
                        | ^                        | ^     |  0x01      | Single driver
                        | ID                       | [5:0] |            | ID
                        */
   uint8_t bTxParamEntry_00_Tx1[1];  /**< APC TX_PARAM_ENTRY for TX1.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RFU                      | [7:6] |            | Reserved
                        | PMU VDDPA setting        | [5:0] |            | VDDPA(v) = (val*10)+1,5 \b0x00 = 1.50 V ... \b0x2Ah = 5.70 V
                        */
   uint8_t bTxParamEntry_00_Tx2[1];  /**< APC TX_PARAM_ENTRY for TX2.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Scaling factor           | [7:0] |            | Scaling factor for TX1 and TX2
                        */
   uint8_t bTxParamEntry_01_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_01_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_01_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_02_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_02_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_02_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_03_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_03_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_03_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_04_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_04_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_04_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_05_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_05_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_05_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_06_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_06_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_06_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_07_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_07_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_07_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_08_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_08_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_08_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_09_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_09_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_09_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0A_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0A_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0A_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0B_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0B_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0B_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0C_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0C_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0C_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0D_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0D_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0D_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0E_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0E_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0E_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_0F_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_0F_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_0F_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_10_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_10_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_10_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_11_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_11_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_11_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_12_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_12_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_12_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_13_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_13_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_13_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_14_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_14_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_14_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_15_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_15_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_15_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_16_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_16_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_16_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_17_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_17_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_17_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_18_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_18_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_18_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_19_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_19_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_19_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1A_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1A_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1A_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1B_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1B_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1B_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1C_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1C_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1C_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1D_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1D_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1D_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1E_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1E_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1E_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_1F_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_1F_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_1F_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_20_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_20_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_20_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_21_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_21_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_21_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_22_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_22_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_22_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_23_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_23_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_23_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_24_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_24_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_24_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_25_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_25_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_25_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_26_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_26_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_26_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_27_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_27_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_27_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_28_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_28_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_28_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_29_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_29_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_29_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2A_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2A_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2A_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2B_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2B_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2B_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2C_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2C_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2C_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2D_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2D_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2D_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2E_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2E_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2E_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_2F_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_2F_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_2F_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_30_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_30_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_30_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_31_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_31_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_31_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_32_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_32_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_32_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_33_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_33_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_33_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_34_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_34_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_34_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_35_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_35_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_35_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_36_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_36_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_36_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_37_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_37_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_37_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_38_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_38_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_38_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_39_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_39_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_39_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3A_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3A_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3A_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3B_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3B_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3B_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3C_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3C_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3C_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3D_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3D_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3D_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3E_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3E_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3E_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_3F_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_3F_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_3F_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_40_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_40_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_40_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_41_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_41_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_41_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_42_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_42_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_42_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_43_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_43_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_43_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_44_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_44_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_44_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_45_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_45_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_45_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_46_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_46_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_46_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_47_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_47_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_47_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_48_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_48_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_48_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_49_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_49_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_49_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_4A_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_4A_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_4A_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_4B_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_4B_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_4B_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_4C_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_4C_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_4C_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_4D_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_4D_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_4D_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t bTxParamEntry_4E_ID[1];  /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_ID */
   uint8_t bTxParamEntry_4E_Tx1[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx1 */
   uint8_t bTxParamEntry_4E_Tx2[1]; /**< APC TX_PARAM_ENTRY for ID. Refer to \ref PN76_APC_TX_t.bTxParamEntry_00_Tx2 */
   uint8_t dummy[3]; /* Do not remove used for alignment */
}PN76_APC_TX_t;

/**
 * @brief Autocoll configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bRfDebounceTimeout[1]; /**< Debounce timeout
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | DEBOUNCE_TIMEOUT         | [7:0] |            | Timeout used after the RF detection during the AUTOCOLL to detect if there is a glitch or continuous RF. Value is entered in 1 micro seconds.
                        */
   uint8_t bSensRes[2]; /**< Response to ReqA / ATQA in order byte 0, byte 1
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Response to ReqA / ATQA  | [15:0]|            | ATQA in order byte 0, byte 1
                        | ^                        | [15:8]|            | Byte1 value
                        | ^                        | [7:0] |            | Byte0 value
                        */
   uint8_t bNfcID1[3]; /**< Response to ReqA / ATQA in order byte 0, byte 1
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | UID address generation   | [31:0]|            | If Random UID is disabled (EEPROM address 0x2CB), the content of these addresses is used to generate a Fixed UID. The order is byte 0, Byte 1, Byte 2; Byte3 - which is the first NFCID1 byte - is fixed to 08h, the check byte is calculated automatically.
                        | ^                        | [31:24] |  0x08    | Byte3 value
                        | ^                        | [23:16] |          | Byte2 value
                        | ^                        | [15:8]  |          | Byte1 value
                        | ^                        | [7:0]   |          | Byte0 value
                        */

   uint8_t bSelRes[1]; /**< Response to Select : SAK
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Response to Select       | [7:0]|            | Response to Select : SAK
                        */
   uint8_t bPollRes[18]; /**< Response to Select : SAK
                        |Function                  | byte  | bits   |  Values    | Description
                        |-------------------------:|:-----:|:------:|:----------:|:--------------------------
                        | Felica Poll response     | [1:0] | [15:0] | 0x01FE     | FeliCa polling response. Shall be the same value.
                        | ^                        | [7:2] | [47:0] |            | FeliCa polling response. NFCID2 (6 bytes).
                        | ^                        | [15:8]| [63:0] |            | FeliCa polling response. PAD (8 bytes).
                        | ^                        | [17:16] | [15:0] |            | FeliCa polling response. System code (2 bytes).
                        */
   uint8_t bRandomUIDEnable[1];/**< Random UID enable
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Random UID enable        | [7:1] |            | Reserved
                        | ^                        | [0]   |  0x00      | Use UID stored in EEPROM
                        | ^                        | ^     |  0x01      | Randomly generate the UID in which the first byte is fixed and the remaining 3 bytes are random A new random number is generated after each RF-OFF to RF-ON.
                        */
}PN76_AUTOCOLL_CFG_t;

/**
 * @brief LPCD settings configuration
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t avg_samples[1]; /**< Number of samples used for averaging
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | Random UID enable        | [7:3] |            | Reserved
                        | LPCD_AVG_SAMPLES         | [2:0] |            | Defines how many samples of the I & Q values are used for the averaging. Average samples in power of 2.
                        | ^                        | ^     |  0x00      | 1 sample
                        | ^                        | ^     |  0x01      | 2 samples
                        | ^                        | ^     |  0x02      | 4 samples
                        | ^                        | ^     |  0x03      | 8 samples
                        | ^                        | ^     |  0x04      | 16 samples
                        | ^                        | ^     |  0x05      | 32 samples
                        | ^                        | ^     |  0x06      | 64 samples
                        | ^                        | ^     |  0x07      | RFU
                        */
   uint8_t bDebugDataSize[1]; /**< Reserved. Do not modify */
   uint8_t lpcd_rssi_target[2]; /**<  Value to be set in register DGRM_RSSI_REG_DGRM_RSSI_TARGET.
                                       Typically the same values from the Type A106 LOAD_RF_CONFIGURATION API (DGRM_RSSI register) are used */
   uint8_t lpcd_rssi_hyst[1]; /**< Value to be set in CLIF_DGRM_RSSI_REG_DGRM_RSSI_HYST
                                       Typically the same values from the Type A106 LOAD_RF_CONFIGURATION API  (DGRM_RSSI register) are used */
   uint8_t wConfig[2]; /**< Number of samples used for averaging
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RFU                      | [15:6]|            | Reserved
                        | LPCD_CONFIG              | [5]   |  0x00      | Disables feature Immediate RF OFF before TXLDO shutdown to save power
                        | ^                        | ^     |  0x01      | Enables feature Immediate RF OFF before TXLDO shutdown to save power. For this feature, Enable VDDPA fast discharge must be enabled.
                        | ^                        | [4]   |  0x00      | Disables VDDPA fast discharge.
                        | ^                        | ^     |  0x01      | Enable VDDPA fast discharge.
                        | ^                        | [3]   |  0x00      | Enable single driver
                        | ^                        | ^     |  0x01      | Enable both drivers
                        | ^                        | [2:0] |            | Acquisition channels
                        | ^                        | ^     |  0x00-0x01 | RFU
                        | ^                        | ^     |  0x02      | Magnitude
                        | ^                        | ^     |  0x03      | I and Q
                        | ^                        | ^     |  0x04      | M, I and Q
                        | ^                        | ^     |  0x05-0x07 | RFU
                        */
   uint8_t bPwrOptCfg[1]; /**< Reserved. Do not modify */
   uint8_t lpcd_threshold_coarse[4];  /**< LPCD threshold type depends upon the \ref PN76_LPCD_SETTINGS_t.wConfig[2:0] value.\n
                                          For 'I and Q' mode:  1st threshold = I ch; 2nd threshold = Q ch

                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | LPCD Q channel threshold |[31:16]|            | ADC LSB granularity of threshold depends of avg_samples_meas value:
                        | ^                        | ^     |  0x00      | unit 1
                        | ^                        | ^     |  0x01      | unit 1/2
                        | ^                        | ^     |  0x02      | unit 1/4
                        | ^                        | ^     |  0x03      | unit 1/8
                        | ^                        | ^     |  0x04      | unit 1/16
                        | ^                        | ^     |  0x05      | unit 1/32
                        | ^                        | ^     |  Other     | Reserved
                        | LPCD I channel threshold | [15:0]|            | ADC LSB granularity of threshold depends of avg_samples_meas value:
                        | ^                        | ^     |  0x00      | unit 1
                        | ^                        | ^     |  0x01      | unit 1/2
                        | ^                        | ^     |  0x02      | unit 1/4
                        | ^                        | ^     |  0x03      | unit 1/8
                        | ^                        | ^     |  0x04      | unit 1/16
                        | ^                        | ^     |  0x05      | unit 1/32
                        | ^                        | ^     |  Other     | Reserved

                        \note If the difference between the measured value and the reference is greater than the threshold on either channels, then a card is detected.
                        */

   uint8_t lpcd_threshold_fine[4]; /**< Reserved. Do not modify */
   uint8_t lpcd_threshold_switch_det[4]; /**< Reserved. Do not modify */
   uint8_t bSuppressWkupThreshold[1]; /**< Reserved. Do not modify */
   uint8_t wWaitDgrm_ref[2]; /**< Reserved. Do not modify */
   uint8_t wDelayCheckSwitch[2]; /**< Reserved. Do not modify */
   uint8_t wWaitRxSettle[2]; /**< Delay between FieldOn and starting ADC data averaging.

                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | LPCD DELAY               |[15:0] |            | Delay between FieldOn and starting ADC data averaging. Value in us, default 14h = 20us
                        */
   uint8_t wDelayRefMeas[2]; /**< Reserved. Do not modify */
   uint8_t bTxLdoVddpa[1]; /**< VDDPA voltage when DCDC (internal or external) or external power source is used to feed TXLDO.

                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | VDDPA voltage LPCD DELAY |[7:0]  |            | TXLDO output voltage.
                        | ^                        | ^     |  0x00-0x2A | resultant voltage would be: 1V50 + this value * 0.10)
                        | ^                        | ^     |  Others    | Reserved
                        */
   uint8_t wCheckPeriod[2]; /**< Timer value defining standby duration before calibration and reference measurement in LPCD single mode(Mode 4)

                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | LPCD DELAY               |[15:0] |            | 2.63ms resolution, default 0x26 = ~100ms
                        */
   uint8_t bBoostDelayToOn[1]; /**< Reserved. Do not modify */
   uint8_t bDoubleDetectionTresholdCount[1]; /**< Reserved. Do not modify */
   uint8_t bReferenceTrackingFreezeCount[1]; /**< Reserved. Do not modify */
   uint8_t bBoostPhaseDelay[1]; /**< Reserved. Do not modify */
   uint8_t bRFU[7]; /**< Reserved. Do not modify */
}PN76_LPCD_SETTINGS_t;


/**
 * @brief DAC down sampling divisor settings used in analog TestBus
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dac_sample_div[1];  /**< DAC down sampling divisor settings used in analog TestBus
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | CONFIGURE_ANALOG_TB      | [7:4]|            |  DAC1 sample Div
                        | ^                        | [3:0] |            |  DAC0 sample Div
                        */
}PN76_ANA_TB_SETTINGS_t;

/**
 * @brief Internal ULPCD settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t Trims[2]; /**< Reserved. Do not modify */
}PN76_ULPCD_CONFIG_INT_t;

/**
 * @brief Internal TRIM settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wNFCLD_Offset_Trim[2]; /**< Reserved. Do not modify */
   uint8_t wNFCLD_Gain_Trim[2]; /**< Reserved. Do not modify */
   uint8_t wRFLD_Offset_Trim[2]; /**< Reserved. Do not modify */
   uint8_t wRFLD_Gain_Trim[2]; /**< Reserved. Do not modify */
   uint8_t wRSSI_Offset_Trim[2]; /**< Reserved. Do not modify */
   uint8_t wRSSI_Gain_Trim[2]; /**< Reserved. Do not modify */
   uint8_t bCustTrimFlags[1]; /**< Reserved. Do not modify */
   uint8_t wCustTrimAlgo[2]; /**< Reserved. Do not modify */
   uint8_t RFU[10]; /**< Reserved. Do not modify */
   uint8_t dwInitialRfldAndNfcld[4]; /**< Reserved. Do not modify */
}PN76_TRIM_CUST_t;

/**
 * @brief Internal TRIM settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wCustomerPhaseOffset[2]; /**< Reserved. Do not modify */
}PN76_TRIM_CUST_EXT_t;

/**
 * @brief TX wave shaping for proprietary correction configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t sCorrection_Entry0[2]; /**< The correction that is applied when TX Proprietary shaping with scaling is enabled.
                                       sCorrection_Entry0 corresponds to correction applied at VDDPA = 1V5.
                                       sCorrection_Entry42 corresponds to correction applied at VDDPA = 5V7.
                                       Range would be -128 to +127.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | PROP_CORRECTION_ENTRY    | [15:8]|            |  Correction applied for ASK10
                        | ^                        | [7:0] |            |  Correction applied for ASK100
                        */
   uint8_t sCorrection_Entry1[2]; /**< Entry for VDDPA = 1V6. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry2[2]; /**< Entry for VDDPA = 1V7. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry3[2]; /**< Entry for VDDPA = 1V8. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry4[2]; /**< Entry for VDDPA = 1V9. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry5[2]; /**< Entry for VDDPA = 2V0. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry6[2]; /**< Entry for VDDPA = 2V1. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry7[2]; /**< Entry for VDDPA = 2V2. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry8[2]; /**< Entry for VDDPA = 2V3. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry9[2]; /**< Entry for VDDPA = 2V4. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry10[2]; /**< Entry for VDDPA = 2V5. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry11[2]; /**< Entry for VDDPA = 2V6. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry12[2]; /**< Entry for VDDPA = 2V7. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry13[2]; /**< Entry for VDDPA = 2V8. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry14[2]; /**< Entry for VDDPA = 2V9. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry15[2]; /**< Entry for VDDPA = 3V0. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry16[2]; /**< Entry for VDDPA = 3V1. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry17[2]; /**< Entry for VDDPA = 3V2. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry18[2]; /**< Entry for VDDPA = 3V3. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry19[2]; /**< Entry for VDDPA = 3V4. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry20[2]; /**< Entry for VDDPA = 3V5. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry21[2]; /**< Entry for VDDPA = 3V6. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry22[2]; /**< Entry for VDDPA = 3V7. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry23[2]; /**< Entry for VDDPA = 3V8. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry24[2]; /**< Entry for VDDPA = 3V9. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry25[2]; /**< Entry for VDDPA = 4V0. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry26[2]; /**< Entry for VDDPA = 4V1. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry27[2]; /**< Entry for VDDPA = 4V2. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry28[2]; /**< Entry for VDDPA = 4V3. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry29[2]; /**< Entry for VDDPA = 4V4. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry30[2]; /**< Entry for VDDPA = 4V5. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry31[2]; /**< Entry for VDDPA = 4V6. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry32[2]; /**< Entry for VDDPA = 4V7. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry33[2]; /**< Entry for VDDPA = 4V8. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry34[2]; /**< Entry for VDDPA = 4V9. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry35[2]; /**< Entry for VDDPA = 5V0. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry36[2]; /**< Entry for VDDPA = 5V1. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry37[2]; /**< Entry for VDDPA = 5V2. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry38[2]; /**< Entry for VDDPA = 5V3. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry39[2]; /**< Entry for VDDPA = 5V4. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry40[2]; /**< Entry for VDDPA = 5V5. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry41[2]; /**< Entry for VDDPA = 5V6. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
   uint8_t sCorrection_Entry42[2]; /**< Entry for VDDPA = 5V7. Refer to PN76_TX_SHAPING_PROPRIETARY_CORR_t.sCorrection_Entry0 */
}PN76_TX_SHAPING_PROPRIETARY_CORR_t;


/**
 * @brief TX wave shaping for proprietary correction configuration for rising edge and falling edges.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t RTRANS0[4];  /**< The rising Transition register values loaded when Proprietary TX Shaping configuration is set in the RM_TECHNO_TX_SHAPING table
                              to use proprietary TX shaping.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | RTRANS                   | [31:0]|            |  These values apply in case EDGE_STYLE = 0 is configured for the rising edge
                        */
   uint8_t RTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t FTRANS0[4]; /**< The falling Transition register values loaded when Proprietary TX Shaping configuration is set in the RM_TECHNO_TX_SHAPING table
                              to use proprietary TX shaping.
                        |Function                  | bits  |  Values    | Description
                        |-------------------------:|:-----:|:----------:|:--------------------------
                        | FTRANS                   | [31:0]|            |  These values apply in case EDGE_STYLE = 0 is configured for the rising edge
                        */
   uint8_t FTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
}PN76_TX_SHAPING_PROPRIETARY_1_t;

/**
 * @brief TX wave shaping for proprietary correction configuration for rising edge and falling edges.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t RTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t FTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
}PN76_TX_SHAPING_PROPRIETARY_2_t;

/**
 * @brief TX wave shaping for proprietary correction configuration for rising edge and falling edges.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t RTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t FTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
}PN76_TX_SHAPING_PROPRIETARY_3_t;

/**
 * @brief TX wave shaping for proprietary correction configuration for rising edge and falling edges.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t RTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t RTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.RTRANS0 */
   uint8_t FTRANS0[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS1[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS2[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
   uint8_t FTRANS3[4]; /**< Refer to PN76_TX_SHAPING_PROPRIETARY_1_t.FTRANS0 */
}PN76_TX_SHAPING_PROPRIETARY_4_t;

/**
 * @brief TX driver NOV (non-overlap) settings configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t CfgNovCal[1]; /**< NOV calibration type
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:2]  |            | Reserved
                        | NOV_CALIBRATION_TYPE     | [1:0]  |  0x00      | No calibration performed, needs to be updated to 01 or 10 before the first RF on of the chip is performed.
                        | ^                        | ^      |  0x01      | Enable FW calibration after every cold boot.
                        | ^                        | ^      |  0x02      | Use calibration value coming from EEPROM NOV_CAL_VAL1, NOV_CAL_VAL2 \b(Default)
                        | ^                        | ^      |  0x03      | RFU
                        */
   uint8_t VddpaCalVal1[1]; /**< It defines the VDDPA value that FW will use to perform NOV calibration group#1
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | VDDPACALVAL1             | [7:0]  |  0x03      | (1.8 V)
                        | ^                        | ^      |  0x0D      | (2.8V)

                        \note See \ref PN76_USER_PMU_t.TxLdoVddpaMaxRdr or \ref PN76_USER_PMU_t.TxLdoVddpaMaxCard for list of voltage levels.
                        */

   uint8_t VddpaCalVal2[1]; /**< It defines the VDDPA value that FW will use to perform NOV calibration group#2
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | VDDPACALVAL2             | [7:0]  |  0x15      | (3.6 V)
                        | ^                        | ^      |  0x24      | (5.1V)

                        \note See \ref PN76_USER_PMU_t.TxLdoVddpaMaxRdr or \ref PN76_USER_PMU_t.TxLdoVddpaMaxCard for list of voltage levels.
                        */
   uint8_t CfgThreshold[1]; /**< It defines VDDPA threshold that FW will use to select Group#1 or Group#2 NOV offset values
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | VDDPACALVAL2             | [7:0]  |  0x08      | (2.3 V)
                        | ^                        | ^      |  0x16      | (3.7V)

                        \note See \ref PN76_USER_PMU_t.TxLdoVddpaMaxRdr or \ref PN76_USER_PMU_t.TxLdoVddpaMaxCard for list of voltage levels.
                        */

   uint8_t UserOffsets1[4]; /**< It defines user static offsets applied if \ref PN76_TX_DRIVER_NOV_t.CfgNovCal [1:0] = 0x02
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [31:29]|            | Reserved
                        | VDDAPA MIN               | [28:24]|            | Group#1 (VDDPA min to CfgThreshold), offset_2l<1>
                        | ^                        | [23:21]|            | Reserved
                        | ^                        | [20:16]|            | Group#1 (VDDPA min to CfgThreshold), offset_2l<0>
                        | ^                        | [15:13]|            | Reserved
                        | ^                        | [12:08]|            | Group#1 (VDDPA min to CfgThreshold), offset_3l_p2
                        | ^                        | [07:05]|            | Reserved
                        | ^                        | [04:00]|            | Group#1 (VDDPA min to CfgThreshold), offset_3l
                        \note See \ref PN76_USER_PMU_t.TxLdoVddpaMaxRdr or \ref PN76_USER_PMU_t.TxLdoVddpaMaxCard for list of voltage levels.
                        */

   uint8_t UserOffsets2[4]; /**< It defines user static offsets applied if \ref PN76_TX_DRIVER_NOV_t.CfgNovCal [1:0] = 0x02
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [31:29]|            | Reserved
                        | VDDAPA MAX               | [28:24]|            | Group#1 (VDDPA max to CfgThreshold), offset_2l<1>
                        | ^                        | [23:21]|            | Reserved
                        | ^                        | [20:16]|            | Group#1 (VDDPA max to CfgThreshold), offset_2l<0>
                        | ^                        | [15:13]|            | Reserved
                        | ^                        | [12:08]|            | Group#1 (VDDPA max to CfgThreshold), offset_3l_p2
                        | ^                        | [07:05]|            | Reserved
                        | ^                        | [04:00]|            | Group#1 (VDDPA max to CfgThreshold), offset_3l
                        \note See \ref PN76_USER_PMU_t.TxLdoVddpaMaxRdr or \ref PN76_USER_PMU_t.TxLdoVddpaMaxCard for list of voltage levels.
                        */
}PN76_TX_DRIVER_NOV_t;

/**
 * @brief Fast VDDPA discharge configuration for PMU.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bEnableFastVDDPADischarge[1]; /**< enable/disable fast VDDPA Discharge
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:1]  |            | Reserved
                        | EnableFast VDDPADischarge| [0]    |  0x00      | Disables fast discharge of VDDPA by setting VDDPA=5.7 and then to 1.5 V, during RF OFF
                        | ^                        | ^      |  0x01      | Enables fast discharge of VDDPA by setting VDDPA=5.7 and then to 1.5 V, during RF OFF (default)
                        */
}PN76_USER_PMU_INT_1_t;

/**
 * @brief Reader mode technology TX wave shaping during active mode of operation
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bResidualAmplitudeLevel_Active_A106[1]; /**< Active mode TypeA-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_Active_A106[1]; /**< Active mode TypeA-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_Active_A106[1]; /**< Active mode TypeA-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_Active_A106[1]; /**< Active mode TypeA-106kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_Active_F212[1]; /**< Active mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_Active_F212[1]; /**< Active mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_Active_F212[1]; /**< Active mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_Active_F212[1]; /**< Active mode TypeF-212kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
   uint8_t bResidualAmplitudeLevel_Active_F424[1]; /**< Active mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bResidualAmplitudeLevel_A106 */
   uint8_t bEdgeType_Active_F424[1]; /**< Active mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeType_A106 */
   uint8_t bEdgeStyleConfiguration_Active_F424[1]; /**< Active mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeStyleConfiguration_A106 */
   uint8_t bEdgeLength_Active_F424[1]; /**< Active mode TypeF-424kbps configuration. See \ref PN76_RM_TECHNO_TX_SHAPING_t.bEdgeLength_A106 */
}PN76_RM_TECHNO_ACTIVE_TX_SHAPING_t;

/**
 * @brief Internal PMU settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bVboost_VbatReadDelay[1]; /**< Reserved. Do not modify */
}PN76_PMU_BOOST_DELAY_t;

/**
 * @brief Reader mode ARC settings to be applied during FDT for A106.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wRmArcA_106_FDT[10]; /**< PWM scheme for RM
                        |Function                  | bytes  |  bits    |  Values    | Description
                        |-------------------------:|:------:|:--------:|:--------------------------
                        | RM_RX_ARC_FDT_0          | [1:0]  |          |            | Settings for RM_RX_ARC_FDT_0.
                        | ^                        | ^      | [15]     |  0x00      | ARC settings apply always
                        | ^                        | ^      | ^        |  0x01      | ARC settings applicable during FDT
                        | ^                        | ^      | [14]     |  0x00      | ARC Disabled for this Tech and Baudrate
                        | ^                        | ^      | ^        |  0x01      | ARC Enabled for this Tech and Baudrate
                        | ^                        | ^      | ^        |  NOTE      | This bit is RFU for RM_RX_ARC_FDT_1, RM_RX_ARC_FDT_2, RM_RX_ARC_FDT_3, RM_RX_ARC_FDT_4.
                        | ^                        | ^      | [13:10]  |            | RFU. Reserved.
                        | ^                        | ^      | [9]      |            | Enable the IIR filter.
                        | ^                        | ^      | [8:7]    |            | MF_GAIN (ths value will be applied to the SIGPR_RM_TECH register, applies as soon as the ARC is enabled)
                        | ^                        | ^      | [6:0]    |            | DPC_ SIGNAL_DETECT_TH_OVR_VAL (this value will be applied to the DGRM_RSSI register, applies as soon as the ARC is enabled)
                        | RM_RX_ARC_FDT_1          | [3:2]  |          |            | Settings for RM_RX_ARC_FDT_1. Bit definitions is same as that of RM_RX_ARC_FDT_0
                        | RM_RX_ARC_FDT_2          | [5:4]  |          |            | Settings for RM_RX_ARC_FDT_2. Bit definitions is same as that of RM_RX_ARC_FDT_0
                        | RM_RX_ARC_FDT_3          | [7:6]  |          |            | Settings for RM_RX_ARC_FDT_3. Bit definitions is same as that of RM_RX_ARC_FDT_0
                        | RM_RX_ARC_FDT_4          | [9:8]  |          |            | Settings for RM_RX_ARC_FDT_4. Bit definitions is same as that of RM_RX_ARC_FDT_0


                        \note For ISO14443-A: In case ARC is disabled, it requires DPC_SIGNAL_DETECT_TH_OVR_VAL larger than 0x50 (with MF_GAIN = 2 (default))
                        \note For ISO14443-A: In case Bit[15] is configured to 0, it requires DPC_SIGNAL_DETECT_TH_OVR_VAL larger than 0x50 (with MF_GAIN = 2 (default)) if the ARC is enabled.
                        */
}PN76_ARC_SETTINGS_1_t;

/**
 * @brief Internal card emulation settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwDPLL_INIT_ActiveInitiator[4]; /**< Reserved. Do not modify */
   uint8_t dwDPLL_GEAR_ActiveInitiator[4]; /**< Reserved. Do not modify */
}PN76_RF_CLOCK_ACTIVE_DPLL_COM_t;

/**
 * @brief Internal VDDPA settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bVddpaAdjustmentEnable[1]; /**< Reserved. Do not modify */
   uint8_t bVddpaAdjustmentMax[1]; /**< Reserved. Do not modify */
   uint8_t bVddpaLoadAdjustment[1]; /**< Reserved. Do not modify */
}PN76_VDDPA_ADJUSTMENT_t;

/**
 * @brief Settings related to NFCLD and RFLD. For Card Mode Dynamic LMA settings.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wMeasuredInterpolatedRSSI[2]; /**< Measured Interpolated RSSI (16 bit, in little-endian format). Each count indicates a value of 1/2048 mV. */
   uint8_t bMeasuredFieldStrength[1]; /**< Field strength (8 bits, 1/16 A/m LSB) used for bMeasuredLMA and wMeasuredInterpolatedRSSI */
}PN76_MEASURED_LMA_RSSI_t;

/**
 * @brief Internal NFCLD/RFLD settings.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wNFCLD_lvl[2]; /**< Reserved. Do not modify */
   uint8_t bNFCLDOff_Ratio[1]; /**< Reserved. Do not modify */
   uint8_t wLPDET_lvl[2]; /**< Reserved. Do not modify */
}PN76_RX_CTRL_t;

/**
 * @brief CLIF related registers values to be loaded for ISO15693 technology and for different baud-rates, used internally.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwTx_Symbol23_Mod_Reg_BR_53[4]; /**< Reserved. Do not modify */
   uint8_t dwTx_Data_Mod_Reg_BR_53[4]; /**< Reserved. Do not modify */
   uint8_t dwTx_Symbol23_Mod_Reg_BR_106[4]; /**< Reserved. Do not modify */
   uint8_t dwTx_Data_Mod_Reg_BR_106[4]; /**< Reserved. Do not modify */
   uint8_t dwTx_Symbol23_Mod_Reg_BR_212[4]; /**< Reserved. Do not modify */
   uint8_t dwTx_Data_Mod_Reg_BR_212[4]; /**< Reserved. Do not modify */
}PN76_15693_BR_CFG_t;

/**
 * @brief Derivation message to consider for generation of encryption or decryption for Master keys
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t abCustEncrDecrDerivMsg[24]; /**< Derivation message for encryption/decryption for Master Keys for interfacing with Mbed */
}PN76_SKM_EncrDecrDerMsg_t;

/**
 * @brief Derivation message to generate encrption/decryption keys to encrypt/decrypt the asymmetric private keys.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t adwDerivMsgEncDecKeyForAsym[24]; /**< Derivation message for encrypting/decrypting the storing/retrieving of Asymm private key */
}PN76_SKM_Asym_KeyDerMsg_t;

/**
 * @brief Internal PMU settings. Do not modify.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t VenMonitorConfig[2]; /**< Reserved. Do not modify */
   uint8_t IrqEdgeSelection[2]; /**< Reserved. Do not modify */
   uint8_t aBoostDelayOverVbatLUT[6]; /**< Reserved. Do not modify */
   uint8_t wOvercurrentMaskTime[2]; /**< Reserved. Do not modify */
}PN76_USER_PMU_S_ROM_Ext_t;

/**
 * @brief TX_SHAPING configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bConfig[1]; /**< PWM scheme for RM
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:1]  |            | Reserved
                        | PWM scheme for RM        | [0]    |  0x00      | defining 3-levels for drivers TX1/2 - required for balanced antenna (default)
                        | ^                        | ^      |  0x01      | defining 2-levels for drivers TX1/2 - required for single ended antenna

                        \note This value is written into CLIF_ANACTROL_TX_CONFIG_REG during Load protocol
                        */

   uint8_t bTX_INV_RM[1]; /**< Transmitter configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:6]  |            | Reserved
                        | TX1 output configuration | [5]    |  0x00      | TX1 non-inverted output (output zero remains zero)
                        | ^                        | ^      |  0x01      | TX1 inverted output (common mode operation, output zero becomes one)
                        | TX2 output configuration | [4]    |  0x00      | TX2 non-inverted output (output zero remains zero)
                        | ^                        | ^      |  0x01      | TX2 inverted output (common mode operation, output zero becomes one)
                        | RFU                      | [3:2]  |            | Reserved
                        | TX1 phase shift configuration | [1]    |  0x00      | TX1 no phase shift, 0 deg
                        | ^                        | ^      |  0x01      | TX1 phase shifted by 180 deg
                        | TX2 phase shift configuration | [0]    |  0x00      | TX2 no phase shift, 0 deg
                        | ^                        | ^      |  0x01      | TX2 phase shifted by 180 deg

                        \note This value is written into CLIF_ANACTROL_TX_CONFIG_REG during Load protocol
                        */
   uint8_t bCLK_MODE_1[1]; /**< Transmitter configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7]    |            | Reserved
                        | CLK_MODE_CW_RM           | [6:4]  |            | CLK_MODE_CW_RM
                        | RFU                      | [3]    |            | Reserved
                        | CLK_MODE_MOD_RM          | [2:0]  |            | CLK_MODE_MOD_RM

                        */

   uint8_t bCLK_MODE_2[1]; /**< CLK_MODE configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7]    |            | Reserved
                        | CLK_MODE_DEFAULT         | [6:4]  |            | CLK_MODE_DEFAULT
                        | RFU                      | [3]    |            | Reserved
                        | CLK_MODE_TRANS_RM        | [2:0]  |            | CLK_MODE_TRANS_RM

                        */
   uint8_t bGSN_MOD_RM[1]; /**< GSN_MOD_RM configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:5]  |            | Reserved
                        | GSN_MOD_RM               | [4:0]  |            | GSN_MOD_RM

                        */
   uint8_t bGSN_CW_RM[1]; /**< GSN_CW_RM configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:5]  |            | Reserved
                        | GSN_CW_RM                | [4:0]  |            | GSN_CW_RM

                        */
   uint8_t bGSP_RM[1]; /**< GSP_RM configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:5]  |            | Reserved
                        | GSP_RM                   | [4:0]  |            | GSP_RM

                        */
   uint8_t bTX_FRCZERO_THR[1]; /**< CLIF_SS_TX_CFG_REG configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7]    |            | Reserved
                        | CLIF_SS_TX_CFG_REG       | [6:0]  |            | Defining CLIF_SS_TX_CFG_REG<12:6>

                        */

   uint8_t bSignalScalingConfig[1]; /**< Global TX_SS_TARGET_SCALE configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | Global TX_SS_TARGET_SCALE| [7:0]  |            | Global TX_SS_TARGET_SCALE configuration for debugging purposes

                        */
   /* Bits[7:0] = Global CLIF_ANACTRL_TX_CONFIG_REG configuration */
   uint8_t bTX_PH_SHIFT_DIV10[1]; /**< Global TX_SS_TARGET_SCALE configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:5]  |            | Reserved
                        |CLIF_ANACTRL_TX_CONFIG_REG| [4:0]  |            | CLIF_ANACTRL_TX_CONFIG_REG.TX_PH_SHIFT_DIV10

                        */

   uint8_t bTX_PH_SHIFT_MOD10[1]; /**< Global CLIF_ANACTRL_TX_CONFIG_REG.TX_PH_SHIFT_MOD10 configuration
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:4]  |            | Reserved
                        |CLIF_ANACTRL_TX_CONFIG_REG.TX_PH_SHIFT_MOD10| [3:0]  |            | CLIF_ANACTRL_TX_CONFIG_REG.TX_PH_SHIFT_MOD10

                        */

}PN76_RM_GLOBAL_TX_SHAPING_t;

/**
 * @brief Internal NFCLD settings. Do not modify, if unsure of the feature.
 * @note Do not modify, if unsure of the feature.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwNFCLD_OnOffThreshold[4]; /**< NFCLD_ON_OFF_THRESHOLD
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | NFCLD_ON_OFF_THRESHOLD   | [31:16]|            | RF Field OFF Threshold
                        | ^                        | [15:0] |            | RF Field ON Threshold

                        \note Value can be overwritten if writing tags A098, A09E or A01F (depends on feature controls: NFCLD interpolation, APC/RX enhancements)
                        */
   uint8_t dwNFCLD_OnOffMaskTime[4]; /**< NFCLD_ON_OFF_MASKTIME
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [31:20]|            | Reserved.
                        | NFCLD_ON_OFF_MASKTIME    | [19:15]|            | Masking time OFF = 10us
                        | ^                        | [14:0] |            | Masking time ON = 300us
                        */
   uint8_t dwNFCLD_P2P_ACTIVE_OnOffMaskTime[4]; /**< Reserved. Do not modify */
   uint8_t wLPDET_OnThreshold_Interpolated[2]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_AnaCtrl_Wkup[4]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_FsmCtrl1_Wkup[4]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_FsmCtrl2_Wkup[4]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_AnaCtrl_Collision[4]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_FsmCtrl1_Collision[4]; /**< Reserved. Do not modify */
   uint8_t dwLPDET_FsmCtrl2_Collision[4]; /**< Reserved. Do not modify */
   uint8_t wRecoveryClockCheck[2]; /**< Reserved. Do not modify */
}PN76_EXT_RF_DETECTION_HW_t;

/**
 * @brief External RF detection input configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wNFCLD_OnThreshold[2]; /**<  RF Field ON Threshold; Code resolution: (1/2048) Vpp @ Vrrsi
                                       \note value can be overwritten if writing tags A098 or A09E (depends on feature controls: APC/RX enhancements)  */
   uint8_t wNFCLD_OffThreshold[2]; /**<   RF Field OFF Threshold; Code resolution: (1/2048) Vpp @ Vrrsi
                                       \note value can be overwritten if writing tags A098 or A09E (depends on feature controls: APC/RX enhancements)  */
   uint8_t wLPDET_OnThreshold[2]; /**<  Code Resolution (1/2048)Vpp at Vrssi 14 = 10mVpp
                                       \note value can be overwritten if writing tags A098 or A09E (depends on feature controls: APC/RX enhancements)  */
   uint8_t wNFCLD_RFLD_Valid_Bit[1]; /**< bit[0] is set to 1 then the NFCLD Threshold is a valid data and calibration wont be done gain till this bit is cleared and POR is issued.
                                       bit[1] is set to 1 then the RFLD Threshold is a valid data and calibration wont be done gain till this bit is cleared and POR is issued. */
   uint8_t Dummy[1]; /**< Reserved for later use. Do not remove. Used to keep alignment. */
}PN76_EXT_RF_DETECT_INT_INPUT_t;

/**
 * @brief Internal SMU settings. Do not modify.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wRxProtConfig[2]; /**< Reserved. Do not modify */
   uint8_t dwTxStdbyConfig[4]; /**< Reserved. Do not modify */
}PN76_USER_SMU_S_t;

/**
 * @brief GPADC configuration. Do not modify. Use the APIs provided to access the GPADC peripheral.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwAdcInCtrl0[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl0[4];  /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl1[4];   /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl1[4];  /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl2[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl2[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl3[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl3[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl4[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl4[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl5[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl5[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl6[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl6[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl7[4]; /**< Reserved. Do not modify */
   uint8_t dwFilterCtrl7[4]; /**< Reserved. Do not modify */
   uint8_t bGpadcSrcSel[1];  /**< Reserved. Do not modify */
}PN76_GPADC_CONFIG_t;

/**
 * @brief GPADC configuration. Do not modify. Use the APIs provided to access the GPADC peripheral.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwAdcInCtrl0[4];  /**< Reserved. Do not modify */
}PN76_GPADC_CONFIG_S_t;

/**
 * @brief GPADC configuration. Do not modify. Use the APIs provided to access the GPADC peripheral.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwAdcInCtrl0[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl1[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl2[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl3[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl4[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl5[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl6[4]; /**< Reserved. Do not modify */
   uint8_t dwAdcInCtrl7[4]; /**< Reserved. Do not modify */
}PN76_GPADC_CONFIG_2_t;

/**
 * @brief GPADC configuration. Do not modify. Use the APIs provided to access the GPADC peripheral.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t dwAdcInCtrl0[4];/**< Reserved. Do not modify */
}PN76_GPADC_CONFIG_S_2_t;

/**
 * @brief ULPCD configuration
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t Xtal_Ctrl[2]; /**< Reserved. Do not modify */
   uint8_t Vddpa_Ctrl[2];   /**< VDDPA control during ULPCD
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [15:9] |            | Reserved
                        | VDDPA control            | [8:3]  |            | TXLDO output voltage during ULPCD polling. Value 0x00 --> 1V50, 0x01 --> 1V60.. with 0.10 voltage increment till value of 0x2A --> 5V70.
                        | RFU                      | [2:0]  |            | Reserved
                        */
   uint8_t Agc_Hfatt_Ctrl[1]; /**< The value to be used during ULPCD. This value must be set to a value read from \ref CLIF_RXCTRL_STATUS register during ULPCD calibration process. */
   uint8_t Timing_Ctrl[1];   /**< ULPCD timing control
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFON_GUARD_TIME          | [7:4]  |            | RFON guard time: (RFON_GUARD_TIME + 2) * LFO-Freq (380 kHz) Guard time: Time between RF-ON and first sampling of data
                        | RFU                      | [3:0]  |            | Reserved
                        */
   uint8_t Tx_Set_Gs_Pn_Tx12[1]; /**< Reserved. Do not modify */
   uint8_t Voltage_Ctrl[1];   /**< ULPCD voltage control
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:2]  |            | Reserved
                        | TX_SUPPLY by VUP_TX      | [1]    |  0x00      | VUP externally supplied (2.8 V to 6.0 V)
                        | ^                        | ^      |  0x01      | VUP supplied by PN7642 itself (pin VUP_TX connected to VBAT/VBATPWR)
                        | RFU                      | [0]    |            | Reserved
                        */
   uint8_t Gpadc_Crl[2]; /**< Reserved. Do not modify */
}PN76_ULPCD_CONFIG_t;

/**
 * @brief ULPCD settings
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t brssi_nsp[1]; /**< Number of RSSI Samples which are internally averaged:
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7]   |            | Reserved
                        | ULPCD RSSI sampling guard time   | [6:0]  |        | This is the time between consecutive RSSI samples.

                        \note Range - 0 - 127 micro seconds The GPADC RSSI acquisition time can be calculated with T= (ROUNDS * (brssi_nsp + 30 + 3.5) + 11.5 ) * Tclkgpadc
                        */
   uint8_t brssi_no_samples[1];   /**< Number of RSSI Samples which are internally averaged:
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:2]  |            | Reserved
                        | number of RSSI Samples   | [1:0]  |  0x00      | 4 rounds
                        | ^                        | ^      |  0x01      | 8 rounds
                        | ^                        | ^      |  0x02      | 16 rounds
                        | ^                        | ^      |  0x03      | 32 rounds
                        */
   uint8_t bthresh_lvl[1];   /**< RSSI Threshold level.
                        \note If the difference between the measured RSSI value and the reference (which is derived during calibration) is greater than the threshold, then a card is detected.
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:5]  |            | Reserved
                        | RSSI Threshold level     | [4:0]  |            | 0 - 31
                        */
   uint8_t bpolarity[1];  /**< GPIO3 abort polarity configuration
                        \note If PN7642 is using the ULPCD, GPIO3 cannot be used for any other purpose than aborting the ULPCD.

                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:1]  |            | Reserved
                        | RSSI Threshold level     | [0]    |  0x00      | low-level aborts ULPCD
                        | ^                        | ^      |  0x01      | high-level aborts ULPCD
                        */
}PN76_ULPCD_SETTINGS_t;

/**
 * @brief Internal PMU settings. Do not modify.
 * @note Do not modify.
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t VbatMonitorConfig[2]; /**< Reserved. Do not modify */
   uint8_t VbatMonitorConfigForStandby[2]; /**< Reserved. Do not modify */
}PN76_USER_PMU_S_t;

/**
 * @brief SMU configuration for temperature warning
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bTempWarning[1];   /**< CLIF & PMU temperature warning
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | PMU high threshold       | [7:6]  |  0x00      | Disabled
                        | ^                        | ^      |  0x01      | 114 degC
                        | ^                        | ^      |  0x02      | 125 degC
                        | ^                        | ^      |  0x03      | 130 degC
                        | PMU low threshold        | [5:4]  |  0x00      | Disabled
                        | ^                        | ^      |  0x01      | 114 degC
                        | ^                        | ^      |  0x02      | 125 degC
                        | ^                        | ^      |  0x03      | 130 degC
                        | CLIF high threshold      | [3:2]  |  0x00      | Disabled
                        | ^                        | ^      |  0x01      | 114 degC
                        | ^                        | ^      |  0x02      | 125 degC
                        | ^                        | ^      |  0x03      | 130 degC
                        | CLIF low threshold       | [1:0]  |  0x00      | Disabled
                        | ^                        | ^      |  0x01      | 114 degC
                        | ^                        | ^      |  0x02      | 125 degC
                        | ^                        | ^      |  0x03      | 130 degC
                        */
   uint8_t bEnableGpio0OnOverTemp[1];   /**< Enable over temperature indication through GPIO0
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7:1]  |            | Reserved
                        | Gpio0 temp indication    | [0]    |  0x00      | temperature event indication through GPIO0 is disabled.
                        | ^                        | ^      |  0x01      | temperature event indication through GPIO0 is enabled.
                        */
}PN76_USER_SMU_CONFIG_t;

/**
 * @brief USB download configuration.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bUsbDL_Disabled[1];   /**< USB Download Disable Status
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | USB download disable status   | [7:0]    |  0x96   | USB download is disabled
                        | ^                        | ^      |  other values  | USB download is enabled
                        */
   uint8_t USBDesc_PID[2]; /**< PN76XX Product ID 0x0149 */
   uint8_t USBDesc_VID[2]; /**< NXP Vendor ID - 0x1FC9 */
   uint8_t MfrStr_Len[1]; /**< Length of Manufacturer String */
   uint8_t MfrString[16]; /**< Manufacturer String */
   uint8_t ProductStr_Len[1]; /**< Length of Product String */
   uint8_t ProductString[16]; /**< Product String */
   uint8_t VolumeString[11]; /**< Drive Name */
   uint8_t USBDesc_Attributes[1];   /**< USB Download Disable Status
                        |Function                  | bits   |  Values    | Description
                        |-------------------------:|:------:|:----------:|:--------------------------
                        | RFU                      | [7]    |  0x01      | Reserved.
                        | USB power configuration  | [6]    |  0x00      | USB bus powered
                        | ^                        | ^      |  0x01      | USB is self powered
                        | USB remove wakeup        | [5]    |  0x00      | Remote wakeup disabled
                        | ^                        | ^      |  0x01      | Remote wakeup enabled
                        | RFU                      | [4:0]  |            | Reserved
                        */
   uint8_t USBDesc_MaxCurr[1]; /**< Current x2 (mA) consumed by the device (e.g. 0xFA=250 decimal=500mA) */
   uint8_t USB_Discharge_Time[1]; /**< Boolean for Faster USB VBUS Discharge Enable */
   uint8_t bUsbDlCustVersionUpdateEnable[1]; /**< Enable update of Firmware version in Customer Protected Area by USB DL.
                                                   0x1 - USB DL will update Customer FW version
                                                   Anything Else - USB DL will not update Customer FW version  */
   uint8_t dwCustCodeVersionOffset[4]; /**< Offset from dwCusUsbDlDataAreaStart, where the Customer Code Version Number is stored in the Customer Code Area */
   uint8_t UsbVbus_Ok_TimeOut[4]; /**< Timeout for waiting for USB VBUS HI (Unit - us) */
   uint8_t bDisableSuspend[1]; /**< Boolean indicating if USB Suspend is disabled
                                    0 - USB Suspend enabled
                                    Anything Else - USB Suspend Disabled */
   uint8_t bAtxPuPdConfig[1]; /**< Pull Up/Down Config for ATX C and D (Usb D+ and D-) pins
                                    bits[1:0] : 00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up */
   uint8_t bCodeSectorIgnoreCount[1]; /**< Number of Sectors to ignore during Mass Storage write to User Code Area.
                                          0 - Sector ignore feature is disabled.
                                          Anything greater than zero and lesser than User Code Area sector count - First N sectors will be ignored during Mass Storage write operation to User Code Areas. Remaining sectors will be shifted towards the beginning of the Area by N sectors.
                                          Anything greater than User Code Area sector count - Sector ignore feature is disabled. */
   uint8_t bDataSectorIgnoreCount[1]; /**< Number of Sectors to ignore during Mass Storage write to User Data Area.
                                          0 - Sector ignore feature is disabled.
                                          Anything greater than zero and lesser than User Data Area sector count - First N sectors will be ignored during Mass Storage write operation to User Data Areas. Remaining sectors will be shifted towards the beginning of the Area by N sectors.
                                          Anything greater than User Data Area sector count - Sector ignore feature is disabled. */
   uint8_t wUsbDlConfig_Crc16[2]; /**< CRC16 for the UsbDlConfig Structure */
}PN76_UsbDlConfig_t;


/**
 * @brief This structure contains the data bytes reserved for future use.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t abReserved_For_nxp_pemv[21]; /**< This area is reserved to be inline with changes in PEMV */
}PN76_Reserve_Inline_Pemv_0_t;
/**
 * @brief This structure contains testbus settings.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t bDigitalTBSignalIndex[1]; /**< Testbus number to be configured. Selected from the list of exposed testbuses in table8 of Instruction layer document */
   uint8_t bDigitalTBSignalBit[1]; /**< Bit Index to be selected from table 8 of instruction layer */
   uint8_t bAnalogTBSignal[1]; /**< Analog Signal tesbus number:\n
(0x78) - obs_clif_tbcontrol_patchbox0\n
(0x79) - obs_clif_tbcontrol_patchbox1\n
(0x7A) - obs_clif_tbcontrol_patchbox2\n
(0x7B) - obs_clif_tbcontrol_patchbox3\n */
}PN76_COMBINED_TB_SETTINGS_t;
/**
 * @brief This structure contains the data bytes reserved for future use.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t abReserved_For_nxp_pemv1[90]; /**< This area is reserved to be inline with changes in PEMV */
}PN76_Reserve_Inline_Pemv_1_t;
/**
 * @brief This structure contains timeout value used for Auth1 and Auth2 stages during MFC authenticate.
 * @details This parameter must be configured by using \ref E_PN76_EEPROM_SECURE_LIB_CONFIG region
 */
typedef struct __attribute__ ((__packed__))
{
   uint8_t wMfcAuthTimeout[2]; /**< FDT Timeout value used for Auth1 & Auth2 stages during MFC Authenticate. 16-bit value in little endian format. */
}PN76_MFC_CFG_t;

/** @} */

/**
 * @addtogroup USERAREA_ADD_USER_AREA_CONFIG
 * @{
 */
/** @brief This structure contains additional digital delay to be provided for different technology and baud-rate combination. Not used at present. */
#define PN76_DIGITAL_DELAY ((const PN76_DIGITAL_DELAY_t*) 0x0)
/** @brief This structure provides the TX guard time to be applied to generate timeout if TX is not completed within this guard time. */
#define PN76_TXIRQ_GUARD ((const PN76_TXIRQ_GUARD_t*) 0x7)
/** @brief This structure provides the default FDT value to be applied if it is enabled. */
#define PN76_FDT_DEFAULT ((const PN76_FDT_DEFAULT_t*) 0xB)
/** @brief This parameter provides the RX guard time to be applied to generate timeout if RX is not received after TX completed within this guard time. */
#define PN76_RXIRQ_GUARD ((const PN76_RXIRQ_GUARD_t*) 0xF)
/** @brief This structure contains RX frame length. Not used at present. */
#define PN76_CLIF_RX_FRAMELEN_CFG ((const PN76_CLIF_RX_FRAMELEN_CFG_t*) 0x13)
/** @brief This structure contains reserved settinsg for NXP. */
#define PN76_UserArea_Reserved ((const PN76_UserArea_Reserved_t*) 0x17)
/** @brief This structure contains default FDT to be applied for ISO18000 protocol communication. */
#define PN76_ISO18000_CFG ((const PN76_ISO18000_CFG_t*) 0x19)
/** @brief ULPCD calibration status to be handled by the application. */
#define PN76_ULPCD_CALIB_STATUS ((const PN76_ULPCD_CALIB_STATUS_t*) 0x1B)
/** @brief This structure contains reserved settinsg for NXP. */
#define PN76_Reserved_For_NXP ((const PN76_Reserved_For_NXP_t*) 0x1C)
/** @} */

/**
 * @addtogroup USERAREA_ADD_SECURE_LIB_AREA_CONFIG
 * @{
 */
/** @brief IC power configuration. */
#define PN76_USER_PMU ((const PN76_USER_PMU_t*) 0x0)
/** @brief Configuration for the XTAL startup procedure. */
#define PN76_CLKGEN ((const PN76_CLKGEN_t*) 0xF)
/** @brief Configuration for RF clock */
#define PN76_RF_CLOCK_CFG ((const PN76_RF_CLOCK_CFG_t*) 0x11)
/** @brief Configuration for SMU block. Do not modify these settings */
#define PN76_USER_SMU ((const PN76_USER_SMU_t*) 0x13)
/** @brief TX wave shaping configuration. */
#define PN76_RM_TECHNO_TX_SHAPING ((const PN76_RM_TECHNO_TX_SHAPING_t*) 0x14)
/** @brief DPC related settings configuration. */
#define PN76_DPC_SETTINGS ((const PN76_DPC_SETTINGS_t*) 0x68)
/** @brief ARC related settings configuration. */
#define PN76_ARC_SETTINGS ((const PN76_ARC_SETTINGS_t*) 0x129)
/** @brief RSSI settings related card emulation. */
#define PN76_APC_RSSI ((const PN76_APC_RSSI_t*) 0x20C)
/** @brief APC algorithm table output settings TX_PARAM_ENTRY_TABLE. Applicable only for card emulation. */
#define PN76_APC_TX ((const PN76_APC_TX_t*) 0x2D4)
/** @brief Autocoll configuration. */
#define PN76_AUTOCOLL_CFG ((const PN76_AUTOCOLL_CFG_t*) 0x3C4)
/** @brief LPCD settings configuration */
#define PN76_LPCD_SETTINGS ((const PN76_LPCD_SETTINGS_t*) 0x3DE)
/** DAC down sampling divisor settings used in analog TestBus */
#define PN76_ANA_TB_SETTINGS ((const PN76_ANA_TB_SETTINGS_t*) 0x409)
/** @brief Internal settings. Do not modify. */
#define PN76_ULPCD_CONFIG_INT ((const PN76_ULPCD_CONFIG_INT_t*) 0x40A)
/** @brief Internal settings. Do not modify. */
#define PN76_TRIM_CUST ((const PN76_TRIM_CUST_t*) 0x40C)
/** @brief Internal settings. Do not modify. */
#define PN76_TRIM_CUST_EXT ((const PN76_TRIM_CUST_EXT_t*) 0x429)
/**  @brief TX wave shaping for proprietary correction configuration. */
#define PN76_TX_SHAPING_PROPRIETARY_CORR ((const PN76_TX_SHAPING_PROPRIETARY_CORR_t*) 0x42B)
/**  @brief TX wave shaping for proprietary correction configuration. */
#define PN76_TX_SHAPING_PROPRIETARY_1 ((const PN76_TX_SHAPING_PROPRIETARY_1_t*) 0x481)
/**  @brief TX wave shaping for proprietary correction configuration. */
#define PN76_TX_SHAPING_PROPRIETARY_2 ((const PN76_TX_SHAPING_PROPRIETARY_2_t*) 0x4A1)
/**  @brief TX wave shaping for proprietary correction configuration. */
#define PN76_TX_SHAPING_PROPRIETARY_3 ((const PN76_TX_SHAPING_PROPRIETARY_3_t*) 0x4C1)
/**  @brief TX wave shaping for proprietary correction configuration. */
#define PN76_TX_SHAPING_PROPRIETARY_4 ((const PN76_TX_SHAPING_PROPRIETARY_4_t*) 0x4E1)
/** @brief TX driver NOV (non-overlap) settings configuration. */
#define PN76_TX_DRIVER_NOV ((const PN76_TX_DRIVER_NOV_t*) 0x501)
/** @brief Fast VDDPA discharge configuration for PMU. */
#define PN76_USER_PMU_INT_1 ((const PN76_USER_PMU_INT_1_t*) 0x50D)
/** @brief Reader mode technology TX wave shaping during active mode of operation */
#define PN76_RM_TECHNO_ACTIVE_TX_SHAPING ((const PN76_RM_TECHNO_ACTIVE_TX_SHAPING_t*) 0x50E)
/** @brief Internal settings. Do not modify. */
#define PN76_PMU_BOOST_DELAY ((const PN76_PMU_BOOST_DELAY_t*) 0x51A)
/** Reader mode ARC settings to be applied during FDT for A106. */
#define PN76_ARC_SETTINGS_1 ((const PN76_ARC_SETTINGS_1_t*) 0x51B)
/** @brief Internal settings. Do not modify. */
#define PN76_RF_CLOCK_ACTIVE_DPLL_COM ((const PN76_RF_CLOCK_ACTIVE_DPLL_COM_t*) 0x525)
/** @brief Internal settings. Do not modify. */
#define PN76_VDDPA_ADJUSTMENT ((const PN76_VDDPA_ADJUSTMENT_t*) 0x52D)
/** @brief Settings related to NFCLD and RFLD. For Card Mode Dynamic LMA settings. */
#define PN76_MEASURED_LMA_RSSI ((const PN76_MEASURED_LMA_RSSI_t*) 0x530)
/** @brief Internal settings. Do not modify. */
#define PN76_RX_CTRL ((const PN76_RX_CTRL_t*) 0x533)
/** @brief Internal settings. Do not modify. */
#define PN76_15693_BR_CFG ((const PN76_15693_BR_CFG_t*) 0x538)
/** @brief Derivation message to consider for generation of encryption or decryption for Master keys */
#define PN76_SKM_EncrDecrDerMsg ((const PN76_SKM_EncrDecrDerMsg_t*) 0x550)
/** @brief Derivation message to generate encrption/decryption keys to encrypt/decrypt the asymmetric private keys. */
#define PN76_SKM_Asym_KeyDerMsg ((const PN76_SKM_Asym_KeyDerMsg_t*) 0x568)
/** @brief Internal settings. Do not modify. */
#define PN76_USER_PMU_S_ROM_Ext ((const PN76_USER_PMU_S_ROM_Ext_t*) 0x580)
/** @brief TX_SHAPING configuration. */
#define PN76_RM_GLOBAL_TX_SHAPING ((const PN76_RM_GLOBAL_TX_SHAPING_t*) 0x58C)
/** @brief RFLD/NFCLD configuration */
#define PN76_EXT_RF_DETECTION_HW ((const PN76_EXT_RF_DETECTION_HW_t*) 0x597)
/** @brief External RF detection input configuration. */
#define PN76_EXT_RF_DETECT_INT_INPUT ((const PN76_EXT_RF_DETECT_INT_INPUT_t*) 0x5BF)
/**  @brief Internal SMU settings. Do not modify. */
#define PN76_USER_SMU_S ((const PN76_USER_SMU_S_t*) 0x5C7)
/** @brief GPADC configuration. Do not modify. Use the APIs provided as part of GPADC driver to access the GPADC peripheral. */
#define PN76_GPADC_CONFIG ((const PN76_GPADC_CONFIG_t*) 0x5CD)
/** @brief GPADC configuration. Do not modify. Use the APIs provided as part of GPADC driver to access the GPADC peripheral. */
#define PN76_GPADC_CONFIG_S ((const PN76_GPADC_CONFIG_S_t*) 0x60E)
/** @brief GPADC configuration. Do not modify. Use the APIs provided as part of GPADC driver to access the GPADC peripheral. */
#define PN76_GPADC_CONFIG_2 ((const PN76_GPADC_CONFIG_2_t*) 0x612)
/** @brief GPADC configuration. Do not modify. Use the APIs provided as part of GPADC driver to access the GPADC peripheral. */
#define PN76_GPADC_CONFIG_S_2 ((const PN76_GPADC_CONFIG_S_2_t*) 0x632)
/**  @brief ULPCD configuration */
#define PN76_ULPCD_CONFIG ((const PN76_ULPCD_CONFIG_t*) 0x636)
/**  @brief ULPCD settings */
#define PN76_ULPCD_SETTINGS ((const PN76_ULPCD_SETTINGS_t*) 0x640)
/** @brief Internal PMU settings. Do not modify. */
#define PN76_USER_PMU_S ((const PN76_USER_PMU_S_t*) 0x644)
/** @brief SMU configuration for temperature warning */
#define PN76_USER_SMU_CONFIG ((const PN76_USER_SMU_CONFIG_t*) 0x648)
/** @brief USB download configuration. */
#define PN76_UsbDlConfig ((const PN76_UsbDlConfig_t*) 0x64A)
/** @brief This structure contains reserved settinsg for NXP. */
#define PN76_Reserve_Inline_Pemv_0 ((const PN76_Reserve_Inline_Pemv_0_t*) 0x68E)
/** @brief PN76 combined testbus settings */
#define PN76_COMBINED_TB_SETTINGS ((const PN76_COMBINED_TB_SETTINGS_t*) 0x6A3)
/** @brief This structure contains reserved settinsg for NXP. */
#define PN76_Reserve_Inline_Pemv_1 ((const PN76_Reserve_Inline_Pemv_1_t*) 0x6A6)
/** @brief This structure contains default FDT to be applied for MFC authentication. */
#define PN76_MFC_CFG ((const PN76_MFC_CFG_t*) 0x700)
/** @} */


#endif /* PH_USERAREA_ADD_H */
