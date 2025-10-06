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
 *
 * Implementation of System Service CLIF HAL interface functions.
 *
 * $Author: $
 * $Revision: $ (02.01.00)
 *
 *
 */

#ifndef _PN76_CLIF_H_
#define _PN76_CLIF_H_

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/** @addtogroup PN76SYSHALClif
 *
 * @brief System Service Interface API's to work with Contactless Interface (CLIF) of PN76 NFC Controller.
 *
 * This module implements CLIF HAL interface, specific to CLIF module.
 *
 * \section CLIF_RX_TX_TABLE CLIF Supported protocols
 *  PN76xx CLIF supports various technologies, protocols with varying baud-rates.
    The below table mentions the RX and TX configurations that are supported. These RX and TX configurations must be
    provided as part of \ref PN76_Sys_LoadRfConfiguration() API.

    \image html LoadRfConfig.png
 * @{
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************************************************************/
/*   GLOBAL DEFINES                                                                                                  */
/*********************************************************************************************************************/

/* Enable Target mode standby/LPDET by default */
#define PHFL_FEAT_ENABLE_TM_NFC_FORUM_WA 0

/*!
 * @brief  Enum for the Tx Load RF Configurations
 */
typedef enum PN76_Clif_TxConfig_Enum
{
   E_PN76_LOADRF_TX_ISO14443A_106 = 0x0,                     /**< Type A baud rate @ 106 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_212,                           /**< Type A baud rate @ 212 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_424,                           /**< Type A baud rate @ 424 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_848,                           /**< Type A baud rate @ 848 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443B_106,                           /**< Type B baud rate @ 106 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443B_212,                           /**< Type B baud rate @ 212 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443B_424,                           /**< Type B baud rate @ 424 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443B_848,                           /**< Type B baud rate @ 848 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_FELICA_212,                              /**< Type F baud rate @ 212 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_FELICA_424,                              /**< Type F baud rate @ 484 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK100,                 /**< Type V (ISO 15693 ) load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK10,                  /**< Type V (ISO 15693 ) load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO180003M3_TARI_9_44_ASK     = 0x0F,    /**< Type ISO18000 P3M3 TAR=9.44us load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO180003M3_TARI_18_88_ASK    = 0x10,    /**< Type ISO18000 P3M3 TAR=18.88us load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_PICC_106_MANCH_SUBC = 0x13U,   /**< Type A Card mode baud rate @ 106 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_PICC_212_BPSK       = 0x14U,   /**< Type A Card mode baud rate @ 212 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_PICC_424_BPSK       = 0x15U,   /**< Type A Card mode baud rate @ 424 load configurations Tx Value.*/
   E_PN76_LOADRF_TX_ISO14443A_PICC_848_BPSK       = 0x16U,   /**< Type A Card mode baud rate @ 848 load configurations Tx Value.*/

   E_PN76_LOADRF_TX_NFC_PT_212_212                = 0x17U,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_PT_424_424                = 0x18U,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_AT_106_106                = 0x19U,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_AT_212_212                = 0x1AU,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_AT_424_424                = 0x1BU,  /**< RFU */

   E_PN76_LOADRF_TX_GTM_All_Al                    = 0x1CU,   /**< General Target Mode configuration.*/
   E_PN76_LOADRF_TX_B_Prime_All                    = 0x1DU,   /**< B Prime configuration.*/
   E_PN76_LOADRF_TX_NFC_AI_106_106                = 0x1E,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_AI_212_212                = 0x1F,  /**< RFU */
   E_PN76_LOADRF_TX_NFC_AI_424_424                = 0x20,  /**< RFU */

   E_PN76_LOADRF_TX_NO_CHANGE = 0xFF         /* Do not change the Technology */
} PN76_Clif_TxConfig_t;

/*!
 * @brief  Enum for the Rx Load RF Configurations
 */
typedef enum PN76_Clif_RxConfig_Enum
{
   E_PN76_LOADRF_RX_ISO14443A_106 = 0x80,                       /**< Type A baud rate @ 106 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_212,                              /**< Type A baud rate @ 212 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_424,                              /**< Type A baud rate @ 424 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_848,                              /**< Type A baud rate @ 848 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443B_106,                              /**< Type B baud rate @ 106 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443B_212,                              /**< Type B baud rate @ 212 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443B_424,                              /**< Type B baud rate @ 424 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443B_848,                              /**< Type B baud rate @ 848 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_FELICA_212,                                 /**< Type F baud rate @ 212 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_FELICA_424,                                 /**< Type F baud rate @ 424 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO15693_6P6_SC,                            /**< Type V (ISO 15693 ) load configurations Rx 6.6kbps Value.*/
   E_PN76_LOADRF_RX_ISO15693_26_SC,                             /**< Type V (ISO 15693 ) load configurations Rx 26kbps Value.*/
   E_PN76_LOADRF_RX_ISO15693_53_SC,                             /**< Type V (ISO 15693 ) load configurations Rx 53kbps Value.*/
   E_PN76_LOADRF_RX_ISO15693_106,                               /**< Type (ISO 15693 106kbps) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO15693_212,                               /**< Type (ISO 15693 212kbps) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO180003M3_MANCH424_4_PERIOD,              /**< Type (ISO18000 P3M3 MANCH_424_4) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO180003M3_MANCH424_2_PERIOD,              /**< Type (ISO18000 P3M3 MANCH_424_2) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO180003M3_MANCH848_4_PERIOD,              /**< Type (ISO18000 P3M3 MANCH_848_4) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO180003M3_MANCH848_2_PERIOD,              /**< Type (ISO18000 P3M3 MANCH_848_2) load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_PICC_106_MILLER = 0x93,           /**< Type A Card mode baud rate @ 106 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_PICC_212_MILLER = 0x94,           /**< Type A Card mode baud rate @ 212 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_PICC_424_MILLER = 0x95,           /**< Type A Card mode baud rate @ 424 load configurations Rx Value.*/
   E_PN76_LOADRF_RX_ISO14443A_PICC_848_MILLER = 0x96,           /**< Type A Card mode baud rate @ 848 load configurations Rx Value.*/

   E_PN76_LOADRF_RX_NFC_PT_212_212            = 0x97,           /**< RFU */
   E_PN76_LOADRF_RX_NFC_PT_424_424            = 0x98,           /**< RFU */
   E_PN76_LOADRF_RX_NFC_AT_106_106            = 0x99,           /**< RFU */
   E_PN76_LOADRF_RX_NFC_AT_212_212            = 0x9a,           /**< RFU */
   E_PN76_LOADRF_RX_NFC_AT_424_424            = 0x9b,           /**< RFU */

   E_PN76_LOADRF_RX_GTM_All_All = 0x9C,                         /**< General Target Mode configuration.*/
   E_PN76_LOADRF_RX_B_Prime_All = 0x9D,                        /**<B Prime configuration>*/
   E_PN76_LOADRF_RX_NO_CHANGE = 0xFF                            /**< Do not change the Technology */
} PN76_Clif_RxConfig_t;

/*!
 * @brief Update RF Configuration type to be used to update the value in EEPROM.
 */
typedef struct PN76_RfConfig
{
   uint8_t bRfConfig;   /**< Technology to be updated */
   uint8_t bRegAddr;    /**< Address of the register to be updated */
   uint8_t bRegVal[4];  /**< Value to be updated in the register */
} PN76_RfConfig_t;

/*!
 * @brief Parameters to perform MIFARE Authentication.
 */
typedef struct PN76_PerformMIFAREAuthParams
{
   uint8_t *pAuthKey;         /**< Pointer to the authorization key */
   uint8_t *pAuthCmdBuffer;   /**< Pointer the authorization command buffer */
   uint32_t *pdwRB2;          /**<  Pointer to the buffer containing random B2. */
} PN76_PerformMIFAREAuthParams_t;

/*!
 * @brief RF Clock Start up modes
 */
typedef enum
{
   E_PN76_RFCLOCK_START_RESET               =  0x00U,    /**< Reserved to system init, client should not use this enum */
   /* Basic PLL config options */
   E_PN76_RFCLOCK_START_PLL_                 =  0x01U,
   E_PN76_RFCLOCK_START_DPLL_                =  0x02U,
   E_PN76_RFCLOCK_START_MASK                =  E_PN76_RFCLOCK_START_PLL_ | E_PN76_RFCLOCK_START_DPLL_,
   /* CLIF_ANA_RX_CTRL_REG and PCRM_CLIF_ANA_LPDET_CTRL_REG buffer options for clock recovery */
   E_PN76_RFCLOCK_START_BUFFER_CONFIG_NONE  =  0x10U,
   E_PN76_RFCLOCK_START_BUFFER_CONFIG_DPLL  =  0x20U,
   E_PN76_RFCLOCK_START_BUFFER_CONFIG_MASK  =  E_PN76_RFCLOCK_START_BUFFER_CONFIG_NONE | E_PN76_RFCLOCK_START_BUFFER_CONFIG_DPLL,
   /* Use following entries when calling PN76_RfClock_StartPll */
   E_PN76_RFCLOCK_START_PLL_INITIATOR       =  E_PN76_RFCLOCK_START_PLL_ | E_PN76_RFCLOCK_START_BUFFER_CONFIG_NONE,
   E_PN76_RFCLOCK_START_PLL_IDLE            =  E_PN76_RFCLOCK_START_PLL_ | E_PN76_RFCLOCK_START_BUFFER_CONFIG_DPLL,
   E_PN76_RFCLOCK_START_PLL_TARGET          =  E_PN76_RFCLOCK_START_DPLL_ | E_PN76_RFCLOCK_START_BUFFER_CONFIG_DPLL,
   E_PN76_RFCLOCK_START_FROM_VARIABLE       =  0xFFU
} PN76_RfClock_StartUpMode_t;

/*!
 * @brief Different PLL input frequencies supported
 */
typedef enum
{
   E_PN76_RFCLOCK_8MHZ =           0x00,
   E_PN76_RFCLOCK_12MHZ =          0x01,
   E_PN76_RFCLOCK_16MHZ =          0x02,
   E_PN76_RFCLOCK_24MHZ =          0x03,
   E_PN76_RFCLOCK_32MHZ =          0x04,
   E_PN76_RFCLOCK_48MHZ =          0x05,
   E_PN76_RFCLOCK_RFU1 =           0x06,
   E_PN76_RFCLOCK_HFO_22_5MHZ =    0x07,
   E_PN76_RFCLOCK_XTAL =           0x08,
   E_PN76_RFCLOCK_FREQ_IN_RESET =  0x0E,
   E_PN76_RFCLOCK_READ_EEPROM =    0x0F  /* Selection via eeprom: CLKGEN.bPLLClkInputFrq */
} PN76_RfClock_FreqIn_t;

/*!
 * @brief AUTOCOLL MODES.
 */
typedef enum
{
   PN76_AUTOCOLL_MODE_NOT_SET      = 0x00, /**< Yet no tech detected. */

   PN76_AUTOCOLL_MODE_PASSIVE_A    = 0x10, /**< Activated as Passive TypeA */
   PN76_AUTOCOLL_MODE_PASSIVE_F212 = 0x11, /**< Activated as Passive TypeF 212. NOTE : Not supported in PN7640 */
   PN76_AUTOCOLL_MODE_PASSIVE_F424 = 0x12, /**< Activated as Passive TypeF 424. NOTE : Not supported in PN7640 */

   PN76_AUTOCOLL_MODE_ACTIVE_A     = 0x20,  /**< Activated as Active TypeA. NOTE : Not supported in PN7640 */
   PN76_AUTOCOLL_MODE_ACTIVE_F212  = 0x21,  /**< Activated as Active TypeF 212. NOTE : Not supported in PN7640 */
   PN76_AUTOCOLL_MODE_ACTIVE_F424  = 0x22,  /**< Activated as Active TypeF 424. NOTE : Not supported in PN7640 */

   PN76_AUTOCOLL_MODE_ACTIVE_INIT_A    = 0x40,  /**< Active initiator TypeA */
   PN76_AUTOCOLL_MODE_ACTIVE_INIT_F212 = 0x41,  /**< Active initiator TypeF 212 */
   PN76_AUTOCOLL_MODE_ACTIVE_INIT_F424 = 0x42,  /**< Active initiator TypeF 424 */
}PN76_eDetected_Protocol;

/*!
 * @brief Parameters to indicate autocoll return status.
 */
typedef struct{
   PN76_eDetected_Protocol eProtocol; /**< Autocoll mode */
   uint8_t bCardActivated;            /**< True if the card activated else false.*/
} PN76_Autocoll_Status;

/*!
 * @brief PRBS Type.
 */
typedef enum
{
   PN76_PRBS9,
   PN76_PRBS15
} PN76_Prbs_Type_t;

#define PN76_MIN_RF_CONFIGURATION_BUFFER_SIZE                    185U /**< Minimum buffer size that needs to be passed to get RF register configuration. */

#define LISTEN_NFC_A_MASK                      0x01U     /**<  Mask To enable LISTEN mode in TypeA Technology (Passive) */
#define LISTEN_NFC_F_MASK                      0x02U     /**<  Mask To enable LISTEN mode in TypeF Technology (Passive) */
#define LISTEN_NFC_A_ACTIVE_MASK               0x04U     /**<  Mask To enable LISTEN mode in TypeA Technology (Active) */
#define LISTEN_NFC_F_ACTIVE_MASK               0x08U     /**<  Mask To enable LISTEN mode in TypeF Technology (Active) */

#define PH_PN51XFLASH_P2P_ACTIVE_MASK    0x02U

/*********************************************************************************************************************/
/*   GLOBAL FUNCTION PROTOTYPES                                                                                      */
/*********************************************************************************************************************/

/*!
 * @brief Performs the RF variable initialization.
 *
 * This function initialize the RF Context variables.
 *
 */
void PN76_Sys_Clif_Rf_PreInit(void);

/*!
 * @brief Performs the RF Timer initialization.
 *
 * This function initialize the 4 RF timers available in CLIF Module.
 *
 */
void PN76_Sys_Clif_RfTimer_Init(void);

/*!
 * @brief Performs the CLIF Initialization.
 *
 * This function initialize the CLIF Clocks and performs Initiator configuration
 *
 * @retval PN76_STATUS_SUCCESS : On successful RF initialization .
 * @retval PN76_STATUS_PLL_ERROR : Incase RF PLL fails to lock.
 * @retval PN76_STATUS_GPADC_ERROR : Incase GPADC Initialization fails during calibration.
 */
PN76_Status_t PN76_Sys_Clif_Init(void);


/*!
 * @brief Performs the CLIF De_Initialization.
 *
 * This function de-initializes the CLIF module by disabling Tx LDO and RF Clocks.
 *
 */
void PN76_Sys_Clif_DeInit(void);

/*!
 * @brief This instruction is used to load the RF configuration from EEPROM into internal CLIF registers.
 *
 * RF configuration refers to a unique combination of RF Technology, mode (target/initiator) and baud rate.
 * RF configuration can be loaded separately for the CLIF receiver (Rx configuration) and transmitter
 * (Tx configuration) path.
 *
 * @param bTxConfig Input the Tx RF Configuration that need to be loaded, refer @ref PN76_Clif_TxConfig_t values.
 * @param bRxConfig Input the Rx RF Configuration that need to be loaded, refer @ref PN76_Clif_RxConfig_t values.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 */
PN76_Status_t PN76_Sys_LoadRfConfiguration(PN76_Clif_TxConfig_t bTxConfig, PN76_Clif_RxConfig_t bRxConfig);

/*!
 * @brief This instruction is used to Update the RF configuration into EEPROM.
 *
 * This function is used to update the RF configuration within EEPROM.
 * Only registers available within the respective RF configuration can be
 * updated, registers can't be added or removed.
 *
 * @param pRfConfiguration Pointer to array containing one or more configurations to be written.
 * @param bRfConfigurationSize Size of array pointed by \p pRfConfiguration.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter error.
 * @retval PN76_STATUS_MEMORY_ERROR Eeprom Write fails.
 *
 */
PN76_Status_t PN76_Sys_UpdateRfConfiguration(PN76_RfConfig_t *pRfConfiguration, uint8_t bRfConfigurationSize);

/*!
 * @brief This instruction is used to Retrieve the RF configuration stored in EEPROM.
 *
 * This function is used to read out an Protocol RF configuration of PN76XX.
 * User needs to provide \p pRfConfBuf buffer of minimum length #PN76_MIN_RF_CONFIGURATION_BUFFER_SIZE
 * to get all the register address-value-pairs of a particular protocol which can be
 * sent using \p bRfConfiguration parameter, else PN76_STATUS_PARAMETER_ERROR shall be returned.
 *
 * @param bRfConfiguration RF Tx \ref PN76_Clif_TxConfig_t or Rx \ref PN76_Clif_RxConfig_t configuration index to be used.
 * @param pRfConfBuf Pointer to a buffer to retrieve register address and value pairs.
 *                   One configuration is a set of 1 Byte Register address within the RF configuration and
 *                   4 Bytes value that shall be written into the register upon \ref PN76_Sys_LoadRfConfiguration.
 * @param pRfConfBufSize Input the \ref pRfConfBuf buffer size and output with valid RF configuration data size to application.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter error.
 */
PN76_Status_t PN76_Sys_RetrieveRfConfiguration(uint8_t bRfConfiguration, uint8_t * pRfConfBuf, uint16_t * pRfConfBufSize);

/*!
 * @brief This instruction is used to get the index of loaded Rx RF configuration.
 *
 * @param pRxConfig [Out] The Rx RF Configuration that was loaded, refer @ref PN76_Clif_RxConfig_t values.
 */
void PN76_Sys_GetLoadedRxConfig(uint8_t *pRxConfig);

/*!
 * @brief This API will turn ON the field by turning on the TXLDO (if already not started) and RF driver.
 *
 * @note    This API must be called only after the RF configuration is loaded by calling \ref PN76_Sys_LoadRfConfiguration().
 *
 * @param RF_Param Values Supported are
 *          0x00: ENABLE RF COLLISION AVOIDANCE
 *          0x01: DISABLE RF COLLISION AVOIDANCE
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_EXTERNAL_FIELD Unable to set ON internal field because an external field has been detected .
 * @retval PN76_STATUS_TIMEOUT Abnormal termination, event never come after delay of 1ms.
 * @retval PN76_STATUS_TXLDO_ERROR Unable to start the TXLDO required for the Tx.
 * @retval PN76_STATUS_NO_LOADRF_CFGS Error in case RF ON is triggered without applying proper Load Rf configurations
 */
PN76_Status_t PN76_Sys_FieldON(uint8_t RF_Param);

/*!
 * @brief This API will turn OFF the field (RF) by turning off the TXLDO and RF Driver.

 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 */
void PN76_Sys_FieldOFF(void);

/*!
 * @brief This instruction is used to Configure PN76XX Registers for MIFARE Authentication.
 *
 * @param pAuthKey Pointer to the Key used for MIFARE Authentication
 * @param dwUID 4 Byte UID of card that needs to be Authenticated
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR Authentication Error.
 */
PN76_Status_t PN76_Sys_ConfigureMIFAREAuth(
    uint8_t *pAuthKey,
    uint32_t dwUID
    );

/*!
 * @brief This instruction is used to configure the Random B into PN76 Registers during first phase MIFARE Authentication.
 *
 * @param pPerformMIFAREAuthParams MIFARE Authentication Parameters
 * @param dwUID 4 Byte UID of card that needs to be Authenticated
 * @param dwRB Received Token RB from Card
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_AUTH_ERROR Authentication Error.
 */
PN76_Status_t PN76_Sys_PerformMIFAREAuth(
    PN76_PerformMIFAREAuthParams_t *pPerformMIFAREAuthParams,
    uint32_t dwUID,
    uint32_t dwRB
    );

/*!
 * @brief This function shall provide CLIF Tx and Rx Buffer pointer address for any RF operation (Ex, Tx and Rx).
 * Prerequisite: Application should have configured CLIF_BM_TX_BUFFER and CLIF_BM_RX_BUFFER registers.
 *
 * NOTE: Both Tx and Rx buffer pointers should not be NULL.
 *
 * @param pTxBuffer Pointer to TX Buffer configured by Application. If NULL, then only Rx Buffer shall be configured.
 * @param wTxBufSize Length of TX Buffer.
 * @param pRxBuffer Pointer to RX Buffer configured by Application. If NULL, then only Tx Buffer shall be configured.
 * @param wRxBufSize Length of RX Buffer.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 */
PN76_Status_t PN76_Sys_Configure_ClifBuffers(uint8_t *pTxBuffer, uint16_t wTxBufSize, uint8_t *pRxBuffer, uint16_t wRxBufSize);

/*!
 * @brief This instruction shall be used to abort Autocoll operation initiated using \ref PN76_Sys_Autocoll.
 *
 */
void PN76_Sys_AutocollAbort(void);

/*!
 * @brief This instruction is used to enter into Listen/Target Mode.
 *
 * This function is used to put PN76XX into Autocoll mode in order to handle card mode.
 * The function returns if either External RF Field is turned OFF or first packet after
 * Type A Layer-3 activation is completed.
 *
 * @param bRfTech Bit-mask indicating the RF technology/technologies to respond during Listen mode.
 * @param pAutocollStatus Return status.
 * @param pwRxLength Length of response in RX Buffer.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_EXTERNAL_FIELD Error due to External RF OFF
 * @retval PN76_STATUS_USER_CANCELLED Autocoll is aborted due to user calling \ref PN76_Sys_AutocollAbort API.
 */
PN76_Status_t PN76_Sys_Autocoll(uint8_t bRfTech, PN76_Autocoll_Status *pAutocollStatus, uint16_t *pwRxLength);

#if PHFL_FEAT_ENABLE_TM_NFC_FORUM_WA
/*!
 * @brief This instruction is used to set Listen/Target Mode & apply default Target Load RF settings.
 *
 * @note This API is not available.
 */
void PN76_Sys_SetTargetMode(void);
/*!
 * @brief This instruction is used to enter into Listen/Target Mode, does Target settings, performs Load Rf, mode settings, CMA & buffer configurations.
 *
 *
 * @param bRfTech Bit-mask indicating the RF technology/technologies to respond during Listen mode.
 * @param pAutocollStatus Return status.
 * @param pwRxLength Length of response in RX Buffer.
 *
 * @retval PN76_STATUS_STARTED Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_EXTERNAL_FIELD Error due to External RF OFF
 * @retval PN76_STATUS_USER_CANCELLED Autocoll is aborted due to user calling \ref PN76_Sys_AutocollAbort API.
 *
 * @note This API is not available.
 */
PN76_Status_t PN76_Sys_InternalAutocollKickStart(uint8_t bRfTech, PN76_Autocoll_Status *pAutocollStatus, uint16_t *pwRxLen);
/*!
 * @brief This instruction is used to resume Target operations in Autocoll mode in order to handle card mode.
 * The function does one iteration of autocoll and exit after performing required operations based on ext rf cmds.
 *
 * @param pwRxLength Length of response in RX Buffer.
 *
 * @retval PN76_STATUS_STARTED Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_EXTERNAL_FIELD Error due to External RF OFF
 * @retval PN76_STATUS_USER_CANCELLED Autocoll is aborted due to user calling \ref PN76_Sys_AutocollAbort API.
 *
 * @note This API is not available.
 */
PN76_Status_t PN76_Sys_InternalAutocollResume(uint16_t *pwRxLen);

 /*!
 * @brief This instruction is used to resume Target operations in Autocoll mode in order to handle card mode.
 * The function returns if either External RF Field is turned OFF or first packet after
 * Type A Layer-3 activation is completed.
 *
 *
 * @param pwRxLength Length of response in RX Buffer.
 *
 * @retval PN76_STATUS_STARTED Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 * @retval PN76_STATUS_EXTERNAL_FIELD Error due to External RF OFF
 * @retval PN76_STATUS_USER_CANCELLED Autocoll is aborted due to user calling \ref PN76_Sys_AutocollAbort API.
 *
 * @note This API is not available.
 */
PN76_Status_t PN76_Sys_InternalAutocollResumeBlocking(uint16_t *pwRxLen);
#endif

/*!
 * @brief This instruction is used to switch RF clock source to HFO from XTAL/external clock during entry to Standby.
 * NOTE : Mandatory to call this instruction before entering Standby/ULP Standby.
 *
 * @param eStart RF Clock start up modes.

 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PLL_ERROR PLL is not locked.
 */
PN76_Status_t PN76_Sys_RfClock_SwitchToHfo(PN76_RfClock_StartUpMode_t eStart);

/*!
 * @brief This function checks the PLL lock status.
 *
 * @retval TRUE PLL locked successfully.
 * @retval FALSE PLL is not locked.
 */
bool PN76_Sys_RfClock_IsPllLocked(void);

/*!
 * @brief This function shall configure PN76 to perform TX operation in card mode.
 * NOTE : It is mandatory to call this function before Transmission during Card/Listen mode for
 * automatic adjustment of Dynamic LMA.
 */
void PN76_Sys_BeforeCardModeTx(void);

/*!
 * @brief This instruction is used to Configure the Clif clock.
 * NOTE : This is required to restore the CLIF clock when Standby entry is prevented.
 *
 * @param eFreqIn Input frequency for Clif module.
 */
void PN76_Sys_RfClock_Configure(PN76_RfClock_FreqIn_t eFreqIn);

/*!
 * @brief This instruction is used to Stop PLL and DPLL before entering Standby.
 *
 */
void PN76_Sys_RfClock_StopPllAndDpll(void);

/*!
 * @brief This instruction is used to initiate PRBS sequence in Initiator Mode.
 *
 * @param bPRBSOption Type of PRBS pattern \ref PN76_Prbs_Type_t that needs to be sent on RF Interface.
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval PN76_STATUS_PARAMETER_ERROR Parameter Error.
 */
PN76_Status_t PN76_Sys_PRBS(PN76_Prbs_Type_t bPRBSOption);


/*!
 * @brief PN76_Clif_CheckActiveIntRf.
 *
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Clif_CheckActiveIntRf(void);

/*!
 * @brief PN76_Clif_ActRfOn.
 *
 *
 * @retval PN76_STATUS_SUCCESS Operation Successful.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 */
PN76_Status_t PN76_Clif_ActRfOn(void);

/*!
 * @brief This API will give the present active protocol loaded.
 *
 *
 * @retval Returns the value present in \ref PN76_eDetected_Protocol enum.
 */
PN76_eDetected_Protocol PN76_Clif_GetActiveProtocol(void);

#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_CLIF_H_ */
