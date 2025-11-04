/*----------------------------------------------------------------------------*/
/* Copyright 2021, 2023 NXP                                                   */
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
 * Interface functions of CLIF HAL for PN76XX IC
 *
 * $Author: NXP $
 * $Revision: $ (02.00.00)
 */

#ifndef CLIF_H
#define CLIF_H

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/
#ifdef MCUXPRESSO_SDK
#include "PN76_Reg_Interface.h"
#else
#include "Pmu.h"
#include "Smu.h"
#include "ClkGen.h"
#endif
#include "PN76_Status.h"
#include "PN76_Clif.h"
#include "Clif_Reg.h"

/** @addtogroup PN76HALClif
 *
 * @brief The CLIF HAL Instructions API's.
 *
 * CLIF Exchange API Flow
 * \image html HALPN76_Exchange_CallFlow.png
 * @{
 *
 */

#ifdef __cplusplus
extern "C" {
#endif

/*********************************************************************************************************************/
/*   GLOBAL DEFINES                                                                                                  */
/*********************************************************************************************************************/
/* CLIF Register Operations */
#define CLIF_SETREG(RegAddr, RegVal)                            PN76_Sys_WriteRegister(RegAddr, RegVal)                        /**< Macro to write a register */
#define CLIF_SETREG_MASK(RegAddr, BitMask)                      PN76_Sys_WriteRegisterOrMask(RegAddr, BitMask)                 /**< Macro to set a bit */
#define CLIF_CLEARREG_MASK(RegAddr, BitMask)                    PN76_Sys_WriteRegisterAndMask(RegAddr, BitMask)                /**< Macro to clear a bit */
#define CLIF_SETFIELD(RegAddr, BitMask, MaskVal)                PN76_Sys_WriteRegisterField(RegAddr,BitMask,MaskVal)           /**< Macro to write a specific field in a register */
#define CLIF_GETFIELD(RegAddr, BitMask, BitPos)                 PN76_GetRegisterField(RegAddr, BitMask, BitPos)                /**< Macro to to test a bit */
#define CLIF_GETREG(RegAddr, RegVal)                            PN76_Clif_ReadRegister(RegAddr, RegVal)                        /**< Macro to read a register */


/*! @brief CLIF HAL Error Codes. */
typedef enum PN76_Clif_Status_e
{
  PN76_CLIF_STATUS_SUCCESS                   = PN76_STATUS_SUCCESS,         /**< Value to be returned in case of success.*/
  PN76_CLIF_STATUS_TIMEOUT                   = PN76_STATUS_TIMEOUT,         /**< No reply received, e.g. PICC removal. */
  PN76_CLIF_STATUS_INTEGRITY_ERROR           = 0x02,                        /**< Wrong CRC or parity detected. */
  PN76_CLIF_STATUS_COLLISION_ERROR           = 0x03,                        /**< A collision occurred. */
  PN76_CLIF_STATUS_BUFFER_OVERFLOW           = PN76_STATUS_BUFFER_OVERFLOW, /**< Attempt to write beyond buffer size. */
  PN76_CLIF_STATUS_PROTOCOL_ERROR            = 0x06,                        /**< Received response violates protocol. */
  PN76_CLIF_STATUS_AUTH_ERROR                = PN76_STATUS_AUTH_ERROR,      /**< Authentication error. */
  PN76_CLIF_STATUS_NO_RF_FIELD               = 0x0A,                        /**< NO/Error in internal RF */
  PN76_CLIF_STATUS_SYNTAX_ERROR              = 0x0C,                        /**< Value to be returned in case of wrong frame length. */
  PN76_CLIF_STATUS_RESOURCE_ERROR            = PN76_STATUS_RESOURCE_ERROR,  /**< An resource error. */
  PN76_CLIF_STATUS_TIMER_ERROR               = 0x0F,                        /**< Timer Error. */
  PN76_CLIF_STATUS_EXTERNAL_FIELD            = PN76_STATUS_EXTERNAL_FIELD,  /**< Error due to External RF. */
  PN76_CLIF_STATUS_RX_TIMEOUT                = 0x11,                        /**< RX has not come after exchange initiated and FDT timer stopped */
  PN76_CLIF_STATUS_USER_CANCELLED            = 0x12,                        /**< When Abort by User. */
  PN76_CLIF_STATUS_PREVENT_STANDBY           = 0x13,                        /**< When Standby is prevented. */
  PN76_CLIF_STATUS_PARAMETER_ERROR           = PN76_STATUS_PARAMETER_ERROR, /**< Value to be returned in case of wrong parameter. */
  PN76_CLIF_STATUS_SEMANTIC_ERROR            = 0x16,                        /**< Value to be returned in case of unexpected instructions. */
  PN76_CLIF_STATUS_PRBS_ERROR                = 0x17,                        /**< Reserved for PRBS Feature. */
  PN76_CLIF_STATUS_TX_FAILURE                = 0x1A,                        /**< Error that indicates that TX IRQ did not Trigger after Exchange was called. */
  PN76_CLIF_STATUS_TXLDO_ERROR               = PN76_STATUS_TXLDO_ERROR,     /**< Error when TX LDO is not started. */

  PN76_CLIF_STATUS_INCOMPLETE_BYTE           = 0x73,                        /**< An incomplete byte was received. */
  PN76_CLIF_STATUS_INTERNAL_ERROR            = PN76_STATUS_INTERNAL_ERROR,  /**< Value to be returned in case of an internal error. */

  PN76_CLIF_STATUS_SUCCESS_CHAINING          = 0xAF,                        /**< Status to indicate more data bytes to be read. */
  PN76_CLIF_STATUS_INVALID_RESPONSE          = 0xFA,                        /**< Status to indicate that invalid response received. Used in ISO18000p3m3/EPC */
} PN76_Clif_Status_t;

/*! @brief CLIF Event Type. */
typedef enum PN76_ClifEventType{
    PN76_CLIF_EVT_TYPE_NONE = (0U),                                 /**< Default Waiting State.*/
    PN76_CLIF_EVT_TYPE_IDLESTATE = (1U << 0),                       /**< Idle State Invoked.*/
    PN76_CLIF_EVT_TYPE_FLDOFF_IN = (1U << 1),                       /**< Internal Field Turned Off. Note: Not used in PN7640. */
    PN76_CLIF_EVT_TYPE_FLDON_EX = (1U << 2),                        /**< External Field Turned On Detected. Note: Not used in PN7640. */
    PN76_CLIF_EVT_TYPE_FLDOFF_EX = (1U << 3),                       /**< External Field Turned Off Detected.*/
    PN76_CLIF_EVT_TYPE_TIMER0 = (1U << 4),                          /**< Timer 0 Expired.*/
    PN76_CLIF_EVT_TYPE_TIMER1 = (1U << 5),                          /**< Timer 1 Expired (FDT Timer).*/
    PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED = (1U << 6),                  /**< Transmission Completed.*/
    PN76_CLIF_EVT_TYPE_RECEIVE_ENDED = (1U << 7),                   /**< Reception Completed.*/
    PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW = (1U << 8),         /**< Exchange Failure due to Receive Buffer Overflow.*/
    PN76_CLIF_EVT_TYPE_RF_ACT_ERR_04 = (1U << 9),                   /**< RF Active Error. Note: Not used in PN7640. */
    PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED = (1U << 10),         /**< On Expiry of TX GUARD Timer*/
    PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED = (1U << 11),         /**< On Expiry of RX GUARD Timer*/
    PN76_CLIF_EVT_TYPE_ABORTED = (1U << 12),                        /**< ABORT Event. */
    PN76_CLIF_EVT_TYPE_INTERNAL_ERROR = (1U << 13),                 /**< Internal Error. */
    PN76_CLIF_EVT_TYPE_ALL= (
        PN76_CLIF_EVT_TYPE_IDLESTATE |
        PN76_CLIF_EVT_TYPE_FLDOFF_IN |
        PN76_CLIF_EVT_TYPE_FLDON_EX |
        PN76_CLIF_EVT_TYPE_FLDOFF_EX |
        PN76_CLIF_EVT_TYPE_TIMER0 |
        PN76_CLIF_EVT_TYPE_TIMER1 |
        PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED |
        PN76_CLIF_EVT_TYPE_RECEIVE_ENDED |
        PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW |
        PN76_CLIF_EVT_TYPE_RF_ACT_ERR_04 |
        PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
        PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED |
        PN76_CLIF_EVT_TYPE_ABORTED |
        PN76_CLIF_EVT_TYPE_INTERNAL_ERROR),                         /**< All Events Enabled */
    PN76_CLIF_EVT_TYPE_MAX = (PN76_CLIF_EVT_TYPE_ALL + 1),          /**< Comparison Maximum */
    PN76_CLIF_SIZEADJUST_EVT_TYPE = 0x7FFFFFFFU                     /**< For 32bit Enum Adjustment */
}PN76_ClifEventType_t;

/*! @brief Received Packet Parameters of Exchange API. */
typedef struct PN76_Rf_RxParams{
    uint8_t bRxCollPos;                                             /**< Collision Position */
    uint8_t bRxBits;                                                /**< Number of Bits Received */
    uint8_t bRxFrames;                                              /**< In case of Multiple Reception Number of Frames Received */
    uint8_t bReserved;                                              /**< Padding */
    uint16_t wRxBytes;                                              /**< Number of Bytes Received */
    uint16_t wReserved;                                             /**< Padding */
}PN76_Rf_RxParams_t;

/*! @brief MIFARE Crypto Keys. */
typedef enum PN76_MIFARECryptoKeys{
    PN76_MFC_KEY_TYPEA = 0x60,                                      /**< Key A.*/
    PN76_MFC_KEY_TYPEB = 0x61                                       /**< Key B.*/
}PN76_MIFARECryptoKeys_t;

/*! @brief CLIF TIMER configuration in units. */
typedef enum PN76_ClifTimerUnits{
    PN76_CLIF_TIME_MICROSECONDS = 0U,                               /**< Time in microseconds (us).*/
    PN76_CLIF_TIME_MILLISECONDS = 1U                                /**< Time in milliseconds (ms).*/
}PN76_ClifTimerUnits_t;

/*! @brief AUTOCOLL Modes. */
typedef enum
{
   PN76_AUTOCOLL_WITHOUT_AUTONOMOUS_MODE     = 0x00,                /**< Return from Autocoll upon Rf-Off, Error or Activation */
   PN76_AUTOCOLL_AUTONOMOUS_WITH_STANDBY     = 0x01,                /**< Return from Autocoll upon Error or Activation. During Rf-Off got to standby and wake-up upon RF detection and continue Autocoll. */
   PN76_AUTOCOLL_AUTONOMOUS_WITHOUT_STANDBY  = 0x02                 /**< Return from Autocoll upon Error or Activation. During Rf-Off just keep on polling for RF detection and be in Autocoll. */
}PN76_AutocollMode_t;


/*! @brief AUTOCOLL Technologies. */
typedef enum
{
   PN76_CLIF_PAS_A_MODE_ENABLE               = 0x01U,               /**< Listen mode in Passive Type A technology.*/
   PN76_CLIF_PAS_F_MODE_ENABLE               = 0x02U,               /**< Listen mode in Passive Type F technology. Not supported in PN7640. */
   PN76_CLIF_ACT_A_MODE_ENABLE               = 0x04U,               /**< Listen mode in Active Type A technology. Not supported in PN7640. */
   PN76_CLIF_ACT_F_MODE_ENABLE               = 0x08U,               /**< Listen mode in Active Type F technology. Not supported in PN7640. */
}PN76_AutocollTech_e;

#if PHFL_FEAT_PN76XX_P2P_SUPPORT
/*! @brief CLIF active communication error cause codes. */
typedef enum
{
   PN76_ACTIVE_NO_ERR = 0,     /**< No Error */
   PN76_ACTIVE_ERR_TIDT_COLSN, /**< 1 External field was detected within TIDT [1] period */
   PN76_ACTIVE_ERR_TADT_COLSN, /**< 2 External field was detected within TADT [1] period */
   PN76_ACTIVE_ERR_TADT_NO_RF, /**< 3 No external field was detected within TADT [2] period */
   PN76_ACTIVE_ERR_MUTE        /**< 4 Peer did switch off RF-Field but no Rx event was raised (no data received) */
                                       /**< 5 - 7 Reserved */
} PN76_ActiveError_t;
#endif

/********/
// EPC

#define PN76_EPC_CMD_MIN_LEN                                   0x01U
#define PN76_EPC_CMD_MAX_LEN                                   0x01U

#define PN76_EPC_CRC_LEN                                       0x02U
#define PN76_EPC_HANDLE_LEN                                    0x02U

#define PN76_EPC_TAG_DATA_MAX_LEN                              0x42U /* 66 Bytes or 528 Bits Max */
#define PN76_EPC_TAG_INFO_HDR_LEN                              0x03U


/**
 * \defgroup PN76_Epc_EPC 18000-Part 3 Mode 3 Feature Handler
 *
*/

/** EPC commands */
typedef enum PN76_Epc_Prot_I_EPC_Cmd_Enum
{
   E_PN76_RF_PROT_I_EPC_CMD_SELECT =         (0x0AU),    /**< Select command code. */
   E_PN76_RF_PROT_I_EPC_CMD_BEGIN_ROUND =    (0x08U),    /**< BeginRound command code. */
   E_PN76_RF_PROT_I_EPC_CMD_RESIZE_ROUND =   (0x09U),    /**< ResizeRound command code. */
   E_PN76_RF_PROT_I_EPC_CMD_NEXT_SLOT =      (0x00U),    /**< NextSlot command code. */
   E_PN76_RF_PROT_I_EPC_CMD_ACK =            (0x01U),    /**< ACK command code. */
   E_PN76_RF_PROT_I_EPC_CMD_NACK =           (0xC0U),    /**< NAK command code. */
   E_PN76_RF_PROT_I_EPC_CMD_REQ_RN =         (0xC1U)     /**< REQ_RN command code. */
} PN76_Epc_Prot_I_EPC_Cmd_e;

typedef struct PN76_Epc_sEpcTagInfo
{
   uint8_t                      bTimeSlotInfo;
   uint8_t                      bTagDataLen;
   uint8_t                      bTagDataNvb;
}PN76_Clif_EpcTagHdr_t;


typedef struct PN76_Epc_sEpcContext
{
   PN76_Clif_EpcTagHdr_t     *psTagHdr;
   uint8_t                      *pbTagData;
   uint8_t                      bStoredCrc[PN76_EPC_CRC_LEN];
   uint8_t                      bEpcHandle[PN76_EPC_HANDLE_LEN];
   uint8_t                      bSession;
   uint8_t                      bQInfo;
   uint16_t                     wTagInfoSize;
   uint32_t                     dwCurrQSlot;
   uint8_t                      bTimeSlotCfg;
}PN76_Clif_EpcContext_t;

typedef struct PN76_Epc_Data
{

   uint8_t *pBuffer;  /** Pointer to payload */
   uint32_t dwLength; /** Length of Buffer */
   uint8_t  bType;    /** Command Type */
} PN76_Epc_Data_t;


typedef enum phHal_RfTimer_Config_Enum
{
   E_PH_HAL_RFTIMER_DUMMY_CONFIG           = 0,
   E_PH_HAL_RFTIMER_STOP_NO_CONDITION      = 0,

   E_PH_HAL_RFTIMER_STOP_ON_RX_STARTED     = CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_STARTED_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_TX_STARTED     = CLIF_TIMER0_CONFIG_T0_STOP_ON_TX_STARTED_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_RF_ON_EXT      = CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_EXT_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_RF_OFF_EXT     = CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_EXT_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_RF_ON_INT      = CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_INT_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_RF_OFF_INT     = CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_INT_MASK,
   E_PH_HAL_RFTIMER_STOP_ON_RX_ENDED       = CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_ENDED_MASK,
   E_PH_HAL_RFTIMER_START_ON_RX_STARTED    = CLIF_TIMER0_CONFIG_T0_START_ON_RX_STARTED_MASK,
   E_PH_HAL_RFTIMER_START_ON_RX_ENDED      = CLIF_TIMER0_CONFIG_T0_START_ON_RX_ENDED_MASK,
   E_PH_HAL_RFTIMER_START_ON_TX_STARTED    = CLIF_TIMER0_CONFIG_T0_START_ON_TX_STARTED_MASK,
   E_PH_HAL_RFTIMER_START_ON_TX_ENDED      = CLIF_TIMER0_CONFIG_T0_START_ON_TX_ENDED_MASK,
   E_PH_HAL_RFTIMER_START_ON_RF_ON_EXT     = CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_EXT_MASK,
   E_PH_HAL_RFTIMER_START_ON_RF_OFF_EXT    = CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_EXT_MASK,
   E_PH_HAL_RFTIMER_START_ON_RF_ON_INT     = CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_INT_MASK,
   E_PH_HAL_RFTIMER_START_ON_RF_OFF_INT    = CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_INT_MASK,
   E_PH_HAL_RFTIMER_START_ON_TX_FRAMESTEP  = CLIF_TIMER0_CONFIG_T0_START_ON_TX_FRAMESTEP_MASK,
   E_PH_HAL_RFTIMER_START_NOW              = CLIF_TIMER0_CONFIG_T0_START_NOW_MASK,
   /******************************************/
   E_PH_HAL_RFTIMER_PRESCALER_ENABLED      = CLIF_TIMER0_CONFIG_T0_MODE_SEL_MASK,
   E_PH_HAL_RFTIMER_PRESCALER_1_2          = (0x0 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref  6.78 MHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_4          = (0x1 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref  3.39 MHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_8          = (0x2 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref  1.70 MHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_16         = (0x3 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref   848 kHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_32         = (0x4 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref   424 kHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_64         = (0x5 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref   212 kHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_128        = (0x6 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref   106 kHz*/
   E_PH_HAL_RFTIMER_PRESCALER_1_256        = (0x7 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS),  /**< ref    53 kHz*/
   /******************************************/
   E_PH_HAL_RFTIMER_ONE_SHOT_MODE_ENABLED  = CLIF_TIMER0_CONFIG_T0_ONE_SHOT_MODE_MASK,
   E_PH_HAL_RFTIMER_RELOAD_ENABLED         = CLIF_TIMER0_CONFIG_T0_MODE_SEL_MASK
   /******************************************/
} phHal_RfTimer_Config_t;



// EPC
/********/

/*!
 * @brief  CLIF Tx Load RF Configurations
 */
typedef PN76_Clif_TxConfig_t Clif_TxConfig_t;

/*!
 * @brief  CLIF Rx Load RF Configurations
 */
typedef PN76_Clif_RxConfig_t Clif_RxConfig_t;

/**
* \name AUTOCOLL MODE Masks
*/
/*@{*/
/** AUTOCOLL Technology mask. */
#define PN76_CLIF_AUTOCOLL_TECH_MASK     0x0F
/** AUTOCOLL Mode mask. */
#define PN76_CLIF_AUTOCOLL_MODE_MASK     0xF0
/** AUTOCOLL Mode position. */
#define PN76_CLIF_AUTOCOLL_MODE_POS      0x04
/*@}*/

/**< Minimum buffer size that needs to be passed to get RF register configuration. */
#define PN76_CLIF_MIN_RF_CONFIGURATION_BUFFER_SIZE      PN76_MIN_RF_CONFIGURATION_BUFFER_SIZE


/** @name CLIF Status error check macros
 * @{
 */
/**
 * Macro which checks a given status against PN76_CLIF_STATUS_SUCCESS. If the status is not equal to PN76_CLIF_STATUS_SUCCESS then
 * the current function is left with the given status code as return value.
 */
#define STATUS_CHECK_CLIF_SUCCESS_NORETVAL(status)         do {if ((status) != PN76_CLIF_STATUS_SUCCESS) {return;}} while (0)
/**
 * Macro which checks a given status against PN76_CLIF_STATUS_SUCCESS. If the status is not equal to PN76_CLIF_STATUS_SUCCESS then
 * the current function is left with the given status code as return value.
 */
#define STATUS_CHECK_CLIF_SUCCESS(status)         do {if ((status) != PN76_CLIF_STATUS_SUCCESS) {return (status);}} while (0)
/**
 * Macro which executes a function and checks the return value against PN76_CLIF_STATUS_SUCCESS. If the calling function does not
 * return PN76_CLIF_STATUS_SUCCESS then the caller is also left with the callee's status code as return value.
 */
#define STATUS_CHECK_CLIF_SUCCESS_FCT(status,fct) do {(status) = (fct); STATUS_CHECK_CLIF_SUCCESS(status);} while (0)
/**
 * Macro which executes a function and checks the return value against PN76_CLIF_STATUS_SUCCESS and returns from the function.
 */
#define STATUS_CHECK_CLIF_SUCCESS_FCT_NORETVAL(status,fct) do {(status) = (fct); STATUS_CHECK_CLIF_SUCCESS_NORETVAL(status);} while (0)
/**
 * Macro which checks a given status against PN76_CLIF_STATUS_SUCCESS. If the status is not equal to PN76_CLIF_STATUS_SUCCESS then
 * the current function is left with the given status code as return value.
 */
#define STATUS_BREAK_CLIF_SUCCESS(status)         do {if ((status) != PN76_CLIF_STATUS_SUCCESS) {break;}} while (0)
/**
 * Macro which executes a function and checks the return value against PN76_CLIF_STATUS_SUCCESS. If the calling function does not
 * return PN76_CLIF_STATUS_SUCCESS then the caller is also left with the callee's status code as return value.
 */
#define STATUS_BREAK_CLIF_SUCCESS_FCT(status,fct) do {(status) = (fct); STATUS_BREAK_CLIF_SUCCESS(status);} while (0)
/**
 * @}
 */

/*********************************************************************************************************************/
/*   GLOBAL FUNCTION PROTOTYPES                                                                                      */
/*********************************************************************************************************************/

/*!
 * @brief  This function configures the RF with basic setup values needed to start its operation.
 * NOTE: PMU, SMU and ClockGen initialization needs to be done before calling \ref PN76_Clif_Init API.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS  Operation successful.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Init(void);

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
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation Successful.
 */
PN76_Clif_Status_t PN76_Clif_LoadRfConfiguration(Clif_TxConfig_t bTxConfig, Clif_RxConfig_t bRxConfig);

/*!
 * @brief This instruction is used to Retrieve the RF configuration stored in EEPROM.
 *
 * This function is used to read out an Protocol RF configuration of PN76XX.
 * User needs to provide \p pRfConfBuf buffer of minimum length #PN76_CLIF_MIN_RF_CONFIGURATION_BUFFER_SIZE
 * to get all the register address-value-pairs of a particular protocol which can be
 * sent using \p bRfConfiguration parameter, else PN76_STATUS_PARAMETER_ERROR shall be returned.
 *
 * @param bRfConfiguration RF Tx \ref PN76_Clif_TxConfig_t or Rx \ref PN76_Clif_RxConfig_t configuration index to be used.
 * @param pRfConfBuf Pointer to a buffer to retrieve register address and value pairs.
 *                   One configuration is a set of 1 Byte Register address within the RF configuration and
 *                   4 Bytes value that shall be written into the register upon \ref PN76_Sys_LoadRfConfiguration.
 * @param pRfConfBufSize Input the \ref pRfConfBuf buffer size and output with valid RF configuration data size to application.
 *
 * @retval PN76_CLIF_STATUS_SUCCESS Operation Successful.
 * @retval PN76_CLIF_STATUS_PARAMETER_ERROR Parameter error.
 */
PN76_Clif_Status_t PN76_Clif_RetrieveRfConfiguration(uint8_t bRfConfiguration, uint8_t * pRfConfBuf, uint16_t * pRfConfBufSize);

/*!
 * @brief This instruction is used to get the index of loaded Rx RF configuration.
 *
 * @param pRxConfig [Out] The Rx RF Configuration that was loaded, refer @ref PN76_Clif_RxConfig_t values.
 */
void PN76_Clif_GetLoadedRxConfig(uint8_t *pRxConfig);

/*!
 * @brief This instruction is used to turn ON the field.
 *
 * Instruction to turn ON the RF by turning on the TXLDO(if already not started) and RF Driver.
 *
 * @param RF_Param Values Supported are
 *          0x00: ENABLE RF COLLISION AVOIDANCE
 *          0x01: DISABLE RF COLLISION AVOIDANCE
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation Successful.
 * @retval PN76_CLIF_STATUS_EXTERNAL_FIELD Unable to set ON internal field because an external field has been detected .
 * @retval PN76_CLIF_STATUS_TIMEOUT Abnormal termination, event never come after delay of 1ms.
 * @retval PN76_CLIF_STATUS_TXLDO_ERROR Unable to start the TXLDO required for the Tx.
 * @retval PN76_CLIF_STATUS_NO_LOADRF_CFGS Error in case RF ON is triggered without applying proper Load Rf configurations
 */
PN76_Clif_Status_t PN76_Clif_FieldON(uint8_t RF_Param);

/*!
 * @brief This instruction is used to turn OFF the field.
 *
 * Instruction to turns OFF the RF by turning off the TXLDO and RF Driver.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation Successful.
 */
void PN76_Clif_FieldOFF(void);

/*!
 * @brief  This function would perform Exchange on the RF Interface.
 *
 * @param[in]  pTxBuffer Transmit Buffer
 * @param[out] pRxBuffer Receive Buffer
 * @param[in]  wTxLength Transmit Length(bytes: max 1024).
 * @param[in]  wRxBufLen Receive Buffer Size
 * @param[out] pRxParams Receive Status data structure \ref PN76_Rf_RxParams_t
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval PN76_CLIF_STATUS_TIMEOUT Reception does not happen.
 * @retval PN76_CLIF_STATUS_USER_CANCELLED User Aborted the transmission..
 * @retval PN76_CLIF_STATUS_BUFFER_OVERFLOW Rx buffer overflow
 * @retval PN76_CLIF_STATUS_INTEGRITY_ERROR Invalid packet received.
 * @retval PN76_CLIF_STATUS_PROTOCOL_ERROR Invalid response received.
 * @retval PN76_CLIF_STATUS_COLLISION_ERROR Collision detected.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Exchange(uint8_t * pTxBuffer, uint8_t * pRxBuffer,
                                 uint16_t wTxLength, uint16_t wRxBufLen, PN76_Rf_RxParams_t * pRxParams);
/*!
 * @brief  This function would perform Transmit on the RF Interface.
 * Note: Currently only T4AT PICC Mode is supported.
 *
 * @param[in]  pTxBuffer Transmit Buffer
 * @param[in]  wTxLength Transmit Length
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval PN76_CLIF_STATUS_TIMEOUT Reception does not happen.
 * @retval PN76_CLIF_STATUS_USER_CANCELLED User Aborted the transmission..
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Transmit(uint8_t * pTxBuffer, uint16_t wTxLength);

/*!
 * @brief  This function would be used to Receive data on the RF Interface.
 *
 * Note: <em>Special behavior:</em> To use PN76_Clif_Receive API in target Mode, \ref PN76_Sys_Autocoll API shall be executed
 * previously. In target mode this API will wait for receive interrupt or external RF OFF interrupt (in case of passive mode).
 *
 * Note: Currently only T4AT PICC Mode is supported.
 *
 * @param[out] pRxBuffer: Receive Buffer
 * @param[out] wRxBufLen: Receive Buffer Size
 * @param[out] pRxParams: Receive Status data structure \ref PN76_Rf_RxParams_t
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval PN76_CLIF_STATUS_TIMEOUT Reception does not happen.
 * @retval PN76_CLIF_STATUS_USER_CANCELLED User Aborted the transmission..
 * @retval PN76_CLIF_STATUS_BUFFER_OVERFLOW Rx buffer overflow
 * @retval PN76_CLIF_STATUS_INTEGRITY_ERROR Invalid packet received.
 * @retval PN76_CLIF_STATUS_PROTOCOL_ERROR Invalid response received.
 * @retval PN76_CLIF_STATUS_COLLISION_ERROR Collision detected.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Receive(uint8_t * pRxBuffer, uint16_t wRxBufLen, PN76_Rf_RxParams_t * pRxParams);

/*!
 * @brief  This function waits/loops until the input time value is elapsed.
 * This function can be configured to generate Time delays in micro or milli seconds.
 *
 * @param[in] bUnit Unit of given timeout value \ref PN76_ClifTimerUnits_t
 * @param[in] wTimeout Timeout value
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Wait(PN76_ClifTimerUnits_t bUnit, uint16_t wTimeout);

/*!
 * @brief  This function performs MIFARE Authentication on Activate Card.
 *
 * @param[in] pKey: Key to be used in authentication.
 * @param[in] bKeyType: MIFARE Crypto Key type \ref PN76_MIFARECryptoKeys_t.
 * @param[in] bBlockNo: Block number on card to authenticate to.
 * @param[in] pUid: Serial number of current cascade level; uint8_t[4].
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval PN76_CLIF_STATUS_AUTH_ERROR Authentication Error.
 */
PN76_Clif_Status_t PN76_Clif_MfcAuth(uint8_t * pKey, PN76_MIFARECryptoKeys_t bKeyType, uint8_t bBlockNo, uint8_t * pUid);

/*!
 * @brief  This function shall be called by Application after CLIF Init to
 * check if PN76 resumed from Autocoll With Standby after detecting External RF Field.
 *
 * @param[out] pbRfTech: Bit values \ref PN76_AutocollTech_e indicate the Listen mode Technologies chosen by Application.
 * @param[out] peAutocollMode: Previous Autocoll mode that was configured before entering Standby.
 */
void PN76_Clif_CheckAutocollDuringStandby(uint8_t *pbRfTech, PN76_AutocollMode_t *peAutocollMode);

/*!
 * @brief  Used to configure the PN76 to NFC target or card mode based on the configured option.
 * Before calling this API Internal Field should be switched OFF.
 *
 * NOTE: Only PN76_CLIF_PAS_A_MODE_ENABLE bit \ref PN76_AutocollTech_e can be used in PN7640 project.
 *
 * @param[in] bRfTech: Bit values as per \ref PN76_AutocollTech_e are used to configure the Listen mode Technologies.
 * @param[in] eAutocollMode: Autocoll modes supported by this API.
 * @param[out] pAutocollStatus: Autocoll return status.
 * @param[out] ppRxBuffer: Pointer to received data after Activation. It can be an error frame or RATS.
 * @param[out] pwRxLen: Number of received data bytes.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval PN76_CLIF_STATUS_PREVENT_STANDBY Entering into Standby is prevented.
 * @retval PN76_CLIF_STATUS_PARAMETER_ERROR Operation successful.
 * @retval PN76_CLIF_STATUS_EXTERNAL_FIELD Operation successful.
 * @retval PN76_CLIF_STATUS_USER_CANCELLED Operation successful.
 */
PN76_Clif_Status_t PN76_Clif_Autocoll(uint8_t bRfTech, PN76_AutocollMode_t eAutocollMode, PN76_Autocoll_Status *pAutocollStatus, uint8_t **ppRxBuffer, uint16_t *pwRxLen);

/*!
 * @brief  Perform Software Low-Power-Card-Detection.
 *
 * @param[in] wLPCDWakeupCounter : 12 bit wake-up counter value. Max value = 4094msecs.
 * @param[in] bEnableCalibration : To enable or disable calibration. 1: Calibration enable. 0: Calibration disabled
 * @param[out] pLpcdRefValue : LPCD Reference value. Note: LPCD Reference value is copied to pLpcdRefValue only when Calibration is enabled.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_LPCD(uint16_t wLPCDWakeupCounter, uint8_t bEnableCalibration, uint32_t *pLpcdRefValue);

/*!
 * @brief  This function shall configure and start the Poll Guard Timer in micro seconds.
 *
 * @param[in] wTimerLoadValue: Guard Timer Value to be set in micro seconds.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_Set_PollGuardTimer(uint16_t wTimerLoadValue);

/**
 * This function is used to get the RF Exchange Timing elapsed to perform communications in the Transceiver State.
 *
 * @param[out] pFdtUs Frame Delay Time(in us).
 * @param[in] bTimeoutUnit Unit of current timeout value (either #PHHAL_HW_TIME_MICROSECONDS or #PHHAL_HW_TIME_MILLISECONDS).
 * @param[in] bTimerDeviation Platform timer deviation percentage.
 *
 * @return Status of the API
 * @retval #PH_ERR_SUCCESS  Operation successful.
 * @retval Other Depends on the underlying components.
 *
 */
PN76_Clif_Status_t PN76_Clif_PCD_GetExchgFdt(uint32_t *pFdtUs, uint8_t bTimeoutUnit, uint8_t bTimerDeviation);

/*!
 * @brief  This function will wait for any event generated in CLIF Hal
 * The user has to enable the IRQ using SetConfig before calling this function.
 *
 * @param[in] dwTimeOut: Timeout for the events.
 * @param[out] pReceivedEvents: Events received from CLIF HAL.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 */
PN76_Clif_Status_t PN76_Clif_EventWaitAny(uint32_t dwTimeOut, PN76_ClifEventType_t* pReceivedEvents);

/*!
 * @brief  This function will consume all events generated in CLIF Hal
 * Before calling the function \ref PN76_Clif_EventWaitAny call this function to consume all the events.
 */
void PN76_Clif_EventConsumeAll(void);

/*!
 * @brief  This API shall terminating any ongoing command/communication.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS Operation successful.
 */
PN76_Clif_Status_t PN76_Clif_AbortEvent(void);


/*!
 * @brief Read back the content of a logical register.
 *
 * This function is used to read back the content of a logical register whose
 * address is given by \p wRegister.
 * The content is available in output parameter \p pValue.
 *
 * @param wRegister Address of the logical register.
 * @param pValue Pointer to a 32 bit variable, where the result (value of the read out register) shall be written.
 *
 * @retval PN76_CLIF_STATUS_SUCCESS Operation Successful.
 * @retval PN76_CLIF_STATUS_PARAMETER_ERROR Unknown register address or address pointed by \p pValue is beyond RAM region.
 */
PN76_Clif_Status_t PN76_Clif_ReadRegister(uint16_t wRegister, uint32_t *pValue);

/*!
 * @brief  This function de-initializes the CLIF Module and to start again \ref PN76_Clif_Init API needs to be used.
 *
 * @return Status of the API
 * @retval PN76_CLIF_STATUS_SUCCESS  Operation successful.
 * @retval Other Depends on the underlying components.
 */
PN76_Clif_Status_t PN76_Clif_DeInit(void);


/********/
// EPC

PN76_Clif_Status_t PN76_Clif_EpcGen2Inventory(
            uint8_t *pCmdData,
            uint32_t dwCmdLen,
            uint8_t *pRspData,
            uint16_t *pwRspLen );


/**
 * \ingroup PN76_Epc_EPC
 * \brief    This Function is used to Activate the 18000-P3M3 Card.
 * \param[in] pbInParam            Pointer to Input Parameters to be used to Activate the Card
 * \param[in] bInParamLength       The Length of the input Data Parameters.
 * \return PN76_Clif_Status_t
 * \retval PN76_CLIF_STATUS_SUCCESS
 */
extern PN76_Clif_Status_t PN76_Clif_Epc_ActivateCard( uint8_t *pbInParam, uint8_t bInParamLength );

extern PN76_Clif_Status_t PN76_Clif_Epc_ResumeActivation( void );

extern PN76_Clif_Status_t PN76_Clif_Epc_TagInvSize( PN76_Epc_Data_t *psResponse );

/**
 * \ingroup PN76_Epc_EPC
 * \brief    This Function is used to Activate the 18000-P3M3 Card.
 * \param[out] pbInParam            Pointer to Input Parameters to be used to Activate the Card
 * \param[out] bInParamLength       The Length of the input Data Parameters.
 * \return PN76_Clif_Status_t
 * \retval PN76_CLIF_STATUS_SUCCESS
 */

extern PN76_Clif_Status_t PN76_Clif_Epc_TagInventoryInfo( uint16_t *pLen, uint8_t **pBuf);

extern PN76_Clif_Status_t PN76_Clif_Epc_DetectCard(PN76_Clif_EpcContext_t *sEpcCtxt,
                                                              uint8_t *pbInParam, uint8_t bInParamLength );

extern PN76_Clif_Status_t PN76_Clif_Epc_ReActivate( PN76_Clif_EpcContext_t *sEpcCtxt );


#ifdef __cplusplus
}
#endif

/** @} */

#endif /* CLIF_H */
