/* Copyright 2021-2023 NXP                                                   */
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
 * Implementation of CLIF HAL for PN76XX IC
 *
 * $Author: NXP $
 * $Revision: $ (02.00.00)
 */

/*********************************************************************************************************************/
/*   INCLUDES                                                                                                        */
/*********************************************************************************************************************/
#ifdef MCUXPRESSO_SDK
#include "fsl_clock.h"
#include "fsl_power.h"
#include "fsl_gpt.h"
#else
#include "PN76xx.h"
#include "Timer.h"
#include "Timers_Apb_Reg.h"
#include "Nvic.h"
#include "PN76_UserAreaAdd.h"
#endif /*MCUXPRESSO_SDK*/
#include "phOsal.h"
#include "PN76_Pcrm.h"
#include "PN76_Reg_Interface.h"
#include "PN76_UserAreaAdd.h"
#include "Clif_Reg.h"
#include "Clif.h"
#include "PN76_Eeprom.h"
#include "Pcrm_Lp_Reg.h"

#if PHFL_FEAT_ENABLE_TM_NFC_FORUM_WA
#ifndef MCUXPRESSO_SDK
#include "Smu.h" /*MCUXPRESSO_SDK*/
#endif
extern uint32_t dwBootReason;
#endif

/*********************************************************************************************************************/
/*   LOCAL DEFINES                                                                                                   */
/*********************************************************************************************************************/
/* Macro for reading double word. Takes input params Source address and 32-bit Variable to be updated */
#define PN76_READ_DWORD(aSrcAddr, dwVal) {                                                             \
                               (dwVal) = ((uint32_t)((uint32_t)(aSrcAddr)[0]));                        \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[1] << BYTE_SIZE));          \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[2] << (BYTE_SIZE * 2)));    \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[3] << (BYTE_SIZE * 3)));    \
                               }

#define PN76_READ_REG_MULTIPLE_DWORD(aSrcAddr, dwVal, bIndex) {                                                             \
                               (dwVal) = ((uint32_t)((uint32_t)(aSrcAddr)[(bIndex * 4) + 0]));                                 \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[(bIndex * 4) + 1] << BYTE_SIZE));                   \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[(bIndex * 4) + 2] << (BYTE_SIZE * 2)));             \
                               (dwVal) |= ((uint32_t)((uint32_t)(aSrcAddr)[(bIndex * 4) + 3] << (BYTE_SIZE * 3)));             \
                            }

/* MFC defines */
#define MIFARE_MAX_RX_BUFFER_SIZE                       (10)
#define MFC_MIN_AUTH_TIMEOUT                            0x200U /* Minimum Timeout value of 600 us at 848KHz */

#define MFC_KEY_SIZE                                    0x06U
#define MFC_KEYTYPE_SIZE                                0x01U
#define MFC_BLKADDR_SIZE                                0x01U
#define MFC_UID_SIZE                                    0x04U

#define MFC_TIMEOUT_FREQ                                13560U
#define MFC_TIMEOUT_DIV                                 10U

#define CLIF_CONTROL_IDLE_CMD                           0x00U
#define CLIF_CONTROL_TRANSMIT_CMD                       0x01U
#define CLIF_CONTROL_RECEIVE_CMD                        0x02U
#define CLIF_CONTROL_TRANSCEIVE_CMD                     0x03U
#define CLIF_CONTROL_KEEP_CMD                           0x04U
#define CLIF_CONTROL_PRBS_CMD                           0x06U
#define SYSTEM_CONFIG_VAL                               0x80U

#define TRANSCEIVE_STATE_IDLE                           0x0U
#define TRANSCEIVE_STATE_WAITTRANSMIT                   0x1U
#define TRANSCEIVE_STATE_TRANSMITTING                   0x2U
#define TRANSCEIVE_STATE_WAITRECEIVE                    0x3U
#define TRANSCEIVE_STATE_WAITFORDATA                    0x4U
#define TRANSCEIVE_STATE_RECEIVING                      0x5U
#define TRANSCEIVE_STATE_LOOPBACK                       0x6U
#define TRANSCEIVE_STATE_RESERVED                       0x7U

#define CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_JEWEL      0x3U
#define CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_JEWEL      0x3U
#define CLIF_TX_WAIT_TX_WAIT_PRESCALER_JEWEL            0x7FU
#define CLIF_TX_WAIT_TX_WAIT_VALUE_JEWEL                0x3U

#define PN76_FELICA_FRAME_LEN                           0x20U

/* Timer config */
#define PN76_CLIF_MAX_FREQ                              13560000U  /**< PN76XX clk Maximum frequency = 13.56 MHz.*/
#define PN76_CLIF_MIN_FREQ                              53000U     /**< PN76XX clk Minimum frequency = 53 KHz.*/
#define PN76_CLIF_MAX_TIME_DELAY_MS                     19784U     /**< PN76XX Maximum Time Delay in milli second = 19.78443396226.*/
#define PN76_CLIF_MIN_TIME_DELAY_US                     1U         /**< PN76XX Minimum Time Delay in micro second = 0.00001886792.*/
#define PN76_CLIF_CONVERSION_MS_SEC                     1000U      /**< MilliSec to Sec (In denominator for calculation purpose) --> 1000.*/
#define PN76_CLIF_CONVERSION_US_SEC                     1000000U   /**< MicroSec to Sec (In denominator for calculation purpose) --> 1000000.*/

#define PN76_DIGITAL_DELAY_FW_ENABLE_MASK               (0x01U)
#define PN76_DIGITAL_DELAY_FW_ENABLE_POS                (0x00U)

#define TXIRQGUARDTIME_MAX                              0xFFFFFUL

/* WARNING: Do not reduce the CLIF Rx Buffer size to less than 64 bytes. */
#define PN76_CLIF_RF_RX_MAX_BUFFER_SIZE                 0x400U           /**< Size of the RF Receive buffer. */
#define PN76_CLIF_RF_RX_PADDING_SIZE                    0x4U             /**< Rx Buffer padding mandatorily required by the Hardware. */
#define PN76_CLIF_RF_AUTOCOLL_TX_BUFFER_SIZE            0x20U            /**< Size of the RF Transmit buffer used for Autocoll. */

#define CLIF_GET_TIMER_COUNT(x)                         (((x) * 13885U) >> 10U)
#define CLIF_TIMER1_PRESCALAR_53KHZ                     0x07U
#ifdef MCUXPRESSO_SDK
/* Macro map to GPT driver. */
#define TIMER_IsFree      GPT_MGR_IsFree
#define TIMER_Start       GPT_MGR_Start
#define TIMER_Stop        GPT_MGR_Stop
#define TIMER_Configure   GPT_MGR_Configure
#define TIMER_Request     GPT_MGR_Request
#define TIMER_Release     GPT_MGR_Release
#define TIMER_Init        GPT_MGR_Init
#define TIMER_ConfigDef_t gpt_handle_t
#endif
typedef void (*FNPTR_TX_IRQ_GUARD_CB)( void *pContext);

/*! @brief Structure to send data. */
typedef struct PN76_SendDataCfg
{
   uint32_t dwTxLength;
   uint8_t bCommand;
   FNPTR_TX_IRQ_GUARD_CB fpTxIrqGuardCb;
}PN76_SendDataCfg_t;

typedef void (*PN76_ClifISrCb_Function_t)(void);

/*! @brief Enumeration to invoke registered Callback's in CLIF ISR. */
typedef enum PN76_ClifIrqCb_e
{
   PN76_CLIFIRQCB_RX,
   PN76_CLIFIRQCB_TX,
   PN76_CLIFIRQCB_FDT,
   PN76_CLIFIRQCB_RFON_DET,
   PN76_CLIFIRQCB_RFOFF_DET,
   PN76_CLIFIRQCB_RFACTIVEERR,
   PN76_CLIFIRQCB_TIMER0,
   PN76_CLIFIRQCB_SCDET,
   PN76_CLIFIRQCB_MAX,
}PN76_ClifIrqCb_t;

/*! @brief Definition of Rf field power states. */
typedef enum pn76_Comm_RfField_Enum
{
   PN76_RF_COMM_RF_FIELD_OFF = 0,
   PN76_RF_COMM_RF_FIELD_ON,
   PN76_RF_COMM_RF_FIELD_ON_SKIP_TIDT,
   PN76_RF_COMM_RF_FIELD_ON_TX_NOV_CAL,
   PN76_RF_COMM_RF_FIELD_ON_AST
} PN76_RfField_e;

/*! @brief Structure definition to backup register states during MIFARE Authentication. */
typedef struct
{
   uint32_t  dwTxFrameStore;
   uint32_t  dwTxWait;
   uint32_t  dwTxCrcStore;
   uint32_t  dwRxCrcStore;
   uint32_t  dwRxWait;
   uint32_t  dwRxCfgStore;
   uint32_t  dwClifInterruptStore;
} PN76_Clif_MfcState_t;
#ifdef MCUXPRESSO_SDK
/**
 * @brief Function prototype for the Bma error handler called by the BMA Isr.
 */
typedef void (*pBmaErrorCallback)(uint32_t);
#endif
/*********************************************************************************************************************/
/*   LOCAL DEFINES for ISO18000p3m3                                                                                  */
/*********************************************************************************************************************/

#define PN76_EPC_RF_MAX_BUFFER_SIZE    0x11C  /* 288 Bytes - Reduced due to RX Buffer Limitation */

#define LEN_BUFFER_OFFSET                       0x04U
#define PN76_EPC_CRC16                  0x01U
#define PN76_EPC_CRC5                   0x02U

#define PN76_EPC_CRC_TX_CFG_E3_CRC16        0x03U
#define PN76_EPC_CRC_TX_CFG_E3_CRC5         0x04U

#define PN76_EPC_CRC_RX_CFG_E3_CRC16        0x03U
#define PN76_EPC_CRC_RX_CFG_E3_CRC5         0x04U

#define PN76_EPC_INV_SEL_LEN_OFFSET     0x01U
#define PN76_EPC_INV_SEL_MIN_LEN        0x04U /* In Bytes */
#define PN76_EPC_INV_SEL_NVB_OFFSET     0x02U
#define PN76_EPC_INV_SEL_INFO_OFFSET    0x03U
#define PN76_EPC_INV_SEL_BR_SIZE        0x03U /* In Bytes */

#define PN76_EPC_INV_SEL_TS_SIZE        0x01U /* In Bytes */
#define PN76_EPC_INV_SEL_TS_MAX         0x00U
#define PN76_EPC_INV_SEL_TS_SINGLE      0x01U
#define PN76_EPC_INV_SEL_TS_HANLDE      0x02U

/* Tag Response Available with Valid Data Bits */
#define PN76_EPC_TAG_RES_AVAIL          0x00U
/* Tag Response Available with Valid Data Bits and Handle */
#define PN76_EPC_TAG_RES_HNDL_AVAIL     0x01U
/* Tag Response Not Available in this Slot */
#define PN76_EPC_TAG_RES_NOT_AVAIL      0x02U
/* Two or More Tags Responded with Collision */
#define PN76_EPC_TAG_RES_COLLISION      0x03U
/* Tags Responded with Integrity Error */
#define PN76_EPC_TAG_RES_INTEGRITY      0x04U

#define PN76_EPC_CMD_LEN                0x04U
#define PN76_EPC_CRC5_LEN               0x05U
#define PN76_EPC_CRC16_LEN              0x10U
#define PN76_EPC_ACK_CMD_LEN            0x02U
#define PN76_EPC_ACK_LEN                0x12U
#define PN76_EPC_NACK_LEN               0x08U


/* BEGIN ROUND Command Frame Information */
#define PN76_EPC_BR_DR_LEN              0x01U /* in Bits*/
#define PN76_EPC_BR_M_LEN               0x02U /* in Bits*/
#define PN76_EPC_BR_TREXT_LEN           0x01U /* in Bits*/
#define PN76_EPC_BR_SEL_LEN             0x02U /* in Bits*/
#define PN76_EPC_BR_SESSION_LEN         0x02U /* in Bits*/
#define PN76_EPC_BR_SESSION_MASK        0x30U
#define PN76_EPC_BR_SESSION_POS         0x04U
#define PN76_EPC_BR_RFU_LEN             0x01U /* in Bits*/
#define PN76_EPC_BR_Q_LEN               0x04U /* in Bits*/
#define PN76_EPC_BR_LEN                 ( PN76_EPC_CMD_LEN + \
                                                   PN76_EPC_BR_DR_LEN + \
                                                   PN76_EPC_BR_M_LEN + \
                                                   PN76_EPC_BR_TREXT_LEN + \
                                                   PN76_EPC_BR_SEL_LEN + \
                                                   PN76_EPC_BR_SESSION_LEN + \
                                                   PN76_EPC_BR_RFU_LEN + \
                                                   PN76_EPC_BR_Q_LEN )

/* NEXT-SLOT Command Frame Information */
#define PN76_EPC_NEXTSLOT_SESSION_LEN   0x02U /* in Bits */
#define PN76_EPC_NEXTSLOT_LEN           (PN76_EPC_CMD_LEN + \
                                                   PN76_EPC_NEXTSLOT_SESSION_LEN)

/* RESIZE-ROUND Command Frame Information */
#define PN76_EPC_RSZRND_SESSION_LEN     0x02U /* in Bits */
#define PN76_EPC_RSZRND_UPDN_LEN        0x03U /* in Bits */
#define PN76_EPC_RSZRND_LEN             (PN76_EPC_CMD_LEN + \
                                                   PN76_EPC_RSZRND_SESSION_LEN)

#define EPC_TX_RX_TIMEOUT                       135U /* 135U = 1.26ms */ /*535U*/ /* 1070U */ /* 1070U */ /* Minimum Timeout value of 1ms */ /* 1070-> 10ms */
#define EPC_MAX_TAG_INFO                        0x07U /* Only 7 Slot Information can be stored within 508 Bytes */
#define EPC_MAX_TAG_SLOT_INFO                   0x0AU
#define EPC_TAG_SLOT_CRC_VALID_MASK             0x20U
#define EPC_TAG_SLOT_HANDLE_VALID_MASK          0x40U
#define EPC_TAG_SLOT_DATA_VALID_MASK            0x80U

#define START_SYMBOL_PREAMBLE                   0x01U
#define START_SYMBOL_FRAME_SYNC                 0x02U

#define BEGINROUND_TX_WAIT                      0x207FU         /* 0x5E7FU */
#define PN76_EPC_RF_TX_MAX_CLIF_BUFFER_SIZE                                0x40U            /**< Size of the RF Transmit buffer for EPC */
/*********************************************************************************************************************/
/*   GLOBAL DATA TYPE                                                                                          */
/*********************************************************************************************************************/
/* Used to save Tx completion status to handle Rx Event in Receive API. */
uint8_t gbTxCompleted;
/* Flag indicates whether Autocoll is being executed. */
volatile uint8_t gbAutocollExeState;

/* Used to save the Timer1 configuration performed by User */
uint32_t gdwReloadBackup;
/* Used to save if Digital Delay is enabled in EEPROM */
uint8_t gbDigiDelayEn;

/* Registers state is saved/re-stored that are used in MFC Auth. */
PN76_Clif_MfcState_t g_sPN76_Clif_MfcState;

/* 4 byte Aligned RF Receive Buffer for Exchange, Transmit/Receive and MFC Auth operations.
 * WARNING : Do not remove Rx buffer padding. */
PH_ALIGN(4) static uint8_t clif_rf_rx_buffer[PN76_CLIF_RF_RX_MAX_BUFFER_SIZE + PN76_CLIF_RF_RX_PADDING_SIZE] PH_PLACE_ZI_DATA_TO_SECTION(NS_VAR);


static uint8_t  aAuthCmdBuffer[ MFC_KEYTYPE_SIZE + MFC_BLKADDR_SIZE + MFC_KEY_SIZE ];
/*****************************************************************************
 * GLOBAL VARIABLES
 ****************************************************************************/
phOsal_EventObj_t ClifEventObj;                       /**< Handle for CLIF Event. */
static const uint8_t bClifEventName[] = "Clif";

TIMER_ConfigDef_t CLIF_TxIrqGuardTimer;               /**< Timer Config for Tx IRQ Guard Timer. */
TIMER_ConfigDef_t CLIF_RxIrqGuardTimer;               /**< Timer Config for Rx IRQ Guard Timer. */

PN76_ClifISrCb_Function_t aCbHandlers[PN76_CLIFIRQCB_MAX];
//extern phOsal_Thread_t pRfThreadHandle;
/*********************************************************************************************************************/
/*   LOCAL STATIC FUNCTIONS DECLARATION                                                                              */
/*********************************************************************************************************************/
static uint32_t PN76_GetRegisterField(uint8_t bRegister, uint32_t dwRegField, uint32_t dwRegPos);
static PN76_Clif_Status_t PN76_Clif_ConfigFDT(void);
static PN76_RfField_e PN76_GetInternalRfField (void);
static PN76_Clif_Status_t PN76_Clif_RxError(uint32_t dwRxStatusDataTmp, uint32_t dwRxStatusError);
static void PN76_Clif_GetRxFrame(PN76_Rf_RxParams_t * pRxParams, uint32_t dwTransceiveVal, uint32_t dwRx_Status);
static PN76_Clif_Status_t PN76_Clif_TimerStart(uint32_t wPrescaler, uint32_t dwLoadValue, uint8_t  bWait);
static PN76_Clif_Status_t PN76_Clif_AddDigitalDelay();
static PN76_Clif_Status_t PN76_Clif_Get_Digital_Delay(uint8_t bRxLoadConfig, uint16_t* pwDigiDelay);

static PN76_Clif_Status_t PN76_Clif_MfcSaveState(void);
static PN76_Clif_Status_t PN76_Clif_MfcRestoreState(void);
static PN76_Clif_Status_t PN76_Clif_MfcAuth_Tx_Prologue_Before_Send(void);
static PN76_Clif_Status_t PN76_Clif_RxData(uint32_t *pdwRfRecvLen);
static PN76_Clif_Status_t PN76_Clif_MfcAuth1(uint8_t *pAuthKey, uint8_t *pAuthCmdBuffer, uint32_t dwUID, uint32_t *pdwRB2);
static PN76_Clif_Status_t PN76_Clif_MfcAuth2(uint32_t *pdwRB2);

static void PN76_Clif_BmaErrorHandler(uint32_t dwBmaErrorStatus);
static void PN76_Clif_CbRFOFFDETIrq(void);
static void PN76_Clif_CbTimer0Irq(void);
static void PN76_Clif_CbRXIrq(void);
static void PN76_Clif_CbSCDETIrq(void);
static void PN76_Clif_CbFDTIrq(void);
static void PN76_Clif_CbTXIrq(void);
static void PN76_Clif_TxIrqGuardCb(void* pContext);
static void PN76_Clif_RxIrqGuardCb(void* pContext);

static PN76_Clif_Status_t PN76_Clif_SendData(uint8_t *pbTxBuffer, PN76_SendDataCfg_t *PN76_SendDataCfg);
static PN76_Clif_Status_t PN76_Clif_Int_DeInit();

static PN76_Clif_Status_t PN76_Clif_Epc_Select(uint8_t *pbParam,
            uint8_t bSelCmdLen,
            uint8_t bNumValidBits);
static PN76_Clif_Status_t PN76_Clif_Epc_BeginRound( uint8_t *pbParam,
            uint8_t *pbSession,
            uint8_t *pbQInfo,
            uint8_t *pbStoredCrc);
static PN76_Clif_Status_t PN76_Clif_Epc_Ack(uint8_t *pbParam,
            uint8_t *pbTagResponse,
            uint8_t *pbTagRespLen,
            uint8_t *pbTagNvb );
static PN76_Clif_Status_t PN76_Clif_Epc_ReqRN(uint8_t *pbParam,
            uint8_t *pbHandle);
static PN76_Clif_Status_t PN76_Clif_Epc_NextSlot( uint8_t bSession,
            uint8_t *pbStoredCrc);
#if 0
static PN76_Clif_Status_t PN76_Clif_Epc_Nack( void );

static PN76_Clif_Status_t PN76_Clif_Epc_ResizeRound( uint8_t bSession,
            uint8_t UpDn,
            uint8_t *pbStoredCrc)
#endif
static void PN76_Clif_Epc_Config(uint8_t cfg_type,
            uint8_t start_symbol,
            uint8_t tx_crc,
            uint8_t rx_crc);
static PN76_Clif_Status_t PN76_Clif_Epc_TxRxWaitIRQ( uint8_t rx_wait );
static PN76_Clif_Status_t PN76_Clif_Epc_Tx_Prologue_Before_Send( uint8_t bRxGuardTimerEnable,
            uint8_t  bNumValidBits );
static uint8_t *PN76_Clif_Epc_Rf_GetTxBuffer( void );

/*********************************************************************************************************************/
/*   LOCAL VARIABLES                                                                                                 */
/*********************************************************************************************************************/
#ifdef MCUXPRESSO_SDK
static pBmaErrorCallback pBmaErrorcallback;
#endif
static PN76_Clif_EpcContext_t gClif_EpcInfo;
#ifndef MCUXPRESSO_SDK
static uint8_t                gbEPCMulti_RxGuardTO;
#endif

PH_ALIGN(16) static uint8_t  epc_hif_buffer[PN76_EPC_RF_MAX_BUFFER_SIZE + LEN_BUFFER_OFFSET];
PH_ALIGN(4) static uint8_t   g_baEpc_RfTxBuffer[PN76_EPC_RF_TX_MAX_CLIF_BUFFER_SIZE];
/*********************************************************************************************************************/
/*   LOCAL STATIC FUNCTIONS DEFINITIONS                                                                              */
/*********************************************************************************************************************/
#ifdef MCUXPRESSO_SDK
static void NVIC_EnableBmaErrorInterrupts(pBmaErrorCallback pcallback_function)
{
   pBmaErrorcallback = pcallback_function;
   /* Enable BMA Error. */
   (void)PN76_Sys_WriteRegister(BMA_INT_SET_ENABLE, (BMA_INT_SET_ENABLE_BMA_AHB_ERROR_SET_ENABLE_MASK       |
                           BMA_INT_SET_ENABLE_BMA_ADDR_RANGE_ERROR_SET_ENABLE_MASK                |
                           BMA_INT_SET_ENABLE_CLIF_SYS_ERROR_SET_ENABLE_MASK                      |
                           BMA_INT_SET_ENABLE_HOSTIF_SYS_ERROR_SET_ENABLE_MASK));
   NVIC_EnableIRQ(BMA_IRQn);
}
#endif
static uint32_t PN76_GetRegisterField(uint8_t bRegister, uint32_t dwRegField, uint32_t dwRegPos)
{
   uint32_t dwRegVal = 0;

   (void)CLIF_GETREG(bRegister, &dwRegVal);
   return ((dwRegVal & dwRegField) >> dwRegPos);
}

static PN76_Clif_Status_t PN76_Clif_ConfigFDT(void)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint32_t dwFDT_DefaultVal = 0;
   uint32_t dwTimer1Reload = 0;

   (void)PN76_ReadEeprom((uint8_t *)&dwFDT_DefaultVal,
       (uint32_t)PN76_FDT_DEFAULT->dwFDT_DefaultVal,
       sizeof(uint32_t),
       E_PN76_EEPROM_USER_AREA);
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_RELOAD, &dwTimer1Reload));

   if ((
        (dwTimer1Reload == 0) ||
        (!(PN76_GetRegisterField(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK, CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_POS))) ||
        (!(PN76_GetRegisterField(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK, CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_POS))))
        && (dwFDT_DefaultVal)
        && (!(PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS))))
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_CONFIG, (CLIF_TIMER1_CONFIG_T1_MODE_SEL_MASK | CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK
                  | CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK | (CLIF_TIMER1_PRESCALAR_53KHZ << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS))));
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, dwFDT_DefaultVal));
   }
   else if (((dwTimer1Reload == 0) || (!(PN76_GetRegisterField(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK, CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_POS))))
               && (dwFDT_DefaultVal) && (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS)))
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_CONFIG, (CLIF_TIMER1_CONFIG_T1_MODE_SEL_MASK | CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK
                  | (CLIF_TIMER1_PRESCALAR_53KHZ << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS))));
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, dwFDT_DefaultVal));
   }

   return eStatus;
}

static PN76_RfField_e PN76_GetInternalRfField (void)
{
   uint32_t RfEnable = PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_TX_RF_STATUS_MASK, CLIF_STATUS_TX_RF_STATUS_POS);
   return RfEnable==0 ? PN76_RF_COMM_RF_FIELD_OFF : PN76_RF_COMM_RF_FIELD_ON;
}

static PN76_Clif_Status_t PN76_Clif_RxError(uint32_t dwRxStatusDataTmp, uint32_t dwRxStatusError)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

    if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL,
           CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS))
    {
        /* If Rx Multiple is set upper layer will parse the packet.
         *
         * Sanity Check.
         */
        if (PN76_GetRegisterField(CLIF_RX_STATUS,
               CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_MASK, CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_POS) > 0)
        {
            eStatus = PN76_CLIF_STATUS_SUCCESS;
        }
        else
        {
            eStatus = PN76_CLIF_STATUS_TIMEOUT;
        }
    }
    else
    {
        if ((dwRxStatusError & CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK) != 0)
        {
            /* In case there has been a collision */
            eStatus = PN76_CLIF_STATUS_COLLISION_ERROR;
        }
        else if ((dwRxStatusError & CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK) != 0)
        {
            /* Any Receiver Framing Error has occurred */
            eStatus = PN76_CLIF_STATUS_INTEGRITY_ERROR;
        }
        else if ((dwRxStatusError & (CLIF_RX_STATUS_ERROR_RX_NOT_FULL_BYTE_MASK)) != 0)
        {
           if ((dwRxStatusDataTmp & (CLIF_RX_STATUS_RX_NUM_LAST_BITS_MASK)) != 0)
           {
               /* If bits have been received either due to wrong reception or intended */
               eStatus = PN76_CLIF_STATUS_INCOMPLETE_BYTE;
           }
        }
        else if ((dwRxStatusError & (
            CLIF_RX_STATUS_ERROR_RX_LATENCY_ERROR_MASK |
            CLIF_RX_STATUS_ERROR_RX_LEN_ERROR_MASK)) != 0)
        {
            /* Any Receiver Framing Error has occurred */
            eStatus = PN76_CLIF_STATUS_INTEGRITY_ERROR;
        }
        else if ((dwRxStatusError & (CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_MASK)) != 0)
        {
            /* Protocol Error. */
            eStatus = PN76_CLIF_STATUS_PROTOCOL_ERROR;
        }
        else
        {
            /* In positive use case we would have success */
            ;
        }
    }

    return eStatus;
}

static void PN76_Clif_GetRxFrame(PN76_Rf_RxParams_t * pRxParams, uint32_t dwTransceiveVal, uint32_t dwRx_Status)
{
    /* Place the RX Status Data in Correct Locations */
    pRxParams->bRxCollPos = (uint8_t)((dwRx_Status & CLIF_RX_STATUS_RX_COLL_POS_MASK) >>
        CLIF_RX_STATUS_RX_COLL_POS_POS);
    pRxParams->bRxBits = (uint8_t)((dwRx_Status & CLIF_RX_STATUS_RX_NUM_LAST_BITS_MASK) >>
        CLIF_RX_STATUS_RX_NUM_LAST_BITS_POS);

    if ((dwTransceiveVal & CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK) == 0U)
    {
        pRxParams->wRxBytes = (uint16_t)((dwRx_Status & CLIF_RX_STATUS_RX_NUM_BYTES_RECEIVED_MASK) >>
            CLIF_RX_STATUS_RX_NUM_BYTES_RECEIVED_POS);

        pRxParams->bRxFrames = (uint8_t)((dwRx_Status & CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_MASK) >>
            CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_POS);
    }
    else
    {
        pRxParams->bRxFrames = (uint8_t)(((dwRx_Status & CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_MASK) >>
            CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_POS));
        pRxParams->wRxBytes = (pRxParams->bRxFrames * PN76_FELICA_FRAME_LEN);
    }
}

static PN76_Clif_Status_t PN76_Clif_TimerStart(
    uint32_t wPrescaler,
    uint32_t dwLoadValue,
    uint8_t  bWait
    )
{
    PN76_Clif_Status_t  eStatus;
    uint32_t    dwRegVal;
#ifdef OPTIMIZATION_REG_MULTIPLE
    PN76_RegIntf_t saWriteRegValue[3];
#endif /* OPTIMIZATION_REG_MULTIPLE */

    phOsal_EventBits_t dwRecEvents = 0;

    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_ENABLE, CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_MASK));

    (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, PN76_CLIF_EVT_TYPE_ALL, NULL);

    /* Enable Timer0 Interrupt */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, CLIF_INT_SET_ENABLE_TIMER0_IRQ_SET_ENABLE_MASK));

#ifndef OPTIMIZATION_REG_MULTIPLE
    /* Write 0 to stop Timer0. */
    dwRegVal = 0U;

    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER0_CONFIG, dwRegVal));

    /* Load the Timer0 Reload value */
    dwRegVal = (dwLoadValue & CLIF_TIMER0_RELOAD_T0_RELOAD_VALUE_MASK);
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER0_RELOAD, dwRegVal));

    /* Timer MODE_SEL is defined by ePrescaler, 0x01U enables the timer */
    dwRegVal = (CLIF_TIMER0_CONFIG_T0_START_NOW_MASK | CLIF_TIMER0_CONFIG_T0_ONE_SHOT_MODE_MASK | wPrescaler | CLIF_TIMER0_CONFIG_T0_ENABLE_MASK );
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER0_CONFIG, dwRegVal));
#endif  /* OPTIMIZATION_REG_MULTIPLE */
#ifdef OPTIMIZATION_REG_MULTIPLE
    /* Write 0 to stop Timer0. */
    saWriteRegValue[0].wRegAddr = CLIF_TIMER0_CONFIG;
    saWriteRegValue[0].btype = PN76_WRITE_REG;
    saWriteRegValue[0].dwRegVal = 0;

    /* Load the Timer0 Reload value */
    dwRegVal = (dwLoadValue & CLIF_TIMER0_RELOAD_T0_RELOAD_VALUE_MASK);
    saWriteRegValue[1].wRegAddr = CLIF_TIMER0_RELOAD;
    saWriteRegValue[1].btype = PN76_WRITE_REG;
    saWriteRegValue[1].dwRegVal = dwRegVal;

    /* Timer MODE_SEL is defined by ePrescaler, 0x01U enables the timer */
    saWriteRegValue[2].wRegAddr = CLIF_TIMER0_CONFIG;
    saWriteRegValue[2].btype = PN76_WRITE_REG;
    saWriteRegValue[2].dwRegVal = (CLIF_TIMER0_CONFIG_T0_START_NOW_MASK | CLIF_TIMER0_CONFIG_T0_ONE_SHOT_MODE_MASK | wPrescaler | CLIF_TIMER0_CONFIG_T0_ENABLE_MASK );

    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_WriteRegisterMultiple(
                saWriteRegValue, sizeof(saWriteRegValue)));
#endif /* OPTIMIZATION_REG_MULTIPLE */

    if (bWait == 1)
    {
        /*Wait for Timer event*/
        eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
            (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_TIMER0 | PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_CHECK_CLIF_SUCCESS(eStatus);
    }

    if (dwRecEvents == PN76_CLIF_EVT_TYPE_ABORTED)
    {
       /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
       STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

       return PN76_CLIF_STATUS_USER_CANCELLED;
    }

    return PN76_CLIF_STATUS_SUCCESS;
}

static void PN76_Clif_BmaErrorHandler(uint32_t dwBmaErrorStatus)
{
   if(dwBmaErrorStatus & (BMA_INT_STATUS_BMA_AHB_ERROR_STATUS_MASK | BMA_INT_STATUS_BMA_ADDR_RANGE_ERROR_STATUS_MASK | BMA_INT_STATUS_CLIF_SYS_ERROR_STATUS_MASK))
   {
      /* Stop the current activity and return error. */
      phOsal_EventPost( &ClifEventObj.EventHandle, E_OS_EVENT_OPT_POST_ISR, PN76_CLIF_EVT_TYPE_ABORTED, NULL);
   }
   else
   {
      /* It seems issue is with HIF buffer management or something else. Not related to clif. */
      while(1);
   }
}

static void PN76_Clif_CbRFOFFDETIrq(void)
{
   /* In active mode it should be handled as part of active comm. */
#if PHFL_FEAT_PN76XX_P2P_SUPPORT
       uint32_t dwRfReg;
       CLIF_GETREG(CLIF_RF_CONTROL, &dwRfReg);
       if(!(dwRfReg & CLIF_RF_CONTROL_TX_AUTO_RFON_MASK))
#endif
       {
   /* Disable both the interrupts even though in active mode active error and in passive target RF off is enabled */
   (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK |
       CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RF_ACTIVE_ERROR_IRQ_CLR_ENABLE_MASK |
       CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK));

   if (!TIMER_IsFree(&CLIF_TxIrqGuardTimer))
   {
      /*Stop and Release the Timer */
      TIMER_Stop(&CLIF_TxIrqGuardTimer);
      TIMER_Release(&CLIF_TxIrqGuardTimer);
   }

   /* Stop the timer, it would be better to add it during initialization */
   (void)CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, (uint32_t)(~CLIF_TIMER1_CONFIG_T1_ENABLE_MASK));
   (void)CLIF_SETREG(CLIF_TIMER1_RELOAD, CLIF_TIMER1_RELOAD__RESET_VALUE);

   /* Send External RF OFF event. */
   (void)phOsal_EventPost(
       &ClifEventObj.EventHandle,
       E_OS_EVENT_OPT_POST_ISR,
       PN76_CLIF_EVT_TYPE_FLDOFF_EX,
       NULL);
       }
}

static void PN76_Clif_CbTimer0Irq(void)
{
   /* Send TIMER0 event (used for Wait and GuardTimer Feature) */
   (void)phOsal_EventPost(
       &ClifEventObj.EventHandle,
       E_OS_EVENT_OPT_POST_ISR,
       PN76_CLIF_EVT_TYPE_TIMER0,
       NULL);
}

static void PN76_Clif_CbRXIrq(void)
{
    /*On the arrival of RX IRQ in any context, stop and release the RXIRQ guard timer if it has started.  */
    if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
    {
       /*Stop and Release the Timer */
       TIMER_Stop(&CLIF_RxIrqGuardTimer);
       TIMER_Release(&CLIF_RxIrqGuardTimer);
    }

    /* Send RX event */
    (void)phOsal_EventPost(
        &ClifEventObj.EventHandle,
        E_OS_EVENT_OPT_POST_ISR,
        PN76_CLIF_EVT_TYPE_RECEIVE_ENDED,
        NULL);
}

static void PN76_Clif_CbSCDETIrq(void)
{
    /*On the arrival of RX IRQ in any context, stop and release the RXIRQ guard timer if it has started.  */
    if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
    {
       /*Stop and Release the Timer */
       TIMER_Stop(&CLIF_RxIrqGuardTimer);
       TIMER_Release(&CLIF_RxIrqGuardTimer);
    }

    /* Send RX event even though only SC Detect event is received. */
    (void)phOsal_EventPost(
        &ClifEventObj.EventHandle,
        E_OS_EVENT_OPT_POST_ISR,
        PN76_CLIF_EVT_TYPE_RECEIVE_ENDED,
        NULL);
}

static void PN76_Clif_CbFDTIrq(void)
{
   uint8_t        bTransceive_State = 0;
   uint8_t        bRxCfgIdx = 0;
   uint32_t       dwTransceiveCon = 0;

   /*On the arrival of Timer1 IRQ in any context, stop and release the RXIRQ guard timer if it has started.  */
   if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
   {
      /*Stop and Release the Timer */
      TIMER_Stop(&CLIF_RxIrqGuardTimer);
      TIMER_Release(&CLIF_RxIrqGuardTimer);
   }

   PN76_Sys_GetLoadedRxConfig(&bRxCfgIdx);
   bTransceive_State = PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_TRANSCEIVE_STATE_MASK, CLIF_STATUS_TRANSCEIVE_STATE_POS);

   (void)CLIF_GETREG(CLIF_TRANSCEIVE_CONTROL, &dwTransceiveCon);
   if ((dwTransceiveCon & CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK) &&
       ((bTransceive_State >= TRANSCEIVE_STATE_WAITRECEIVE) || ((bRxCfgIdx == E_PN76_LOADRF_RX_FELICA_212) || (bRxCfgIdx == E_PN76_LOADRF_RX_FELICA_424))))
   {
      /* Set the transceive state machine to IDLE. */
      (void)CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD);
   }

   /* Send FDT event (as Timer1 elapsed) */
   (void)phOsal_EventPost(
       &ClifEventObj.EventHandle,
       E_OS_EVENT_OPT_POST_ISR,
       PN76_CLIF_EVT_TYPE_TIMER1,
       NULL);
}

static void PN76_Clif_CbTXIrq(void)
{
    /* Send Tx Ended event */
    (void)phOsal_EventPost(
        &ClifEventObj.EventHandle,
        E_OS_EVENT_OPT_POST_ISR,
        PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED,
        NULL);
}

static void PN76_Clif_TxIrqGuardCb(void* pContext)
{
   /*Lets clear the TX, RX, TIMER1 and SC_DET interrupts */
   (void)CLIF_SETREG_MASK(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK |
               CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK |
               CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK));

   /*Stop and Release the Timer */
   TIMER_Stop(&CLIF_TxIrqGuardTimer);
   TIMER_Release(&CLIF_TxIrqGuardTimer);

   if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
   {
       /*Stop and Release the Rx Guard timer bcoz it would have configured in RF exchange */
       TIMER_Stop(&CLIF_RxIrqGuardTimer);
       TIMER_Release(&CLIF_RxIrqGuardTimer);
   }

   /* Set the transceive state machine to IDLE. */
   CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD);

   /* Send TX GUARD TIMER event (as guard timer elapsed) */
   (void)phOsal_EventPost(
       &ClifEventObj.EventHandle,
       E_OS_EVENT_OPT_POST_ISR,
       PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED,
       NULL);
}

static void PN76_Clif_RxIrqGuardCb(void* pContext)
{
   /*Lets also disable the RX, TIMER1 and SC_DET interrupts */
   (void)CLIF_SETREG_MASK(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK |
               CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK |
               CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK));

   /*Stop and Release the Timer */
   TIMER_Stop(&CLIF_RxIrqGuardTimer);
   TIMER_Release(&CLIF_RxIrqGuardTimer);
   /*We should not have reached here if RX IRQ had arrived */
   /* Set the transceive state machine to IDLE. */
   CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD);

   /* Send RX GUARD TIMER event (as RX guard timer elapsed) */
   (void)phOsal_EventPost(
       &ClifEventObj.EventHandle,
       E_OS_EVENT_OPT_POST_ISR,
       PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED,
       NULL);
}

static PN76_Clif_Status_t PN76_Clif_AddDigitalDelay()
{
   PN76_Clif_Status_t  eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint32_t       dwTempDelay = 0;
   uint16_t       wDigDly = 0;
   uint8_t        bRxCfgIdx = 0;
   uint32_t       dwRfRecvStatus = 0x00U;

   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_CONFIG, &dwRfRecvStatus));

   if((dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK) &&
               (dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK) &&
               ((dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_MASK) == 0))
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_RELOAD, &gdwReloadBackup));

      PN76_Sys_GetLoadedRxConfig(&bRxCfgIdx);

      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Get_Digital_Delay(bRxCfgIdx, &wDigDly));
      dwTempDelay = gdwReloadBackup + wDigDly;

      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, dwTempDelay));
   }

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_Get_Digital_Delay(uint8_t bRxLoadConfig, uint16_t* pwDigiDelay)
{
   PN76_Clif_Status_t  eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint16_t       wDigiDelay = 0;

   switch(bRxLoadConfig)
   {
      /* Type A */
      case E_PN76_LOADRF_RX_ISO14443A_106:
         /* A 106 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_A_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 8;
         break;

      case E_PN76_LOADRF_RX_ISO14443A_212:
         /* A 212 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_A_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 4;
         break;

      case E_PN76_LOADRF_RX_ISO14443A_424:
         /* A 424 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_A_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_ISO14443A_848:
         /* A 848 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_A_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;

         /* Type B */
      case E_PN76_LOADRF_RX_ISO14443B_106:
         /* B 106 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_B_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 8;
         break;

      case E_PN76_LOADRF_RX_ISO14443B_212:
         /* B 212 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_B_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 4;
         break;

      case E_PN76_LOADRF_RX_ISO14443B_424:
         /* B 424 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_B_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_ISO14443B_848:
         /* B 848 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_B_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;
         /* Type F */
      case E_PN76_LOADRF_RX_FELICA_212:
         /* F 212 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_F_424, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_FELICA_424:
         /* F 424 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_F_424, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;

      case E_PN76_LOADRF_RX_ISO15693_6P6_SC:
         /* 6.6kBd */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay, (uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_15693_fast_high, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 16;
         break;

      case E_PN76_LOADRF_RX_ISO15693_26_SC:
         /* 26kBd */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_15693_fast_high, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 8;
         break;

      case E_PN76_LOADRF_RX_ISO15693_53_SC:
         /* 53kBd */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay, (uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_15693_fast_high, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 4;
         break;

      case E_PN76_LOADRF_RX_ISO15693_106:
         /* 106kBd */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_15693_fast_high, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_ISO15693_212:
         /* 212kBd */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_15693_fast_high, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;

         /* ISO 1800P3M3 */
      case E_PN76_LOADRF_RX_ISO180003M3_MANCH424_4_PERIOD:
         /* 18003M3 424_4 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_18000_4_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_ISO180003M3_MANCH424_2_PERIOD:
         /* 18003M3 424_2 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_18000_2_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         wDigiDelay *= 2;
         break;

      case E_PN76_LOADRF_RX_ISO180003M3_MANCH848_4_PERIOD:
         /* 18003M3 848_4 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_18000_4_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;

      case E_PN76_LOADRF_RX_ISO180003M3_MANCH848_2_PERIOD:
         /* 18003M3 848_2 */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom((uint8_t *)&wDigiDelay,(uint32_t)PN76_DIGITAL_DELAY->bDigiDelay_18000_2_848, sizeof(uint8_t), E_PN76_EEPROM_USER_AREA));
         break;

      default:
         break;
   }

   *pwDigiDelay = (uint16_t)CLIF_GET_TIMER_COUNT(wDigiDelay);

   return PN76_CLIF_STATUS_SUCCESS;
}

static PN76_Clif_Status_t PN76_Clif_MfcSaveState(void)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   g_sPN76_Clif_MfcState.dwTxFrameStore = 0;
   g_sPN76_Clif_MfcState.dwTxWait = 0;
   g_sPN76_Clif_MfcState.dwTxCrcStore = 0;
   g_sPN76_Clif_MfcState.dwRxCrcStore = 0;
   g_sPN76_Clif_MfcState.dwRxWait = 0;
   g_sPN76_Clif_MfcState.dwRxCfgStore = 0;
   g_sPN76_Clif_MfcState.dwClifInterruptStore = 0;

   /* Back up the interrupt enable register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_INT_ENABLE, &g_sPN76_Clif_MfcState.dwClifInterruptStore));

   /* Back up the TX Frame config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TX_FRAME_CONFIG, &g_sPN76_Clif_MfcState.dwTxFrameStore));

   /* Back up the TX CRC config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_CRC_TX_CONFIG, &g_sPN76_Clif_MfcState.dwTxCrcStore));

   /* Back up the RX Wait Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TX_WAIT, &g_sPN76_Clif_MfcState.dwTxWait));

   /* Back up the RX Wait Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_WAIT, &g_sPN76_Clif_MfcState.dwRxWait));

   /* Back up the RX config Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_PROTOCOL_CONFIG, &g_sPN76_Clif_MfcState.dwRxCfgStore));

   /* Back up the RX CRC config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_CRC_RX_CONFIG, &g_sPN76_Clif_MfcState.dwRxCrcStore));

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_MfcRestoreState(void)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Stop the Timer */
   /* Stop the Timer if Running */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG_MASK(CLIF_TIMER1_CONFIG,
               CLIF_TIMER1_CONFIG_T1_ENABLE_MASK));

   /* Clear unexposed, Rx and Tx interrupts */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
               (CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK)));

   /* Back up the interrupt enable register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, g_sPN76_Clif_MfcState.dwClifInterruptStore));

   /* Back up the TX Frame config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_FRAME_CONFIG, g_sPN76_Clif_MfcState.dwTxFrameStore));

   /* Back up the TX CRC config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CRC_TX_CONFIG, g_sPN76_Clif_MfcState.dwTxCrcStore));

   /* Back up the RX Wait Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_WAIT, g_sPN76_Clif_MfcState.dwTxWait));

   /* Back up the RX Wait Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_RX_WAIT, g_sPN76_Clif_MfcState.dwRxWait));

   /* Back up the RX config Register */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_RX_PROTOCOL_CONFIG, g_sPN76_Clif_MfcState.dwRxCfgStore));

   /* Back up the RX CRC config */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CRC_RX_CONFIG, g_sPN76_Clif_MfcState.dwRxCrcStore));

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_MfcAuth_Tx_Prologue_Before_Send( void )
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t dwRxIrqGuardTime;
    uint32_t dwTemp;
    uint8_t  bIndex;

    for (bIndex = 0; bIndex < PN76_CLIFIRQCB_MAX; bIndex++)
    {
       aCbHandlers[bIndex] = NULL;
    }
    /*Lets register the desired callbacks */
    aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
    aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;
    aCbHandlers[PN76_CLIFIRQCB_TX] = PN76_Clif_CbTXIrq;
    aCbHandlers[PN76_CLIFIRQCB_TIMER0] = PN76_Clif_CbTimer0Irq;

    (void)PN76_ReadEeprom((uint8_t *)&dwRxIrqGuardTime,(uint32_t)PN76_RXIRQ_GUARD->dwRXIRQ_GuardTime, sizeof(uint32_t), E_PN76_EEPROM_USER_AREA);

    if (dwRxIrqGuardTime)
    {
       /*Enable the SC DET IRQ */
       STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_MASK));

       /* Check if Rx IRQ GuardTimer is not free and
        * Stop and Release the timer before Requesting Timer once again. */
       if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
       {
          /* Stop and Release the Rx Guard Timer */
          TIMER_Stop(&CLIF_RxIrqGuardTimer);
          TIMER_Release(&CLIF_RxIrqGuardTimer);
       }

       /*Request timer */
       eStatus = (PN76_Clif_Status_t)TIMER_Request(&CLIF_RxIrqGuardTimer);

       if (eStatus == PN76_CLIF_STATUS_SUCCESS)
       {
          /*Configure RX Gard timer */
		  #ifdef MCUXPRESSO_SDK
          eStatus = (PN76_Clif_Status_t)TIMER_Configure(&CLIF_RxIrqGuardTimer, true, dwRxIrqGuardTime, &PN76_Clif_RxIrqGuardCb, NULL );
		  #else
		  eStatus = (PN76_Clif_Status_t)TIMER_Configure(&CLIF_RxIrqGuardTimer, E_TIMER_HAL_INTERRUPTMODE, dwRxIrqGuardTime, &PN76_Clif_RxIrqGuardCb, NULL );
		  #endif
          if (eStatus != PN76_CLIF_STATUS_SUCCESS)
          {
             eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
             STATUS_CHECK_CLIF_SUCCESS(eStatus);
          }
       }
       else
       {
          eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
          STATUS_CHECK_CLIF_SUCCESS(eStatus);
       }
    }

    /* set the FDT timeout with CLIF_TIMER1 */
    (void)PN76_ReadEeprom((uint8_t *)&dwTemp, (uint32_t)PN76_MFC_CFG->wMfcAuthTimeout, sizeof(uint16_t), E_PN76_EEPROM_SECURE_LIB_CONFIG);

    /* Clear the timer before configuring. */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG,
                (uint32_t)(~CLIF_TIMER1_CONFIG_T1_ENABLE_MASK)));
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, CLIF_TIMER1_RELOAD__RESET_VALUE));

    /* MFC card shall respond  within 1ms.
     * Check for the Minimum Timeout Value.
     * */
    dwTemp = (dwTemp < MFC_MIN_AUTH_TIMEOUT)? MFC_MIN_AUTH_TIMEOUT: dwTemp;
    dwTemp = (dwTemp * MFC_TIMEOUT_FREQ) >> MFC_TIMEOUT_DIV;

    /* Configure timer ticking at 848KHz i.e. approx 1.179us. */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_CONFIG,
                                              (CLIF_TIMER1_CONFIG_T1_ENABLE_MASK
                                              | CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK
                                              | CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK
                                              | CLIF_TIMER1_CONFIG_T1_MODE_SEL_MASK
                                              | (0x3 << CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS))));

    /* Timer ticking at 848KHz i.e. approx 1.179us for one count. */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, dwTemp));

    return PN76_CLIF_STATUS_SUCCESS;
}

static PN76_Clif_Status_t PN76_Clif_RxData(uint32_t *pdwRfRecvLen)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint32_t           dwRfRecvStatus = 0x00U;

   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS, &dwRfRecvStatus));

   *pdwRfRecvLen = (uint16_t)((dwRfRecvStatus & CLIF_RX_STATUS_RX_NUM_BYTES_RECEIVED_MASK) |
               (((dwRfRecvStatus & CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_MASK) >>
                  CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_POS) * PN76_FELICA_FRAME_LEN));

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_MfcAuth1(uint8_t *pAuthKey, uint8_t *pAuthCmdBuffer, uint32_t dwUID, uint32_t *pdwRB2)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t           dwRxLength = 0;
    uint32_t           dwRB;
    PN76_SendDataCfg_t PN76_SendMfcDataCfg;
    phOsal_EventBits_t dwRecEvents = 0;
    PN76_PerformMIFAREAuthParams_t sAuthParams;

    do
    {
        if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_MfcAuth_Tx_Prologue_Before_Send() )
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }

        /* Clear any existing events that needs to be expected. */
        (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED |
            PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED), NULL);

        /* Send the Key type and the block */
        PN76_SendMfcDataCfg.dwTxLength = (MFC_KEYTYPE_SIZE + MFC_BLKADDR_SIZE);
        PN76_SendMfcDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
        PN76_SendMfcDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

        if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pAuthCmdBuffer, &PN76_SendMfcDataCfg))
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }

        /** Wait until TX Ended or FDT (Timer1) or TX Guard TIMER events are set */
        eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
              (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
            PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_BREAK_CLIF_SUCCESS(eStatus);

        if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
        {
           /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
           STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

           eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
           break;
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1
                    | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED
                    )) != 0U)
        {
            /* TIMEOUT */
            /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                        CLIF_INT_STATUS_TIMER1_IRQ_MASK));
            eStatus = PN76_CLIF_STATUS_TIMEOUT;
            break;
        }

        eStatus = (PN76_Clif_Status_t) PN76_Sys_ConfigureMIFAREAuth(pAuthKey, dwUID);
        if( eStatus != PN76_CLIF_STATUS_SUCCESS )
        {
            /* Configure for MFC Auth failed */
            eStatus = PN76_CLIF_STATUS_AUTH_ERROR;
            break;
        }

        /* wait until RX IRQ */
        /** Wait until RX or FDT (Timer1) or TX Guard TIMER events are set */
        eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
           (phOsal_EventOpt_t) (E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
             PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_BREAK_CLIF_SUCCESS(eStatus);

        /* Check for timeout */
        if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
        {
           /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
           STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

           eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
           break;
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1
                    | PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED
                    )) != 0U)
        {
            /* TIMEOUT */
            /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                        CLIF_INT_STATUS_TIMER1_IRQ_MASK));
            eStatus = PN76_CLIF_STATUS_TIMEOUT;
            break;
        }

        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_RxData(&dwRxLength));

        /* Check if the Received Length is valid else return error */
        if (dwRxLength != (sizeof(uint32_t)))
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }
        else
        {
           PN76_READ_DWORD(clif_rf_rx_buffer, dwRB);
        }

        sAuthParams.pAuthKey = pAuthKey;
        sAuthParams.pAuthCmdBuffer = pAuthCmdBuffer;
        sAuthParams.pdwRB2 = pdwRB2;
        eStatus = (PN76_Clif_Status_t) PN76_Sys_PerformMIFAREAuth(&sAuthParams, dwUID, dwRB);

    }while(0);

    return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_MfcAuth2(uint32_t *pdwRB2)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t           dwRxLength = 0;
    uint32_t           dwRB;
    uint16_t           wBufIndex = 0;
    PN76_SendDataCfg_t PN76_SendMfcDataCfg;
    phOsal_EventBits_t dwRecEvents = 0;

    do
    {
        /* 5) Generate a 32bit random number RA. */
        wBufIndex = sizeof(uint32_t);
        wBufIndex += (uint16_t)(sizeof(uint32_t));

        if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_MfcAuth_Tx_Prologue_Before_Send() )
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }

        /* Clear any existing events that needs to be expected. */
        (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED |
            PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED), NULL);

        /* Send the Key type and the block */
        PN76_SendMfcDataCfg.dwTxLength = wBufIndex;
        PN76_SendMfcDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
        PN76_SendMfcDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

        if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (aAuthCmdBuffer, &PN76_SendMfcDataCfg))
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }

        /* Wait until TX Ended or FDT (Timer1) or TX Guard TIMER events are set */
        eStatus =(PN76_Clif_Status_t) (phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
            (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
            PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_BREAK_CLIF_SUCCESS(eStatus);

        if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
        {
           /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
           STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

           eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
           break;
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1
                    | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED
                    )) != 0U)
        {
            /* TIMEOUT */
            /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                        CLIF_INT_STATUS_TIMER1_IRQ_MASK));
            eStatus = PN76_CLIF_STATUS_TIMEOUT;
            break;
        }

        /* Wait until RX or FDT (Timer1) or TX Guard TIMER events are set */
        eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
             (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
             PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_BREAK_CLIF_SUCCESS(eStatus);

        /* Check for ABORT scenario. */
        if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
        {
           /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
           STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

           eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
           break;
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1
                    | PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED
                    )) != 0U)
        {
            /* TIMEOUT */
            /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                        CLIF_INT_STATUS_TIMER1_IRQ_MASK));
            eStatus = PN76_CLIF_STATUS_TIMEOUT;
            break;
        }

        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_RxData(&dwRxLength));

        /* Check if the Received Length is valid else return error */
        if (dwRxLength != (sizeof(uint32_t)))
        {
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }
        else
        {
            PN76_READ_DWORD(clif_rf_rx_buffer, dwRB);
        }

        /* Check for RB`` integrity */
        if(dwRB != *pdwRB2)
        {
            /* Authentication Error */
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            break;
        }

   }while(0);

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_Int_DeInit()
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Reset all Globals. */
   gbTxCompleted = 0;
   gbAutocollExeState = false;
   gdwReloadBackup = 0;
   gbDigiDelayEn = 0;


   if (!TIMER_IsFree(&CLIF_TxIrqGuardTimer))
   {
      /* Stop and Release the Tx Guard Timer */
      TIMER_Stop(&CLIF_TxIrqGuardTimer);
      TIMER_Release(&CLIF_TxIrqGuardTimer);
   }

   if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
   {
      /* Stop and Release the Rx Guard Timer */
      TIMER_Stop(&CLIF_RxIrqGuardTimer);
      TIMER_Release(&CLIF_RxIrqGuardTimer);
   }

   /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
   STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL,
       CLIF_CONTROL_IDLE_CMD));

   /* Clear the pending status of TX, RX, FDT, SC_DET and RF SW IRQ also */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS, (CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_MASK)));

   /* Stop the any existing timer running. */
   STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_CLEARREG_MASK(CLIF_TIMER0_CONFIG,
               (uint32_t)(~CLIF_TIMER0_CONFIG_T0_ENABLE_MASK)));
   STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG,
               (uint32_t)(~CLIF_TIMER1_CONFIG_T1_ENABLE_MASK)));

   return eStatus;
}

#if PHFL_FEAT_PN76XX_P2P_SUPPORT
/* For PN76xx at 45MHz, with default code optimization O2,
 * */
void PN76_Loop_Wait(volatile uint32_t dwUSec)
{
   dwUSec *= 170;
   dwUSec = dwUSec >> 5;

   while(dwUSec)
   {
      /* to be qmore compliant, do the subtract not in the loop header */
      dwUSec--;
   }
}

void PN76_Clif_ActErrIrqHandler(void)
{
   uint32_t dwReg;
   PN76_ClifEventType_t eActErrorCode = PN76_CLIF_EVT_TYPE_NONE;
   PN76_ActiveError_t eActiveErrCause;

   dwReg = PN76_Sys_ReadRegister(CLIF_STATUS);
   eActiveErrCause = (PN76_ActiveError_t) ((dwReg & CLIF_STATUS_RF_ACTIVE_ERROR_CAUSE_MASK) >> CLIF_STATUS_RF_ACTIVE_ERROR_CAUSE_POS);

   switch(eActiveErrCause)
   {
   case PN76_ACTIVE_NO_ERR:     /**< No Error */
      /* ActiveError was false alarm, reject. Restart rfctrl taking over TX driver control:
       * => auto_rfon and auto_rfoff are set
       * => no collision avoidance bcoz already communication ongoing.
       * => No need of initial rfon (as either Internal/External RF field is present);
       *  */
      PN76_Sys_WriteRegister(CLIF_RF_CONTROL, (CLIF_RF_CONTROL_TX_AUTO_RFON_MASK | CLIF_RF_CONTROL_TX_AUTO_RFOFF_MASK));
      PN76_Sys_WriteRegisterOrMask(CLIF_RF_CONTROL, CLIF_RF_CONTROL_TX_RF_ENABLE_MASK);
      /* Return from ISR w/o posting error. */
      return;
      break;

   case PN76_ACTIVE_ERR_TIDT_COLSN: /**< 1 External field was detected within TIDT [1] period */
   case PN76_ACTIVE_ERR_TADT_COLSN: /**< 2 External field was detected within TADT [1] period */
      /* Check whether RF exchange or Tx or RX command received, if so return response back else set notify flag. */
      eActErrorCode = PN76_CLIF_EVT_TYPE_FLDOFF_EX;
      break;

   case PN76_ACTIVE_ERR_TADT_NO_RF: /**< 3 No external field was detected within TADT [2] period */
#if PHFL_ARTF631514_TRITON
#define NFCLD_ON_MASK_TIME_MASK      (0x000003FFUL)

   /* HW active error is triggered for large (but compliant) Tadt+n*Trfw (due to longer NFCLD latency) */
   {
      /* Active P2P dwNFCLD_P2P_ACTIVE_OnOffMaskTime "Bit[0:14] - Masking time ON = 20us, Bit[15:19] - Masking time OFF = 20us" */
      uint32_t dwNFCLD_P2P_ACTIVE_OnOffMaskTime = 0x80030;

      /* Mask time in 8/fc ~ 0.6 us cycles; apply as multiples of 1 us for extra buffer*/
      uint32_t dwNfcldOnMaskTime = dwNFCLD_P2P_ACTIVE_OnOffMaskTime & CLIF_RXM_NFCLD_MASK_REG_RXM_NFCLD_ON_MASK_TIME_MASK;
      PN76_Loop_Wait(dwNfcldOnMaskTime);

      if((PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_RF_DET_STATUS_MASK, CLIF_STATUS_RF_DET_STATUS_POS)))
      {
         /* ActiveError was false alarm, reject
          * Restart rfctrl taking over TX driver control:
          * => auto_rfon and auto_rfoff are set
          * => no collision avoidance
          * => no initial rfon (as external field is present);
          * */
         PH_HALREG_SETREG(CLIF_RF_CONTROL_REG, (CLIF_RF_CONTROL_REG_TX_AUTO_RFON_MASK | CLIF_RF_CONTROL_REG_TX_AUTO_RFOFF_MASK));
         PH_HALREG_SETBITN(CLIF_RF_CONTROL_REG, CLIF_RF_CONTROL_REG_TX_RF_ENABLE_POS);
         /* Return from ISR w/o posting error. */
         return;
      }
   }
#endif
      eActErrorCode = PN76_CLIF_EVT_TYPE_FLDOFF_EX;
      break;

   case PN76_ACTIVE_ERR_MUTE:        /**< 4 Peer did switch off RF-Field but no Rx event was raised (no data received) */
      eActErrorCode = PN76_CLIF_EVT_TYPE_RF_ACT_ERR_04;

      PN76_eDetected_Protocol eProtocol;
      eProtocol = PN76_Clif_GetActiveProtocol();

      /* If the target switches ON & OFF without txing data, then Initiator should consider as timeout and retry. For the host to retry lets enable RF.
       * If in-case the host is trying to discontinue further transactions then it should send RF-OFF cmd explicitly. */
      if((eProtocol == PN76_AUTOCOLL_MODE_ACTIVE_INIT_A) || (eProtocol == PN76_AUTOCOLL_MODE_ACTIVE_INIT_F212) || (eProtocol == PN76_AUTOCOLL_MODE_ACTIVE_INIT_F424))
      {
         PN76_Clif_ActRfOn();
      }

      break;
   }

//   /* Lets also clear the other interrupt enables */
//   CLIF_SETREG_MASK(CLIF_INT_CLR_ENABLE,  (CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK
//               | CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK
//               | CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK
//               | CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_MASK));
//
//   CLIF_SETREG_MASK(CLIF_INT_CLR_STATUS,
//               (CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK
//               | CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK
//               | CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK
//               | CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_MASK
//               | CLIF_INT_SET_ENABLE_RX_IRQ_SET_ENABLE_MASK));

   /* Need to check whether to clear all other interrupts */
   PN76_Sys_WriteRegister(CLIF_INT_CLR_ENABLE, CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK);

   /* Check for Tx & Rx Guard Timers, stop & release it. */
   if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
   {
      /* Stop and Release the Rx Guard Timer */
      TIMER_Stop(&CLIF_RxIrqGuardTimer);
      TIMER_Release(&CLIF_RxIrqGuardTimer);
   }

   if (!TIMER_IsFree(&CLIF_TxIrqGuardTimer))
   {
      /* Stop and Release the Rx Guard Timer */
      TIMER_Stop(&CLIF_TxIrqGuardTimer);
      TIMER_Release(&CLIF_TxIrqGuardTimer);
   }

   /* Stop the FWT timer */
   PN76_Sys_WriteRegisterAndMask(CLIF_TIMER1_CONFIG, (~(CLIF_TIMER1_CONFIG_T1_ENABLE_MASK)));
   PN76_Sys_WriteRegister(CLIF_TIMER1_RELOAD, CLIF_TIMER1_RELOAD__RESET_VALUE);

//   /* Disable the SW IRQ used to notify RX/Timeout bcoz it is ended up with active ERROR */
//   phPn51xFlash_Dispatch_CfgRFSwIrq(FALSE);
//   phPn51xFlash_Dispatch_SetRFSwIrq(FALSE);

   /* Post the Error event. */
   (void)phOsal_EventPost( &ClifEventObj.EventHandle, E_OS_EVENT_OPT_POST_ISR, eActErrorCode, NULL);
}
#endif /* PHFL_FEAT_PN76XX_P2P_SUPPORT */



/*********************************************************************************************************************/
/*   GLOBAL FUNCTIONS                                                                                                */
/*********************************************************************************************************************/
#ifdef MCUXPRESSO_SDK
void BMA_IRQHandler(void);
void BMA_IRQHandler(void)
{
   uint32_t dwBmaErrorStatus;
   /* Read BMA error interrupt status */
   dwBmaErrorStatus = PN76_Sys_ReadRegister(BMA_INT_STATUS);
   /* Clear BMA interrupt status. */
   (void)PN76_Sys_WriteRegister(BMA_INT_CLR_STATUS, dwBmaErrorStatus);
   /* Helps during debug session */
   __BKPT(0);
   /* Post bma error to callback handler. */
   if(pBmaErrorcallback != NULL)
   {
      pBmaErrorcallback(dwBmaErrorStatus);
   }
}
#endif
PN76_Clif_Status_t PN76_Clif_Init(void)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint8_t            bIndex;
    uint32_t           dwRxBufferAddr;

    /* Timer is initialized, as GP Timers are used for Tx and Rx Guard Timers. */
    TIMER_Init();
	#ifdef MCUXPRESSO_SDK
    NVIC_EnableIRQ(CLIF_IRQn);
	#endif

    /* Reset all Globals. */
    gbTxCompleted = 0U;
    gbAutocollExeState = false;
    gdwReloadBackup = 0;
    gbDigiDelayEn = 0;

    /* Initialize the CLIF Timers */
    PN76_Sys_Clif_RfTimer_Init();

    /* Initialization of RF Variables. */
    PN76_Sys_Clif_Rf_PreInit();

    /* Enable BMA Error . */
    NVIC_EnableBmaErrorInterrupts(PN76_Clif_BmaErrorHandler);

    /* Create the event. */
    ClifEventObj.pEvtName = (uint8_t *)bClifEventName;
    ClifEventObj.intialValue = 0U;
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus,(PN76_Clif_Status_t)( phOsal_EventCreate(&ClifEventObj.EventHandle, &ClifEventObj)));

    for (bIndex = 0; bIndex < PN76_CLIFIRQCB_MAX; bIndex++)
    {
        aCbHandlers[bIndex] = NULL;
    }

    aCbHandlers[PN76_CLIFIRQCB_TIMER0] = PN76_Clif_CbTimer0Irq;

    dwRxBufferAddr = (uint32_t)clif_rf_rx_buffer;
    if (dwRxBufferAddr & 3)
    {
        /* Return error if CLIF Rx buffer is not 32bit aligned. */
        return PN76_CLIF_STATUS_RESOURCE_ERROR;
    }
	
	/* CLIF Initialization */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_Clif_Init());
	
    /* Set RX buffer address (word aligned) */
    /* Set buffer reception size */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_BM_RX_BUFFER, ((dwRxBufferAddr >> 2) & CLIF_BM_RX_BUFFER_RX_BUFFER_START_ADDRESS_MASK) |
               (((PN76_CLIF_RF_RX_MAX_BUFFER_SIZE >> 2) << CLIF_BM_RX_BUFFER_RX_BUFFER_LENGTH_POS) & CLIF_BM_RX_BUFFER_RX_BUFFER_LENGTH_MASK)));

    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_RX_FRAME_LENGTH, CLIF_RX_FRAME_LENGTH__RESET_VALUE));

    /* Clear all events. */
    (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, PN76_CLIF_EVT_TYPE_ALL, NULL);

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_LoadRfConfiguration(Clif_TxConfig_t bTxConfig, Clif_RxConfig_t bRxConfig)
{
    return (PN76_Clif_Status_t)PN76_Sys_LoadRfConfiguration(bTxConfig, bRxConfig);
}

PN76_Clif_Status_t PN76_Clif_RetrieveRfConfiguration(uint8_t bRfConfiguration, uint8_t * pRfConfBuf, uint16_t * pRfConfBufSize)
{
    return (PN76_Clif_Status_t)PN76_Sys_RetrieveRfConfiguration(bRfConfiguration, pRfConfBuf, pRfConfBufSize);
}

void PN76_Clif_GetLoadedRxConfig(uint8_t *pRxConfig)
{
   PN76_Sys_GetLoadedRxConfig(pRxConfig);
}

PN76_Clif_Status_t PN76_Clif_FieldON(uint8_t RF_Param)
{
    return (PN76_Clif_Status_t)PN76_Sys_FieldON(RF_Param);
}

void PN76_Clif_FieldOFF(void)
{
    PN76_Sys_FieldOFF();
}

PN76_Clif_Status_t PN76_Clif_Exchange(uint8_t * pTxBuffer, uint8_t * pRxBuffer,
                                 uint16_t wTxLength, uint16_t wRxBufLen, PN76_Rf_RxParams_t * pRxParams)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint8_t            bTransceive_State = 0;
    uint32_t           dwIntEnbReg = 0;
    uint32_t           dwRxIrqGuardTime = 0;
    PN76_SendDataCfg_t PN76_SendDataCfg;
    phOsal_EventBits_t dwRecEvents = 0;
    uint32_t           dwRx_Status = 0U;
    uint32_t           dwRxStatusError = 0U;
    uint32_t           dwTransceiveStatus = 0U;
    uint32_t           dwSysConf = 0U;

#ifdef OPTIMIZATION_REG_MULTIPLE
    uint16_t           awRegAddress[3];
    uint8_t            abRegValue[12];
    uint8_t            bIndex = 0;
#endif /* OPTIMIZATION_REG_MULTIPLE */

    /* Reset memory of RxParams */
    memset(pRxParams, 0x00, sizeof(PN76_Rf_RxParams_t));

    do{
#if PHFL_FEAT_PN76XX_P2P_SUPPORT
       uint32_t dwRfReg;
       CLIF_GETREG(CLIF_RF_CONTROL, &dwRfReg);
       if(dwRfReg & CLIF_RF_CONTROL_TX_AUTO_RFON_MASK)
       {
          /* In active comm set Initiator mode bit while performing Tx operation. */
 //         PH_HALREG_SETBITN(CLIF_TRANSCEIVE_CONTROL_REG, CLIF_TRANSCEIVE_CONTROL_REG_INITIATOR_POS);

          /* Look for RF field if not just turn ON. */
          if (PN76_Clif_CheckActiveIntRf() != PN76_STATUS_SUCCESS)
          {
             eStatus = PN76_CLIF_STATUS_NO_RF_FIELD;
             break;
          }

          aCbHandlers[PN76_CLIFIRQCB_RFACTIVEERR] = PN76_Clif_ActErrIrqHandler;
          aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
          dwIntEnbReg |= CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK;
       }else
#endif
       {
        /* In Passive Initiator mode check for internal field ON. */
        if (PN76_GetInternalRfField() != PN76_RF_COMM_RF_FIELD_ON)
        {
            eStatus = PN76_CLIF_STATUS_NO_RF_FIELD;
            break;
        }
       }

        /*Clear the pending status of TX, RX, FDT, SC_DET, SOF_DET. */
        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                    (CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK |
                    CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_MASK |
                    CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_BUFFER_OVERFLOW_IRQ_CLR_STATUS_MASK)));

        /* If Framestep is enabled, configure registers to work with T1T/Jewel Tag. */
        if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_POS))
        {
            /* Disable parity on TX and enable parity on RX path */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_CLEARREG_MASK(CLIF_TX_FRAME_CONFIG, (uint32_t)(~CLIF_TX_FRAME_CONFIG_TX_PARITY_ENABLE_MASK)));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG_MASK(CLIF_RX_PROTOCOL_CONFIG, CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_ENABLE_MASK));

            /* Enable CRC on both TX and RX path for Jewel */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CRC_TX_CONFIG, (CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK | CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK |
                        (CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_JEWEL << CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_POS))));

            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CRC_RX_CONFIG, (CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK | CLIF_CRC_RX_CONFIG_RX_CRC_INV_MASK |
                        (CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_JEWEL << CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_POS))));

            /* Set TX wait to 29us */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_WAIT, (CLIF_TX_WAIT_TX_WAIT_PRESCALER_JEWEL | (CLIF_TX_WAIT_TX_WAIT_VALUE_JEWEL << CLIF_TX_WAIT_TX_WAIT_VALUE_POS))));
        }

        /* Check if Transceive state machine is in IDLE or > WAITTRANSMIT  */
        bTransceive_State = PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_TRANSCEIVE_STATE_MASK, CLIF_STATUS_TRANSCEIVE_STATE_POS);
        if ((bTransceive_State > TRANSCEIVE_STATE_WAITTRANSMIT) || (bTransceive_State == TRANSCEIVE_STATE_IDLE))
        {
            /* Restart the Transceive state by loading Idle and Transceive command back. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_TRANSCEIVE_CMD));
        }

        /* Configure default value for FDT in case Application has not configured it. */
        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_ConfigFDT());

        if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS))
        {
            /* Register FDT timer callback only incase when RxMultiple is enabled. */
            aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;
        }
        else
        {
           /* Read System config register to return Exchange based on SC Detect IRQ. */
           CLIF_GETREG(SYSTEM_CONFIG, &dwSysConf);

           if(dwSysConf & SYSTEM_CONFIG_VAL)
           {
              /* Register the desired callbacks. */
              aCbHandlers[PN76_CLIFIRQCB_SCDET] = PN76_Clif_CbSCDETIrq;
              /*Enable the SC DET IRQ */
              dwIntEnbReg |= CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_MASK;
           }

            /* Register the desired callbacks. */
            aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
            aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;

            (void)PN76_ReadEeprom((uint8_t *)&dwRxIrqGuardTime,(uint32_t)PN76_RXIRQ_GUARD->dwRXIRQ_GuardTime, sizeof(uint32_t), E_PN76_EEPROM_USER_AREA);

            if (dwRxIrqGuardTime)
            {
                /* Enable the SC DET IRQ when Rx Guard Timer is enabled. */
                dwIntEnbReg |= CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_MASK;

                /* Check if Rx IRQ GuardTimer is not free and
                 * Stop and Release the timer before Requesting Timer once again. */
                if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
                {
                   /* Stop and Release the Rx Guard Timer */
                   TIMER_Stop(&CLIF_RxIrqGuardTimer);
                   TIMER_Release(&CLIF_RxIrqGuardTimer);
                }
                /* Request timer for Rx Guard Timer. */
                eStatus = (PN76_Clif_Status_t)TIMER_Request(&CLIF_RxIrqGuardTimer);

                if (eStatus == PN76_CLIF_STATUS_SUCCESS)
                {
                    /* Configure RX Gard timer */
					#ifdef MCUXPRESSO_SDK
                	eStatus = (PN76_Clif_Status_t)(TIMER_Configure(&CLIF_RxIrqGuardTimer, true, dwRxIrqGuardTime, &PN76_Clif_RxIrqGuardCb, NULL ));
					#else
					eStatus = (PN76_Clif_Status_t)TIMER_Configure(&CLIF_RxIrqGuardTimer, E_TIMER_HAL_INTERRUPTMODE, dwRxIrqGuardTime, &PN76_Clif_RxIrqGuardCb, NULL );
					#endif
                    if (eStatus != PN76_CLIF_STATUS_SUCCESS)
                    {
                       /* Return error if Timer cannot be configured. */
                       eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
                       break;
                    }
                }
                else
                {
                    /* Return error if Timer Request fails. */
                    eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
                    break;
                }
            }
        }

        /* Enable CLIF Interrupts required for Exchange operation. */
        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus,
            (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, dwIntEnbReg));

        /* Clear any existing events that needs to be expected. */
        (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED |
            PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW | PN76_CLIF_EVT_TYPE_TIMER1 |
            PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED | PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED), NULL);

        PN76_SendDataCfg.dwTxLength = (uint32_t)wTxLength;
        PN76_SendDataCfg.bCommand = 0xFF;
        PN76_SendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

        /*Now lets send data */
        STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_SendData(pTxBuffer, &PN76_SendDataCfg));

        /* Wait for event */
        eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
            (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
            (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
            PHOSAL_MAX_DELAY,
            (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW |
            PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
            PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED | PN76_CLIF_EVT_TYPE_ABORTED),
            &dwRecEvents));
        STATUS_BREAK_CLIF_SUCCESS(eStatus);

        if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
        {
            /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

            eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW)) != 0U)
        {
           /* Exit exchange based on SC Detect IRQ. */
           CLIF_GETREG(SYSTEM_CONFIG, &dwSysConf);
           if(dwSysConf & SYSTEM_CONFIG_VAL)
           {
              eStatus = PN76_CLIF_STATUS_SUCCESS;
           }
           else
           {
            dwRx_Status = 0;
            dwRxStatusError = 0;
            dwTransceiveStatus = 0;

#ifndef OPTIMIZATION_REG_MULTIPLE
            /* Get the Rx Status Data reg*/
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS, &dwRx_Status));
            /* Get the Receiver Error Status bits */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwRxStatusError));
            /* Get the Transceive Reg Status */
            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TRANSCEIVE_CONTROL, &dwTransceiveStatus));
#endif /* OPTIMIZATION_REG_MULTIPLE */
#ifdef OPTIMIZATION_REG_MULTIPLE
            awRegAddress[bIndex++] = CLIF_RX_STATUS;
            awRegAddress[bIndex++] = CLIF_RX_STATUS_ERROR;
            awRegAddress[bIndex++] = CLIF_TRANSCEIVE_CONTROL;

            STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_ReadRegisterMultiple(awRegAddress,
                abRegValue, bIndex));

            PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRx_Status, 0);
            PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRxStatusError, 1);
            PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwTransceiveStatus, 2);
#endif /* OPTIMIZATION_REG_MULTIPLE */

            PN76_Clif_GetRxFrame(pRxParams, dwTransceiveStatus, dwRx_Status);

            if ((dwRecEvents & PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW) != 0U)
            {
               /* Received extra bytes by CLIF Receiver. */
               eStatus = PN76_CLIF_STATUS_BUFFER_OVERFLOW;
            }
            else
            {
                eStatus = PN76_Clif_RxError(dwRx_Status, dwRxStatusError);
                if (pRxParams->wRxBytes == 0)
                {
                    if (eStatus == PN76_CLIF_STATUS_SUCCESS)
                    {
                        eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
                    }
                    else
                    {
                        /* Do nothing */
                    }
                }
            }
        }
        }
        else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
                    PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED)) != 0U)
        {
            if ((PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS)) &&
                (dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1)))
            {
               dwRx_Status = 0;
               dwRxStatusError = 0;
               dwTransceiveStatus = 0;

#ifndef OPTIMIZATION_REG_MULTIPLE
               /* Get the Rx Status Data reg*/
               STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS, &dwRx_Status));
               /* Get the Receiver Error Status bits */
               STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwRxStatusError));
               /* Get the Transceive Reg Status */
               STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TRANSCEIVE_CONTROL, &dwTransceiveStatus));
#endif /* OPTIMIZATION_REG_MULTIPLE */
#ifdef OPTIMIZATION_REG_MULTIPLE
               awRegAddress[bIndex++] = CLIF_RX_STATUS;
               awRegAddress[bIndex++] = CLIF_RX_STATUS_ERROR;
               awRegAddress[bIndex++] = CLIF_TRANSCEIVE_CONTROL;

               STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_ReadRegisterMultiple(awRegAddress,
                           abRegValue, bIndex));

               PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRx_Status, 0);
               PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRxStatusError, 1);
               PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwTransceiveStatus, 2);
#endif /* OPTIMIZATION_REG_MULTIPLE */

               PN76_Clif_GetRxFrame(pRxParams, dwTransceiveStatus, dwRx_Status);

               eStatus = PN76_Clif_RxError(dwRx_Status, dwRxStatusError);
               if (pRxParams->wRxBytes == 0)
               {
                   if (eStatus == PN76_CLIF_STATUS_SUCCESS)
                   {
                       eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
                   }
                   else
                   {
                       /* Do nothing */
                   }
               }
            }
            else
            {
                /* Set the transceive state machine to IDLE, so that CLIF IP will be ready to accept next command. */
                STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
                STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
                            CLIF_INT_STATUS_TIMER1_IRQ_MASK));
                if (dwRecEvents & PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED)
                {
                    eStatus = PN76_CLIF_STATUS_TX_FAILURE;
                }
                else
                {
                    eStatus = PN76_CLIF_STATUS_TIMEOUT;
                }
            }
        }
        else
        {
            /* Control should not reach here. */
            eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
        }
    }while(0);

    /* Check Buffer Size of received data against the size of buffer provided by user. */
    if (wRxBufLen >= pRxParams->wRxBytes)
    {
        memcpy(pRxBuffer, clif_rf_rx_buffer, pRxParams->wRxBytes);
    }
    else
    {
        eStatus = PN76_CLIF_STATUS_BUFFER_OVERFLOW;
    }

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_Transmit(uint8_t * pTxBuffer, uint16_t wTxLength)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint8_t            bTransceive_State = 0;
    PN76_SendDataCfg_t PN76_SendDataCfg;
    phOsal_EventBits_t dwRecEvents = 0;

    PN76_SendDataCfg.bCommand = 0;
    PN76_SendDataCfg.dwTxLength = 0;
    PN76_SendDataCfg.fpTxIrqGuardCb = NULL;

    gbTxCompleted = 0;

    do{

#if PHFL_FEAT_PN76XX_P2P_SUPPORT
           uint32_t dwRfReg;
           CLIF_GETREG(CLIF_RF_CONTROL, &dwRfReg);

       /* check for Active mode comm and ext field */
       if(dwRfReg & CLIF_RF_CONTROL_TX_AUTO_RFON_MASK)
       {
          /* In active comm set Initiator mode bit while performing Tx operation. */
//            PH_HALREG_SETBITN(CLIF_TRANSCEIVE_CONTROL_REG, CLIF_TRANSCEIVE_CONTROL_REG_INITIATOR_POS);

          /* Look for RF field if not just turn ON. */
          if (PN76_Clif_CheckActiveIntRf() != PN76_STATUS_SUCCESS)
          {
             eStatus = PN76_CLIF_STATUS_NO_RF_FIELD;
             break;
          }


          aCbHandlers[PN76_CLIFIRQCB_RFACTIVEERR] = PN76_Clif_ActErrIrqHandler;
//          aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
          dwRfReg = CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK;
          /* Enable CLIF Interrupts required for active operation. */
          STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus,
              (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, dwRfReg));

          /* TODO : In case of active initiator do we need to consider enabling FWT i.e. FDT Timer1?? */
       }
       else
#endif
       {
       if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK, CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS))
       {
           /* In Passive Initiator mode, check for Internal RF Field is ON. */
           if (PN76_GetInternalRfField() != PN76_RF_COMM_RF_FIELD_ON)
           {
              eStatus = PN76_CLIF_STATUS_NO_RF_FIELD;
              break;
           }

           /* Configure default value of FDT based on EEPROM value, in case Application has not configured it. */
           STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_ConfigFDT());
       }
       else
       {
          /* In Passive Target mode, check for External RF Field is ON. */
          if ((PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_RF_DET_STATUS_MASK, CLIF_STATUS_RF_DET_STATUS_POS)) == 0U)
          {
              eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
              break;
          }

          aCbHandlers[PN76_CLIFIRQCB_RFOFF_DET] = PN76_Clif_CbRFOFFDETIrq;

          /* Configure the PN76 during Card/Listen mode before Tx operation.
           * Warning: Do not remove this API call. */
          PN76_Sys_BeforeCardModeTx();
       }
       }

       /*Check if transceive state machine is in IDLE or > WAITTRANSMIT  */
       bTransceive_State = PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_TRANSCEIVE_STATE_MASK, CLIF_STATUS_TRANSCEIVE_STATE_POS);
       if ((bTransceive_State != TRANSCEIVE_STATE_WAITTRANSMIT) && (bTransceive_State != TRANSCEIVE_STATE_TRANSMITTING))
       {
          /* Restart the Transceive state by loading Idle and Transceive command back. */
          STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));

          if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK, CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS))
          {
              STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_TRANSCEIVE_CMD));
          }
          else
          {
              /* Control is not expected to reach here in Target mode. */
              return PN76_CLIF_STATUS_INTERNAL_ERROR;
          }
       }

       /* Lets register the desired callbacks */
       aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
       aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;
       aCbHandlers[PN76_CLIFIRQCB_TX] = PN76_Clif_CbTXIrq;

       /* Clear any existing events that needs to be expected. */
       (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED |
           PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW |
           PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED), NULL);

       PN76_SendDataCfg.dwTxLength = (uint32_t)wTxLength;
       PN76_SendDataCfg.bCommand = 0xFF;
       PN76_SendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

       /* Now lets send Tx data */
       STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_SendData(pTxBuffer, &PN76_SendDataCfg));
    }while(0);

    STATUS_CHECK_CLIF_SUCCESS(eStatus);

    /* Wait for event */
    eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
        (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
       (phOsal_EventOpt_t) (E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
        PHOSAL_MAX_DELAY,
        (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED | PN76_CLIF_EVT_TYPE_FLDOFF_EX |
        PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
        PN76_CLIF_EVT_TYPE_ABORTED),
        &dwRecEvents));
    STATUS_CHECK_CLIF_SUCCESS(eStatus);

    if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
    {
       /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
       STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

       eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
    }
    else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_FLDOFF_EX) != 0U)
    {
       eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
    }
    else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED) != 0U)
    {
       eStatus = PN76_CLIF_STATUS_TIMEOUT;
    }
    else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED) != 0U)
    {
       eStatus = PN76_CLIF_STATUS_SUCCESS;
       gbTxCompleted = 1;
    }
    else
    {
       /* Control should not reach here. */
       eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
    }

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_Receive(
    uint8_t * pRxBuffer,
    uint16_t wRxBufLen,
    PN76_Rf_RxParams_t * pRxParams)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
    PN76_Clif_Status_t eStatustmp = PN76_CLIF_STATUS_INTERNAL_ERROR;
    uint8_t            bTransceive_State = 0;
    phOsal_EventBits_t dwRecEvents = 0;
    uint32_t           dwRx_Status = 0U;
    uint32_t           dwRxStatusError = 0U;
    uint32_t           dwTransceiveStatus = 0U;

#ifdef OPTIMIZATION_REG_MULTIPLE
    uint16_t           awRegAddress[3];
    uint8_t            abRegValue[12];
    uint8_t            bIndex = 0;
#endif /* OPTIMIZATION_REG_MULTIPLE */

    /* Reset memory of RxParams */
    memset(pRxParams, 0x00, sizeof(PN76_Rf_RxParams_t));

    do
    {
#if PHFL_FEAT_PN76XX_P2P_SUPPORT
       uint32_t dwRfReg;
       CLIF_GETREG(CLIF_RF_CONTROL, &dwRfReg);

       /* check for Active mode comm and ext field */
       if(!(dwRfReg & CLIF_RF_CONTROL_TX_AUTO_RFON_MASK))
#endif
       {
        if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK, CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS))
        {
            /* In Passive Initiator mode, check for Internal RF field is ON. */
            if (PN76_GetInternalRfField() != PN76_RF_COMM_RF_FIELD_ON)
            {
               eStatus = PN76_CLIF_STATUS_NO_RF_FIELD;
               break;
            }
        }
        else
        {
           /* In Passive Target mode, check for External RF Field is ON. */
           if ((PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_RF_DET_STATUS_MASK, CLIF_STATUS_RF_DET_STATUS_POS)) == 0U)
           {
               eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
               break;
           }
        }
       }

        /* Look pending status of RX IRQ and in Passive Initiator mode, Timer1 IRQ. */
        if (gbTxCompleted == 1)
        {
           /* Wait for event */
           eStatustmp = (PN76_Clif_Status_t)(phOsal_EventPend(
               (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
               (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
               1U,
               (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW |
               PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_FLDOFF_EX |
               PN76_CLIF_EVT_TYPE_ABORTED),
               &dwRecEvents));
           if (eStatustmp == PN76_CLIF_STATUS_SUCCESS)
           {
              if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
              {
                 /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
                 STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

                 eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
              }
              else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW)) != 0U)
              {
                 eStatus = PN76_CLIF_STATUS_SUCCESS;
              }
              else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_FLDOFF_EX) != 0U)
              {
                 eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
              }
              else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_TIMER1) != 0U)
              {
                 eStatus = PN76_CLIF_STATUS_TIMEOUT;
              }
              else
              {
                 /* Control should not reach here. */
                 eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
              }
              gbTxCompleted = 0;
           }
        }

        if (eStatustmp != PN76_CLIF_STATUS_SUCCESS)
        {
           aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
           aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;
           aCbHandlers[PN76_CLIFIRQCB_RFOFF_DET] = PN76_Clif_CbRFOFFDETIrq;

           /* Check if transceive state machine is in IDLE or > WAITTRANSMIT  */
           bTransceive_State = PN76_GetRegisterField(CLIF_STATUS, CLIF_STATUS_TRANSCEIVE_STATE_MASK, CLIF_STATUS_TRANSCEIVE_STATE_POS);
           if ((!((bTransceive_State >= TRANSCEIVE_STATE_WAITRECEIVE) && (bTransceive_State <= TRANSCEIVE_STATE_RECEIVING))))
           {
              /* Restart the Transceive state by loading Idle and Transceive command back. */
              STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));

              STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_TRANSCEIVE_CMD));

              if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK, CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS))
              {
                 STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG_MASK(CLIF_CONTROL, CLIF_TRANSCEIVE_CONTROL_TX_SKIP_SEND_ENABLE_MASK));
              }
           }

           /* Wait for event */
           eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
               (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
              (phOsal_EventOpt_t) (E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
               PHOSAL_MAX_DELAY,
               (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW |
               PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_FLDOFF_EX |
               PN76_CLIF_EVT_TYPE_ABORTED),
               &dwRecEvents));
           STATUS_CHECK_CLIF_SUCCESS(eStatus);

           /* Clear previously occurred unwanted events */
           (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, PN76_CLIF_EVT_TYPE_ALL, NULL);

           if ((dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED) != 0U)
           {
              /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
              STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

              eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
           }
           else if ((dwRecEvents & (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW)) != 0U)
           {
              eStatus = PN76_CLIF_STATUS_SUCCESS;
           }
           else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_FLDOFF_EX) != 0U)
           {
              eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
           }
           else if ((dwRecEvents & PN76_CLIF_EVT_TYPE_TIMER1) != 0U)
           {
              eStatus = PN76_CLIF_STATUS_TIMEOUT;
           }
           else
           {
              /* Control should not reach here. */
              eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
           }
        }
    }while(0);
    STATUS_CHECK_CLIF_SUCCESS(eStatus);

    dwRx_Status = 0;
    dwRxStatusError = 0;
    dwTransceiveStatus = 0;

#ifndef OPTIMIZATION_REG_MULTIPLE
    /* Get the Rx Status Data reg*/
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS, &dwRx_Status));
    /* Get the Receiver Error Status bits */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwRxStatusError));
    /* Get the Transceive Reg Status */
    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TRANSCEIVE_CONTROL, &dwTransceiveStatus));
#endif /* OPTIMIZATION_REG_MULTIPLE */
#ifdef OPTIMIZATION_REG_MULTIPLE
    awRegAddress[bIndex++] = CLIF_RX_STATUS;
    awRegAddress[bIndex++] = CLIF_RX_STATUS_ERROR;
    awRegAddress[bIndex++] = CLIF_TRANSCEIVE_CONTROL;

    STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_ReadRegisterMultiple(awRegAddress,
                abRegValue, bIndex));

    PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRx_Status, 0);
    PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwRxStatusError, 1);
    PN76_READ_REG_MULTIPLE_DWORD(abRegValue, dwTransceiveStatus, 2);
#endif /* OPTIMIZATION_REG_MULTIPLE */

    PN76_Clif_GetRxFrame(pRxParams, dwTransceiveStatus, dwRx_Status);
    if ((dwRecEvents & PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW) != 0U)
    {
       /* Received extra bytes by CLIF Receiver. */
       eStatus = PN76_CLIF_STATUS_BUFFER_OVERFLOW;
    }
    else
    {
        eStatus = PN76_Clif_RxError(dwRx_Status, dwRxStatusError);
        if (pRxParams->wRxBytes == 0)
        {
            if (eStatus == PN76_CLIF_STATUS_SUCCESS)
            {
                eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
            }
            else
            {
                /* Do nothing */
            }
        }
    }

    /* Check Buffer Size of received data against the size of buffer provided by user. */
    if (wRxBufLen >= pRxParams->wRxBytes)
    {
        memcpy(pRxBuffer, clif_rf_rx_buffer, pRxParams->wRxBytes);
    }
    else
    {
        eStatus = PN76_CLIF_STATUS_BUFFER_OVERFLOW;
    }

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_MfcAuth(uint8_t * pKey, PN76_MIFARECryptoKeys_t bKeyType, uint8_t bBlockNo, uint8_t * pUid)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
   PN76_Clif_Status_t eStatustmp = PN76_CLIF_STATUS_SUCCESS;
   uint32_t           dwFdt_Config = 0;
   uint32_t           dwFdt_Reload = 0;
   uint32_t           dwRB2;
   uint32_t           dwUid;

   /* Reset CLIF RX Buffer memory for MFC Auth operation */
   memset(clif_rf_rx_buffer, 0x00, 10);

   /* Reset MIFARE Auth memory for MFC Auth operation */
   memset(aAuthCmdBuffer, 0, (MFC_KEYTYPE_SIZE + MFC_BLKADDR_SIZE + MFC_KEY_SIZE));

   aAuthCmdBuffer[0] = bKeyType;
   aAuthCmdBuffer[1] = bBlockNo;
   memcpy(&aAuthCmdBuffer[2], pUid, MFC_UID_SIZE);

   PN76_READ_DWORD(pUid, dwUid);

   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_MfcSaveState());

   /* Disable Rx CRC */
   CLIF_SETREG(CLIF_CRC_RX_CONFIG, CLIF_CRC_RX_CONFIG__RESET_VALUE);

   /* Here get the FDT configured earlier*/
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_CONFIG, &dwFdt_Config));
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_RELOAD, &dwFdt_Reload));

   do
   {
      dwRB2 = 0;
      eStatustmp = PN76_Clif_MfcAuth1(pKey, aAuthCmdBuffer, dwUid, &dwRB2);
      if(eStatustmp != PN76_CLIF_STATUS_SUCCESS)
      {
         break;
      }

      /* Reset CLIF RX Buffer memory for MFC Auth operation */
      memset(clif_rf_rx_buffer, 0x00, 10);

      eStatustmp = PN76_Clif_MfcAuth2(&dwRB2);
   }while(0);

   if ((eStatustmp == PN76_CLIF_STATUS_SUCCESS) || (eStatustmp == PN76_CLIF_STATUS_TIMEOUT))
   {
      eStatus = eStatustmp;
   }
   else
   {
      /* Return AUTH Error incase of any internal error. */
      eStatus = PN76_CLIF_STATUS_AUTH_ERROR;
   }

   if (eStatus != PN76_CLIF_STATUS_SUCCESS)
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatustmp, (PN76_Clif_Status_t) CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~(SYSTEM_CONFIG_MFC_CRYPTO_ON_MASK))));
   }

   /* Restore back all Register states of INT_Enable, RX_CRC, TX_CRC etc. */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatustmp, PN76_Clif_MfcRestoreState());

   /* Revert back the FDT settings */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatustmp, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_CONFIG, dwFdt_Config));
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatustmp, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TIMER1_RELOAD, dwFdt_Reload));

   return eStatus;
}

void PN76_Clif_CheckAutocollDuringStandby(uint8_t *pbRfTech, PN76_AutocollMode_t *peAutocollMode)
{
   uint32_t dwRegVal;

   *pbRfTech = 0;
   *peAutocollMode = PN76_AUTOCOLL_WITHOUT_AUTONOMOUS_MODE;

   if(CLIF_GETREG(PCRM_SYS_BOOT1_STS, &dwRegVal) != PN76_CLIF_STATUS_SUCCESS)
   {
      return;
   }

   /* Wake up due to external field presence. */
   if(PCRM_SYS_BOOT1_STS_BOOT_LPDET_MASK & dwRegVal)
   {
      CLIF_GETREG(PCRM_GPREG3, &dwRegVal);
      if((dwRegVal) & (PN76_CLIF_AUTOCOLL_MODE_MASK | PN76_CLIF_AUTOCOLL_TECH_MASK))
      {
         *pbRfTech = (uint8_t)(dwRegVal & PN76_CLIF_AUTOCOLL_TECH_MASK);
         *peAutocollMode = (PN76_AutocollMode_t)((dwRegVal & PN76_CLIF_AUTOCOLL_MODE_MASK) >> PN76_CLIF_AUTOCOLL_MODE_POS);
      }
   }
}

#if PHFL_FEAT_ENABLE_TM_NFC_FORUM_WA

PN76_Autocoll_Status gKernelAutocollStatus;
volatile uint16_t gwKernelRxLen;
uint8_t            gaTxBuff[PN76_CLIF_RF_AUTOCOLL_TX_BUFFER_SIZE];
TIMER_ConfigDef_t sAutoTimer;

/* Autocoll timer to schedule autocoll for every 50us */
#define PN76_CLIF_AUTOCOLL_SCHEDULER_TICK_US    50
void autocallTimerCalback(void *vParams)
{
   (void)vParams;
   /* Perform one iteration and check whether the autocoll is still active.  */
   if(PN76_Sys_InternalAutocollResume((uint16_t *)&gwKernelRxLen) == PN76_STATUS_STARTED)
   {
      /* Let the timer re-kick to schedule Autocoll*/
      TIMER_Start(&sAutoTimer);
   }
}
void PN76_Clif_AutocollKickStart(void)
{
   memset(gaTxBuff, 0x00, sizeof(gaTxBuff));
   /* Provide TxBuffer and RxBuffer address along with Buffer size to PN76 Secure FW. */
   (void)PN76_Sys_Configure_ClifBuffers(gaTxBuff, PN76_CLIF_RF_AUTOCOLL_TX_BUFFER_SIZE,
               clif_rf_rx_buffer, PN76_CLIF_RF_RX_MAX_BUFFER_SIZE);
   gbAutocollExeState = true;
   (void)PN76_Sys_InternalAutocollKickStart(0x01, &gKernelAutocollStatus, (uint16_t *)&gwKernelRxLen);
   /* Start Autocoll timer to schedule autocoll for every 50us. */
#ifndef MCUXPRESSO_SDK
   sAutoTimer.dwTimer_Period = PN76_CLIF_AUTOCOLL_SCHEDULER_TICK_US;
   sAutoTimer.eModeInt = E_TIMER_HAL_INTERRUPTMODE;
   sAutoTimer.pcall_back_parameter = NULL;
   sAutoTimer.pcallback_function = &autocallTimerCalback;
   (void)TIMER_Request( &sAutoTimer);
   (void)TIMER_Configure(&sAutoTimer, E_TIMER_HAL_INTERRUPTMODE, PN76_CLIF_AUTOCOLL_SCHEDULER_TICK_US, &autocallTimerCalback, NULL);
   (void)TIMER_Start(&sAutoTimer);
#endif /*MCUXPRESSO_SDK*/
#ifdef MCUXPRESSO_SDK
   sAutoTimer.timerPeriod = PN76_CLIF_AUTOCOLL_SCHEDULER_TICK_US;
   sAutoTimer.enableInterrupt = true;
   sAutoTimer.cbParam = NULL;
   sAutoTimer.callback = &autocallTimerCalback;
   (void)TIMER_Request( &sAutoTimer);
   (void)TIMER_Configure(&sAutoTimer, true, PN76_CLIF_AUTOCOLL_SCHEDULER_TICK_US, &autocallTimerCalback, NULL);
   (void)TIMER_Start(&sAutoTimer);
#endif
}

PN76_Clif_Status_t PN76_Clif_AutocollResumeExit(void)
{
   if((SMU_BOOT_REASON() & PCRM_SYS_BOOT1_STS_BOOT_LPDET_MASK) && (gbAutocollExeState == true))
   {
      TIMER_Stop(&sAutoTimer);
      TIMER_Release(&sAutoTimer);

      /* When Autocoll is under execution, Abort Operation API needs to be executed.  */
       PN76_Sys_AutocollAbort();

       /* Exit Autocoll smoothly */
       (void) PN76_Sys_InternalAutocollResumeBlocking((uint16_t *)&gwKernelRxLen);


       /* Reset the global variable. */
       gbAutocollExeState = false;

       /* Autocoll Force exit. */
       return PN76_CLIF_STATUS_USER_CANCELLED;
   }
   else
   {
      /* Autocoll is not running. */
      return PN76_CLIF_STATUS_SUCCESS;
   }
}

#endif
PN76_Clif_Status_t PN76_Clif_Autocoll(uint8_t bRfTech, PN76_AutocollMode_t eAutocollMode, PN76_Autocoll_Status *pAutocollStatus, uint8_t **ppRxBuffer, uint16_t *pwRxLen)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint32_t           dwAutocollConfig;
   uint8_t            aTxBuff[PN76_CLIF_RF_AUTOCOLL_TX_BUFFER_SIZE] = {0, };
   uint16_t           wReceivedRxLen;
   phOsal_EventBits_t dwRecEvents = 0;

   do{
//      phOsal_ThreadChangePrio(&pRfThreadHandle,PH_OSAL_TASK_PRIORITY_LOW);
#if PHFL_FEAT_ENABLE_TM_NFC_FORUM_WA
      if((SMU_BOOT_REASON() & PCRM_SYS_BOOT1_STS_BOOT_LPDET_MASK) && (gbAutocollExeState == true))
      {
            TIMER_Stop(&sAutoTimer);
            TIMER_Release(&sAutoTimer);

            eStatus = (PN76_Clif_Status_t) PN76_Sys_InternalAutocollResumeBlocking((uint16_t *)&gwKernelRxLen);
            memcpy(pAutocollStatus, &gKernelAutocollStatus, sizeof(gKernelAutocollStatus));
            wReceivedRxLen = gwKernelRxLen;
      }
      else
#endif
      {
         /* Provide TxBuffer and RxBuffer address along with Buffer size to PN76 Secure FW. */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_Configure_ClifBuffers(
             aTxBuff, PN76_CLIF_RF_AUTOCOLL_TX_BUFFER_SIZE,
             clif_rf_rx_buffer, PN76_CLIF_RF_RX_MAX_BUFFER_SIZE));

         gbAutocollExeState = true;

         eStatus = (PN76_Clif_Status_t) PN76_Sys_Autocoll(bRfTech,
                     pAutocollStatus,
                     &wReceivedRxLen);
      }

      gbAutocollExeState = false;

//      phOsal_ThreadChangePrio(&pRfThreadHandle,PH_OSAL_TASK_PRIORITY_HIGHEST);

      if(eStatus == PN76_CLIF_STATUS_SUCCESS)
      {
         *ppRxBuffer = clif_rf_rx_buffer;
         *pwRxLen = wReceivedRxLen;
         break;
      }
      else if(eStatus == PN76_CLIF_STATUS_EXTERNAL_FIELD)
      {
         if(eAutocollMode == PN76_AUTOCOLL_AUTONOMOUS_WITHOUT_STANDBY)
         {
            /* Block on External RF event */
            PN76_Clif_EventConsumeAll();

            /* Disable all CLIF Interrupts that are handled in CLIF HAL. */
            STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_ENABLE,
                (CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK |
                 CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK |
                 CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK)));

            /* Enable CLIF External RF ON Interrupt */
            STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE,
                CLIF_INT_SET_ENABLE_RFON_DET_IRQ_SET_ENABLE_MASK));

            eStatus = (PN76_Clif_Status_t)(phOsal_EventPend(
                (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
                (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
                PHOSAL_MAX_DELAY,
                PN76_CLIF_EVT_TYPE_FLDON_EX,
                &dwRecEvents));
            STATUS_CHECK_CLIF_SUCCESS(eStatus);

            if (dwRecEvents != PN76_CLIF_EVT_TYPE_FLDON_EX)
            {
               /* Received Unexpected event. */
               eStatus = PN76_CLIF_STATUS_INTERNAL_ERROR;
               break;
            }
         }
         else if(eAutocollMode == PN76_AUTOCOLL_AUTONOMOUS_WITH_STANDBY)
         {
            /* Enter standby. */
            dwAutocollConfig = bRfTech & PN76_CLIF_AUTOCOLL_TECH_MASK;
            dwAutocollConfig |= ((uint8_t)eAutocollMode << PN76_CLIF_AUTOCOLL_MODE_POS) & PN76_CLIF_AUTOCOLL_MODE_MASK;
            /* Set gPREG such that will have autocoll configs saved during standby. */
            PCRM_SETFIELD(PCRM_GPREG3, (PN76_CLIF_AUTOCOLL_MODE_MASK | PN76_CLIF_AUTOCOLL_TECH_MASK), dwAutocollConfig);

            /* Set wakeup source as ext RF field. */
            PN76_Sys_PCRM_EnterStandby(E_PN76_PCRM_WAKEUP_SOURCE_RFFIELD, 0x00);

            /* Unable to enter standby. */
            PCRM_SETFIELD(PCRM_GPREG3, (PN76_CLIF_AUTOCOLL_MODE_MASK | PN76_CLIF_AUTOCOLL_TECH_MASK), 0x00);
            eStatus = PN76_CLIF_STATUS_PREVENT_STANDBY;
            break;
         }
         else
         {
            /* Default NON-Autonomous mode. */
            break;
         }
      }
      else
      {
         /* In case of PN76_CLIF_STATUS_BUFFER_OVERFLOW or PN76_STATUS_PARAMETER_ERROR. */
         break;
      }
   }while(1);

   return eStatus;
}

PN76_Clif_Status_t PN76_Clif_LPCD(uint16_t wLPCDWakeupCounter, uint8_t bEnableCalibration, uint32_t *pLpcdRefValue)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_TIMEOUT;
   PN76_Status_t eLpcdStatus = PN76_STATUS_TIMEOUT;
   uint32_t dwRecEvents;

   if (bEnableCalibration == 1)
   {
      /* Perform LPCD Calibration.
       * Need not check return status of LPCD Calibration. */
      (void)PN76_Sys_PCRM_LPCD_Start(E_PN76_LPCD_REFERENCE_BOOT);

      (void)PN76_Sys_PCRM_LPCD_Start(E_PN76_LPCD_MEASUREMENT_BOOT);

      eStatus = PN76_Clif_Wait(PN76_CLIF_TIME_MILLISECONDS, 100);

      /* Read LPCD Reference value */
      *pLpcdRefValue = PN76_Sys_PCRM_GetLpcdReference();

      return eStatus;
   }
   else
   {
      eLpcdStatus = PN76_Sys_PCRM_LPCD_Start(E_PN76_LPCD_MEASUREMENT_BOOT);
      if (eLpcdStatus == PN76_STATUS_TAG_DETECTED)
      {
         eStatus = PN76_CLIF_STATUS_SUCCESS;
      }
      else if (eLpcdStatus == PN76_STATUS_EXTERNAL_FIELD)
      {
         eStatus = PN76_CLIF_STATUS_EXTERNAL_FIELD;
      }
      else
      {
         /* Wait for specific count or for ABORT event */
         eStatus = (PN76_Clif_Status_t)phOsal_EventPend(
                     (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
                      (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
                     wLPCDWakeupCounter,
                     PN76_CLIF_EVT_TYPE_ABORTED,
                     &dwRecEvents);
         if (dwRecEvents & PN76_CLIF_EVT_TYPE_ABORTED)
         {
            eStatus = PN76_CLIF_STATUS_USER_CANCELLED;
         }
      }
   }

   return eStatus;
}

static PN76_Clif_Status_t PN76_Clif_SendData(uint8_t *pbTxBuffer, PN76_SendDataCfg_t *PN76_SendDataCfg)
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
#ifndef OPTIMIZATION_REG_MULTIPLE
   uint32_t           dwTxDataRegVal = 0;
#endif /* OPTIMIZATION_REG_MULTIPLE */
   uint32_t           dwTxIrqGuardTime = 0;
   uint8_t            bOffset = 0;
   uint32_t           dwIntEnbReg = 0;

   /*Clear the pending status of TX, RX, FDT, SC_DET and RF SW IRQ also */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS, (CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_MASK)));

   if(PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK, CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS))
   {
      /* Enable Timer1 in case of initiator. Expected to be configured before send data called */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_ENABLE_MASK));

      gbDigiDelayEn = 0;

      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom(&gbDigiDelayEn,
          (uint32_t)PN76_DIGITAL_DELAY->bDigitalDelay_En,
          0x01U,
          E_PN76_EEPROM_USER_AREA));

      /* Enable digital delay only if enabled in EEPROM. */
      if(gbDigiDelayEn & PN76_DIGITAL_DELAY_FW_ENABLE_MASK)
      {
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_AddDigitalDelay());
      }

      dwIntEnbReg |= CLIF_INT_SET_ENABLE_TIMER1_IRQ_SET_ENABLE_MASK;
   }

#ifndef OPTIMIZATION_REG_MULTIPLE
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TX_DATA_CONFIG, &dwTxDataRegVal));

   dwTxDataRegVal &= ~(CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK);

   /* Set Number of bytes to send */
   dwTxDataRegVal |= (CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK & PN76_SendDataCfg->dwTxLength);

   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_DATA_CONFIG, dwTxDataRegVal));
#endif /* OPTIMIZATION_REG_MULTIPLE */
#ifdef OPTIMIZATION_REG_MULTIPLE
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Sys_WriteRegisterField(
       CLIF_TX_DATA_CONFIG,
       CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK,
       PN76_SendDataCfg->dwTxLength));
#endif /* OPTIMIZATION_REG_MULTIPLE */

   bOffset = ((uint32_t)pbTxBuffer & 3) + ((PN76_SendDataCfg->dwTxLength) % 4);
   if ((bOffset % 4) != 0)
   {
      bOffset = 1;
   }
   else
   {
      bOffset = 0;
   }

   /* Set Tx buffer address (word aligned) */
   /* Set offset */
   /* Set Tx buffer address (word aligned), set offset */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_BM_TX_BUFFER,
               (((uint32_t)pbTxBuffer & 3) << CLIF_BM_TX_BUFFER_TX_HEADER_BYTE_OFFSET_POS) |
               (uint32_t)((((CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK & PN76_SendDataCfg->dwTxLength) / 4) + bOffset) << CLIF_BM_TX_BUFFER_TX_BUFFER_LENGTH_POS) |
               ((((uint32_t)pbTxBuffer >> 2) & CLIF_BM_TX_BUFFER_TX_BUFFER_START_ADDRESS_MASK) << CLIF_BM_TX_BUFFER_TX_BUFFER_START_ADDRESS_POS)));

   (void)PN76_ReadEeprom((uint8_t *)&dwTxIrqGuardTime,
       (uint32_t)PN76_TXIRQ_GUARD->dwTXIRQ_GuardTime,
       sizeof(uint32_t),
       E_PN76_EEPROM_USER_AREA);

   /*Lets start the platform timer to timeout incase TX IRQ does not trigger */
   if (dwTxIrqGuardTime)
   {
      /* Check if Tx IRQ GuardTimer is not free,
       * Stop and Release the timer before Requesting Timer once again. */
      if (!TIMER_IsFree(&CLIF_TxIrqGuardTimer))
      {
         /*Stop and Release the Timer */
         TIMER_Stop(&CLIF_TxIrqGuardTimer);
         TIMER_Release(&CLIF_TxIrqGuardTimer);
      }

      /* Request the timer */
      if( TIMER_Request(&CLIF_TxIrqGuardTimer) != PN76_STATUS_SUCCESS )
      {
         return PN76_CLIF_STATUS_TIMER_ERROR;
      }

      /*Configure the Tx Guard timer */
      if (dwTxIrqGuardTime > TXIRQGUARDTIME_MAX)
      {
         dwTxIrqGuardTime = TXIRQGUARDTIME_MAX;
      }
	  #ifdef MCUXPRESSO_SDK
      if (TIMER_Configure(&CLIF_TxIrqGuardTimer, true, dwTxIrqGuardTime, PN76_SendDataCfg->fpTxIrqGuardCb, NULL ) != kStatus_Success)
	  #else
	  if (TIMER_Configure(&CLIF_TxIrqGuardTimer, E_TIMER_HAL_INTERRUPTMODE, dwTxIrqGuardTime, PN76_SendDataCfg->fpTxIrqGuardCb, NULL ) != PN76_STATUS_SUCCESS)
	  #endif
      {
         /* Release the timer acquired before returning with error. */
         TIMER_Stop(&CLIF_TxIrqGuardTimer);
         TIMER_Release(&CLIF_TxIrqGuardTimer);

         return PN76_CLIF_STATUS_TIMER_ERROR;
      }

      /*Start the Timer */
      TIMER_Start(&CLIF_TxIrqGuardTimer);
   }

   /* If RX MULTIPLE ENABLE is set, then do not enable RX interrupt. */
   if (PN76_GetRegisterField(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS))
   {
      /* Enable required CLIF Interrupt */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, (CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_MASK |
          CLIF_INT_SET_ENABLE_TIMER1_IRQ_SET_ENABLE_MASK | CLIF_INT_SET_ENABLE_RX_BUFFER_OVERFLOW_IRQ_SET_ENABLE_MASK)));

      /* Disable CLIF Interrupt not required */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_ENABLE, CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK));
   }
   else
   {
      /* Enable required CLIF Interrupt */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, (CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_MASK |
          CLIF_INT_SET_ENABLE_RX_IRQ_SET_ENABLE_MASK | CLIF_INT_SET_ENABLE_RX_BUFFER_OVERFLOW_IRQ_SET_ENABLE_MASK | dwIntEnbReg)));

      if (dwIntEnbReg == 0)
      {
          /* Disable CLIF FDT Timer Interrupt in Target Mode. */
          STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_ENABLE, CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK));
      }
   }

   if (PN76_SendDataCfg->bCommand != 0xFF)
   {
      /* Load Transceive command */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD));
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, PN76_SendDataCfg->bCommand));
   }

   /* Enable the Start Send Bit */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, (CLIF_CONTROL_START_SEND_MASK | CLIF_CONTROL_KEEP_CMD)));

   return PN76_CLIF_STATUS_SUCCESS;
}

PN76_Clif_Status_t PN76_Clif_EventWaitAny(uint32_t dwTimeOut, PN76_ClifEventType_t* pReceivedEvents)
{
    return (PN76_Clif_Status_t)(phOsal_EventPend(
        (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
        (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
        dwTimeOut,
        PN76_CLIF_EVT_TYPE_ALL,
        (phOsal_EventBits_t *)pReceivedEvents));
}

void PN76_Clif_EventConsumeAll(void)
{
   /*clear previously occurred unwanted events*/
   (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, PN76_CLIF_EVT_TYPE_ALL, NULL);
}

PN76_Clif_Status_t PN76_Clif_AbortEvent(void)
{
    if (gbAutocollExeState == false)
    {
        /* Posting ABORT Event shall stop all CLIF CMD execution. */
        return (PN76_Clif_Status_t) (phOsal_EventPost(
            &ClifEventObj.EventHandle,
            E_OS_EVENT_OPT_NONE,
            PN76_CLIF_EVT_TYPE_ABORTED,
            NULL));
    }
    else
    {
        /* Reset the global variable. */
        gbAutocollExeState = false;
        /* When Autocoll is under execution, Abort Operation API needs to be executed.  */
        PN76_Sys_AutocollAbort();
        return PN76_CLIF_STATUS_SUCCESS;
    }
}

PN76_Clif_Status_t PN76_Clif_Set_PollGuardTimer(uint16_t wTimerLoadValue)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t           dwTimerLoadValue;

    /* Calculate the CLIF Timer reload value. */
    dwTimerLoadValue =(uint32_t) ( PN76_CLIF_MAX_FREQ / (PN76_CLIF_CONVERSION_US_SEC/100));
    dwTimerLoadValue =(uint32_t) ((wTimerLoadValue * dwTimerLoadValue)/100);

    STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_TimerStart(
        0x00U,
        dwTimerLoadValue,
        0));

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_PCD_GetExchgFdt(uint32_t *pFdtUs, uint8_t bTimeoutUnit, uint8_t bTimerDeviation)
{
    PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t dwTimer1Output;
    uint32_t dwTimer1Reload;
    uint32_t dwTmp;
    float32_t fTime = 0;

    /* Read Timer1 output register to get 20bit counter value */
    STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_OUTPUT, &dwTimer1Output));
    dwTimer1Output = dwTimer1Output & CLIF_TIMER1_OUTPUT_T1_VALUE_MASK;

    /* Get T1 reload value */
    STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TIMER1_RELOAD, &dwTimer1Reload));
    dwTimer1Reload = dwTimer1Reload & CLIF_TIMER1_RELOAD_T1_RELOAD_VALUE_MASK;

    /* Subtract reload- and counter values */
    dwTmp = dwTimer1Reload - dwTimer1Output;

    if(bTimeoutUnit == PN76_CLIF_TIME_MICROSECONDS)
    {
        fTime = ((dwTmp / 13.56) - 9.44 /* 1 ETU */);
    }
    else
    {
        fTime = (PN76_CLIF_MIN_FREQ  / PN76_CLIF_CONVERSION_MS_SEC);

        fTime = ((dwTmp / (fTime / 1000U)));

        /* Subtract obtained PICC response time with platform timer deviation percentage */
        fTime -= ((fTime * bTimerDeviation) / 100);
    }

    /* Return the value */
    *pFdtUs = (uint32_t)fTime;
    if ((float32_t)*pFdtUs < fTime)
    {
        ++(*pFdtUs);
    }

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_Wait(
                                  PN76_ClifTimerUnits_t bUnit,
                                  uint16_t wTimeout
                                  )
{
    PN76_Clif_Status_t  eStatus;
    uint32_t   dwLoadValue;
    uint32_t   wPrescaler;
    uint32_t   wFreq;

    /* Parameter check */
    if ((bUnit != PN76_CLIF_TIME_MICROSECONDS) && (bUnit != PN76_CLIF_TIME_MILLISECONDS))
    {
        return PN76_CLIF_STATUS_PARAMETER_ERROR;
    }

    /* If time-out value is zero, there is no wait needed */
    if (wTimeout == 0U)
    {
        return PN76_CLIF_STATUS_SUCCESS;
    }

    do
    {
        /* Setting the Prescaler frequency according to wTimeout */
        if (bUnit == PN76_CLIF_TIME_MILLISECONDS)
        {
            wFreq = PN76_CLIF_MIN_FREQ;
            wPrescaler = 0x3CU;
            while(wTimeout > PN76_CLIF_MAX_TIME_DELAY_MS)
            {
                wTimeout -= PN76_CLIF_MAX_TIME_DELAY_MS;
                /* Calculating the load value */
                dwLoadValue =(uint32_t) (PN76_CLIF_MAX_TIME_DELAY_MS * ( wFreq  / PN76_CLIF_CONVERSION_MS_SEC) );
                STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_TimerStart(
                    wPrescaler,
                    dwLoadValue,
                    1));
            }

            dwLoadValue =(uint32_t) (  wTimeout * ( wFreq  / PN76_CLIF_CONVERSION_MS_SEC) );
        }
        else
        {
            /* Here wTimeout will be in uS and not be Zero */
            wFreq = PN76_CLIF_MAX_FREQ;
            wPrescaler = 0x00U;
            /* Reducing the division by 2 digits to retain the 2 digit decimal places which were getting wiped out */
            dwLoadValue =(uint32_t) ( wFreq / (PN76_CLIF_CONVERSION_US_SEC/100));
            /* Restoring the division done in the earlier step */
            dwLoadValue =(uint32_t) ((wTimeout * dwLoadValue)/100);
        }

        eStatus = PN76_Clif_TimerStart(
            wPrescaler,
            dwLoadValue,
            1);
        STATUS_CHECK_CLIF_SUCCESS(eStatus);
    }while(0);

    return eStatus;
}

PN76_Clif_Status_t PN76_Clif_ReadRegister(uint16_t wRegister, uint32_t *pValue)
{
   PN76_Clif_Status_t status = PN76_CLIF_STATUS_SUCCESS;

   *pValue = PN76_Sys_ReadRegister(wRegister);

   if(*pValue == 0xABBADEADUL)
   {
      status = PN76_CLIF_STATUS_PARAMETER_ERROR;
   }

   return status;
}

PN76_Clif_Status_t PN76_Clif_DeInit()
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Perform CLIF DeInit to reset globals and stop timers and load IDLE CMD to CLIF_CONTROL Register. */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_Int_DeInit());

   /* Perform CLIF De-Initialization. */
   PN76_Sys_Clif_DeInit();

   /* Delete CLIF event. */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus,(PN76_Clif_Status_t)(phOsal_EventDelete(&ClifEventObj.EventHandle)));

   return eStatus;
}

/* Clif IRQ handler  */
#ifdef MCUXPRESSO_SDK
void CLIF_DriverIRQHandler(void)
#else
void CLIF_Isr(void)
#endif
{
   uint32_t dwClifIntStatus = 0;
   uint32_t dwClifIntEnable = 0;
   uint32_t dwRfRecvStatus = 0x00U;
   uint32_t dwSysConf = 0;

   /* Read Clif interrupt enable and status registers. */
   (void)CLIF_GETREG(CLIF_INT_ENABLE, &dwClifIntEnable);
   (void)CLIF_GETREG(CLIF_INT_STATUS, &dwClifIntStatus);

   dwClifIntStatus &=dwClifIntEnable;

   /* Clear Clif interrupt status */
   (void)CLIF_SETREG(CLIF_INT_CLR_STATUS, dwClifIntStatus);

   /* Revert the Timer Reload value with User configuration by subtracting Digital Delay */
   if (dwClifIntStatus & (CLIF_INT_STATUS_RX_IRQ_MASK | CLIF_INT_STATUS_TIMER1_IRQ_MASK))
   {
      if(gbDigiDelayEn & PN76_DIGITAL_DELAY_FW_ENABLE_MASK)
      {
         gbDigiDelayEn = 0;
         /* Restore timer reload value */
         (void)CLIF_GETREG(CLIF_TIMER1_CONFIG, &dwRfRecvStatus);

         if((dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK) &&
                     (dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK) &&
                     ((dwRfRecvStatus & CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_MASK) == 0))
         {
            CLIF_SETREG(CLIF_TIMER1_RELOAD, gdwReloadBackup);
         }
      }
   }

   if (dwClifIntStatus & CLIF_INT_STATUS_RX_SC_DET_IRQ_MASK)
   {
      /*Lets clear the status stored in the variable and handle the interrupt*/
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RX_SC_DET_IRQ_MASK);


      /* Read System config register to return Exchange based on SC Detect IRQ. */
      CLIF_GETREG(SYSTEM_CONFIG, &dwSysConf);

      if(dwSysConf & SYSTEM_CONFIG_VAL)
      {
        if (aCbHandlers[PN76_CLIFIRQCB_SCDET])
        {
          aCbHandlers[PN76_CLIFIRQCB_SCDET]();
        }
      }

      else
      {
       /*Lets start the Platform timer after sc detection. The timer will be stopped on RX else send out error code on expiration */
       if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
       {
        /*Start the Timer */
        (void)TIMER_Start(&CLIF_RxIrqGuardTimer);
       }
      }
   }

   if (dwClifIntStatus & CLIF_INT_STATUS_RX_SOF_DET_IRQ_MASK)
   {
      /*Lets clear the status stored in the variable and handle the interrupt*/
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RX_SOF_DET_IRQ_MASK);
   }

   /* TX IRQ. */
   if(CLIF_INT_STATUS_TX_IRQ_MASK & dwClifIntStatus)
   {
      /*Lets clear the status stored in the variable and handle the interrupt*/
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_TX_IRQ_MASK);

      (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK);

      if (!TIMER_IsFree(&CLIF_TxIrqGuardTimer))
      {
         /*Stop and Release the Timer */
         TIMER_Stop(&CLIF_TxIrqGuardTimer);
         TIMER_Release(&CLIF_TxIrqGuardTimer);
      }

      if (aCbHandlers[PN76_CLIFIRQCB_TX])
      {
         aCbHandlers[PN76_CLIFIRQCB_TX]();
      }
   }

   if(CLIF_INT_STATUS_RFOFF_DET_IRQ_MASK & dwClifIntStatus)
   {
      /* Lets clear the status stored in the variable and handle the interrupt*/
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RFOFF_DET_IRQ_MASK);

      if (aCbHandlers[PN76_CLIFIRQCB_RFOFF_DET])
      {
         aCbHandlers[PN76_CLIFIRQCB_RFOFF_DET]();
      }
   }

   if(CLIF_INT_STATUS_RFON_DET_IRQ_MASK & dwClifIntStatus)
   {
      /* Send External RF ON event */
      (void)phOsal_EventPost(
          &ClifEventObj.EventHandle,
          E_OS_EVENT_OPT_POST_ISR,
          PN76_CLIF_EVT_TYPE_FLDON_EX,
          NULL);
   }

   if(CLIF_INT_STATUS_RF_ACTIVE_ERROR_IRQ_MASK & dwClifIntStatus)
   {
      /* Need to handle for Active Mode Communication */
   }

   if(CLIF_INT_STATUS_RX_IRQ_MASK & dwClifIntStatus)
   {
      /* Lets clear the status stored in the variable and handle the interrupt */
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RX_IRQ_MASK);

      /* Lets also disable the RX, TIMER1, SOF_DET  and SC_DET interrupts */
      (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK));

      if (aCbHandlers[PN76_CLIFIRQCB_RX])
      {
          aCbHandlers[PN76_CLIFIRQCB_RX]();
      }
   }

   if(CLIF_INT_STATUS_RX_BUFFER_OVERFLOW_IRQ_MASK & dwClifIntStatus)
   {
      /* Lets clear the status stored in the variable and handle the interrupt */
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RX_BUFFER_OVERFLOW_IRQ_MASK);

      /* Lets also disable the RX, RX Bufferoverflow, TIMER1, SOF_DET and SC_DET interrupts */
      (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_RX_BUFFER_OVERFLOW_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK));

      /* Post RX Bufferover error event */
      (void)phOsal_EventPost(
          &ClifEventObj.EventHandle,
          E_OS_EVENT_OPT_POST_ISR,
          PN76_CLIF_EVT_TYPE_RECEIVE_BUFFER_OVERFLOW,
          NULL);
   }

   if(CLIF_INT_STATUS_TIMER1_IRQ_MASK & dwClifIntStatus)
   {
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_TIMER1_IRQ_MASK);

      /* Lets also disable the RX, TIMER1, SOF_DET  and SC_DET interrupts */
      (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK |
                  CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK));

      if (aCbHandlers[PN76_CLIFIRQCB_FDT])
      {
          aCbHandlers[PN76_CLIFIRQCB_FDT]();
      }
   }

   if(CLIF_INT_STATUS_CTS_IRQ_MASK & dwClifIntStatus)
   {
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_CTS_IRQ_MASK);
   }

   if (CLIF_INT_STATUS_TIMER0_IRQ_MASK & dwClifIntStatus)
   {
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_TIMER0_IRQ_MASK);

      /* Lets also disable the TIMER0 interrupts */
      (void)CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_MASK));

      if (aCbHandlers[PN76_CLIFIRQCB_TIMER0])
      {
          aCbHandlers[PN76_CLIFIRQCB_TIMER0]();
      }
   }

#if PHFL_FEAT_PN76XX_P2P_SUPPORT
   if (CLIF_INT_STATUS_RF_ACTIVE_ERROR_IRQ_MASK & dwClifIntStatus)
   {
      dwClifIntStatus = dwClifIntStatus & (~CLIF_INT_STATUS_RF_ACTIVE_ERROR_IRQ_MASK);

      if (aCbHandlers[PN76_CLIFIRQCB_RFACTIVEERR])
      {
          aCbHandlers[PN76_CLIFIRQCB_RFACTIVEERR]();
      }
   }
#endif
}

/////////////////////////////////////////////////////////////////////////////////////////////////////
// ISO18000p3m3 implementation
/////////////////////////////////////////////////////////////////////////////////////////////////////

PN76_Clif_Status_t PN76_Clif_EpcGen2Inventory(
            uint8_t *pCmdData,
            uint32_t dwCmdLen,
            uint8_t *pRspData,
            uint16_t *pwRspLen )
{
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint16_t              wBufIndex = 0;
   uint16_t              nSizeTagInvInfo = 0;
   uint8_t *             pbuf = (uint8_t*)0;

   if( pCmdData[0] == 0x00)
   {
      eStatus = PN76_Clif_Epc_ActivateCard(pCmdData, dwCmdLen);
   }
   else if(pCmdData[0] == 0x01)
   {
      eStatus = PN76_Clif_Epc_ResumeActivation();
   }
   else
   {
      eStatus = PN76_CLIF_STATUS_SYNTAX_ERROR;
   }

   wBufIndex = 0;
   *pwRspLen = wBufIndex;
//   pRspData[wBufIndex++] = 0x00;
   if( eStatus == PN76_CLIF_STATUS_SUCCESS )
   {
      // copy the data present in the epc
      PN76_Clif_Epc_TagInventoryInfo( &nSizeTagInvInfo, &pbuf);
//      pRspData[wBufIndex++] = 0x00; //((nSizeTagInvInfo + 1) >> 8) & 0xFF;
//      pRspData[wBufIndex++] = 0x00; //((nSizeTagInvInfo + 1)) & 0xFF;
//      pRspData[wBufIndex++] = PN76_CLIF_STATUS_SUCCESS;
      memcpy( &(pRspData[wBufIndex]), pbuf, nSizeTagInvInfo );
      wBufIndex += nSizeTagInvInfo;
      *pwRspLen = wBufIndex;
   }
   return eStatus;
}


static uint8_t * PN76_Clif_Epc_Rf_GetTxBuffer( void )
{
   return &g_baEpc_RfTxBuffer[0];
}

static void PN76_Clif_Epc_Config(uint8_t cfg_type,
            uint8_t start_symbol,
            uint8_t tx_crc,
            uint8_t rx_crc)
{

   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   if(rx_crc)
   {
      if (PN76_EPC_CRC5 == cfg_type)
      {
         /* selects CRC-5 algorithm for EPC Mode 3 */
         CLIF_SETFIELD(CLIF_CRC_RX_CONFIG,
                     (CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_MASK | CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK | CLIF_CRC_RX_CONFIG_RX_CRC_INV_MASK),
                     (PN76_EPC_CRC_RX_CFG_E3_CRC5 << CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_POS) | (CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK) );
      }
      else
      {
         CLIF_SETFIELD(CLIF_CRC_RX_CONFIG,
                     ( CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_MASK | CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK | CLIF_CRC_RX_CONFIG_RX_CRC_INV_MASK),
                     (PN76_EPC_CRC_RX_CFG_E3_CRC16 << CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_POS) | (CLIF_CRC_RX_CONFIG_RX_CRC_INV_MASK));
      }
   }
   else
   {
      CLIF_SETREG(CLIF_CRC_RX_CONFIG, 0x00);
   }

   if(tx_crc)
   {
      if (PN76_EPC_CRC5 == cfg_type)
      {
         CLIF_SETFIELD(CLIF_CRC_TX_CONFIG,
                     (CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_MASK | CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK | CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK),
                     (PN76_EPC_CRC_TX_CFG_E3_CRC5 << CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_POS) | (CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK));
      }
      else
      {
         CLIF_SETFIELD(CLIF_CRC_TX_CONFIG,
                     (CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_MASK | CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK | CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK),
                     (PN76_EPC_CRC_TX_CFG_E3_CRC16 << CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_POS) | (CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK));
      }
   }
   else
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT_NORETVAL(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CRC_TX_CONFIG, 0x00));
   }

   STATUS_CHECK_CLIF_SUCCESS_FCT_NORETVAL(eStatus, (PN76_Clif_Status_t) CLIF_SETFIELD(CLIF_CRC_TX_CONFIG,CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK, tx_crc));
   STATUS_CHECK_CLIF_SUCCESS_FCT_NORETVAL(eStatus, (PN76_Clif_Status_t)CLIF_SETFIELD(CLIF_CRC_RX_CONFIG,CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK, rx_crc));

   CLIF_SETFIELD(CLIF_TX_FRAME_CONFIG,
              CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_MASK,
              start_symbol << CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_POS);
   return ;
}


static PN76_Clif_Status_t PN76_Clif_Epc_Tx_Prologue_Before_Send( uint8_t bRxGuardTimerEnable,
            uint8_t  bNumValidBits )
{

   uint32_t dwWaitTime = 0;
   uint32_t dwRxIrqGuardTime = 0;
   uint32_t dwTxDataRegVal = 0;
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;


   (void)PN76_ReadEeprom((uint8_t *)&dwWaitTime, (uint32_t)&PN76_ISO18000_CFG->wFdt_18000_DefVal, sizeof(uint16_t), E_PN76_EEPROM_USER_AREA);
   if( dwWaitTime < EPC_TX_RX_TIMEOUT)
   {
      dwWaitTime = EPC_TX_RX_TIMEOUT;
   }

   /** initialize the CLIF callbacks for ISO18000 */
   aCbHandlers[PN76_CLIFIRQCB_RX] = PN76_Clif_CbRXIrq;
   aCbHandlers[PN76_CLIFIRQCB_FDT] = PN76_Clif_CbFDTIrq;
   aCbHandlers[PN76_CLIFIRQCB_TX] = PN76_Clif_CbTXIrq;

   /*Clear the pending status of TX, RX, FDT, SC_DET, SOF_DET. */
   STATUS_BREAK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_CLR_STATUS,
               (CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_MASK |
               CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_MASK | CLIF_INT_CLR_STATUS_RX_BUFFER_OVERFLOW_IRQ_CLR_STATUS_MASK)));

   /* Clear any existing events that needs to be expected. */
   (void)phOsal_EventClear(&ClifEventObj.EventHandle, E_OS_EVENT_OPT_NONE, (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED |
       PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
       PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED), NULL);

   /** Set TX_WAIT register value */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_WAIT, 0x207F));

   /** configure CLIF_TIMER1 */
   CLIF_SETREG(CLIF_TIMER1_RELOAD, dwWaitTime);
   CLIF_SETREG(CLIF_TIMER1_CONFIG, ( CLIF_TIMER1_CONFIG_T1_ENABLE_MASK
                                             | E_PH_HAL_RFTIMER_START_ON_TX_ENDED
                                             | E_PH_HAL_RFTIMER_STOP_ON_RX_STARTED
                                             | E_PH_HAL_RFTIMER_PRESCALER_ENABLED
                                             | E_PH_HAL_RFTIMER_PRESCALER_1_128 ));
   CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, ~(CLIF_TIMER1_CONFIG_T1_RELOAD_ENABLE_MASK));

   gbDigiDelayEn = 0;

   /** check if digital delay config enabled and setup for additional digital delay */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_ReadEeprom(&gbDigiDelayEn,
       (uint32_t)PN76_DIGITAL_DELAY->bDigitalDelay_En,
       0x01U,
       E_PN76_EEPROM_USER_AREA));

   /* Enable digital delay only if enabled in EEPROM. */
   if(gbDigiDelayEn & PN76_DIGITAL_DELAY_FW_ENABLE_MASK)
   {
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, PN76_Clif_AddDigitalDelay());
   }

   /** setup the RXGuard timer if enabled */
   if( bRxGuardTimerEnable == TRUE )
   {
      (void)PN76_ReadEeprom((uint8_t *)&dwRxIrqGuardTime,(uint32_t)PN76_RXIRQ_GUARD->dwRXIRQ_GuardTime, sizeof(uint32_t), E_PN76_EEPROM_USER_AREA);

      if (dwRxIrqGuardTime)
      {
         /*Enable the SC DET IRQ */
         STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_INT_SET_ENABLE, CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_MASK));

         /* Check if Rx IRQ GuardTimer is not free and
          * Stop and Release the timer before Requesting Timer once again. */
         if (!TIMER_IsFree(&CLIF_RxIrqGuardTimer))
         {
            /* Stop and Release the Rx Guard Timer */
            TIMER_Stop(&CLIF_RxIrqGuardTimer);
            TIMER_Release(&CLIF_RxIrqGuardTimer);
         }

         /*Request timer */
         eStatus = (PN76_Clif_Status_t)TIMER_Request(&CLIF_RxIrqGuardTimer);

         if (eStatus == PN76_CLIF_STATUS_SUCCESS)
         {
            /*Configure RX Gard timer */
        	eStatus = (PN76_Clif_Status_t)(TIMER_Configure(&CLIF_RxIrqGuardTimer, true, dwRxIrqGuardTime, &PN76_Clif_RxIrqGuardCb, NULL ));
            if (eStatus != PN76_CLIF_STATUS_SUCCESS)
            {
               eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
               STATUS_CHECK_CLIF_SUCCESS(eStatus);
            }
         }
         else
         {
            eStatus = PN76_CLIF_STATUS_TIMER_ERROR;
            STATUS_CHECK_CLIF_SUCCESS(eStatus);
         }
      }
   }

   /* Set bNumValidBits */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_GETREG(CLIF_TX_DATA_CONFIG, &dwTxDataRegVal));

   dwTxDataRegVal &= ~(CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK | CLIF_TX_DATA_CONFIG_TX_LAST_BITS_MASK);

   /* Set Number of bytes to send */
   dwTxDataRegVal |= (( (uint32_t)bNumValidBits << CLIF_TX_DATA_CONFIG_TX_LAST_BITS_POS) & CLIF_TX_DATA_CONFIG_TX_LAST_BITS_MASK);

   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_DATA_CONFIG, dwTxDataRegVal));

   return eStatus;
}



static PN76_Clif_Status_t PN76_Clif_Epc_TxRxWaitIRQ( uint8_t rx_wait )
{
    PN76_Clif_Status_t  estatus = PN76_CLIF_STATUS_SUCCESS;
    uint32_t dwCrcTxCfg;
    uint32_t dwClifIntStat;
    uint32_t dwClifStat;
    uint32_t dwClifStatErr;
    uint32_t dwRecEvents;

    /** Wait until TX Ended or FDT (Timer1) or TX Guard TIMER events are set */
    estatus = (PN76_Clif_Status_t)phOsal_EventPend(
        (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
        (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
        PHOSAL_MAX_DELAY,
        (PN76_CLIF_EVT_TYPE_TRANSMIT_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
        PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED |
        PN76_CLIF_EVT_TYPE_ABORTED),
        &dwRecEvents);
    STATUS_BREAK_CLIF_SUCCESS(estatus);

    if( dwRecEvents & (PN76_CLIF_EVT_TYPE_TIMER1 | PN76_CLIF_EVT_TYPE_TX_GUARD_TIMER_ELAPSED | PN76_CLIF_EVT_TYPE_ABORTED) )
    {
        /* if FDT or TX_GUARD timer timed out */
        /* Set the transceive state machine to IDLE such that CLIF IP will be ready to accept next command. */
        CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_IDLE_CMD);
        estatus = PN76_CLIF_STATUS_TIMEOUT;
    }

    if (( rx_wait ) && (PN76_CLIF_STATUS_SUCCESS == estatus))
    {
       /** TX is done and waiting for RX IRQ */
       /** Wait until RX or FDT (Timer1) or TX Guard TIMER events are set */
       estatus = (PN76_Clif_Status_t)phOsal_EventPend(
           (volatile phOsal_Event_t *)(&ClifEventObj.EventHandle),
            (phOsal_EventOpt_t)(E_OS_EVENT_OPT_PEND_SET_ANY | E_OS_EVENT_OPT_PEND_CLEAR_ON_EXIT),
           PHOSAL_MAX_DELAY,
           (PN76_CLIF_EVT_TYPE_RECEIVE_ENDED | PN76_CLIF_EVT_TYPE_TIMER1 |
            PN76_CLIF_EVT_TYPE_RX_GUARD_TIMER_ELAPSED |
           PN76_CLIF_EVT_TYPE_ABORTED),
           &dwRecEvents);
       STATUS_BREAK_CLIF_SUCCESS(estatus);

       /* Check for timeout */
       if( !(dwRecEvents & PN76_CLIF_EVT_TYPE_RECEIVE_ENDED) )
       {
           /*
            * In case of timeout when CRC5 is set and enabled indicating BeginRound or Next Slot Command,
            * the presence of SOF_DET_IRQ along with either of SOF detected bit\collision detected bit or
            *  EMD irq will be treated as collision error
            */
           CLIF_GETREG(CLIF_CRC_TX_CONFIG, &dwCrcTxCfg);
           CLIF_GETREG(CLIF_INT_STATUS, &dwClifIntStat);
           CLIF_GETREG(CLIF_STATUS, &dwClifStat);
           CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifStatErr);

           if((dwCrcTxCfg & CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK) &&
              (dwCrcTxCfg & CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK) &&
              (dwClifIntStat & CLIF_INT_STATUS_RX_SOF_DET_IRQ_MASK) &&

              (  (dwClifStat & CLIF_STATUS_RX_SOF_DETECTED_MASK) ||
                 (dwClifStatErr & CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK) ||
                 (dwClifIntStat & CLIF_INT_STATUS_RX_EMD_IRQ_MASK) ))
           {
              estatus = PN76_CLIF_STATUS_COLLISION_ERROR;
           }
           else
           {
              /* TIMEOUT */
              estatus = PN76_CLIF_STATUS_TIMEOUT;
           }
       }
   }

    if(!rx_wait)
    {
       /* Stop the FDT Timer if RX is not required */
       CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_ENABLE_MASK);
    }

    /* Disable the Reload Enable of the Timer */
    CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, ~CLIF_TIMER1_CONFIG_T1_RELOAD_ENABLE_MASK);
    return estatus;
}

/*********************************************************************************************************************/
/*   SELECT COMMAND                                                                                                  */
/*********************************************************************************************************************/

static PN76_Clif_Status_t PN76_Clif_Epc_Select( uint8_t *pbParam,
            uint8_t bSelCmdLen,
            uint8_t bNumValidBits)
{
   /* Return status */
   PN76_SendDataCfg_t clifSendDataCfg;
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t  *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   PN76_Clif_Status_t eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Set TX_WAIT to 0 */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_WAIT, 0x00));

   /* Build Select Frame */
   memcpy( pbEpcCmdBuffer, pbParam , bSelCmdLen);

   /* Enable the CRC16 for RX/TX to the below sent Frame */
   /* resets to default - "frame-sync" as SOF */
   PN76_Clif_Epc_Config(PN76_EPC_CRC16,START_SYMBOL_FRAME_SYNC,TRUE,FALSE);

   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(FALSE, bNumValidBits));

   /* Transmit the Select Frame */
   clifSendDataCfg.dwTxLength = bSelCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed, since there is no response to the
   * Select Command need not wait for the reception */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( FALSE );

   /* Reset the State-Machine to Idle */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));

   return epc_status;
}

/*********************************************************************************************************************/
/*   BEGIN-ROUND COMMAND                                                                                             */
/*********************************************************************************************************************/

static PN76_Clif_Status_t PN76_Clif_Epc_BeginRound( uint8_t *pbParam ,
            uint8_t *pbSession,
            uint8_t *pbQInfo,
            uint8_t *pbStoredCrc)
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint8_t                *pbResponse = NULL;
   uint32_t               dwResponseLen=0;
   uint8_t                bBufferIndex = 0;
   uint8_t                bNumValidBits = 0;
   uint16_t               wEpcCmdLen = 0;
   PN76_Clif_Status_t     eStatus = PN76_CLIF_STATUS_SUCCESS;
   uint32_t               dwClifRxStat;

   /* Build BeginRound Frame */

   /* Get the number of valid bits in the last byte */
   bNumValidBits = (uint8_t)(PN76_EPC_BR_LEN % BYTE_SIZE);

   /* Set the command length in bytes */
   wEpcCmdLen = (PN76_EPC_BR_LEN >> 3) + 1;

   memcpy( pbEpcCmdBuffer, pbParam , wEpcCmdLen);

   /* Enable the CRC5 for TX/RX to the below sent Frame */
   /* selects "preamble" as SOF for BeginRound command */
   PN76_Clif_Epc_Config(PN76_EPC_CRC5,START_SYMBOL_PREAMBLE, TRUE, TRUE);

   /* Store the Time Session Information */
   *pbSession = (pbEpcCmdBuffer[1] & PN76_EPC_BR_SESSION_MASK)
   >> PN76_EPC_BR_SESSION_POS;

   /* Set the Tx_Wait of 150us + 10us delta */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_TX_WAIT, BEGINROUND_TX_WAIT));

   /* Store the Time Slot Information */
   *pbQInfo = (pbEpcCmdBuffer[2] >> 7) | (( pbEpcCmdBuffer[1] & 0x07 ) << 1);

   /* Setup Clif config including all timing params */
#ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
#endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(TRUE, bNumValidBits));

   /* Send the command and data */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed and the Response to the Command */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( TRUE );

   if (PN76_CLIF_STATUS_SUCCESS == epc_status)
   {
      CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
      if(dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK
                           | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK
                           | CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_MASK))
      {
         //dwResponseLen = 0;
         epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
      }
      else
      {
         epc_status = PN76_Clif_RxData(&dwResponseLen);
         if((dwResponseLen == PN76_EPC_CRC_LEN) && (PN76_CLIF_STATUS_SUCCESS == epc_status))
         {
            bBufferIndex = 0;
            pbResponse = (uint8_t*) &clif_rf_rx_buffer[0];
            /* Store the StoredCRC Information */
            pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
            bBufferIndex++;
            pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
         }
         else
         {
            epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
         }
      }
   }

   /* Reset the State-Machine to Idle */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));

   CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
   if( dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK))
   {
      epc_status = PN76_CLIF_STATUS_COLLISION_ERROR;
   }

   return epc_status;
}


/*********************************************************************************************************************/
/*   ACK COMMAND                                                                                                     */
/*********************************************************************************************************************/
static PN76_Clif_Status_t PN76_Clif_Epc_Ack(uint8_t *pbParam,
            uint8_t *pbTagResponse,
            uint8_t *pbTagRespLen,
            uint8_t *pbTagNvb )
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint32_t               dwResponseLen=0;
   uint8_t                bBufferIndex = 0;
   uint8_t                bNumValidBits = 0;
   uint16_t               wEpcCmdLen = 0;
   uint32_t               dwClifRxStat;
   PN76_Clif_Status_t     eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Get the number of valid bits in the last byte */
   bNumValidBits = (uint8_t)(PN76_EPC_ACK_LEN % BYTE_SIZE);

   /* Build ACK Frame */
   pbEpcCmdBuffer[wEpcCmdLen++] = (E_PN76_RF_PROT_I_EPC_CMD_ACK << (BYTE_SIZE - PN76_EPC_ACK_CMD_LEN))
                                | (pbParam[bBufferIndex] >> 2);
   pbEpcCmdBuffer[wEpcCmdLen++] = (pbParam[bBufferIndex] << 6) | (pbParam[bBufferIndex+1] >> 2);
   pbEpcCmdBuffer[wEpcCmdLen++] = ((pbParam[bBufferIndex+1] & 0x03) << 6);

   /* Set the command length in bytes */
   wEpcCmdLen = (PN76_EPC_ACK_LEN >> 3) + 1;

   /* Disable the CRC5 for RX and for TX to the below sent Frame */
   /* resets to default - "frame-sync" as SOF */
   PN76_Clif_Epc_Config(PN76_EPC_CRC16, START_SYMBOL_FRAME_SYNC, FALSE, FALSE);


   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   eStatus = (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(TRUE, bNumValidBits);
   if( eStatus != PN76_CLIF_STATUS_SUCCESS)
   {
      dwResponseLen = 0;
      *pbTagRespLen = (uint8_t) dwResponseLen;
      return eStatus;
   }

   /* Send the command and data */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed and the Response to the Command */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( TRUE );

   if (PN76_CLIF_STATUS_SUCCESS == epc_status)
   {
      CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
      if( dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK
                           | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK
                           | CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_MASK))
      {
         dwResponseLen = 0;
         epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
      }
      else
      {
         epc_status = PN76_Clif_RxData(&dwResponseLen);

         if(( dwResponseLen ) && (PN76_EPC_TAG_DATA_MAX_LEN >= dwResponseLen) && (PN76_CLIF_STATUS_SUCCESS == epc_status))
         {
            *pbTagNvb = (uint8_t) CLIF_GETFIELD(CLIF_RX_STATUS,CLIF_RX_STATUS_RX_NUM_LAST_BITS_MASK, CLIF_RX_STATUS_RX_NUM_LAST_BITS_POS);
            memcpy( pbTagResponse , &clif_rf_rx_buffer[0] , dwResponseLen);
         }
         else
         {
            dwResponseLen = 0;
            epc_status = PN76_CLIF_STATUS_INVALID_RESPONSE;
         }
      }
   }
   else
   {
      CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
      if( dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK))
      {
         epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
      }
   }

   if(PN76_CLIF_STATUS_TIMEOUT ==  epc_status)
   {
      /* Reset the State-Machine to Idle */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));
   }

   /* Update the Response Len if success or Zero in case of error */
   *pbTagRespLen = (uint8_t) dwResponseLen;

   return epc_status;
}

/*********************************************************************************************************************/
/*   NEXTSLOT COMMAND                                                                                                */
/*********************************************************************************************************************/
static PN76_Clif_Status_t PN76_Clif_Epc_NextSlot( uint8_t bSession,
            uint8_t *pbStoredCrc)
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint8_t                *pbResponse = NULL;
   uint32_t               dwResponseLen=0;
   uint8_t                bBufferIndex = 0;
   uint8_t                bNumValidBits = 0;
   uint16_t               wEpcCmdLen = 0;
   uint32_t               dwClifRxStat;
   PN76_Clif_Status_t     eStatus = PN76_CLIF_STATUS_SUCCESS;

   /* Get the number of valid bits in the last byte */
   bNumValidBits = (uint8_t)(PN76_EPC_NEXTSLOT_LEN % BYTE_SIZE);

   /* Build Next Slot Frame */
   pbEpcCmdBuffer[wEpcCmdLen++] = (E_PN76_RF_PROT_I_EPC_CMD_NEXT_SLOT << PN76_EPC_CMD_LEN)
                                  | ( bSession << (BYTE_SIZE - PN76_EPC_CMD_LEN - PN76_EPC_NEXTSLOT_SESSION_LEN) );

   /* Set the command length in bytes */
   wEpcCmdLen = (PN76_EPC_NEXTSLOT_LEN >> 3) + 1;

   /* Enable the CRC5 for RX and Disable for TX to the below sent Frame */
   /* resets to default - "frame-sync" as SOF */
   PN76_Clif_Epc_Config(PN76_EPC_CRC5,START_SYMBOL_FRAME_SYNC,FALSE,TRUE);

   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(TRUE, bNumValidBits));

   /* Send the Key type and the block */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed and the Response to the Command */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( TRUE );

   if (PN76_CLIF_STATUS_SUCCESS == epc_status)
   {
      CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
      if( dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK
                           | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK
                           | CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_MASK))
      {
         dwResponseLen = 0;
         epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
      }
      else
      {
         epc_status = PN76_Clif_RxData(&dwResponseLen);

         if( (dwResponseLen == PN76_EPC_CRC_LEN) && (PN76_CLIF_STATUS_SUCCESS == epc_status))
         {
            pbResponse = &clif_rf_rx_buffer[0];
            bBufferIndex = 0;
            pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
            bBufferIndex++;
            pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
         }
         else
         {
            epc_status = PN76_CLIF_STATUS_INTEGRITY_ERROR;
         }
      }
   }

   CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
   if(dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK
                        | CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK))
   {
      epc_status = PN76_CLIF_STATUS_COLLISION_ERROR;
   }

   /* Reset the State-Machine to Idle */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));

   return epc_status;
}


#ifdef  EPC_FEATURE
/*********************************************************************************************************************/
/*   RESIZE-ROUND COMMAND                                                                                            */
/*********************************************************************************************************************/
static PN76_Clif_Status_t PN76_Clif_Epc_ResizeRound( uint8_t bSession,
            uint8_t UpDn,
            uint8_t *pbStoredCrc)
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint8_t                *pbResponse = NULL;
   uint32_t               dwResponseLen=0;
   uint8_t                bBufferIndex = 0;
   uint8_t                bNumValidBits = 0;
   uint16_t               wEpcCmdLen = 0;
   uint32_t               dwClifRxStat;

   /* Get the number of valid bits in the last byte */
   bNumValidBits = (uint8_t)(PN76_EPC_RSZRND_LEN % BYTE_SIZE);

   /* Build Resize Round Frame */
   pbEpcCmdBuffer[wEpcCmdLen++] = (E_PN76_RF_PROT_I_EPC_CMD_RESIZE_ROUND << PN76_EPC_CMD_LEN)
                                    | ( bSession << (BYTE_SIZE - PN76_EPC_CMD_LEN - PN76_EPC_RSZRND_SESSION_LEN) )
                                    | ( UpDn >> 1 );
   pbEpcCmdBuffer[wEpcCmdLen++] = (UpDn << 7);

   /* Set the command length in bytes */
   wEpcCmdLen = (PN76_EPC_RSZRND_LEN >> 3) + 1;

   /* Enable the CRC5 for RX and Disable for TX to the below sent Frame */
   /* resets to default - "frame-sync" as SOF */
   PN76_Clif_Epc_Config(PN76_EPC_CRC5,START_SYMBOL_FRAME_SYNC,FALSE,TRUE);

   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(TRUE, bNumValidBits));

   /* Send the Key type and the block */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed and the Response to the Command */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( TRUE );

   if (PN76_CLIF_STATUS_SUCCESS == epc_status)
   {
      epc_status = PN76_Clif_RxData(&dwResponseLen);

      if( (dwResponseLen == PN76_EPC_CRC_LEN) && (PN76_CLIF_STATUS_SUCCESS == epc_status))
      {
         pbResponse = &clif_rf_rx_buffer[0];
         bBufferIndex = 0;
         pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
         bBufferIndex++;
         pbStoredCrc[bBufferIndex] = pbResponse[bBufferIndex];
      }
      else
      {
         epc_status = PN76_CLIF_STATUS_INVALID_RESPONSE;
      }
   }
   else
   {
      CLIF_GETREG(CLIF_RX_STATUS_ERROR, &dwClifRxStat);
      if( dwClifRxStat & (CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK))
      {
         epc_status = PN76_CLIF_STATUS_COLLISION_ERROR;
      }
   }

   if(PN76_CLIF_STATUS_TIMEOUT ==  epc_status)
   {
      /* Reset the State-Machine to Idle */
      STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));
   }

   return epc_status;
}

/*********************************************************************************************************************/
/*   NACK COMMAND                                                                                                    */
/*********************************************************************************************************************/
static PN76_Clif_Status_t PN76_Clif_Epc_Nack( void )
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t  *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint16_t  wEpcCmdLen = 0;
   uint8_t   bNumValidBits = 0;

   /* Build NACK Frame */
   pbEpcCmdBuffer[wEpcCmdLen++] = E_PN76_RF_PROT_I_EPC_CMD_NACK ;

   /* No CRC for TX to the below sent Frame */
   PH_HALREG_CLEARBITN( CLIF_CRC_TX_CONFIG_REG, CLIF_CRC_TX_CONFIG_REG_TX_CRC_ENABLE_POS);

   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(FALSE, bNumValidBits));

   /* Send the Key type and the block */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Transmit the NACK Frame */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, CLIF_CONTROL_TRANSMIT_CMD));

   /* Wait for the Transmission to be Completed, since there is no response to the
   * Select Command need not wait for the reception */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( FALSE );

   /* Reset the State-Machine to Idle */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x0));

   return epc_status;
}

#endif

/*********************************************************************************************************************/
/*   REQ_RN COMMAND                                                                                                  */
/*********************************************************************************************************************/
static PN76_Clif_Status_t PN76_Clif_Epc_ReqRN( uint8_t *pbParam,
            uint8_t *pbHandle)
{
   /* Return status */
   PN76_SendDataCfg_t     clifSendDataCfg;
   PN76_Clif_Status_t     eStatus;
   PN76_Clif_Status_t     epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                *pbEpcCmdBuffer =  PN76_Clif_Epc_Rf_GetTxBuffer();
   uint8_t                *pbResponse = NULL;
   uint32_t               dwResponseLen=0;
   uint8_t                bBufferIndex = 0;
   uint8_t                bNumValidBits = 0;
   uint16_t               wEpcCmdLen = 0;
   uint8_t                bParamIndex = 0;

   /* Build REQ-RN Frame */
   pbEpcCmdBuffer[wEpcCmdLen++] = E_PN76_RF_PROT_I_EPC_CMD_REQ_RN ;
   pbEpcCmdBuffer[wEpcCmdLen++] = pbParam[bParamIndex++] ;
   pbEpcCmdBuffer[wEpcCmdLen++] = pbParam[bParamIndex] ;

   /* Enable the CRC16 for RX and TX to the below sent Frame */
   /* resets to default - "frame-sync" as SOF */
   PN76_Clif_Epc_Config(PN76_EPC_CRC16,START_SYMBOL_FRAME_SYNC,TRUE,TRUE);

   /* Setup Clif config including all timing params */
   #ifndef MCUXPRESSO_SDK
   gbEPCMulti_RxGuardTO = 0;
   #endif
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) PN76_Clif_Epc_Tx_Prologue_Before_Send(TRUE, bNumValidBits));

   /* Send the Key type and the block */
   clifSendDataCfg.dwTxLength = wEpcCmdLen;
   clifSendDataCfg.bCommand = CLIF_CONTROL_TRANSCEIVE_CMD;
   clifSendDataCfg.fpTxIrqGuardCb = (FNPTR_TX_IRQ_GUARD_CB) PN76_Clif_TxIrqGuardCb;

   if( PN76_CLIF_STATUS_SUCCESS != PN76_Clif_SendData (pbEpcCmdBuffer, &clifSendDataCfg))
   {
      /* returning integrity error so that further does not break in handling */
      return PN76_CLIF_STATUS_INTEGRITY_ERROR;
   }

   /* Wait for the Transmission to be Completed and the Response to the Command */
   epc_status = PN76_Clif_Epc_TxRxWaitIRQ( TRUE );

   if (PN76_CLIF_STATUS_SUCCESS == epc_status)
   {
   epc_status = PN76_Clif_RxData(&dwResponseLen);
      if( (dwResponseLen == PN76_EPC_HANDLE_LEN) && (PN76_CLIF_STATUS_SUCCESS == epc_status))
      {
         pbResponse = &clif_rf_rx_buffer[0];
         bBufferIndex = 0;
         pbHandle[bBufferIndex] = pbResponse[bBufferIndex];
         bBufferIndex++;
         pbHandle[bBufferIndex] = pbResponse[bBufferIndex];
      }
      else
      {
         epc_status = PN76_CLIF_STATUS_INVALID_RESPONSE;
      }
   }

   /* Reset the State-Machine to Idle */
   STATUS_CHECK_CLIF_SUCCESS_FCT(eStatus, (PN76_Clif_Status_t) CLIF_SETREG(CLIF_CONTROL, 0x00));

   return epc_status;
}


/*********************************************************************************************************************/
/*   GLOBAL FUNCTIONS                                                                                                */
/*********************************************************************************************************************/

PN76_Clif_Status_t PN76_Clif_Epc_DetectCard(PN76_Clif_EpcContext_t *sEpcCtxt,
            uint8_t *pbInParam,
            uint8_t bInParamLength )
{
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                bBufferIndex = 0;
   volatile uint8_t                bSelectLen = pbInParam[PN76_EPC_INV_SEL_LEN_OFFSET];
   volatile uint8_t                bFrameLen = (uint8_t)(sizeof (bSelectLen) + bSelectLen
                                       + ((!(!(bSelectLen)))*PN76_EPC_INV_SEL_NVB_OFFSET))
                                       + PN76_EPC_INV_SEL_BR_SIZE +  PN76_EPC_INV_SEL_TS_SIZE;

   bFrameLen = (uint8_t)(sizeof(bSelectLen));
   bFrameLen += bSelectLen;
   bFrameLen +=  ((!(!(bSelectLen)))*PN76_EPC_INV_SEL_NVB_OFFSET);
   bFrameLen +=  PN76_EPC_INV_SEL_BR_SIZE +  PN76_EPC_INV_SEL_TS_SIZE;

   bBufferIndex++;   /* adding the length for ResumeInventory field */
   bBufferIndex++;   /* adding the length for ResumeInventory field */

   if(0x00 == pbInParam[0])
   {
      if( bSelectLen )
      {
         if( bSelectLen >= PN76_EPC_INV_SEL_MIN_LEN)
         {
            bBufferIndex += bSelectLen + PN76_EPC_INV_SEL_NVB_OFFSET;
            epc_status = PN76_Clif_Epc_Select( (pbInParam + PN76_EPC_INV_SEL_INFO_OFFSET),
                           bSelectLen, pbInParam[PN76_EPC_INV_SEL_NVB_OFFSET]);
            bBufferIndex -= 1;
         }
         else
         {
            epc_status = PN76_CLIF_STATUS_PARAMETER_ERROR;
         }
      }

      sEpcCtxt->bTimeSlotCfg =
            *(pbInParam + bBufferIndex + PN76_EPC_INV_SEL_BR_SIZE);

      if(sEpcCtxt->bTimeSlotCfg > PN76_EPC_INV_SEL_TS_HANLDE)
      {
         epc_status = PN76_CLIF_STATUS_PARAMETER_ERROR;
      }
   }
   else
   {
      epc_status = PN76_CLIF_STATUS_PARAMETER_ERROR;
   }

   if((PN76_CLIF_STATUS_SUCCESS == epc_status) || (PN76_CLIF_STATUS_TIMEOUT == epc_status))
   {

      epc_status = PN76_Clif_Epc_BeginRound((pbInParam + bBufferIndex), &(sEpcCtxt->bSession),
                                               &(sEpcCtxt->bQInfo), sEpcCtxt->bStoredCrc );

      if(PN76_CLIF_STATUS_SUCCESS == epc_status)
      {
         epc_status = PN76_Clif_Epc_Ack( sEpcCtxt->bStoredCrc, sEpcCtxt->pbTagData,
                                            &(sEpcCtxt->psTagHdr->bTagDataLen), &(sEpcCtxt->psTagHdr->bTagDataNvb));
         if(PN76_CLIF_STATUS_INTEGRITY_ERROR == epc_status)
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_INTEGRITY;
         }
         else if(sEpcCtxt->psTagHdr->bTagDataLen)
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_AVAIL;
            sEpcCtxt->wTagInfoSize += sEpcCtxt->psTagHdr->bTagDataLen;
         }
         else
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_NOT_AVAIL;
         }
         sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;
      }
      else
      {

         if(PN76_CLIF_STATUS_TIMEOUT == epc_status)
         {
            sEpcCtxt->psTagHdr->bTagDataLen = 0;
            sEpcCtxt->psTagHdr->bTagDataNvb = 0;
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_NOT_AVAIL;
            sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;
         }
         else if(PN76_CLIF_STATUS_COLLISION_ERROR == epc_status)
         {
            sEpcCtxt->psTagHdr->bTagDataLen = 0;
            sEpcCtxt->psTagHdr->bTagDataNvb = 0;
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_COLLISION;
            sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;
         }
         else
         {
            /* Integrity error */
            sEpcCtxt->psTagHdr->bTagDataLen = 0;
            sEpcCtxt->psTagHdr->bTagDataNvb = 0;
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_INTEGRITY;
            sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;
         }
      }
   }

   return epc_status;
}

static void PN76_Clif_Epc_BufferInit (PN76_Clif_EpcContext_t *sEpcCtxt)
{

   memset( (void *)epc_hif_buffer, 0, sizeof(epc_hif_buffer));

   sEpcCtxt->psTagHdr = (PN76_Clif_EpcTagHdr_t *)(epc_hif_buffer + LEN_BUFFER_OFFSET);
   sEpcCtxt->pbTagData = (((uint8_t *)sEpcCtxt->psTagHdr) + PN76_EPC_TAG_INFO_HDR_LEN);

   sEpcCtxt->wTagInfoSize = 0;

   return;
}

PN76_Clif_Status_t PN76_Clif_Epc_ReActivate( PN76_Clif_EpcContext_t *sEpcCtxt )
{
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;

   do
   {
      uint8_t   bTagRespLen = 0;

      epc_status = PN76_Clif_Epc_NextSlot( sEpcCtxt->bSession, sEpcCtxt->bStoredCrc );

      if(PN76_CLIF_STATUS_SUCCESS == epc_status)
      {
         epc_status = PN76_Clif_Epc_Ack( sEpcCtxt->bStoredCrc, sEpcCtxt->pbTagData,
                                            &(sEpcCtxt->psTagHdr->bTagDataLen), &(sEpcCtxt->psTagHdr->bTagDataNvb));
         if(PN76_CLIF_STATUS_INTEGRITY_ERROR == epc_status)
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_INTEGRITY;
            bTagRespLen = 0;
         }
         else if(sEpcCtxt->psTagHdr->bTagDataLen)
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_AVAIL;
            sEpcCtxt->wTagInfoSize += sEpcCtxt->psTagHdr->bTagDataLen;
         }
         else
         {
            sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_NOT_AVAIL;
         }
      }
      else if(PN76_CLIF_STATUS_COLLISION_ERROR == epc_status)
      {
         sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_COLLISION;
      }
      else if (PN76_CLIF_STATUS_TIMEOUT == epc_status)
      {
         sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_NOT_AVAIL;
      }
      else
      {
         sEpcCtxt->psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_NOT_AVAIL;
         sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;
         break;
      }
      sEpcCtxt->dwCurrQSlot--;
      sEpcCtxt->wTagInfoSize += PN76_EPC_TAG_INFO_HDR_LEN;

      bTagRespLen = sEpcCtxt->psTagHdr->bTagDataLen;
      sEpcCtxt->psTagHdr = (PN76_Clif_EpcTagHdr_t *)(sEpcCtxt->pbTagData + bTagRespLen );
      sEpcCtxt->pbTagData = (((uint8_t *)sEpcCtxt->psTagHdr) + PN76_EPC_TAG_INFO_HDR_LEN);

      /* Check if we can continue for the next Tag Information and the Time Slot */
   }while (((sEpcCtxt->wTagInfoSize
         + PN76_EPC_TAG_DATA_MAX_LEN + PN76_EPC_TAG_INFO_HDR_LEN)
           < PN76_EPC_RF_MAX_BUFFER_SIZE )
             && (sEpcCtxt->dwCurrQSlot));

   epc_status = PN76_CLIF_STATUS_SUCCESS;

   return epc_status;
}


PN76_Clif_Status_t PN76_Clif_Epc_ResumeActivation( void )
{
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;

   if(PN76_EPC_INV_SEL_TS_MAX == gClif_EpcInfo.bTimeSlotCfg)
   {
      /* Disable all interrupt enable */
      CLIF_SETREG(CLIF_INT_CLR_ENABLE, (~(CLIF_INT_CLR_ENABLE__RESET_VALUE)));

      /* Clear TX /RX IRQ and Timer 2 IRQ */
      CLIF_SETREG(CLIF_INT_CLR_STATUS,
                       ( CLIF_INT_STATUS_TX_IRQ_MASK
                             | CLIF_INT_STATUS_RX_IRQ_MASK
                             | CLIF_INT_STATUS_TIMER1_IRQ_MASK ));

      PN76_Clif_Epc_BufferInit ( &gClif_EpcInfo );

      if(gClif_EpcInfo.dwCurrQSlot)
      {
         epc_status = PN76_Clif_Epc_ReActivate(&gClif_EpcInfo);

         if(gClif_EpcInfo.wTagInfoSize)
         {
            // This register is not present. Why it is required...
            // CLIF_SETREG( CLIF_INT_SET_STATUS_REG, CLIF_INT_SET_STATUS_REG_RX_IRQ_SET_STATUS_MASK);
         }
      }
      else
      {
         epc_status = PN76_CLIF_STATUS_SEMANTIC_ERROR;
      }

   }
   else
   {
      epc_status = PN76_CLIF_STATUS_SEMANTIC_ERROR;
   }

   /* Stop the Timer if Running */
   CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_ENABLE_MASK);
//   PH_HALREG_SETREG(CLIF_TIMER1_CONFIG_REG, 0);
   return epc_status;
}


PN76_Clif_Status_t PN76_Clif_Epc_ActivateCard( uint8_t *pbInParam,
            uint8_t bInParamLength )
{
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                bTimeSlotCfg = 0;

   memset( (void *)&gClif_EpcInfo, 0, sizeof(gClif_EpcInfo));

   /* Disable all interrupt enable */
   CLIF_SETREG(CLIF_INT_CLR_ENABLE,(~(CLIF_INT_CLR_ENABLE__RESET_VALUE)));

   /* Clear TX /RX IRQ and Timer 2 IRQ */
   CLIF_SETREG(CLIF_INT_CLR_STATUS, ( CLIF_INT_STATUS_TX_IRQ_MASK
                                    | CLIF_INT_STATUS_RX_IRQ_MASK
                                    | CLIF_INT_STATUS_TIMER1_IRQ_MASK ));
   /* Initialize the Tag Info Structure */
   PN76_Clif_Epc_BufferInit ( &gClif_EpcInfo );

   epc_status = PN76_Clif_Epc_DetectCard(&gClif_EpcInfo, pbInParam, bInParamLength);

   if((PN76_CLIF_STATUS_SUCCESS == epc_status)
         || (PN76_CLIF_STATUS_TIMEOUT == epc_status)
         || (PN76_CLIF_STATUS_INTEGRITY_ERROR == epc_status)
         || (PN76_CLIF_STATUS_COLLISION_ERROR == epc_status))
   {

      bTimeSlotCfg = gClif_EpcInfo.bTimeSlotCfg;

      /* Process the Time Slot Information */
      switch(bTimeSlotCfg)
      {
         /* Issue the Next Slot Until the Internal Buffer is filled */
         case PN76_EPC_INV_SEL_TS_MAX:
         {
            uint8_t   bTagRespLen = 0;

            gClif_EpcInfo.dwCurrQSlot = (1UL << (gClif_EpcInfo.bQInfo & NIBBLE_MASK));

            if(gClif_EpcInfo.dwCurrQSlot)
            {
               /* Already Consumed one time slot */
               gClif_EpcInfo.dwCurrQSlot--;
            }

            if(gClif_EpcInfo.dwCurrQSlot)
            {
               bTagRespLen = gClif_EpcInfo.psTagHdr->bTagDataLen;

               gClif_EpcInfo.psTagHdr = (PN76_Clif_EpcTagHdr_t *)(gClif_EpcInfo.pbTagData + bTagRespLen );
               gClif_EpcInfo.pbTagData = (((uint8_t *)gClif_EpcInfo.psTagHdr) + PN76_EPC_TAG_INFO_HDR_LEN);

               epc_status = PN76_Clif_Epc_ReActivate(&gClif_EpcInfo);
            }


            break;
         }
         /* Issue the Req_Rn if there is a Valid Tag Response */
         case PN76_EPC_INV_SEL_TS_HANLDE:
         {
            if(PN76_CLIF_STATUS_SUCCESS == epc_status)
            {
               epc_status = PN76_Clif_Epc_ReqRN(gClif_EpcInfo.bStoredCrc,
                                                         gClif_EpcInfo.bEpcHandle);
            }
            if(PN76_CLIF_STATUS_SUCCESS == epc_status)
            {
               uint8_t bTagDataLen = gClif_EpcInfo.psTagHdr->bTagDataLen;
               gClif_EpcInfo.pbTagData[bTagDataLen++] = gClif_EpcInfo.bEpcHandle[0];
               gClif_EpcInfo.pbTagData[bTagDataLen++] = gClif_EpcInfo.bEpcHandle[1];
               gClif_EpcInfo.psTagHdr->bTimeSlotInfo = PN76_EPC_TAG_RES_HNDL_AVAIL;
               gClif_EpcInfo.wTagInfoSize += (uint16_t)sizeof(gClif_EpcInfo.bEpcHandle);
            }
            break;
         }
         /* Pause the Processing and wait for next Host command */
         case PN76_EPC_INV_SEL_TS_SINGLE:
         {
            break;
         }
         default:
         {
            break;
         }
      }

   }

   /* Update the Status to Success if the Collision Error, Integrity Error or the Timeout Occurred  */
   epc_status = ((PN76_CLIF_STATUS_TIMEOUT == epc_status)
                  || (PN76_CLIF_STATUS_COLLISION_ERROR == epc_status)
                        || (PN76_CLIF_STATUS_INTEGRITY_ERROR == epc_status) )?
                                       PN76_CLIF_STATUS_SUCCESS: epc_status;

   /* Stop the Timer if Running */
   CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_ENABLE_MASK);
//   PH_HALREG_SETREG(CLIF_TIMER1_CONFIG_REG, 0);

   /* Enable the RX IRQ if the Tag one of the Time Slot Information is available */
   if((gClif_EpcInfo.wTagInfoSize)
         && (PN76_CLIF_STATUS_SUCCESS == epc_status))
   {
      /* TC: To Clear the Idle IRQ during the Activate/Reactivate Operation */
      CLIF_SETREG( CLIF_INT_CLR_STATUS, CLIF_INT_CLR_STATUS_IDLE_IRQ_CLR_STATUS_MASK);
      // TODO: Below register is not present...
      // CLIF_SETREG( CLIF_INT_SET_STATUS, CLIF_INT_SET_STATUS_RX_IRQ_SET_STATUS_MASK);
   }

   return epc_status;
}


#if 0
/*
 * Note: This function is commented, so that when the feature is available, needs to be implemented.
 * Commented for coverage purpose
 */

PN76_Clif_Status_t PN76_Clif_Epc_TagInvSize( PN76_Epc_Data_t *psResponse )
{
   // TODO: this is not being used...
   PN76_Clif_Status_t        epc_status = PN76_CLIF_STATUS_SUCCESS;
   uint8_t                      bBufIndex = 0;

   psResponse->pBuffer[bBufIndex++] = (uint8_t) gClif_EpcInfo.wTagInfoSize;
   psResponse->pBuffer[bBufIndex++] = (uint8_t) (gClif_EpcInfo.wTagInfoSize >> BYTE_SIZE);
   psResponse->dwLength = bBufIndex;

   return epc_status;
}
#endif

PN76_Clif_Status_t PN76_Clif_Epc_TagInventoryInfo( uint16_t *pLen, uint8_t **pBuf)
{
   PN76_Clif_Status_t  epc_status = PN76_CLIF_STATUS_SUCCESS;
//   psResponse->pBuffer = (epc_hif_buffer + LEN_BUFFER_OFFSET);
//   psResponse->dwLength = gClif_EpcInfo.wTagInfoSize;
   *pLen = gClif_EpcInfo.wTagInfoSize;
   *pBuf = (epc_hif_buffer + LEN_BUFFER_OFFSET);

   return epc_status;
}
