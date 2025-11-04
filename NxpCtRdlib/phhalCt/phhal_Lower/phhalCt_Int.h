/*----------------------------------------------------------------------------*/
/* Copyright 2014, 2015, 2022  NXP                                                        */
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
 * Hardware Abstraction Layer functions for internal calls, not to be used directly by PAL & Application
 * $Author:  $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 */

#ifndef PHHALCT_INT_H
#define PHHALCT_INT_H

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include "ph_Datatypes.h"


#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "ph_EStatus.h"
#include "phhalCt_TDA.h"
#include "phhalCt_platform.h"
#include "phOsal.h"
#include "phhalCt_Event.h"
#include "fsl_gpt.h"
#include "PN76_UtilsHelper.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */
/**
 * Set the timer in maximum allowed time in ATR between each character.
 */
#define PHHAL_CT_ATRMODE_MAXTIME           1
/**
 * Set the timer in PPS Exchange mode configuration.
 */
#define PHHAL_CT_PPSMODE_9600_ETU          4
/**
 * Set the timer in the software triggered mode
  */
#define PHHAL_CT_SW_TRIGGER                 5
/**
 * Maximum parity repetitions allowed.
 */
#define PHHAL_CT_MAX_RETRY_PARITY       4

/* Common Macros used in both profile EMVCo and 7816.*/
/**
 * TOC register value for the software trigger
 */
#define PHHAL_CT_T23_SOFTWARE_TRIG_CONFIG    0x61
/**
 * Macros for CT Timer TOC register configuration value, Timer 1,2,3 wired as 24 bit timer. The timer is started on
 * first  start bit, and then on each subsequent bit.
 */
#define PHHAL_CT_T123START_BIT_CONFIG    0x7C
/**
 * Macro for T=0 protocol.
 */
#define PHHAL_CT_PROTOCOL_T0            0x00
/**
 * Macro for T=1 protocol.
 */
#define PHHAL_CT_PROTOCOL_T1            0x01
/**
 * Macro for T=15 protocol.
 */
#define PHHAL_CT_PROTOCOL_T15           0x0F
/**
 * Macro for T=14 protocol.
 */
#define PHHAL_CT_PROTOCOL_T14           0x0E
/**
 * Masking for extracting last four bits of any byte.
 */
#define PHHAL_CT_LSB_NIBBLE_MASK          0x0F
/**
 * Special value for TC1.
 */
#define PHHAL_CT_SPECIAL_TC1_VALUE        0xFF
/**
 *  Maximum possible value IFSC for 7816 and EMVCo.
 */
#define PHHAL_CT_MAX_IFSC            0xFE
/**
 * Default value for FiDi.
 */
#define PHHAL_CT_DEFAULT_FIDI              0x11
/**
 * UnSupported TC2 for Atr Byte.
 */
#define PHHAL_CT_UNSUPPORTED_TC2            0x00
/* EMVCo Profile Specific Macros.*/
/**
 * The maximum allowed Character waiting Index value in EMVCO mode.
 */
#define PHHAL_CT_EMVCO_CWI_MAX            0x05
/**
 * The minimum allowed Character waiting Index value in EMVCO/7816 mode.
 */
#define PHHAL_CT_MIN_CWI          0x00
/**
 * The maximum allowed Block waiting Index value in EMVCO mode.
 */
#define PHHAL_CT_EMVCO_BWI_MAX            0x04
/**
 * Minimum supported value for FiDi in TA1 for EMVCo.
 */
#define PHHAL_CT_EMVCO_FIDI_MIN_VAL       0x11
/**
 * Maximum supported value for FiDi in TA1 for EMVCo.
 */
#define PHHAL_CT_EMVCO_FIDI_MAX_VAL       0x13
/**
 *  Minimum possible value for IFSC in EMVCo.
 */
#define PHHAL_CT_EMVCO_MIN_IFSC        0x10
/**
 *  Minimum possible value for IFSC in EMVCo.
 */
#define PHHAL_CT_EMVCO_MAX_SUPPORTED_TC1        0x1E
/**
 * EMVCo Supported TC2.
 */
#define PHHAL_CT_EMVCO_SUPPORTED_TC2      0x0A
/**
 * EMVCo Supported TC3.
 */
#define PHHAL_CT_EMVCO_SUPPORTED_TC3      0x00
/**
 * EMVCo max supported ATR Byte count.
 */
#define PHHAL_CT_EMVCO_MAX_ATR_BYTE        32
/**
 * TO1 timer maximum allowable count for to be 20160 in case of EMVCo.
 */
#define PHHAL_CT_ATR_TOR1_TIMER_MAX_COUNT   0x54
/**
 * Early timer value for EMVCo is 380(200+180).
 */
#define PHHAL_CT_EMVCO_EARLY_TIMER_VALUE       0xB4
/**
 * Mute timer value for EMVCO is 42000.
 */
#define PHHAL_CT_EMVCO_MUTE_TIMER_LSB_VALUE    0x11
#define PHHAL_CT_EMVCO_MUTE_TIMER_MSB_VALUE    0xA4

/* 7816 profile specific Macros.*/

/**
 * The maximum parity error count value,Set the number of allowed repetitions in reception or transmission mode before logic 1;
 * setting pe in ct_usr1_reg. The value 000 indicates that, if only one parity error has occurred, bit pe is set at
 *  the value 111 indicates that bit pe will be set at logic 1 after 8 parity errors.
 */
#define PHHAL_CT_MAXPARITY_ERROR_COUNT      7
/**
 * Parity error reset.
 */
#define PHHAL_CT_RESET_PARITY_ERR_COUNT     0x00
/**
 * Specific mode byte MASK in TA1 byte.
 */
#define PHHAL_CT_BIT5_MASK                0x10
/**
 * Changable/Non changable mode byte MASK in TA1 byte.
 */
#define PHHAL_CT_BIT8_MASK                0x80
/**
 * The maximum allowed Block waiting Index value in 7816 mode
 */
#define PHHAL_CT_7816_BWI_MAX            0x09
/**
 * FIDI table Dimension Length.
 */
#define PHHAL_CT_FIDI_TAB_LEN             108
/**
 *  Minimum possible value for IFSC in 7816.
 */
#define PHHAL_CT_7816_MIN_IFSC          0x01
/**
 * CRC presence check
 */
#define PHHAL_CT_CRC_PRESENCE_CHECK_MASK       0x01
/**
 * ISO7816 max supported ATR Byte count.
 */
#define PHHAL_CT_7816_MAX_ATR_BYTE             33
/**
 * Early timer value for 7816 is 400(200+200).
 */
#define PHHAL_CT_7816_EARLY_TIMER_VALUE         0xC8
/**
 * Mute timer value for 7816 is 40000.
 */
#define PHHAL_CT_7816_MUTE_TIMER_LSB_VALUE      0x41
#define PHHAL_CT_7816_MUTE_TIMER_MSB_VALUE      0x9C

/* Macro map to GPT driver. */
#define TIMER_IsFree      GPT_MGR_IsFree
#define TIMER_Start       GPT_MGR_Start
#define TIMER_Stop        GPT_MGR_Stop
#define TIMER_Configure   GPT_MGR_Configure
#define TIMER_Request     GPT_MGR_Request
#define TIMER_Release     GPT_MGR_Release
#define TIMER_Init        GPT_MGR_Init
#define TIMER_ConfigDef_t gpt_handle_t

#define high 0x01
#define low  0x00
/* *****************************************************************************************************************
 * Types/Structure Declarations
 * *****************************************************************************************************************.*/
/**
 * Structure for indicating Atr byte processing function.
 */
typedef struct
{
    phStatus_t (*InterfaceChars)(phhalCt_DATAParams_t *, uint8_t, uint8_t); /**< typedef function pointer
                                                                                      for atr interface
                                                                                      character's processing function.*/
    uint8_t T; /**< Atr switch count  which will change after processing till each TD byte.*/
}phhalCt_AtrType;

/**
 * Typedef for a function pointer to CT HAL API phhalCt_SetTransmissionProtocol()
 */
typedef phStatus16_t (phhalCt_SetTransmissionProtocol_t)(uint8_t bCardProtocol);

/**
 * Clock configuration structure having specified values for Pdr,Clk division factor for particular FiDi.
 */
typedef struct
{
    uint16_t wPdrRegValue;    /**< Used to store pdr register value for different baud rates.*/
    uint8_t  bFiDi;           /**< Used to store value for FiDi as per Atr.*/
    uint8_t  bClockDivider;   /**< Clock divider value according to FiDi.*/
    uint8_t  bDValue;         /**< D value according to Di as per FIDI table.*/
}phhalCt_ClockUart_t;
/* *****************************************************************************************************************
 * Extern Variables
 * *****************************************************************************************************************.*/
extern const phhalCt_ClockUart_t gkphhalCt_BPreScalar[];
/* *****************************************************************************************************************
 * Function Prototypes
 * *****************************************************************************************************************.*/

/**
 * This function is used to set the WWT for T=0 protocol,BWT for T=1 protocol according to the mode selected.
 *
 * @param[in/out] phhalCt_Params  HAL context structure pointer
 * @param[in] dwMode  The mode can be BWT mode for T=1 protocol, WWT for T=0 protocol.
 *                     Different possible modes are:
 *                     - #PHHAL_CT_ATRMODE_MAXTIME To set the ATR maximum timeout (Used only internal)during activation.
 *                     - #PHHAL_CT_APDUMODE_BWT To set the BWT timeout for T=1 protocol.
 *                     - #PHHAL_CT_APDUMODE_WWT To set the WWT timeout for T=0 protocol.
 *                     - #PHHAL_CT_PPSMODE_9600_ETU To set timer for PPS Exchange.
 * @param[in]  dwWTX  WTX value to be multiplied to the BWT value in case of T=1 protocol.
 *                     - For #PHHAL_CT_APDUMODE_BWT it should be 1 or greater than 1 .
 *                     - For #PHHAL_CT_ATRMODE_MAXTIME/PHHAL_CT_APDUMODE_WWT/PHHAL_CT_PPSMODE_9600_ETU it can be
 *                       any value, and this value is not used.
 * @return     Status code for Set Timer.
 *
 * @retval    #PH_ERR_SUCCESS  Timer values has been applied successfully.
 * @maskedret #PH_ERR_INVALID_PARAMETER   Parameters are invalid.
 */
phStatus16_t phhalCt_SetTimer(void * phhalCt_Params, uint32_t dwMode, uint32_t dwWTX);
/**
 * This function is used to switch control between multiple TDA slots
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[in]  eSlot_Index       Slot number
 *
 * @retval    #PH_ERR_SUCCESS The slot has been switched successfully.
 */
phStatus16_t phhalCt_SwitchSlot(void * phhalCt_Params, phhalCt_SlotType_t eSlot_Index);

/**
 * This function will clear the all common context variables in CT HAL.
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @retval     none
 */
void phhalCt_ClearContext(phhalCt_DATAParams_t * phhalCt_DATAParams);

/**
 * This function is used to set the default values to the  common context variables used for protocol parameters.
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @retval     none
 */
void phhalCt_SetDefaultValues( phhalCt_DATAParams_t * phhalCt_DATAParams);

/**
 * Handling of any/ all events.
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @retval    #PH_ERR_SUCCESS                   No event occured to handle
 * @retval    #PH_ERR_CT_PARITY_ERROR           Parity error
 * @retval    #PH_ERR_CT_OVERUN_ERROR           Data overrun error
 * @retval    #PH_ERR_CT_FRAMING_ERROR          Data Framing error
 * @retval    #PH_ERR_CT_CARD_REMOVED           Card removed
 */
phStatus_t phhalCt_HandleCommonEvent(phhalCt_DATAParams_t * phhalCt_DATAParams);

/**
 * This function is used to performs a warm activation.
 * Configures the timers according to the EMVCo, if success, returns the ATR to the user.
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[out]   pbAtrBuffer      Pointer to the ATR buffer where the ATR bytes will be stored
 * @param[out]  pbAtrSize        Pointer to which the count of ATR bytes is copied
 * @return      Status code for warm activation.
 * @note       User can call this api independently but after phhalCt_CardActivate Api only.
 *
 * @retval    #PH_ERR_SUCCESS             Cold activation successful and ATR bytes are received successfully.
 * @maskedret #PH_ERR_OPERATION_TIMEDOUT  Api timed out.
 * @maskedret #PH_ERR_INVALID_PARAMETER   Parameters are invalid.
 * @maskedret #PH_ERR_CT_MAIN_CARD_ABSENT Card is absent in the slot.
 * @maskedret #PH_ERR_CT_CARD_ALREADY_ACTIVATED  Card is already activated.
 * @maskedret #PH_ERR_CT_MUTE_ERROR       Card is muted.
 * @maskedret #PH_ERR_CT_EARLY_ERROR      Card has answered early.
 * @maskedret #PH_ERR_CT_PARITY_ERROR     Card has parity error while receiving the ATR.
 * @maskedret #PH_ERR_CT_OVERUN_ERROR     Fifo is over run while receiving the ATR.
 * @maskedret #PH_ERR_CT_FRAMING_ERROR    Framing error while receiving the ATR.
 * @maskedret #PH_ERR_CT_ATR_PARSER_ERROR ATR parser failed, ATR is inconsistent with the specification.
 */
phStatus16_t phhalCt_WarmReset( void * phhalCt_Params, uint8_t * pbAtrBuffer, uint8_t * pbAtrSize );

/**
 * This is helper/common function to process the ATR after cold or warm activation..
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[out]   pbAtrBuffer      Pointer to the ATR buffer where the ATR bytes will be stored
 * @param[out]  pbAtrSize        Pointer to which the count of ATR bytes is copied
 *
 * @retval    #PH_ERR_SUCCESS             Cold activation successful and ATR bytes are received successfully.
 * @maskedret #PH_ERR_OPERATION_TIMEDOUT  Api timed out.
 * @maskedret #PH_ERR_INVALID_PARAMETER   Parameters are invalid.
 * @maskedret #PH_ERR_CT_MAIN_CARD_ABSENT Card is absent in the slot.
 * @maskedret #PH_ERR_CT_CARD_ALREADY_ACTIVATED  Card is already activated.
 * @maskedret #PH_ERR_CT_MUTE_ERROR       Card is muted.
 * @maskedret #PH_ERR_CT_EARLY_ERROR      Card has answered early.
 * @maskedret #PH_ERR_CT_PARITY_ERROR     Card has parity error while receiving the ATR.
 * @maskedret #PH_ERR_CT_OVERUN_ERROR     Fifo is over run while receiving the ATR.
 * @maskedret #PH_ERR_CT_FRAMING_ERROR    Framing error while receiving the ATR.
 * @maskedret #PH_ERR_CT_ATR_PARSER_ERROR ATR parser failed, ATR is inconsistent with the specification.
 */
phStatus16_t phhalCt_ProcessActivation( void * phhalCt_Params, uint8_t * pbAtrBuffer, uint8_t * pbAtrSize );

/**
 * This function is used to set the baud rate, calculate the timing values for BWT,WWT and CWT etc.
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @return    Status code for Baud Rate Setting.
 *
 * @retval    #PH_ERR_SUCCESS   Setting the baud rate is successful.
 * @maskedret #PH_ERR_INVALID_PARAMETER  Parameters are invalid.
 */
phStatus16_t phhalCt_SetBaudRate(phhalCt_DATAParams_t * phhalCt_DATAParams);

/**
 * This function registers the call back function to be called from the ISR on the specified interrupts.
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[out] pCallBackFunc  Function to be called from the ISR.
 * @param[out] dwInterrupts   Interrupt bits on which the call back function shall be called
 *                          (In case of CT only the CT_USR2_REG (UART Status 2) interrupt
 *                          register will be sent with the call back).
 *
 * @return Status of the operation.
 * @retval    #PH_ERR_SUCCESS    Call back registered is successful
 * @maskedret #PH_ERR_INVALID_PARAMETER  Parameter has not been sent correctly
 */
phStatus16_t phhalCt_RegCallBack(void * phhalCt_Params, pphhalCt_CallbackFunc_t pCallBackFunc, uint32_t dwInterrupts);

/**
 * This API is the ISR for CTIF.
 *
 * This API is part the Vector Table and direclty called in the event of CT ISR.

 * @param     none
 * @retval    none
 */
void CTHandler(void);

/**
 * Function on successfull activation of card used to set baud rate, guard time and transmission protocol as T=0 or T=1
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @retval    none
 */
void phhalCt_SetCardProfile(void * phhalCt_Params);

/**
 * Initiates System timer to monitor card mute specific timeout
 * @param     none
 * @retval    #PH_ERR_SUCCESS    Timer successfully attained
 * @retval    #PH_ERR_FAILED     Timer not free
 */
phStatus16_t phhalCt_MuteCardTimerInit( void );

/**
 * Triggers the timer on cold/ warm reset
 * @param     none
 * @retval    none
 */
void phhalCt_MuteCardTimerStart( void );

/**
 * Timeout callback handler to raise card Mute error event
 * @param     none
 * @retval    none
 */
void phhalCt_MuteCardTimerCb(void* pContext);

/**
 * Stops Mjute card timer when either data received or timedout
 * @param     none
 * @retval    none
 */
void phhalCt_MuteCardTimerStop( void );

/**
 * Set the default baud rate and triggers CT IP timers before cold/ warm reset
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @retval    #PH_ERR_SUCCESS               Activation configurations successfully done
 * @retval    #PH_ERR_INVALID_PARAMETER     Invalid params
 */
phStatus16_t phhalCt_SetActivationConfig(void * phhalCt_Params);

/**
 * Stops CT IP Timer, direct setting up registers
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[in]  SlotNum           Slot number to selected as current transacting slot
 * @retval    none
 */
void phhalCt_SelectSlot( void * phhalCt_DATAParams, phhalCt_SlotType_t SlotNum );

/**
 * Flush the FIFO at the time of deactivation of card
 * @param     none
 * @retval    #PH_ERR_SUCCESS      Flushed FIFO successful
 */
phStatus16_t phhalCt_DeactivateCardConfig(void);

#endif /* NXPBUILD__PHHAL_CT.*/

/** @}.*/
#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */
