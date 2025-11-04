/*----------------------------------------------------------------------------*/
/* Copyright 2014, 2015, 2022-2023 NXP                                                        */
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
 * Hardware Abstraction Layer APIs mainly used by PAL & Application
 * $Author:  $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 */

#ifndef SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_INTERFACE_H_
#define SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_INTERFACE_H_

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include "ph_Datatypes.h"


#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "ph_EStatus.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */
/**
 * Macros for 1.8V  VCC selection during ATR reception
 */
#define PHHAL_CT_VCC1M8                   0x02
/**
 * Macros for 3V  VCC selection during ATR reception.
 */
#define PHHAL_CT_VCC3                     0x01
/**
 * Macros for 5V  VCC selection during ATR reception.
 * */
#define PHHAL_CT_VCC5                     0x00
/**
 * Set the timer in BWT mode configuration.
 */
#define PHHAL_CT_APDUMODE_BWT              2
/**
 * Set the timer in WWT mode configuration.
 */
#define PHHAL_CT_APDUMODE_WWT              3

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * *****************************************************************************************************************.*/
/**
 * These enums are used by HAL APIs for indicating different error status codes.
 */
typedef enum {
    /** \b 0x81 */ PH_ERR_CT_MUTE_ERROR  = (PH_CT_ERR_CUSTOM_BEGIN+0x0001),    /**< Card is muted.*/
    /** \b 0x82 */ PH_ERR_CT_EARLY_ERROR,           /**< Card is too early to answer.*/
    /** \b 0x83 */ PH_ERR_CT_PARITY_ERROR,          /**< Card has parity errors.*/
    /** \b 0x84 */ PH_ERR_CT_OVERUN_ERROR,          /**< Fifo is overrun.*/
    /** \b 0x85 */ PH_ERR_CT_FRAMING_ERROR,         /**< Framing error.*/
    /** \b 0x86 */ PH_ERR_CT_TEMPERATURE_LATCHED,   /**< Temperature latch error.*/
    /** \b 0x87 */ PH_ERR_CT_CARD_REMOVED,          /**< Card removed.*/
    /** \b 0x88 */ PH_ERR_CT_PROTECTION_LATCHED,    /**< Protection is latched.*/
    /** \b 0x89 */ PH_ERR_CT_TIME_OUT_ATR_20160ETU, /**< ATR long timeout 20160etu error .*/
    /** \b 0x8A */ PH_ERR_CT_TIME_OUT_ATR_10080ETU, /**< ATR char waiting timeout 10080etu error.*/
    /** \b 0x8B */ PH_ERR_CT_TIME_OUT_WWT_OR_BWT,   /**< BWT or WWT timeout error.*/
    /** \b 0x8C */ PH_ERR_CT_TIME_OUT_CWT,          /**< CWT timeout error.*/
    /** \b 0x8D */ PH_ERR_CT_CARD_ALREADY_ACTIVATED,/**< Card is already activated .*/
    /** \b 0x8E */ PH_ERR_CT_ATR_PARSER_ERROR,      /**< ATR parser error.*/
    /** \b 0x8F */ PH_ERR_CT_ATR_WARM_RESET_INDICATED,  /**< Warning from the ATR parser to issue the warm reset.*/
    /** \b 0x90 */ PH_ERR_CT_MAIN_CARD_PRESENT,     /**< Main slot card present.*/
    /** \b 0x91 */ PH_ERR_CT_MAIN_CARD_ABSENT,      /**< Main slot card absent.*/
    /** \b 0x92 */ PH_ERR_CT_PPS_EXCHANGE_ERROR,    /**< PPS Exchange is not successful.*/
    /** \b 0x93 */ PH_ERR_CT_CLASS_CHANGE_INDICATED, /**< Atr having class indicator came.*/
    /** \b 0x94 */ PH_ERR_CT_CLOCKSTOP_NOT_SUPPORTED, /**< Atr having not supported value for clock stop.*/
    /** \b 0x95 */ PH_ERR_CT_ATR_SPECIFIC_PARAMETER_UNSUPPORTED,     /**< Atr having Invalid Protocol for 7816 profile.*/
    /** \b 0x96 */ PH_ERR_PPS_EXCHANGE_NOT_REQUIRED, /**< PPS Exchange Api called with default or lower baudrate and first offered protocol.*/
    /** \b 0x97 */ PH_ERR_CT_ASYNCH_SHUTDOWN,        /**< Asynchronous shutdown of CT.*/
    /** \b 0x98 */ PH_ERR_CT_CARD_DEACTIVATED,       /**< Card is deactivated due to removal or fault */
    /** \b 0x98 */ PH_ERR_CT_INVALID_SLOT,           /**< Invalid slot number */
    /** \b 0x99 */ PH_ERR_CT_HAL_INVALID             /**< Invalid enumeration.*/
}phhalCt_ErrorCodes_t;

/**
 * Enum for Supported protocol types
 */
typedef enum phhalCt_ProtocolType
{
    E_PROTOCOL_CT_T0 = 0x00,        /**< T=0 protocol  */
    E_PROTOCOL_CT_T1 = 0x01,        /**< T=1 protocol */
    E_PROTOCOL_CT_BOTH_T0_T1,       /**< T=0 and T=1 both protocol supported. */
    E_PROTOCOL_CT_INVALID = 0xFF    /**< Invalid protocol selection */
} phhalCt_ProtocolType_t;

/* *****************************************************************************************************************
 * Extern Variables
 * *****************************************************************************************************************.*/

/* *****************************************************************************************************************
 * Function Prototypes
 * *****************************************************************************************************************.*/

/**
 * To Get HAL buffer pointer reference, called from PAL
 * @param     none
 * @retval    Hal buffer reference
 */
uint8_t * phhalCt_GetBuffReference(void);

/**
 * HAL API to do a cold reset/activate of the card for ATR reception, internally based on selected slot, the function will trigger activation
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[in]  pbAtrBuffer       Pointer to Received ATR buffer
 * @param[in]  pbAtrSize         Pointer to Received ATR's length
 * @param[out] bVccSel           Class (voltage) selection A, B, C
 * @param[in]  pIFSC             Pointer to value of card supported IFS
 * @param[in]  pSelT0            Pointer to value card supporting T=0 protocol
 * @param[in]  pSelT1            Pointer to value card supporting T=1 protocol
 *
 * @retval  The return value come from the CT hal layer, the same return code is passed to the application layer.
 * @retval  #PH_ERR_SUCCESS                       If the cold activation is success and ATR is received
 * @retval  #PH_ERR_INVALID_PARAMETER             Parameters are invalid.
 *
 * @maskedret  #PH_ERR_CT_CARD_ALREADY_ACTIVATED  Card is already in activate state
 * @maskedret  #PH_ERR_CT_MUTE_ERROR              Card is mute
 * @maskedret  #PH_ERR_CT_MAIN_CARD_ABSENT        No Card Present
 * @maskedret  #PH_ERR_CT_INVALID_SLOT            Invalid slot number
 * @maskedret  #PH_ERR_CT_EARLY_ERROR             Card early error
 * @maskedret  #PH_ERR_CT_CLASS_CHANGE_INDICATED  Class change indicated
 */
phStatus16_t phhalCt_CardActivate(  void * phhalCt_Params,
                                    uint8_t * pbAtrBuffer,
                                    uint8_t * pbAtrSize,
                                    uint8_t bVccSel,
                                    uint8_t * pIFSC,
                                    uint8_t * pSelT0,
                                    uint8_t * pSelT1 );

/**
 * This function is used to deactivate the card.
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @return    Status code for deactivation.
 *
 * @retval    #PH_ERR_SUCCESS   Card is deactivated successfully.
 *
 */
phStatus16_t phhalCt_DeactivateCard( void * phhalCt_Params );

/**
 * This function is used to deactivate the card from ISR.
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @return    Status code for deactivation.
 *
 * @retval    #PH_ERR_SUCCESS   Card is deactivated successfully.
 *
 */
phStatus16_t phhalCt_DeactivateCard_fromISR( void * phhalCt_Params );

/**
 * This function is used to set the protocol T=0 or T=1.
 * @param[out] bCardProtocol - Protocol value, if set to 1 ,T=1 protocol else for other values T=0 will get select.
 *                             There is no checking for supported protocol in this api.User should pass only supported protocol as per Atr.
 *                             -Calling this api is optional to user,because activation and PPS exchange api calls this api itself in hal,
 *                             But If card atr supports both protocol then user can call this api after activation with his own choice
 *                             protocol.But User should not call this api after PPS Exchange with other than agreed protocol.
 *
 * @return    Status code for setting transmission protocol.
 *
 * @retval    #PH_ERR_SUCCESS   Protocol bit has been successfully set as per parameter.
 */
phStatus16_t phhalCt_SetTransmissionProtocol(uint8_t bCardProtocol);

/**
 * This function is used to transmit data to the card.
 * @param[in/out]   phhalCt_Params  HAL context structure pointer
 * @param[in]    pbTransmitData  Pointer to the transmit buffer.
 * @param[in]    wTransmitSize   Number of bytes to be transmitted to the card.
 * @return       Status code for transmit operation.
 *
 * @retval    #PH_ERR_SUCCESS   Bytes have been transmitted successfully.
 * @maskedret #PH_ERR_OPERATION_TIMEDOUT   Api timed out.
 * @maskedret #PH_ERR_INVALID_PARAMETER    Parameters are invalid.
 * @maskedret #PH_ERR_CT_PARITY_ERROR      Card has nacked the bytes.
 * @maskedret #PH_ERR_CT_OVERUN_ERROR      Fifo is over run while transmitting the bytes.
 * @maskedret #PH_ERR_CT_FRAMING_ERROR     Framing error while transmitting the bytes.
 */
phStatus16_t phhalCt_Transmit(void * const phhalCt_Params, uint8_t const * const pbTransmitData, uint16_t wTransmitSize);

/**
 * This function is used to receive the data from card.
 * @param[in/out]   phhalCt_Params  HAL context structure pointer
 * @param[out]   pbReceiveData   Pointer to the receive buffer.
 * @param[out]    wReceiveSize    Number of bytes to be received from the card.
 * @return Status code for receive operation.
 *
 * @retval    #PH_ERR_SUCCESS   Bytes have been received successfully.
 *
 * @maskedret #PH_ERR_OPERATION_TIMEDOUT  Api timed out.
 * @maskedret #PH_ERR_INVALID_PARAMETER   Parameters are invalid.
 * @maskedret #PH_ERR_CT_PARITY_ERROR     Card has parity errors while sending the bytes.
 * @maskedret #PH_ERR_CT_OVERUN_ERROR     Fifo is over run while receiving the bytes.
 * @maskedret #PH_ERR_CT_FRAMING_ERROR    Framing error while receiving the bytes.
 * @maskedret #PH_ERR_CT_TIME_OUT_WWT_OR_BWT   BWT/CWT timer elapsed in case of T=1 or WWT timer elapsed in case of T=0.
 */
phStatus16_t phhalCt_Receive(void * phhalCt_Params, uint8_t *pbReceiveData, uint16_t wReceiveSize);

/**
 * This function is used for PPS request and PPS response handling in negotiable mode.
 * This function also applies new baud rate and new protocol according to negotiated values.
 * @note    Before Calling this Api user has to call #phhalCt_SetTimer with #PHHAL_CT_PPSMODE_9600_ETU mode.
 *        - Parity error retry count for PPS Exchange is used is 7.
 *        - For Errorneous Status code, Structure parameters will be reset to 0.But for #PH_ERR_PPS_EXCHANGE_NOT_REQUIRED
 *          structure parameter will have value same as input.
 *
 * @param[in/out]   phhalCt_Params  HAL context structure pointer
 *                - bFidi will be updated with supported FiDi after PPS.
 *                - bProtSelT0 ,bProtSelT1 will be output as per what protocol will be selected after PPS exchange.
 *
 * @return Status code for PPS Exchange operation.
 *
 * @retval    #PH_ERR_SUCCESS  If Correct PPS Response has been received successfully,structure parameters
 *                             will be updated as per PPS Response .
 * @maskedret #PH_ERR_INVALID_PARAMETER  Parameters are invalid.
 * @maskedret #PH_ERR_CT_PPS_EXCHANGE_ERROR    If Wrong PPS response has been received.
 * @maskedret #PH_ERR_PPS_EXCHANGE_NOT_REQUIRED  If PPS Exchange is called with default baudrate and first offered protocol.
 *
 */
phStatus16_t phhalCt_PPSRequestHandling( void * phhalCt_Params );

/**
 * Stops CT IP Timer, direct setting up registers
 * @param     none
 * @retval    none
 */
void phhalCt_StopCTTimer( void );

/**
 * Set the CT hal configurations to the desired value.
 *
 * @param[in/out] phhalCt_Params  HAL context structure pointer
 * @param[in] eConfig          CT HAL configurations.
 * @param[in] dwValue          Desired value to be set the mentioned CT hal configuration.
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
 * @return Status for CT set configurations.
 *
 * @retval    #PH_ERR_SUCCESS             operation is successful.
 * @maskedret #PH_ERR_INVALID_PARAMETER   for invalid parameter.
 */
phStatus16_t phhalCt_SetConfig(void * phhalCt_Params, phAppCt_Configs_t eConfig, uint8_t dwValue, uint32_t dwMode, uint32_t dwWTX);

/**
 * This function is used to check if card is present in the requested slot
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @retval #PH_ERR_CT_INVALID_SLOT       Invalid slot is chosen
 * @retval #PH_ERR_CT_MAIN_CARD_PRESENT  card is present.
 * @retval #PH_ERR_CT_MAIN_CARD_ABSENT   card is absent.
 */
phStatus16_t phhalCt_CheckCardPres( void * phhalCt_Params );

/**
 * This function returns currently selected card slot number
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @retval    phhalCt_SlotType_t current selected slot enum number
 */
phhalCt_SlotType_t phhalCt_GetSelectedSlot( void * phhalCt_Params );

/**
 * This function checks the card activation state of currently selected slot number
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 *
 * @retval #PH_ERR_CT_INVALID_SLOT       Invalid slot is chosen
 * @retval #PH_ERR_CT_CARD_ALREADY_ACTIVATED  card is in activate state
 * @retval #PH_ERR_CT_CARD_DEACTIVATED   card is in deactivation state
 */
phStatus16_t phhalCt_CheckCardActive( void * phhalCt_Params );

/**
 * User function for providing microsecond delay
 *
 * @param[in] dwUSec      count in microseconds
 *
 * @retval    none
 */
void phUser_Wait(uint32_t dwUSec);

/**
 * User function wrapper calling internally memset
 *
 * @param[out] pvBuf       buffer pointer
 * @param[in] dwu8Val     value to be set
 * @param[in] dwLength    number of bytes
 *
 * @retval    none
 */
void phUser_MemSet(void* pvBuf, uint32_t dwu8Val, uint32_t dwLength);

/**
 * User function wrapper calling internally memcpy
 *
 * @param[out] pvDst       Destination buffer pointer
 * @param[in] pvSrc       Source buffer pointer
 * @param[in] dwLength    number of bytes
 *
 * @retval    none
 */
void phUser_MemCpy(void* pvDst, const void* pvSrc, uint32_t dwLength);

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */

#endif /* SDK_PN76_NONSECURE_DEVICES_PN76_DRIVERS_CT_PHHALCT_INTERFACE_H_ */


