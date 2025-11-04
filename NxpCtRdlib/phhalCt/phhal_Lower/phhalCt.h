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
 * Hardware Abstraction Layer APIs mainly used by HAL itself
 * $Author:  $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 */

#ifndef PHHAL_CT_H
#define PHHAL_CT_H

/* *****************************************************************************************************************
 * Includes
 * *****************************************************************************************************************.*/
#include "ph_NxpCTBuild.h"
#include "ph_Datatypes.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "ph_EStatus.h"
#include "phhalCt_TDA.h"
#include "phhalCt_Event.h"
#include "phOsal.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * *****************************************************************************************************************.*/
/**
 * CT HAL internal buffer maximum size,
 * A software FIFO of 261 bytes is used in the HAL for synchronization with 32 byte hardware buffer.
 */
#define PHHAL_CT_MAXBUFSIZE                261
/* *****************************************************************************************************************
 * Types/Structure Declarations
 * *****************************************************************************************************************.*/
/**
 * CT ISR Call back function signature.
 */
typedef void ( *pphhalCt_CallbackFunc_t )( uint32_t );
/**
 * This structure contains the necessary protocol parameters required by the Pal layer.
 */
typedef struct
{
    uint8_t bNegotiableMode; /**< Used for set negotiable mode in 7816 profile in absence of TA2.*/
    uint8_t bTA2Bit8Set;     /**< Used for specific 7816 test to monitor bit 8 of TA2 */
    uint8_t bIsTA1Absent;    /**< Used for monitor absence of TA1 for 7816 test */
    uint8_t bFlagT15TAValue; /**< Used for storing value of first TA after setting flag 15.*/
    uint8_t bCRCPresent;     /**< Used to set if CRC will be used for 7816 profile.*/
    uint8_t bIFSC;           /**< Stores Card's maximum information field size in a block.*/
/** In Negotiable mode stores the fidi value as it comes in TA1 byte of atr,
 *  In specific mode,In EMVCo or if TA1 is absent then  stores baudrate which is going
 * to be use for further.*/
    uint8_t bFiDi;
    uint8_t bProtSelT0;      /**< Used for setting if T=0 protocol will be supported.*/
    uint8_t bProtSelT1;      /**< Used for setting if T=1 protocol will be supported.*/
    uint8_t bWI;             /**< Used for setting WI value for WWT calculation for T0 protocol.*/
    uint8_t bBWI;            /**< Used for setting BWI value for BWT calculation for T1 protocol.*/
    uint8_t bCWI;            /**< Used for setting CWI value for CWT calculation for T1 protocol.*/
}phhalCt_ProtocolParams_t;

/**
 * This Structure contains Atr parameters which will be used during Atr parsing.
 */
typedef struct
{
    uint8_t bInvalidAtr;            /**< Used to set flag if Atr is not according to standard.*/
    uint8_t bTCKByte;               /**< Used during ATR parser as TCK byte presence depends on TD1 byte.*/
    uint8_t bValueofNInTC1;         /**< Used to store extra guard time indicated by atr.*/
    uint8_t bEarlyEventFlag ;       /**< It will be update if early event occurs.*/
    uint8_t bFlagT15;               /**< Used for storing flag 15 information for 7816 if TD byte is as 0x0F.*/
    uint8_t bFlagT15TAPresent;      /**< Used for set presence of TA if flag 15 is present.*/
    uint8_t bWarmResetState;        /**< Used to check the warm reset status in card Warm reset.*/
    uint8_t bInvalidTA1;            /**< Used to set flag if unsupported baudrate indicated in specific mode. */
    uint8_t bInvalidTD1;            /**< Used to set flag if unsupported protocol indicated in specific mode. */
    uint8_t bLastOfferedProt;       /**< Last offered protocol by card in ATR */
    phhalCt_ProtocolParams_t sAtrHalParams;   /**< atr parameter structure */
}phhalCt_AtrParameterType_t;

/**
 * Slot Specific Structure contains each slot parameters and configurations
 */
typedef struct phhalCt_SlotParams
{
   uint8_t                       gphhalCt_BFiDi;         /**< FiDi value as per TA1 byte in Atr.*/
   uint8_t                       gphhalCt_BCurrentFiDi;  /**< Updated FiDi value in code according to negotiable or specific mode, this only will be used for setting baud rate.*/
   uint8_t                       gphhalCt_BEmvEn;        /**< Used to set flag for EMVCo profile.*/
   uint8_t                       gphhalCt_BFirstOfferedProt;     /**< Used to update first offered protocol according to TD1 in Atr.*/

   /* Following variables are used to hold the waiting times.*/
   uint32_t                      gphhalCt_DwCharacterWaitingTime;   /**< Used for inter-character delay time for APDU reception in T=1 protocol.*/
   uint32_t                      gphhalCt_DwWaitingTime;            /**< In T=0 APDU used for inter byte delay timer  for character reception.*/
   uint32_t                      gphhalCt_DwBlockWaitingTime;       /**< Used for the Block waiting timer[max block waiting time].*/

   phhalTda_DATAParams_t         * pTDAPins;             /**< HAL TDA control component holder */
   phhalCt_SlotType_t            SlotNum;                /**< HAL Slot number component holder */
   phhalCt_AtrParameterType_t    sAtrParams;             /**< Slot specific ATR parameters configurations */

}phhalCt_SlotParams_t;

/**
 * Main HAL Context Structure consists of common HAL & slot parameters or configurations
 */
typedef struct phhalCt_DATAParams
{
   uint8_t  		         gphhalCt_BActivationState;                /**< Used to check the activation status in Card Activate*/
   uint8_t  		         gphhalCt_BTimerCount;                     /**< 8 bit timer reg is used for 24000 etu ART timer, this variable is used for count */
   uint8_t  				   gphhalCt_DriverBuff[PHHAL_CT_MAXBUFSIZE]; /**< CT HAL internal 261 bytes software buffer for ATR and APDU reception.*/
   uint8_t  				   gphhalCt_BTransmitComplete;               /**< Used to set after transmission has successfully completed.*/
   uint8_t  				   gphhalCt_BCWTFlag;                        /**< Used to set only in T1 protocol when CWT is going to be use.*/
   uint8_t 		            gphhalCt_BParityErr;                      /**< parity error flag used for each TX/Rx */
   uint8_t 		            gphhalCt_BLastByteTransmit;               /**< Last byte Tx byte  */
   uint16_t 		         gphhalCt_WPendingBytes;                   /**< Used to store number of remaining byte in fifo which are not read still.*/
   uint16_t  				   gphhalCt_WReceiveOffset;                  /**< Used for keeping a count of the offset value in the APDU reception*/
   uint16_t 		         gphhalCt_WDataCount;                      /**< Used as index for storing data to HAL buffer in ISR context */
   uint16_t  				   gphhalCt_WReceiveSize;                    /**< ISR monitoring RX max size */
   uint32_t 				   gdwphhalCtRegIntrpts;                     /**< Unused for now */
   pphhalCt_CallbackFunc_t gpphhalCt_CallbackFunc;                   /**< Unused for now */
   phhalCt_EventType_t 		gphhalCt_InEvent;                         /**< Keeps event type requested/ expected */
   phhalCt_SlotType_t  		gphhalCt_SelectedSlot_t;                  /**< Used to check current slot selected */
   phOsal_EventObj_t 		HwEventObj;                               /**< Event Object */
   phhalCt_SlotParams_t 	phhalCt_Params[PHAPP_MAX_CT_SLOT_SUPPORTED]; /**< Slot specific number of HAL instances and there credentials */

}phhalCt_DATAParams_t;

/* *****************************************************************************************************************
 * Extern Variables
 * *****************************************************************************************************************.*/

/* *****************************************************************************************************************
 * Function Prototypes
 * *****************************************************************************************************************.*/
/**
 * The CT HAL Initialization will initialize hal data params with defaults, initialize CT IP and initialize all TDA controls, ISR etc
 *
 * @param[in/out] phhalCt_Params    HAL context structure pointer
 * @param[out]    eSlot             Slot number
 * @return Status for CT IP Initialization.
 *
 * @retval    #PH_ERR_SUCCESS  Initialization of CT IP is successful.
 * @retval    #PH_ERR_FAILED   Initialization of CT IP failed.
 */
phStatus16_t phhalCt_Init( void * phhalCt_Params, phhalCt_SlotType_t eSlot );

#endif /* NXPBUILD__PHHAL_CT.*/

/** @}.*/
#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */
