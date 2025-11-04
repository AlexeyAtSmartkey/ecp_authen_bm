/*----------------------------------------------------------------------------*/
/* Copyright 2014, 2015, 2022, 2024  NXP                                      */
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
 * Protocol Abstraction Layer APIs
 * $Author:  $
 * $Revision: $
 * $Date: $
 *
 * History:
 *
 */

#ifndef PHPAL_CT_H
#define PHPAL_CT_H
/* *****************************************************************************************************************
 * Includes
 * **************************************************************************************************************** */

#include "ph_Datatypes.h"
#include "ph_EStatus.h"
#include "phhalCt_Interface.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/* *****************************************************************************************************************
 * MACROS/Defines
 * **************************************************************************************************************** */
/**
 *  Default value for IFSC.
 */
#define PHPAL_CT_DEFAULT_IFSC                0x20
/**
 *Maximum Allowed Atr bytes for EMVCo Profile.
 */
#define PHPAL_CT_EMV_MAX_ATR_BYTES           32
/**
 *Maximum Allowed Atr bytes for 7816 Profile.
 */
#define PHPAL_CT_7816_MAX_ATR_BYTES          33
/**
 * Maximum possible Apdu size in T=0 protocol
 */
#define PHPAL_CT_MAX_APDU_SIZE_T0       261
/**
 * Minimum possible Apdu size in T=0 protocol
 */
#define PHPAL_CT_MIN_APDU_SIZE_T0       4

/* *****************************************************************************************************************
 * Types/Structure Declarations
 * **************************************************************************************************************** */

/**
 * These enums are used by PAL Apis for indicating different error status codes.
 */
typedef enum {
   PH_CT_ERR_CT_PROTOCOL_NOT_SUPPORTED = (PH_CT_ERR_CUSTOM_BEGIN+0x0001), /**< Selected protocol not supported */
   PH_ERR_CT_RETRY_COUNT_FAILURE,      /**< Terminal has tried retry for maximum retry count. */
   PH_ERR_CT_INS_COMMAND_ERROR,        /**< Invalid procedure byte received.  */
   PH_ERR_CT_EXT_APDU_NOT_SUPPORTED,   /**< Extended Apdu is not supported.*/
   PH_ERR_CT_RESYNCH_SUCCESS,          /**< Resynchronisation is done successfully in 7816 profile.*/
   PH_ERR_CT_CHAINING_ABORT_REQUESTED, /**< Abort chaining Request is received from card in T= 1.*/
   PH_ERR_CT_DADSAD_NOT_SUPPORTED,     /**< SAD or DAD is not supported for NAD.*/
   PH_ERR_CT_PAL_SUCCESS_TX_CHAINING,  /**< last TX block transmitted successfully, Send next Tx Chain block */
   PH_ERR_CT_PAL_SUCCESS_RX_CHAINING,  /**< last RX block received successfully, RX Chaining in progress. One or More Blocks to be received */
   PH_ERR_CT_PAL_INVALID               /**< Invalid Enum */
} phpalCt_ErrorCodes_t;
/** @} */

/**
 * Enum for Options for Split Chaining Transceive API
 */
typedef enum phpalCt_TransceiveOption
{
    E_PHPAL_CT_TXRX_DEFAULT = 0x00,    /**< Data to be Transmitted followed by Data Receive, without Chaining in Tx */
    E_PHPAL_CT_TX_CHAINING  = 0x01,    /**< Data to be transmitted with Chaining, and will be followed by another Tx data Block */
    E_PHPAL_CT_RX_CHAINING  = 0x02     /**< Data to be received with Chaining (May or May not be followed by more RX blocks) */
} phpalCt_TransceiveOption_t;

/**
 * Enumeration for the different class of the card
 */
typedef enum
{
    E_PHPAL_CT_VCC5             = 0x00,         /**< Class A is selected */
    E_PHPAL_CT_VCC3             = 0x01,         /**< Class B is selected */
    E_PHPAL_CT_VCC1M8           = 0x02,         /**< Class C is selected */
    E_PHPAL_CT_INVALID_CLASS    = 0xFF          /**< Invalid class selected */
} phpalCt_ClassType_t;


/**
 * Structure for ATR reception
 */
typedef struct phpalCt_DataParams
{
      uint8_t  *pbAtrBuffer;           /**< Pointer for ATR buffer */
      uint8_t  bAtrReceivedLength;     /**< Received ATR's length*/
      uint8_t  bSizeOfATRbuffer;       /**< Size of ATR buffer which user will provide */
} phpalCt_DataParams_t;

/**
 * Structure for generic protocol related parameters,extracted from card's ATR
 */
typedef struct phpalCt_ProtParams
{
      uint8_t  gphpalCt_ProtSel; /**< Variable to save card supported protocol */
      uint8_t  gphpalCt_BEmvEn;  /**< Variable to save EMVCo or NonEMVCo profile */
      uint8_t  gphpalCt_BSadDad; /**< NAD for  card to terminal communication.*/
      uint8_t  gphpalCt_BDadSad; /**< NAD for terminal to card communication.*/
      uint8_t  gphpalCt_BIFSC;   /**< Variable to save IFSC value from ATR for PAL.*/
} phpalCt_ProtParams_t;

/**
 * Structure for T=1 protocol related parameters, extracted from card's ATR
 */
typedef struct phpalCt_ProtT1
{
      uint8_t     gbReaderChainingInPrgrs;   /**< Chaining operation is in progress from reader side */
      uint8_t     gbCardChainingInPrgrs;     /**< Chaining operation is in progress from card side */
      uint8_t     gbCardSequenceNo;          /**< Current sequence number of the card */
      uint8_t     gbReaderSequenceNo;        /**< Current sequence number of the Interface device */
      uint8_t     gbReaderNextSequenceNo;    /**< Next sequence number of the Interface device */
      uint8_t     gbTLState;                 /**< Stores current gbTLState */
      uint8_t     gbDLState;                 /**< Stores current gbDLState */
      uint8_t     gbRetryCount;              /**< R-Block retry counter */
      uint8_t     gbSBlockFlag;              /**< S-Block flag used to know whether at the beginning of the protocol S block has been sent or not */
      uint8_t     gbSBlock;                  /**< IFSD Request reference */
      uint8_t     gbRBlockType;              /**< last Received I-block error type */
      uint8_t     gbWTX;                     /**< WTX value from the card */
      uint8_t     gbLastChainedBlock;        /**< last chained block from interface device */
      uint8_t     gbChainAbort;              /**< Chaining Abort */
      uint8_t     gbResynchReqSend;          /**< resynch req is send or not by interface device */
      uint8_t*    gbBufferReference;         /**< Hal buffer reference */
} phpalCt_ProtT1_t;

/**
 * Structure for T=0 protocol related parameters, extracted from card's ATR
 */
typedef struct phpalCt_ProtT0
{
      uint8_t     gClass;                    /**< Class byte for framing of the APDU command during the reception of procedure byte to save command */
      uint8_t     gINS;                      /**< Instruction byte for framing of the APDU command during the reception of procedure byte to save command */
      uint8_t     gbP1;                      /**< P1 byte for framing of the APDU command during the reception of procedure byte to save command */
      uint8_t     gbP2;                      /**< P2 byte for framing of the APDU command during the reception of procedure byte to save command */
      uint8_t     gbGetResponseApdu;         /**< get response command apdu */
      uint8_t     gCase_APDU;                /**< T0 case detection */
      uint8_t     gbSW1;                     /**< SW1 byte */
      uint8_t     gbSW2;                     /**< SW2 byte */
      uint8_t     gbGotSw2Byte_Case4S;       /**< 8 bit character used as a boolean flag to tell if the byte SW2 of the SW1SW2 status has been received from ICC, only in the case 4S scenarios */
      uint16_t    gbLen;                     /**< Length byte for framing of the APDU command during the reception of procedure byte to save command */
      uint8_t *   gbBuffReference;           /**< Hal buffer reference */
} phpalCt_ProtT0_t;

/**
 * Main Protocol Abstraction Layer (PAL) Context Structure consists of each slot Instances
 */
typedef struct phpalCt_DATAParams
{
      phpalCt_DataParams_t       sAtrParams;              /**< PAL ATR context */
      phpalCt_ProtParams_t       sProtParams;             /**< PAL protocol context*/
      phpalCt_ProtT0_t           sT0Params;               /**< PAL T=0 context */
      phpalCt_ProtT1_t           sT1Params;               /**< PAL T=1 context */
      void *                     phalDataParams;          /**< HAL Main context Structure Instance */
}phpalCt_DATAParams_t;

/* *****************************************************************************************************************
 * Extern Variables
 * **************************************************************************************************************** */

/* *****************************************************************************************************************
 * Function Prototypes
 * **************************************************************************************************************** */

/**
 * This function is used to initialize the CT IP PAL Layer, mainly initializes context structure params with defaults
 *
 * @param[in/out] phpalCt_DATAParams    PAL slot context structure pointer
 *
 * @retval #PH_ERR_SUCCESS   Initialization of CT IP PAL is successful.
 * @retval #PH_ERR_FAILED    Initialization of CT IP PAL failed.
 */
phStatus16_t phpalCt_Init( phpalCt_DATAParams_t * phpalCt_DATAParams );

/**
 * This Function does a cold reset/activate of the card for ATR reception based on requested slot instance pointer. the API
 * performs three iterations for different class selection starting with the CLASS A internally.
 *
 * @param[in/out] phpalCt_DATAParams    PAL slot context structure pointer
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
phStatus16_t phpalCt_ActivateCard ( phpalCt_DATAParams_t * phpalCt_DATAParams );

/**
 *
 * This Api calls the appropriate APi's of the underlying protocol for a T0 or T1 transcieve.
 * The transceive api internally uses the T=0 or T=1 protocol selection and routes the Apdu accordingly.
 *
 * @param[in/out]  phpalCt_DATAParams     PAL slot context structure pointer
 * @param[in]   pbTransmitBuff         Pointer to the transmit buffer
 * @param[in]   dwTransmitSize         Size of the bytes to be transmitted
 * @param[out]  pbReceiveBuff          Pointer to the receive buffer
 * @param[out]  pwReceiveSize          Pointer to the receive buffer size
 * @param[out]  eOption                PAL options for Transceive chaining
 *
 * @retval #PH_ERR_SUCCESS             The Apdu transmitted successfully and received the response successfully.
 * @retval #PH_ERR_INVALID_PARAMETER   Parameters are invalid.
 * @retval #PH_ERR_FAILED              Transcieve unsuccessful
 *
 * @maskedret    #PH_ERR_CT_CARD_REMOVED              Card absent
 * @maskedret    #PH_ERR_CT_CARD_DEACTIVATED          Card Deactivated due to removal or fault or removal-insert
 * @maskedret    #PH_ERR_CT_RETRY_COUNT_FAILURE       If Retry count has been exceeded than allowable value.
 * @maskedret    #PH_ERR_CT_INS_COMMAND_ERROR         Improper INS is received from card.
 * @maskedret    #PH_ERR_CT_RESYNCH_SUCCESS           If Resynchronisation happened for 7816 profile.
 * @maskedret    #PH_ERR_CT_CHAINING_ABORT_REQUESTED  If Chaining Abortion request is received from card
 * @maskedret    #PH_ERR_CT_EXT_APDU_NOT_SUPPORTED    If Extended command Apdu is passed for T0 protocol.
 */
phStatus16_t phpalCt_Transceive( phpalCt_DATAParams_t * phpalCt_DATAParams,
                                 uint8_t* pbTransmitBuff,
                                 uint32_t dwTransmitSize,
                                 uint8_t* pbReceiveBuff,
                                 uint16_t* pwReceiveSize,
                                 phpalCt_TransceiveOption_t eOption );

/**
 * Set the CT pal or hal configurations to the desired value.
 *
 * @param[in/out]   phpalCt_DATAParams     PAL slot context structure pointer
 * @param[out]   eConfig                CT configurable parameter
 * @param[in]   dwValue                Desired value to be set the mentioned configuration.
 *
 * @retval    #PH_ERR_SUCCESS             operation is successful.
 * @retval    #PH_ERR_INVALID_PARAMETER   invalid parameter.
 */
phStatus16_t phpalCt_SetConfig(phpalCt_DATAParams_t * phpalCt_DATAParams, phAppCt_Configs_t eConfig, uint8_t dwValue);

/**
 * Get the CT pal or hal configurations from the desired value.
 *
 * @param[in/out]   phpalCt_DATAParams     PAL slot context structure pointer
 * @param[out]   eConfig                CT configurable parameter
 * @param[in]   * pwValue              Desired value to be received in the variable from the mentioned configuration.
 *
 * @retval    #PH_ERR_SUCCESS             operation is successful.
 * @retval    #PH_ERR_INVALID_PARAMETER   invalid parameter.
 */
phStatus16_t phpalCt_GetConfig(phpalCt_DATAParams_t * phpalCt_DATAParams, phAppCt_Configs_t eConfig, uint8_t * pwValue);

/** @}.*/
#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
#endif /* PHPAL_CT_H */
