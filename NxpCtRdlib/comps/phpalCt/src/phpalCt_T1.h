/*----------------------------------------------------------------------------*/
/* Copyright 2014-2024  NXP                                                   */
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
 *
 * This file contains the implementation of T=1 protocol.
 *
 * $Date$
 * $Author$
 * $Revision$
 *
 */

#ifndef PHPALCT_T1_H
#define PHPALCT_T1_H

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/**
 *
 * @brief Contact Interface Flash Code PAL layer implementation. This file implements the T=1 protocol.
 *
 */

/* *******************************************************************************************************************
 *  Includes
 * ****************************************************************************************************************** */
#include "phpalCt.h"

/* *******************************************************************************************************************
 * Global Defines
 * ****************************************************************************************************************** */

/**
 * Index of the NAD field in a block
 */
#define PHPAL_CT_T1_NAD             0
/**
 * Index of the PCB field in a block
 */
#define PHPAL_CT_T1_PCB             1
/**
 * Index of the LEN field in a block
 */
#define PHPAL_CT_T1_LEN             2
/**
 * Index of the Information Field in a block
 */
#define PHPAL_CT_T1_INF             3

/**
 *  R-Blocks PCB field definitions
 */
#define PHPAL_CT_T1_R_BLOCK_OK_0          0x80      /*  Error free acknowledgment with sequence number = 0    */
#define PHPAL_CT_T1_R_BLOCK_OK_1          0x90      /*  Error free acknowledgment with sequence number = 1    */
#define PHPAL_CT_T1_R_BLOCK_BADPAR_0      0x81      /*  Parity error with sequence number = 0  */
#define PHPAL_CT_T1_R_BLOCK_BADPAR_1      0x91      /*  Parity error with sequence number = 1  */
#define PHPAL_CT_T1_R_BLOCK_BAD_0         0x82      /*  Other error with sequence number = 0  */
#define PHPAL_CT_T1_R_BLOCK_BAD_1         0x92      /*  Other error with sequence number = 1  */

/**
 * I-Blocks PCB field definitions
 */
#define PHPAL_CT_T1_I_BLOCK_NO_MBIT_0      0x00   /* I Block with no more bit set(no chaining) with sequence number=0*/
#define PHPAL_CT_T1_I_BLOCK_NO_MBIT_1      0x40   /* I Block with no more bit set(no chaining) with sequence number=1*/
#define PHPAL_CT_T1_I_BLOCK_MBIT_0         0x20   /* I Block with more bit set(chaining) with sequence number=0 */
#define PHPAL_CT_T1_I_BLOCK_MBIT_1         0x60   /* I Block with more bit set(chaining) with sequence number=1 */

/**
 * S-Blocks PCB field definitions
 */
#define PHPAL_CT_T1_S_BLOCK_RESYNCH_REQ   0xC0      /* S Block with resync request */
#define PHPAL_CT_T1_S_BLOCK_RESYNCH_RESP  0xE0      /* S Block with resync response */
#define PHPAL_CT_T1_S_BLOCK_IFS_REQ       0xC1      /* S Block with IFS request */
#define PHPAL_CT_T1_S_BLOCK_IFS_RESP      0xE1      /* S Block with IFS response */
#define PHPAL_CT_T1_S_BLOCK_ABORT_REQ     0xC2      /* S Block with chaining abort request */
#define PHPAL_CT_T1_S_BLOCK_ABORT_RESP    0xE2      /* S Block with chaining abort response */
#define PHPAL_CT_T1_S_BLOCK_WTX_REQ       0xC3      /* S Block with wait time extension request */
#define PHPAL_CT_T1_S_BLOCK_WTX_RESP      0xE3      /* S Block with wait time extension response */

/**
 * T1 protocol transport layer state machine
 */
#define PHPAL_CT_T1_TL_SEND                                0x01      /* */
#define PHPAL_CT_T1_TL_SEND_CHAINING                       0x02      /* */
#define PHPAL_CT_T1_TL_RECEIVE                             0x03      /* */
#define PHPAL_CT_T1_TL_RECEIVE_CHAINING                    0x04      /* */
#define PHPAL_CT_T1_TL_RETRANSMIT                          0x05      /* */
/**
 * T1 protocol data link layer state machine
 */
#define PHPAL_CT_T1_DL_SEND_BLOCK                          0x01      /* */
#define PHPAL_CT_T1_DL_RECEIVE_BLOCK                       0x02      /* */
#define PHPAL_CT_T1_DL_RECEIVED_S_BLOCK                    0x03      /* */
#define PHPAL_CT_T1_DL_RECEIVED_R_BLOCK                    0x04      /* */

/**
 *
 * Minimum value of IFSC accepted in EMVCo
 */
#define PHPAL_CT_T1_MIN_IFSC_VAL                            16

/**
 * Maximum value of IFSC accepted in EMVCo
 *
 */
#define PHPAL_CT_T1_MAX_IFSC_VAL                            254

/**
 *
 * Maximum number of retries before we do the de-activation or return error to the user
 */
#define PHPAL_CT_T1_MAX_RETRY_COUNT                         2
/* *******************************************************************************************************************
 * Type Definitions
 * ****************************************************************************************************************** */
/** Enums for sent R Block status for received I Block,this will help to maintain error for received I block.*/
typedef enum
{
    E_R_NO_BLOCK_SEND, /**< R Block is not send.*/
    E_R_ERROR_FREE, /**< R Block indicating error free  Ack. is send from terminal.*/
    E_R_PARITY_ERROR,/**< R Block indicating parity error is send.*/
    E_R_OTHER_ERROR /**< R Block indicating other error is send.*/
}phpalCt_RBlockSendType_t;
/* *******************************************************************************************************************
 * Function Prototypes
 * ****************************************************************************************************************** */

/**
 * Initializes the pal layer of the Ct interface.
 * The initialization includes the reader side capabilities like IFSD,chaining,sequence counters etc..
 * @return
 * @retval #PH_ERR_SUCCESS
 */
phStatus16_t phpalCt_T1_Init( phpalCt_DATAParams_t * phpalCt_DATAParams );

/**
 * Resets all the counters and resets the state machine
 *
 * @return
 * @retval #PH_ERR_SUCCESS
 */
phStatus16_t phpalCt_T1_DeInit(phpalCt_DATAParams_t * phpalCt_DATAParams);

/**
 * @brief This function transmits the Apdu in T=1 protocol and returns the response to the application.
 *
 * This Transceive API supports Split Tx and RX chaining in transceive operations.
 * The T=1 protocol is further divided into Transport Layer(handling of chaining) and
 * Data Link Layer(error, acknowledgment handling). This function handles the Transport layer of the T=1 protocol,
 * which includes sending the I-Block without chaining or with chaining if required. Also the function receives the
 * I-Block without chaining or with chaining.
 * The state machine will return to the application layer if and only there is successful exchange of I blocks
 * or if there any timeout error (from unresponsive card).
 * @warning This approach is only for the internal implementation convenience and
 * there is nothing specified in the specification as such.
 * @warning The protocol has to be selected before calling this Api
 *
 * @param pbTransmitBuff(in) - Pointer to the transmit buffer
 * @param dwTransmitSize(in) - Size of the bytes to be transmitted
 * @param pbReceiveBuff(out) - Pointer to the receive buffer
 * @param dwReceiveSize(out) - Pointer to the receive buffer size
 * @param eOption(in)        - Enum Constant indicating the expected behaviour of the Tranceive operation.
 * @return
 */
phStatus16_t phpalCt_T1_Transcieve_SplitChaining( phpalCt_DATAParams_t * phpalCt_DATAParams,
												uint8_t* pbTransmitBuff,
												uint32_t dwTransmitSize,
												uint8_t* pbReceiveBuff,
												uint16_t* pwReceiveSize,
												phpalCt_TransceiveOption_t eOption );

//#endif /* NXPBUILD__PHPAL_CT */

#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
#endif /* PHPALCT_T1_H */