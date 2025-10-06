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

/* *******************************************************************************************************************
 * Includes
 * ****************************************************************************************************************** */
 
#include "phpalCt.h"
#include "phpalCt_T1.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/* *******************************************************************************************************************
 * Internal Definitions
 * ****************************************************************************************************************** */
/**
 * IFSD size of the interface device and is fixed to 254 in case of EMVCo
 */
#define PHPAL_CT_T1_IFSD 254
/* *******************************************************************************************************************
 * Type Definitions
 * ****************************************************************************************************************** */
typedef enum
{
    PH_ERR_CT_RETRANSMISSION_REQUIRED = (PH_CT_ERR_CUSTOM_BEGIN + 0x0021) /**< If Retransmission is needed.*/
} phpalCt_ErrorCodesT1_t;
/* *******************************************************************************************************************
 * Global and Static Variables
 * ****************************************************************************************************************** */

/* *******************************************************************************************************************
 * Private Function Prototypes
 * *******************************************************************************************************************/
/**
 *@brief This function is used to send S block from terminal to card.
 * @param dwType - Type of S block(Request/Response) to be send.
 * @param pbRecvBuff - points to the last received block buffer from card.
 * @return #PH_CT_ERR_SUCCESS - if S block is send successfully.
 */
static phStatus16_t phpalCt_Send_S_Block(phpalCt_DATAParams_t *phpalCt_DATAParams,
                                         uint32_t dwType,
                                         uint8_t *pbRecvBuff);
/**
 * @brief This function is used to send R block from terminal to card.
 * @param dwType - It indicates R Block PCB.
 * @return #PH_CT_ERR_SUCCESS - if R block is send successfully.
 */
static phStatus16_t phpalCt_Send_R_Block(phpalCt_DATAParams_t *phpalCt_DATAParams, uint32_t dwType);
/**
 *@brief This function is used to compute LRC for Blocks.
 * @param pbBlock - points to Block which LRC is need to calculate.
 * @param wLength - Total length for Block.
 * @return bLrc - The LRC value came after calculation.
 */
static uint8_t phpalCt_ComputeLrc(uint8_t *pbBlock, uint16_t wLength);
/**
 *@brief This function is used to compute LRC for Blocks.
 * @param pbBlock - points to Block which LRC is need to calculate.
 * @param wLength - Total length for Block.
 * @param bLrc - The LRC value for block.
 * @return PH_CT_ERR_SUCCESS - If LRC Value is correct.
 *         PH_CT_ERR_FAILED - IF LRC  Value is  not correct.
 */
static phStatus16_t phpalCt_VerifyLrc(uint8_t *pbBlock, uint16_t wLength, uint8_t bLrc);
/**
 * It handles which type of R block(Error free/Indicating parity or other error) to be send for received I block.
 * @return PH_CT_ERR_SUCCESS
 */
static phStatus16_t phpalCt_HandleCardError(phpalCt_DATAParams_t *phpalCt_DATAParams);
/**
 *@brief This function is used to verify PCB for recieved block ,it is valid PCB or not.
 * @param pbReceiveBuff - points to received block.
 * @return PH_CT_ERR_SUCCESS
 *         PH_CT_ERR_FAILED
 */
static phStatus16_t phpalCt_CheckPcb(uint8_t *pbReceiveBuff);
/**
 *@brief This function works as a general
 * @param pbReceiveBuff
 * @return
 */
static phStatus16_t phpalCt_ReceiveGeneral(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff);

/**
 * This Api is to abstract the Hal transmit functionality since we have to start the BWT timer inside
 */
static phStatus16_t phpalCt_SendData_Card(phpalCt_DATAParams_t *phpalCt_DATAParams,
                                          uint8_t *pbTransmitData,
                                          uint16_t wTransmitSize);

/**
 * @brief This is the data link layer state machine of the T=1 protocol.
 * This function does not returns until it sends an I-Block and receives a successful I-Block.
 * It returns to the  transport layer state machine if chaining is going on from IFD or card.
 * All the error handling scenarios will be handled in this function.
 * @param pbTransmitBuff
 * @param dwTransmitSize
 * @param pbReceiveBuff
 * @param pwReceiveSize
 * @return
 */
static phStatus16_t phpalCt_T1_DL_StateMachine(phpalCt_DATAParams_t *phpalCt_DATAParams, uint32_t dwTransmitSize);

/**
 *This function is used to check S block response and request.
 */
static phStatus16_t phpalCt_HandleSBlock(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff);

/**
 *This function is used to check R block response.
 */
static phStatus16_t phpalCt_HandleRBlock(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff);

/**
 *This function is used to Negotiate IFSD request and response.
 */
static phStatus16_t phpalCt_NegoIfsd(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff);

/* *******************************************************************************************************************
 *   Public Functions
 * *******************************************************************************************************************/

/**
 * Initializes the pal layer of the Ct interface.
 * The initialization includes the reader side capabilities like IFSD,chaining,sequence counters etc..
 * @return
 */
phStatus16_t phpalCt_T1_Init(phpalCt_DATAParams_t *phpalCt_DATAParams)
{
    phStatus16_t phStatus = PH_CT_ERR_SUCCESS;
    /* Reset the counters */
    phpalCt_DATAParams->sT1Params.gbReaderSequenceNo = 0x01;
    phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo =
        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01U));
    phpalCt_DATAParams->sT1Params.gbCardSequenceNo        = 0x00;
    phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x00;
    phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs   = 0x00;
    phpalCt_DATAParams->sT1Params.gbRetryCount            = 0x00;
    phpalCt_DATAParams->sT1Params.gbSBlockFlag            = 0x00;
    phpalCt_DATAParams->sT1Params.gbTLState               = PHPAL_CT_T1_TL_SEND;
    phpalCt_DATAParams->sT1Params.gbDLState               = PHPAL_CT_T1_DL_SEND_BLOCK;
    phpalCt_DATAParams->sT1Params.gbWTX                   = 0x01;
    phpalCt_DATAParams->sT1Params.gbResynchReqSend        = 0x00;
    /* Making by default NAD value for Card and interface device as non addressing to be use.*/
    phpalCt_DATAParams->sProtParams.gphpalCt_BSadDad = 0x00;
    phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad = 0x00;
    phpalCt_DATAParams->sT1Params.gbLastChainedBlock = 0x00;
    phpalCt_DATAParams->sT1Params.gbChainAbort       = 0x00;
    phpalCt_DATAParams->sT1Params.gbRBlockType       = E_R_NO_BLOCK_SEND;
    phpalCt_DATAParams->sT1Params.gbBufferReference  = phhalCt_GetBuffReference();
    return phStatus;
}

/**
 * Resets all the counters and resets the state machine
 * @return
 */
phStatus16_t phpalCt_T1_DeInit(phpalCt_DATAParams_t *phpalCt_DATAParams)
{
    /* Reset the counters */
    phpalCt_DATAParams->sT1Params.gbReaderSequenceNo = 0x01;
    phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo =
        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01U));
    phpalCt_DATAParams->sT1Params.gbCardSequenceNo        = 0x00;
    phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x00;
    phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs   = 0x00;
    phpalCt_DATAParams->sT1Params.gbRetryCount            = 0x00;
    /* Clear the S-Block */
    phpalCt_DATAParams->sT1Params.gbSBlockFlag       = 0x00;
    phpalCt_DATAParams->sT1Params.gbWTX              = 0x01;
    phpalCt_DATAParams->sProtParams.gphpalCt_BSadDad = 0x00;
    phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad = 0x00;
    /* Reset the state machine */
    phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_SEND;
    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_SEND_BLOCK;

    return PH_CT_ERR_SUCCESS;
}

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
 * there is nothing specified in the ISO7816-3 or EMVCo specification as such.
 * @warning The protocol has to be selected before calling this Api
 *
 * @param pbTransmitBuff - Pointer to the transmit buffer
 * @param dwTransmitSize - Size of the bytes to be transmitted
 * @param pbReceiveBuff - Pointer to the receive buffer
 * @param dwReceiveSize - Pointer to the receive buffer size
 * @param eOption       - Enum Constant indicating the expected behaviour of the Tranceive operation.
 * @return
 */
phStatus16_t phpalCt_T1_Transcieve_SplitChaining(phpalCt_DATAParams_t *phpalCt_DATAParams,
                                                 uint8_t *pbTransmitBuff,
                                                 uint32_t dwTransmitSize,
                                                 uint8_t *pbReceiveBuff,
                                                 uint16_t *pwReceiveSize,
                                                 phpalCt_TransceiveOption_t eOption)
{
    phStatus16_t phStatus        = PH_CT_ERR_FAILED;
    uint16_t wTotalLength        = 0x00;
    uint16_t wChainingOffset     = 0x00;
    uint16_t wPrevChainingOffset = 0x00;
    uint32_t wRemainingBytes     = 0x00;
    uint8_t bBlockLength         = 0x00;

    /* Determine the entry point to the Transport Layer State machine */
    if (eOption == E_PHPAL_CT_RX_CHAINING)
    {
        /* Initialize the state machine to receive next block in RX Chain from ICC */
        phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RECEIVE_CHAINING;
    }
    else if ((dwTransmitSize > (uint32_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC)) ||
             (eOption == E_PHPAL_CT_TX_CHAINING))
    {
        /* Change the state machine to send via chaining */
        phpalCt_DATAParams->sT1Params.gbTLState               = PHPAL_CT_T1_TL_SEND_CHAINING;
        wRemainingBytes                                       = dwTransmitSize;
        phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x01;
    }
    else
    {
        /* Initialize the state machine to the send Apdu */
        phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_SEND;
    }

    do
    {
        /* Negotiate IFSD if the first S-Block IFSD negotiation is not yet done */
        if (phpalCt_DATAParams->sT1Params.gbSBlockFlag == 0x00)
        {
            /* artf153487 - To  add 7 etu delay for first block of T=1 protocol ,as T=0 is protocol is selected by
             default, for which bgt is 16 etu around.*/
            phUser_Wait(800);
            /* Negotiate the IFSD with the ICC.
             * The pbReceiveBuff is dummy here while sending IFS request */
            phStatus = phpalCt_NegoIfsd(phpalCt_DATAParams, pbReceiveBuff);
            PH_CT_RETURN_ON_FAILURE(phStatus);

        }

        /* Continuous loop until we send back the Apdu response or timeout error */
        while (1)
        {
            switch (phpalCt_DATAParams->sT1Params.gbTLState)
            {
                case PHPAL_CT_T1_TL_SEND:
                {
                    if (phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs)
                    {
                        /* Last call to Transceive was with TX_CHAINING ON. Only last block needs to be sent */
                        phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x00;

                        /* This will be the last packet to send */
                        phpalCt_DATAParams->sT1Params.gbLastChainedBlock = 0x01;
                    }

                    /* Prepare the sequence counter */
                    phpalCt_DATAParams->sT1Params.gbReaderSequenceNo =
                        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01));
                    /* Prepare the next sequence counter */
                    phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo =
                        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01));

                    /* Copy the NAD byte */
                    phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_NAD] =
                        phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

                    /* Copy the PCB byte */
                    if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                    {
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                            PHPAL_CT_T1_I_BLOCK_NO_MBIT_1;
                    }
                    else
                    {
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                            PHPAL_CT_T1_I_BLOCK_NO_MBIT_0;
                    }

                    /* Copy the Length byte */
                    phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN] = (uint8_t)(dwTransmitSize);
                    bBlockLength                                                     = (uint8_t)dwTransmitSize;

                    /* Copy the apdu in the information field */
                    (void)phUser_MemCpy(&phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                        pbTransmitBuff, dwTransmitSize);

                    wTotalLength        = (uint16_t)(dwTransmitSize + 3);
                    wPrevChainingOffset = 0x00;

                    /* Transmit the block to the card and wait for the response */
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_SEND_BLOCK;
                    phStatus = phpalCt_T1_DL_StateMachine(phpalCt_DATAParams, wTotalLength);

                    if (phStatus == PH_CT_ERR_SUCCESS)
                    {
                        /* Change the state machine to the receive */
                        phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RECEIVE;
                    }
                    else
                    {
                        if ((PH_CT_COMP_PAL_CT | PH_ERR_CT_RETRANSMISSION_REQUIRED) == phStatus)
                        {
                            /* Increment the retry counter for resending the block*/
                            phpalCt_DATAParams->sT1Params.gbRetryCount++;
                            phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RETRANSMIT;
                            break;
                        }
                        /* Return the error */
                        return phStatus;
                    }
                }
                break;

                case PHPAL_CT_T1_TL_SEND_CHAINING:
                {
                    /* Prepare the sequence counter */
                    phpalCt_DATAParams->sT1Params.gbReaderSequenceNo =
                        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01));
                    /* Prepare the next sequence counter */
                    phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo =
                        (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbReaderSequenceNo) & (uint8_t)(0x01));
                    /* Check still the remaining bytes are greater than the IFSC
                     * If yes then send via chaining */
                    if (wRemainingBytes > (uint16_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC))
                    {
                        wRemainingBytes =
                            (wRemainingBytes - (uint16_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC));

                        /* Copy the NAD byte */
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_NAD] =
                            phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

                        /* Copy the PCB byte */
                        if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_MBIT_1;
                        }
                        else
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_MBIT_0;
                        }

                        /* Copy the Length byte */
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN] =
                            (uint8_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC);
                        bBlockLength = (uint8_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC);
                        /* Copy the apdu in the information field */
                        (void)phUser_MemCpy(&phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                            &pbTransmitBuff[wChainingOffset],
                                            phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC);

                        wPrevChainingOffset = wChainingOffset;
                        /* Increase the offset by those many number of bytes */
                        wChainingOffset += (uint16_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC);

                        /* Add the NAD,PCB,and LEN bytes */
                        wTotalLength = (uint16_t)(phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC + 3);

                        /* Transmit the block to the card and wait for the response */
                        phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_SEND_BLOCK;
                        phStatus = phpalCt_T1_DL_StateMachine(phpalCt_DATAParams, wTotalLength);

                        if (phStatus != PH_CT_ERR_SUCCESS)
                        {
                            if ((PH_CT_COMP_PAL_CT | PH_ERR_CT_RETRANSMISSION_REQUIRED) == phStatus)
                            {
                                /* Increment the retry counter for resending the block*/
                                phpalCt_DATAParams->sT1Params.gbRetryCount++;
                                phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RETRANSMIT;
                                break;
                            }
                            /* Return the error */
                            return phStatus;
                        }
                    }
                    else
                    {
                        if (eOption != E_PHPAL_CT_TX_CHAINING)
                        {
                            /* This will be the last packet to send */
                            phpalCt_DATAParams->sT1Params.gbLastChainedBlock      = 0x01;
                            phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x00;
                        }

                        /* Copy the NAD byte */
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_NAD] =
                            phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

                        /* Copy the PCB byte */
                        if (phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs)
                        {
                            if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                            {
                                phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                    PHPAL_CT_T1_I_BLOCK_MBIT_1;
                            }
                            else
                            {
                                phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                    PHPAL_CT_T1_I_BLOCK_MBIT_0;
                            }
                        }
                        else
                        {
                            if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                            {
                                phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                    PHPAL_CT_T1_I_BLOCK_NO_MBIT_1;
                            }
                            else
                            {
                                phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                    PHPAL_CT_T1_I_BLOCK_NO_MBIT_0;
                            }
                        }

                        /* Copy the Length byte */
                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN] = (uint8_t)(wRemainingBytes);
                        bBlockLength                                                     = (uint8_t)(wRemainingBytes);

                        wPrevChainingOffset = wChainingOffset;
                        /* Copy the apdu in the information field */
                        (void)phUser_MemCpy(&phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                            &pbTransmitBuff[wChainingOffset], wRemainingBytes);

                        /* Add the NAD,PCB,and LEN bytes */
                        wTotalLength = (uint16_t)(wRemainingBytes + 3);

                        /* Transmit the block to the card and wait for the response */
                        phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_SEND_BLOCK;

                        phStatus = phpalCt_T1_DL_StateMachine(phpalCt_DATAParams, wTotalLength);

                        if (phStatus == PH_CT_ERR_SUCCESS)
                        {
                            /* If TX chaining is in progress, return so that user can call Transceive API with next TX
                             * Chain block */
                            if (eOption == E_PHPAL_CT_TX_CHAINING)
                            {
                                phStatus = (PH_CT_COMP_PAL_CT | PH_ERR_CT_PAL_SUCCESS_TX_CHAINING);
                                return phStatus;
                            }
                            else
                            {
                                /* TX Chaining is finished. We have sent the last block
                                 * Hence change the state machine to the receive */
                                phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RECEIVE;
                                wRemainingBytes                         = 0x00;
                                wChainingOffset                         = 0x00;
                            }
                        }
                        else
                        {
                            if ((PH_CT_COMP_PAL_CT | PH_ERR_CT_RETRANSMISSION_REQUIRED) == phStatus)
                            {
                                /* Increment the retry counter for resending the block*/
                                phpalCt_DATAParams->sT1Params.gbRetryCount++;
                                phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RETRANSMIT;
                                break;
                            }
                            /* Return the error */
                            return phStatus;
                        }
                    }
                }
                break;
                case PHPAL_CT_T1_TL_RETRANSMIT:
                {
                    phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_NAD] =
                        phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

                    /* Copy the PCB byte */
                    if (phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs)
                    {
                        /* Copy the PCB byte */
                        if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_MBIT_1;
                        }
                        else
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_MBIT_0;
                        }
                    }
                    else
                    {
                        if (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo == 0x01)
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_NO_MBIT_1;
                        }
                        else
                        {
                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_PCB] =
                                PHPAL_CT_T1_I_BLOCK_NO_MBIT_0;
                        }
                    }

                    /* Copy the Length byte */
                    phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN] = bBlockLength;

                    /* Copy the apdu in the information field */
                    (void)phUser_MemCpy(&phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                        &(pbTransmitBuff[wPrevChainingOffset]), (uint32_t)bBlockLength);

                    wTotalLength = (uint16_t)(bBlockLength + 3);

                    /* Transmit the block to the card and wait for the response */
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_SEND_BLOCK;
                    phStatus = phpalCt_T1_DL_StateMachine(phpalCt_DATAParams, wTotalLength);

                    if (phStatus == PH_CT_ERR_SUCCESS)
                    {
                        /* Chaining is finished we have sent the last block
                         * Hence change the state machine to the receive */
                        if (!(phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs))
                        {
                            /* Change the state machine to the receive */
                            phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RECEIVE;
                            wRemainingBytes                         = 0x00;
                            wChainingOffset                         = 0x00;
                        }
                        else if ((phpalCt_DATAParams->sT1Params.gbLastChainedBlock == 0x01) &&
                                 (eOption == E_PHPAL_CT_TX_CHAINING))
                        {
                            /* If TX chaining is in progress, but transmitted all available Tx Data,
                             * return so that user can call Transceive API with next TX Chain block */
                            phStatus = (PH_CT_COMP_PAL_CT | PH_ERR_CT_PAL_SUCCESS_TX_CHAINING);
                            return phStatus;
                        }
                        else
                        {
                            /* If TX chaining is in progress, but there is available Tx Data to transmit, then go back
                             * to Tx Chaining State.*/
                            phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_SEND_CHAINING;
                        }
                    }
                    else
                    {
                        if ((PH_CT_COMP_PAL_CT | PH_ERR_CT_RETRANSMISSION_REQUIRED) == phStatus)
                        {
                            /* Increment the retry counter for resending the block */
                            phpalCt_DATAParams->sT1Params.gbRetryCount++;
                            phpalCt_DATAParams->sT1Params.gbTLState = PHPAL_CT_T1_TL_RETRANSMIT;
                            break;
                        }
                        /* Return the error */
                        return phStatus;
                    }
                }
                break;
                case PHPAL_CT_T1_TL_RECEIVE:
                {
                    if (phpalCt_DATAParams->sT1Params.gbChainAbort)
                    {
                        /*ISO7816-3 : Data received before abort request is of no use.*/
                        phpalCt_DATAParams->sT1Params.gbChainAbort = 0x00; /* TODO: Should we change status returned? */
                    }

                    /* Copy received data to User Rx Buffer */
                    (void)phUser_MemCpy(&pbReceiveBuff[0],
                                        &phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                        phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN]);
                    /* Update Receive Length variable */
                    *pwReceiveSize = phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN];

                    wChainingOffset = 0x00; /* TODO: Is this needed ? */

                    if (phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs == 0x01)
                    {
                        /* If Card chaining (ie:RX chaining) is in progress,
                         * return so that user can call Transceive API to receive next RX Chain block */
                        phStatus = (PH_CT_COMP_PAL_CT | PH_ERR_CT_PAL_SUCCESS_RX_CHAINING);
                        return phStatus;
                    }
                    else
                    {
                        /* No More blocks to receive, simply return Success */
                        return phStatus;
                    }
                }
                break;
                case PHPAL_CT_T1_TL_RECEIVE_CHAINING:
                {
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                    phStatus = phpalCt_T1_DL_StateMachine(phpalCt_DATAParams, wTotalLength);
                    if (phStatus == PH_CT_ERR_SUCCESS)
                    {
                        if (phpalCt_DATAParams->sT1Params.gbChainAbort)
                        {
                            /*ISO7816-3 : Data received before abort request is of no use.*/
                            phpalCt_DATAParams->sT1Params.gbChainAbort =
                                0x00; /* TODO: Should we change status returned? */
                        }

                        /* Copy received data to User Rx Buffer */
                        (void)phUser_MemCpy(&pbReceiveBuff[0],
                                            &phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_INF],
                                            phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN]);
                        /* Update Receive Length variable */
                        *pwReceiveSize = phpalCt_DATAParams->sT1Params.gbBufferReference[PHPAL_CT_T1_LEN];

                        if (phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs == 0x01)
                        {
                            /* If Card chaining (ie:RX chaining) is in progress,
                             * return so that user can call Transceive API to receive next RX Chain block */
                            phStatus = (PH_CT_COMP_PAL_CT | PH_ERR_CT_PAL_SUCCESS_RX_CHAINING);
                            return phStatus;
                        }
                        else
                        {
                            /* No More blocks to receive, simply return Success */
                            return phStatus;
                        }
                    }
                    else
                    {
                        /* Return the error */
                        return phStatus;
                    }
                }
                break;
                default:
                {
                }
                break;
            }
        }
    } while (0);
}

/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */
/**
 * @brief This is the data link layer state machine of the T=1 protocol.
 * This function does not returns until it sends an I-Block and receives a successful I-Block.
 * It returns to the  transport layer state machine if chaining is going on from IFD or card.
 * All the error handling scenarios will be handled in this function.
 * @param pbTransmitBuff
 * @param dwTransmitSize
 * @param pbReceiveBuff
 * @param pwReceiveSize
 * @return
 */
static phStatus16_t phpalCt_T1_DL_StateMachine(phpalCt_DATAParams_t *phpalCt_DATAParams, uint32_t dwTransmitSize)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    uint8_t bLrc          = 0x00;
    uint8_t bReceiveBuffer[5];
    uint16_t wLength        = (uint16_t)(dwTransmitSize);
    uint8_t *pbTransmitBuff = phpalCt_DATAParams->sT1Params.gbBufferReference;
    uint8_t *pbReceiveBuff  = phpalCt_DATAParams->sT1Params.gbBufferReference;

    do
    {
        /* Continuous loop until we send back the Apdu response or timeout error */
        while (1)
        {
            switch (phpalCt_DATAParams->sT1Params.gbDLState)
            {
                case PHPAL_CT_T1_DL_SEND_BLOCK:
                {
                    /* No headers to be added in the data link layer */
                    /* Compute the LRC */
                    bLrc                    = phpalCt_ComputeLrc(pbTransmitBuff, wLength);
                    pbTransmitBuff[wLength] = bLrc;
                    wLength++;

                    phStatus = phpalCt_SendData_Card(phpalCt_DATAParams, pbTransmitBuff, wLength);
                    PH_CT_RETURN_ON_FAILURE(phStatus);
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;

                } /* End of case PHPAL_CT_T1_DL_SEND_BLOCK */
                break;
                case PHPAL_CT_T1_DL_RECEIVE_BLOCK:
                {
                    /* Reset the WTX value to original value for any block to be received
                     * If an S-Block Requeste comes again the WTX value will be overwritten in the S- Block
                     * handling case*/
                    phpalCt_DATAParams->sT1Params.gbWTX = 0x01;
                    /* Call the general receive and verify generic values */
                    phStatus = phpalCt_ReceiveGeneral(phpalCt_DATAParams, pbReceiveBuff);
                    if (PH_CT_ERR_SUCCESS != phStatus)
                    {
                        if (PH_CT_ERR_INTEGRITY_ERROR == phStatus)
                        {
                            if (phpalCt_DATAParams->sT1Params.gbResynchReqSend)
                            {
                                if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
                                {
                                    phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                                    phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                                }
                                else
                                {
                                    phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, PHPAL_CT_T1_S_BLOCK_RESYNCH_REQ,
                                                                    bReceiveBuffer);
                                    phpalCt_DATAParams->sT1Params.gbRetryCount++;
                                }
                            }
                            else
                            {
                                phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                            }
                            PH_CT_RETURN_ON_FAILURE(phStatus);
                            /* If other verification errors, remain in the DL state machine */
                            break;
                        }
                        else
                        {
                            return phStatus;
                        }
                    }

                    /* Check the block type if it is S block go to the S block state machine */
                    if ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0xC0) == 0xC0)
                    {
                        /* S block received */
                        phpalCt_DATAParams->sT1Params.gbDLState          = PHPAL_CT_T1_DL_RECEIVED_S_BLOCK;
                        phpalCt_DATAParams->sT1Params.gbLastChainedBlock = 0x00;
                    }
                    else if ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0xC0) == 0x80)
                    {
                        /* R block received */
                        phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVED_R_BLOCK;
                    }
                    else
                    {
                        phpalCt_DATAParams->sT1Params.gbLastChainedBlock = 0x00;
                        if (phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs == 0x01)
                        {
                            phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                            PH_CT_RETURN_ON_FAILURE(phStatus);

                            phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                            break;
                        }
                        /* I block received */
                        /* Validate the sequence number */
                        if (phpalCt_DATAParams->sT1Params.gbCardSequenceNo !=
                            ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0x40) >> 6))
                        {
                            /* Invalid sequence number from the card */
                            /* Send an R Block with the same sequence number of reader? (Not sure from the
                            specification point of view) and be in the same state i.e. receive state */
                            phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                            PH_CT_RETURN_ON_FAILURE(phStatus);
                            break;
                        }

                        /** To check if terminal also in chaining state.*/

                        /* Release the retry counter since we have received a proper I block */
                        phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                        phpalCt_DATAParams->sT1Params.gbRBlockType = E_R_NO_BLOCK_SEND;
                        /* Successfully received the I block from the card */
                        /* Increment the card's sequence number */
                        phpalCt_DATAParams->sT1Params.gbCardSequenceNo =
                            (uint8_t)((uint8_t)(~phpalCt_DATAParams->sT1Params.gbCardSequenceNo) & (uint8_t)(0x01));
                        /* Check if chaining from card is in progress or started */
                        if ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0x20) >> 5)
                        {
                            /* Chaining bit is set from the card */
                            /* Send R block as acknowledgment with the next expected sequence number from card */
                            if (phpalCt_DATAParams->sT1Params.gbCardSequenceNo)
                            {
                                phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_1);
                            }
                            else
                            {
                                phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_0);
                            }
                            phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs = 0x01;
                            phpalCt_DATAParams->sT1Params.gbRBlockType          = E_R_ERROR_FREE;
                            return phStatus;
                        }
                        else
                        {
                            /* Normal I block response received */
                            if (phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs == 0x01)
                            {
                                /* Last block from the card, hence clear the chaining flag */
                                phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs = 0x00;
                            }
                            else
                            {
                                if (phpalCt_DATAParams->sT1Params.gbChainAbort)
                                {
                                    phpalCt_DATAParams->sT1Params.gbChainAbort = 0x00;
                                    return PH_CT_ADD_COMPCODE(PH_ERR_CT_CHAINING_ABORT_REQUESTED, PH_CT_COMP_PAL_CT);
                                }
                            }
                            return phStatus;
                        }
                    }

                } /* End of case PHPAL_CT_T1_DL_RECEIVE_BLOCK */
                break;
                case PHPAL_CT_T1_DL_RECEIVED_S_BLOCK:
                {
                    phStatus = phpalCt_HandleSBlock(phpalCt_DATAParams, pbReceiveBuff);
                    PH_CT_RETURN_ON_FAILURE(phStatus);

                    /* Since this S-Block request is from the card side remain in the receive loop only */
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                } /* End of case PHPAL_CT_T1_DL_RECEIVED_S_BLOCK */
                break;
                case PHPAL_CT_T1_DL_RECEIVED_R_BLOCK:
                {
                    phStatus = phpalCt_HandleRBlock(phpalCt_DATAParams, pbReceiveBuff);
                    PH_CT_RETURN_ON_FAILURE(phStatus);
                    if (phpalCt_DATAParams->sT1Params.gbDLState != PHPAL_CT_T1_DL_RECEIVE_BLOCK)
                    {
                        return PH_CT_ERR_SUCCESS;
                    }

                } /* End of case PHPAL_CT_T1_DL_RECEIVED_R_BLOCK */
                break;
                default:
                {
                }
                break;
            } /* End of switch case state machine */
        }     /* End of while(1) */
    } while (0);
}
/**
 *
 * @param pbReceiveBuff
 * @return
 */
static phStatus16_t phpalCt_CheckPcb(uint8_t *pbReceiveBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    uint8_t bCount        = 0x00;
    uint8_t bPcbArray[16] = {
        PHPAL_CT_T1_I_BLOCK_NO_MBIT_0, PHPAL_CT_T1_I_BLOCK_NO_MBIT_1,    PHPAL_CT_T1_I_BLOCK_MBIT_0,
        PHPAL_CT_T1_I_BLOCK_MBIT_1,    PHPAL_CT_T1_R_BLOCK_OK_0,         PHPAL_CT_T1_R_BLOCK_OK_1,
        PHPAL_CT_T1_R_BLOCK_BADPAR_0,  PHPAL_CT_T1_R_BLOCK_BADPAR_1,     PHPAL_CT_T1_R_BLOCK_BAD_0,
        PHPAL_CT_T1_R_BLOCK_BAD_1,     PHPAL_CT_T1_S_BLOCK_RESYNCH_RESP, PHPAL_CT_T1_S_BLOCK_IFS_REQ,
        PHPAL_CT_T1_S_BLOCK_IFS_RESP,  PHPAL_CT_T1_S_BLOCK_ABORT_REQ,    PHPAL_CT_T1_S_BLOCK_ABORT_RESP,
        PHPAL_CT_T1_S_BLOCK_WTX_REQ,
    };
    for (bCount = 0x00; bCount < 16; bCount++)
    {
        if (pbReceiveBuff[PHPAL_CT_T1_PCB] == bPcbArray[bCount])
        {
            phStatus = PH_CT_ERR_SUCCESS;
            break;
        }
    }
    return phStatus;
}

/**
 * It handles which type of R block(Error free/Indicating parity or other error) to be send for received I block.
 * @return PH_CT_ERR_SUCCESS
 */
static phStatus16_t phpalCt_HandleCardError(phpalCt_DATAParams_t *phpalCt_DATAParams)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    uint8_t bReceiveBuffer[4];
    /* Check if we are in the receive loop for more than three retries */
    if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
    {
        phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
        if (phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn)
        {
            return PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
        }
        /*For non emvco only we are sending resynch request.*/
        phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, PHPAL_CT_T1_S_BLOCK_RESYNCH_REQ, bReceiveBuffer);
        return phStatus;
    }
    /* Send an R Block with the same sequence number when the length check fails
     * and be in the same state i.e. receive state */

    if (phpalCt_DATAParams->sT1Params.gbRBlockType == E_R_PARITY_ERROR)
    {
        if (phpalCt_DATAParams->sT1Params.gbCardSequenceNo)
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_BADPAR_1);
        }
        else
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_BADPAR_0);
        }
    }
    else if (phpalCt_DATAParams->sT1Params.gbRBlockType == E_R_ERROR_FREE)
    {
        if (phpalCt_DATAParams->sT1Params.gbCardSequenceNo)
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_1);
        }
        else
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_0);
        }
    }
    else
    {
        phpalCt_DATAParams->sT1Params.gbRBlockType = E_R_OTHER_ERROR;
        if (phpalCt_DATAParams->sT1Params.gbCardSequenceNo)
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_BAD_1);
        }
        else
        {
            phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_BAD_0);
        }
    }

    return phStatus;
}
/**
 *@brief This function is used to send S block from terminal to card.
 * @param dwType - Type of S block(Request/Response) to be send.
 * @param pbRecvBuff - points to the last received block buffer from card.
 * @return #PH_CT_ERR_SUCCESS - if S block is send successfully.
 */
static phStatus16_t phpalCt_Send_S_Block(phpalCt_DATAParams_t *phpalCt_DATAParams, uint32_t dwType, uint8_t *pbRecvBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;

    uint8_t bSBlock[5] = {0x00, 0x01, 0x00, 0x00, 0x00};

    uint8_t bTotalLen = 5; /* Minimum there is length of 5 */
    do
    {
        /* NAD value */
        bSBlock[PHPAL_CT_T1_NAD] = phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

        /* S Block PCB value */
        bSBlock[PHPAL_CT_T1_PCB] = (uint8_t)(dwType);

        /* Length is 0 for resync response */
        /* NOTE: Resync request, abort request, abort response are not allowed according to the EMVCo specification */
        bSBlock[PHPAL_CT_T1_LEN] = 0x01;

        if (dwType == PHPAL_CT_T1_S_BLOCK_IFS_RESP)
        {
            if ((pbRecvBuff[PHPAL_CT_T1_INF] < PHPAL_CT_T1_MIN_IFSC_VAL) ||
                (pbRecvBuff[PHPAL_CT_T1_INF] > PHPAL_CT_T1_MAX_IFSC_VAL))
            {
                phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                /* break out from the while loop */
                break;
            }
            else
            {
                /* Take the new IFSC value */
                phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC = pbRecvBuff[PHPAL_CT_T1_INF];
                bSBlock[PHPAL_CT_T1_INF]                       = phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC;
                /* A proper S-block arrived so release the retry counter */
                phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
            }
        }
        else if (dwType == PHPAL_CT_T1_S_BLOCK_IFS_REQ)
        {
            bSBlock[PHPAL_CT_T1_INF]               = (uint8_t)(PHPAL_CT_T1_IFSD);
            phpalCt_DATAParams->sT1Params.gbSBlock = 0x01;
        }
        else if (dwType == PHPAL_CT_T1_S_BLOCK_WTX_RESP)
        {
            /* If the integer multiple is of value 0 then it is an S-Block error */
            if (0 == pbRecvBuff[PHPAL_CT_T1_INF])
            {
                phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                /* break out from the while loop */
                break;
            }
            else
            {
                bSBlock[PHPAL_CT_T1_INF] = pbRecvBuff[PHPAL_CT_T1_INF];
                /* Store the WTX response */
                phpalCt_DATAParams->sT1Params.gbWTX = pbRecvBuff[PHPAL_CT_T1_INF];
                /* A proper S-block arrived so release the retry counter */
                phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
            }
        }
        else
        {
            if (dwType == PHPAL_CT_T1_S_BLOCK_RESYNCH_REQ)
            {
                bSBlock[PHPAL_CT_T1_LEN]                       = 0x00;
                bTotalLen                                      = 4;
                phpalCt_DATAParams->sT1Params.gbResynchReqSend = 0x01;
            }
            else
            {
                if (dwType == PHPAL_CT_T1_S_BLOCK_ABORT_RESP)
                {
                    bSBlock[PHPAL_CT_T1_LEN] = 0x00;
                    bTotalLen                = 4;
                }
            }
        }

        /* Compute and append the LRC */
        bSBlock[bTotalLen - 1] = phpalCt_ComputeLrc(bSBlock, (uint16_t)(bTotalLen - 1));
        /* Transmit */
        phStatus = phpalCt_SendData_Card(phpalCt_DATAParams, bSBlock, bTotalLen);
    } while (0);
    return phStatus;
}

/**
 * @brief
 * @param dwType
 * @return
 */
static phStatus16_t phpalCt_Send_R_Block(phpalCt_DATAParams_t *phpalCt_DATAParams, uint32_t dwType)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    uint8_t bRBlock[4]    = {0x00, 0x00, 0x00, 0x00};
    do
    {
        /* NAD value */
        bRBlock[PHPAL_CT_T1_NAD] = phpalCt_DATAParams->sProtParams.gphpalCt_BDadSad;

        /* R Block PCB value */
        bRBlock[PHPAL_CT_T1_PCB] = (uint8_t)(dwType);

        /* Compute the LRC */
        bRBlock[3] = phpalCt_ComputeLrc(bRBlock, (uint16_t)(3));
        /* Transmit */
        phStatus = phpalCt_SendData_Card(phpalCt_DATAParams, bRBlock, 4);
        PH_CT_BREAK_ON_FAILURE(phStatus);

        /* If we are sending any error blocks increment the retry count*/
        if ((bRBlock[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BADPAR_0) ||
            (bRBlock[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BADPAR_1) ||
            (bRBlock[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BAD_0) ||
            (bRBlock[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BAD_1))
        {
            phpalCt_DATAParams->sT1Params.gbRetryCount++;
        }
    } while (0);
    return phStatus;
}

/**
 *
 * @param bRBlock
 * @param wLength
 * @return
 */
static uint8_t phpalCt_ComputeLrc(uint8_t *pbBlock, uint16_t wLength)
{
    uint8_t bLrc        = 0x00;
    uint16_t wByteCount = 0x00;

    for (wByteCount = 0x00; wByteCount < wLength; wByteCount++)
    {
        bLrc ^= pbBlock[wByteCount];
    }

    return bLrc;
}

/**
 *
 * @param pbRBlock
 * @param wLength
 * @param bLrc
 * @return
 */
static phStatus16_t phpalCt_VerifyLrc(uint8_t *pbBlock, uint16_t wLength, uint8_t bLrc)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;

    if (bLrc == phpalCt_ComputeLrc(pbBlock, wLength))
    {
        phStatus = PH_CT_ERR_SUCCESS;
    }
    return phStatus;
}

static phStatus16_t phpalCt_ReceiveGeneral(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    uint16_t wLength      = 0x00;
    uint8_t bBlockParity  = 0x00;
    uint8_t bInvalidLen   = 0x00;

    do
    {
        /* Receive the first 3 bytes header information */
        /* Currently the parity error count is kept at 1. Please check this later */
        phStatus = phhalCt_Receive(phpalCt_DATAParams->phalDataParams, pbReceiveBuff, 3);
        if (PH_CT_ERR_SUCCESS != phStatus)
        {
            if ((PH_CT_COMP_HAL_CT | PH_ERR_CT_PARITY_ERROR) == phStatus)
            {
                bBlockParity = 0x01;
            }
            else if (((PH_CT_COMP_HAL_CT | PH_ERR_CT_TIME_OUT_WWT_OR_BWT) == phStatus) &&
                     (!(phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn)))
            {
                phStatus = PH_CT_ERR_INTEGRITY_ERROR;
                break;
            }
            else
            {
                (void)phhalCt_DeactivateCard(phpalCt_DATAParams->phalDataParams);
                phhalCt_StopCTTimer();
                break;
            }
        }

        /* Extract the length information */
        wLength = (uint16_t)(pbReceiveBuff[PHPAL_CT_T1_LEN]);
        /* Increase the wLength for epilogue field */
        /* Check the length information is within the limit (IFSD) */
        if (pbReceiveBuff[PHPAL_CT_T1_LEN] > PHPAL_CT_T1_IFSD)
        {
            bInvalidLen = 0x01;
        }
        wLength++;
        phStatus = phhalCt_Receive(phpalCt_DATAParams->phalDataParams, &pbReceiveBuff[PHPAL_CT_T1_INF], wLength);
        phhalCt_StopCTTimer();

        if (bInvalidLen)
        {
            phStatus = PH_CT_ERR_INTEGRITY_ERROR;
            break;
        }

        if ((PH_CT_ERR_SUCCESS != phStatus) || (bBlockParity))
        {
            if (((PH_CT_COMP_HAL_CT | PH_ERR_CT_PARITY_ERROR) == phStatus) || (bBlockParity))
            {
                if (!(phpalCt_DATAParams->sT1Params.gbSBlock) &&
                    (phpalCt_DATAParams->sT1Params.gbRBlockType == E_R_NO_BLOCK_SEND))
                {
                    phpalCt_DATAParams->sT1Params.gbRBlockType = E_R_PARITY_ERROR;
                }
                phStatus = PH_CT_ERR_INTEGRITY_ERROR;
            }
            break;
        }

        /* Invalid NAD handling */
        if (pbReceiveBuff[PHPAL_CT_T1_NAD] != phpalCt_DATAParams->sProtParams.gphpalCt_BSadDad)
        {
            phStatus = PH_CT_ERR_INTEGRITY_ERROR;
            break;
        }
        /* Check the invalid PCB case */
        /* If an R-Block is received ignore this check */
        phStatus = phpalCt_CheckPcb(pbReceiveBuff);
        if (PH_CT_ERR_SUCCESS != phStatus)
        {
            phStatus = PH_CT_ERR_INTEGRITY_ERROR;
            break;
        }

        /* Verify LRC */
        /* Add the first 3 bytes of prologue filed and neglect the epilogue field */
        phStatus = phpalCt_VerifyLrc(pbReceiveBuff, (wLength + 3 - 1), pbReceiveBuff[wLength + 3 - 1]);

        /* Check if the LRC verification is success */
        if (PH_CT_ERR_SUCCESS != phStatus)
        {
            if (!(phpalCt_DATAParams->sT1Params.gbSBlock) &&
                (phpalCt_DATAParams->sT1Params.gbRBlockType == E_R_NO_BLOCK_SEND))
            {
                phpalCt_DATAParams->sT1Params.gbRBlockType = E_R_PARITY_ERROR;
            }
            phStatus = PH_CT_ERR_INTEGRITY_ERROR;
        }
    } while (0);

    return phStatus;
}

static phStatus16_t phpalCt_SendData_Card(phpalCt_DATAParams_t *phpalCt_DATAParams,
                                          uint8_t *pbTransmitData,
                                          uint16_t wTransmitSize)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    /* Start the BWT timer */
    phhalCt_SetConfig(phpalCt_DATAParams->phalDataParams, E_CONF_TIMER, 0, PHHAL_CT_APDUMODE_BWT,
                      (uint32_t)phpalCt_DATAParams->sT1Params.gbWTX);

    phStatus = phhalCt_Transmit(phpalCt_DATAParams->phalDataParams, pbTransmitData, wTransmitSize);
    return phStatus;
}

static phStatus16_t phpalCt_HandleSBlock(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_SUCCESS;
    do
    {
        if (phpalCt_DATAParams->sT1Params.gbSBlock == 0x01)
        {
            if ((PHPAL_CT_T1_S_BLOCK_IFS_RESP != pbReceiveBuff[PHPAL_CT_T1_PCB]) ||
                ((uint8_t)(PHPAL_CT_T1_IFSD) != pbReceiveBuff[PHPAL_CT_T1_INF]) ||
                (0x01 != pbReceiveBuff[PHPAL_CT_T1_LEN]))
            {
                if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
                {
                    phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                    return PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                }
                phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, PHPAL_CT_T1_S_BLOCK_IFS_REQ, pbReceiveBuff);
                PH_CT_BREAK_ON_FAILURE(phStatus);
                phpalCt_DATAParams->sT1Params.gbRetryCount++;
                phStatus = PH_CT_ERR_INTEGRITY_ERROR;
            }
        }
        else
        {
            /* No sequence number will be attached to the S block so ignore the sequence number */
            if (PHPAL_CT_T1_S_BLOCK_ABORT_REQ == pbReceiveBuff[PHPAL_CT_T1_PCB])
            {
                if (phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn)
                {
                    phStatus = phhalCt_DeactivateCard(phpalCt_DATAParams->phalDataParams);
                    phStatus = phpalCt_T1_DeInit(phpalCt_DATAParams);
                    return PH_CT_ADD_COMPCODE(PH_ERR_CT_CHAINING_ABORT_REQUESTED, PH_CT_COMP_PAL_CT);
                }
                phStatus =
                    phpalCt_Send_S_Block(phpalCt_DATAParams, (uint32_t)(PHPAL_CT_T1_S_BLOCK_ABORT_RESP), pbReceiveBuff);
                phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs = 0x00;
                phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs   = 0x00;
                /*gbCardSequenceNo = 0x00;*/ /*CardSequence number will retain the same as it was before abort request*/
                phpalCt_DATAParams->sT1Params.gbChainAbort = 0x01;
            }
            else if (PHPAL_CT_T1_S_BLOCK_IFS_REQ == pbReceiveBuff[PHPAL_CT_T1_PCB])
            {
                if ((pbReceiveBuff[PHPAL_CT_T1_LEN] != 0x01))
                {
                    phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                }
                else
                {
                    /* When chaining is in progress card can not negotiate the IFSC request according to the EMVCo*/
                    if (phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs ||
                        phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs)
                    {
                        phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                    }
                    else
                    {
                        phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, (uint32_t)(PHPAL_CT_T1_S_BLOCK_IFS_RESP),
                                                        pbReceiveBuff);
                    }
                }
            }
            else if (PHPAL_CT_T1_S_BLOCK_WTX_REQ == pbReceiveBuff[PHPAL_CT_T1_PCB])
            {
                if ((pbReceiveBuff[PHPAL_CT_T1_LEN] != 0x01))
                {
                    phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                }
                else
                {
                    phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, (uint32_t)(PHPAL_CT_T1_S_BLOCK_WTX_RESP),
                                                    pbReceiveBuff);
                }
            }
            else if ((PHPAL_CT_T1_S_BLOCK_WTX_RESP == pbReceiveBuff[PHPAL_CT_T1_PCB]) ||
                     (PHPAL_CT_T1_S_BLOCK_IFS_RESP == pbReceiveBuff[PHPAL_CT_T1_PCB]) ||
                     (PHPAL_CT_T1_S_BLOCK_ABORT_RESP == pbReceiveBuff[PHPAL_CT_T1_PCB]))
            {
                phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
            }
            else
            {
                if ((PHPAL_CT_T1_S_BLOCK_RESYNCH_RESP == pbReceiveBuff[PHPAL_CT_T1_PCB]))
                {
                    if ((phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn) ||
                        !(phpalCt_DATAParams->sT1Params.gbResynchReqSend))
                    {
                        phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                    }
                    else
                    {
                        phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC = 0x20;
                        phpalCt_DATAParams->sT1Params.gbResynchReqSend = 0x00;
                        phpalCt_T1_Init(phpalCt_DATAParams);
                        phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RESYNCH_SUCCESS, PH_CT_COMP_PAL_CT);
                    }
                }
            }
        }
    } while (0);
    return phStatus;
}

static phStatus16_t phpalCt_NegoIfsd(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    /* Send IFSD request to card.*/
    phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, PHPAL_CT_T1_S_BLOCK_IFS_REQ, pbReceiveBuff);
    PH_CT_RETURN_ON_FAILURE(phStatus);

    while (1)
    {
        phStatus = phpalCt_ReceiveGeneral(phpalCt_DATAParams, pbReceiveBuff);
        if (PH_CT_ERR_INTEGRITY_ERROR == phStatus)
        {
            if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
            {
                phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                break;
            }
            phStatus = phpalCt_Send_S_Block(phpalCt_DATAParams, PHPAL_CT_T1_S_BLOCK_IFS_REQ, pbReceiveBuff);
            PH_CT_BREAK_ON_FAILURE(phStatus);
            phpalCt_DATAParams->sT1Params.gbRetryCount++;
        }
        else if (PH_CT_ERR_SUCCESS == phStatus)
        {
            phStatus = phpalCt_HandleSBlock(phpalCt_DATAParams, pbReceiveBuff);
            PH_CT_BREAK_ON_SUCCESS(phStatus);
            if (PH_CT_ERR_INTEGRITY_ERROR == phStatus)
            {
                /* Be in Receive loop for getting again IFSD response.*/
            }
            else
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
    /* Set the flag as 0 after first block negotiation done successfully.*/
    phpalCt_DATAParams->sT1Params.gbSBlock = 0x00;
    /* Stop the timer */
    phhalCt_StopCTTimer();

    /* Set the flag that the first S-Block negotiation is done */
    phpalCt_DATAParams->sT1Params.gbSBlockFlag = 0x01;
    return phStatus;
}

static phStatus16_t phpalCt_HandleRBlock(phpalCt_DATAParams_t *phpalCt_DATAParams, uint8_t *pbReceiveBuff)
{
    phStatus16_t phStatus = PH_CT_ERR_FAILED;
    do
    {
        if (0x00 != pbReceiveBuff[PHPAL_CT_T1_LEN])
        {
            phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
            PH_CT_BREAK_ON_FAILURE(phStatus);

            phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
        }
        else
        {
            if (phpalCt_DATAParams->sT1Params.gbCardChainingInPrgrs)
            {
                if ((phpalCt_DATAParams->sT1Params.gbCardSequenceNo))
                {
                    phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_1);
                }
                else
                {
                    phStatus = phpalCt_Send_R_Block(phpalCt_DATAParams, PHPAL_CT_T1_R_BLOCK_OK_0);
                }
                PH_CT_BREAK_ON_FAILURE(phStatus);
                phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                break;
            }
            /* Any error scenarios retransmit the frame ( Retransmit possible only three times) */
            if ((pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BADPAR_0) ||
                (pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BADPAR_1) ||
                (pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BAD_0) ||
                (pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_BAD_1))
            {
                /* If an R block comes with the next reader sequence number,
                      means the last I block has received correctly.
                   But we have not received the previous I block from the card correctly yet.
                 So send the R block with previous card sequence number to force a retransmission */
                if (phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo ==
                    ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0x10) >> 4))
                {
                    phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                    phStatus                                   = phpalCt_HandleCardError(phpalCt_DATAParams);
                    PH_CT_BREAK_ON_FAILURE(phStatus);
                    phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                }
                else
                {
                    /* Check if we are in the receive loop for more than three retries */
                    if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
                    {
                        phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                        phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                        break;
                    }

                    /* Retransmit the frame */
                    phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRANSMISSION_REQUIRED, PH_CT_COMP_PAL_CT);
                    break;
                }
            }
            else
            {
                if (((pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_OK_0) ||
                     (pbReceiveBuff[PHPAL_CT_T1_PCB] == PHPAL_CT_T1_R_BLOCK_OK_1)))
                {
                    if (phpalCt_DATAParams->sT1Params.gbChainAbort)
                    {
                        phpalCt_DATAParams->sT1Params.gbChainAbort = 0x00;
                        /* No need to update card sequence number after abort request.*/
                        /*gbCardSequenceNo = (uint8_t)((uint8_t)(~gbCardSequenceNo) & (uint8_t)(0x01));*/
                        return PH_CT_ADD_COMPCODE(PH_ERR_CT_CHAINING_ABORT_REQUESTED, PH_CT_COMP_PAL_CT);
                    }
                    if ((phpalCt_DATAParams->sT1Params.gbReaderChainingInPrgrs) == 0x01)
                    {
                        /* Acknowledgment for the chaining frame*/
                        /* Check the sequence number if improper then send SYNC request */
                        if (phpalCt_DATAParams->sT1Params.gbReaderNextSequenceNo !=
                            ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0x10) >> 4))
                        {
                            if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
                            {
                                phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                                return PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                            }
                            phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRANSMISSION_REQUIRED, PH_CT_COMP_PAL_CT);
                            break;
                        }
                        else
                        {
                            /* Release the retry counter since we have received a proper R block */
                            phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                            /* Proper R-Block as an acknowledgment for the chaining frame */
                            /* Return to the Transport layer to send the next chaining block */
                            phStatus = PH_CT_ERR_SUCCESS;
                            break;
                        }
                    }
                    else
                    {
                        if ((phpalCt_DATAParams->sT1Params.gbLastChainedBlock == 0x01) &&
                            (phpalCt_DATAParams->sT1Params.gbReaderSequenceNo ==
                             ((pbReceiveBuff[PHPAL_CT_T1_PCB] & 0x10) >> 4)))
                        {
                            /**
                             * Scenario where for last chained block error free response comes.
                             * For this scenario we have to retransmit the last chained block to card.
                             */
                            if (phpalCt_DATAParams->sT1Params.gbRetryCount == PHPAL_CT_T1_MAX_RETRY_COUNT)
                            {
                                phpalCt_DATAParams->sT1Params.gbRetryCount = 0x00;
                                return PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRY_COUNT_FAILURE, PH_CT_COMP_PAL_CT);
                            }
                            phStatus = PH_CT_ADD_COMPCODE(PH_ERR_CT_RETRANSMISSION_REQUIRED, PH_CT_COMP_PAL_CT);
                            break;
                        }
                        else
                        {
                            phStatus = phpalCt_HandleCardError(phpalCt_DATAParams);
                            PH_CT_BREAK_ON_FAILURE(phStatus);
                        }

                        phpalCt_DATAParams->sT1Params.gbDLState = PHPAL_CT_T1_DL_RECEIVE_BLOCK;
                    }
                }
            }
        }
    } while (0);
    return phStatus;
}
//#endif /* NXPBUILD__PHPAL_CT */

#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
