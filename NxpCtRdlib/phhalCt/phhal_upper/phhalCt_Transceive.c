/*
 *                    Copyright (c), NXP Semiconductors
 *
 *                       (C) NXP Semiconductors 2014,2015
 *
 *         All rights are reserved. Reproduction in whole or in part is
 *        prohibited without the written consent of the copyright owner.
 *    NXP reserves the right to make changes without notice at any time.
 *   NXP makes no warranty, expressed, implied or statutory, including but
 *   not limited to any implied warranty of merchantability or fitness for any
 *  particular purpose, or that the use will not infringe any third party patent,
 *   copyright or trademark. NXP must not be liable for any loss or damage
 *                            arising from its use.
 */

/** @file
 *
 * Implements CT HAL which directly interacts with CT IP registers.
 *
 * Project:  PN7462AU
 *
 * $Date$
 * $Author$
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include "ph_Datatypes.h"


#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "phhalCt.h"
#include "phhalCt_Int.h"
#include "phhalCt_Interface.h"
#include "phhalCt_Event.h"

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
/**
 * PPS request and response PPSS byte.
 */
#define PHHAL_CT_PPSS_BYTE                     0xFF

/**
 * Maximum fifo size in the CT IP.
 */
#define PHHAL_CT_MAX_FIFO_SIZE            32

/**
 *  Initial Threshold value for Fifo to get interrupt.
 */
#define PHHAL_CT_INITIAL_FIFO_THRESHOLD_VALUE  0x12

/**
 *  Fifo fill count for remaining bytes.
 */
#define PHHAL_CT_FIFO_FILL_COUNT   12

/**
 *  Maximum receive timeout value. This is calculated over default baud rate with maximum number of received bytes can
 *  be 254+4 = 258 bytes. 258 bytes in the interval of 10079 ETU(829 mili second).
 *  Hence the timeout value will be at least 258*1000(Mili Second)
 */
#define PHHAL_CT_MAX_RECEIVE_TIMEOUT   (258*1000)

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */
phStatus16_t phhalCt_PPSExchangeHandling( phhalCt_DATAParams_t * phhalCt_DATAParams,
                                                 uint8_t *pbPPSRequestBuffer ,
                                                 uint8_t *pbPPSResponseBuffer,
                                                 uint8_t bNegotiableProtocol );
/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

phStatus16_t phhalCt_Transmit(void * const phhalCt_Params, uint8_t const * const pbTransmitData, uint16_t wTransmitSize)
{
    uint8_t bLoopCount = 0x00;
    uint16_t  bCount = 0;
    uint16_t wRemainingBytes = 0x00;
    uint32_t dwExitFlag = 0x00;
    phStatus16_t eStatus = PH_CT_ERR_FAILED;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;

    phhalCt_DATAParams->gphhalCt_BTransmitComplete = 0x00;
    phhalCt_DATAParams->gphhalCt_WPendingBytes = 0x00;
    /* Clear the global data counter updated in ISR for reception of bytes.*/
    phhalCt_DATAParams->gphhalCt_WDataCount = 0x00;
    /* Clear the offset as well.*/
    phhalCt_DATAParams->gphhalCt_WReceiveOffset = 0x00;
    phhalCt_DATAParams->gphhalCt_BCWTFlag = 0x00;
    phhalCt_DATAParams->gphhalCt_BParityErr = 0x00;

    do
    {
        /* Check for the null pointer.*/
        if ((pbTransmitData == NULL) || (wTransmitSize == 0x00))
        {
           return PH_CT_ADD_COMPCODE(PH_CT_ERR_INVALID_PARAMETER, PH_CT_COMP_HAL_CT);
        }

        if( PH_ERR_CT_MAIN_CARD_ABSENT == phhalCt_CheckCardPres(phhalCt_DATAParams) )
        {
           return PH_CT_ADD_COMPCODE(PH_ERR_CT_MAIN_CARD_ABSENT, PH_CT_COMP_HAL_CT);
        }

        if( PH_ERR_CT_CARD_DEACTIVATED == phhalCt_CheckCardActive(phhalCt_DATAParams) )
        {
           return PH_CT_ADD_COMPCODE(PH_ERR_CT_CARD_DEACTIVATED, PH_CT_COMP_HAL_CT);
        }

        while(!(phhalCT_TESTBITN(eMSR, CT_MSR_BGT_SHIFT)))
        {
            /* To ensure transmission should start, only after BGT timer elapsed.*/
        }

        /* Check if the card removal event is pending */
        eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                         (phhalCt_EventType_t)(E_PH_HALCT_EVENT_CARD_REMOVED),
                                          1,
                                          FALSE );

        if(PH_CT_ERR_SUCCESS == eStatus)
        {
            if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_CARD_REMOVED) == E_PH_HALCT_EVENT_CARD_REMOVED)
            {
                phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)E_PH_HALCT_EVENT_CARD_REMOVED);
                eStatus = PH_ERR_CT_CARD_REMOVED;
                break;
            }
        }

        /* Save the last byte which will be filled in Fifo in ISR and LCT bit will be set */
        phhalCt_DATAParams->gphhalCt_BLastByteTransmit = pbTransmitData[wTransmitSize-1];

        /* Clear Events */
       (void) phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)(E_PH_HALCT_EVENT_ALL));

        phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;

        /* Flush the FIFO */
        phhalCt_SETBITN(eUCR2X, CT_UCR2X_FIFO_FLUSH_SHIFT);

        /* Set the Mode to transmission.*/
        phhalCt_SETBITN(eUCR1X, CT_UCR1X_T_R_SHIFT);

        /* Set the mode to byte access since we are transmitting one byte at a time.*/
        phhalCT_SETFIELDSHIFT(eUCR2X, CT_UCR2X_WRDACC_MASK, CT_UCR2X_WRDACC_SHIFT, 0x00);

        /* Transmission algorithm starts here.*/
        wRemainingBytes = wTransmitSize;

        if(wRemainingBytes > PHHAL_CT_MAX_FIFO_SIZE)
        {
            /* Load first 32 bytes in Fifo.*/
            for(bLoopCount = 0x00; bLoopCount<PHHAL_CT_MAX_FIFO_SIZE; bLoopCount++)
            {
               phhalCt_SETREG(eUTR_URR_REG_ADR1, pbTransmitData[bCount++]);
            }

            /* Set the fifo threshold to 20 in the transmission mode(default is 1)
             * so that whenever the Fifo will have 20 more bytes, we will get an interrupt.
             * Initial threshold is set to 20 because we will have enough time to load more bytes in fifo,
             * which will prevent more time gap in bytes during transmission.
             */
            phhalCT_SETFIELD(eFCR, CT_FCR_FTC4_FTC0_MASK, PHHAL_CT_INITIAL_FIFO_THRESHOLD_VALUE);

            /* Wait for the transmission completed interrupt.*/
            eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                             (phhalCt_EventType_t)(E_PH_HALCT_EVENT_TX | E_PHHAL_CT_ERROR_EVENTS),
                                              1000,
                                              TRUE );

            PH_CT_BREAK_ON_FAILURE(eStatus);
            phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;
            /* Reduce the remaining bytes by 32 since already 32 bytes have been loaded to Fifo.*/
            wRemainingBytes -= PHHAL_CT_MAX_FIFO_SIZE;

            /* Load 12 bytes in Fifo one by one , because after 20 bytes are already in Fifo so we can fill only 12 bytes at once .*/
            while(wRemainingBytes > PHHAL_CT_FIFO_FILL_COUNT)
            {
                /* Disable the Fifo threshold interrupt */
               phhalCt_SETBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);

                /* Load all 12 bytes in Fifo.*/
                for(bLoopCount = 0x00; bLoopCount<PHHAL_CT_FIFO_FILL_COUNT; bLoopCount++)
                {
                   phhalCt_SETREG(eUTR_URR_REG_ADR1, pbTransmitData[bCount++]);
                }

                /* Enable the Fifo threshold interrupt again.*/
                phhalCt_CLEARBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);

                /* Wait for the transmission completed interrupt.*/
                eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                                 (phhalCt_EventType_t)(E_PH_HALCT_EVENT_TX | E_PHHAL_CT_ERROR_EVENTS),
                                                  1000,
                                                  TRUE );

                PH_CT_BREAK_ON_FAILURE(eStatus);
                phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;
                /* Reduce the remaining bytes by 12 since already 12 bytes have been loaded to Fifo.*/
                wRemainingBytes -= PHHAL_CT_FIFO_FILL_COUNT;
            }
        }
        if(0x01 == dwExitFlag)
        {
            break;
        }

        /* Set the fifo threshold to 0 in the transmission mode(default is 1)
         * so that whenever the Fifo is empty we will get an interrupt
         */
        phhalCT_SETFIELD(eFCR, CT_FCR_FTC4_FTC0_MASK, 0x00);

        /* Still bytes to be transmitted ? Load the Fifo with the remaining bytes.*/
        if(wRemainingBytes > 1)
        {
            /* Disable the Fifo threshold interrupt */
            phhalCt_SETBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);

            while(wRemainingBytes-1)
            {
                phhalCt_SETREG(eUTR_URR_REG_ADR1, pbTransmitData[bCount++]);
                wRemainingBytes--;
            }

            /* Enable the Fifo threshold interrupt again.*/
            phhalCt_CLEARBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);

            eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                             (phhalCt_EventType_t)(E_PH_HALCT_EVENT_TX | E_PHHAL_CT_ERROR_EVENTS),
                                             1000,
                                             TRUE );
            PH_CT_BREAK_ON_FAILURE(eStatus);
            phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;
        }
        else
        {
           if(wRemainingBytes == 0x01)
           {
               /* Disable the Fifo threshold so that we will not get interrupt for this last byte */
               phhalCt_SETBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);
               phhalCt_SETBITN(eUCR1X,CT_UCR1X_LCT_SHIFT);
               phhalCt_SETREG(eUTR_URR_REG_ADR1, phhalCt_DATAParams->gphhalCt_BLastByteTransmit);
               wRemainingBytes--;
           }
        }

        /* During the T=0 transmit if the last byte in the Fifo is naked by the card for more than
         * PEC retry counter this error is captured here and updated. */
        /* Looping for transmit to receive state.*/
        while( phhalCT_TESTBITN(eUCR1X,CT_UCR1X_T_R_SHIFT) &&
               (!(phhalCt_DATAParams->gphhalCt_BParityErr)) &&
               phhalCT_TESTBITN(eUCR1X,CT_UCR1X_LCT_SHIFT) )
        {
            /* This is required to know the last byte is sent and fifo is empty.*/
        }
        /* Set the transmission completion flag.*/
        phhalCt_DATAParams->gphhalCt_BTransmitComplete = 0x01;

        /* Enable the Fifo threshold interrupt again.*/
        phhalCt_CLEARBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);

        if(phhalCt_DATAParams->gphhalCt_BParityErr == 0x01)
        {
            phhalCt_DATAParams->gphhalCt_BParityErr = 0x00;
            /* Consume the event transmit */
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)E_PH_HALCT_EVENT_PARITY);
            eStatus = PH_ERR_CT_PARITY_ERROR;
            break;
        }

        /* Clear Events, to consume all events before Receive api.
         * It will help in RTOS where previous Receive api's last character CWT out event will occur in next receive api.
         */
       (void) phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)(E_PH_HALCT_EVENT_ALL));
        phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;

        eStatus = PH_CT_ERR_SUCCESS;
    }while(0);

    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}

phStatus16_t phhalCt_Receive(void * phhalCt_Params, uint8_t *pbReceiveData, uint16_t wReceiveSize)
{
    volatile phStatus16_t eStatus = PH_CT_ERR_FAILED; /*artf555048 : Prevent Optimization. False BWT event is randomly raised
                                                   when using O2 Optimization */
    uint8_t  bBlockParity = 0x00;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;

    /* Check for the null pointer.*/
    if ((pbReceiveData == NULL) || (wReceiveSize == 0x00))
    {
       return PH_CT_ADD_COMPCODE(PH_CT_ERR_INVALID_PARAMETER, PH_CT_COMP_HAL_CT);
    }

    if( PH_ERR_CT_MAIN_CARD_ABSENT == phhalCt_CheckCardPres(phhalCt_DATAParams) )
    {
       return PH_CT_ADD_COMPCODE(PH_ERR_CT_MAIN_CARD_ABSENT, PH_CT_COMP_HAL_CT);
    }

    if( PH_ERR_CT_CARD_DEACTIVATED == phhalCt_CheckCardActive(phhalCt_DATAParams) )
    {
       return PH_CT_ADD_COMPCODE(PH_ERR_CT_CARD_DEACTIVATED, PH_CT_COMP_HAL_CT);
    }

    do
    {
        /* Enter Critical section */
        NVIC_DisableIRQ(CT_IRQn);
        while(phhalCt_GETREG(eFSR))
        {
            phhalCt_DATAParams->gphhalCt_DriverBuff[phhalCt_DATAParams->gphhalCt_WDataCount++] = (uint8_t) phhalCt_GETREG(eUTR_URR_REG_ADR1);
            phhalCt_DATAParams->gphhalCt_WPendingBytes++;

        }
        /* Exit Critical section */
        NVIC_EnableIRQ(CT_IRQn);

        /* Check if there are already requested bytes available in the buffer */
        if(phhalCt_DATAParams->gphhalCt_WPendingBytes >= wReceiveSize)
        {
            /* Decrease the pending bytes to be copied to the protocol layer */
            phhalCt_DATAParams->gphhalCt_WPendingBytes-=wReceiveSize;
            /* Check if there are any errors pending */
            eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                             (phhalCt_EventType_t)(E_PHHAL_CT_ERROR_EVENTS),
                                             1,
                                             FALSE );
        }
        else
        {
            /* Critical section */
            NVIC_DisableIRQ(CT_IRQn);
            /* Assign the receive size to the global receive size which is checked in the ISR */
            phhalCt_DATAParams->gphhalCt_WReceiveSize = wReceiveSize;
            NVIC_EnableIRQ(CT_IRQn);

            if( PH_ERR_CT_MAIN_CARD_PRESENT != phhalCt_CheckCardPres( phhalCt_DATAParams ) )
            {
               return PH_ERR_CT_CARD_REMOVED;
            }

            /* Wait for response bytes */
            /* Blocking until there is timeout or RX complete event is coming */
            /* 2 seconds timeout has been kept for the RTOS timer */
            if ((phhalCT_TESTBITN(eUCR1X, CT_UCR1X_PROT_SHIFT)))
            {
                /* For T=1 the parity event should not be waited since the parity error should be handled in the
                 * protocol layer */
                eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                                 (phhalCt_EventType_t)( E_PH_HALCT_EVENT_RX | E_PH_HALCT_EVENT_TO3 |
                                                 E_PH_HALCT_EVENT_FRM_ERR | E_PH_HALCT_EVENT_OVR_ERR |
                                                 E_PH_HALCT_EVENT_PTL_ERR | E_PH_HALCT_EVENT_PROTL_ERR |
                                                 E_PH_HALCT_EVENT_ASYNC | E_PH_HALCT_EVENT_CARD_REMOVED),
                                                 PHHAL_CT_MAX_RECEIVE_TIMEOUT,
                                                 FALSE );
            }
            else
            {
                /* For T=0 the parity event should be and deactivation to be performed */
                eStatus = phhalCt_Event_WaitAny( phhalCt_DATAParams,
                                                 (phhalCt_EventType_t)(E_PH_HALCT_EVENT_RX | E_PH_HALCT_EVENT_TO3 |E_PHHAL_CT_ERROR_EVENTS),
                                                 PHHAL_CT_MAX_RECEIVE_TIMEOUT,
                                                 FALSE );
            }
            PH_CT_BREAK_ON_FAILURE(eStatus);
        }

        if(((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_RX) == E_PH_HALCT_EVENT_RX))
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, E_PH_HALCT_EVENT_RX);
            /* If parity event has occurred with Receive event.
             * Useful for T=1 protocol EMVCo Compliance test cases.*/
            if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_PARITY) == E_PH_HALCT_EVENT_PARITY)
            {
                if(phhalCT_TESTBITN(eUCR1X, CT_UCR1X_PROT_SHIFT))
                {
                    /* If T=1 protocol,then first receive full block then send parity error status.*/
                    bBlockParity = 0x01;
                }
                else
                {
                    /* In T=0, As soon as parity error detected send parity error status.*/
                    eStatus = PH_ERR_CT_PARITY_ERROR;
                    break;
                }
            }
            phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;

            /* Critical section */
            NVIC_DisableIRQ(CT_IRQn);
            /* Decrease the pending bytes to be copied to the protocol layer */
            phhalCt_DATAParams->gphhalCt_WPendingBytes -= wReceiveSize;
            NVIC_EnableIRQ(CT_IRQn);

        }
        /*
         * If WT/BWT timer expired in case of T=0 protocol return a timeout error,
         * so that a de-activation(T=0) or an R block(T=1) is called is called from the pal layer.
         */
        if(((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_TO3) == E_PH_HALCT_EVENT_TO3))
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, E_PH_HALCT_EVENT_TO3);
            /* Either the WWT timer or BWT timer expired or CWT timer expired */
            eStatus = PH_ERR_CT_TIME_OUT_WWT_OR_BWT;
            if(phhalCt_DATAParams->gphhalCt_BCWTFlag)
            {
                /* If this flag is set that means T=1 character waiting time out.*/
                eStatus = PH_ERR_CT_TIME_OUT_CWT;
            }

            phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;
            break;
        }
        eStatus = phhalCt_HandleCommonEvent(phhalCt_DATAParams);
        PH_CT_BREAK_ON_FAILURE(eStatus);

        /* Copy the requested bytes for the user */
        phUser_MemCpy((uint8_t*) pbReceiveData, &phhalCt_DATAParams->gphhalCt_DriverBuff[phhalCt_DATAParams->gphhalCt_WReceiveOffset], wReceiveSize);

        /* Increment the offset for the pending bytes if any to be returned */
        phhalCt_DATAParams->gphhalCt_WReceiveOffset += wReceiveSize;
        eStatus = PH_CT_ERR_SUCCESS;
        if(bBlockParity)
        {
            eStatus = PH_ERR_CT_PARITY_ERROR;
        }
    }while(0);
   return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}


phStatus16_t phhalCt_PPSRequestHandling( void * phhalCt_Params )
{
    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    uint8_t bPPSRequestBuffer[4];
    uint8_t bPPSResponseBuffer[4] = {0x00,0x00,0x00,0x00};
    uint8_t bNegotiableProtocol;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    if( phhalCt_SlotParams->sAtrParams.sAtrHalParams.bNegotiableMode )
    {
       /* Delay of 10 Etu is required for BGT.*/
       phUser_Wait(1000);
       phhalCt_SetTimer(phhalCt_DATAParams, PHHAL_CT_PPSMODE_9600_ETU, 0x00);

       do
       {
			if(!(phhalCt_SlotParams->sAtrParams.sAtrHalParams.bProtSelT0))
			{
			  bNegotiableProtocol = E_PROTOCOL_CT_T1;
			}
			else
			{
			  bNegotiableProtocol = E_PROTOCOL_CT_T0 ;
			}

			/* Clear the protocol bit.*/
			phhalCt_CLEARBITN(eUCR1X, CT_UCR1X_PROT_SHIFT);
			/* Setting Parity retransmission count as maximum for PPS Response.*/
			phhalCT_SETFIELDSHIFT(eFCR, CT_FCR_PEC2_PEC0_MASK, CT_FCR_PEC2_PEC0_SHIFT, PHHAL_CT_MAXPARITY_ERROR_COUNT);

			/* PPS Request and Response exchange handling.*/
			eStatus = phhalCt_PPSExchangeHandling(phhalCt_DATAParams, bPPSRequestBuffer,bPPSResponseBuffer, bNegotiableProtocol );
			PH_CT_BREAK_ON_FAILURE(eStatus);

			/* Setting baud rate for negotiated FiDi.*/
			eStatus = phhalCt_SetBaudRate( phhalCt_DATAParams );
			PH_CT_BREAK_ON_FAILURE(eStatus);

			/* Setting transmission protocol using negotiated protocol value.*/
			phhalCt_SetTransmissionProtocol(bNegotiableProtocol);

       }while(0);

       if(PH_CT_ERR_SUCCESS != eStatus)
       {
           if(PH_ERR_PPS_EXCHANGE_NOT_REQUIRED != eStatus)
           {
              /* ReSetting Parity retransmission count as zero for errorneous PPS Response.*/
              phhalCT_SETFIELDSHIFT(eFCR, CT_FCR_PEC2_PEC0_MASK, CT_FCR_PEC2_PEC0_SHIFT, PHHAL_CT_RESET_PARITY_ERR_COUNT);
              eStatus = PH_CT_ERR_SUCCESS;
           }
       }
       phhalCt_StopCTTimer();
       return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
    }
	eStatus = PH_ERR_PPS_EXCHANGE_NOT_REQUIRED;
    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}

/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */

phStatus16_t phhalCt_PPSExchangeHandling( phhalCt_DATAParams_t * phhalCt_DATAParams,
                                                 uint8_t *pbPPSRequestBuffer ,
                                                 uint8_t *pbPPSResponseBuffer,
                                                 uint8_t bNegotiableProtocol )
{
    phStatus16_t eStatus = PH_CT_ERR_FAILED;
    uint8_t bPpsSecondByte = 0x00;
    uint8_t bValue = 0xFF; /* Default value.*/
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    do
    {
        /* Construct PPS request Buffer.*/
        pbPPSRequestBuffer[0] = PHHAL_CT_PPSS_BYTE;
        pbPPSRequestBuffer[1] = (PHHAL_CT_BIT5_MASK | bNegotiableProtocol);
        bValue ^= pbPPSRequestBuffer[1];
        pbPPSRequestBuffer[2] = phhalCt_SlotParams->sAtrParams.sAtrHalParams.bFiDi;
        bValue ^= pbPPSRequestBuffer[2];
        /* Assign Final PCK value to PPS request buffer.*/
        pbPPSRequestBuffer[3] = bValue;

        eStatus = phhalCt_Transmit(phhalCt_DATAParams, pbPPSRequestBuffer,4);
        if(PH_CT_ERR_SUCCESS != eStatus)
        {
            break;
        }

           /* Receive Starting 2 byte of pps response so that further byte presence can come to know.*/
           eStatus = phhalCt_Receive(phhalCt_DATAParams, pbPPSResponseBuffer,2);
           PH_CT_BREAK_ON_FAILURE(eStatus);

           if((pbPPSRequestBuffer[0] != pbPPSResponseBuffer[0])
               ||((pbPPSRequestBuffer[1] & PHHAL_CT_LSB_NIBBLE_MASK) != (pbPPSResponseBuffer[1] & PHHAL_CT_LSB_NIBBLE_MASK)))
           {
                eStatus = PH_ERR_CT_PPS_EXCHANGE_ERROR;
                break;
           }
            /* Testing b5 of PPS0 response for PPS1 presence.*/
           if( (pbPPSResponseBuffer[1] & PHHAL_CT_BIT5_MASK) == 0)
           {
                /* If bit b5 of PPS0 indicates PPS1 absence so card is only ready for default value of FiDi.*/
               phhalCt_SlotParams->gphhalCt_BCurrentFiDi = PHHAL_CT_DEFAULT_FIDI;  /*default value.*/
           }
           else
           {
               eStatus = phhalCt_Receive(phhalCt_DATAParams, &(pbPPSResponseBuffer[2]),1);
               PH_CT_BREAK_ON_FAILURE(eStatus);

               /*Setting PPS1 byte presence flag.*/
               bPpsSecondByte = 0x01;
               if(pbPPSRequestBuffer[2] != pbPPSResponseBuffer[2] )
               {
                   eStatus = PH_ERR_CT_PPS_EXCHANGE_ERROR;
                   break;
               }
           }
           eStatus = phhalCt_Receive(phhalCt_DATAParams, &(pbPPSResponseBuffer[3]),1);
           PH_CT_BREAK_ON_FAILURE(eStatus);

           /* If second byte is missing in PPS Response, remove PPS request's second byte from PCK calculation*/
           if(!(bPpsSecondByte))
           {
               if((pbPPSRequestBuffer[1] & PHHAL_CT_BIT5_MASK)==0x10)   /* b5 present in PPS0 request.*/
               {
                   pbPPSRequestBuffer[3]^=  PHHAL_CT_BIT5_MASK;          /* so remove bit b5 for PCK calculation.*/
               }
               pbPPSRequestBuffer[3]^= pbPPSRequestBuffer[2];
               /* Negotiate FiDi value value using default value .*/
               pbPPSRequestBuffer[2] = phhalCt_SlotParams->gphhalCt_BCurrentFiDi;
           }
           if(pbPPSRequestBuffer[3] != pbPPSResponseBuffer[3] )
           {
               eStatus = PH_ERR_CT_PPS_EXCHANGE_ERROR;
           }
    }while(0);
    return eStatus;
}

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */

