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
 * This file contains the implementation for T=0 protocol.
 *
 * $Date$
 * $Author$
 * $Revision$
 *
 */

/* *****************************************************************************************************************
 * Includes
 * ******************************************************************************************************************/

#include "phpalCt.h"
#include "phpalCt_T0.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/* *****************************************************************************************************************
 * Internal Definitions
 * **************************************************************************************************************** */

/************************ 7816-3 T=0 CASES ******************************************* */
#define PHPAL_CT_CASE_1S                 0
#define PHPAL_CT_CASE_2S                 1
#define PHPAL_CT_CASE_3S                 2
#define PHPAL_CT_CASE_4S                 3
#define PHPAL_CT_CASE_2E                 4
#define PHPAL_CT_CASE_3E                 5
#define PHPAL_CT_CASE_4E                 6
#define PHPAL_CT_CASE_INVALID            0xFF

typedef enum {
    PH_ERR_CT_INS_NO_MATCH_ERROR = (PH_CT_ERR_CUSTOM_BEGIN+0x0011)
}phpalCt_ErrorCodesT0_t;

/* *******************************************************************************************************************
 * Global Variables
 * ****************************************************************************************************************** */


/* *******************************************************************************************************************
 * Private Functions Prototypes
 * ****************************************************************************************************************** */
/**
 * API used to Short APDU exchange with the card
 */
static phStatus16_t phpalHwCt_ShortAPDU_Exchange( phpalCt_DATAParams_t * phpalCt_DATAParams,
												uint8_t* pbTransmitBuff,
												uint8_t* pbReceiveBuff,
												uint16_t* pwReceiveSize );

static phStatus16_t phpalHwCt_Receive_ProcByte( phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t* bProcByte,uint16_t wCount, uint8_t* pbReceiveBuff );
static phStatus16_t phpalHwCt_Case34_Send( phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t *pbTransmitBuff,uint8_t bProcByte,uint8_t* nb, uint8_t* bDataToSend );
static phStatus16_t phpalHwCt_Case24_Receive(  phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t bProcByte,uint16_t* wCount, uint8_t* pbReceiveBuff );
static phStatus16_t phpalHwCt_OtherCases_Receive( phpalCt_DATAParams_t * phpalCt_DATAParams,
												uint8_t bProcByte,
												uint8_t* bDataToSend,
												uint8_t* bWarning,
												uint8_t* pbReceiveBuff,
												uint16_t bCount );
/**
 * API used to receive the response from the card
 */
static phStatus16_t phpalHwCt_RcvCardData(phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t *pbAPDU_ExchBuffer,uint16_t nb,uint16_t ptr);
/**
 * API used to send the command to the card
 */
static phStatus16_t phpalHwCt_SendCardData( phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t *pbAPDU_ExchBuffer,uint16_t nb,uint16_t ptr);

/* *******************************************************************************************************************
 * Public Functions
 * ****************************************************************************************************************** */
phStatus16_t phpalCt_T0_Init( phpalCt_DATAParams_t * phpalCt_DATAParams )
{
   phStatus16_t phStatus = PH_CT_ERR_SUCCESS;

   phpalCt_DATAParams->sT0Params.gClass = 0x00;
   phpalCt_DATAParams->sT0Params.gINS = 0x00;
   phpalCt_DATAParams->sT0Params.gbP1 = 0x00;
   phpalCt_DATAParams->sT0Params.gbP2 = 0x00;
   phpalCt_DATAParams->sT0Params.gbSW1 = 0x00;
   phpalCt_DATAParams->sT0Params.gbSW2 = 0x00;
   phpalCt_DATAParams->sT0Params.gCase_APDU = PHPAL_CT_CASE_INVALID;
   phpalCt_DATAParams->sT0Params.gbGetResponseApdu = 0x00;
   phpalCt_DATAParams->sT0Params.gbBuffReference = phhalCt_GetBuffReference();
   return phStatus;
}

/**
 *@brief   phpalHwCt_TranscieveT0,This Function is used transmitting command/data to/from the card in T0 protocol
 *          and receive response.
 *@param   pbTransmitBuff : Pointer to the pbTransmitbuff passed by the upper layer
 *         dwTransmitSize  : Size of the pbTransmitBuff passed by the upper layer
 *         *pbReceiveBuff  : Pointer to the pbReceiveBuff passed by the upper layer for data reception
 *         *pwReceiveSize  : Pointer to the pwReceiveSize to copy the received data size
 *@return  PH_CT_ERR_SUCCESS - PPS Exchange done successfully
 *         PH_ERR_CT_MAIN_CARD_ABSENT - If the card is absent in the main slot
 *         PH_CT_ERR_INVALID_PARAMETER - If invalid parameter is passed
 *
 */

 phStatus16_t phpalCt_T0_Transcieve( phpalCt_DATAParams_t * phpalCt_DATAParams,
		 	 	 	 	 	 	   uint8_t* pbTransmitBuff,
                                   uint32_t dwTransmitSize,
                                   uint8_t* pbReceiveBuff,
                                   uint16_t* pwReceiveSize )
{
    uint16_t wCount=0;
    phStatus16_t eStatus = PH_CT_ERR_FAILED;
    do
    {
        /* Short APDU Handling */
        /* CASE 1 : 4 bytes header */
        if(dwTransmitSize == 0x04)
        {
            phpalCt_DATAParams->sT0Params.gCase_APDU = PHPAL_CT_CASE_1S;
        }
        /* CASE 2 short: 5 bytes header */
        else if(dwTransmitSize == 0x05)
        {
            phpalCt_DATAParams->sT0Params.gCase_APDU = PHPAL_CT_CASE_2S;
        }
        /* CASE 3 and CASE 4 : */
        else if((dwTransmitSize > 0x05) && (pbTransmitBuff[4] != 0x00))
        {
            wCount = pbTransmitBuff[PHPAL_CT_P3];
            if(dwTransmitSize == (wCount + 0x05))                              /* pass the length*/
            {
                phpalCt_DATAParams->sT0Params.gCase_APDU = PHPAL_CT_CASE_3S;                           /*Case 3 short*/
            }
            else if(dwTransmitSize == (wCount + 0x06))                         /* 00 at the end of APDU */
            {
                phpalCt_DATAParams->sT0Params.gCase_APDU = PHPAL_CT_CASE_4S;                           /* then CASE 4 short */
            }
            else
            {
                eStatus = PH_CT_ERR_INVALID_PARAMETER;
                break;
            }
        }
        /* Extended APDU Handling */
        else if((dwTransmitSize >= 0x07) && ( pbTransmitBuff[PHPAL_CT_P3] == 0))
        {
            /* Extended APDU support is not applicable*/
            eStatus = PH_ERR_CT_EXT_APDU_NOT_SUPPORTED;
            break;
        }
        else
        {
            eStatus = PH_CT_ERR_INVALID_PARAMETER;
            break;
        }

        eStatus = phpalHwCt_ShortAPDU_Exchange( phpalCt_DATAParams, pbTransmitBuff,pbReceiveBuff,pwReceiveSize );

    }while(0);

    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_PAL_CT);
}
 /* *****************************************************************************************************************
  * Private Functions Prototypes
  * ***************************************************************************************************************** */
/**
 *@brief   phpalHwCt_ShortAPDU_Exchange, This is Api used perform a the APDU exchange with card in Short APDU
 *         where max length is 255 bytes.
 *@param   uint8_t* pbTransmitBuff - Pointer to the transmit buffer
 *@param   uint32_t dwTransmitSize - Size of the transmit buffer
 *@param   uint8_t* pbReceiveBuff - Pointer to the receive buffer
 *@param   uint16_t* pwReceiveSize - Pointer to the address where receive size shall be populated
 *@return  PH_CT_ERR_SUCCESS - Exchange done successfully
 *@return  PH_ERR_CT_RX_LENGTH_ERROR - Error in the received length of the response from the card
 *@return  PH_ERR_CT_TX_LENGTH_ERROR - Error in the Transmit length of the response to the card
 *@retval  PH_ERR_CT_INS_COMMAND_ERROR - Incorrect command passed from the upper layer
 */

static phStatus16_t phpalHwCt_ShortAPDU_Exchange(phpalCt_DATAParams_t * phpalCt_DATAParams,
											   uint8_t* pbTransmitBuff,
                                               uint8_t* pbReceiveBuff,
                                               uint16_t* pwReceiveSize )
{
    uint16_t wCount = 0;
    uint8_t bProcByte = 0,nb = 0;
    uint8_t bCase_3_4 = 0;
    uint8_t bCase_2_4 = 0;
    uint8_t bWarning = 0;
    uint8_t bDataToSend = 0x01;
    uint8_t bTransmitBuffer[5] = {0x00, 0x00, 0x00, 0x00, 0x00};
    phStatus16_t eStatus = PH_CT_ERR_FAILED;

    (void) phUser_MemCpy(bTransmitBuffer,pbTransmitBuff,5);

    /* sending first command */
    phpalCt_DATAParams->sT0Params.gClass  = bTransmitBuffer[PHPAL_CT_CLASS];                                  /* command save */
    phpalCt_DATAParams->sT0Params.gINS    = bTransmitBuffer[PHPAL_CT_INS];
    phpalCt_DATAParams->sT0Params.gbP1    = bTransmitBuffer[PHPAL_CT_P1];
    phpalCt_DATAParams->sT0Params.gbP2    = bTransmitBuffer[PHPAL_CT_P2];
    phpalCt_DATAParams->sT0Params.gbSW1   = 0x00;
    phpalCt_DATAParams->sT0Params.gbSW2   = 0x00;

    /* Reset global flag */
    phpalCt_DATAParams->sT0Params.gbGotSw2Byte_Case4S = false;

    if(phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_1S)
    {
        bTransmitBuffer[PHPAL_CT_P3] = 0x00;
        phpalCt_DATAParams->sT0Params.gbLen = 0x00;
    }
    else
    {
        phpalCt_DATAParams->sT0Params.gbLen = bTransmitBuffer[PHPAL_CT_P3];
    }

    /* Start the timer here just before sending the first Apdu */
    /* Set the timer in WWT mode */
    phhalCt_SetConfig(phpalCt_DATAParams->phalDataParams, E_CONF_TIMER, 0, PHHAL_CT_APDUMODE_WWT, 0x00 );

    eStatus = phpalHwCt_SendCardData( phpalCt_DATAParams, bTransmitBuffer, 0x05, 0x00 );/* send command CLA INS P1 P2 L */
    PH_CT_RETURN_ON_FAILURE(eStatus);
    /* *******************  reception loop  ********************** */
    while(1)                                                 /* main loop */
    {
        /* reception of the first byte*/
        while(1)                                             /* null byte case loop */
        {
            eStatus = phpalHwCt_Receive_ProcByte(phpalCt_DATAParams, &bProcByte, wCount, pbReceiveBuff);
            if((eStatus != PH_CT_ERR_SUCCESS) && (eStatus != PH_ERR_CT_INS_NO_MATCH_ERROR))
            {
                return eStatus;
            }
            else
            {

               /* The correct procedure byte/ status byte has come exit the loop */
                PH_CT_BREAK_ON_SUCCESS(eStatus);
                /* It is a NULL byte 60 then remain in same loop to receive procedure byte*/

            }
        }

        /**
         * ISO7816-3 Case4S.2 : For ISO 7816, In case 4s apdu if we get 0x90 proc byte for case 3s command.
         * We should continue with card by sending get response command.
         */
        if((!phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn)&&(bProcByte == 0x90)&&(phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_4S) && bCase_3_4)
        {
        	phpalCt_DATAParams->sT0Params.gbGetResponseApdu = 0x01;
        }
        bCase_3_4 = (phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_3S) || ((phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_4S) && bDataToSend);
        bCase_2_4 = (phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_2S) || ((phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_4S) && !bDataToSend);

        if(bCase_3_4)
        {
            eStatus = phpalHwCt_Case34_Send(phpalCt_DATAParams,pbTransmitBuff ,bProcByte,&nb,&bDataToSend);
        }
        else
        {
            if(bCase_2_4)
            {
                eStatus = phpalHwCt_Case24_Receive( phpalCt_DATAParams,bProcByte,&wCount,pbReceiveBuff );
            }
        }
        if((eStatus != PH_CT_ERR_SUCCESS) && (eStatus != PH_ERR_CT_INS_NO_MATCH_ERROR))
        {
            return eStatus;
        }
        else
        {
            if(eStatus == PH_ERR_CT_INS_NO_MATCH_ERROR)
            {
                eStatus = phpalHwCt_OtherCases_Receive( phpalCt_DATAParams, bProcByte,&bDataToSend, &bWarning, pbReceiveBuff, wCount );
            }
        }
        if((eStatus != PH_CT_ERR_SUCCESS) && (eStatus != PH_ERR_CT_INS_NO_MATCH_ERROR))
        {
            return eStatus;
        }
        if((eStatus == PH_ERR_CT_INS_NO_MATCH_ERROR)||(phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_1S))
        {
            if( (((bProcByte & 0xF0) == 0x60) || ((bProcByte & 0xF0) == 0x90)) )
            {
                /* Receive next byte only if SW2 was not already received */
                if(phpalCt_DATAParams->sT0Params.gbGotSw2Byte_Case4S == false)
                {
                    eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams, pbReceiveBuff,1,1+wCount); /* receive SW2 */
                    PH_CT_RETURN_ON_FAILURE(eStatus);
                }

                if(bWarning)
                {
                    /* Case 4 with warnings */
                    pbReceiveBuff[wCount] = phpalCt_DATAParams->sT0Params.gbSW1;
                    pbReceiveBuff[wCount+1] = phpalCt_DATAParams->sT0Params.gbSW2;
                }
                *pwReceiveSize = wCount+2;
                phhalCt_StopCTTimer();
                return  PH_CT_ERR_SUCCESS;
            }
            else
            {
                /* Error procedure byte */
                return PH_ERR_CT_INS_COMMAND_ERROR;
            }
        }
    }
}

static phStatus16_t phpalHwCt_Receive_ProcByte( phpalCt_DATAParams_t * phpalCt_DATAParams,
											  uint8_t* bProcByte,
                                              uint16_t wCount,
                                              uint8_t* pbReceiveBuff)
{
    phStatus16_t eStatus = PH_ERR_CT_INS_NO_MATCH_ERROR;
    eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams, pbReceiveBuff,1,wCount);
    PH_CT_RETURN_ON_FAILURE(eStatus);

    *bProcByte = pbReceiveBuff[wCount];
    if(( (*bProcByte) != 0x60 ) &&
         !((phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_1S)
         && (((*bProcByte) == (0xFF-phpalCt_DATAParams->sT0Params.gINS)) || ((*bProcByte) == phpalCt_DATAParams->sT0Params.gINS)
         || ((*bProcByte) == (phpalCt_DATAParams->sT0Params.gINS+1)) || ((*bProcByte) == (phpalCt_DATAParams->sT0Params.gINS^0xFE)))))
    {
        return PH_CT_ERR_SUCCESS;       /* SW1!=0x60 (NUL BYTE) */
    }
    return PH_ERR_CT_INS_NO_MATCH_ERROR;
}

static phStatus16_t phpalHwCt_Case34_Send(phpalCt_DATAParams_t * phpalCt_DATAParams,uint8_t *pbTransmitBuff,uint8_t bProcByte,uint8_t* nb, uint8_t* bDataToSend)
{
    phStatus16_t eStatus = PH_ERR_CT_INS_NO_MATCH_ERROR;
    do
    {
        /* ************************************************** */
        /* *         case 3 and case 4(data send)           * */
        /* ************************************************** */
        if((bProcByte == phpalCt_DATAParams->sT0Params.gINS) || (bProcByte == (phpalCt_DATAParams->sT0Params.gINS+1)))/* non asserted mode */
        {
            /* transmission of all remaining bytes  with programming state */
            eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams, pbTransmitBuff, phpalCt_DATAParams->sT0Params.gbLen, 5+(*nb));
            PH_CT_BREAK_ON_FAILURE(eStatus);
            phpalCt_DATAParams->sT0Params.gbLen = 0x00;
            *bDataToSend = 0x00;
            eStatus = PH_CT_ERR_SUCCESS;
        }
        else if((bProcByte == (0xFF-phpalCt_DATAParams->sT0Params.gINS)) || (bProcByte == (phpalCt_DATAParams->sT0Params.gINS^0xFE)))
        {
            /* transmission byte per byte */
            eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams,pbTransmitBuff,1,5+(*nb));
            PH_CT_BREAK_ON_FAILURE(eStatus);
            phpalCt_DATAParams->sT0Params.gbLen--;                                             /* data byte available number */
            (*nb)++;                                                /* number of data byte sent to the card */
            if (phpalCt_DATAParams->sT0Params.gbLen == 0x00)                                      /* end of transmission */
            {
                *bDataToSend = 0x00;
            }
            eStatus = PH_CT_ERR_SUCCESS;
        }
        else
        {
            /* Only for quality QA */
        }
    }while(0);
    return eStatus;
}

static phStatus16_t phpalHwCt_Case24_Receive(  phpalCt_DATAParams_t * phpalCt_DATAParams,
											 uint8_t bProcByte,
                                             uint16_t* wCount,
                                             uint8_t* pbReceiveBuff )
{
    phStatus16_t eStatus = PH_ERR_CT_INS_NO_MATCH_ERROR;
    uint16_t wLocalCount = *wCount;
    uint8_t bGetResponseCmd[5] = {0x00,0xC0,0x00,0x00,0x00};
    uint8_t bTransmitBuffer[5];

    do
    {
        /* ************************************************** */
        /* *        case 2 and case 4(data to received)     * */
        /* ************************************************** */
        /** NOTE : '61XX' and '6CXX' procedure bytes are only used when processing case 2 and 4 commands */
        if((bProcByte == 0x61) && (phpalCt_DATAParams->sT0Params.gCase_APDU != PHPAL_CT_CASE_4S))     /* SW2= number of response bytes available */
        {
            /*  data byte available   */
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams, pbReceiveBuff, 1, wLocalCount+1);            /* receive SW2 */
            PH_CT_BREAK_ON_FAILURE(eStatus);
            /* Form the GET RESPONSE instruction */
            bGetResponseCmd[PHPAL_CT_P3] = pbReceiveBuff[1+wLocalCount];          /* Licc = SW2 */

            if(!(phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn))
            {
                bGetResponseCmd[PHPAL_CT_CLASS] = phpalCt_DATAParams->sT0Params.gClass;
            }
            phpalCt_DATAParams->sT0Params.gClass = bGetResponseCmd[PHPAL_CT_CLASS];                            /* command save */
            phpalCt_DATAParams->sT0Params.gINS = bGetResponseCmd[PHPAL_CT_INS];
            phpalCt_DATAParams->sT0Params.gbP1 = bGetResponseCmd[PHPAL_CT_P1];
            phpalCt_DATAParams->sT0Params.gbP2 = bGetResponseCmd[PHPAL_CT_P2];
            phpalCt_DATAParams->sT0Params.gbLen = bGetResponseCmd[PHPAL_CT_P3];

            eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams,bGetResponseCmd,5,0);   /* send get response command */
            PH_CT_BREAK_ON_FAILURE(eStatus);

        }
        else if(bProcByte == 0x6C)                       /* SW2 = exact length Le */
        {
            /* data length not accepted  */
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams,pbReceiveBuff,1,1+wLocalCount);            /* receive SW2 */
            PH_CT_BREAK_ON_FAILURE(eStatus);

            phpalCt_DATAParams->sT0Params.gbLen = pbReceiveBuff[1];                              /* length equal to SW2 */
            bTransmitBuffer[0] = phpalCt_DATAParams->sT0Params.gClass;                            /* command to send */
            bTransmitBuffer[1] = phpalCt_DATAParams->sT0Params.gINS;
            bTransmitBuffer[2] = phpalCt_DATAParams->sT0Params.gbP1;
            bTransmitBuffer[3] = phpalCt_DATAParams->sT0Params.gbP2;
            bTransmitBuffer[4] = (uint8_t)phpalCt_DATAParams->sT0Params.gbLen;
            eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams,bTransmitBuffer,5,0); /* send command CLA INS P1 P2 L */
            PH_CT_BREAK_ON_FAILURE(eStatus);

        }
        else if(bProcByte == phpalCt_DATAParams->sT0Params.gINS)
        {
            /* reads all the data sent by the card */
            if (phpalCt_DATAParams->sT0Params.gbLen == 0x00)
            {
                phpalCt_DATAParams->sT0Params.gbLen = PHPAL_CT_MAX_LENGTH;
            }
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams,pbReceiveBuff,phpalCt_DATAParams->sT0Params.gbLen,wLocalCount); /* read data send by the card */
            PH_CT_BREAK_ON_FAILURE(eStatus);


            *wCount += phpalCt_DATAParams->sT0Params.gbLen;                                          /* length of the response (phpalCt_DATAParams->sT0Params.pT0Params->gINS + data ) */
            eStatus = PH_CT_ERR_SUCCESS;
        }
        else if(bProcByte == (0xFF-phpalCt_DATAParams->sT0Params.gINS))
        {
            /*  reads byte by byte all the data sent by the card */
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams,pbReceiveBuff,1,wLocalCount++);/*read data send by the card */
            PH_CT_BREAK_ON_FAILURE(eStatus);

            phpalCt_DATAParams->sT0Params.gbLen -= 1;                                           /* decrement the length of the block */
            (*wCount)++;
            eStatus = PH_CT_ERR_SUCCESS;
        }
        else
        {
            /* Only for quality QA */
        }
    }while(0);
    return eStatus;
}

static phStatus16_t phpalHwCt_OtherCases_Receive( phpalCt_DATAParams_t * phpalCt_DATAParams,
												uint8_t bProcByte,
                                                uint8_t* bDataToSend,
                                                uint8_t* bWarning,
                                                uint8_t* pbReceiveBuff,
                                                uint16_t bCount )
{
    phStatus16_t eStatus = PH_ERR_CT_INS_NO_MATCH_ERROR;
    uint8_t bGetResponseCmd[5] = {0x00,0xC0,0x00,0x00,0x00};
    uint8_t bSw2Byte;

    do
    {
        /* On receipt of the warning status in step 3 */
    	/**
    	 * ISO7816-3 Case4S.4 : on reception for 0x9xxx other than 0x9000 in step 3, process should be aborted for case 4s apdu.
    	 * EMV 4.3 : on reception for 0x9xxx other than 0x9000 ,process will be continue considering warning status bytes.
    	 */
        if ((phpalCt_DATAParams->sT0Params.gCase_APDU==PHPAL_CT_CASE_4S) && (phpalCt_DATAParams->sT0Params.gINS != 0xC0 ) && (!(*bDataToSend)) &&
           (( bProcByte == 0x62 || bProcByte ==0x63 ||
           (((phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn)&&((bProcByte & 0xF0) == 0x90))))))
        {
            /* Read one more byte */
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams,&bSw2Byte,1,0);
            PH_CT_BREAK_ON_FAILURE(eStatus);

            if((bProcByte==0x90) && (bSw2Byte == 0x00))
            {
                /* ICC has sent status 9000, Not a warning. Handle this at end of phpalHwCt_ShortAPDU_Exchange() */
                eStatus = PH_ERR_CT_INS_NO_MATCH_ERROR;

                /* Save the read byte in Receive Buffer */
                pbReceiveBuff[bCount + 1] = bSw2Byte;

                /* Set flag so that we will not wait for SW2 byte */
                phpalCt_DATAParams->sT0Params.gbGotSw2Byte_Case4S = true;

                break;
            }

            /* ICC has sent a warning. Either 62XX, 63XX or 9XXX. Save the read byte in Receive Buffer */
            pbReceiveBuff[1] = bSw2Byte;

            /* Case 4 with warnings so performs a get response */
            *bWarning = 1;
            phpalCt_DATAParams->sT0Params.gbSW1 = bProcByte;
            phpalCt_DATAParams->sT0Params.gbSW2 = pbReceiveBuff[1];
            if(!(phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn))
            {
                bGetResponseCmd[PHPAL_CT_CLASS] = phpalCt_DATAParams->sT0Params.gClass;
            }

			eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams,bGetResponseCmd,5,0);
			PH_CT_BREAK_ON_FAILURE(eStatus);

        }
        /* ************************************************** */
        /* *         Specific cases                         * */
        /* *         -  Case 1 with 1 procedure byte before * */
        /* *            the status bytes                    * */
        /* *         -  Case 4 with ICC discarding the TTL  * */
        /* *            datas                               * */
        /* ************************************************** */
        else if( phpalCt_DATAParams->sT0Params.gbGetResponseApdu || ((phpalCt_DATAParams->sT0Params.gCase_APDU == PHPAL_CT_CASE_4S) && ((bProcByte == 0x61))) )
        {
        	phpalCt_DATAParams->sT0Params.gbGetResponseApdu = 0x00;

            /* perform the get response command and discard data to send */
            eStatus = phpalHwCt_RcvCardData(phpalCt_DATAParams,pbReceiveBuff,1,bCount+1);                         /* receive SW2 */
            PH_CT_BREAK_ON_FAILURE(eStatus);

            *bDataToSend=0;                                                    /* discard bytes to transmit */

            bGetResponseCmd[PHPAL_CT_P3] = pbReceiveBuff[1+bCount];        /* Licc = SW2 */

            if(!(phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn))
            {
                bGetResponseCmd[PHPAL_CT_CLASS] = phpalCt_DATAParams->sT0Params.gClass;
            }
            eStatus = phpalHwCt_SendCardData(phpalCt_DATAParams,bGetResponseCmd,5,0); /*send get response command*/
            PH_CT_BREAK_ON_FAILURE(eStatus);
        }
        else
        {
            /* Only for quality QA */
        }
    }while(0);
    /* command save */
    phpalCt_DATAParams->sT0Params.gClass = bGetResponseCmd[PHPAL_CT_CLASS];
    phpalCt_DATAParams->sT0Params.gINS   = bGetResponseCmd[PHPAL_CT_INS];
    phpalCt_DATAParams->sT0Params.gbP1   = bGetResponseCmd[PHPAL_CT_P1];
    phpalCt_DATAParams->sT0Params.gbP2   = bGetResponseCmd[PHPAL_CT_P2];
    phpalCt_DATAParams->sT0Params.gbLen  = bGetResponseCmd[PHPAL_CT_P3];

    return eStatus;
}
/**
 *@brief   phpalHwCt_RcvCardData, This Function used perform a reception operation from the card
 *@param  *pbAPDU_ExchBuffer : Pointer to the buffer passed for reception of data from card
 *         wDataLength : Count of bytes to be received from the card
 *         ptr : index to the buffer that is passed for the reception
 *@return  PH_CT_ERR_SUCCESS - Receive done successfully
 *         - If the RX received is erroneous
 */
static phStatus16_t phpalHwCt_RcvCardData(phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t *pbAPDU_ExchBuffer, uint16_t wDataLength, uint16_t ptr)
{
    phStatus16_t eStatus = phhalCt_Receive(phpalCt_DATAParams->phalDataParams,pbAPDU_ExchBuffer+ptr,wDataLength);

    if(((PH_CT_COMP_HAL_CT|PH_ERR_CT_PARITY_ERROR)== eStatus)||((PH_CT_COMP_HAL_CT|PH_ERR_CT_TIME_OUT_WWT_OR_BWT)== eStatus))
    {
        (void)phhalCt_DeactivateCard(phpalCt_DATAParams->phalDataParams);
    }

    return eStatus;
}
/**
 *@brief   phpalHwCt_SendCardData, This is Function used perform a transmission operation to the card
 *
 *@param  *pbAPDU_ExchBuffer : Pointer to the buffer to be passed to the card
 *         wDataLength : Size of the data to be transmitted to the card
 *         ptr : index to the buffer that is passed for the transmission
 *@return  PH_CT_ERR_SUCCESS - Transmit done successfully
 *          - If the RX received is erroneous
 *          - If the TX data/command is erroneous
 */
static phStatus16_t phpalHwCt_SendCardData( phpalCt_DATAParams_t * phpalCt_DATAParams, uint8_t *pbAPDU_ExchBuffer, uint16_t wDataLength, uint16_t ptr )
{
    phStatus16_t eStatus = phhalCt_Transmit(phpalCt_DATAParams->phalDataParams, pbAPDU_ExchBuffer+ptr, wDataLength);
    return eStatus;
}

#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */

