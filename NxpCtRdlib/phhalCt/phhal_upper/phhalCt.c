/*
 *                    Copyright (c), NXP Semiconductors
 *
 *                       (C) NXP Semiconductors 2014,2015,2021-2023
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
#include "phhalCt_TDA.h"
#include "phhalCt_Event.h"

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 * Total Size: NNNbytes
 * ***************************************************************************************************************** */

/**
 * This table will be used for all valid possible baud rate selection.
 */
const phhalCt_ClockUart_t gkphhalCt_BPreScalar[]={
        {  0x0BA0,    0x01,     6,   1},
        {  0x05D0,    0x02,     6,   2},
        {  0x02E8,    0x03,     6,   4},
        {  0x0174,    0x04,     6,   8},
        {  0x00BA,    0x05,     6,   16},
        {  0x00B0,    0x06,     7,   32},
        {  0x005D,    0x07,     7,   64},
        {  0x00F8,    0x08,     6,   12},
        {  0x0120,    0x09,     7,   20},

        {  0x08B8,    0x11,     5,   1},
        {  0x045C,    0x12,     5,   2},
        {  0x022E,    0x13,     5,   4},
        {  0x0117,    0x14,     5,   8},
        {  0x00BA,    0x15,     6,   16},
        {  0x00B0,    0x16,     7,   32},
        {  0x005D,    0x17,     7,   64},
        {  0x00BA,    0x18,     5,   12},
        {  0x0120,    0x19,     7,   20},

        {  0x0AE6,    0x21,     4,   1},
        {  0x0573,    0x22,     4,   2},
        {  0x02B9,    0x23,     4,   4},
        {  0x015C,    0x24,     4,   8},
        {  0x00AA,    0x25,     4,   16},
        {  0x0110,    0x26,     7,   32},
        {  0x0080,    0x27,     7,   64},
        {  0x00E8,    0x28,     4,   12},
        {  0x01B0,    0x29,     7,   20},

        {  0x0BA0,    0x31,     3,   1},
        {  0x05D0,    0x32,     3,   2},
        {  0x02E8,    0x33,     3,   4},
        {  0x0174,    0x34,     3,   8},
        {  0x00BA,    0x35,     3,   16},
        {  0x005D,    0x36,     3,   32},
        {  0x00B0,    0x37,     7,   64},
        {  0x00F8,    0x38,     3,   12},
        {  0x0094,    0x39,     3,   20},

        {  0x0D14,    0x41,     2,   1},
        {  0x068A,    0x42,     2,   2},
        {  0x0345,    0x43,     2,   4},
        {  0x01A2,    0x44,     2,   8},
        {  0x00D1,    0x45,     2,   16},
        {  0x0066,    0x46,     2,   32},
        {  0x0110,    0x47,     7,   64},
        {  0x0117,    0x48,     2,   12},
        {  0x00A7,    0x49,     2,   20},

        {  0x0BA0,    0x51,     1,   1},
        {  0x05D0,    0x52,     1,   2},
        {  0x02E8,    0x53,     1,   4},
        {  0x0174,    0x54,     1,   8},
        {  0x00BA,    0x55,     1,   16},
        {  0x005D,    0x56,     1,   32},
        {  0x005D,    0x57,     3,   64},
        {  0x00F8,    0x58,     1,   12},
        {  0x0094,    0x59,     1,   20},

        {  0x0E88,    0x61,     1,   1},
        {  0x0744,    0x62,     1,   2},
        {  0x03A2,    0x63,     1,   4},
        {  0x01D1,    0x64,     1,   8},
        {  0x00E8,    0x65,     1,   16},
        {  0x0074,    0x66,     1,   32},
        {  0x00AE,    0x67,     5,   64},
        {  0x0136,    0x68,     1,   12},
        {  0x00BA,    0x69,     1,   20},

        {  0x0C00,    0x91,     5,   1},
        {  0x0600,    0x92,     5,   2},
        {  0x0300,    0x93,     5,   4},
        {  0x0180,    0x94,     5,   8},
        {  0x00C0,    0x95,     5,   16},
        {  0x0060,    0x96,     5,   32},
        {  0x0080,    0x97,     7,   64},
        {  0x0100,    0x98,     5,   12},
        {  0x0096,    0x99,     5,   20},

        {  0x0C00,    0xA1,     3,   1},
        {  0x0600,    0xA2,     3,   2},
        {  0x0300,    0xA3,     3,   4},
        {  0x0180,    0xA4,     3,   8},
        {  0x00C0,    0xA5,     3,   16},
        {  0x0060,    0xA6,     3,   32},
        {  0x003C,    0xA7,     4,   64},
        {  0x0100,    0xA8,     3,   12},
        {  0x0098,    0xA9,     3,   20},

        {  0x0C00,    0xB1,     2,   1},
        {  0x0600,    0xB2,     2,   2},
        {  0x0300,    0xB3,     2,   4},
        {  0x0180,    0xB4,     2,   8},
        {  0x00C0,    0xB5,     2,   16},
        {  0x0060,    0xB6,     2,   32},
        {  0x0040,    0xB7,     3,   64},
        {  0x0100,    0xB8,     2,   12},
        {  0x0098,    0xB9,     2,   20},

        {  0x0C00,    0xC1,     1,   1},
        {  0x0600,    0xC2,     1,   2},
        {  0x0300,    0xC3,     1,   4},
        {  0x0180,    0xC4,     1,   8},
        {  0x00C0,    0xC5,     1,   16},
        {  0x0060,    0xC6,     1,   32},
        {  0x0048,    0xC7,     2,   64},
        {  0x0100,    0xC8,     1,   12},
        {  0x0099,    0xC9,     1,   20},

        {  0x1000,    0xD1,     1,   1},
        {  0x0800,    0xD2,     1,   2},
        {  0x0400,    0xD3,     1,   4},
        {  0x0200,    0xD4,     1,   8},
        {  0x0100,    0xD5,     1,   16},
        {  0x0080,    0xD6,     1,   32},
        {  0x0040,    0xD7,     1,   64},
        {  0x0154,    0xD8,     1,   12},
        {  0x00CC,    0xD9,     1,   20},

    };


phhalCt_DATAParams_t * phhalCt_RefDATAParams;

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

uint8_t * phhalCt_GetBuffReference(void)
{
   return ((uint8_t *)(phhalCt_RefDATAParams->gphhalCt_DriverBuff));
}

phStatus16_t phhalCt_Init( void * phhalCt_Params, phhalCt_SlotType_t eSlot )
{
    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    uint8_t i = 0;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
    phhalCt_RefDATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;

    if(eSlot >= E_AUX_LAST)
    {
       return PH_CT_ERR_INVALID_PARAMETER;
    }

    phhalCt_DATAParams->gphhalCt_SelectedSlot_t = eSlot;
    phhalCt_DATAParams->gpphhalCt_CallbackFunc = NULL;
    phhalCt_DATAParams->gdwphhalCtRegIntrpts = 0;

    /* Clear/ put to default of all the global variables. */
    phhalCt_ClearContext(phhalCt_DATAParams);

    phhalCt_DATAParams->gphhalCt_InEvent = E_PH_HALCT_EVENT_WAITING;
    eStatus = phhalCt_Event_Init(phhalCt_DATAParams);
    PH_CT_RETURN_ON_FAILURE(eStatus);
    /* Clear the HAL buffer. */
    (void) phUser_MemSet(phhalCt_DATAParams->gphhalCt_DriverBuff, 0x00, PHHAL_CT_MAXBUFSIZE);

    /* Initialise slot specific hal params */
    for( i = 0; i < PHAPP_MAX_CT_SLOT_SUPPORTED; i++ )
    {
       phhalCt_DATAParams->phhalCt_Params[i].gphhalCt_BEmvEn = TRUE;
       phhalCt_DATAParams->phhalCt_Params[i].SlotNum = (phhalCt_SlotType_t)i;
       phhalTda_SlotParamsInit( phhalCt_DATAParams->phhalCt_Params[i].pTDAPins, (phhalCt_SlotType_t)i );
    }

    eStatus = phhalTda_Init();
    phhalCt_SwitchSlot( phhalCt_DATAParams, eSlot );

    NVIC_ClearPendingIRQ(CT_IRQn);
    NVIC_SetPriority(CT_IRQn, 5);
    NVIC_EnableIRQ(CT_IRQn);
    TIMER_Init();
    NVIC_ClearPendingIRQ(GPT_IRQn);
    NVIC_SetPriority(GPT_IRQn, 5);
    NVIC_EnableIRQ(GPT_IRQn);

    return eStatus ;
}


phStatus16_t phhalCt_SetConfig(void * phhalCt_Params, phAppCt_Configs_t eConfig, uint8_t dwValue, uint32_t dwMode, uint32_t dwWTX)
{
    phStatus16_t wStatus = PH_CT_ERR_SUCCESS;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;

    switch(eConfig)
    {
       case E_CONF_COMPLIANCE:
           if(dwValue < E_COMP_LAST)
           {
              phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t].gphhalCt_BEmvEn =  (uint8_t)((dwValue == E_EMVCO_ENABLE)? E_EMVCO_ENABLE: E_ISO7816_ENABLE);
           }
           else
           {
              wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
           }
           break;

       case E_CONF_SELECT_SLOT:
           if(dwValue < E_AUX_LAST)
           {
              phhalCt_SwitchSlot( phhalCt_DATAParams, (phhalCt_SlotType_t)dwValue );
           }
           else
           {
              wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
           }
           break;

       case E_CONF_TIMER:
          phhalCt_SetTimer(phhalCt_DATAParams, dwMode, dwWTX);
          break;

       default:
           wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
    }
    return wStatus;
}


phStatus16_t phhalCt_SwitchSlot( void * phhalCt_Params, phhalCt_SlotType_t eSlot_Index )
{
    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;

    phhalCT_TDAUnselect();
    phhalCt_SelectSlot(phhalCt_DATAParams, eSlot_Index);
    phhalTda_RestoreContext(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t].pTDAPins);
    phhalCT_TDASelect( eSlot_Index );
    phhalCt_SetCardProfile(phhalCt_DATAParams);
    return eStatus;
}

phStatus16_t phhalCt_CheckCardActive( void * phhalCt_Params )
{
   phStatus16_t eStatus = PH_ERR_CT_INVALID_SLOT;
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
   phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

   if( phhalCt_SlotParams->SlotNum == phhalCt_DATAParams->gphhalCt_SelectedSlot_t )
   {
      if( high == phhalTda_CheckCardActive(phhalCt_SlotParams->pTDAPins) )
      {
         eStatus = PH_ERR_CT_CARD_ALREADY_ACTIVATED;
      }
      else
      {
         eStatus = PH_ERR_CT_CARD_DEACTIVATED;
      }
   }
   return eStatus;
}

phStatus16_t phhalCt_CheckCardPres( void * phhalCt_Params )
{
    phStatus16_t eStatus = PH_ERR_CT_INVALID_SLOT;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    if( phhalCt_SlotParams->SlotNum == phhalCt_DATAParams->gphhalCt_SelectedSlot_t )
    {
       /* Check if card is present in the selected AUX slot*/
       if( high == phhalTda_CheckCardPres(phhalCt_SlotParams->pTDAPins) )
       {
          eStatus =  PH_ERR_CT_MAIN_CARD_PRESENT;
       }
       else
       {
          eStatus = PH_ERR_CT_MAIN_CARD_ABSENT;
       }
    }
    return eStatus;
}

#if 0

phStatus16_t phhalCt_ClockStartStop(uint8_t bClockStop, uint8_t bLowHigh)
{
    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    if(gphhalCt_SelectedSlot_t == E_AUXILIARY_SLOT)
    {
        /* For Aux. Slot.*/
    }
    else
    {
        eStatus = phRomhalCt_ClockStartStopConfig(bClockStop, bLowHigh, E_MAIN_SLOT);
    }

    return eStatus;
}

phStatus16_t phhalCt_DeInit(void)
{
    phStatus16_t eStatus;
    /* Perform a soft reset */
    if (phhalCt_Reset() != PH_CT_ERR_SUCCESS)
    {
        return PH_CT_ERR(FAILED,HAL_CT);
    }

    /* De-configuring the CT specific PCR Registers */
    /* TBD: below code is to deinit main slot, this would be replaced by deinit code for AUX slot*/
    /*PH_REG_CLEAR_BIT(PCR_SYS_REG, ENABLE_CT);
    PH_REG_CLEAR_BIT(PCR_CLK_CFG_REG, CLOCK_CTIF_ENABLE);
    PH_REG_CLEAR_BIT(PCR_CLK_CFG_REG, IPCLOCK_CTIF_ENABLE);
    PH_REG_CLEAR_BIT(PCR_SYS_REG, AUTOMATIC_CT_DEACT);*/

    /* Disables the NVIC for Contact Interface */
    /*TBD to replace with correct NVIC disable */
    /*phhalCt_CLEARBITN(NVIC_ISER_REG,PHHAL_NVIC_CTIF);*/

    /* Globals specific to the current session of card has to be cleared*/
    phhalCt_ClearContext();

    /* Clear Events */
    eStatus = phhalCt_Event_Consume((phhalCt_EventType_t)(E_PH_HALCT_EVENT_ALL | E_PH_HALCT_EVENT_CARD_REMOVED));
    PH_CT_RETURN_ON_FAILURE(eStatus);
    /* Deinitialize all event group.*/
    eStatus = phhalCt_Event_Deinit();

    return eStatus;
}


phStatus16_t phhalCt_Reset(void)
{
    /* Perform a Soft reset this will reset the whole CT UART IP */
    phhalCt_CLEARBITN(CT_SSR_REG,CT_SSR_REG_NOT_SOFTRESET_POS);
    /* Delay to wait for one clock cycle */
    /*TBD to check wait duration required and how to add */
    /*phUser_Wait(100);*/
    if (phhalCT_TESTBITN(CT_SSR_REG, CT_SSR_REG_NOT_SOFTRESET_POS))
    {
        return PH_CT_ERR_SUCCESS;
    }
    else
    {
        return PH_CT_ERR(FAILED,HAL_CT);
    }
}


void phhalCt_AsyncShutDown(void)
{
    (void)phhalCt_Event_Post(E_PH_HALCT_EVENT_ASYNC);
}
#endif

void phhalCt_MuteCardTimerCb( void * pContext )
{
   phhalCt_MuteCardTimerStop();

   /* Post the event */
   (void) phhalCt_Event_Post(phhalCt_RefDATAParams, E_PH_HALCT_EVENT_MUTE);
   return;
}
/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */

void CT_DriverIRQHandler( void )
{
    phhalCt_DATAParams_t * phhalCt_DATAParams = phhalCt_RefDATAParams;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    /* Read the Status of USR1 Register and check if any error bit is enabled and set corresponding error flag*/
    uint8_t bUartStatus1 = (uint8_t)phhalCt_GETREG(eUSR1);
    uint8_t bUartStatus2 = (uint8_t)phhalCt_GETREG(eUSR2);

    if (bUartStatus1 & CT_USR1_PE_MASK)
    {
        /* During the T=0 transmit if the last byte in the Fifo is naked by the card for more than
         * PEC retry counter this error is captured here and updated */
        if(!phhalCt_DATAParams->gphhalCt_BActivationState)
        {
            if((!(phhalCT_TESTBITN(eUCR1X,CT_UCR1X_PROT_SHIFT))) && (phhalCT_TESTBITN(eUCR1X,CT_UCR1X_T_R_SHIFT)))
            {
                /* Flush the Fifo */
                phhalCt_SETBITN(eUCR2X,CT_UCR2X_FIFO_FLUSH_SHIFT);
                phhalCt_DATAParams->gphhalCt_BParityErr = 0x01;
            }
        }

        /* Post the event */
        (void) phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_PARITY);
        if ((!(bUartStatus1 & CT_USR1_FT_MASK))||(phhalCt_DATAParams->gphhalCt_BActivationState))
        {
            return;
        }
    }
    if (bUartStatus1 & CT_USR1_OVR_MASK)
    {
        /* Post the event */
        (void) phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_OVR_ERR);
        return;
    }
    if (bUartStatus1 & CT_USR1_FER_MASK)
    {
        /* Post the event */
        (void) phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_FRM_ERR);
        return;
    }
    if (bUartStatus1 & CT_USR1_FT_MASK)
    {
        /* If at least one byte is received[ATR byte] and card activate is called restart the timer **/
        if (phhalCt_DATAParams->gphhalCt_BActivationState)
        {
            phhalCt_DATAParams->gphhalCt_DriverBuff[phhalCt_DATAParams->gphhalCt_WDataCount++] = (uint8_t) phhalCt_GETREG(eUTR_URR_REG_ADR1);

            /* Handle Atr parsing parity error.*/
            if(phhalCt_DATAParams->gphhalCt_WDataCount == 0x01)
            {
               phhalCt_MuteCardTimerStop();
                /* Again Enabling Parity error event after first byte.*/
               phhalCt_CLEARBITN(eUCR2X,CT_UCR2X_DISPE_SHIFT);
            }

            /* Post the event */
            (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_RX);
            bUartStatus1 = (bUartStatus1 &  (uint8_t)~(CT_USR1_FT_MASK));
        }
        else
        {
            if(phhalCt_DATAParams->gphhalCt_BTransmitComplete == 0x00)
            {
                  if(phhalCT_GETFIELD(eFCR, CT_FCR_FTC4_FTC0_MASK) == 0x00)
                  {
                      /* Disable the Fifo threshold so that we will not get interrupt for this last byte */
                      phhalCt_SETBITN(eUCR2X,CT_UCR2X_DISFT_SHIFT);
                      phhalCt_SETBITN(eUCR1X,CT_UCR1X_LCT_SHIFT);
                      phhalCt_SETREG(eUTR_URR_REG_ADR1, phhalCt_DATAParams->gphhalCt_BLastByteTransmit);
                  }
                /* Post the event */
                (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_TX);
                bUartStatus1 = (bUartStatus1 &  (uint8_t)~(CT_USR1_FT_MASK));
                return;
            }

            if(phhalCt_DATAParams->gphhalCt_BCWTFlag == 0x00)
            {
              if(phhalCT_TESTBITN(eUCR1X,CT_UCR1X_PROT_SHIFT))
              {
                   /* Change the count value to character waiting time Dirty
                   * fix for CWT waiting time not able to achieve in RTOS env */
                 phhalCt_SETREG(eTOR1, (uint8_t)(phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime));
                 phhalCt_SETREG(eTOR2, (uint8_t)(phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime >> 8));
                 phhalCt_SETREG(eTOR3, (uint8_t)(phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime >> 16));
                  /* Timer 1,2,3 forms a 24 bit timer and they start on each subsequent start bit */
                 phhalCt_SETREG(eTOC, PHHAL_CT_T123START_BIT_CONFIG);

                 phhalCt_DATAParams->gphhalCt_BCWTFlag = 0x01;
              }
            }

            /* At higher baud rate receive events are missed during processing of last byte,
            * thats why for doing copy in hal buffer as soon as bytes comes in fifo  this logic is needed.
            */
            while(phhalCt_GETREG(eFSR))
            {
              phhalCt_DATAParams->gphhalCt_DriverBuff[phhalCt_DATAParams->gphhalCt_WDataCount++] = (uint8_t) phhalCt_GETREG(eUTR_URR_REG_ADR1);
              phhalCt_DATAParams->gphhalCt_WPendingBytes++;

            }
            if(phhalCt_DATAParams->gphhalCt_WPendingBytes >= phhalCt_DATAParams->gphhalCt_WReceiveSize)
            {
              /* Post the event */
              (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_RX);

              /* Place a very high value so that even if some more bytes come in the Fifo
               * this check will never get called*/
              phhalCt_DATAParams->gphhalCt_WReceiveSize = 0xFFFF;
            }
        }
        return;
    }
    /* Check the status of USR2 REGISTER*/
    if (bUartStatus2 & CT_USR2_TO3_MASK)
    {
        if (phhalCt_DATAParams->gphhalCt_BActivationState) /*For the case for ATR reception*/
        {
            /* All ATR Bytes Received */
            phhalCt_DATAParams->gphhalCt_BActivationState = 0;

            /* Post the event */
            (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_TO3);
            bUartStatus2 = (bUartStatus2 &  (uint8_t)~(CT_USR2_TO3_MASK));
            return;
        }
        else /* For BWT or CWT violation */
        {
            /* Post the event */
            (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_TO3);
            bUartStatus2 = (bUartStatus2 &  (uint8_t)~(CT_USR2_TO3_MASK));
            return;
        }
    }
    if (bUartStatus2 & CT_USR2_TO1_MASK)
    {
        /* Increment the software counter */
        phhalCt_DATAParams->gphhalCt_BTimerCount++;
        /* Count is reached for 20160 value */
        if(phhalCt_DATAParams->gphhalCt_BTimerCount == PHHAL_CT_ATR_TOR1_TIMER_MAX_COUNT)
        {
            phhalCt_StopCTTimer();
            phhalCt_DATAParams->gphhalCt_BTimerCount = 0;
            phhalCt_DATAParams->gphhalCt_BActivationState = 0;
            /* Post the event */
            (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_TO1);
        }
        return;
    }
    if (bUartStatus2 & CT_USR2_INTAUXL_MASK)
    {
         if( low == phhalTda_CheckCardPres(phhalCt_SlotParams->pTDAPins) )
         {
            /* Post the event */
            (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_CARD_REMOVED);
            /* Call the deactivate also even though the HW deactivation takes place */
            phhalCt_DeactivateCard_fromISR(phhalCt_DATAParams);
         }
         bUartStatus2 = (bUartStatus2 &  (uint8_t)~(CT_USR2_INTAUXL_MASK));
    }
    if (bUartStatus2 & CT_USR2_PROTL_MASK)
    {
        /* Post the event */
        (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_PROTL_ERR);
        bUartStatus2 = (bUartStatus2 &  (uint8_t)~(CT_USR2_PROTL_MASK));
    }
    if (bUartStatus2 & CT_USR2_PTL_MASK)
    {
        /* Post the event */
        (void)phhalCt_Event_Post(phhalCt_DATAParams, E_PH_HALCT_EVENT_PTL_ERR);
        bUartStatus2 = (bUartStatus2 &  (uint8_t)~(CT_USR2_PTL_MASK));
    }
}

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */

