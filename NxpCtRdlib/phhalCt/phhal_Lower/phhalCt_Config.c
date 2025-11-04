/*----------------------------------------------------------------------------*/
/* Copyright 2014,2015,2023 NXP                                               */
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

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "phhalCt.h"
#include "phhalCt_Int.h"
#include "phhalCt_Interface.h"


/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
#define PHHAL_CT_CARD_DEFAULT_CLOCK      0x05
/**
 * Set the timer in maximum allowed time in ATR between each character.
 */
#define PHHAL_CT_ATRMODE_MAXTIME           1
/**
 * TOR1 timer value for atr mode in EMVCo.
 */
#define PHHAL_CT_EMV_ATRMODE_TOR1_VAL      0xF0
/**
 * Macros for CT Timer TOR register value of 10081 etu LSB started during ATR reception, Loading the value of 0x2761
 *  into TOR register will give the value of 10081 ETU's.
 */
#define PHHAL_CT_LSB_ETU10080_VALUE       0x61
/**
 * Macros for CT Timer TOR register value of 10081 etu MSB started during ATR reception, Loading the value of 0x2761
 *  into TOR register will give the value of 10081 ETU's.
 */
#define PHHAL_CT_MSB_ETU10080_VALUE       0x27
/**
 * Timer 1 starts on 1st Start bit on I/O line, Timer 2 and 3 starts on every start bit on I/O line, this is used during
 * the ATR reception.
 */
#define PHHAL_CT_T1START_T23START_CONFIG    0x75
/**
 * Macros for CT Timer TOR register value of 9600 etu LSB started during ATR reception, Loading the value of 0x2580
 * into TOR register will give the value of 9600 ETU's.
 */
#define PHHAL_CT_LSB_ETU9600_VALUE        0x81
/**
 * Macros for CT Timer TOR register value of 9600 etu MSB started during ATR reception, Loading the value of 0x2580
 * into TOR register will give the value of 9600 ETU's.
 */
#define PHHAL_CT_MSB_ETU9600_VALUE        0x25
/**
 * Macros for CT Timer TOC register configuration value, Timer 1 is stopped, and Timers 3 and 2 form a 16-bit Timer and
 * is started on the first start bit detected on pin I/O.
 */
#define PHHAL_CT_T1STOP_T23STARTONIO_CONFIG    0x71

/**
 * Set the timer in maximum allowed time in ATR between each character.
 */
#define PHHAL_CT_ATRMODE_MAXTIME           1

/** Set the timer in PPS Exchange mode configuration.*/
#define PHHAL_CT_PPSMODE_9600_ETU          4
/**
 * Maximum parity error that is allowed.
 */
#define PHHAL_CT_MAX_PARITY_ERR_COUNT     7
/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Global and Static Variables
 *
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */

static phStatus16_t phhalCt_SetIPTimer( void * phhalCt_Params, uint32_t dwMode, uint32_t dwWTX, uint32_t dwBlockWaitTime, uint32_t dwWaitTime );

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

phStatus16_t phhalCt_SetActivationConfig(void * phhalCt_Params)
{
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    do
    {
        /* Set the card clock default value to 5 Mhz max */
        /* The PDR default value 372 is multiplied by 8 will result in 0xBA0, Since we are dividing the Card clock
         * frequency by 8 [ACC2- ACC0 = clock/6], we have to multiply the default 372 etu value with 8 for sampling and
         * hence the value 0xBA0 is loaded as the default value in the PDR register */

        phhalCt_SETREG( eCCRX, ( CT_CCRX_ACC2_ACC0_MASK & ( 0x05 << CT_CCRX_ACC2_ACC0_SHIFT )) );
        phhalCt_SETREG( eUCR2X, 0 );
        phhalCt_SETREG( ePDRX_LSB, 0xB8 );
        phhalCt_SETREG( ePDRX_MSB, 0x08 );

        /* Configure the timers for ATR reception */
        phhalCt_SetIPTimer( phhalCt_DATAParams, PHHAL_CT_ATRMODE_MAXTIME, 0x00, 0x00, 0x00 );

        /* This has been done as a workaround for the hardware BUG SEE for more details PR NO: SC2290 */
        phhalCt_SETREG(eUCR1X, 0x00000000);
        phhalCt_SETREG(eUCR2X, 0x00000000);

        /* Set the fifo threshold to 0 so that for each byte we will get interrupt */
        phhalCT_SETFIELD(eFCR, CT_FCR_FTC4_FTC0_MASK, 0x00);

        if(phhalCt_SlotParams->sAtrParams.bWarmResetState == 0x01)
        {
            /* Enable the warm reset for ATR reception */
            /* RESET low */
            PH_HAL_CT_RESET_LOW;
#if (defined(NXPBUILD__PHHAL_HW_PALLAS))
            /* Warm Reset Initialization Delay between 40000 & 45000 cycles, below calculation produce 41638 cycles (9.211ms) */
            for(i=0; i<27*1000; i++);
#elif (defined(NXPBUILD__PHHAL_HW_GOC_7642))
            /* Warm Reset Initialization Delay between 40000 & 45000 cycles, below calculation produce 42673 cycles */
            phUser_Wait(WARM_RESET_INITIALIZATION_DELAY);
#endif
            /* RESET high */
            PH_HAL_CT_RESET_HIGH;
            phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, eRSTIN, high);
        }
        eStatus = PH_CT_ERR_SUCCESS;
    }while(0);

    return eStatus;
}

static phStatus16_t phhalCt_SetIPTimer( void * phhalCt_Params, uint32_t dwMode, uint32_t dwWTX, uint32_t dwBlockWaitTime, uint32_t dwWaitTime )
{
    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

    uint32_t dwLoadBWTValue = (uint32_t)(dwBlockWaitTime * dwWTX);

    /*Stop the timers before loading the new values*/
    phhalCt_SETREG(eTOC, (uint8_t)(0));

    switch (dwMode)
    {
        /* Used to set inter character delay and maximum allowed reception time for atr bytes during atr reception.*/
        case PHHAL_CT_ATRMODE_MAXTIME:
        {
            if(phhalCt_SlotParams->gphhalCt_BEmvEn)
            {
                /* Timer configuration for the EMVCO ATR reception*/
                /* 20160 Timer --> 0xF0 * 0x54 = 20160 [Timer value]*/
               phhalCt_SETREG(eTOR1,PHHAL_CT_EMV_ATRMODE_TOR1_VAL);
                /* 10080 timer*/
               phhalCt_SETREG(eTOR2, PHHAL_CT_LSB_ETU10080_VALUE);
               phhalCt_SETREG(eTOR3, PHHAL_CT_MSB_ETU10080_VALUE);
                /* Timer 1 starts on 1st Start bit on I/O line, Timer 2 and 3 starts on every start bit on I/O line.*/
               phhalCt_SETREG(eTOC, PHHAL_CT_T1START_T23START_CONFIG);
            }
            else
            {
                /* 9600 timer*/
               phhalCt_SETREG(eTOR2, PHHAL_CT_LSB_ETU9600_VALUE);
               phhalCt_SETREG(eTOR3, PHHAL_CT_MSB_ETU9600_VALUE);
                /* Timer 1 will remain stop, Timer 2 and 3 starts on every start bit on I/O line.*/
               phhalCt_SETREG(eTOC, PHHAL_CT_T1STOP_T23STARTONIO_CONFIG);
            }

            eStatus = PH_CT_ERR_SUCCESS;
        }
        break;
        /* Used to set BWT value in timers for T1 protocol.*/
        case PHHAL_CT_APDUMODE_BWT:
        {
            /* Load the value of gdwBlockWaitingTime to timer registers */
            phhalCt_SETREG(eTOR1, (uint8_t)(dwLoadBWTValue));
            phhalCt_SETREG(eTOR2, (uint8_t)(dwLoadBWTValue >> 8));
            phhalCt_SETREG(eTOR3, (uint8_t)(dwLoadBWTValue >> 16));
            /* Timer 1,2,3 forms a 24 bit timer and they start on each subsequent start bit */
            phhalCt_SETREG(eTOC, PHHAL_CT_T123START_BIT_CONFIG);
            eStatus = PH_CT_ERR_SUCCESS;
        }
        break;
        /* Used to set WWT value in timers for T0 protocol.*/
        case PHHAL_CT_APDUMODE_WWT:
        {
            /* Load the value of gdwWaitingTime to timer registers */
            phhalCt_SETREG(eTOR1, (uint8_t)(dwWaitTime));
            phhalCt_SETREG(eTOR2, (uint8_t)(dwWaitTime >> 8));
            phhalCt_SETREG(eTOR3, (uint8_t)(dwWaitTime >> 16));
            /*Timer 1,2,3 forms a 24 bit timer and they start on each subsequent start bit */
            phhalCt_SETREG(eTOC, PHHAL_CT_T123START_BIT_CONFIG);
            eStatus = PH_CT_ERR_SUCCESS;
        }
        break;
        /* Used to set WWT value in timers for PPS Exchange in 7816.*/
        case PHHAL_CT_PPSMODE_9600_ETU:
        {
            /* Load the value of initial WWT value for PPS exchange.*/
            phhalCt_SETREG(eTOR1, PHHAL_CT_LSB_ETU9600_VALUE);
            phhalCt_SETREG(eTOR2, PHHAL_CT_MSB_ETU9600_VALUE);
            /* Timer 1,2,3 forms a 24 bit timer and they start on each subsequent start bit.*/
            phhalCt_SETREG(eTOC, PHHAL_CT_T123START_BIT_CONFIG);
            eStatus = PH_CT_ERR_SUCCESS;
        }
        break;
        default:
            phhalCt_SETREG(eTOR1, (uint8_t)(0));
            phhalCt_SETREG(eTOR2, (uint8_t)(0));
            phhalCt_SETREG(eTOR3, (uint8_t)(0));
            phhalCt_SETREG(eTOC, (uint8_t)(0));
        break;
    }
    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}

phStatus16_t phhalCt_SetTimer(void * phhalCt_Params, uint32_t dwMode, uint32_t dwWTX)
{
    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;

    if(dwMode == PHHAL_CT_PPSMODE_9600_ETU )
    {
        /*Stop the timers before loading the new values*/
        phhalCt_SETREG(eTOC, (uint8_t)(0));

        /* Load the value of initial WWT value for PPS exchange.*/
        phhalCt_SETREG(eTOR2, PHHAL_CT_LSB_ETU9600_VALUE);
        phhalCt_SETREG(eTOR3, PHHAL_CT_MSB_ETU9600_VALUE);
        /* Timer 1 will remain stop, Timer 2 and 3 starts on every start bit on I/O line.*/
        phhalCt_SETREG(eTOC, PHHAL_CT_T1STOP_T23STARTONIO_CONFIG);
    }
    else if(dwMode == PHHAL_CT_SW_TRIGGER)
    {
      /* Load the default values of ETU */
        /* Set the card clock default value to 5 Mhz max */
        phhalCT_SETFIELD(eCCRX, CT_CCRX_ACC2_ACC0_MASK ,PHHAL_CT_CARD_DEFAULT_CLOCK);
        /* The PDR default value 372 is multiplied by 8 will result in 0xBA0, Since we are dividing the Card clock
         * frequency by 8 [ACC2- ACC0 = clock/6], we have to multiply the default 372 etu value with 8 for sampling and
         * hence the value 0x8B8 is loaded as the default value in the PDR register */
        phhalCt_SETREG(ePDRX_LSB, 0xB8);
        phhalCt_SETREG(ePDRX_MSB, 0x08);

        /*Stop the timers before loading the new values*/
        phhalCt_SETREG(eTOC, (uint8_t)(0));

        phhalCt_SETREG(eTOR2, (uint8_t)(dwWTX ));
        phhalCt_SETREG(eTOR3, (uint8_t)(dwWTX >> 8));
        /* Timer 1 will remain stop, Timer 2 and 3 starts now */
        phhalCt_SETREG(eTOC, PHHAL_CT_T23_SOFTWARE_TRIG_CONFIG);
    }
    else
    {
        eStatus = phhalCt_SetIPTimer( phhalCt_DATAParams,
                                      dwMode,
                                      dwWTX,
                                      phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t].gphhalCt_DwBlockWaitingTime,
                                      phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t].gphhalCt_DwWaitingTime );
    }
    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}

/**
 *Function Name     : phhalCt_DeactivateCardConfig
 *Description       : This function is used to perform the Firmware Deactivation procedure
 *                    This function replaces phRomhalCt_CardDeactivateConfig (See Artf189696)
 *Output Parameters : PH_CT_ERR_SUCCESS
 */
phStatus16_t phhalCt_DeactivateCardConfig(void)
{

    /* Flush the FIFO */
    phhalCt_SETBITN(eUCR2X,CT_UCR2X_FIFO_FLUSH_SHIFT);

    /* Firmware workaround for the hardware bug */
    phhalCt_SETREG(eUCR1X, 0x00000000);
    phhalCt_SETREG(eUCR2X, 0x00000000);

    return PH_CT_ERR_SUCCESS;
}

phStatus16_t phhalCt_SetTransmissionProtocol(uint8_t bCardProtocol)
{
   if ( bCardProtocol == E_PROTOCOL_CT_T1 )
   {   /* Setting the protocol to T=1 */
     phhalCt_SETBITN(eUCR1X,CT_UCR1X_PROT_SHIFT);
   }
   else
   {
     /* Set the protocol to T=0 and set the parity error count to 4.*/
     phhalCt_CLEARBITN(eUCR1X, CT_UCR1X_PROT_SHIFT);
     phhalCT_SETFIELDSHIFT(eFCR, CT_FCR_PEC2_PEC0_MASK, CT_FCR_PEC2_PEC0_SHIFT, PHHAL_CT_MAX_RETRY_PARITY);
   }
   return PH_CT_ERR_SUCCESS;
}


/** stop the timers, the timers will be stopped irrespective of any configuration and count.*/
void phhalCt_StopCTTimer( void )
{
   phhalCt_SETREG(eTOC, 0x00);
}

#endif
