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
#include "phhalCt_Event.h"
#include "phhalCt_Interface.h"

/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
/**
 *  Default value for IFSC.
 */
#define PHHAL_CT_DEFAULT_IFSC                   0x20
/**
 *  Default value for waiting integer.
 */
#define PHHAL_CT_7816_DEFAULT_BWI               0x04
/**
 *  Default value for waiting integer.
 */
#define PHHAL_CT_7816_DEFAULT_CWI               0x0D
/**
 *  Default value for waiting integer.
 */
#define PHHAL_CT_DEFAULT_WI                     0x0A
/**
 *  Default value for extra guard time.
 */
#define PHHAL_CT_DEFAULT_EXTRAGUARD_TIME        0x00

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

/**
 * This function calculates WWT,BWT and CWT.
 */
static void phhalCt_CalculateWWTBWTCWT(phhalCt_DATAParams_t * phhalCt_DATAParams, uint8_t bTableCount);

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

void phUser_MemSet(void * pvBuf, uint32_t dwu8Val, uint32_t dwLength)
{
   (void)memset(pvBuf, (int)dwu8Val, dwLength);
}

void phUser_MemCpy(void* pvDst, const void* pvSrc, uint32_t dwLength)
{
   (void)memcpy(pvDst, pvSrc, dwLength);
}

/* Wait based on SW Precision */
void phUser_Wait(uint32_t dwUSec)
{
	PN76_Common_Wait(dwUSec);
}

phhalCt_SlotType_t phhalCt_GetSelectedSlot( void * phhalCt_Params )
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
   return phhalCt_DATAParams->gphhalCt_SelectedSlot_t;
}

void phhalCt_SelectSlot( void * phhalCt_DATAParams, phhalCt_SlotType_t SlotNum )
{
   ((phhalCt_DATAParams_t *)phhalCt_DATAParams)->gphhalCt_SelectedSlot_t = SlotNum;
}

phStatus16_t phhalCt_SetBaudRate(phhalCt_DATAParams_t * phhalCt_DATAParams)
{
    phStatus16_t eStatus = PH_CT_ERR_FAILED;
    uint8_t bCount = 0x00;
    //volatile uint32_t temp = 0;
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);
    do
    {
        /* Search for the supported FiDi value from the table */
        for(bCount=0;bCount <PHHAL_CT_FIDI_TAB_LEN;bCount++)
        {
            if(phhalCt_SlotParams->gphhalCt_BCurrentFiDi == gkphhalCt_BPreScalar[bCount].bFiDi)
            {
                break;
            }
        }
        if(bCount == PHHAL_CT_FIDI_TAB_LEN) /* End of table reached no FiDi found */
        {
            eStatus = PH_CT_ERR_INVALID_PARAMETER;
            break;
        }

        /* Set the clock divider value from the table */
        phhalCT_SETFIELD(eCCRX, CT_CCRX_ACC2_ACC0_MASK, (gkphhalCt_BPreScalar[bCount].bClockDivider));
        /* Set the PDR register value from the table */
        phhalCt_SETREG(ePDRX_LSB, (uint8_t )(gkphhalCt_BPreScalar[bCount].wPdrRegValue));
        phhalCt_SETREG(ePDRX_MSB, (uint8_t )(gkphhalCt_BPreScalar[bCount].wPdrRegValue >> 8));

        /* Update the current FiDi value */
        phhalCt_SlotParams->gphhalCt_BCurrentFiDi = phhalCt_SlotParams->gphhalCt_BFiDi;
        /* Calculate the timing parameters based on the table index */
        (void)phhalCt_CalculateWWTBWTCWT(phhalCt_DATAParams, bCount);

        eStatus = PH_CT_ERR_SUCCESS;
    }while(0);
    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}

/* *****************************************************************************************************************
 * Internal Functions
 * ***************************************************************************************************************** */

/**
 *Function Name     : phhalCt_ClearContext
 *Description       : This Api is used to clear the global variables used within CT HAL except the slot index.
 *
 *Input Parameters  : None
 *
 *Output Parameters : None
 *
 */

void phhalCt_ClearContext(phhalCt_DATAParams_t * phhalCt_DATAParams)
{
    phhalCt_DATAParams->gphhalCt_BActivationState = 0x00;
    phhalCt_DATAParams->gphhalCt_BTimerCount = 0x00;
    phhalCt_DATAParams->gphhalCt_BTransmitComplete = 0x00;
    phhalCt_DATAParams->gphhalCt_WPendingBytes = 0x00;
    phhalCt_DATAParams->gphhalCt_BCWTFlag = 0x00;
    phhalCt_DATAParams->gphhalCt_WDataCount = 0x00;
    phhalCt_DATAParams->gphhalCt_WReceiveOffset = 0x00;
}

/**
 *Function Name     : phhalCt_SetDefaultValues
 *Description       : This Api is used to set the default values to the  global variables used for protocol parameters
 *
 *Input Parameters  : psAtrParams - pointer to Atr parameter structure.
 *
 *Output Parameters : None
 *
 */
void phhalCt_SetDefaultValues(phhalCt_DATAParams_t * phhalCt_DATAParams)
{
   phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

   phhalCt_SlotParams->gphhalCt_BFiDi     = PHHAL_CT_DEFAULT_FIDI;
   phhalCt_SlotParams->gphhalCt_BCurrentFiDi = PHHAL_CT_DEFAULT_FIDI;

   phhalCt_SlotParams->sAtrParams.bValueofNInTC1 = PHHAL_CT_DEFAULT_EXTRAGUARD_TIME;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bCWI   = PHHAL_CT_7816_DEFAULT_CWI;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bBWI    = PHHAL_CT_7816_DEFAULT_BWI;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bWI = PHHAL_CT_DEFAULT_WI;
   phhalCt_SlotParams->gphhalCt_BFirstOfferedProt = 0x00;

   phhalCt_SlotParams->sAtrParams.bFlagT15 = 0x00;
   phhalCt_SlotParams->sAtrParams.bFlagT15TAPresent = 0x00;
   phhalCt_SlotParams->sAtrParams.bEarlyEventFlag = 0x00;

   phhalCt_SlotParams->sAtrParams.bTCKByte = 0x00;
   phhalCt_SlotParams->sAtrParams.bInvalidAtr = 0x00;
   phhalCt_SlotParams->sAtrParams.bInvalidTD1 = 0x00;
   phhalCt_SlotParams->sAtrParams.bInvalidTA1 = 0x00;
   phhalCt_SlotParams->sAtrParams.bLastOfferedProt = 0x00;
   phhalCt_SlotParams->sAtrParams.bWarmResetState = 0x00;

   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bIFSC = PHHAL_CT_DEFAULT_IFSC;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bFiDi = PHHAL_CT_DEFAULT_FIDI;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bProtSelT1 = 0x00;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bProtSelT0 = 0x01;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bNegotiableMode = 0x00;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bTA2Bit8Set = 0x00;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bIsTA1Absent = 0x00;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bFlagT15TAValue = 0x00;
   phhalCt_SlotParams->sAtrParams.sAtrHalParams.bCRCPresent = 0x00;

   phhalCt_DATAParams->gphhalCt_WReceiveSize = 0xFFFF;
}


/**
 *Function Name    : phhalCt_HandleCommonEvent
 *Description      : This function is used to process all common hardware fault events like parity ,overrun,protl,prot.
 *
 *Input Parameters  :void
 *Output Parameters :PH_CT_ERR_SUCCESS - If any of the hardware fault event is not generated.\
 *                   PH_ERR_CT_MUTE_ERROR - Card is muted
 *                   PH_ERR_CT_EARLY_ERROR - Card has answered early
 *                   PH_ERR_CT_PARITY_ERROR - Card has parity error while receiving the ATR
 *                   PH_ERR_CT_OVERUN_ERROR - Fifo is over run while receiving the ATR
 *                   PH_ERR_CT_FRAMING_ERROR - Framing error while receiving the ATR
 */
phStatus16_t phhalCt_HandleCommonEvent(phhalCt_DATAParams_t * phhalCt_DATAParams)
{
    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    do
    {
        if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_PARITY) == E_PH_HALCT_EVENT_PARITY)
        {
            phhalCt_DATAParams->gphhalCt_BParityErr = 0x00;
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)PH_ERR_CT_PARITY_ERROR);
            eStatus = PH_ERR_CT_PARITY_ERROR;
            break;
        }
        else if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_OVR_ERR) == E_PH_HALCT_EVENT_OVR_ERR)
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)PH_ERR_CT_OVERUN_ERROR);
            eStatus = PH_ERR_CT_OVERUN_ERROR;
            break;
        }
        else if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_FRM_ERR) == E_PH_HALCT_EVENT_FRM_ERR)
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)PH_ERR_CT_FRAMING_ERROR);
            eStatus = PH_ERR_CT_FRAMING_ERROR;
            break;
        }
        else if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_PTL_ERR) == E_PH_HALCT_EVENT_PTL_ERR)
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)PH_ERR_CT_TEMPERATURE_LATCHED);
            eStatus = PH_ERR_CT_TEMPERATURE_LATCHED;
            break;
        }
        else if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_ASYNC) == E_PH_HALCT_EVENT_ASYNC)
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)E_PH_HALCT_EVENT_ASYNC);
            (void)phhalCt_DeactivateCard(phhalCt_DATAParams);
            eStatus = PH_ERR_CT_ASYNCH_SHUTDOWN;
            break;
        }
        else if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_CARD_REMOVED) == E_PH_HALCT_EVENT_CARD_REMOVED)
        {
            phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)E_PH_HALCT_EVENT_CARD_REMOVED);
            (void)phhalCt_DeactivateCard(phhalCt_DATAParams);
            eStatus = PH_ERR_CT_CARD_REMOVED;
            break;
        }
        else
        {
            if((phhalCt_DATAParams->gphhalCt_InEvent & E_PH_HALCT_EVENT_PROTL_ERR) == E_PH_HALCT_EVENT_PROTL_ERR)
            {
                phhalCt_Event_Consume(phhalCt_DATAParams, (phhalCt_EventType_t)PH_ERR_CT_PROTECTION_LATCHED);
                eStatus = PH_ERR_CT_PROTECTION_LATCHED;
            }
        }
    }while(0);
    return eStatus;
}

/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */

/**
 *Function Name     : phhalCt_CalculateWWTBWTCWT
 *Description       : This Api is used to calculate WWT ,BWT and CWT values according to atr provided parameters.
 *
 *Input Parameters  : bTableCount - index for particular clock uart structure from clock uart table.
 */
static void phhalCt_CalculateWWTBWTCWT(phhalCt_DATAParams_t * phhalCt_DATAParams, uint8_t bTableCount)
{
    phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);
    uint16_t wFactoCorr = (uint16_t)(gkphhalCt_BPreScalar[bTableCount].bDValue * 1000);

    /* WWT calculation */
    /*  WWT = (960 x D x WI)
    *  Final WWT = {WWT + (D x 480)} EMVCO Specification 9.2.2.1
    * */
    phhalCt_SlotParams->gphhalCt_DwWaitingTime = (uint32_t)(960 * phhalCt_SlotParams->sAtrParams.sAtrHalParams.bWI);
    phhalCt_SlotParams->gphhalCt_DwWaitingTime = (uint32_t)(phhalCt_SlotParams->gphhalCt_DwWaitingTime * gkphhalCt_BPreScalar[bTableCount].bDValue);
    if(phhalCt_SlotParams->gphhalCt_BEmvEn)
    {
       phhalCt_SlotParams->gphhalCt_DwWaitingTime = (uint32_t)((phhalCt_SlotParams->gphhalCt_DwWaitingTime) + (uint32_t)(480 * gkphhalCt_BPreScalar[bTableCount].bDValue));
    }
    phhalCt_SlotParams->gphhalCt_DwWaitingTime += 1;

    /* CWT calculation.*/
     /* EMVCO Specification 9.2.4.2.2.*/
    phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime = (uint16_t)( 1 << phhalCt_SlotParams->sAtrParams.sAtrHalParams.bCWI);
    if(phhalCt_SlotParams->gphhalCt_BEmvEn)
    {
        phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime += 16;
    }
    else
    {
        phhalCt_SlotParams->gphhalCt_DwCharacterWaitingTime += 12;
    }

    /* BWT calculation.*/
    /* BWT = 11 ETU + 2^BWI*960* (372D/F).*/
    /* Final BWT = {BWT + (D x 960)} EMVCO Specification 9.2.4.2.2.*/
    phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime  = (uint32_t)(1 << phhalCt_SlotParams->sAtrParams.sAtrHalParams.bBWI);
    phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime *= wFactoCorr;
    phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime /= 1000;
    phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime *= 960;
    phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime += 12;
    if(phhalCt_SlotParams->gphhalCt_BEmvEn)
    {
       phhalCt_SlotParams->gphhalCt_DwBlockWaitingTime += (uint32_t)(960*gkphhalCt_BPreScalar[bTableCount].bDValue);
    }
}

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */

