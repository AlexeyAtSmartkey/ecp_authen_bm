/*
 * phhalCt_TDA.c
 *
 *  Created on: Feb 16, 2022
 *      Author: nxf80132
 */

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
 * Implements CT HAL TDA which directly interacts with CT IP registers.
 *
 * Project:  PN7642
 *
 * $Date$
 * $Author$
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include "PN76_CT.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "phhalCt.h"
#include "phhalCt_Int.h"
#include "phhalCt_Interface.h"
/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */
/** Macro for Default clock value 4.92MHz for activation.*/


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

/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */
phStatus16_t phhalTda_Init(void)
{
   volatile uint32_t temp = 0;

   PH_HAL_CT_RESET_LOW;				/* RESET low */
   PH_HAL_CT_CLKDIV2_LOW;			/* Set CLK_DIV2 low */
   PH_HAL_CT_CLKDIV1_HIGH;			/* Set CLK_DIV1 high */
   PH_HAL_CT_1V8_HIGH;				/* Set 1V8 high */
   PH_HAL_CT_5V3_LOW;				/* Set 5V_3V low */
   PH_HAL_CT_CMDVCCN_HIGH;			/* Set CMDVCC high */

   temp = phhalCt_GETREG(eSSR);
   temp =  temp | ( ( CT_SSR_IOAUXEN_MASK & ( 0x1 << CT_SSR_IOAUXEN_SHIFT )) |
            		( CT_SSR_CLKAUXEN_MASK & ( 0x1 << CT_SSR_CLKAUXEN_SHIFT )) );
   phhalCt_SETREG(eSSR, temp);
   return PH_CT_ERR_SUCCESS ;
}

phStatus16_t phhalTda_Activation( void * phhalCt_Params )
{
   volatile uint32_t i;
   phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
   phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

   /* RESET low */
   PH_HAL_CT_RESET_LOW;
   phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, eRSTIN, low);

   /* Set CMDVCC low for activation */
   PH_HAL_CT_CMDVCCN_LOW;
   phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, eCMDVccn, low);

   for(i=0;i<20000;i++);

   /* RESET high */
   PH_HAL_CT_RESET_HIGH;
   phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, eRSTIN, high);

   return eStatus;
}

void PN76_CT_Clock_Init( void )
{
   PN76_Sys_Hal_CT_PCRM_Init();

#if defined(NXPBUILD__PHHAL_HW_GOC_7642)
   CONFIG_GOC_BOARD_PINS;
#elif defined(NXPBUILD__PHHAL_HW_PALLAS)
   CONFIG_PALLAS_BOARD_PINS;
#endif

   PN76_Sys_Hal_CT_USB_PLL_On();
}

void phhalTda_SlotParamsInit( phhalTda_DATAParams_t * pTda_Params, phhalCt_SlotType_t Slot_type )
{
   pTda_Params->bCmdvccn = high;
   pTda_Params->bRstin = low;
   pTda_Params->bClkdiv1 = high;
   pTda_Params->bClkdiv2 = low;
   pTda_Params->bEn5v3vn = low;
   pTda_Params->bEn1v8n = high;
   pTda_Params->bChipselect = low;
   pTda_Params->bIscardPresent = low;
   pTda_Params->bIscardActive = low;
}

void phhalTda_SelectClassVcc( void * phhalCt_Params, uint8_t bVccSel )
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *) phhalCt_Params;
   phhalCt_SlotParams_t * phhalCt_SlotParams = &(phhalCt_DATAParams->phhalCt_Params[phhalCt_DATAParams->gphhalCt_SelectedSlot_t]);

   switch(bVccSel)
   {
      case PHHAL_CT_VCC1M8:
         /* Set 1V8 low */
    	   PH_HAL_CT_1V8_LOW;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e1V8N, low);
         /* Set 5V_3V high */
         PH_HAL_CT_5V3_HIGH;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e5V3VN, high);
         break;

      case PHHAL_CT_VCC3:
         /* Set 1V8 high */
    	   PH_HAL_CT_1V8_HIGH;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e1V8N, high);
         /* Set 5V_3V low */
         PH_HAL_CT_5V3_LOW;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e5V3VN, low);
         break;

      case PHHAL_CT_VCC5:
         /* Set 1V8 high */
    	   PH_HAL_CT_1V8_HIGH;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e1V8N, high);
         /* Set 5V_3V high */
         PH_HAL_CT_5V3_HIGH;
         phhalTda_SetContext(phhalCt_SlotParams->pTDAPins, e5V3VN, high);
         break;

      default:
         break;
   }
}

void phhalTda_SetContext( phhalTda_DATAParams_t * pTda_Params, phhalTda_HCPins_t pin, uint8_t state )
{
   switch(pin)
   {
      case eCMDVccn:
         pTda_Params->bCmdvccn = state;
         break;

      case eRSTIN:
         pTda_Params->bRstin = state;
         break;

      case eCLKDIV1:
         pTda_Params->bClkdiv1 = state;
         break;

      case eCLKDIV2:
         pTda_Params->bClkdiv2 = state;
         break;

      case e5V3VN:
         pTda_Params->bEn5v3vn = state;
         break;

      case e1V8N:
         pTda_Params->bEn1v8n = state;
         break;

      case eCS:
         pTda_Params->bChipselect = state;
         break;

      case eCPresent:
         pTda_Params->bIscardPresent = state;
         break;

      case eCActive:
         pTda_Params->bIscardActive = state;
         break;

      default:
         break;
   }
}

void phhalTda_GetContext( phhalTda_DATAParams_t * pTda_Params, phhalTda_HCPins_t pin, uint8_t * pstate )
{
   switch(pin)
   {
      case eCMDVccn:
         *pstate = pTda_Params->bCmdvccn;
         break;

      case eRSTIN:
         *pstate = pTda_Params->bRstin;
         break;

      case eCLKDIV1:
         *pstate = pTda_Params->bClkdiv1;
         break;

      case eCLKDIV2:
         *pstate = pTda_Params->bClkdiv2;
         break;

      case e5V3VN:
         *pstate = pTda_Params->bEn5v3vn;
         break;

      case e1V8N:
         *pstate = pTda_Params->bEn1v8n;
         break;

      case eCS:
         *pstate = pTda_Params->bChipselect;
         break;

      case eCPresent:
         *pstate = pTda_Params->bIscardPresent;
         break;

      case eCActive:
         *pstate = pTda_Params->bIscardActive;
         break;

      default:
         break;
   }
}

void phhalTda_RestoreContext(phhalTda_DATAParams_t * pTda_Params)
{
   phhalTda_HCPins_t pin;
   uint8_t state;

   for( pin = eCMDVccn; pin <= eCActive ; pin++ )
   {
      phhalTda_GetContext(pTda_Params, pin, &state);
      switch(pin)
      {
         case eCMDVccn:
            if(state == high)
            {
               PH_HAL_CT_CMDVCCN_HIGH;
            }
            else
            {
               PH_HAL_CT_CMDVCCN_LOW;
            }
            break;

         case eRSTIN:
            if(state == high)
            {
               PH_HAL_CT_RESET_HIGH;
            }
            else
            {
               PH_HAL_CT_RESET_LOW;
            }
            break;

         case eCLKDIV1:
            if(state == high)
            {
               PH_HAL_CT_CLKDIV1_HIGH;
            }
            else
            {
               PH_HAL_CT_CLKDIV1_LOW;
            }
            break;

         case eCLKDIV2:
            if(state == high)
            {
               PH_HAL_CT_CLKDIV2_HIGH;
            }
            else
            {
               PH_HAL_CT_CLKDIV2_LOW;
            }
            break;

         case e5V3VN:
            if(state == high)
            {
               PH_HAL_CT_5V3_HIGH;
            }
            else
            {
               PH_HAL_CT_5V3_LOW;
            }
            break;

         case e1V8N:
            if(state == high)
            {
               PH_HAL_CT_1V8_HIGH;
            }
            else
            {
               PH_HAL_CT_1V8_LOW;
            }
            break;

         case eCActive:
        	 if(state == high)
        	 {
        		 phhalCt_SETBITN(eUCR2X, CT_UCR2X_NOT_AUTOCONV_SHIFT);
        		 phhalCt_SETBITN(eUCR1X, CT_UCR1X_CONV_SHIFT);
        	 }
        	 break;

         case eCS:
         case eCPresent:
         default:
            break;
      }
   }
}

uint8_t phhalTda_CheckCardActive(phhalTda_DATAParams_t * pTda_Params)
{
   return pTda_Params->bIscardActive;
}

uint8_t phhalTda_CheckCardPres(phhalTda_DATAParams_t * pTda_Params)
{
   if( low == pTda_Params->bCmdvccn )
   {
       if( !PH_HAL_CT_ISCARDPRESENT )
       {
             /* Fault condition observed over slot, card already deactivated by TDA */
             pTda_Params->bIscardActive = low;
             pTda_Params->bIscardPresent = low;
       }
       else
       {
             /* card present and is in Activated state */
             pTda_Params->bIscardActive = high;
             pTda_Params->bIscardPresent = high;
       }
   }
   else
   {
       if( PH_HAL_CT_ISCARDPRESENT )
       {
             /* Card is present, this is to actually distinguish has card been extracted after fault
              *  detection or in between slot switch */
             pTda_Params->bIscardPresent = high;
             pTda_Params->bIscardActive = low;
             /* TBD if anything needs to be done to know card is in still activate state or not since
              * code will hit here after every slot switch before resume operation */
       }
       else
       {
             /* Card Removed */
             pTda_Params->bIscardActive = low;
             pTda_Params->bIscardPresent = low;
       }
   }
   return pTda_Params->bIscardPresent;
}

void phhalCT_TDAUnselect( void )
{
   ALL_TDA_CS_UNSELECT;
}

void phhalCT_TDASelect( phhalCt_SlotType_t eSlot_Index )
{
   switch(eSlot_Index)
   {
      case E_AUX_SLOT1:
         CARD_TDA1_SELECT;
         break;

      case E_AUX_SLOT2:
         CARD_TDA2_SELECT;
         break;
#if defined(NXPBUILD__PHHAL_HW_PALLAS)
      case E_AUX_SLOT3:
         CARD_TDA3_SELECT;
         break;
#endif
      default:
         break;
   }
}

#endif
