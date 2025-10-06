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
 * Contact Interface : Protocol Abstraction Layer
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
#include "phpalCt_T0.h"
#include "phpalCt_T1.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
/* ******************************************************************************************************************
 * Global Defines
 * ***************************************************************************************************************** */

/* ******************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */

typedef struct phpalCt_FactTable{
    uint8_t bFiDiValue;
    uint16_t wFactCorr;
}phpalCt_FactTable_t;

/* ******************************************************************************************************************
 * GLOBAL AND STATIC VARIABLES
 * ***************************************************************************************************************** */


/* *******************************************************************************************************************
 * Private Function Prototypes
 * *******************************************************************************************************************/
/**
 *
 *This Function is used to set the Transmission protocol to T=0 or T=1 from the upper layer
 *
 * @param[out] Slot_T1   PAL T=1 context structure pointer
 * @param[out] Slot_P    PAL protocol context structure pointer
 * @param[in]  eProtocolType   #E_PHPAL_CT_T0 or #E_PHPAL_CT_T1 to be passed from the upper layer
 *
 * @retval #PH_CT_ERR_SUCCESS   If the protocol set successfully
 * @retval #PH_CT_ERR_CT_PROTOCOL_NOT_SUPPORTED  If Unsupported protocol parameter is passed
 */
static phStatus16_t phpalCt_SetProtocol( phpalCt_DATAParams_t * phpalCt_DATAParams );

//static phStatus16_t phpalCt_ProcessActivation(phpalCt_DATAParams_t * phpalCt_DATAParams);
/* *******************************************************************************************************************
 *   Public Functions
 * *******************************************************************************************************************/

phStatus16_t phpalCt_GetConfig( phpalCt_DATAParams_t * phpalCt_DATAParams, phAppCt_Configs_t eConfig, uint8_t * const pwValue )
{
   phStatus16_t wStatus = PH_CT_ERR_SUCCESS;

   switch(eConfig)
   {
      case E_CONF_COMPLIANCE:
         *pwValue = (uint8_t)phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn;
         break;

      case E_CONF_CARD_PRESENCE:
         *pwValue = (uint8_t)phhalCt_CheckCardPres( phpalCt_DATAParams->phalDataParams );
         break;

      case E_CONF_ACTIVATION_STATE:
         *pwValue = (uint8_t)phhalCt_CheckCardActive( phpalCt_DATAParams->phalDataParams );
         break;

      case E_CONF_SELECT_SLOT:
         *pwValue = (uint8_t)phhalCt_GetSelectedSlot( phpalCt_DATAParams->phalDataParams );
         break;

      case E_CONF_PROTOCOL:
         *pwValue = (uint8_t)phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel;
         break;

      case E_CONF_IFSC:
         *pwValue = (uint8_t)phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC;
         break;

      case E_CONF_MAX_IFSD:
         *pwValue = PHPAL_CT_T1_MAX_IFSC_VAL;
         break;

      default:
         wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
         break;
   }
   return wStatus;
}

/**
 * @brief This Api is used to initialize the CT IP and is called from the upper layer
 *
 *         PH_CT_ERR_FAILED - If resetting the CP IP is unsuccessful
 */
phStatus16_t phpalCt_Init( phpalCt_DATAParams_t * phpalCt_DATAParams )
{
   phpalCt_T0_Init( phpalCt_DATAParams );
   phpalCt_T1_Init( phpalCt_DATAParams );
   phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel = E_PROTOCOL_CT_INVALID;
   phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn = TRUE;
   phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC = PHPAL_CT_DEFAULT_IFSC;
   return PH_CT_ERR_SUCCESS;
}


/**
 * Set the CT pal configurations to the desired value.
 */
phStatus16_t phpalCt_SetConfig( phpalCt_DATAParams_t * phpalCt_DATAParams, phAppCt_Configs_t eConfig, uint8_t dwValue )
{
    phStatus16_t wStatus;

    switch(eConfig)
    {
       case E_CONF_COMPLIANCE:
           if( dwValue < E_COMP_LAST )
           {
              phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn =  (uint8_t)((dwValue == E_EMVCO_ENABLE)? E_EMVCO_ENABLE: E_ISO7816_ENABLE);
              wStatus = phhalCt_SetConfig( phpalCt_DATAParams->phalDataParams, eConfig, dwValue, 0, 0 );
           }
           else
           {
              wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
           }
           break;

       case E_CONF_SELECT_SLOT:
           if(dwValue < E_AUX_LAST)
           {
              wStatus = phhalCt_SetConfig( phpalCt_DATAParams->phalDataParams, eConfig, dwValue, 0, 0 );
           }
           else
           {
              return PH_CT_ERR_INVALID_PARAMETER;
           }
           break;

       default:
           wStatus = PH_CT_ERR(INVALID_PARAMETER, HAL_CT);
    }

    return wStatus;
}


/**
 *@brief   phpalHwCt_ActivateCard, This Function does a cold reset/activate of the card for ATR reception,
 *         the API performs three iterations for different vcc selection internally.
 *
 *@param   pDataParams - Pointer to the context structure of the PAL layer
 *         dwSlotNumber - Slot number of of which the card is present and activation has to be carried out
 *@return  PH_CT_ERR_SUCCESS - If the cold activation is success and ATR is received
 *
 */
/**
 * This is helper/common function to process the ATR after cold or warm activation.
 */
phStatus16_t phpalCt_ActivateCard ( phpalCt_DATAParams_t * phpalCt_DATAParams )
{

   phStatus16_t phStatus = PH_CT_ERR_FAILED;
   uint8_t bcount = 0;
   uint8_t bActivateSequence[] = { PHHAL_CT_VCC5, PHHAL_CT_VCC3, PHHAL_CT_VCC1M8 };
   uint8_t bIFSC;
   uint8_t bSelT0;
   uint8_t bSelT1;
#if 0
   uint8_t bEarlyFlag = FALSE;
#endif

   phpalCt_DATAParams->sAtrParams.bSizeOfATRbuffer = 32;

   while( bcount < 3 )
   {
      phStatus = phhalCt_CardActivate( phpalCt_DATAParams->phalDataParams,
                                       phpalCt_DATAParams->sAtrParams.pbAtrBuffer,
                                       &(phpalCt_DATAParams->sAtrParams.bAtrReceivedLength),
                                       bActivateSequence[bcount],
                                       &bIFSC,
                                       &bSelT0,
                                       &bSelT1 );
      if( phStatus == (PH_ERR_CT_MUTE_ERROR | PH_CT_COMP_HAL_CT) )
      {
         bcount++;
      }
      else
      {
         break;
      }
   }

#if 0
   if( phpalCt_DATAParams->sProtParams.gphpalCt_BEmvEn == E_ISO7816_ENABLE )
   {
      if((phStatus == PH_CT_ERR_SUCCESS)||(phStatus == (PH_ERR_CT_EARLY_ERROR| PH_CT_COMP_HAL_CT)))
      {
          if(phStatus == (PH_ERR_CT_EARLY_ERROR| PH_CT_COMP_HAL_CT))
          {
              bEarlyFlag = TRUE;
          }

          phStatus = phpalCt_ProcessActivation( phpalCt_DATAParams );
          //PH_BREAK_ON_FAILURE(phStatus);
          if(bEarlyFlag)
          {
             phStatus = (PH_ERR_CT_EARLY_ERROR| PH_CT_COMP_HAL_CT);
          }
      }
   }
#endif

   if( (phStatus == PH_CT_ERR_SUCCESS) ||
       (phStatus == (PH_ERR_CT_CLASS_CHANGE_INDICATED | PH_CT_COMP_HAL_CT)) ||
       (phStatus == (PH_ERR_CT_EARLY_ERROR | PH_CT_COMP_HAL_CT)) ||
       (phStatus == (PH_CT_COMP_HAL_CT|PH_ERR_PPS_EXCHANGE_NOT_REQUIRED)) )
   {
      phpalCt_DATAParams->sProtParams.gphpalCt_BIFSC = bIFSC;
      if(!(bSelT0))
      {
         phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel = E_PROTOCOL_CT_T1;
      }
      else if(bSelT0 && bSelT1)
      {
         phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel = E_PROTOCOL_CT_BOTH_T0_T1;
      }
      else
      {
         phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel = E_PROTOCOL_CT_T0;
      }
      phpalCt_SetProtocol( phpalCt_DATAParams );
   }
   else if( phStatus == (PH_ERR_CT_MUTE_ERROR | PH_CT_COMP_HAL_CT) )
   {
	   phhalCt_DeactivateCard(phpalCt_DATAParams->phalDataParams);
   }
   return phStatus;
}


/**
 *
 *@brief   This Function is used to set the Transmission protocol to T=0 or T=1 from the upper layer
 *@param   bProtocolType - bProtocolType or T=0 or T=1 to be passed from the upper layer
 *
 *@return  PH_CT_ERR_SUCCESS - If the protocol set successfully
 *         PH_CT_ERR_CT_PROTOCOL_NOT_SUPPORTED - If invalid protocol parameter is passed
 */
static phStatus16_t phpalCt_SetProtocol( phpalCt_DATAParams_t * phpalCt_DATAParams )
{
    phStatus16_t eStatus = PH_CT_ERR_CT_PROTOCOL_NOT_SUPPORTED;
    do
    {
        if( (phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel != E_PROTOCOL_CT_T0) &&
            (phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel != E_PROTOCOL_CT_T1) &&
            (phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel != E_PROTOCOL_CT_BOTH_T0_T1) )
        {
            return PH_CT_ERR(CT_PROTOCOL_NOT_SUPPORTED, PAL_CT);
        }

        /**HAL API used to set the transmission protocol*/
        eStatus = phhalCt_SetTransmissionProtocol((uint8_t)(phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel));
        phpalCt_T1_Init( phpalCt_DATAParams );
    }while(0);
    return eStatus;
}

#if 0

phStatus16_t phpalCt_SetNAD(uint8_t bDADSAD)
{
    uint8_t btempDADSAD;
    uint8_t btempSADDAD;

    btempDADSAD = bDADSAD;
    btempSADDAD = (uint8_t)(((btempDADSAD &0xF0)>>4)+((btempDADSAD &0x0F)<<4));
    if (  ((btempSADDAD == btempDADSAD) && (bDADSAD != 0)) ||
          ((btempDADSAD & 0x88) != 0 )
       )
     {
        return PH_CT_ERR(CT_DADSAD_NOT_SUPPORTED, PAL_CT);
     }
    gphpalCt_BDadSad = btempDADSAD;
    gphpalCt_BSadDad = btempSADDAD;
    return PH_CT_ERR_SUCCESS;
}
/**
 *
 * @brief   This Api calls the appropriate APi's of the underlying protocol for a T0 or T1 related transcieve.
 * @param   pbTransmitBuff - Pointer to the transmit buffer
 * @param   dwTransmitSize - Number of the bytes to be transmitted
 * @param   pbReceiveBuff - Pointer to the receive buffer
 * @param   dwReceiveSize - Pointer to the receive buffer size
 * @return  PH_CT_ERR_INVALID_PARAMETER - If the parameters passed has any errors
 *          PH_ERR_CT_MAIN_CARD_ABSENT - If the card is absent in the main slot
 *          PH_CT_ERR_SUCCESS - If the transaction with the card is successful
 */
#endif

phStatus16_t phpalCt_Transceive( phpalCt_DATAParams_t * phpalCt_DATAParams,
                                 uint8_t* pbTransmitBuff,
                                 uint32_t dwTransmitSize,
                                 uint8_t* pbReceiveBuff,
                                 uint16_t* pwReceiveSize,
                                 phpalCt_TransceiveOption_t eOption )
{
    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    uint8_t cardinfo;
    do
    {
        if((pbTransmitBuff == NULL) || (pbReceiveBuff == NULL) || (pwReceiveSize == NULL) )
        {
           return PH_CT_ADD_COMPCODE(eStatus, PH_CT_COMP_PAL_CT);
        }

        phpalCt_GetConfig(phpalCt_DATAParams, E_CONF_CARD_PRESENCE, &cardinfo);
        if( PH_ERR_CT_MAIN_CARD_ABSENT == cardinfo )
        {
           return PH_CT_ADD_COMPCODE(PH_ERR_CT_MAIN_CARD_ABSENT, PH_CT_COMP_PAL_CT);
        }

        phpalCt_GetConfig(phpalCt_DATAParams, E_CONF_ACTIVATION_STATE, &cardinfo);
        if( PH_ERR_CT_CARD_DEACTIVATED == cardinfo )
        {
           return PH_CT_ADD_COMPCODE(PH_ERR_CT_CARD_DEACTIVATED, PH_CT_COMP_PAL_CT);
        }

        /* Reset the number of bytes received */
        *pwReceiveSize = 0;

        /* If the protocol set by the user is T=1 then call the T=1 Transceive api */
        if( phpalCt_DATAParams->sProtParams.gphpalCt_ProtSel == E_PROTOCOL_CT_T1 )
        {
            eStatus = phpalCt_T1_Transcieve_SplitChaining( phpalCt_DATAParams, pbTransmitBuff, dwTransmitSize, pbReceiveBuff,  pwReceiveSize, eOption );
        }
        else
        {
            /* Max buffer size is 261 only  and minimum size should be greater than 3 */
            if((dwTransmitSize > PHPAL_CT_MAX_APDU_SIZE_T0)  || (dwTransmitSize < PHPAL_CT_MIN_APDU_SIZE_T0))
            {
                return PH_CT_ERR(INVALID_PARAMETER,PAL_CT);
            }
            /* If the protocol set by the user is T=0 then call the T=0 Transceive api */
            eStatus = phpalCt_T0_Transcieve( phpalCt_DATAParams, pbTransmitBuff, dwTransmitSize, pbReceiveBuff,  pwReceiveSize );
        }
    }while(0);
    return eStatus;
}

#if 0

/**
 *@brief   This function is used to deinitialize the CT IP and disable the NVIC for contact interface
 *@param   void
 *@return  #PH_CT_ERR_SUCCESS If Card Deactivate is done successfully
 *@retval #PH_ERR_CT_MAIN_CARD_PRESENT If the card is absent in the slot
 */
phStatus16_t phpalCt_DeInit(void)
{
    phStatus16_t eStatus = PH_CT_ERR_INVALID_PARAMETER;
    eStatus = phpalCt_T1_DeInit();
    eStatus = phhalCt_DeInit();
    return eStatus;
}

/* *******************************************************************************************************************
 * Private Functions
 * ****************************************************************************************************************** */
/**
 * This function is used to store values for class and clock stop according to ATR.
 * @param  psAtrPALParams - points toward structure for ATR's parameter which will be use in PAL.
 * @param  bClass - points to Class which is supported by Card through atr.
 */
static phStatus16_t phpalCt_NegotiateClassClock(phhalCt_ProtocolParams_t *psAtrPALParams ,uint8_t *bClass)
{

    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    uint8_t bOfferedClass = 0x00;
    bOfferedClass = (uint8_t)(psAtrPALParams->bFlagT15TAValue & (0x3F));

   switch(bOfferedClass)
   {
       case 1:
           *bClass = PHHAL_CT_VCC5;
       break;
       case 2:
       case 3:
           *bClass = PHHAL_CT_VCC3;
       break;
       case 4:
       case 6:
       case 7:
           *bClass = PHHAL_CT_VCC1M8;
       break;
       default:
           eStatus = PH_CT_ERR_INVALID_PARAMETER;
       break;
   }


   return eStatus;
}

static phStatus16_t phpalCt_ProcessActivation(phpalCt_DATAParams_t * phpalCt_DATAParams)
{
    phStatus16_t eStatus = PH_CT_ERR_SUCCESS;
    eStatus = phhalCt_PPSRequestHandling( phpalCt_DATAParams->phalDataParams );
    /* Wait atleast 10 etu for not violating BGT */
    phUser_Wait(1000);
    return eStatus;
}

#endif /* defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS) */
#endif
