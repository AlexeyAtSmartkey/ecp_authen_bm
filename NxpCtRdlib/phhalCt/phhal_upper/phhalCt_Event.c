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
 * CT RTOS event mechanism.
 *
 * Project:
 *
 * $Date$
 * $Author$
 * $Revision$
 */



/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include <stdio.h>
#include "ph_Datatypes.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "phhalCt.h"

/* Event Based Functionality. */
#include "phhalCt_Event.h"
#include "phOsal.h"

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

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */


/* *****************************************************************************************************************
 * Private Functions
 * ***************************************************************************************************************** */


/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */

phStatus16_t phhalCt_Event_Init(void * phhalCt_Params)
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;
   return phOsal_EventCreate( &(phhalCt_DATAParams->HwEventObj.EventHandle), &(phhalCt_DATAParams->HwEventObj) );
}

phStatus16_t phhalCt_Event_WaitAny( void * phhalCt_Params,
                                  phhalCt_EventType_t eEventType,
                                  uint32_t dwTimeout,
                                  uint32_t fConsume )
{
	phStatus16_t eStatus = PH_CT_ERR_FAILED;
    uint32_t xbits = 0;
    phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;
    phhalCt_EventType_t * pRcvdEvt = &(phhalCt_DATAParams->gphhalCt_InEvent);

    if (phhalCt_DATAParams->HwEventObj.EventHandle == NULL) /* In case it is not initialized yet */
        return PH_CT_ERR(FAILED,HAL_CT);

    /* Clear the Events */
    if (fConsume == TRUE)
    {
        eStatus = phhalCt_Event_Consume(phhalCt_DATAParams, eEventType);
    }

    /* Don't Clear flags after ISR and Wait for any bits to be Set */
    phOsal_EventPend( &(phhalCt_DATAParams->HwEventObj.EventHandle), E_OS_EVENT_OPT_NONE, dwTimeout, (uint32_t)eEventType, (phOsal_EventBits_t *)&xbits );
    if( (xbits & ((uint32_t)eEventType)) != 0 )
    {
        /* Return the Events That were Set */
        *pRcvdEvt = (phhalCt_EventType_t) xbits;
        eStatus = PH_CT_ERR_SUCCESS;
    }
    else
    {
        eStatus = PH_CT_ERR_OPERATION_TIMEDOUT;
    }

    return PH_CT_ADD_COMPCODE(eStatus,PH_CT_COMP_HAL_CT);
}
/**
 *
 * @param eEventType
 * @return
 */
phStatus16_t  phhalCt_Event_Post( void * phhalCt_Params, phhalCt_EventType_t eEventType )
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;

   if( phhalCt_DATAParams->HwEventObj.EventHandle == NULL )    /* In case it is not initialized yet */
     return PH_CT_ERR(INVALID_PARAMETER,HAL_CT);

   phOsal_EventPost( &(phhalCt_DATAParams->HwEventObj.EventHandle),E_OS_EVENT_OPT_NONE, (uint32_t)eEventType, NULL );
   return PH_CT_ERR_SUCCESS;
}

phStatus16_t  phhalCt_Event_Consume( void * phhalCt_Params, phhalCt_EventType_t eEventType)
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;

   phOsal_EventClear( &(phhalCt_DATAParams->HwEventObj.EventHandle), E_OS_EVENT_OPT_NONE, (uint32_t)eEventType, NULL );
   return PH_CT_ERR_SUCCESS;
}

phStatus16_t phhalCt_Event_Deinit(void * phhalCt_Params)
{
   phhalCt_DATAParams_t * phhalCt_DATAParams = (phhalCt_DATAParams_t *)phhalCt_Params;

   /* Delete the Event Group */
   phOsal_EventDelete( &(phhalCt_DATAParams->HwEventObj.EventHandle) );
   return PH_CT_ERR_SUCCESS;
}

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */
