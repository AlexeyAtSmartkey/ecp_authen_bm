/*----------------------------------------------------------------------------*/
/* Copyright 2024 NXP                                                         */
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
* SAM (Secure Access Module) implementation for Reader Library
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#include <ph_Status.h>
#include <phbalReg.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PHBAL_REG_SAM

#include "phbalReg_Sam.h"
#include "TDA/phbalReg_Sam_TDA.h"
	

phStatus_t phbalReg_Sam_Init(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wSizeOfDataParams, void * pLowerBalDataParams,
    uint8_t * pAtrBuffer, uint16_t wAtrBufSize, uint8_t * pTxBuffer, uint16_t wTxBufSize, uint8_t * pRxBuffer, uint16_t wRxBufSize)
{
    if(sizeof(phbalReg_Sam_DataParams_t) != wSizeOfDataParams)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_BAL);
    }

    /* Verify buffer sizes */
    if((wAtrBufSize == 0) || (wTxBufSize == 0) || (wRxBufSize == 0))
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_BAL);
    }

    PH_ASSERT_NULL_DATA_PARAM(pDataParams, PH_COMP_BAL);
    PH_ASSERT_NULL_PARAM(pLowerBalDataParams, PH_COMP_BAL);
    PH_ASSERT_NULL_PARAM(pAtrBuffer, PH_COMP_BAL);
    PH_ASSERT_NULL_PARAM(pTxBuffer, PH_COMP_BAL);
    PH_ASSERT_NULL_PARAM(pRxBuffer, PH_COMP_BAL);

    /* Initialize the data parameters to default values */
    pDataParams->wId = PH_COMP_BAL | PHBAL_REG_SAM_ID;
    pDataParams->pLowerBalDataParams = pLowerBalDataParams;
    pDataParams->pAtrBuffer = pAtrBuffer;
    pDataParams->wMaxAtrBufSize = wAtrBufSize;
    pDataParams->pTxBuffer = pTxBuffer;
    pDataParams->wTxBufSize = wTxBufSize;
    pDataParams->pRxBuffer = pRxBuffer;
    pDataParams->wRxBufSize = wRxBufSize;

    pDataParams->bCommType = PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA;
    pDataParams->bIsPortOpened = PH_OFF;

    pDataParams->bI2C_BitRate = PHBAL_REG_SAM_CONFIG_BITRATE_FAST_MODE;

    /* Reset ATR length */
    (void) memset(pDataParams->pAtrBuffer, 0x0U, pDataParams->wMaxAtrBufSize);
    pDataParams->wAtrBufSize = 0x00;

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

phStatus_t phbalReg_Sam_GetPortList(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wPortBufSize, uint8_t * pPortNames,
    uint16_t * pNumOfPorts)
{
	PH_UNUSED_VARIABLE(pDataParams);
	PH_UNUSED_VARIABLE(wPortBufSize);
	PH_UNUSED_VARIABLE(pPortNames);
	PH_UNUSED_VARIABLE(pNumOfPorts);

    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_BAL);
}

phStatus_t phbalReg_Sam_SetPort(phbalReg_Sam_DataParams_t * pDataParams, uint8_t * pPortName)
{
	PH_UNUSED_VARIABLE(pDataParams);
	PH_UNUSED_VARIABLE(pPortName);

    return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_BAL);
}

phStatus_t phbalReg_Sam_OpenPort(phbalReg_Sam_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* Port should be closed */
    if(pDataParams->bIsPortOpened != PH_OFF)
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_BAL);
    }

    /* Reset ATR length */
    (void) memset(pDataParams->pAtrBuffer, 0x00U, pDataParams->wMaxAtrBufSize);
    pDataParams->wAtrBufSize = 0x00;

    /* Activate SAM */
    switch(pDataParams->bCommType)
    {
        case PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA:
            wStatus = phbalReg_Sam_ActivateSam_TDA(pDataParams);

            /* Do PPS only if not in specific mode and only if non-default values are used */
            if(wStatus == PH_ERR_SUCCESS)
            {
                wStatus = phbalReg_Sam_Pps_TDA(pDataParams);
            }
            break;

	

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_BAL);
            break;
    }

    /* Connection successfully established with SAM */
    pDataParams->bIsPortOpened = (uint8_t) (wStatus == PH_ERR_SUCCESS);

    return wStatus;
}

phStatus_t phbalReg_Sam_ClosePort(phbalReg_Sam_DataParams_t * pDataParams)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* Port should be open */
    if(pDataParams->bIsPortOpened == PH_OFF)
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_BAL);
    }

    /* Reset ATR length */
    (void) memset(pDataParams->pAtrBuffer, 0x00U, pDataParams->wMaxAtrBufSize);
    pDataParams->wAtrBufSize = 0x00;

    /* Card is now closed */
    pDataParams->bIsPortOpened = PH_OFF;

    /* De-Activate SAM */
    switch(pDataParams->bCommType)
    {
        case PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA:
            wStatus = phbalReg_Sam_DeActivateSam_TDA(pDataParams);
            break;

	

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_BAL);
            break;
    }

    return wStatus;
}

phStatus_t phbalReg_Sam_Exchange(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wOption, uint8_t * pTxBuffer,
    uint16_t wTxBufLen, uint16_t wRxBufSize, uint8_t * pRxBuffer, uint16_t * pRxBufLen)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* Check options */
    if(wOption != PH_EXCHANGE_DEFAULT)
    {
        return PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_BAL);
    }

    /* Port should be open */
    if(pDataParams->bIsPortOpened == PH_OFF)
    {
        return PH_ADD_COMPCODE(PH_ERR_USE_CONDITION, PH_COMP_BAL);
    }

    /* Check if TxBuffer is big enough */
    if(pDataParams->wTxBufSize < (2 + wTxBufLen))
    {
        return PH_ADD_COMPCODE(PH_ERR_BUFFER_OVERFLOW, PH_COMP_BAL);
    }

    /* Reset receive length */
    *pRxBufLen = 0;

    /* Perform SAM Exchange*/
    switch(pDataParams->bCommType)
    {
        case PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA:
            wStatus = phbalReg_Sam_TransmitData_TDA(pDataParams, pTxBuffer, wTxBufLen, wRxBufSize, pRxBuffer, pRxBufLen);
            break;

	

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_BAL);
            break;
    }

    return wStatus;
}

phStatus_t phbalReg_Sam_SetConfig(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wConfig, uint16_t wValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* Set Success status */
    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);

    switch(wConfig)
    {
        case PHBAL_REG_SAM_CONFIG_COMMUNICATION_TYPE:
            if((wValue != PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA) && (wValue != PHBAL_REG_SAM_COMMUNICATION_TYPE_TDA))
            {
                wStatus = PH_ADD_COMPCODE(PH_ERR_INVALID_PARAMETER, PH_COMP_BAL);
            }
            else
            {
                pDataParams->bCommType = (uint8_t) wValue;
            }
            break;

	

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
            break;
    }

    return wStatus;
}

phStatus_t phbalReg_Sam_GetConfig(phbalReg_Sam_DataParams_t * pDataParams, uint16_t wConfig, uint16_t * pValue)
{
    phStatus_t  PH_MEMLOC_REM wStatus;

    /* Set Success status */
    wStatus = PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);

    switch(wConfig)
    {
        case PHBAL_REG_SAM_CONFIG_COMMUNICATION_TYPE:
            *pValue = pDataParams->bCommType;
            break;

	

        default:
            wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_BAL);
            break;
    }

    return PH_ADD_COMPCODE(PH_ERR_SUCCESS, PH_COMP_BAL);
}

#endif /* NXPBUILD__PHBAL_REG_SAM */
