/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                    */
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
* Internal functions for PN76xx HAL.
*
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/

#include <phhalHw.h>
#include <ph_RefDefs.h>
#include <ph_Status.h>

#ifdef NXPBUILD__PHHAL_HW_PN76XX
#include <phTools.h>
#include <phTools.h>
#include "phhalHw_PN76xx.h"
#include "phhalHw_PN76xx_Int.h"
#include "PN76_Reg_Interface.h"
#include "Clif_Reg.h"
#include "Clif.h"

#define PHHAL_HW_15693_26KBPS                               (0x00000000)
#define PHHAL_HW_15693_53KBPS                               (0x00000020)
#define PHHAL_HW_15693_106KBPS                              (0x00000040)
#define PHHAL_HW_15693_212KBPS                              (0x00000060)

#define CLIF_SIGPRO_RM_ENABLES_RM_OOK_COL_LOW_SLOPE_MASK    (0x00018000UL)
#define CLIF_SIGPRO_RM_ENABLES_REG_PROTOCOL_INDEX           (0x8U)
#define RETRIEVE_RF_CONFIG_REG_VALUE_PAIR_LENGTH            (0x5U)

phStatus_t phhalHw_Pn76xx_Int_GetTxBuffer(
                                          phhalHw_Pn76xx_DataParams_t * pDataParams,
                                          uint8_t ** pTxBuffer,
                                          uint16_t * pTxBufferLen,
                                          uint16_t * pTxBufferSize
                                          )
{
    /* We need to watch that we do not overwrite content below the RxStartPos though. */
    if (pDataParams->pTxBuffer == (pDataParams->pRxBuffer))
    {
        *pTxBuffer = &pDataParams->pTxBuffer[pDataParams->wRxBufStartPos];
        *pTxBufferSize = pDataParams->wTxBufSize - pDataParams->wRxBufStartPos;
    }
    /* Else just return the actual Buffer. */
    else
    {
        *pTxBuffer = pDataParams->pTxBuffer;
        *pTxBufferSize = pDataParams->wTxBufSize;
    }

    /* Return stored length. */
    *pTxBufferLen = pDataParams->wTxBufLen;

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_GetRxBuffer(
                                          phhalHw_Pn76xx_DataParams_t * pDataParams,
                                          uint8_t ** pRxBuffer,
                                          uint16_t * pRxBufferLen,
                                          uint16_t * pRxBufferSize
                                          )
{
    uint8_t PH_MEMLOC_REM bOffset = 0U;

#ifndef NXPBUILD__PHHAL_HW_PN76XX_ENABLE_P2P
    if ((pDataParams->bActiveMode != PH_ON) && (pDataParams->bNfcipMode == PH_ON))
    {
        bOffset = 1U;
    }
#endif
    /* Update out parameters */
    *pRxBuffer = &pDataParams->pRxBuffer[pDataParams->wRxBufStartPos - bOffset];
    *pRxBufferSize = pDataParams->wRxBufSize - pDataParams->wRxBufStartPos - bOffset;
    *pRxBufferLen = pDataParams->wRxBufLen;

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_TimerStart(
                                         phhalHw_Pn76xx_DataParams_t * pDataParams,
                                         uint32_t wPrescaler,
                                         uint32_t dwLoadValue
                                         )
{
    phStatus_t  PH_MEMLOC_REM  status;
    uint32_t    PH_MEMLOC_REM  dwTemp;

    /* write 0 to stop timer */
    dwTemp = 0U;

    PH_CHECK_SUCCESS_FCT(status, CLIF_SETREG(CLIF_TIMER1_CONFIG, dwTemp));

    /* load the timer  reload value */
    dwTemp = (dwLoadValue & CLIF_TIMER1_RELOAD_T1_RELOAD_VALUE_MASK);
    PH_CHECK_SUCCESS_FCT(status, CLIF_SETREG(CLIF_TIMER1_RELOAD, dwTemp));

    /* Timer MODE_SEL is defined by ePrescaler, 0x01U enables the timer */
    dwTemp = (CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK | CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK |
              wPrescaler | CLIF_TIMER1_CONFIG_T1_ENABLE_MASK );
    PH_CHECK_SUCCESS_FCT(status, CLIF_SETREG(CLIF_TIMER1_CONFIG, dwTemp));

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_SetConfig_Int(
                                        phhalHw_Pn76xx_DataParams_t * pDataParams,
                                        uint16_t wConfig,
                                        uint16_t wValue
                                        )
{
    phStatus_t  PH_MEMLOC_REM statusTmp = 0U;
    uint32_t    PH_MEMLOC_REM dwValue = 0U;
    uint32_t    PH_MEMLOC_REM dwTemp = 0U;
    float32_t   PH_MEMLOC_REM fTime = 0.0;
    uint8_t     PH_MEMLOC_REM aRetrieveRfConfig[PN76_MIN_RF_CONFIGURATION_BUFFER_SIZE] = {0};
    uint16_t    PH_MEMLOC_REM wRxLength = sizeof(aRetrieveRfConfig);
    uint8_t     PH_MEMLOC_REM bRxRMEn_Offset = CLIF_SIGPRO_RM_ENABLES_REG_PROTOCOL_INDEX * RETRIEVE_RF_CONFIG_REG_VALUE_PAIR_LENGTH;

    switch(wConfig)
    {
    case PHHAL_HW_CONFIG_PARITY:

        /* Tx-Parity,  Rx-Parity is OFF */
        if (wValue == PH_OFF)
        {
            dwValue = (uint32_t)~(uint32_t)CLIF_TX_FRAME_CONFIG_TX_PARITY_ENABLE_MASK;
            /* Perform write */
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_TX_FRAME_CONFIG, dwValue));

            dwValue = (uint32_t)~(uint32_t)CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_ENABLE_MASK;
            /* Perform write */
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_RX_PROTOCOL_CONFIG, dwValue));
        }
        else
        {
            /* Turn ON Tx-Parity */
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(CLIF_TX_FRAME_CONFIG, CLIF_TX_FRAME_CONFIG_TX_PARITY_ENABLE_MASK));

            /* Turn ON Rx-Parity */
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(CLIF_RX_PROTOCOL_CONFIG, CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_ENABLE_MASK));
        }

        break;

    case PHHAL_HW_CONFIG_TXCRC:

        if (wValue == PH_OFF)
        {
            /* CRC calculator, your services are not required */
            dwValue = (uint32_t)~(uint32_t)CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK;

            /* Perform write */
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_CRC_TX_CONFIG, dwValue));

            if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443A)
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, PN76_Clif_RetrieveRfConfiguration(
                    E_PN76_LOADRF_RX_ISO14443A_106,
                    &aRetrieveRfConfig[0],
                    &wRxLength));

                if (aRetrieveRfConfig[bRxRMEn_Offset++] == CLIF_SIGPRO_RM_ENABLES)
                {
                    dwValue = aRetrieveRfConfig[bRxRMEn_Offset++];
                    dwValue |= (aRetrieveRfConfig[bRxRMEn_Offset++] << 8U);
                    dwValue |= (aRetrieveRfConfig[bRxRMEn_Offset++] << 16U);
                    dwValue |= (aRetrieveRfConfig[bRxRMEn_Offset++] << 24U);

                    PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(
                        CLIF_SIGPRO_RM_ENABLES,
                        (dwValue & CLIF_SIGPRO_RM_ENABLES_RM_OOK_COL_LOW_SLOPE_MASK)));
                }
            }
        }
        else
        {
            /* Clear the Bits */
            dwTemp = (uint32_t) ~( CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK);
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_CRC_TX_CONFIG, dwTemp));

            /* Set the new value */
            dwTemp = (uint32_t)(CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK);
            /* If the card type is other than I18000p3m3, operate the CRC in 16-bit mode */
            if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_I18000P3M3)
            {
                /* Just set the bit for 5-bit mode operation */
                dwTemp |= (uint32_t)CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK;
            }

            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(CLIF_CRC_TX_CONFIG, dwTemp));

            if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443A)
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_SIGPRO_RM_ENABLES, (uint32_t)(~CLIF_SIGPRO_RM_ENABLES_RM_OOK_COL_LOW_SLOPE_MASK)));
            }
        }
        break;

    case PHHAL_HW_CONFIG_RXCRC:

        if (wValue == PH_OFF)
        {
            /* CRC calculator, your services are not required */
            dwValue = (uint32_t)~(uint32_t)CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK;

            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_CRC_RX_CONFIG, dwValue));
        }
        else
        {
            /* Clear the Bits */
            dwTemp = (uint32_t) ~( CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK);
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_CRC_RX_CONFIG, dwTemp));

            /* Set the new value */
            dwTemp = (uint32_t)CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK;
            /* If the card type is other than I18000p3m3, operate the CRC in 16-bit mode */
            if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_I18000P3M3)
            {
                /* Just set the bit for 5-bit mode operation */
                dwTemp |= (uint32_t)CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK;
            }

            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(CLIF_CRC_RX_CONFIG, dwTemp));
        }
        break;

    case PHHAL_HW_CONFIG_ASK100:
        if(PHHAL_HW_CARDTYPE_ISO15693 == pDataParams->bCardType )
        {
            /* switch off 100% ASK */
            if (wValue == PH_OFF)
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK10, E_PN76_LOADRF_RX_NO_CHANGE));
            }
            /* switch on 100% ASK */
            else
            {
                PH_CHECK_SUCCESS_FCT(statusTmp, PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK100, E_PN76_LOADRF_RX_NO_CHANGE));
            }
        }
        break;

    case PHHAL_HW_CONFIG_RXWAIT_US:
        /* Set Rx Wait(deaf) bits */
        dwValue = PHHAL_HW_PN76XX_TR_RX_PRESCALAR;
        dwTemp = wValue;
        if(0U != dwTemp)
        {
            fTime = (float32_t)(((float32_t)dwTemp * 13.56) / (float32_t)(dwValue));
            dwTemp = (uint32_t)fTime;
            dwValue |= (uint32_t)dwTemp << CLIF_RX_WAIT_RX_WAIT_VALUE_POS;
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG(CLIF_RX_WAIT, dwValue ));
        }
        else
        {
            PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG(CLIF_RX_WAIT, dwValue ));
        }
        break;
    }

    return PH_ERR_SUCCESS;
}


phStatus_t phhalHw_Pn76xx_Int_SetCardMode(
                                          phhalHw_Pn76xx_DataParams_t * pDataParams,
                                          uint16_t wTxDataRate,
                                          uint16_t wRxDataRate,
                                          uint16_t wSubcarrier
                                          )
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t     PH_MEMLOC_REM bTxConfig = 0U;
    uint8_t     PH_MEMLOC_REM bRxConfig = 0U;

    if(pDataParams->wTargetMode == PH_OFF)
    {
        if(wTxDataRate == pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXDATARATE_FRAMING])
        {
            wTxDataRate = PHHAL_HW_RF_DATARATE_NO_CHANGE;
        }
        if(wRxDataRate == pDataParams->wCfgShadow[PHHAL_HW_CONFIG_RXDATARATE_FRAMING])
        {
            wRxDataRate = PHHAL_HW_RF_DATARATE_NO_CHANGE;
        }
    }

/*
 * In Reader/initiator mode bCardType is set as part fo apply protocol setting and during PSL/PPS bCardType updated.
 * In Passive Card/Target mode bCardType is set to NONE/UNKNOWN in autocoll and is updated during PSL/PPS.
 * In Active Target mode bCardType is set to NONE/UNKNOWN in autocoll, hence below check has been added to hanlde it.
 * NOTE: Active mode Proprietary Baudrate communication is not handled.
 * */

    {
       switch (pDataParams->bCardType)
       {
       case PHHAL_HW_CARDTYPE_ISO14443A:

           /* Check if Target is activated and perform required change to switch BaudRate. */
           if (pDataParams->wTargetMode != PH_OFF)
           {
               switch (wTxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_106:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_PICC_106_MANCH_SUBC;
                   break;
               case PHHAL_HW_RF_DATARATE_212:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_PICC_212_BPSK;
                   break;
               case PHHAL_HW_RF_DATARATE_424:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_PICC_424_BPSK;
                   break;
               case PHHAL_HW_RF_DATARATE_848:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_PICC_848_BPSK;
                   break;
               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;
               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }

               switch (wRxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_106:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_PICC_106_MILLER;
                   break;
               case PHHAL_HW_RF_DATARATE_212:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_PICC_212_MILLER;
                   break;
               case PHHAL_HW_RF_DATARATE_424:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_PICC_424_MILLER;
                   break;
               case PHHAL_HW_RF_DATARATE_848:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_PICC_848_MILLER;
                   break;
               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;
               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }
           }
           else
           {
               switch (wTxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_106:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_106;
                   break;
               case PHHAL_HW_RF_DATARATE_212:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_212;
                   break;
               case PHHAL_HW_RF_DATARATE_424:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_424;
                   break;
               case PHHAL_HW_RF_DATARATE_848:
                   bTxConfig = E_PN76_LOADRF_TX_ISO14443A_848;
                   break;
               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;
               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }
               switch (wRxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_106:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_106;
                   break;
               case PHHAL_HW_RF_DATARATE_212:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_212;
                   break;
               case PHHAL_HW_RF_DATARATE_424:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_424;
                   break;
               case PHHAL_HW_RF_DATARATE_848:
                   bRxConfig = E_PN76_LOADRF_RX_ISO14443A_848;
                   break;
               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;
               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }
           }
           break;

       case PHHAL_HW_CARDTYPE_ISO14443B:

           switch (wTxDataRate)
           {
           case PHHAL_HW_RF_DATARATE_106:
               bTxConfig = E_PN76_LOADRF_TX_ISO14443B_106;
               break;
           case PHHAL_HW_RF_DATARATE_212:
               bTxConfig = E_PN76_LOADRF_TX_ISO14443B_212;
               break;
           case PHHAL_HW_RF_DATARATE_424:
               bTxConfig = E_PN76_LOADRF_TX_ISO14443B_424;
               break;
           case PHHAL_HW_RF_DATARATE_848:
               bTxConfig = E_PN76_LOADRF_TX_ISO14443B_848;
               break;
           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;
           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }

           switch (wRxDataRate)
           {
           case PHHAL_HW_RF_DATARATE_106:
               bRxConfig = E_PN76_LOADRF_RX_ISO14443B_106;
               break;
           case PHHAL_HW_RF_DATARATE_212:
               bRxConfig = E_PN76_LOADRF_RX_ISO14443B_212;
               break;
           case PHHAL_HW_RF_DATARATE_424:
               bRxConfig = E_PN76_LOADRF_RX_ISO14443B_424;
               break;
           case PHHAL_HW_RF_DATARATE_848:
               bRxConfig = E_PN76_LOADRF_RX_ISO14443B_848;
               break;
           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;
           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }
           break;

       case PHHAL_HW_CARDTYPE_FELICA_212:
       case PHHAL_HW_CARDTYPE_FELICA_424:
           {
               switch (wTxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_212:
                   bTxConfig = E_PN76_LOADRF_TX_FELICA_212;
                   break;

               case PHHAL_HW_RF_DATARATE_424:
                   bTxConfig = E_PN76_LOADRF_TX_FELICA_424;
                   break;

               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;

               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }

               switch (wRxDataRate)
               {
               case PHHAL_HW_RF_DATARATE_212:
                   bRxConfig = E_PN76_LOADRF_RX_FELICA_212;
                   break;

               case PHHAL_HW_RF_DATARATE_424:
                   bRxConfig = E_PN76_LOADRF_RX_FELICA_424;
                   break;

               case PHHAL_HW_RF_DATARATE_NO_CHANGE:
                   bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
                   break;

               default:
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }

           }
           break;

       case PHHAL_HW_CARDTYPE_ISO15693:
           switch (wTxDataRate)
           {
           case PHHAL_HW_RF_TX_DATARATE_1_OUT_OF_4:
               bTxConfig = E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK10;
               break;

           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;

           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }

           switch (wRxDataRate)
           {
           case PHHAL_HW_RF_RX_DATARATE_LOW:
               bRxConfig = E_PN76_LOADRF_RX_ISO15693_6P6_SC;
               break;

           case PHHAL_HW_RF_RX_DATARATE_HIGH:
               bRxConfig = E_PN76_LOADRF_RX_ISO15693_26_SC;
               break;

           case PHHAL_HW_RF_RX_DATARATE_FAST_HIGH:
               bRxConfig = E_PN76_LOADRF_RX_ISO15693_53_SC;
               break;

           case PHHAL_HW_RF_DATARATE_106:
               bRxConfig = E_PN76_LOADRF_RX_ISO15693_106;
               break;

           case PHHAL_HW_RF_DATARATE_212:
               bRxConfig = E_PN76_LOADRF_RX_ISO15693_212;
               break;

           case PHHAL_HW_RF_RX_DATARATE_FAST_LOW:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);

           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;

           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }
           break;

#ifdef NXPBUILD__PHHAL_HW_PN7642
        case PHHAL_HW_CARDTYPE_I18000P3M3:
           switch (wTxDataRate)
           {
           case PHHAL_HW_RF_TX_DATARATE_I18000P3M3:
               /* Subcarrier check */
               if ((wSubcarrier != PHHAL_HW_SUBCARRIER_DUAL) &&
                   (wSubcarrier != PHHAL_HW_SUBCARRIER_QUAD))
               {
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }
               bTxConfig = E_PN76_LOADRF_TX_ISO180003M3_TARI_9_44_ASK;
               break;

           case PHHAL_HW_RF_TX_DATARATE_I18000P3M3_TARI1888:
               /* Subcarrier check */
               if ((wSubcarrier != PHHAL_HW_SUBCARRIER_DUAL) &&
                   (wSubcarrier != PHHAL_HW_SUBCARRIER_QUAD))
               {
                   return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
               }
               bTxConfig = E_PN76_LOADRF_TX_ISO180003M3_TARI_18_88_ASK;
               break;

           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bTxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;

           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }

           switch (wRxDataRate)
           {
           case PHHAL_HW_RX_I18000P3M3_FL_423_MAN2:
               bRxConfig = E_PN76_LOADRF_RX_ISO180003M3_MANCH424_2_PERIOD;
               break;
           case PHHAL_HW_RX_I18000P3M3_FL_423_MAN4:
               bRxConfig = E_PN76_LOADRF_RX_ISO180003M3_MANCH424_4_PERIOD;
               break;
           case PHHAL_HW_RX_I18000P3M3_FL_847_MAN2:
               bRxConfig = E_PN76_LOADRF_RX_ISO180003M3_MANCH848_2_PERIOD;
               break;
           case PHHAL_HW_RX_I18000P3M3_FL_847_MAN4:
               bRxConfig = E_PN76_LOADRF_RX_ISO180003M3_MANCH848_4_PERIOD;
               break;
           case PHHAL_HW_RF_DATARATE_NO_CHANGE:
               bRxConfig = PHHAL_HW_RF_DATARATE_NO_CHANGE;
               break;
           default:
               return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
           }
           break;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */


       case PHHAL_HW_CARDTYPE_ICODEEPCUID:
       default:
           return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
       }
    }

    if((PHHAL_HW_RF_DATARATE_NO_CHANGE != bTxConfig) || (PHHAL_HW_RF_DATARATE_NO_CHANGE != bRxConfig))
    {
        PH_CHECK_SUCCESS_FCT(statusTmp,
            PN76_Clif_LoadRfConfiguration(
            (PN76_Clif_TxConfig_t) bTxConfig,
            (PN76_Clif_RxConfig_t) bRxConfig ));
    }

    /* If Datarate is changed, then Update Data-rate in shadow for parity setting */
    if(wTxDataRate != PHHAL_HW_RF_DATARATE_NO_CHANGE)
    {
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXDATARATE_FRAMING] = wTxDataRate;
    }
    if(wRxDataRate != PHHAL_HW_RF_DATARATE_NO_CHANGE)
    {
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_RXDATARATE_FRAMING] = wRxDataRate;
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_SetTxDataRateFraming(
                                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                   uint16_t wConfig,
                                                   uint16_t wValue
                                                   )
{
    uint16_t   PH_MEMLOC_REM wFraming = 0U;
    phStatus_t PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;

    if ((pDataParams->wCfgShadow[wConfig] & PHHAL_HW_RF_DATARATE_OPTION_MASK) != (wValue & PHHAL_HW_RF_DATARATE_OPTION_MASK))
    {
        /* Update the framing, based on the Higher byte */
        wFraming = wValue & PHHAL_HW_RF_FRAMING_OPTION_MASK;
        wFraming = wFraming >> 0x08U;

        if((wFraming != PHHAL_HW_CARDTYPE_CURRENT) && (wFraming != pDataParams->bCardType))
        {
            if((wValue & PHHAL_HW_RF_FRAMING_OPTION_MASK) != PHHAL_HW_RF_TYPE_ACTIVE_FRAMING)
            {
                pDataParams->bCardType = (uint8_t)wFraming;
            }
        }

        /* Update the Baudrate based on the lower byte */
        wValue = wValue & PHHAL_HW_RF_DATARATE_OPTION_MASK;

        if(pDataParams->bCardType != PHHAL_HW_CARDTYPE_ISO15693)
        {
            /* Evaluate hardware settings */
            PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_Int_SetCardMode(
                pDataParams,
                wValue,
                PHHAL_HW_RF_DATARATE_NO_CHANGE,
                pDataParams->wCfgShadow[PHHAL_HW_CONFIG_SUBCARRIER]));
        }

        if(pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO15693)
        {
            if(wValue == PHHAL_HW_RF_TX_DATARATE_1_OUT_OF_4)
            {
                /* clear the 15693 datarate mask */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~SYSTEM_CONFIG_15693_CHANGE_DATARATE_MASK)));
                /* set the value */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(SYSTEM_CONFIG, (uint32_t)(PHHAL_HW_15693_26KBPS)));

                PH_CHECK_SUCCESS_FCT(statusTmp, PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK100, E_PN76_LOADRF_RX_ISO15693_26_SC));
            }
            else if(wValue == PHHAL_HW_RF_I15693_53KBPS_DATARATE)
            {
                /* clear the 15693 datarate mask */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~SYSTEM_CONFIG_15693_CHANGE_DATARATE_MASK)));
                /* set the value */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(SYSTEM_CONFIG, (uint32_t)(PHHAL_HW_15693_53KBPS)));
            }
            else if(wValue == PHHAL_HW_RF_DATARATE_106)
            {
                /* clear the 15693 datarate mask */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~SYSTEM_CONFIG_15693_CHANGE_DATARATE_MASK)));
                /* set the value */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(SYSTEM_CONFIG, (uint32_t)(PHHAL_HW_15693_106KBPS)));
            }
            else if(wValue == PHHAL_HW_RF_DATARATE_212)
            {
                /* clear the 15693 datarate mask */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~SYSTEM_CONFIG_15693_CHANGE_DATARATE_MASK)));
                /* set the value */
                PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(SYSTEM_CONFIG, (uint32_t)(PHHAL_HW_15693_212KBPS)));
            }
            else
            {
                /* To avoid the warning */
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);    /* return the invalid parameter */
            }
        }

        /* Write config data into shadow */
        pDataParams->wCfgShadow[wConfig] = (wValue | (wFraming << 0x08U)) ;
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_SetRxDataRateFraming(
                                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                   uint16_t wConfig,
                                                   uint16_t wValue
                                                   )
{
    uint16_t   PH_MEMLOC_REM wFraming = 0U;
    phStatus_t PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;

    if ((pDataParams->wCfgShadow[wConfig] & PHHAL_HW_RF_DATARATE_OPTION_MASK) != (wValue & PHHAL_HW_RF_DATARATE_OPTION_MASK))
    {
        /* Update teh framing, based on the Higher byte */
        wFraming = wValue & PHHAL_HW_RF_FRAMING_OPTION_MASK;
        wFraming = wFraming >> 0x08U;

        if((wFraming != PHHAL_HW_CARDTYPE_CURRENT) && (wFraming != pDataParams->bCardType))
        {
            if((wValue & PHHAL_HW_RF_FRAMING_OPTION_MASK) != PHHAL_HW_RF_TYPE_ACTIVE_FRAMING)
            {
                pDataParams->bCardType = (uint8_t)wFraming;
            }
        }

        /* Update the Baudrate based on the lower byte */
        wValue = wValue & PHHAL_HW_RF_DATARATE_OPTION_MASK;

        /* Evaluate hardware settings */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_Int_SetCardMode(
            pDataParams,
            PHHAL_HW_RF_DATARATE_NO_CHANGE,
            wValue,
            pDataParams->wCfgShadow[PHHAL_HW_CONFIG_SUBCARRIER]));

        /* Write config data into shadow */
        pDataParams->wCfgShadow[wConfig] = (wValue | (wFraming << 0x08U));
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_SetMinFdt(
                                        phhalHw_Pn76xx_DataParams_t * pDataParams,
                                        uint16_t wValue
                                        )
{
    phStatus_t PH_MEMLOC_REM statusTmp = 0U;
    uint16_t   PH_MEMLOC_REM wTimer = 0U;
    uint16_t   PH_MEMLOC_REM wTxRate = 0U;

    if (wValue == PH_ON)
    {
        /* Get current timeout value */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_GetConfig(
            pDataParams,
            PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS,
            &wTimer));

        /* Backup current value */
        pDataParams->dwFdtPc = wTimer;

        /* Get current data rate */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_GetConfig(
            pDataParams,
            PHHAL_HW_CONFIG_TXDATARATE_FRAMING,
            &wTxRate));

        /* Select timeout value based on data rate */
        switch(wTxRate & PHHAL_HW_RF_DATARATE_OPTION_MASK)
        {
            case PHHAL_HW_RF_DATARATE_106:
                wTimer = PHHAL_HW_MINFDT_106_US;
                break;

            case PHHAL_HW_RF_DATARATE_212:
                wTimer = PHHAL_HW_MINFDT_212_US;
                break;

            case PHHAL_HW_RF_DATARATE_424:
                wTimer = PHHAL_HW_MINFDT_424_US;
                break;

            case PHHAL_HW_RF_DATARATE_848:
                wTimer = PHHAL_HW_MINFDT_848_US;
                break;

            default:
                break;
        }

        /* Set timeout value */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_SetConfig(
            pDataParams,
            PHHAL_HW_CONFIG_TIMEOUT_VALUE_US,
            wTimer));
    }
    else if (wValue == PH_OFF)
    {
        /* Restore the timeout value */
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_SetConfig(
            pDataParams,
            PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS,
            pDataParams->dwFdtPc));
    }
    else
    {
        /* If option is not #PH_OFF or #PH_ON */
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }
    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_Int_SetTmo(
                                     phhalHw_Pn76xx_DataParams_t *pDataParams,
                                     uint16_t wTimeout,
                                     uint8_t  bUnit
                                     )
{
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint32_t    PH_MEMLOC_REM wPrescaler;
    uint32_t    PH_MEMLOC_REM dwLoadValue;
    uint16_t    PH_MEMLOC_REM wUDigitalDelay;

    wUDigitalDelay = 0U;
    /* Parameter check */
    if ((bUnit != PHHAL_HW_TIME_MICROSECONDS) && (bUnit != PHHAL_HW_TIME_MILLISECONDS))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    if(wTimeout == 0U)
    {
        return PH_ERR_SUCCESS;
    }

    if (bUnit == PHHAL_HW_TIME_MICROSECONDS)
    {
        /* here wTimeout will be in uS */
        wPrescaler = 0x00U;
        /* Reducing the division by 2 digits to retain the 2 digit decimal places which were getting wiped out */
        dwLoadValue =(uint32_t) ( PHHAL_HW_PN76XX_MAX_FREQ / (PHHAL_HW_PN76XX_CONVERSION_US_SEC/100));
        /* Restoring the division done in the earlier step */
        dwLoadValue =(uint32_t) (((wTimeout + wUDigitalDelay) * dwLoadValue)/100);
    }
    else
    {
        wPrescaler = 0x3CU;
        if(wTimeout <= PHHAL_HW_PN76XX_MAX_TIME_DELAY_MS)
        {
            dwLoadValue =(uint32_t) (wTimeout * ( PHHAL_HW_PN76XX_MIN_FREQ / PHHAL_HW_PN76XX_CONVERSION_MS_SEC));
        }
        else
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
        }
    }

    PH_CHECK_SUCCESS_FCT(statusTmp,
        phhalHw_Pn76xx_Int_TimerStart(
        pDataParams,
        wPrescaler,
        dwLoadValue
        ));

    return PH_ERR_SUCCESS;
}


phStatus_t phhalHw_Pn76xx_Int_ClearNSetRegFields(
                                                 phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                 uint8_t bRegister,
                                                 uint32_t dwMask,
                                                 uint32_t dwPos,
                                                 uint16_t wValue
                                                 )
{
    uint32_t    PH_MEMLOC_REM dwTemp = 0U;
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;

    dwTemp = (uint32_t) ~(dwMask);

    PH_CHECK_SUCCESS_FCT(status, CLIF_CLEARREG_MASK(bRegister, dwTemp));

    dwTemp = (uint32_t) ((wValue << dwPos) & dwMask);

    PH_CHECK_SUCCESS_FCT(status, CLIF_SETREG_MASK(bRegister, dwTemp));


    return PH_ERR_SUCCESS;
}

#ifdef NXPBUILD__PHHAL_HW_PN7642
phStatus_t phhalHw_Pn76xx_Int_EpcGen2Inventory(
                                               phhalHw_Pn76xx_DataParams_t * pDataParams,
                                               uint8_t * pSelectCommand,
                                               uint8_t bSelectCommandLength,
                                               uint8_t bSelectCommandBitsInLastByte,
                                               uint8_t * pBeginRoundCommand,
                                               uint8_t bTimeslotProcessingBehavior,
                                               uint8_t ** ppRxBuffer,
                                               uint16_t * pRxDataLength
                                               )
{

    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint16_t    PH_MEMLOC_REM wBufferLength = 0;
    uint16_t    PH_MEMLOC_REM wRxLen = 0U;
    uint8_t *   PH_MEMLOC_REM pTmpRxBuffer = 0U;
    uint16_t    PH_MEMLOC_REM wTmpRxBufferLen = 0U;
    uint16_t    PH_MEMLOC_REM wTmpRxBufferSize = 0U;
    uint8_t     PH_MEMLOC_BUF aCmdBuffer[46];

    if ((pDataParams == NULL) ||
        (PH_GET_COMPCODE(pDataParams) != PH_COMP_HAL) ||
        (PH_GET_COMPID(pDataParams) != PHHAL_HW_PN76XX_ID))

    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_HAL);
    }

    /* Validate pBeginRoundCommand and bTimeslotProcessingBehavior */
    if ((NULL == pBeginRoundCommand)
        || (bTimeslotProcessingBehavior > PHHAL_HW_PN76XX_MAX_EPC_GEN2_TIMESLOT))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Validate the parameters of Select command */
    if (0U != (bSelectCommandLength))
    {
        /* Validate pSelectCommand, bSelectCommandLength and bSelectCommandBitsInLastByte */
        if (                            \
            (NULL == pSelectCommand)    \
            || (bSelectCommandLength > PHHAL_HW_PN76XX_MAX_SELECT_COMMAND_LENGTH)    \
            ||  (bSelectCommandBitsInLastByte > PHHAL_HW_PN76XX_MAX_NUM_OF_BITS_FOR_LAST_BYTE) \
            )
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
        }
    }

    /* Build the command frame */
    wBufferLength = 0U;

    phhalHw_Pn76xx_Int_GetRxBuffer(pDataParams,
        &pTmpRxBuffer,
        &wTmpRxBufferLen,
        &wTmpRxBufferSize);

    /* Write Tx Data */
    aCmdBuffer[wBufferLength++] = 0x00; /* command */
    aCmdBuffer[wBufferLength++] = 0x00; /* ResumeInventory */
    aCmdBuffer[wBufferLength++] = bSelectCommandLength;
    /*
    No Select command is set prior to BeginRound command.
    'Valid Bits in last Byte' field and 'Select command' field shall not be present.
    */
    if(0U != (bSelectCommandLength))
    {
        aCmdBuffer[wBufferLength++] = bSelectCommandBitsInLastByte;

        /* Copy the Instruction payload and update the buffer length*/
        (void)memcpy(&aCmdBuffer[wBufferLength], pSelectCommand, bSelectCommandLength);
        wBufferLength+= bSelectCommandLength;
    }
    /* Copy the Instruction payload and update the buffer length*/
    (void)memcpy(&aCmdBuffer[wBufferLength], pBeginRoundCommand, PHHAL_HW_PN76XX_BEGIN_COMMAND_LENGTH);
    wBufferLength+= PHHAL_HW_PN76XX_BEGIN_COMMAND_LENGTH;

    aCmdBuffer[wBufferLength++] = bTimeslotProcessingBehavior;

    /* call the CLIF inventory command. */
    wRxLen = 0;
    *pRxDataLength = wRxLen;
    statusTmp = PN76_Clif_EpcGen2Inventory( &aCmdBuffer[1], (wBufferLength-1), pTmpRxBuffer, &wRxLen);

    if (statusTmp == PH_ERR_SUCCESS)
    {
        /* copy the RX buffer and length and send it to the upper layer */
        *ppRxBuffer = pTmpRxBuffer;
        *pRxDataLength = wRxLen;
    }

    return PH_ADD_COMPCODE(statusTmp, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_Int_EpcGen2ResumeInventory(
                                                     phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                     uint8_t ** ppRxBuffer,
                                                     uint16_t * pRxDataLength
                                                     )
{
   phStatus_t  PH_MEMLOC_REM statusTmp;
   uint16_t    PH_MEMLOC_REM wBufferLength = 0;
   uint16_t    PH_MEMLOC_REM wRxLen = 0U;
   uint8_t *   PH_MEMLOC_REM pTmpRxBuffer = 0U;
   uint16_t    PH_MEMLOC_REM wTmpRxBufferLen = 0U;
   uint16_t    PH_MEMLOC_REM wTmpRxBufferSize = 0U;
   uint8_t     PH_MEMLOC_BUF aCmdBuffer[2];

   if ((NULL == pDataParams) ||
       (PH_GET_COMPCODE(pDataParams) != PH_COMP_HAL) ||
       (PH_GET_COMPID(pDataParams) != PHHAL_HW_PN76XX_ID))

   {
       return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_DATA_PARAMS, PH_COMP_HAL);
   }

   /* Build the command frame */
   wBufferLength = 0U;

   phhalHw_Pn76xx_Int_GetRxBuffer(pDataParams,
       &pTmpRxBuffer,
       &wTmpRxBufferLen,
       &wTmpRxBufferSize);

   /* Write Tx Data */
   aCmdBuffer[wBufferLength++] = 0x00; /* cmd */
   aCmdBuffer[wBufferLength++] = 0x01; /* ResumeInventory */

   /* Send it to the chip */
   statusTmp = PN76_Clif_EpcGen2Inventory( &aCmdBuffer[1], (wBufferLength-1), pTmpRxBuffer, &wRxLen);

   if (statusTmp == PH_ERR_SUCCESS)
   {
       /* copy the RX buffer and length and send it to the upper layer */
       *ppRxBuffer = pTmpRxBuffer;
       *pRxDataLength = wRxLen;
   }

   return PH_ADD_COMPCODE(statusTmp, PH_COMP_HAL);
}
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#endif  /* NXPBUILD__PHHAL_HW_PN76XX */
