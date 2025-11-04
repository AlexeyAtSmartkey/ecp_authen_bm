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
* PN76XX Reader Library Generic HAL interface.
*
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/

#include <ph_Status.h>
#include <phhalHw.h>
#include <ph_RefDefs.h>

#ifdef NXPBUILD__PH_KEYSTORE
#include <phKeyStore.h>
#endif /* NXPBUILD__PH_KEYSTORE */
#ifdef NXPBUILD__PHHAL_HW_PN76XX
#include <phTools.h>
#include "PN76_Reg_Interface.h"
#include "Clif_Reg.h"
#include "PN76_Eeprom.h"
#include "Clif.h"
#include "phhalHw_PN76xx.h"
#include "phhalHw_PN76xx_Int.h"
#ifdef NXPBUILD__PHHAL_HW_PN7642
#include "PN76_UserAreaAdd.h"
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#define SET_PN76XX_SHADOW(USED_SHADOW)   \
    pShadowDefault = &(USED_SHADOW)[0][0]; \
    wShadowCount = (uint16_t)(sizeof((USED_SHADOW)) / (sizeof((USED_SHADOW)[0])))

#define MASK_TX_LASTBITS        0x07U    /**< The bits that are valid for TX_LATS_BITS field */
#define MASK_RX_LASTBITS        0x07U    /**< The bits that are valid for RX_LATS_BITS field */
#define MASK_RXWAIT             0xFFFFFU /**< Bitmask for RxWait bits. */
#define PHHAL_HW_PN76XX_EMVCO_EMD_NO_BYTES (1 << EMD_CONTROL_EMD_NOISE_BYTES_THRESHOLD_POS)
#define PHHAL_HW_PN76XX_EMVCO_ISO_NO_BYTES (0 << EMD_CONTROL_EMD_NOISE_BYTES_THRESHOLD_POS)
#define PHHAL_HW_PN76XX_EMVCO_EMD_TIMER    (1 << EMD_CONTROL_EMD_TRANSMISSION_TIMER_USED_POS)
#define PHHAL_HW_PN76XX_EMD_3P0     (EMD_CONTROL_EMD_ENABLE_MASK | \
                                     EMD_CONTROL_EMD_TRANSMISSION_ERROR_ABOVE_NOISE_THRESHOLD_IS_NO_EMD_MASK | \
                                     PHHAL_HW_PN76XX_EMVCO_EMD_NO_BYTES | PHHAL_HW_PN76XX_EMVCO_EMD_TIMER)

#define PHHAL_HW_PN76XX_ISO_EMD     (EMD_CONTROL_EMD_ENABLE_MASK | \
                                     EMD_CONTROL_EMD_TRANSMISSION_ERROR_ABOVE_NOISE_THRESHOLD_IS_NO_EMD_MASK | \
                                     PHHAL_HW_PN76XX_EMVCO_ISO_NO_BYTES | PHHAL_HW_PN76XX_EMVCO_EMD_TIMER)

/* Default shadow for ISO14443-3A Mode */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_I14443a[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_ON},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             76U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             85U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_106 | PHHAL_HW_RF_TYPE_A_FRAMING},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_106 | PHHAL_HW_RF_TYPE_A_FRAMING},
    {PHHAL_HW_CONFIG_ASK100,                PH_ON}
};

/* Default shadow for ISO14443-3B Mode */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_I14443b[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_OFF},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             76U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             85U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_106 | PHHAL_HW_RF_TYPE_B_FRAMING},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_106 | PHHAL_HW_RF_TYPE_B_FRAMING},
    {PHHAL_HW_CONFIG_ASK100,                PH_OFF}
};

/* Default shadow for FeliCa Mode */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_Felica[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_OFF},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             88U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             160U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_212 | PHHAL_HW_RF_TYPE_F_FRAMING},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_212 | PHHAL_HW_RF_TYPE_F_FRAMING},
    {PHHAL_HW_CONFIG_ASK100,                PH_OFF}
};

/* Default shadow for FeliCa Mode at 424 baud rate */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_Felica_424[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_OFF},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             85U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             160U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_424 | PHHAL_HW_RF_TYPE_F_FRAMING},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RF_DATARATE_424 | PHHAL_HW_RF_TYPE_F_FRAMING},
    {PHHAL_HW_CONFIG_ASK100,                PH_OFF}
};

/* Default shadow for ISO15693 Mode */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_I15693[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_OFF},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             300U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             500U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_TX_DATARATE_1_OUT_OF_4},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RF_RX_DATARATE_HIGH},
    {PHHAL_HW_CONFIG_SUBCARRIER,            PHHAL_HW_SUBCARRIER_SINGLE},
    {PHHAL_HW_CONFIG_ASK100,                PH_ON}
};

/* Default shadow for ISO18000-3 Mode3 */
static const uint16_t PH_MEMLOC_CONST_ROM wPn76xx_DefaultShadow_I18000p3m3[][2] =
{
    {PHHAL_HW_CONFIG_PARITY,                PH_OFF},
    {PHHAL_HW_CONFIG_TXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXCRC,                 PH_ON},
    {PHHAL_HW_CONFIG_RXWAIT_US,             76U},
    {PHHAL_HW_CONFIG_TXWAIT_US,             300U},
    {PHHAL_HW_CONFIG_TXDATARATE_FRAMING,    PHHAL_HW_RF_TX_DATARATE_I18000P3M3},
    {PHHAL_HW_CONFIG_RXDATARATE_FRAMING,    PHHAL_HW_RX_I18000P3M3_FL_847_MAN4},
    {PHHAL_HW_CONFIG_SUBCARRIER,            PHHAL_HW_SUBCARRIER_DUAL},
    {PHHAL_HW_CONFIG_ASK100,                PH_OFF}
};


phStatus_t phhalHw_Pn76xx_Init(
                               phhalHw_Pn76xx_DataParams_t * pDataParams,
                               uint16_t wSizeOfDataParams,
                               void * pBalDataParams,
                               void * pKeyStoreDataParams,
                               uint8_t * pTxBuffer,
                               uint16_t wTxBufSize,
                               uint8_t * pRxBuffer,
                               uint16_t wRxBufSize
                               )
{
    phStatus_t PH_MEMLOC_REM wStatus;
    uint8_t    PH_MEMLOC_REM bAddOffset = 0;


    /* The buffers cannot be zero */
    if (wTxBufSize == 0U || wRxBufSize == 0U)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Check all the pointers */
    PH_ASSERT_NULL(pDataParams);
    PH_ASSERT_NULL(pTxBuffer);
    PH_ASSERT_NULL(pRxBuffer);

    (void)memset(pDataParams, 0x00U, (sizeof(phhalHw_Pn76xx_DataParams_t)));

    /* The first bytes are reserved for the SPI commands */
    pDataParams->pTxBuffer                = pTxBuffer;
    pDataParams->wTxBufSize               = wTxBufSize;
    pDataParams->wRxBufSize               = wRxBufSize;

    /* If Rx buffer is not DWORD aligned then use the HAL buffer for Reception else buffer passed. */
    if ((0x03 & ((uint32_t)pRxBuffer)) != 0)
    {
       bAddOffset = (4 - (0x03 % ((uint32_t)pRxBuffer)));
    }
    pDataParams->pRxBuffer            = (uint8_t *)&pRxBuffer[bAddOffset];

    /* Initialize the private data */

    pDataParams->wId                      = PH_COMP_HAL | PHHAL_HW_PN76XX_ID;
    pDataParams->pKeyStoreDataParams      = pKeyStoreDataParams;

    pDataParams->wRxBufLen              = 0U;
    pDataParams->wRxBufStartPos         = 0U;

    pDataParams->wTxBufLen              = 0U;
    pDataParams->wTxBufStartPos         = 0U;

    pDataParams->bActiveMode            = PH_OFF;
    pDataParams->bCardType              = PHHAL_HW_CARDTYPE_ISO14443A;
    pDataParams->bTimeoutUnit           = PHHAL_HW_TIME_MICROSECONDS;
    pDataParams->wFieldOffTime          = PHHAL_HW_FIELD_OFF_DEFAULT;
    pDataParams->wFieldRecoveryTime     = PHHAL_HW_FIELD_RECOVERY_DEFAULT;
    pDataParams->bSymbolStart           = PH_OFF;
    pDataParams->bSymbolEnd             = PH_OFF;

    pDataParams->bRfResetAfterTo        = PH_OFF;
    pDataParams->bOpeMode               = RD_LIB_MODE_NFC;
    pDataParams->dwFelicaEmdReg         = 0U;
    pDataParams->bRxMultiple            = PH_OFF;
    pDataParams->bJewelActivated        = PH_OFF;
    pDataParams->bRfca                  = PH_ON;
    pDataParams->wTargetMode            = PH_OFF;
    pDataParams->dwTxWaitMs             = 0U;
    pDataParams->bMfcCryptoEnabled      = PH_OFF;
    pDataParams->bCardMode              = PH_OFF;
    pDataParams->wAdditionalInfo        = 0U;
    pDataParams->bPollGuardTimeFlag     = PH_OFF;
    pDataParams->bNfcipMode             = PH_OFF;
    pDataParams->dwExpectedEvent        = 0U;
    pDataParams->wLPCDWakeupCounterInMs = 0U;
    pDataParams->dwLpcdRefVal           = 0U;
    pDataParams->bLpcdMode              = 0U;
#ifdef NXPBUILD__PHHAL_HW_PN7642
    pDataParams->wTimingMode            = PHHAL_HW_TIMING_MODE_OFF;
    pDataParams->dwTimingUs             = 0U;
    pDataParams->bTimerDeviation        = 3;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

    /* Initialize CLIF Module of PN76 device. */
    PH_CHECK_SUCCESS_FCT(wStatus, PN76_Clif_Init());

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_DeInit(
                                 phhalHw_Pn76xx_DataParams_t * pDataParams
                                 )
{
    phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    /* De-Initialize data parameters */
    pDataParams->wId                    = 0U;
    pDataParams->pKeyStoreDataParams    = NULL;
    pDataParams->pTxBuffer              = NULL;
    pDataParams->wTxBufSize             = 0U;
    pDataParams->wTxBufLen              = 0U;
    pDataParams->wTxBufStartPos         = 0U;
    pDataParams->pRxBuffer              = NULL;
    pDataParams->wRxBufSize             = 0U;
    pDataParams->wRxBufLen              = 0U;
    pDataParams->wRxBufStartPos         = 0U;
    pDataParams->bCardType              = PHHAL_HW_CARDTYPE_UNKNOWN;
    pDataParams->bTimeoutUnit           = PHHAL_HW_TIME_MICROSECONDS;
    pDataParams->wFieldOffTime          = PHHAL_HW_FIELD_OFF_DEFAULT;
    pDataParams->wFieldRecoveryTime     = PHHAL_HW_FIELD_RECOVERY_DEFAULT;
    pDataParams->bSymbolStart           = PH_OFF;
    pDataParams->bSymbolEnd             = PH_OFF;
    pDataParams->wAdditionalInfo        = 0U;
    pDataParams->bRfResetAfterTo        = PH_OFF;
    pDataParams->bRxMultiple            = PH_OFF;
    pDataParams->bActiveMode            = PH_OFF;
    pDataParams->bRfca                  = PH_ON;
    pDataParams->wTargetMode            = PH_OFF;
    pDataParams->bOpeMode               = RD_LIB_MODE_NFC;
    pDataParams->dwFelicaEmdReg         = 0U;
    pDataParams->bJewelActivated        = PH_OFF;
    pDataParams->dwTxWaitMs             = 0U;
    pDataParams->bMfcCryptoEnabled      = PH_OFF;
    pDataParams->bCardMode              = PH_OFF;
    pDataParams->bPollGuardTimeFlag     = PH_OFF;
    pDataParams->bNfcipMode             = PH_OFF;
    pDataParams->dwExpectedEvent        = 0U;
    pDataParams->dwLpcdRefVal           = 0U;
    pDataParams->wLPCDWakeupCounterInMs = 0U;
    pDataParams->bLpcdMode              = 0U;
#ifdef NXPBUILD__PHHAL_HW_PN7642
    pDataParams->wTimingMode            = PHHAL_HW_TIMING_MODE_OFF;
    pDataParams->dwTimingUs             = 0U;
    pDataParams->bTimerDeviation        = 0U;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

    wStatus = PN76_Clif_DeInit();

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_AsyncAbort(
                                     phhalHw_Pn76xx_DataParams_t * pDataParams
                                     )
{
    phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    wStatus = PN76_Clif_AbortEvent();

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_FieldOn(
                                  phhalHw_Pn76xx_DataParams_t * pDataParams
                                  )
{
    phStatus_t PH_MEMLOC_REM wStatus;
    uint8_t    PH_MEMLOC_REM bRFONconfig = 0U;

    if(pDataParams->bActiveMode == PH_ON)
    {
        bRFONconfig |= 0x02U;
    }

    if(pDataParams->bRfca == PH_OFF)
    {
        bRFONconfig |= 0x01U;
    }

    wStatus = PN76_Clif_FieldON(bRFONconfig);

    if ((wStatus & PH_ERR_MASK) == PH_ERR_RF_ERROR)
    {
        wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_RF_ERROR, PH_COMP_HAL);
    }

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_FieldOff(
                                   phhalHw_Pn76xx_DataParams_t * pDataParams
                                   )
{
    phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    /* Disable the EMD. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_SET_EMD, PH_OFF));

    PN76_Clif_FieldOFF();
    return wStatus;
}

phStatus_t phhalHw_Pn76xx_FieldReset(
                                     phhalHw_Pn76xx_DataParams_t * pDataParams
                                     )
{
    phStatus_t PH_MEMLOC_REM wStatus;

    /* Switch off the field */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_FieldOff(pDataParams));

    /* Wait for field-off time-out */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Wait(
        pDataParams,
        PHHAL_HW_TIME_MILLISECONDS,
        (pDataParams->wFieldOffTime)));

    /* In Active mode FW will enter idle state when the RF OFF CMD is seen during active communication.
     * So, apply protocol settings/LoadRf during Field reset. */
    if(pDataParams->bActiveMode == PH_ON)
    {
        if(pDataParams->bCardType == PHHAL_HW_CARDTYPE_UNKNOWN)
        {
            pDataParams->bCardType = PHHAL_HW_CARDTYPE_I18092M_ACTIVE_106;
        }
        PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_ApplyProtocolSettings(pDataParams, pDataParams->bCardType));
    }

    /* Switch on the field again */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_FieldOn(pDataParams));

    /* Wait for field-recovery time-out */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Wait(
        pDataParams,
        PHHAL_HW_TIME_MILLISECONDS,
        (pDataParams->wFieldRecoveryTime)));

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_ApplyProtocolSettings(
                                                phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                uint8_t bCardType
                                                )
{
    phStatus_t PH_MEMLOC_REM wStatus;
    const uint16_t * PH_MEMLOC_REM pShadowDefault;
    uint16_t   PH_MEMLOC_REM wShadowCount;
    uint8_t    PH_MEMLOC_REM bUseDefaultShadow;
    uint16_t   PH_MEMLOC_COUNT wIndex;
    uint16_t   PH_MEMLOC_REM wConfig;
    PN76_Clif_TxConfig_t PH_MEMLOC_REM wTxConfig;
    PN76_Clif_RxConfig_t PH_MEMLOC_REM wRxConfig;

    /* Disable the EMD. */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_SET_EMD, PH_OFF));

    /* Store new card type */
    if (bCardType != PHHAL_HW_CARDTYPE_CURRENT)
    {
        pDataParams->bCardType = bCardType;
        pDataParams->bTimeoutUnit = PHHAL_HW_TIME_MICROSECONDS;
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_US] = 0;
        pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS] = 0;
        bUseDefaultShadow = 1U;
    }
    else
    {
        bUseDefaultShadow = 0U;
    }

    pDataParams->bActiveMode       = PH_OFF;
    pDataParams->wTargetMode       = PH_OFF;
    pDataParams->bJewelActivated   = PH_OFF;
    pDataParams->bNfcipMode        = PH_OFF;

    /* Configure reader IC for current card */
    switch (pDataParams->bCardType)
    {
        /* configure hardware for ISO 14443A */
    case PHHAL_HW_CARDTYPE_ISO14443A:
        wTxConfig = E_PN76_LOADRF_TX_ISO14443A_106;
        wRxConfig = E_PN76_LOADRF_RX_ISO14443A_106;


        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(wTxConfig, wRxConfig));

        /* Use 14443a default shadow */
        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_I14443a);
        break;

    case PHHAL_HW_CARDTYPE_ISO14443B:
        wTxConfig = E_PN76_LOADRF_TX_ISO14443B_106;
        wRxConfig = E_PN76_LOADRF_RX_ISO14443B_106;


        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(wTxConfig, wRxConfig));

        /* Use 14443b shadow */
        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_I14443b);
        break;

    case PHHAL_HW_CARDTYPE_FELICA_212:
        wTxConfig = E_PN76_LOADRF_TX_FELICA_212;
        wRxConfig = E_PN76_LOADRF_RX_FELICA_212;


        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(wTxConfig, wRxConfig));

        /* Use Felica shadow */
        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_Felica);
        break;

    case PHHAL_HW_CARDTYPE_FELICA_424:
        wTxConfig = E_PN76_LOADRF_TX_FELICA_424;
        wRxConfig = E_PN76_LOADRF_RX_FELICA_424;


        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(wTxConfig, wRxConfig));

        /* Use Felica shadow for 424*/
        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_Felica_424);
        break;

    case PHHAL_HW_CARDTYPE_ISO15693:
        /* Use 15693 shadow */
        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_ISO15693_26_1OF4_ASK100, E_PN76_LOADRF_RX_ISO15693_26_SC));

        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_I15693);

        break;




    case PHHAL_HW_CARDTYPE_I18000P3M3:
        /* Use 18000p3m3 shadow */
#ifdef NXPBUILD__PHHAL_HW_PN7640
        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_NO_CHANGE, E_PN76_LOADRF_RX_NO_CHANGE));
#endif /* NXPBUILD__PHHAL_HW_PN7640 */
#ifdef NXPBUILD__PHHAL_HW_PN7642
        PH_CHECK_SUCCESS_FCT(wStatus,PN76_Clif_LoadRfConfiguration(E_PN76_LOADRF_TX_ISO180003M3_TARI_9_44_ASK, E_PN76_LOADRF_RX_ISO180003M3_MANCH848_4_PERIOD));  /* Masking RxDataRate with Minimum Configuration Index */
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
        SET_PN76XX_SHADOW(wPn76xx_DefaultShadow_I18000p3m3);
        break;

    default:
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Copy over default shadow contents into current shadow. */
    if (0U != bUseDefaultShadow)
    {
        /* Initialize config shadow */
        (void)memset(pDataParams->wCfgShadow, 0x00U, (sizeof(uint16_t) * PHHAL_HW_PN76XX_SHADOW_COUNT));

        for (wIndex = 0U; wIndex < wShadowCount; ++wIndex)
        {
            wConfig = pShadowDefault[wIndex << 1U];

            /* Updated TxCRC and RxCRC in shadow due to LoadRFConfig */
            if ((wConfig == PHHAL_HW_CONFIG_TXCRC) ||
                (wConfig == PHHAL_HW_CONFIG_RXCRC))
            {
                if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443B)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, wConfig, pShadowDefault[(wIndex << 1U) + 1U]));
                }
                else
                {
                    /* Write config data into shadow */
                    pDataParams->wCfgShadow[wConfig] = pShadowDefault[(wIndex << 1U) + 1U];
                }
            }

            /* Configure the RxWait using Shadow values */
            if (wConfig == PHHAL_HW_CONFIG_RXWAIT_US)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, wConfig, pShadowDefault[(wIndex << 1U) + 1U]));
            }

            /* Configure the TxWait using Shadow values */
            if(wConfig == PHHAL_HW_CONFIG_TXWAIT_US)
            {
                if (((pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443A) || (pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443B)) &&
                    (pDataParams->bOpeMode != RD_LIB_MODE_ISO))
                {
                    /* Configure TxWait of 500 micro seconds in EMVCo and NFC mode. */
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, wConfig, 500U));
                }
                else
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig(pDataParams, wConfig, pShadowDefault[(wIndex << 1U) + 1U]));
                }
            }
            pDataParams->wCfgShadow[wConfig] = pShadowDefault[(wIndex << 1U) + 1U];
        }
    }

    /* MIFARE Crypto1 state is disabled by default */
    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_SetConfig(pDataParams, PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1, PH_ON));

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_SetConfig(
                                    phhalHw_Pn76xx_DataParams_t * pDataParams,
                                    uint16_t wConfig,
                                    uint16_t wValue
                                    )
{
    phStatus_t  PH_MEMLOC_REM wStatus;
    uint32_t    PH_MEMLOC_REM dwRegister = 0U;
    uint32_t    PH_MEMLOC_REM dwTemp = 0U;
    uint32_t    PH_MEMLOC_REM dwValue = 0U;
    float32_t   PH_MEMLOC_REM fTime = 0.0;
    uint8_t *   PH_MEMLOC_REM pBuffer = NULL;
    uint16_t    PH_MEMLOC_REM wBufferSize;
    uint16_t    PH_MEMLOC_REM wBufferLen = 0U;

    /* Check if Apply Protocol is already done. */
    if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_UNKNOWN)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_HAL);
    }

    switch(wConfig)
    {
        case PHHAL_HW_CONFIG_TXBUFFER_OFFSET:
            /* Setting the value of additional info */
            pDataParams->wAdditionalInfo = wValue;
            break;

        case PHHAL_HW_CONFIG_RXBUFFER_STARTPOS:
            /* Retrieve RxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetRxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Boundary check */
            if (wValue >= pDataParams->wRxBufSize)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            /* Set start position */
            pDataParams->wRxBufStartPos = wValue;
            break;

        case PHHAL_HW_CONFIG_TXBUFFER_LENGTH:

            /* Retrieve TxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Check parameter, must not exceed TxBufferSize */
            if (wValue > pDataParams->wTxBufSize)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            if ((pDataParams->bActiveMode != PH_ON) && (pDataParams->bNfcipMode == PH_ON))
            {
                wValue++;
            }

            /* set buffer length */
            pDataParams->wTxBufLen = wValue;
            break;

        case PHHAL_HW_CONFIG_TXBUFFER:

            /* Retrieve TxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Check parameter, must not exceed TxBufferSize */
            if (pDataParams->wAdditionalInfo >= pDataParams->wTxBufSize)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            pBuffer[pDataParams->wAdditionalInfo] = (uint8_t)wValue;

            break;

        case PHHAL_HW_CONFIG_TXDATARATE_FRAMING:
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_SetTxDataRateFraming(pDataParams, wConfig, wValue));
            break;

        case PHHAL_HW_CONFIG_RXDATARATE_FRAMING:
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_SetRxDataRateFraming(pDataParams, wConfig, wValue));

            if (((pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXDATARATE_FRAMING] & PHHAL_HW_RF_DATARATE_OPTION_MASK) != PHHAL_HW_RF_DATARATE_106)
                && ((pDataParams->wCfgShadow[wConfig] & PHHAL_HW_RF_DATARATE_OPTION_MASK) == PHHAL_HW_RF_DATARATE_106))
            {
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig_Int(pDataParams, PHHAL_HW_CONFIG_RXWAIT_US, 70U));
            }
            break;

        case PHHAL_HW_CONFIG_RFCA:

            if ((wValue != PH_ON) && (wValue != PH_OFF))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            pDataParams->bRfca = (uint8_t)wValue;
            break;


        case PHHAL_HW_CONFIG_SUBCARRIER:

            if (pDataParams->wCfgShadow[wConfig] != wValue)
            {
                /* Parameter check */
                if ((pDataParams->bCardType != PHHAL_HW_CARDTYPE_ISO15693) &&
                    (pDataParams->bCardType != PHHAL_HW_CARDTYPE_I18000P3M3))
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_HAL);
                }

                /* Only single subcarrier to be used while reception by ISO15693 */
                if ((pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO15693) && (wValue != PHHAL_HW_SUBCARRIER_SINGLE))
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
                }

                /* Evaluate hardware settings */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_SetCardMode(
                        pDataParams,
                        ((pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXDATARATE_FRAMING]) & PHHAL_HW_RF_DATARATE_OPTION_MASK),
                        ((pDataParams->wCfgShadow[PHHAL_HW_CONFIG_RXDATARATE_FRAMING]) & PHHAL_HW_RF_DATARATE_OPTION_MASK),
                        wValue));

                /* Update Subcarrier setting */
                pDataParams->wCfgShadow[PHHAL_HW_CONFIG_SUBCARRIER] = wValue;
            }

            break;

        case PHHAL_HW_CONFIG_POLL_GUARD_TIME_US:
            if (wValue == 0x00U)
            {
                return PH_ERR_SUCCESS;
            }

            pDataParams->bPollGuardTimeFlag = PH_ON;

            PN76_Clif_EventConsumeAll();

            PH_CHECK_SUCCESS_FCT(wStatus, PN76_Clif_Set_PollGuardTimer(wValue));
            break;

        case PHHAL_HW_CONFIG_OPE_MODE:
            pDataParams->bOpeMode = (uint8_t)wValue;
            break;

        case PHHAL_HW_CONFIG_RFRESET_ON_TIMEOUT:

            if (wValue == PH_OFF)
            {
                pDataParams->bRfResetAfterTo = PH_OFF;
            }
            else
            {
                pDataParams->bRfResetAfterTo = PH_ON;
            }

            break;

        case PHHAL_HW_CONFIG_PARITY:
        case PHHAL_HW_CONFIG_ASK100:
           if (pDataParams->wCfgShadow[wConfig] != wValue)
           {
               /* Use internal set config */
               PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig_Int(pDataParams, wConfig, wValue));

               /* Write config data into shadow */
               pDataParams->wCfgShadow[wConfig] = wValue;
           }
           break;
        case PHHAL_HW_CONFIG_RXWAIT_US:
            /* Use internal set config */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig_Int(pDataParams, wConfig, wValue));

            /* Write config data into shadow */
            pDataParams->wCfgShadow[wConfig] = wValue;
            break;

        case PHHAL_HW_CONFIG_TXCRC:
        case PHHAL_HW_CONFIG_RXCRC:
            /* Check shadow while performing configuration in EMVCo mode, to have good timing performance.
             * As in EMVCo mode ApplyProtocolSettings shall always be followed by FieldOn function. */
            if (pDataParams->bOpeMode == RD_LIB_MODE_EMVCO)
            {
                if (pDataParams->wCfgShadow[wConfig] != wValue)
                {
                    /* Use internal set config */
                    PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig_Int(pDataParams, wConfig, wValue));
                }
            }
            else
            {
                /* NOTE : Do not perform shadow check, as FieldOn function of Pn76xx FW performs
                 * LoadRFConfiguration of previously applied Protocol configuration and the shadow
                 * value of HAL for Tx and Rx CRC doesn't have the value that is configured on CLIF. */

                /* Use internal set config */
                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_SetConfig_Int(pDataParams, wConfig, wValue));
            }

            /* Write config data into shadow */
            pDataParams->wCfgShadow[wConfig] = wValue;
            break;

        case PHHAL_HW_CONFIG_TXLASTBITS:

            if (pDataParams->wCfgShadow[wConfig] != wValue)
            {
                /* Check parameter */
                if (wValue > MASK_TX_LASTBITS)
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
                }
                PH_CHECK_SUCCESS_FCT(wStatus,CLIF_CLEARREG_MASK(CLIF_TX_DATA_CONFIG, (uint32_t)(~(CLIF_TX_DATA_CONFIG_TX_LAST_BITS_MASK))));
                PH_CHECK_SUCCESS_FCT(wStatus,CLIF_SETREG_MASK(CLIF_TX_DATA_CONFIG, (wValue << CLIF_TX_DATA_CONFIG_TX_LAST_BITS_POS)));

                /* Write config data into shadow */
                pDataParams->wCfgShadow[wConfig] = wValue;
            }
            break;

        case PHHAL_HW_CONFIG_RXALIGN:

            if (pDataParams->wCfgShadow[wConfig] != wValue)
            {
                /* Check the parameter */
                if (wValue >  MASK_RX_LASTBITS)
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
                }

                PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_ClearNSetRegFields(pDataParams,
                        CLIF_RX_PROTOCOL_CONFIG, CLIF_RX_PROTOCOL_CONFIG_RX_BIT_ALIGN_MASK,
                        CLIF_RX_PROTOCOL_CONFIG_RX_BIT_ALIGN_POS, wValue));


                /* Write config data into shadow */
                pDataParams->wCfgShadow[wConfig] = wValue;
            }
            break;

        case PHHAL_HW_CONFIG_TXWAIT_US:

            if (pDataParams->wCfgShadow[wConfig] != wValue)
            {
                /* Set TxWait */
                fTime = 0.0;
                dwValue = PHHAL_HW_PN76XX_TR_RX_PRESCALAR;
                dwTemp = wValue;

                if(0U != dwTemp)
                {
                    fTime = (float32_t)(((float32_t)dwTemp * 13.56) / (float32_t)(dwValue));
                    dwTemp = (uint32_t)fTime;
                    dwValue |= (uint32_t)((dwTemp ) << CLIF_TX_WAIT_TX_WAIT_VALUE_POS);
                    PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_TX_WAIT, dwValue));
                }
                else
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_TX_WAIT, dwValue));
                }

                /* Write configuration data into shadow */
                pDataParams->wCfgShadow[wConfig] = wValue;
            }
            break;

        case PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1:
            /* Disable crypto, enabling is not supported */
            if ((wValue != PH_OFF) && ( pDataParams->bMfcCryptoEnabled == PH_ON))
            {
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t)(~(SYSTEM_CONFIG_MFC_CRYPTO_ON_MASK))));
                pDataParams->bMfcCryptoEnabled = PH_OFF;
            }
            break;

        case PHHAL_HW_CONFIG_TIMEOUT_VALUE_US:
            if ((pDataParams->wCfgShadow[wConfig] != wValue) || (pDataParams->bTimeoutUnit != PHHAL_HW_TIME_MICROSECONDS) || (pDataParams->bOpeMode != RD_LIB_MODE_EMVCO))
            {
                PH_CHECK_SUCCESS_FCT(wStatus,
                                     phhalHw_Pn76xx_Int_SetTmo(
                                             pDataParams,
                                             wValue,
                                             PHHAL_HW_TIME_MICROSECONDS));
                /* Write config data into shadow */
                pDataParams->wCfgShadow[wConfig] = wValue;
                pDataParams->bTimeoutUnit = PHHAL_HW_TIME_MICROSECONDS;
            }
            break;

        case PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS:
            if ((pDataParams->wCfgShadow[wConfig] != wValue) || (pDataParams->bTimeoutUnit != PHHAL_HW_TIME_MILLISECONDS) || (pDataParams->bOpeMode != RD_LIB_MODE_EMVCO))
            {
                PH_CHECK_SUCCESS_FCT(wStatus,
                                     phhalHw_Pn76xx_Int_SetTmo(
                                             pDataParams,
                                             wValue,
                                             PHHAL_HW_TIME_MILLISECONDS));
                /* Write config data into shadow */
                pDataParams->wCfgShadow[wConfig] = wValue;
                pDataParams->bTimeoutUnit = PHHAL_HW_TIME_MILLISECONDS;
            }
            break;

        case PHHAL_HW_CONFIG_NFCIP_STARTBYTE:
            if((wValue != PH_ON) && (wValue != PH_OFF))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            pDataParams->bNfcipMode = (uint8_t)wValue;
            break;

        case PHHAL_HW_CONFIG_JEWEL_MODE:
            if (wValue == PH_ON)
            {
                pDataParams->bJewelActivated = (uint8_t)wValue;
                /* Enable FrameStep in Transceive Control Register. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_MASK));
            }
            else if (wValue == PH_OFF)
            {
                pDataParams->bJewelActivated = (uint8_t)wValue;
                /* Disable FrameStep in Transceive Control Register. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_TRANSCEIVE_CONTROL, (uint32_t )~(CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_MASK)));
            }
            else
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            break;

        case PHHAL_HW_CONFIG_SET_EMD:
            pDataParams->bEmdFlag = (uint8_t)wValue;
            if(wValue == 0x1U)
            {
                dwRegister = 0U;

                /* Read the EMD CONTROL Register to get RM EMD SENSITIVITY field */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_GETREG(EMD_CONTROL, &dwRegister));

                /* Retain only the RM EMD SENSITIVITY value field. */
                dwRegister &= (uint32_t)(EMD_CONTROL_EMD_RM_EMD_SENSITIVITY_MASK);

                if(pDataParams->bOpeMode != RD_LIB_MODE_ISO)
                {
                    dwRegister |= PHHAL_HW_PN76XX_EMD_3P0;
                }
                else
                {
                    dwRegister |= PHHAL_HW_PN76XX_ISO_EMD;
                }
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(EMD_CONTROL, dwRegister));

                /* Set the RM RESYNC ENABLE in SIGPRO RM ENABLE Register. */
                if (pDataParams->bCardType == PHHAL_HW_CARDTYPE_ISO14443A)
                {
                    PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_SIGPRO_RM_ENABLES, CLIF_SIGPRO_RM_ENABLES_RM_RESYNC_RESET_ENABLE_MASK));
                }
            }
            else
            {
                /* Clear EMD Enable bit in EMD Control Register */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(EMD_CONTROL,(uint32_t)(~EMD_CONTROL_EMD_ENABLE_MASK)));
            }
            break;

        case PHHAL_HW_CONFIG_RXMULTIPLE:
            if (wValue == PH_ON)
            {
                pDataParams->bRxMultiple = PH_ON;
                /* Enable Rx Multiple in Transceive Control Register. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_TRANSCEIVE_CONTROL, CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK));
                /* Reset Timer1 (FDT Timer) stop condition. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, (uint32_t )~(CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK)));
            }
            else
            {
                pDataParams->bRxMultiple = PH_OFF;
                /* Disable Rx Multiple in Transceive Control Register. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_TRANSCEIVE_CONTROL, (uint32_t )~(CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK)));
                /* Set Timer1 (FDT Timer) stop condition to Stop on RX Start condition. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK));
            }
            break;

        case PHHAL_HW_CONFIG_MFHALTED:
            if((wValue != PH_ON) && (wValue != PH_OFF))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            if(wValue == PH_ON)
            {
               /* Set Autocoll state A in system config Register. */
               PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(SYSTEM_CONFIG, SYSTEM_CONFIG_AUTOCOLL_STATE_A_MASK));
                pDataParams->bCardMode  = PH_ON;
            }
            else
            {
               /* Clear Autocoll state A in system config Register. */
               PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(SYSTEM_CONFIG, (uint32_t )(~SYSTEM_CONFIG_AUTOCOLL_STATE_A_MASK)));
                pDataParams->bCardMode  = PH_OFF;
            }

            break;

        case PHHAL_HW_CONFIG_FIELD_OFF_TIME:
            /* Off time shall not be zero. */
            if (wValue == 0U)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* Store off time. */
            pDataParams->wFieldOffTime = wValue;
            break;

        case PHHAL_HW_CONFIG_FIELD_RECOVERY_TIME:
            /* Store recovery time. */
            pDataParams->wFieldRecoveryTime = wValue;
            break;

        case PHHAL_HW_CONFIG_SET_SYMBOL_SEND:
            /* check parameter */
            if ((wValue != PH_ON) && (wValue != PH_OFF))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* PH_ON implies Clearing Bit-3 (DataEn Bit in TxDataNum). */
            if (wValue == PH_ON)
            {
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_TX_FRAME_CONFIG,  ~(uint32_t)CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_MASK));
            }
            /* PH_OFF implies Setting Bit-3 (DataEn Bit in TxDataNum). */
            else
            {
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_TX_FRAME_CONFIG, CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_MASK));
            }
            break;


        case PHHAL_HW_CONFIG_SYMBOL_START:
            /* Parameter check */
            if ((pDataParams->bCardType != PHHAL_HW_CARDTYPE_ISO15693) &&
                (pDataParams->bCardType != PHHAL_HW_CARDTYPE_I18000P3M3))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_HAL);
            }

            /* Parameter check #2 */
            switch (wValue)
            {
                case PHHAL_HW_SYMBOL_I15693_SOF:
                    if (pDataParams->bCardType != PHHAL_HW_CARDTYPE_ISO15693)
                    {
                        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
                    }
                    break;
                case PHHAL_HW_SYMBOL_I18000P3M3_PREAMBLE:
                case PHHAL_HW_SYMBOL_I18000P3M3_FSYNC:
                    if (pDataParams->bCardType != PHHAL_HW_CARDTYPE_I18000P3M3)
                    {
                        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
                    }
                    break;
                case PH_OFF:
                    break;
                default:
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
            }

            /* Clear the Bits of TX_CONFIG_TX_START_SYMBOL_MASK & DATA_ENABLE */
            if(wValue == PH_OFF)
            {
                dwTemp = (uint32_t) ~( CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_MASK | CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_MASK);
            }
            else
            {
                dwTemp = (uint32_t) ~( CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_MASK);
            }

            PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_TX_FRAME_CONFIG, dwTemp));

            dwValue = 0U;

            /* Set new symbol */
            switch (wValue)
            {
            case PHHAL_HW_SYMBOL_I15693_SOF:
                dwValue = 0x3U;
                break;
            case PHHAL_HW_SYMBOL_I18000P3M3_PREAMBLE:
                dwValue = 0x1U;
                break;
            case PHHAL_HW_SYMBOL_I18000P3M3_FSYNC:
                dwValue = 0x2U;
                break;
            default:
                break;
            }

            /* Set the new value */
            dwTemp = (uint32_t)((dwValue << CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_POS) & CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_MASK);
            dwTemp |= (uint32_t)((dwValue << CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_POS) & CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_MASK);

            PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_TX_FRAME_CONFIG, dwTemp));
            break;

        case PHHAL_HW_CONFIG_CRCTYPE:
            if(!(wValue & (PHHAL_HW_CRCTYPE_CRC5 | PHHAL_HW_CRCTYPE_CRC16 | PHHAL_HW_CRCOPTION_INVERTED)))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            dwValue = 0U;
            /* dwRegister will contain all the bits that need to be zeroed out */
            dwRegister = 0U;

            if(0U != (wValue & PHHAL_HW_CRCTYPE_CRC16))
            {
                dwRegister |= CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK;
            }
            else
            {
                /* QAC */
            }

            if(0U != (wValue & PHHAL_HW_CRCOPTION_INVERTED))
            {
                dwValue |= CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK;
            }
            else
            {
                dwRegister |= CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK;
            }

            if ((pDataParams->bCardType == PHHAL_HW_CARDTYPE_I18000P3M3) && (0U != ((wValue & PHHAL_HW_CRCTYPE_CRC16))))
            {
                dwRegister |= CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_MASK;
                dwValue |= (0x3U << CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_POS);
            }

            /*Clear the Bits */
            dwTemp = (uint32_t) ~( dwRegister );

            PH_CHECK_SUCCESS_FCT(wStatus, CLIF_CLEARREG_MASK(CLIF_CRC_TX_CONFIG, dwTemp));

            /*Set the new value  */
            dwTemp = dwValue;

            /*Write CRC Tx Configuration*/
            PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG_MASK(CLIF_CRC_TX_CONFIG, dwTemp));
            break;

        case PHHAL_HW_CONFIG_TXWAIT_MS:
            /* Parameter checking */
            if (wValue > 650U) /* To set Max value for wValue in uS i.e, 0xFFFFU )*/
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            /* Store the value in terms of uS in shadow table*/
            pDataParams->dwTxWaitMs =  wValue;

            /* Set TxWait */
            fTime = 0.0;
            dwValue = PHHAL_HW_PN76XX_TR_RX_PRESCALAR;
            dwTemp = wValue*1000U;
            if(0U != dwTemp)
            {
                fTime = (float32_t)(((float32_t)dwTemp * 13.56) / (float32_t)(dwValue));
                dwTemp = (uint32_t)fTime;
                dwValue |= (uint32_t)((dwTemp ) << CLIF_TX_WAIT_TX_WAIT_VALUE_POS);
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_TX_WAIT, dwValue ));
            }
            else
            {
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_TX_WAIT, dwValue ));
            }
            break;

        case PHHAL_HW_CONFIG_SETMINFDT:
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_SetMinFdt(pDataParams, wValue));
            break;

        case PHHAL_HW_CONFIG_RFON_INTERRUPT:
            if((wValue != PH_ON) && (wValue != PH_OFF))
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            if(wValue == PH_ON)
            {
                /* Disable all CLIF Interrupts that are handled in CLIF HAL. */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_INT_CLR_ENABLE, (CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK |
                        CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_MASK |
                        CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK | CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK |
                        CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK)));

                /* Enable CLIF External RF ON Interrupt */
                PH_CHECK_SUCCESS_FCT(wStatus, CLIF_SETREG(CLIF_INT_SET_ENABLE, CLIF_INT_SET_ENABLE_RFON_DET_IRQ_SET_ENABLE_MASK));

                pDataParams->dwExpectedEvent = PH_PN76XX_EVT_RFON_DETECT;
            }
            else
            {
                pDataParams->dwExpectedEvent = 0;
            }
            break;

#ifdef NXPBUILD__PHHAL_HW_PN7642
        case PHHAL_HW_CONFIG_TIMING_MODE:
        {
            /* Check supported option bits */
            switch (wValue & PHHAL_HW_TIMING_MODE_OPTION_MASK)
            {
            case PHHAL_HW_TIMING_MODE_OPTION_DEFAULT:
            case PHHAL_HW_TIMING_MODE_OPTION_AUTOCLEAR:
                break;
            default:
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }

            /* Check supported timing modes */
            switch (wValue & (uint16_t)~(uint16_t)PHHAL_HW_TIMING_MODE_OPTION_MASK)
            {
            case PHHAL_HW_TIMING_MODE_OFF:
            case PHHAL_HW_TIMING_MODE_FDT:
                pDataParams->dwTimingUs = 0U;
                pDataParams->wTimingMode = wValue;
                break;
            case PHHAL_HW_TIMING_MODE_COMM:
                return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
            default:
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            break;
        }

        case PHHAL_HW_CONFIG_TIMER_DEVIATION_PROXIMITY_CHECK:
            /* Max timer deviation should be 5 percentage */
            if(wValue > 5)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
            }
            pDataParams->bTimerDeviation = wValue;
        break;

#endif /* NXPBUILD__PHHAL_HW_PN7642 */


        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_GetConfig(
                                    phhalHw_Pn76xx_DataParams_t * pDataParams,
                                    uint16_t wConfig,
                                    uint16_t * pValue
                                    )
{
    phStatus_t PH_MEMLOC_REM wStatus;
    uint16_t   PH_MEMLOC_REM wBufferLen;
    uint16_t   PH_MEMLOC_REM wBufferSize;
    uint32_t   PH_MEMLOC_REM dwRegister = 0;
    uint8_t *  PH_MEMLOC_REM pBuffer;
    uint8_t    PH_MEMLOC_REM bAutocollState;

    /* Check all the pointers */
    PH_ASSERT_NULL(pValue);

    switch(wConfig)
    {
        case PHHAL_HW_CONFIG_OPE_MODE:
            *pValue = pDataParams->bOpeMode;
            break;

        case PHHAL_HW_CONFIG_SET_EMD:
            *pValue = pDataParams->bEmdFlag;
            break;
        case PHHAL_HW_CONFIG_PARITY:
        case PHHAL_HW_CONFIG_TXCRC:
        case PHHAL_HW_CONFIG_RXCRC:
        case PHHAL_HW_CONFIG_TXLASTBITS:
        case PHHAL_HW_CONFIG_TXDATARATE_FRAMING:
        case PHHAL_HW_CONFIG_RXDATARATE_FRAMING:
        case PHHAL_HW_CONFIG_ASK100:
        case PHHAL_HW_CONFIG_SUBCARRIER:
        case PHHAL_HW_CONFIG_TXWAIT_US:
        case PHHAL_HW_CONFIG_RXWAIT_US:

          /* Read config from shadow */
          *pValue = pDataParams->wCfgShadow[wConfig];
          break;

        case PHHAL_HW_CONFIG_TXBUFFER_OFFSET:
        case PHHAL_HW_CONFIG_RXLASTBITS:

            *pValue = pDataParams->wAdditionalInfo;
            break;

        case PHHAL_HW_CONFIG_TIMEOUT_VALUE_US:

            if (pDataParams->bTimeoutUnit == PHHAL_HW_TIME_MICROSECONDS)
            {
                *pValue = pDataParams->wCfgShadow[wConfig];
            }
            else
            {
                if (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS] > (0xFFFFU / 1000U))
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
                }
                *pValue = pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS] * 1000U;
            }
            break;

        case PHHAL_HW_CONFIG_TIMEOUT_VALUE_MS:

            if (pDataParams->bTimeoutUnit == PHHAL_HW_TIME_MILLISECONDS)
            {
                *pValue = pDataParams->wCfgShadow[wConfig];
            }
            else
            {
                *pValue = pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TIMEOUT_VALUE_US] / 1000U;
            }
            break;

        case PHHAL_HW_CONFIG_FIELD_OFF_TIME:

            *pValue = pDataParams->wFieldOffTime;
            break;

        case PHHAL_HW_CONFIG_FIELD_RECOVERY_TIME:

            *pValue = pDataParams->wFieldRecoveryTime;
            break;

        case PHHAL_HW_CONFIG_JEWEL_MODE:

            /* Write configuration data into shadow */
            *pValue = pDataParams->bJewelActivated;
            break;

        case PHHAL_HW_CONFIG_RFRESET_ON_TIMEOUT:

            *pValue = pDataParams->bRfResetAfterTo;
            break;

        case PHHAL_HW_CONFIG_DISABLE_MF_CRYPTO1:

            /* Check Crypto1On Status */
            if ( pDataParams->bMfcCryptoEnabled == PH_ON)
            {
                *pValue = PH_OFF; /* OFF in this case means "Crypto1 not disabled --> enabled" */
            }
            else
            {
                *pValue = PH_ON; /* ON in this case means "Crypto1 is disabled" */
            }
            break;


        case PHHAL_HW_CONFIG_RXBUFFER_STARTPOS:

            /* Return parameter */
            *pValue = pDataParams->wRxBufStartPos;
            break;

        case PHHAL_HW_CONFIG_RXBUFFER_BUFSIZE:

            /* Retrieve RxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetRxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Return parameter */
            *pValue = wBufferSize;
            break;

        case PHHAL_HW_CONFIG_TXBUFFER_BUFSIZE:

            /* Retrieve TxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Return parameter */
            *pValue = wBufferSize;
            break;

        case PHHAL_HW_CONFIG_TXBUFFER_LENGTH:

            /* Retrieve TxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));
            if ((pDataParams->bActiveMode != PH_ON) && (pDataParams->bNfcipMode == PH_ON))
            {
                if (wBufferLen != 0)
                {
                    wBufferLen--;
                }
            }
            /* Return parameter */
            *pValue = wBufferLen;
            break;

        case PHHAL_HW_CONFIG_TXBUFFER:

            /* Retrieve TxBuffer parameters */
            PH_CHECK_SUCCESS_FCT(wStatus, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pBuffer, &wBufferLen, &wBufferSize));

            /* Check additional info parameter */
            if (pDataParams->wAdditionalInfo >= pDataParams->wTxBufSize)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
            }

            /* Retrieve TxBuffer byte */
            *pValue = (uint16_t)pBuffer[pDataParams->wAdditionalInfo];
            break;

        case PHHAL_HW_CONFIG_RXMULTIPLE:
            *pValue =  pDataParams->bRxMultiple;
            break;

        case PHHAL_HW_CONFIG_NFCIP_STARTBYTE:
            *pValue = pDataParams->bNfcipMode;
            break;

        case PHHAL_HW_CONFIG_TARGET_DATARATE_FRAMING:
            *pValue = pDataParams->wTargetMode;
            break;

        case PHHAL_HW_CONFIG_ACTIVEMODE:
            /* Return parameter */
            *pValue = (uint16_t)pDataParams->bActiveMode;
            break;

        case PHHAL_HW_CONFIG_CARD_TYPE:
            *pValue = pDataParams->bCardType;
            break;

        case PHHAL_HW_CONFIG_MFHALTED:
            PH_CHECK_SUCCESS_FCT(wStatus,CLIF_GETREG(SYSTEM_CONFIG, &dwRegister));
            bAutocollState = (uint8_t)((dwRegister & SYSTEM_CONFIG_AUTOCOLL_STATE_A_MASK) >> SYSTEM_CONFIG_AUTOCOLL_STATE_A_POS);

            *pValue = bAutocollState;
            break;

        case PHHAL_HW_CONFIG_INT_RF_ON:

            PH_CHECK_SUCCESS_FCT(wStatus,CLIF_GETREG(CLIF_STATUS, &dwRegister));
            if((dwRegister & CLIF_STATUS_TX_RF_STATUS_MASK ) == CLIF_STATUS_TX_RF_STATUS_MASK)
            {
                *pValue = PH_ON;
            }
            else
            {
                *pValue = PH_OFF;
            }
            break;

        case PHHAL_HW_CONFIG_EXT_RF_ON:
            /* Retrieve Status register */
            PH_CHECK_SUCCESS_FCT(wStatus,CLIF_GETREG(CLIF_STATUS, &dwRegister));
            /* Check EXT_RF_ON bit */
            if (0U != (dwRegister & CLIF_STATUS_RF_DET_STATUS_MASK))
            {
                *pValue = PH_ON; /* ON if external RF field is detected */
            }
            else
            {
                *pValue = PH_OFF; /* OFF if no external RF field is detected */
            }
            break;

#ifdef NXPBUILD__PHHAL_HW_PN7642
        case PHHAL_HW_CONFIG_TIMING_MODE:
        {
            *pValue = pDataParams->wTimingMode;
            break;
        }

        case PHHAL_HW_CONFIG_TIMING_US:
        {
            if (pDataParams->dwTimingUs > 0xFFFFU)
            {
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
            }

            *pValue = (uint16_t)pDataParams->dwTimingUs;
            pDataParams->dwTimingUs = 0U;
            break;
        }

        case PHHAL_HW_CONFIG_TIMING_MS:
        {
            if (pDataParams->dwTimingUs > (0xFFFFU * 1000U))
            {
                pDataParams->dwTimingUs = 0U;
                return PH_ADD_COMPCODE_FIXED(PH_ERR_PARAMETER_OVERFLOW, PH_COMP_HAL);
            }

            *pValue = (uint16_t)(pDataParams->dwTimingUs / 1000U);
            pDataParams->dwTimingUs = 0U;
            break;
        }

        case PHHAL_HW_CONFIG_TIMER_DEVIATION_PROXIMITY_CHECK:
        {
            *pValue = pDataParams->bTimerDeviation;
            break;
        }
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

        default:
            return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
    }

    return PH_ERR_SUCCESS;
}

phStatus_t phhalHw_Pn76xx_SetListenParameters(
                                              phhalHw_Pn76xx_DataParams_t * pDataParams,
                                              uint8_t * pSensRes,
                                              uint8_t * pNfcId1,
                                              uint8_t SelRes,
                                              uint8_t * pPollingResp,
                                              uint8_t bNfcId3
                                              )
{
    uint8_t PH_MEMLOC_BUF aCmd[PHHAL_HW_PN76XX_SET_LISTEN_LEN];
    phStatus_t wStatus = PH_ERR_INTERFACE_ERROR;

    /* Check all the pointers */
    PH_ASSERT_NULL(pSensRes);
    PH_ASSERT_NULL(pNfcId1);
    PH_ASSERT_NULL(pPollingResp);

    if(0U != bNfcId3)
    {
        /*Coverity*/;
    }

    (void)memcpy(&aCmd[0], pSensRes, PHHAL_HW_PN76XX_SET_LISTEN_SENRES_LEN);
    (void)memcpy(&aCmd[2], pNfcId1, PHHAL_HW_PN76XX_SET_LISTEN_NFCID1_LEN);
    (void)memcpy(&aCmd[5], &SelRes, PHHAL_HW_PN76XX_SET_LISTEN_SELRES_LEN);
    (void)memcpy(&aCmd[6], pPollingResp, PHHAL_HW_PN76XX_SET_LISTEN_POLLRES_LEN);
#ifdef NXPBUILD__PHHAL_HW_PN7640
    wStatus = (PN76_Status_t)PN76_WriteEeprom(aCmd, PHHAL_HW_PN76XX_SET_LISTEN_EEPROM_ADDR, PHHAL_HW_PN76XX_SET_LISTEN_LEN);
#endif /* NXPBUILD__PHHAL_HW_PN7640 */
#ifdef NXPBUILD__PHHAL_HW_PN7642
    wStatus = (PN76_Status_t)PN76_WriteEeprom(aCmd, PHHAL_HW_PN76XX_SET_LISTEN_EEPROM_ADDR, PHHAL_HW_PN76XX_SET_LISTEN_LEN, E_PN76_EEPROM_SECURE_LIB_CONFIG);
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

     return wStatus;
}

phStatus_t phhalHw_Pn76xx_Exchange(
                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                   uint16_t wOption,
                                   uint8_t * pTxBuffer,
                                   uint16_t wTxLength,
                                   uint8_t ** ppRxBuffer,
                                   uint16_t * pRxLength
                                   )
{
    phStatus_t         PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    phStatus_t         PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
    phStatus_t         PH_MEMLOC_REM ExchgStatus = PH_ERR_SUCCESS;
    uint16_t           PH_MEMLOC_REM wTmpRxBufferLen = 0U;
    uint16_t           PH_MEMLOC_REM wTmpRxBufferSize = 0U;
    uint8_t            PH_MEMLOC_REM * pTmpRxBuffer = 0U;
    uint8_t *          PH_MEMLOC_REM pTmpBuffer = NULL;
    uint16_t           PH_MEMLOC_REM wTmpBufferLen = 0U;
    uint16_t           PH_MEMLOC_REM wTmpBufferSize = 0U;
    uint16_t           PH_MEMLOC_REM wNumByteReceived;
    uint32_t           PH_MEMLOC_REM dwValue;
    PN76_Rf_RxParams_t PH_MEMLOC_REM bRxParams = {0};
    PN76_ClifEventType_t PH_MEMLOC_REM dwEventFlags = PN76_CLIF_EVT_TYPE_NONE;
#ifdef NXPBUILD__PHHAL_HW_PN7642
    uint32_t           PH_MEMLOC_REM dwTimingSingle = 0;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

    /* Check all the pointers */
    if (0U != (wTxLength)) PH_ASSERT_NULL(pTxBuffer);

    do
    {
        if (pDataParams->wTargetMode != PH_OFF)
        {
            /* If wTargetMode is changed then Target is activated and Exchange should not be used to perform Tx Operation. */
            statusTmp = (PH_ERR_USE_CONDITION | PH_COMP_HAL);
            break;
        }

        /* Check options */
        if (0U != (wOption & (uint16_t)~(uint16_t)(PH_EXCHANGE_BUFFERED_BIT | PH_EXCHANGE_LEAVE_BUFFER_BIT)))
        {
            statusTmp = (PH_ERR_INVALID_PARAMETER | PH_COMP_HAL);
            break;
        }

        /* Validate input parameters. */
        if (((ppRxBuffer == NULL) || (pRxLength == NULL)) && ((wOption & PH_EXCHANGE_BUFFERED_BIT) == 0U))
        {
            statusTmp = (PH_ERR_INVALID_PARAMETER | PH_COMP_HAL);
            break;
        }

        /* Validate received parameter */
        if (pRxLength != NULL)
        {
            *pRxLength = 0U;
        }

        /* retrieve transmit buffer */
        PH_CHECK_FAILURE_FCT(statusTmp, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pTmpBuffer, &wTmpBufferLen, &wTmpBufferSize));

        /* clear internal buffer if requested */
        if ((0U == ((wOption & PH_EXCHANGE_LEAVE_BUFFER_BIT))))
        {
            pDataParams->wTxBufLen = 0U;
            pDataParams->wTxBufStartPos = 0U;
        }

        if (wTxLength != 0U)
        {
            /* check wTmpBufferSize fill all the required data to be transmitted */
            if (wTmpBufferSize < (wTxLength + pDataParams->wTxBufLen + pDataParams->wTxBufStartPos))
            {
                /* Can't fit in the HAL buffer what we are trying to send */
                pDataParams->wTxBufLen = 0U;
                pDataParams->wTxBufStartPos = 0U;
                statusTmp = (PH_ERR_BUFFER_OVERFLOW | PH_COMP_HAL);
                break;
            }

            /* copy data */
            (void)memcpy(&pTmpBuffer[pDataParams->wTxBufStartPos + pDataParams->wTxBufLen], pTxBuffer, wTxLength);
            pDataParams->wTxBufLen += wTxLength;
        }

        wTxLength = 0U;

        if (0U != (wOption & PH_EXCHANGE_BUFFERED_BIT ))
        {
            return PH_ERR_SUCCESS;
        }

        pDataParams->wTxBufLen += pDataParams->wTxBufStartPos;

        /* Check for maximum bytes that can be sent to IC */
        if(pDataParams->wTxBufLen > 0x400U)
        {
            /* PN76XX TxBuffer max size can be 1024 bytes. */
            statusTmp = (PH_ERR_BUFFER_OVERFLOW | PH_COMP_HAL);
            break;
        }

        if (pDataParams->bPollGuardTimeFlag == PH_ON)
        {
            pDataParams->bPollGuardTimeFlag = PH_OFF;

            status = PN76_Clif_EventWaitAny(PHOSAL_MAX_DELAY, &dwEventFlags);
            if (status == PH_ERR_SUCCESS)
            {
                /* When there is no errors in preconditions wait till timer expire. */
                if (0U != (dwEventFlags & PN76_CLIF_EVT_TYPE_ABORTED))
                {
                    statusTmp = PH_ERR_ABORTED;
                }
                else if (0U != (dwEventFlags & PN76_CLIF_EVT_TYPE_TIMER0))
                {
                    statusTmp = PH_ERR_SUCCESS;
                }
                else
                {
                    statusTmp = PH_ERR_INTERNAL_ERROR;
                }
            }
        }
    }
    while (0);

    if (statusTmp != PH_ERR_SUCCESS)
    {
        return statusTmp;
    }

    if (pDataParams->bJewelActivated == PH_ON)
    {
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_TXLASTBITS, 0x07U));

        /* Set Timer1 (FDT Timer) start condition to Tx Frame Step detected instead of Tx Ended. */
        PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(
            CLIF_TIMER1_CONFIG,
            (uint32_t )~(CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK)));

        PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(
            CLIF_TIMER1_CONFIG,
            CLIF_TIMER1_CONFIG_T1_START_ON_TX_FRAMESTEP_MASK));
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_Int_GetRxBuffer(
            pDataParams,
            &pTmpRxBuffer,
            &wTmpRxBufferLen,
            &wTmpRxBufferSize));

    status = PN76_Clif_Exchange(pTmpBuffer, pTmpRxBuffer, pDataParams->wTxBufLen, wTmpRxBufferSize, &bRxParams);
    ExchgStatus = status; //Backup Exchange status

    if (status == PN76_CLIF_STATUS_TX_FAILURE)
    {
        status = PH_ERR_IO_TIMEOUT;
    }
    PH_CHECK_ABORT(status);

    /* Reset for the next transaction */
    pDataParams->wTxBufStartPos = 0U;
    pDataParams->wTxBufLen = 0U;

    wTxLength = 0U;
#ifdef NXPBUILD__PHHAL_HW_PN7642
    if(status != PH_ERR_IO_TIMEOUT)
    {
        /* Timing */
        if ((pDataParams->wTimingMode & (uint16_t)~(uint16_t)PHHAL_HW_TIMING_MODE_OPTION_MASK) == PHHAL_HW_TIMING_MODE_FDT)
        {
            /* Calculate FDT Value */
            PH_CHECK_SUCCESS_FCT(status, PN76_Clif_PCD_GetExchgFdt(&dwTimingSingle, pDataParams->bTimeoutUnit, pDataParams->bTimerDeviation));

            /* FDT single -> replace the previous value */
            if (0U != (pDataParams->wTimingMode & PHHAL_HW_TIMING_MODE_OPTION_AUTOCLEAR))
            {
                pDataParams->dwTimingUs = dwTimingSingle;
            }
            /* FDT -> add current value to current count */
            else
            {
                /* Check for overflow */
                if ((0xFFFFFFFFU - pDataParams->dwTimingUs) < dwTimingSingle)
                {
                    pDataParams->dwTimingUs = 0xFFFFFFFFU;
                }
                /* Update global timing value */
                else
                {
                    pDataParams->dwTimingUs = pDataParams->dwTimingUs + dwTimingSingle;
                }
            }
        }
    }
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
    /* Reset TxLastBits */
    if (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] != 0U)
    {
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_TXLASTBITS, 0x00U));
    }

    if (pDataParams->bJewelActivated == PH_ON)
    {
        /* Reset Timer1 (FDT Timer) start condition to Tx Ended instead of Tx Frame Step detected. */
        PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_CLEARREG_MASK(CLIF_TIMER1_CONFIG, (uint32_t )~(CLIF_TIMER1_CONFIG_T1_START_ON_TX_FRAMESTEP_MASK)));
        PH_CHECK_SUCCESS_FCT(statusTmp, CLIF_SETREG_MASK(CLIF_TIMER1_CONFIG, CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK));
    }

    if((status == PH_ERR_SUCCESS) || (status == PH_ERR_SUCCESS_INCOMPLETE_BYTE) || (status == PH_ERR_INTEGRITY_ERROR))
    {
        if (status != PH_ERR_SUCCESS)
        {
            pDataParams->wAdditionalInfo = bRxParams.bRxBits;
        }

        *ppRxBuffer = (uint8_t *)(&pDataParams->pRxBuffer[0]);

        *pRxLength = bRxParams.wRxBytes;

        if ((0U != (pDataParams->wRxBufStartPos)) && (status != PH_ERR_INTEGRITY_ERROR))
        {
            *pRxLength = *pRxLength + (pDataParams->wRxBufStartPos);
        }
    }
    /* considering the case for collision */
    else if (status == PH_ERR_COLLISION_ERROR)
    {
        wNumByteReceived = ((uint16_t)bRxParams.bRxCollPos >> 3U);

        /* Extracting valid bits from Collision position */
        if(bRxParams.bRxCollPos >= 8U)
        {
            dwValue = bRxParams.bRxCollPos % 8U ;
        }
        else
        {
            dwValue = bRxParams.bRxCollPos;
        }

        /* Increment no of bytes received in case of incomplete bits received. */
        if (0U != (dwValue))
        {
             ++wNumByteReceived;
        }

        /* Store valid bits of last byte */
        pDataParams->wAdditionalInfo = (uint16_t)dwValue;

        *ppRxBuffer = (uint8_t *)(&pDataParams->pRxBuffer[0]);
        *pRxLength = wNumByteReceived;
    }
    else
    {
        if (status == PN76_CLIF_STATUS_NO_RF_FIELD)
        {
            status = PH_ERR_IO_TIMEOUT;
        }
        *pRxLength = 0;
    }
    pDataParams->wRxBufLen = *pRxLength;
    pDataParams->wTxBufLen = 0x00;

    if ((ExchgStatus & PH_ERR_MASK) == PH_ERR_IO_TIMEOUT)
    {
       /* Reset after timeout behavior */
       if (pDataParams->bRfResetAfterTo != PH_OFF)
       {
           PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_FieldReset(pDataParams));
       }
    }

    return PH_ADD_COMPCODE(status, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_Transmit(
                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                   uint16_t wOption,
                                   uint8_t * pTxBuffer,
                                   uint16_t wTxLength
                                   )
{
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t *   PH_MEMLOC_REM pTmpBuffer = NULL;
    uint16_t    PH_MEMLOC_REM wTmpBufferLen = 0;
    uint16_t    PH_MEMLOC_REM wTmpBufferSize;

    if (0U != (wTxLength))
    {
        if ((PH_TRANSMIT_PREV_FRAME & wOption) == 0U)
        {
            PH_ASSERT_NULL(pTxBuffer);
        }
    }

    /* Check options */
    if (wOption & (uint16_t)~(uint16_t)(PH_TRANSMIT_BUFFERED_BIT | PH_TRANSMIT_LEAVE_BUFFER_BIT | PH_TRANSMIT_PREV_FRAME))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Re-send option should not be combined with buffer options. */
    if ((wOption & PH_TRANSMIT_PREV_FRAME) && (wOption & (uint16_t)~(uint16_t)(PH_TRANSMIT_PREV_FRAME)))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* In Target Mode it's not allowed to have same buffers for transmission and reception
    *  since the data to transmit would get overwritten by received data. */
    if ((pDataParams->wTargetMode != PH_OFF) &&
        (pDataParams->pTxBuffer == pDataParams->pRxBuffer))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_HAL);
    }

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_Int_GetTxBuffer(pDataParams, &pTmpBuffer, &wTmpBufferLen, &wTmpBufferSize));

    if ((PH_TRANSMIT_PREV_FRAME & wOption) != 0U)
    {
        /* Length to be transmitted should not be zero and should not be in Reader Mode */
        if ( (pDataParams->wTargetMode == PH_OFF) || (wTxLength == 0x00U) )
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
        }
        /* Check parameter, must not exceed TxBufferSize */
        else if (wTxLength > wTmpBufferSize)
        {
            return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
        }
        else
        {
            pDataParams->wTxBufLen = wTxLength;
            wTxLength = 0U;
        }
    }

    if (!(wOption & (PH_TRANSMIT_LEAVE_BUFFER_BIT | PH_TRANSMIT_PREV_FRAME)))
    {
        pDataParams->wTxBufLen = 0U;
        pDataParams->wTxBufStartPos = 0U;
    }

    if (wTxLength != 0U)
    {
        if (wTxLength > (wTmpBufferSize - wTmpBufferLen))
        {
            pDataParams->wTxBufLen = 0U;
            pDataParams->wTxBufStartPos = 0U;
            return PH_ADD_COMPCODE_FIXED(PH_ERR_BUFFER_OVERFLOW, PH_COMP_HAL);
        }
        (void)memcpy(&pTmpBuffer[pDataParams->wTxBufStartPos + pDataParams->wTxBufLen], pTxBuffer, wTxLength);
        pDataParams->wTxBufLen += wTxLength;
    }

    wTxLength = 0U;

    if (0U != (wOption & PH_EXCHANGE_BUFFERED_BIT))
    {
        return PH_ERR_SUCCESS;
    }

    pDataParams->wTxBufLen += pDataParams->wTxBufStartPos;

    status = PN76_Clif_Transmit(pTmpBuffer, pDataParams->wTxBufLen);
    PH_CHECK_ABORT(status);

    /* Reset TxLastBits */
    if (pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXLASTBITS] != 0)
    {
        PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_TXLASTBITS, 0x00));
    }

    pDataParams->wTxBufStartPos = 0U;
    /* Reset buffered bytes */
    pDataParams->wTxBufLen = 0U;

    return PH_ADD_COMPCODE(status, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_Receive(
                                  phhalHw_Pn76xx_DataParams_t * pDataParams,
                                  uint16_t wOption,
                                  uint8_t ** ppRxBuffer,
                                  uint16_t * pRxLength
                                  )
{
    phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    phStatus_t  PH_MEMLOC_REM statusTmp;
    uint8_t *   PH_MEMLOC_REM pTmpBuffer = NULL;
    uint16_t    PH_MEMLOC_REM wTmpBufferLen = 0;
    uint16_t    PH_MEMLOC_REM wTmpBufferSize;
    PN76_Rf_RxParams_t        bRxParams = {0};

    /* Validate input parameters. */
    if ((wOption != 0U) || (ppRxBuffer == NULL) || (pRxLength == NULL))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    pDataParams->wRxBufLen = 0U;

    PH_CHECK_SUCCESS_FCT(statusTmp, phhalHw_Pn76xx_Int_GetRxBuffer(pDataParams, &pTmpBuffer, &wTmpBufferLen, &wTmpBufferSize));

    /* Wait for the Data to be received */
    status = PN76_Clif_Receive(pTmpBuffer, wTmpBufferSize, &bRxParams);

    /* Reset for the next transaction */
    pDataParams->wTxBufStartPos = 0U;
    pDataParams->wTxBufLen = 0U;
    if((status == PH_ERR_SUCCESS) || (status == PH_ERR_SUCCESS_INCOMPLETE_BYTE) || (status == PH_ERR_INTEGRITY_ERROR))
    {
        if (status != PH_ERR_SUCCESS)
        {
            pDataParams->wAdditionalInfo = bRxParams.bRxBits;
        }

        *ppRxBuffer = (uint8_t *)(&pDataParams->pRxBuffer[0]);

        *pRxLength = bRxParams.wRxBytes;

        if ((0U != (pDataParams->wRxBufStartPos)) && (status != PH_ERR_INTEGRITY_ERROR))
        {
            *pRxLength = *pRxLength + (pDataParams->wRxBufStartPos);
        }
    }
    /* considering the case for collision */
    else if (status == PH_ERR_COLLISION_ERROR)
    {
        *ppRxBuffer = (uint8_t *)(&pDataParams->pRxBuffer[0]);
        *pRxLength = bRxParams.wRxBytes;

        bRxParams.bRxBits = (uint8_t)(bRxParams.bRxCollPos + 8 - (*pRxLength * 8U));
        if(0U != (pDataParams->wRxBufStartPos))
        {
            *pRxLength = *pRxLength + (pDataParams->wRxBufStartPos);
        }
        if (bRxParams.bRxBits == 0U)
        {
            *pRxLength = *pRxLength - 1;
        }
    }
    else
    {
        if (status == PN76_CLIF_STATUS_NO_RF_FIELD)
        {
            status = PH_ERR_IO_TIMEOUT;
        }
        *pRxLength = 0;
    }
    pDataParams->wRxBufLen = *pRxLength;
    pDataParams->wTxBufLen = 0x00;

    return PH_ADD_COMPCODE(status, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_Autocoll(
                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                   uint16_t wMode,
                                   uint8_t ** ppRxBuffer,
                                   uint16_t * pRxLength,
                                   uint16_t * pProtParams
                                   )
{
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    uint8_t    PH_MEMLOC_REM offsetPos = 0U;
    uint8_t    PH_MEMLOC_REM offsetLen = 0U;

    uint8_t   PH_MEMLOC_REM bRfTechnology = 0U;

    uint8_t     PH_MEMLOC_REM bTypeA_CRC = 0;
    uint8_t     PH_MEMLOC_REM bTypeF_CRC = 0;
    uint16_t    PH_MEMLOC_REM wCrcIn = 0;
    uint16_t    PH_MEMLOC_REM wCrcCalc = 0;

    /* Check all the pointers */
    PH_ASSERT_NULL(ppRxBuffer);
    PH_ASSERT_NULL(pRxLength);
    PH_ASSERT_NULL(pProtParams);

    PN76_Autocoll_Status sAutocollStat;
    uint8_t  *pAutocoll_Buffer;
    uint16_t  wLength;

    /* Disable the EMD. */
    PH_CHECK_SUCCESS_FCT(status, phhalHw_Pn76xx_SetConfig(pDataParams, PHHAL_HW_CONFIG_SET_EMD, PH_OFF));

    if(pDataParams->bCardMode == PH_ON)
    {
        bRfTechnology = PN76_CLIF_PAS_A_MODE_ENABLE;
    }
    else
    {
        /* RFTech A */
        if((wMode & A_MODE) == A_MODE)
        {
            bRfTechnology |= PN76_CLIF_PAS_A_MODE_ENABLE;
        }
        /* RFTech F */
        if((wMode & F_MODE) == F_MODE)
        {
            bRfTechnology |= PN76_CLIF_PAS_F_MODE_ENABLE;
        }
        /* RFTech Active A */
        if((wMode & ACTIVE_A_MODE) == ACTIVE_A_MODE)
        {
            bRfTechnology |= PN76_CLIF_ACT_A_MODE_ENABLE;
        }
        /* RFTech Active F */
        if((wMode & ACTIVE_F_MODE) == ACTIVE_F_MODE)
        {
            bRfTechnology |= PN76_CLIF_ACT_F_MODE_ENABLE;
        }
        /* RFTech B and Active B */
        if(((wMode & B_MODE) == B_MODE)||((wMode & ACTIVE_B_MODE) == ACTIVE_B_MODE))
        {
            /* Do nothing, ignore -- NFCP576 -- as the NFC forum DTA application expects success for Listen B */
            return PH_ERR_SUCCESS;
        }
    }
    /* set the receive length */
    *pRxLength = 0U;

    pDataParams->wRxBufLen = 0U;

    /* Reset the Flag used to indicate if Passive Target is activated by ISO/IEC 18092 Frame */
    pDataParams->wTargetMode = PH_OFF;
    pDataParams->bActiveMode = PH_OFF;
    pDataParams->bNfcipMode  = PH_OFF;

    status = PN76_Clif_Autocoll(bRfTechnology,
                               PN76_AUTOCOLL_WITHOUT_AUTONOMOUS_MODE,
                               &sAutocollStat,
                               &pAutocoll_Buffer,
                               &wLength);

    if (status == PH_ERR_SUCCESS)
    {
        switch(sAutocollStat.eProtocol)
        {
            case PN76_AUTOCOLL_MODE_PASSIVE_A:
               *pProtParams = PHHAL_HW_RF_TYPE_A_FRAMING | PHHAL_HW_RF_DATARATE_106;
               break;
            case PN76_AUTOCOLL_MODE_PASSIVE_F212:
               *pProtParams = PHHAL_HW_RF_TYPE_F_FRAMING | PHHAL_HW_RF_DATARATE_212;
               break;
            case PN76_AUTOCOLL_MODE_PASSIVE_F424:
               *pProtParams = PHHAL_HW_RF_TYPE_F_FRAMING | PHHAL_HW_RF_DATARATE_424;
               break;
            case PN76_AUTOCOLL_MODE_ACTIVE_A:
               *pProtParams = PHHAL_HW_RF_TYPE_ACTIVE_FRAMING | PHHAL_HW_RF_DATARATE_106;
               bTypeA_CRC = 1;
               break;
            case PN76_AUTOCOLL_MODE_ACTIVE_F212:
               *pProtParams = PHHAL_HW_RF_TYPE_ACTIVE_FRAMING | PHHAL_HW_RF_DATARATE_212;
               bTypeF_CRC = 1;
               break;
            case PN76_AUTOCOLL_MODE_ACTIVE_F424:
               *pProtParams = PHHAL_HW_RF_TYPE_ACTIVE_FRAMING | PHHAL_HW_RF_DATARATE_424;
               bTypeF_CRC = 1;
               break;
            default:
               /* Invalid Framing as Pn76xx will not emulate other than Type-A, Type-F and Active Frame */
               return PH_ADD_COMPCODE_FIXED(PH_ERR_FRAMING_ERROR, PH_COMP_HAL);
        }

        /* Disable active mode */
        if(((*pProtParams & PHHAL_HW_RF_DATARATE_OPTION_MASK) == PHHAL_HW_RF_DATARATE_106) && (pAutocoll_Buffer[0] == PHHAL_HW_PN76XX_I18092MT_START_BYTE))
        {
            /* Offset for StartByte as it included if Passive Communication in ISO/IEC 18092 */
            offsetPos = 1U;
            offsetLen = 1U;
        }

        if((*pProtParams & PHHAL_HW_RF_FRAMING_OPTION_MASK) == PHHAL_HW_RF_TYPE_ACTIVE_FRAMING)
        {
            pDataParams->bActiveMode = PH_ON;
        }

        /* At-least a byte data + 2 bytes of crc.  */
        if(wLength >= 3)
        {
            if ((bTypeA_CRC == 0x1U) || (bTypeF_CRC == 0x1U))
            {
                if (bTypeA_CRC == 0x1U)
                {
                    /* Retrieve CRC */
                    wCrcIn  = (uint16_t)(((uint16_t)pAutocoll_Buffer[(wLength) - 1U]) << 8U);
                    wCrcIn |= (uint16_t)(pAutocoll_Buffer[(wLength) - 2U]);

                    /* Remove CRC from input data */
                    wLength -= 2U;

                    /* Calculate CRC */
                    PH_CHECK_SUCCESS_FCT(status, phTools_CalculateCrc16(
                                PH_TOOLS_CRC_OPTION_DEFAULT,
                                PH_TOOLS_CRC16_PRESET_ISO14443A,
                                PH_TOOLS_CRC16_POLY_ISO14443,
                                pAutocoll_Buffer,
                                wLength,
                                &wCrcCalc));
                }
                else if (bTypeF_CRC == 0x1U)
                {
                    /* Retrieve CRC */
                    wCrcIn = (uint16_t)(pAutocoll_Buffer[(wLength) - 1U]);
                    wCrcIn |= (uint16_t)(((uint16_t)pAutocoll_Buffer[(wLength) - 2U]) << 8U);

                    /* Remove CRC from input data */
                    wLength -= 2U;

                    /* Calculate CRC */
                    PH_CHECK_SUCCESS_FCT(status, phTools_CalculateCrc16(
                                PH_TOOLS_CRC_OPTION_MSB_FIRST,
                                PH_TOOLS_CRC16_PRESET_FELICA,
                                PH_TOOLS_CRC16_POLY_FELICA,
                                pAutocoll_Buffer,
                                wLength,
                                &wCrcCalc));
                }
                /* CRC Check -> Compare input and calculated crc */
                if (wCrcIn == wCrcCalc)
                {
                    status = PH_ERR_SUCCESS;
                }
                else
                {
                    return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_HAL);
                }
            }
            else
            {
               /* Remove CRC from input data */
               wLength -=2;
            }

            /* Store received data length in dataparams */
            pDataParams->wRxBufLen = wLength;
            memcpy(pDataParams->pRxBuffer, pAutocoll_Buffer, wLength);

            /* Return RxBuffer pointer */
            /* Offset "F0" incase of Active communication */
            *ppRxBuffer = pDataParams->pRxBuffer + offsetPos;

            /* Return RxBuffer length */
            /* Offset "F0" + CRC incase of Active communication */
            *pRxLength = pDataParams->wRxBufLen - offsetLen;

            pDataParams->wTargetMode = *pProtParams;

            pDataParams->wCfgShadow[PHHAL_HW_CONFIG_RXDATARATE_FRAMING] = *pProtParams;
            pDataParams->wCfgShadow[PHHAL_HW_CONFIG_TXDATARATE_FRAMING] = *pProtParams;
        }
        else
        {
           return PH_ADD_COMPCODE_FIXED(PH_ERR_INTEGRITY_ERROR, PH_COMP_HAL);
        }
    }

    return PH_ADD_COMPCODE(status, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_Wait(
                               phhalHw_Pn76xx_DataParams_t * pDataParams,
                               uint8_t bUnit,
                               uint16_t wTimeout
                               )
{
    phStatus_t PH_MEMLOC_REM wStatus;

    wStatus = PN76_Clif_Wait((PN76_ClifTimerUnits_t)(bUnit), wTimeout);

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_LPCD_SetConfig(
                                         phhalHw_Pn76xx_DataParams_t * pDataParams,
                                         uint16_t wConfig,
                                         uint32_t dwValue
                                         )
{

   phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
#ifdef NXPBUILD__PHHAL_HW_PN7642

    switch(wConfig)
    {
    case PHHAL_HW_CONFIG_SET_LPCD_WAKEUPTIME_MS:
    {
        /* Value should be greater than 3ms */
        if(dwValue >= 0x03U)
        {
            pDataParams->wLPCDWakeupCounterInMs = dwValue;
        }
        else
        {
            pDataParams->wLPCDWakeupCounterInMs = 0x03U;
        }
     }
     break;

    case PHHAL_HW_CONFIG_LPCD_MODE:
        if((dwValue == PHHAL_HW_PN76XX_LPCD_MODE_DEFAULT) || (dwValue ==  PHHAL_HW_PN76XX_LPCD_MODE_POWERDOWN))
        {
            pDataParams->bLpcdMode = (uint8_t)dwValue;
        }
        else
        {
            wStatus = PH_ERR_INVALID_PARAMETER;
        }
        break;

    default:
        wStatus = PH_ERR_UNSUPPORTED_PARAMETER;
        break;
    }

    wStatus = PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
#ifdef NXPBUILD__PHHAL_HW_PN7640
    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7640 */
    return wStatus;
}

phStatus_t phhalHw_Pn76xx_LPCD_GetConfig(
                                         phhalHw_Pn76xx_DataParams_t * pDataParams,
                                         uint16_t wConfig,
                                         uint32_t * pValue
                                         )
{
   phStatus_t  PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
    /* Check all the pointers */
    PH_ASSERT_NULL(pValue);
#ifdef NXPBUILD__PHHAL_HW_PN7642
    switch(wConfig)
    {
    case PHHAL_HW_CONFIG_SET_LPCD_WAKEUPTIME_MS:
        *pValue = pDataParams->wLPCDWakeupCounterInMs;
        break;

    case PHHAL_HW_CONFIG_LPCD_MODE:
        *pValue = pDataParams->bLpcdMode;
        break;

    case PHHAL_HW_CONFIG_LPCD_REF_VAL:
        *pValue = pDataParams->dwLpcdRefVal;
        break;

    default:
       wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_PARAMETER, PH_COMP_HAL);
    }

    wStatus = PH_ERR_SUCCESS;
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
#ifdef NXPBUILD__PHHAL_HW_PN7640
    wStatus = PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7640 */
    return wStatus;
}

phStatus_t phhalHw_Pn76xx_Lpcd(
                               phhalHw_Pn76xx_DataParams_t * pDataParams
                               )
{
   phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;
#ifdef NXPBUILD__PHHAL_HW_PN7642

    uint8_t    PH_MEMLOC_REM bCalibrationEn = 0;
    uint32_t   PH_MEMLOC_REM dwLpcdRefValue = 0;

    if (pDataParams->bLpcdMode == PHHAL_HW_PN76XX_LPCD_MODE_DEFAULT)
    {
        bCalibrationEn = 1;

        wStatus = PN76_Clif_LPCD(pDataParams->wLPCDWakeupCounterInMs, bCalibrationEn, &dwLpcdRefValue);
        pDataParams->dwLpcdRefVal = dwLpcdRefValue;
    }
    else
    {
       do
       {
          wStatus = PN76_Clif_LPCD(pDataParams->wLPCDWakeupCounterInMs, bCalibrationEn, NULL);
       }while(wStatus == PN76_CLIF_STATUS_TIMEOUT);
    }

    wStatus = PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#ifdef NXPBUILD__PHHAL_HW_PN7640
    wStatus = PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

    return wStatus;
}

phStatus_t phhalHw_Pn76xx_MfcAuthenticateKeyNo(
                                               phhalHw_Pn76xx_DataParams_t * pDataParams,
                                               uint8_t bBlockNo,
                                               uint8_t bKeyType,
                                               uint16_t wKeyNo,
                                               uint16_t wKeyVersion,
                                               uint8_t * pUid
                                               )
{
#if defined(NXPBUILD__PH_KEYSTORE)
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    uint8_t    PH_MEMLOC_BUF aKey[PHHAL_HW_MFC_KEY_LENGTH * 2];
    uint8_t *  PH_MEMLOC_REM pKey;
    uint16_t   PH_MEMLOC_REM bKeystoreKeyType = 0U;

    /* Bail out if we haven't got a key-store */
    if (pDataParams->pKeyStoreDataParams == NULL)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_USE_CONDITION, PH_COMP_HAL);
    }

    /* Retrieve KeyA & KeyB from key-store */
    status = phKeyStore_GetKey(
        pDataParams->pKeyStoreDataParams,
        wKeyNo,
        wKeyVersion,
        sizeof(aKey),
        aKey,
        &bKeystoreKeyType);

    /* Change component code for invalid parameter */
    if ((status & PH_ERR_MASK) == PH_ERR_INVALID_PARAMETER)
    {
        return PH_ADD_COMPCODE((status & PH_ERR_MASK), PH_COMP_HAL);
    }
    else
    {
        PH_CHECK_SUCCESS(status);
    }

    /* Check key type */
    if (bKeystoreKeyType != PH_KEYSTORE_KEY_TYPE_MIFARE)
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Evaluate which key to use */
    if (bKeyType == PHHAL_HW_MFC_KEYA)
    {
        /* Use KeyA */
        pKey = aKey;
    }
    else if (bKeyType == PHHAL_HW_MFC_KEYB)
    {
        /* Use KeyB */
        pKey = &aKey[PHHAL_HW_MFC_KEY_LENGTH];
    }
    else
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    /* Call the authentication function using the key */
    return phhalHw_Pn76xx_MfcAuthenticate(
        pDataParams,
        bBlockNo,
        bKeyType,
        pKey,
        pUid);
#else /* NXPBUILD__PH_KEYSTORE */
    PH_UNUSED_VARIABLE(pDataParams);
    PH_UNUSED_VARIABLE(bBlockNo);
    PH_UNUSED_VARIABLE(bKeyType);
    PH_UNUSED_VARIABLE(wKeyNo);
    PH_UNUSED_VARIABLE(wKeyVersion);
    PH_UNUSED_VARIABLE(pUid);
    return PH_ADD_COMPCODE_FIXED(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PH_KEYSTORE */
}

phStatus_t phhalHw_Pn76xx_MfcAuthenticate(
                                          phhalHw_Pn76xx_DataParams_t * pDataParams,
                                          uint8_t bBlockNo,
                                          uint8_t bKeyType,
                                          uint8_t * pKey,
                                          uint8_t * pUid
                                          )
{
    phStatus_t PH_MEMLOC_REM status = PH_ERR_SUCCESS;
    uint8_t    PH_MEMLOC_REM bPn76KeyType;
    uint32_t   PH_MEMLOC_REM dwRegister = 0;

    /* Validate input parameters */
    if ((NULL == pKey) ||
        (NULL == pUid) ||
        ((bKeyType != PHHAL_HW_MFC_KEYA) && (bKeyType != PHHAL_HW_MFC_KEYB)))
    {
        return PH_ADD_COMPCODE_FIXED(PH_ERR_INVALID_PARAMETER, PH_COMP_HAL);
    }

    if(bKeyType == PHHAL_HW_MFC_KEYA)
    {
        bPn76KeyType = PN76_MFC_KEY_TYPEA;
    }
    else
    {
        bPn76KeyType = PN76_MFC_KEY_TYPEB;
    }

    status = PN76_Clif_MfcAuth(
        pKey,
        (PN76_MIFARECryptoKeys_t)(bPn76KeyType),
        bBlockNo,
        pUid);
    if(PN76_CLIF_STATUS_SUCCESS == status)
    {
       /* Check auth success */
       PH_CHECK_SUCCESS_FCT(status, CLIF_GETREG(SYSTEM_CONFIG, &dwRegister));
       if((0U == ((dwRegister & SYSTEM_CONFIG_MFC_CRYPTO_ON_MASK))))
       {
           status = PH_ERR_AUTH_ERROR;
           pDataParams->bMfcCryptoEnabled = PH_OFF;
       }
       else
       {
           pDataParams->bMfcCryptoEnabled = PH_ON;
       }
    }
    return PH_ADD_COMPCODE(status, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_I18000p3m3Inventory(
                                              phhalHw_Pn76xx_DataParams_t * pDataParams,
                                              uint8_t * pSelCmd,
                                              uint8_t bSelCmdLen,
                                              uint8_t bNumValidBitsinLastByte,
                                              uint8_t * pBeginRndCmd,
                                              uint8_t bTSprocessing,
                                              uint8_t ** ppRxBuffer,
                                              uint16_t * wRxBufferLen
                                              )
{
#ifdef NXPBUILD__PHHAL_HW_PN7642
   phStatus_t  PH_MEMLOC_REM statusTmp = PH_ERR_SUCCESS;
   phStatus_t  PH_MEMLOC_REM status = PH_ERR_SUCCESS;
   uint16_t    PH_MEMLOC_REM wResultSize;
   uint8_t     PH_MEMLOC_REM bTarget = 0U;
   uint8_t     PH_MEMLOC_REM bSession = 0U;
   uint8_t     PH_MEMLOC_COUNT bQ = 1;
   uint8_t     PH_MEMLOC_REM bBuff1, bBuff2;
   uint16_t    PH_MEMLOC_REM bIndex = 0;
   uint16_t    PH_MEMLOC_REM wNumOfSlots = 0;
   PN76_ClifEventType_t PH_MEMLOC_REM dwEventFlags = PN76_CLIF_EVT_TYPE_NONE;

   /* Reset the Rx Buffer Start Position. */
   pDataParams->wRxBufStartPos = 0;
   pDataParams->wCurrentSlotCount = 0;

   if(bSelCmdLen > 0U)
   {
       bTarget = pSelCmd[0];
       bTarget = bTarget>> 1U;
       bTarget = bTarget&0x07U;

       bSession = pBeginRndCmd[1]>> 4U;
       bSession &= 0x03U;

       switch(bSession)
       {
       case 0:
       case 2:
       {
           if(bSession != bTarget)
           {
               statusTmp = (PH_ERR_INVALID_PARAMETER | PH_COMP_HAL);
           }
           break;
       }
       default:
           statusTmp = (PH_ERR_INVALID_PARAMETER | PH_COMP_HAL);
       }

   }

   if (statusTmp != PH_ERR_SUCCESS)
   {
       return statusTmp;
   }

   if (bTSprocessing == PHHAL_HW_I18000P3M3_GET_MAX_RESPS)
   {
       bSelCmdLen = 0U;
   }

   if (pDataParams->bPollGuardTimeFlag == PH_ON)
   {
       pDataParams->bPollGuardTimeFlag = PH_OFF;

       status = PN76_Clif_EventWaitAny(PHOSAL_MAX_DELAY, &dwEventFlags);
       if (status == PH_ERR_SUCCESS)
       {
           /* When there is no errors in preconditions wait till timer expire. */
           if (0U != (dwEventFlags & PN76_CLIF_EVT_TYPE_ABORTED))
           {
               statusTmp = PH_ERR_ABORTED;
           }
           else if (0U != (dwEventFlags & PN76_CLIF_EVT_TYPE_TIMER0))
           {
               statusTmp = PH_ERR_SUCCESS;
           }
           else
           {
               statusTmp = PH_ERR_INTERNAL_ERROR;
           }
       }
   }

   status = phhalHw_Pn76xx_Int_EpcGen2Inventory(
           pDataParams,
           pSelCmd,
           bSelCmdLen,
           bNumValidBitsinLastByte,
           pBeginRndCmd,
           bTSprocessing,
           ppRxBuffer,
           &wResultSize
           );
   PH_CHECK_ABORT(status);

   if (status == PH_ERR_SUCCESS)
   {
       /*Retrieve the result size and result*/
       *wRxBufferLen = wResultSize;

       if (wResultSize > 0U)
       {
           /* Response length is 3bytes by default. With 1st byte indicating Response status.
            * If 1st Byte has value '2' it indicates there is no response in any Timeslot,
            * all other values indicate response availability.(As specified in PN7642 Instruction Layer document) */

           /* Extract bQ value from pBeginRndCmd */
           bBuff1 = *(pBeginRndCmd + 1) & (uint8_t)0x7;
           bBuff2 = *(pBeginRndCmd + 2) & (uint8_t)0x80;

           bQ = (bBuff1 << 1) | (bBuff2 >> 7);

           wNumOfSlots = 1 << bQ;

           while (0U != wNumOfSlots)
           {
               /* Do not proceed if available buffer is not enough to accommodate further exchanges */
               if (bIndex >= wResultSize)
               {
                   /* Backup the relevant data for Resume Inventory */
                   pDataParams->wCurrentSlotCount = wNumOfSlots;

                   status = PH_ERR_SUCCESS_CHAINING;
                   break;
               }
               else
               {
                   if ((*ppRxBuffer)[bIndex] == 0U)
                   {
                       bIndex += (*ppRxBuffer)[bIndex + 1];
                   }
                   else if (((*ppRxBuffer)[bIndex] == 2U)
                       && ((*ppRxBuffer)[bIndex + 1] == 0U)
                       && ((*ppRxBuffer)[bIndex + 2] == 0U))
                   {
                       status = PH_ERR_IO_TIMEOUT;
                   }
                   else if (((*ppRxBuffer)[bIndex] == 3U)
                       && ((*ppRxBuffer)[bIndex + 1] == 0U)
                       && ((*ppRxBuffer)[bIndex + 2] == 0U))
                   {
                       status = PH_ERR_COLLISION_ERROR;

                       if((bTSprocessing & PHHAL_HW_I18000P3M3_ONE_TS_ONLY) ||
                           (bTSprocessing & PHHAL_HW_I18000P3M3_GET_TAG_HANDLE))
                       {
                           break;
                       }
                   }
                   else if ((*ppRxBuffer)[bIndex] == 1U)
                   {
                       bIndex += (*ppRxBuffer)[bIndex + 1];
                   }
                   else
                   {
                       status = PH_ERR_IO_TIMEOUT;
                   }

                   bIndex += 3U;
                   wNumOfSlots--;
               }
           }
       }
       else
       {
           status = PH_ERR_INTERNAL_ERROR;
       }
   }
   else
   {
       status = PH_ERR_IO_TIMEOUT;
   }

   return PH_ADD_COMPCODE(status, PH_COMP_HAL);
#else  /* NXPBUILD__PHHAL_HW_PN7642 */
   return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
}

phStatus_t phhalHw_Pn76xx_18000p3m3ResumeInventory(
                                                   phhalHw_Pn76xx_DataParams_t * pDataParams,
                                                   uint8_t ** ppRxBuffer,
                                                   uint16_t * wRxBufferLen
                                                   )
{
#ifdef NXPBUILD__PHHAL_HW_PN7642
   phStatus_t  PH_MEMLOC_REM status = PH_ERR_IO_TIMEOUT;
   uint16_t    PH_MEMLOC_REM wResultSize;
   uint16_t    PH_MEMLOC_REM bIndex = 0;
   uint16_t    PH_MEMLOC_REM wNumOfSlots = 0;

   status = phhalHw_Pn76xx_Int_EpcGen2ResumeInventory(
           pDataParams,
           ppRxBuffer,
           &wResultSize);
   PH_CHECK_ABORT(status);

   if (status == PH_ERR_SUCCESS)
   {
       /*Retrieve the result size and result*/
       *wRxBufferLen = wResultSize;

       if (wResultSize > 0U)
       {
           /* Response length is 3bytes by default. With 1st byte indicating Response status.
            * If 1st Byte has value '2' it indicates there is no response in any Timeslot,
            * all other values indicate response availability.(As specified in PN7642 Instruction Layer document) */
           wNumOfSlots = pDataParams->wCurrentSlotCount;
           pDataParams->wCurrentSlotCount = 0;

           while (0U != wNumOfSlots)
           {
               /* Do not proceed if available buffer is not enough to accommodate further exchanges */
               if (bIndex >= wResultSize)
               {
                   /* Backup the relevant data for Resume Inventory */
                   pDataParams->wCurrentSlotCount = wNumOfSlots;

                   status = PH_ERR_SUCCESS_CHAINING;
                   break;
               }
               else
               {
                   if ((*ppRxBuffer)[bIndex] == 0U)
                   {
                       bIndex += (*ppRxBuffer)[bIndex + 1];
                   }
                   else if (((*ppRxBuffer)[bIndex] == 2)
                       && ((*ppRxBuffer)[bIndex + 1] == 0)
                       && ((*ppRxBuffer)[bIndex + 2] == 0))
                   {
                       status = PH_ERR_IO_TIMEOUT;
                   }
                   else if (((*ppRxBuffer)[bIndex] == 3)
                       && ((*ppRxBuffer)[bIndex + 1] == 0)
                       && ((*ppRxBuffer)[bIndex + 2] == 0))
                   {
                       status = PH_ERR_COLLISION_ERROR;
                   }
                   else
                   {
                       status = PH_ERR_IO_TIMEOUT;
                   }

                   bIndex += 3U;
                   wNumOfSlots--;
               }
           }
       }
       else
       {
           status = PH_ERR_INTERNAL_ERROR;
       }
   }
   else
   {
       status = PH_ERR_IO_TIMEOUT;
   }

   return PH_ADD_COMPCODE(status, PH_COMP_HAL);
#else
   return PH_ADD_COMPCODE(PH_ERR_UNSUPPORTED_COMMAND, PH_COMP_HAL);
#endif /* NXPBUILD__PHHAL_HW_PN7642 */
}

phStatus_t phhalHw_Pn76xx_EventWait(
                                    phhalHw_Pn76xx_DataParams_t * pDataParams,
                                    uint32_t dwEventTimeout
                                    )
{
    phStatus_t PH_MEMLOC_REM wStatus = PH_ERR_SUCCESS;

    PN76_ClifEventType_t dwReceivedEvents = PN76_CLIF_EVT_TYPE_NONE;
    PH_CHECK_SUCCESS_FCT(wStatus, PN76_Clif_EventWaitAny(dwEventTimeout, &dwReceivedEvents));

    if (pDataParams->dwExpectedEvent == PH_PN76XX_EVT_RFON_DETECT)
    {
       if ((dwReceivedEvents & PN76_CLIF_EVT_TYPE_FLDON_EX) == 0U)
       {
          wStatus = PH_ERR_INTERNAL_ERROR;
       }
       pDataParams->dwExpectedEvent = 0U;
    }

    return PH_ADD_COMPCODE(wStatus, PH_COMP_HAL);
}

phStatus_t phhalHw_Pn76xx_EventConsume(
                                       phhalHw_Pn76xx_DataParams_t * pDataParams
                                       )
{
    PN76_Clif_EventConsumeAll();
    return PH_ERR_SUCCESS;
}

#endif  /* NXPBUILD__PHHAL_HW_PN76XX */
