/*----------------------------------------------------------------------------*/
/* Copyright 2019-2023 NXP                                                    */
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
/*
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "ph_Datatypes.h"
#include "fsl_power.h"
#include "stdlib.h"
#include "PN76_Reg_Interface.h"
#include "PN76_Pcrm.h"
#include "PN76_Eeprom.h"
#include "PN76_Clif.h"
#include "Pcrm_Hp_Reg.h"
#include "Pcrm_Lp_Reg.h"
#include "PN76_UserAreaAdd.h"
#include "PN76_UtilsHelper.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.power"
#endif

#define PMU_ANA_VBAT_VMON_THRES_POS  (14U)
#define PMU_ANA_VBAT_VMON_THRES_MASK (0x4000UL)
#define PMU_ANA_VBAT_VMON_EN_POS     (15U)
#define PMU_ANA_VBAT_VMON_EN_MASK    (0x8000UL)
#define PMU_VBAT_VMON_REG_MASK       (0x0FFFUL)

#define PMU_VBAT_MONITOR_CONFIG_EE_ADDR         0x8E7U
#define PMU_VBAT_MONITOR_STANDBY_CONFIG_EE_ADDR 0x8E9U

#define SMU_ENABLE_GPIO0_OVERTEMP_STBY_EE_ADDR 0x16U

#define SMU_PATCH_I2C_MASK 0x28UL

/* Definitions for  of the bTempWarning flash data parameter */
#define SMU_TEMP_WARNING_CLIF_LOW_TH_MASK  0x03UL
#define SMU_TEMP_WARNING_CLIF_LOW_TH_POS   0U
#define SMU_TEMP_WARNING_CLIF_HIGH_TH_MASK 0x0CUL
#define SMU_TEMP_WARNING_CLIF_HIGH_TH_POS  2U
#define SMU_TEMP_WARNING_PMU_LOW_TH_MASK   0x30UL
#define SMU_TEMP_WARNING_PMU_LOW_TH_POS    4U
#define SMU_TEMP_WARNING_PMU_HIGH_TH_MASK  0xC0UL
#define SMU_TEMP_WARNING_PMU_HIGH_TH_POS   6U

/** Macro to convert a 4 bytes array to uint32_t (little endian) */
#define SMU_ARRAY_TO_UINT32(a) \
    ((uint32_t)(a)[0] | ((uint32_t)(a)[1] << 8) | ((uint32_t)(a)[2] << 16) | ((uint32_t)(a)[3] << 24))

#define PCRM_FLC_GPO_2_REG_VEN_INTERNAL_MASK (0x00000200UL)
#define PCRM_FLC_GPO_2_REG_VEN_INTERNAL_POS  (9U)

#define SMU_SMU_RX_PROT_CONFIG_EE_ADDR 0x6D9U

#define HOSTIF_I2C_CONTROL_REG               (HOSTIF->I2C_CONTROL)
#define HOSTIF_I2C_CONTROL_REG_I2C_ADDR_MASK HOSTIF_I2C_CONTROL_I2C_ADDR_MASK
#define HOSTIF_I3C_DYNADDR_REG               (HOSTIF->I3C_DYNADDR)
#define HOSTIF_I3C_DYNADDR_REG_DADDR_MASK    HOSTIF_I3C_DYNADDR_DADDR_MASK
#define HOSTIF_I3C_DYNADDR_REG_DADDR_POS     HOSTIF_I3C_DYNADDR_DADDR_SHIFT

typedef struct __attribute__((__packed__))
{
    uint16_t wXtalCtrl;
    uint16_t wVddpaCtrl;
    uint8_t bAgcHfAttCtrl;
    uint8_t bTimingCtrl;
    uint16_t wTrims;
    uint8_t bTxSetGsPnTx12;
    uint8_t bVoltageCtrl;
    uint16_t wGpadcCtrl;
} phHal_Ulpcd_Config_t;

typedef struct __attribute__((__packed__))
{
    uint8_t bRssiNsp;
    uint8_t bRssiNoSamples;
    uint8_t bThreshLvl;
    uint8_t bPolarity;
} phHal_Ulpcd_Settings_t;

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint8_t bSMU_TempWarning;
volatile uint32_t dwBootReason;
static volatile uint32_t gphHal_Smu_SuspendWkpInfo;
/* silent compiler warning */
static uint32_t dwDwlPadbkup __attribute__((unused));
static uint32_t dwAuxPadBkup __attribute__((unused));
static uint32_t dwGPIOPadBkup __attribute__((unused));

static pmu_callback_t s_pmuCallback = NULL;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
__attribute__ ((weak)) void GPADC_HandleIRQ(void)
{
    /* Void implementation of the weak function. */
}

void PMU_Init(void)
{
    PN76_Sys_Hal_PCRM_Pmu_Init();

    /* To enable NS RF IRQ */
    NVIC_EnableIRQ(PCRM_IRQn);

    /* Initialize the PCRM Interrupts. */
    PCRM_SETREG(PCRM_INT_SET_ENABLE, PCRM_INT_SET_ENABLE_OVERCURRENT_IRQ_SET_ENABLE_MASK |
                                         PCRM_INT_SET_ENABLE_OVER_TEMP_PMU_IRQ_SET_ENABLE_MASK |
                                         PCRM_INT_SET_ENABLE_OVER_TEMP_NFC_IRQ_SET_ENABLE_MASK |
                                         PCRM_INT_SET_ENABLE_VDDIO_OK_IRQ_SET_ENABLE_MASK);
}

/*!
 * @brief This function configures the VBAT monitoring FSM.
 *
 * @param enableMonitor Enable/disable VBAT monitor
 * @param setStandbyCfg  Put the standby configuration if true
 */
void PMU_VbatMonitorConfig(bool enableMonitor, bool setStandbyCfg)
{
    uint16_t wRegData;

    if (enableMonitor)
    {
        if (setStandbyCfg)
        {
            (void)PN76_ReadEeprom((uint8_t *)&wRegData, (uint16_t)(uint32_t)(PN76_USER_PMU_S->VbatMonitorConfig),
                            (uint16_t)sizeof(uint16_t), E_PN76_EEPROM_SECURE_LIB_CONFIG);
        }
        else
        {
            (void)PN76_ReadEeprom((uint8_t *)&wRegData,(uint16_t)(uint32_t)(PN76_USER_PMU_S->VbatMonitorConfig),(uint16_t)sizeof(uint16_t),
                            E_PN76_EEPROM_SECURE_LIB_CONFIG);
        }

        PCRM_SETFIELDSHIFT(PCRM_PMU_ANA_VMON_CTRL, PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_THRESH_SEL_MASK,
                           PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_THRESH_SEL_POS,
                           ((wRegData & PMU_ANA_VBAT_VMON_THRES_MASK) >> PMU_ANA_VBAT_VMON_THRES_POS));
        PCRM_SETFIELDSHIFT(PCRM_PMU_ANA_VMON_CTRL, PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_EN_MASK,
                           PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_EN_POS,
                           ((wRegData & PMU_ANA_VBAT_VMON_EN_MASK) >> PMU_ANA_VBAT_VMON_EN_POS));
        PCRM_SETREG(PCRM_PMU_ANA_VBAT_MON, (wRegData & PMU_VBAT_VMON_REG_MASK));
    }
    else
    {
        PCRM_CLEARBITN(PCRM_PMU_ANA_VBAT_MON, PCRM_PMU_ANA_VBAT_MON_VBAT_MON_FSM_EN_POS);
    }
}

status_t PMU_UsbVbusCheck(void)
{
    uint32_t dwLoopMaxVal;
    uint32_t dwLoopCount;
    uint32_t dwWaitUs;
    status_t status;

    /* Program the USB VBUS Debounce time, before enabling USB VBUS monitor */
    PCRM_SETFIELDSHIFT(PCRM_DIG_VBUS_DEBOUNCE_CTRL, PCRM_DIG_VBUS_DEBOUNCE_CTRL_VBUS_DEBOUNCE_TIME_MASK,
                       PCRM_DIG_VBUS_DEBOUNCE_CTRL_VBUS_DEBOUNCE_TIME_POS, PMU_USB_VBUS_DEBOUNCE_TIMEOUT);

    /* If faster discharge is enabled in the EEPROM then set pulldown resistance to pulldown the USB_VBUS */

#if (PMU_USB_VBUS_FASTDISCHARGE_ENABLE)
    PCRM_SETBITN(PCRM_PMU_ANA_MISC_CTRL, PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_PULLDOWN_EN_POS);
#else
    PCRM_CLEARBITN(PCRM_PMU_ANA_MISC_CTRL, PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_PULLDOWN_EN_POS);
#endif

    /* Enable USB VBUS Monitor */
    PCRM_SETBITN(PCRM_PMU_ANA_MISC_CTRL, PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_MON_EN_POS);

    /* Time Out for detecting USB VBUS */
    dwWaitUs = PMU_USB_VBUSOK_WAIT_TIME;

    /* Divide it in chunks of 5 us */
    dwLoopMaxVal = (dwWaitUs / 5UL);
    dwLoopCount  = 0x00;

    do
    {
        /* check if USB VBUS is present before wait */
        if (PCRM_TESTBITN(PCRM_PMU_ANA_STS2, PCRM_PMU_ANA_STS2_USB_VBUS_PRESENT_POS))
        {
            status = kStatus_Success;
            break;
        }

        PN76_Common_Wait(5); // wait for 5 uSecs
        ++dwLoopCount;
    } while (dwLoopCount <= dwLoopMaxVal);

    /* Check if USB VBUS was not detected before TimeOut */
    if (dwLoopCount > dwLoopMaxVal)
    {
        status = kStatus_Timeout;
    }

    return status;
}

/*
 * Register PMU callback called when PMU event happens.
 */
void PMU_RegisterCallback(pmu_callback_t callback)
{
    s_pmuCallback = callback;
}

void PMU_HandleIRQ(void)
{
    uint32_t dwIrqStatus             = 0;
    uint8_t bEnableGPIO0_On_OverTemp = 0;

    dwIrqStatus = PN76_Sys_ReadRegister(PCRM_INT_STATUS);

    if ((dwIrqStatus & PCRM_INT_STATUS_VDDIO_OK_IRQ_STATUS_MASK) != 0U) /* This IT is triggered on both edges */
    {
    }

    if ((dwIrqStatus & PCRM_INT_STATUS_OVERCURRENT_IRQ_STATUS_MASK) != 0U)
    /********************************************************************************/
    {
        /* Turn OFF the boost and LDO.*/
        (void)PN76_Sys_Hal_PCRM_TxldoConfig(E_PN76_PCRM_TXDRIVER_STOP);

        PCRM_CLEARBITN(PCRM_PMU_ANA_VMON_CTRL, PCRM_PMU_ANA_VMON_CTRL_VMON_VUP_EN_POS);

        if (NULL != s_pmuCallback)
        {
            s_pmuCallback(kPMU_EventOverCurrent);
        }
    }

    /********************************************************************************/
    if (0U !=
        (dwIrqStatus & (PCRM_INT_STATUS_OVER_TEMP_PMU_IRQ_STATUS_MASK | PCRM_INT_STATUS_OVER_TEMP_NFC_IRQ_STATUS_MASK)))
    /********************************************************************************/
    {
        /* disable Temp IRQ */
        PCRM_SETREG(PCRM_INT_CLR_ENABLE, PCRM_INT_CLR_ENABLE_OVER_TEMP_PMU_IRQ_CLEAR_ENABLE_MASK |
                                             PCRM_INT_CLR_ENABLE_OVER_TEMP_NFC_IRQ_CLEAR_ENABLE_MASK);

        /* Turn off RF, which is the main source of over temperature */
        PN76_Sys_FieldOFF();

        /* Set the GPIO1 if enabled in EEPROM for over temperature irq.*/
        (void)PN76_ReadEeprom((uint8_t *)&bEnableGPIO0_On_OverTemp,(uint16_t)(uint32_t)(PN76_USER_SMU_CONFIG->bEnableGpio0OnOverTemp),
                        (uint16_t)sizeof(uint8_t), E_PN76_EEPROM_USER_AREA);
        if (0U != bEnableGPIO0_On_OverTemp)
        {
            /* Set GPIO0 before entering standby */
            PCRM_SETBITN(PCRM_PAD_GPIO0, PCRM_PAD_GPIO0_GPIO0_EN_OUT_POS);
            PCRM_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);
        }

        /* Incase of Temperature error enter the standby with temp sensor as wake up. */
        (void)PN76_Sys_PCRM_EnterStandby(E_PN76_PCRM_WAKEUP_SOURCE_TEMPSENSOR, 0);

        /* Clear the GPIO0 is the prevention reason is LOW_TEMP*/
        if (0U != bEnableGPIO0_On_OverTemp)
        {
            /* Clear GPIO0 if standby is prevented */
            PCRM_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);
        }

        if (NULL != s_pmuCallback)
        {
            s_pmuCallback(kPMU_EventOverTemp);
        }
    }

    if (0U != (dwIrqStatus & PCRM_INT_STATUS_VDDIO_OK_IRQ_STATUS_MASK))
    {
        if (NULL != s_pmuCallback)
        {
            s_pmuCallback(kPMU_EventVddioOk);
        }
    }

    /* Clear the PCRM Interrupt Status */
    PCRM_SETREG(PCRM_INT_CLR_STATUS, dwIrqStatus);
}

void PCRM_IRQHandler(void)
{
    PMU_HandleIRQ();
    GPADC_HandleIRQ();
}

void SMU_Init(void)
{
    uint32_t dwRegVal = 0;

    /* SMU Initialization */
    PN76_Sys_Hal_PCRM_Smu_Init();

    dwRegVal = PN76_Sys_ReadRegister(PCRM_INT_ENABLE);
    /* Fetch the temperature threshold from EEPROM */
    (void)PN76_ReadEeprom((uint8_t *)&bSMU_TempWarning,(uint16_t)(uint32_t)(PN76_USER_SMU_CONFIG->bTempWarning),(uint16_t)sizeof(uint8_t),
                    E_PN76_EEPROM_USER_AREA);

    if (0UL != (dwRegVal & (PCRM_INT_ENABLE_OVER_TEMP_PMU_IRQ_ENABLE_MASK | PCRM_INT_ENABLE_OVER_TEMP_NFC_IRQ_ENABLE_MASK)))
    {
        /* Configure temperature sensor */
        PCRM_SETFIELDSHIFT(
            PCRM_PMU_ANA_TEMP_SNS_CTRL, PCRM_PMU_ANA_TEMP_SNS_CTRL_NFC_OVER_TEMP_SEL_MASK,
            PCRM_PMU_ANA_TEMP_SNS_CTRL_NFC_OVER_TEMP_SEL_POS,
            (bSMU_TempWarning & SMU_TEMP_WARNING_CLIF_HIGH_TH_MASK) >> SMU_TEMP_WARNING_CLIF_HIGH_TH_POS);

        PCRM_SETFIELDSHIFT(PCRM_PMU_ANA_TEMP_SNS_CTRL, PCRM_PMU_ANA_TEMP_SNS_CTRL_PMU_OVER_TEMP_SEL_MASK,
                           PCRM_PMU_ANA_TEMP_SNS_CTRL_PMU_OVER_TEMP_SEL_POS,
                           (bSMU_TempWarning & SMU_TEMP_WARNING_PMU_HIGH_TH_MASK) >> SMU_TEMP_WARNING_PMU_HIGH_TH_POS);
    }
    else
    {
        /* Disable temperature sensor */
        PCRM_SETFIELD(
            PCRM_PMU_ANA_TEMP_SNS_CTRL,
            PCRM_PMU_ANA_TEMP_SNS_CTRL_NFC_OVER_TEMP_SEL_MASK | PCRM_PMU_ANA_TEMP_SNS_CTRL_PMU_OVER_TEMP_SEL_MASK, 0);
    }
	dwBootReason = ((PN76_HALREG_GET_REG(PCRM_SYS_BOOT1_STS) & SMU_BOOT1_STS_BOOT_REASON_MASK) << SMU_BOOT1_STS_BOOT_REASON_POS);
    dwBootReason |= (((PN76_HALREG_GET_REG(PCRM_SYS_BOOT3_STS) & SMU_BOOT3_STS_RESET_REASON_MASK) << SMU_BOOT3_STS_RESET_REASON_POS) << (SMU_BOOT1_STS_BOOT_REASON_LAST_POS + 1));
}

bool PCRM_TestBitN(uint16_t wRegAddr, uint32_t dwBitPos)
{
    uint32_t dwRegValue = 0;

    /* Read the Register content */
    dwRegValue = PN76_Sys_ReadRegister(wRegAddr);

    /* Test the given bit position */
    return ((dwRegValue & (1UL << dwBitPos)) != 0UL);
}

/*
 * brief This function checks the USB power.
 */
status_t POWER_CheckUsbPower(void)
{
    status_t status = kStatus_Success;

    do
    {
        /* Check if VDDIO is present */
        if (PN76_Sys_Hal_PCRM_GetPadPowerStatus() != E_PN76_PCRM_FULLPOWER)
        {
            /* VDDIO Not Present */
            break;
        }

#ifdef USB_VDDIO_2V1_CHK_ENABLE
        /* Perform the VDDIO Threshold check to determine if VDDIO is sufficient for USB operation. (ie: Check if VDDIO
         * HI is Ok. VDDIO>2.1V) USB communication does not work well with certain USB Bus Masters/Hubs when VDDIO is
         * less than 2.1V */
        if (!PN76_Sys_Hal_PCRM_IsVddioHiOk())
        {
            /* VDDIO Not sufficient */
            break;
        }
#endif /* USB_VDDIO_2V1_CHK_ENABLE */

        /* All Power Pre-requisites for USB Operation are checked */
        status = kStatus_Success;

    } while (false);

    return status;
}
