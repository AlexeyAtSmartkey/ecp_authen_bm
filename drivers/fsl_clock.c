/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_clock.h"
#include "PN76_Eeprom.h"
#include "PN76_Pcrm.h"
#include "PN76_Clif.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.clock"
#endif

#define CLOCK_HFO_SYS_CLK_SRC_SEL_ADDR 0xBEUL

/*******************************************************************************
 * Variables
 ******************************************************************************/
static uint32_t s_clockLpuartFreq;

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
/*!
 * @brief Start the Clif PLL.
 *
 * @return Start succeed or fail
 */
static status_t CLOCK_StartClifPll(void);

/*******************************************************************************
 * Code
 ******************************************************************************/

/*
 * brief Start the Clif PLL.
 *
 * return Start succeed or fail
 */
static status_t CLOCK_StartClifPll(void)
{
   status_t status = kStatus_Success;

   if (!PN76_Sys_RfClock_IsPllLocked())
   {
      status = (PN76_STATUS_SUCCESS == PN76_Sys_Clif_Init()) ? kStatus_Success : kStatus_Fail;
   }

   return status;
}

/*
 * brief Gets the clock frequency for a specific clock name.
 *
 * This function checks the current clock configurations and then calculates
 * the clock frequency for a specific clock name defined in clock_name_t.
 * The MCG must be properly configured before using this function.
 *
 * param clockName Clock names defined in clock_name_t
 * return Clock frequency value in Hertz
 */
uint32_t CLOCK_GetFreq(clock_name_t clockName)
{
    uint32_t freq = 0UL;

    switch (clockName)
    {
        case kCLOCK_CoreSysClk:
            freq = CLOCK_GetCoreSysClkFreq();
            break;

        default:
            /* empty. */
            break;
    }

    return freq;
}

/*
 * brief Get the core clock or system clock frequency.
 *
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetCoreSysClkFreq(void)
{
    uint8_t val   = 0U;
    uint32_t freq = 0U;

    (void)PN76_ReadEeprom(&val, (uint16_t)CLOCK_HFO_SYS_CLK_SRC_SEL_ADDR, (uint16_t)sizeof(uint8_t), E_PN76_EEPROM_IC_CONFIG);

    if (val == 1U)
    {
        freq = (CLOCK_HFO_FREQ_HZ / 2U);
    }
    else
    {
        freq = CLOCK_HFO_FREQ_HZ;
    }

    return freq;
}

/*
 * brief Start the Crystal oscillator (XTAL).
 *
 * note This function should only be used when XTAL is used as the CLIF Clock source.
 *
 * return Returns @ref kStatus_Success if succeed, otherwise returns kStatus_Fail.
 */
status_t CLOCK_InitOsc(void)
{
    PN76_Status_t pn76Status;

    do
    {
        /* Check if XTAL is already running */
        pn76Status = PN76_Sys_Hal_PCRM_StartXtal(E_PN76_PCRM_CLKGEN_XTALPHASE_IS_READY);
        if (pn76Status == PN76_STATUS_SUCCESS)
        {
            break; /* XTAL is already Running */
        }

        /* Attempt to start XTAL */
        pn76Status = PN76_Sys_Hal_PCRM_StartXtal(E_PN76_PCRM_CLKGEN_XTALPHASE_INITIAL_START);
        if (pn76Status != PN76_STATUS_SUCCESS)
        {
            break; /* Unable to start XTAL */
        }

        /* Wait till XTAL is Running */
        pn76Status = PN76_Sys_Hal_PCRM_StartXtal(E_PN76_PCRM_CLKGEN_XTALPHASE_WAIT_READY);

    } while (false);

    return (pn76Status == PN76_STATUS_SUCCESS) ? kStatus_Success : kStatus_Fail;
}

/*
 * brief Initialize the USB PLL.
 *
 * This function initializes the USB PLL to work, it tries to use XTAL clock
 * as reference clock of USB PLL, if the XTAL is not available, then tries
 * to use CLIF PLL as reference clock.
 *
 * return Return kStatus_Success if succeed, otherwise return kStatus_Fail.
 */
status_t CLOCK_InitUsbPll(void)
{
    status_t status;
    clock_usb_pll_src_t usbPllSrc;

    do
    {
        /* First Attempt to use XTAL as reference Clk for USB PLL */
        status =  CLOCK_InitOsc();

        if (kStatus_Success == status)
        {
            /* XTAL is OK. Select 27.12MHz XTAL clock as Reference clock for the USB PLL */
            usbPllSrc = kCLOCK_UsbPllSrcXtal;
        }
        else
        {
            /* XTAL not available. Attempt to fall back to HFO/CLIF PLL for reference Clock for USB PLL */
            status = CLOCK_StartClifPll();
            if(kStatus_Success != status)
            {
                break;
            }

            /* CLIF PLL is OK. Select 27.12MHz CLIF PLL clock as Reference clock for the USB PLL */
            usbPllSrc = kCLOCK_UsbPllSrcClifPll;
        }

        status = CLOCK_SetUsbPllSource(usbPllSrc);
        if(kStatus_Success != status)
        {
            break;
        }

        /* Enable USB PLL LDO and the USB PLL output. Wait for USB PLL Lock */
        status = CLOCK_StartUsbPll();

    } while(false);

    return status;
}

/*
 * brief Get the LPUART clock frequency.
 *
 * param instance The LPUART instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetLpuartClkFreq(uint8_t instance)
{
    /* TODO: Find the way to get LPUART clock source. */
    return s_clockLpuartFreq;
}

/*
 * brief Get the SPIM clock frequency.
 *
 * param instance The SPIM instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetSpiClkFreq(uint8_t instance)
{
    /* The same as core clock. */
    return CLOCK_GetCoreSysClkFreq();
}

/*
 * brief Get the I2CM clock frequency.
 *
 * param instance The I2CM instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetI2cClkFreq(uint8_t instance)
{
    /* The same as core clock. */
    return CLOCK_GetCoreSysClkFreq();
}

/*
 * brief Get the SCTimer clock frequency.
 *
 * param instance The SCTimer instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetSctClkFreq(uint8_t instance)
{
    return 45000000UL;
}

/*
 * brief Get the TIMERS(GPT) clock frequency.
 *
 * param instance The peripheral instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetGptClkFreq(uint8_t instance)
{
    /* The same as core clock. */
    return CLOCK_GetCoreSysClkFreq();
}

/*
 * brief Get the GPADC clock frequency.
 *
 * param instance The peripheral instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetGpadcClkFreq(uint8_t instance)
{
    uint8_t val   = 0U;
    uint32_t freq;

    (void)PN76_ReadEeprom(&val, (uint16_t)0xBD, (uint16_t)sizeof(uint8_t), E_PN76_EEPROM_IC_CONFIG);

    if (0U == val)
    {
        /* 0: HFO/4 */
        freq = 22500000UL;
    }
    else
    {
        /* 1: CLIF clock */
        freq = 27120000UL;
    }

    return freq;
}

/*
 * brief Get the CT clock frequency.
 *
 * param instance The peripheral instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetCtClkFreq(uint8_t instance)
{
    return 27120000UL;
}

/*
 * brief Get the CLIF clock frequency.
 *
 * param instance The peripheral instance.
 * return Clock frequency in Hz.
 */
uint32_t CLOCK_GetClifClkFreq(uint8_t instance)
{
    return 27120000UL;
}

/*
 * brief Set the LPUART clock source.
 *
 * param instance The LPUART instance.
 * param src The LPUART clock source.
 */
void CLOCK_SetLpuartClk(uint8_t instance, clock_lpuart_src_t src)
{
    PN76_Sys_PCRM_ClockEnable((PN76_PCRM_IP_Clocks_t)src);

    if (kCLOCK_LpuartSrcXtal == src)
    {
        s_clockLpuartFreq = CLOCK_XTAL_FREQ_HZ;
    }
    else
    {
        s_clockLpuartFreq = CLOCK_HFO_FREQ_HZ;
    }
}
