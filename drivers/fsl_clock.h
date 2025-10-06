/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_CLOCK_H_
#define _FSL_CLOCK_H_

#include "fsl_common.h"
#include "PN76_Pcrm.h"

/*!
 * @defgroup clock CLOCK: Clock Driver
 *
 * @{
 */

/*******************************************************************************
 * Configurations
 ******************************************************************************/

/*! @brief Configure whether driver controls clock
 *
 * When set to 0, peripheral drivers will enable clock in initialize function
 * and disable clock in de-initialize function. When set to 1, peripheral
 * driver will not control the clock, application could control the clock out of
 * the driver.
 *
 * @note All drivers share this feature switcher. If it is set to 1, application
 * should handle clock enable and disable for all drivers.
 */
#if !(defined(FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL))
#define FSL_SDK_DISABLE_DRIVER_CLOCK_CONTROL 0
#endif

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief CLOCK driver version. */
#define FSL_CLOCK_DRIVER_VERSION (MAKE_VERSION(2, 0, 1))

/* Definition for delay API in clock driver, users can redefine it to the real application. */
#ifndef SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY
#define SDK_DEVICE_MAXIMUM_CPU_CLOCK_FREQUENCY (90000000UL)
#endif

#define CLOCK_ULFO_FREQ_HZ 1000UL
#define CLOCK_LFO_FREQ_HZ  380000UL
#define CLOCK_HFO_FREQ_HZ  90000000UL
#define CLOCK_XTAL_FREQ_HZ 27120000UL
#define CLOCK_USB_PLL_FREQ_HZ 48000000UL

/*! @brief Clock ip name array for SPI. */
#define SPI_CLOCKS  \
    {               \
        kCLOCK_Spi, \
    }

/*! @brief Clock ip name array for I2C. */
#define I2C_CLOCKS  \
    {               \
        kCLOCK_I2c, \
    }

/*! @brief Clock ip name array for GPDMA. */
#define GPDMA_CLOCKS  \
    {                 \
        kCLOCK_Gpdma, \
    }

/*!
 * @brief Clock ip name array for LPUART.
 *
 * The clock is already enabled by calling CLOCK_SetLpuartClk.
 */
#define LPUART_CLOCKS     \
    {                     \
        kCLOCK_IpInvalid, \
    }

/*!
 * @brief Clock ip name array for SCTimer.
 */
#define SCT_CLOCKS  \
    {               \
        kCLOCK_Sct, \
    }

/*! @brief Clock name used to get clock frequency. */
typedef enum _clock_name
{
    /* ----------------------------- System layer clock -------------------------------*/
    kCLOCK_CoreSysClk, /*!< Core/system clock                                   */
} clock_name_t;

/*!
 * @brief Peripheral clock name difinition used for clock gate.
 */
typedef enum _clock_ip_name
{
    kCLOCK_Timer  = E_PN76_PCRM_TIMERS_CLK,  /*!< TIMER CLOCK */
    kCLOCK_Hostif = E_PN76_PCRM_HOSTIF_CLK,  /*!< HOST IF CLOCK */
    kCLOCK_Usb    = E_PN76_PCRM_USB_CLK,     /*!< USB IP CLOCK */
    kCLOCK_Spi    = E_PN76_PCRM_SPIM_CLK,    /**< SPIM IP CLOCK */
    kCLOCK_I2c    = E_PN76_PCRM_I2CM_CLK,    /**< I2CM IP CLOCK */
    kCLOCK_Ct     = E_PN76_PCRM_CT_CLK,      /**< CT IP CLOCK */
    kCLOCK_Gpdma  = E_PN76_PCRM_DMA_CLK,     /**< DMA IP CLOCK */
    kCLOCK_Sct    = E_PN76_PCRM_PWM_CLK,     /**< PWM IP CLOCK */
    kCLOCK_SctSrc45M = E_PN76_PCRM_PWM_45M_CLK,  /**< PWM 45MHz counter clock 0. */
    kCLOCK_IpInvalid = 127,                  /*!< Invalid IP clock. */
} clock_ip_name_t;

/**
 * \brief  Enum for selection of the USB PLL reference clock
 */
typedef enum _clock_usb_pll_src
{
    kCLOCK_UsbPllSrcXtal = 0, /**< 27.12MHz XTAL clock */
    kCLOCK_UsbPllSrcClifPll   /**< 27.12MHz CLIF PLL clock */
} clock_usb_pll_src_t;

/*! @brief LPUART clock source. */
typedef enum _clock_lpuart_src
{
    kCLOCK_LpuartSrcHfo    = E_PN76_PCRM_LP_UART_CLK,      /**< HFO 90M */
    kCLOCK_LpuartSrcXtal   = E_PN76_PCRM_LP_UART_XTAL_CLK, /**< XTAL 27.12M */
} clock_lpuart_src_t;

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/*!
 * @brief Performs Clock Module Initialization. This function initialize XTAL, SYSTEM CLK (HFO) and also configures the
 * clock to the CLIF Module as SYSTEM Clock till PLL is available/locked.
 */
static inline void CLOCK_InitClockGeneration(void)
{
    PN76_Sys_Hal_PCRM_Clkgen_Init();
}

/*!
 * @brief Gets the clock frequency for a specific clock name.
 *
 * This function checks the current clock configurations and then calculates
 * the clock frequency for a specific clock name defined in clock_name_t.
 * The MCG must be properly configured before using this function.
 *
 * @param clockName Clock names defined in clock_name_t
 * @return Clock frequency value in Hertz
 */
uint32_t CLOCK_GetFreq(clock_name_t clockName);

/*!
 * @brief Get the core clock or system clock frequency.
 *
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetCoreSysClkFreq(void);

/*!
 * @brief Get the LPUART clock frequency.
 *
 * @param instance The LPUART instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetLpuartClkFreq(uint8_t instance);

/*!
 * @brief Get the SPIM clock frequency.
 *
 * @param instance The SPIM instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetSpiClkFreq(uint8_t instance);

/*!
 * @brief Get the I2CM clock frequency.
 *
 * @param instance The I2CM instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetI2cClkFreq(uint8_t instance);

/*!
 * @brief Get the SCTimer clock frequency.
 *
 * @param instance The SCTimer instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetSctClkFreq(uint8_t instance);

/*!
 * @brief Get the TIMERS(GPT) clock frequency.
 *
 * @param instance The peripheral instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetGptClkFreq(uint8_t instance);

/*!
 * @brief Get the GPADC clock frequency.
 *
 * @param instance The peripheral instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetGpadcClkFreq(uint8_t instance);

/*!
 * @brief Get the CT clock frequency.
 *
 * @param instance The peripheral instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetCtClkFreq(uint8_t instance);

/*!
 * @brief Get the CLIF clock frequency.
 *
 * @param instance The peripheral instance.
 * @return Clock frequency in Hz.
 */
uint32_t CLOCK_GetClifClkFreq(uint8_t instance);

/*!
 * @brief Set the LPUART clock source.
 *
 * @param instance The LPUART instance.
 * @param src The LPUART clock source.
 */
void CLOCK_SetLpuartClk(uint8_t instance, clock_lpuart_src_t src);

/*!
 * @brief Enable the clock for specific IP.
 *
 * @param name  Which clock to enable, see \ref clock_ip_name_t.
 */
static inline void CLOCK_EnableClock(clock_ip_name_t name)
{
    if (name < kCLOCK_IpInvalid)
    {
        PN76_Sys_PCRM_ClockEnable((PN76_PCRM_IP_Clocks_t)name);
    }
}

/*!
 * @brief Disable the clock for specific IP.
 *
 * @param name  Which clock to disable, see \ref clock_ip_name_t.
 */
static inline void CLOCK_DisableClock(clock_ip_name_t name)
{
    if (name < kCLOCK_IpInvalid)
    {
        PN76_Sys_PCRM_ClockDisable((PN76_PCRM_IP_Clocks_t)name);
    }
}

/**
 * @brief Select the USB PLL Reference Clock Source.
 *
 * @param source Clock source for the USB PLL Reference Clock \ref clock_usb_pll_src_t.
 *
 * @retval  kStatus_Success Operation Successful
 * @retval  kStatus_InvalidArgument Invalid parameter
 */
static inline status_t CLOCK_SetUsbPllSource(clock_usb_pll_src_t source)
{
    return (PN76_Sys_PCRM_SetUsbPllClk((PN76_PCRM_UsbPllClk_t)source) == PN76_STATUS_SUCCESS) ? kStatus_Success :
                                                                                                kStatus_InvalidArgument;
}

/*!
 * @brief This function enables the USB PLL and returns after the PLL is Locked.
 *
 * @note Pre-Requisite for this function is that USB PLL reference clock source should be selected and running.
 *
 * @retval  kStatus_Success Operation Successful
 * @retval  kStatus_Timeout Operation failed.
 */
static inline status_t CLOCK_StartUsbPll(void)
{
    return (PN76_Sys_PCRM_StartUsbPll() == PN76_STATUS_SUCCESS) ? kStatus_Success : kStatus_Timeout;
}

/*!
 * @brief Start the Crystal oscillator (XTAL).
 *
 * @note This function should only be used when XTAL is used as the CLIF Clock source.
 *
 * @return Returns \ref kStatus_Success if succeed, otherwise returns kStatus_Fail.
 */
status_t CLOCK_InitOsc(void);

/*!
 * @brief Switch system clock and CLIF clock to HFO.
 *
 * This function is used to initialize the System clock to HFO and
 * revert the CLIF Clock from XTAL/PLL to HFO before entering Standby/ULP Standby.
 */
static inline void CLOCK_SwitchSystemClockToHfo(void)
{
    PN76_Sys_Hal_PCRM_SystemClockInit();
}

/*!
 * @brief Initialize the USB PLL.
 *
 * This function initializes the USB PLL to work, it tries to use XTAL clock
 * as reference clock of USB PLL, if the XTAL is not available, then tries
 * to use CLIF PLL as reference clock.
 *
 * @return Return \ref kStatus_Success if succeed, otherwise return kStatus_Fail.
 */
status_t CLOCK_InitUsbPll(void);

/* @} */

#if defined(__cplusplus)
}
#endif /* __cplusplus */

/*! @} */

#endif /* _FSL_CLOCK_H_ */
