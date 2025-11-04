/*
** ###################################################################
**     Processor:           PN7642EV
**     Compilers:           GNU C Compiler
**                          IAR ANSI C/C++ Compiler for ARM
**                          Keil ARM C/C++ Compiler
**                          MCUXpresso Compiler
**
**     Reference manual:    PN76xx, Rev.0, Mar 2021
**     Version:             rev. 1.0, 2021-03-03
**     Build:               b220906
**
**     Abstract:
**         Provides a system configuration function and a global variable that
**         contains the system frequency. It configures the device and initializes
**         the oscillator (PLL) that is part of the microcontroller device.
**
**     Copyright 2016 Freescale Semiconductor, Inc.
**     Copyright 2016-2022 NXP
**     All rights reserved.
**
**     SPDX-License-Identifier: BSD-3-Clause
**
**     http:                 www.nxp.com
**     mail:                 support@nxp.com
**
**     Revisions:
**     - rev. 1.0 (2021-03-03)
**         Initial version.
**
** ###################################################################
*/

/*!
 * @file PN7642
 * @version 1.0
 * @date 060922
 * @brief Device specific configuration file for PN7642 (header file)
 *
 * Provides a system configuration function and a global variable that contains
 * the system frequency. It configures the device and initializes the oscillator
 * (PLL) that is part of the microcontroller device.
 */
#ifndef _SYSTEM_PN7642_H_
#define _SYSTEM_PN7642_H_                    /**< Symbol preventing repeated inclusion */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#define DEFAULT_SYSTEM_CLOCK           45000000u           /* Default System clock value */
#ifndef CLK_MAINXTAL_CLK
#define CLK_MAINXTAL_CLK               38400000u           /* External crystal 38.4M clock */
#endif
#define CLK_RC32M_CLK                  32000000u           /* On-chip RC OSC 32 MHz clock */
#define CLK_XTAL32K_CLK                   32768u           /* External crystal 32 kHz clock */
#define CLK_RC32K_CLK                     32768u           /* On-chip RC OSC 32 KHz clock */

/**
 * @brief System clock frequency (core clock)
 *
 * The system clock frequency supplied to the SysTick timer and the processor
 * core clock. This variable can be used by the user application to setup the
 * SysTick timer or configure other parameters. It may also be used by debugger to
 * query the frequency of the debug timer or configure the trace clock speed
 * SystemCoreClock is initialized with a correct predefined value.
 */
extern uint32_t SystemCoreClock;

/**
 * @brief Setup the microcontroller system.
 *
 * Typically this function configures the oscillator (PLL) that is part of the
 * microcontroller device. For systems with variable clock speed it also updates
 * the variable SystemCoreClock. SystemInit is called from startup_device file.
 */
void SystemInit(void);

/**
 * @brief Updates the SystemCoreClock variable.
 *
 * It must be called whenever the core clock is changed during program
 * execution. SystemCoreClockUpdate() evaluates the clock register settings and calculates
 * the current core clock.
 */
void SystemCoreClockUpdate(void);

/**
 * @brief SystemInit function hook.
 *
 * This weak function allows to call specific initialization code during the
 * SystemInit() execution.This can be used when an application specific code needs
 * to be called as close to the reset entry as possible (for example the Multicore
 * Manager MCMGR_EarlyInit() function call).
 * NOTE: No global r/w variables can be used in this hook function because the
 * initialization of these variables happens after this function.
 */
void SystemInitHook(void);

/**
 * @brief Check boot status.
 *
 */
void SystemCheckBoot(uint32_t bootStatus);

#ifdef __cplusplus
}
#endif

#endif  /* _SYSTEM_PN7642_DSP_H_ */
