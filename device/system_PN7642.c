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
 * @brief Device specific configuration file for PN7642 (implementation file)
 *
 * Provides a system configuration function and a global variable that contains
 * the system frequency. It configures the device and initializes the oscillator
 * (PLL) that is part of the microcontroller device.
 */

#include <stdint.h>
#include "fsl_device_registers.h"
#include "PN76_Pcrm.h"

/* ----------------------------------------------------------------------------
   -- Core clock
   ---------------------------------------------------------------------------- */

uint32_t SystemCoreClock = DEFAULT_SYSTEM_CLOCK;

/* ----------------------------------------------------------------------------
   -- SystemInit()
   ---------------------------------------------------------------------------- */

__attribute__ ((weak)) void SystemInit (void)
{
#if ((__FPU_PRESENT == 1) && (__FPU_USED == 1))
    SCB->CPACR |= ((3UL << 10*2) | (3UL << 11*2));    /* set CP10, CP11 Full Access */
#endif /* ((__FPU_PRESENT == 1) && (__FPU_USED == 1)) */

    SystemInitHook();
}

/* ----------------------------------------------------------------------------
   -- SystemCoreClockUpdate()
   ---------------------------------------------------------------------------- */

void SystemCoreClockUpdate (void)
{
}

/* ----------------------------------------------------------------------------
   -- SystemInitHook()
   ---------------------------------------------------------------------------- */

__attribute__ ((weak)) void SystemInitHook (void)
{
    /* Void implementation of the weak function. */
}

/* ----------------------------------------------------------------------------
   -- SystemCheckBoot()
   ---------------------------------------------------------------------------- */

void SystemCheckBoot(uint32_t bootStatus)
{
    switch(bootStatus)
    {
        case (uint32_t)PN76_STATUS_MEMORY_ERROR:
            /* It seems some memory error in the boot which was recovered later.
             * Its suggested to do system reset and start fresh. */
            PN76_Sys_Hal_HardReset();
            break;

        case (uint32_t)PN76_STATUS_INTERNAL_ERROR:
        case (uint32_t)PN76_STATUS_RECOVERY_ERROR:
            /* It seems PN76xx boot noticed and error which is not recovered. */
            while(true)
            {
            }
            break;

        case (uint32_t)PN76_STATUS_SUCCESS:
        default:
            /* Nothing to do */
            break;
    }
}
