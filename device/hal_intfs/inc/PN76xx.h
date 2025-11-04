/*
 * Copyright (c) 2009-2017 ARM Limited. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the License); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an AS IS BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*----------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                    */
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
 * PN76xx NFC controller M33 core file.
 * $Author$
 * $Revision$ (01.01.00)
 * $Date$
 *
 * History:
 *
 */

#ifndef PN76XX_H
#define PN76XX_H

#ifdef __cplusplus
extern "C" {
#endif

/* ===========================================================================================================================
 */
/* ================                                Interrupt Number Definition ================ */
/* ===========================================================================================================================
 */

/*!
 * @addtogroup PN76InterruptVector
 * @{
 */

/*! @brief PN76 Interrupt Vector Table. */
typedef enum IRQn
{
    /* =======================================  ARM Cortex-M33 Specific Interrupt Numbers
       ======================================== */
    Reset_IRQn            = -15, /*!< -15  Reset Vector, invoked on Power up and warm reset                     */
    NonMaskableInt_IRQn   = -14, /*!< -14  Non maskable Interrupt, cannot be stopped or preempted               */
    HardFault_IRQn        = -13, /*!< -13  Hard Fault, all classes of Fault                                     */
    MemoryManagement_IRQn = -12, /*!< -12  Memory Management, MPU mismatch, including Access Violation
                                           and No Match                                                         */
    BusFault_IRQn = -11,         /*!< -11  Bus Fault, Pre-Fetch-, Memory Access Fault, other address/memory
                                           related Fault                                                        */
    UsageFault_IRQn   = -10,     /*!< -10  Usage Fault, i.e. Undef Instruction, Illegal State Transition        */
    SecureFault_IRQn  = -9,      /*!< -9 Secure Fault Interrupt                                                 */
    SVCall_IRQn       = -5,      /*!< -5 System Service Call via SVC instruction                                */
    DebugMonitor_IRQn = -4,      /*!< -4 Debug Monitor                                                          */
    PendSV_IRQn       = -2,      /*!< -2 Pendable request for system service                                    */
    SysTick_IRQn      = -1,      /*!< -1 System Tick Timer                                                      */

    /* ===========================================  PN76XX Interrupt Numbers  =========================================
     */
    TIMER_IRQn           = 0, /* General purpose timer 0/1 interrupt */
    BMA_ERROR_IRQn       = 1, /*  Reserved 1 -> Free to be use by non-secure */
    RESERVED2_IRQn       = 2, /*  Reserved 2 -> Free to be use by non-secure */
    CLIF_RF_IRQn         = 3, /* CLIF HAL non-secure interrupt */
    SECURE4_IRQn         = 4, /* Not available to non-secure state, secure interrupt 4 */
    SECURE5_IRQn         = 5, /* Not available to non-secure state, secure interrupt 5 */
    DMA_IRQn             = 6,
    PCRM_IRQn            = 7,  /* PCRM HAL non-secure interrupt */
    RESERVED8_IRQn       = 8,  /* Reserved 8 -> Free to be use by non-secure */
    HOSTIF_IRQn          = 9,  /* TX or RX buffer from I2C or SPI module */
    SECURE10_IRQn        = 10, /* Not available to non-secure state, secure interrupt 10 */
    SECURE11_IRQn        = 11, /* Not available to non-secure state, secure interrupt 11 */
    SECURE12_IRQn        = 12, /* Not available to non-secure state, secure interrupt 12 */
    RESERVED13_IRQn      = 13, /* Reserved 13 -> Free to be use by non-secure */
    RESERVED14_IRQn      = 14, /* Reserved 14 -> Free to be use by non-secure */
    RESERVED15_IRQn      = 15, /* Reserved 15 -> Free to be use by non-secure */
    RESERVED16_IRQn      = 16, /* Reserved 16 -> Free to be use by non-secure */
    SECURE17_IRQn        = 17, /* Not available to non-secure state, secure interrupt 17 */
    I2C_MASTER_IRQn      = 18,
    SPI_MASTER_IRQn      = 19,
    SPI_MASTER_FIFO_IRQn = 20,
    SECURE21_IRQn        = 21, /* Not available to non-secure state, secure interrupt 21 */
    SECURE22_IRQn        = 22, /* Not available to non-secure state, secure interrupt 22 */
    SECURE23_IRQn        = 23, /* Not available to non-secure state, secure interrupt 23 */
    CT_IRQn              = 24,
    USB_MASTER_IRQn      = 25,
    PWM_IRQn             = 26,
    RESERVED27_IRQn      = 27, /* Reserved 27 -> Free to be use by non-secure */
    LP_UART_RX_IRQn      = 28,
    LP_UART_TX_IRQn      = 29,
    RESERVED30_IRQn      = 30, /* Reserved 30 -> Free to be use by non-secure */
    GPIO0_IRQn           = 31,
    GPIO1_IRQn           = 32,
    GPIO2_IRQn           = 33,
    GPIO3_IRQn           = 34,
    GPIO_COMMON_IRQn     = 35,
    RESERVED36_IRQn      = 36, /* Reserved 36 -> Free to be use by non-secure */
    USB_VBUS_IRQn        = 37,
    RESERVED38_IRQn      = 38, /* Reserved 38 -> Free to be use by non-secure */
    RESERVED39_IRQn      = 39, /* Reserved 39 -> Free to be use by non-secure */
    RESERVED40_IRQn      = 40, /* Reserved 40 -> Free to be use by non-secure */
    RESERVED41_IRQn      = 41, /* Reserved 41 -> Free to be use by non-secure */
    SECURE42_IRQn        = 42, /* Not available to non-secure state, secure interrupt 42 */
    SECURE43_IRQn        = 43, /* Not available to non-secure state, secure interrupt 43 */
    SECURE44_IRQn        = 44, /* Not available to non-secure state, secure interrupt 44 */
    SECURE45_IRQn        = 45, /* Not available to non-secure state, secure interrupt 45 */
    RESERVED46_IRQn      = 46, /* Reserved 46 -> Free to be use by non-secure */
    RESERVED47_IRQn      = 47, /* Reserved 47 -> Free to be use by non-secure */
    IRQn_END             = 48  /* Invalid */
} IRQn_Type;

/*!
 * @}
 */ /* end of group Interrupt_vector_numbers */

/* ===========================================================================================================================
 */
/* ================                           Processor and Core Peripheral Section ================ */
/* ===========================================================================================================================
 */

/*!
 * @addtogroup Cortex_Core_Configuration Cortex M33 Core Configuration
 * @{
 */

#define __CM33_REV             0x0001 /*!< Core Revision r2p1 */
#define __MPU_PRESENT          0      /*!< Set to 1 if MPU is present */
#define __VTOR_PRESENT         1      /*!< Set to 1 if VTOR is present */
#define __NVIC_PRIO_BITS       3      /*!< Number of Bits used for Priority Levels */
#define __Vendor_SysTickConfig 0      /*!< Set to 1 if different SysTick Config is used */
#define __FPU_PRESENT          0      /*!< Set to 1 if FPU is present */
#define __FPU_DP               0      /*!< Set to 1 if FPU is double precision FPU (default is single precision FPU) */
#define __ICACHE_PRESENT       0      /*!< Set to 1 if I-Cache is present */
#define __DCACHE_PRESENT       0      /*!< Set to 1 if D-Cache is present */
#define __DTCM_PRESENT         0      /*!< Set to 1 if DTCM is present */

#include <core_cm33.h> /*!< ARM Cortex-M33 processor and core peripherals */

/*!
 * @}
 */ /* end of group  Cortex_Core_Configuration */

#ifdef __cplusplus
}
#endif

#endif /* PN76XX_H */
