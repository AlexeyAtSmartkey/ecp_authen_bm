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
**     Build:               b221014
**
**     Abstract:
**         CMSIS Peripheral Access Layer for PN7642
**
**     Copyright 1997-2016 Freescale Semiconductor, Inc.
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
 * @file PN7642.h
 * @version 1.0
 * @date 2021-03-03
 * @brief CMSIS Peripheral Access Layer for PN7642
 *
 * CMSIS Peripheral Access Layer for PN7642
 */

#ifndef _PN7642_H_
#define _PN7642_H_                               /**< Symbol preventing repeated inclusion */

/** Memory map major version (memory maps with equal major version number are
 * compatible) */
#define MCU_MEM_MAP_VERSION 0x0100U
/** Memory map minor version */
#define MCU_MEM_MAP_VERSION_MINOR 0x0000U


/* ----------------------------------------------------------------------------
   -- Interrupt vector numbers
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Interrupt_vector_numbers Interrupt vector numbers
 * @{
 */

/** Interrupt Number Definitions */
#define NUMBER_OF_INT_VECTORS 62                 /**< Number of interrupts in the Vector table */

typedef enum IRQn {
  /* Auxiliary constants */
  NotAvail_IRQn                = -128,             /**< Not available device specific interrupt */

  /* Core interrupts */
  NonMaskableInt_IRQn          = -14,              /**< Non Maskable Interrupt */
  HardFault_IRQn               = -13,              /**< Cortex-M33 SV Hard Fault Interrupt */
  MemoryManagement_IRQn        = -12,              /**< Cortex-M33 Memory Management Interrupt */
  BusFault_IRQn                = -11,              /**< Cortex-M33 Bus Fault Interrupt */
  UsageFault_IRQn              = -10,              /**< Cortex-M33 Usage Fault Interrupt */
  SecureFault_IRQn             = -9,               /**< Cortex-M33 Secure Fault Interrupt */
  SVCall_IRQn                  = -5,               /**< Cortex-M33 SV Call Interrupt */
  DebugMonitor_IRQn            = -4,               /**< Cortex-M33 Debug Monitor Interrupt */
  PendSV_IRQn                  = -2,               /**< Cortex-M33 Pend SV Interrupt */
  SysTick_IRQn                 = -1,               /**< Cortex-M33 System Tick Interrupt */

  /* Device specific interrupts */
  GPT_IRQn                     = 0,                /**< General Purpose Timers */
  BMA_IRQn                     = 1,                /**< Buffer Mapping/Arbitration Unit */
  CLIF_IRQn                    = 3,                /**< Contactless Interface */
  SECURE4_IRQn                 = 4,                /**< Not available to non-secure state, secure interrupt 4 */
  SECURE5_IRQn                 = 5,                /**< Not available to non-secure state, secure interrupt 5 */
  GPDMA_IRQn                   = 6,                /**< Non-secure DMA */
  PCRM_IRQn                    = 7,                /**< Power, Clock, Reset Management Unit */
  HOSTIF_IRQn                  = 9,                /**< Host Interface Module */
  SECURE10_IRQn                = 10,               /**< Not available to non-secure state, secure interrupt 10 */
  SECURE11_IRQn                = 11,               /**< Not available to non-secure state, secure interrupt 11 */
  SECURE12_IRQn                = 12,               /**< Not available to non-secure state, secure interrupt 12 */
  SECURE17_IRQn                = 17,               /**< Not available to non-secure state, secure interrupt 17 */
  I2C_IRQn                     = 18,               /**< I2C Master Interface */
  SPI_IRQn                     = 19,               /**< SPI Master Interface */
  SPI_FIFO_IRQn                = 20,               /**< SPI Master FIFO Interrupt */
  SECURE21_IRQn                = 21,               /**< Not available to non-secure state, secure interrupt 21 */
  SECURE22_IRQn                = 22,               /**< Not available to non-secure state, secure interrupt 22 */
  SECURE23_IRQn                = 23,               /**< Not available to non-secure state, secure interrupt 23 */
  CT_IRQn                      = 24,               /**< Contact Interface Unit */
  USB_IRQn                     = 25,               /**< USB */
  SCT_IRQn                     = 26,               /**< SCTimer/PWM */
  LPUART_RX_IRQn               = 28,               /**< LP UART RX */
  LPUART_TX_IRQn               = 29,               /**< LP UART TX */
  GPIO0_IRQn                   = 31,               /**< Power, Clock, Reset Management Unit: GPIO0 */
  GPIO1_IRQn                   = 32,               /**< Power, Clock, Reset Management Unit: GPIO1 */
  GPIO2_IRQn                   = 33,               /**< Power, Clock, Reset Management Unit: GPIO2 */
  GPIO3_IRQn                   = 34,               /**< Power, Clock, Reset Management Unit: GPIO3 */
  GPIO_IRQn                    = 35,               /**< Power, Clock, Reset Management Unit: GPIO Common */
  USB_VBUS_IRQn                = 37,               /**< Power, Clock, Reset Management Unit: USB_VBUS Monitor */
  SECURE42_IRQn                = 42,               /**< Not available to non-secure state, secure interrupt 42 */
  SECURE43_IRQn                = 43,               /**< Not available to non-secure state, secure interrupt 43 */
  SECURE44_IRQn                = 44,               /**< Not available to non-secure state, secure interrupt 44 */
  SECURE45_IRQn                = 45                /**< Not available to non-secure state, secure interrupt 45 */
} IRQn_Type;

/*!
 * @}
 */ /* end of group Interrupt_vector_numbers */


/* ----------------------------------------------------------------------------
   -- Cortex M33 Core Configuration
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Cortex_Core_Configuration Cortex M33 Core Configuration
 * @{
 */

#define __MPU_PRESENT                  0         /**< Defines if an MPU is present or not */
#define __NVIC_PRIO_BITS               3         /**< Number of priority bits implemented in the NVIC */
#define __Vendor_SysTickConfig         0         /**< Vendor specific implementation of SysTickConfig is defined */
#define __FPU_PRESENT                  0         /**< Defines if an FPU is present or not */
#define __DSP_PRESENT                  0         /**< Defines if Armv8-M Mainline core supports DSP instructions */
#define __SAUREGION_PRESENT            0         /**< Defines if an SAU is present or not */

#include "core_cm33.h"                 /* Core Peripheral Access Layer */
#include "system_PN7642.h"             /* Device specific configuration file */

/*!
 * @}
 */ /* end of group Cortex_Core_Configuration */


/* ----------------------------------------------------------------------------
   -- Mapping Information
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Mapping_Information Mapping Information
 * @{
 */

/** Mapping Information */
/*!
 * @addtogroup gpdma_request
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*!
 * @brief Structure for the GPDMA hardware request
 *
 * Defines the structure for the GPDMA hardware request collections. The user can configure the
 * hardware request to trigger the GPDMA transfer accordingly. The index
 * of the hardware request varies according  to the to SoC.
 */
typedef enum _gpdma_request_source
{
    kGpdmaRequestDisabled           = 0U,          /**< GPDMA Channel disabled */
    kGpdmaRequestMuxLpuartTx        = 1U,          /**< LPUART Transmit */
    kGpdmaRequestMuxLpuartRx        = 2U,          /**< LPUART Receive */
    kGpdmaRequestMuxSctRequest0     = 3U,          /**< SCT channel 0 */
    kGpdmaRequestMuxSctRequest1     = 4U,          /**< SCT channel 1 */
    kGpdmaRequestMuxSpiMasterTx     = 5U,          /**< SPI Master Transmit */
    kGpdmaRequestMuxSpiMasterRx     = 6U,          /**< SPI Master Receive */
    kGpdmaRequestMuxI2cMasterMst    = 11U,         /**< I2C Master Master */
    kGpdmaRequestMuxI2cMasterSlv    = 12U,         /**< I2C Master Slave */
    kGpdmaRequestMuxI2cMasterMon    = 13U,         /**< I2C Master Monitor */
} gpdma_request_source_t;

/* @} */


/*!
 * @}
 */ /* end of group Mapping_Information */


/* ----------------------------------------------------------------------------
   -- Device Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Peripheral_access_layer Device Peripheral Access Layer
 * @{
 */


/*
** Start of section using anonymous unions
*/

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang diagnostic push
  #else
    #pragma push
    #pragma anon_unions
  #endif
#elif defined(__GNUC__)
  /* anonymous unions are enabled by default */
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma language=extended
#else
  #error Not supported compiler type
#endif

/* ----------------------------------------------------------------------------
   -- CT Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup CT_Peripheral_Access_Layer CT Peripheral Access Layer
 * @{
 */

/** CT - Register Layout Typedef */
typedef struct {
  __IO uint32_t SSR;                               /**< , offset: 0x0 */
  __IO uint32_t PDRX_LSB;                          /**< , offset: 0x4 */
  __IO uint32_t PDRX_MSB;                          /**< , offset: 0x8 */
  __IO uint32_t FCR;                               /**< , offset: 0xC */
  __IO uint32_t GTRX;                              /**< , offset: 0x10 */
  __IO uint32_t UCR1X;                             /**< , offset: 0x14 */
  __IO uint32_t UCR2X;                             /**< , offset: 0x18 */
  __IO uint32_t CCRX;                              /**< , offset: 0x1C */
  __IO uint32_t PCR;                               /**< , offset: 0x20 */
  __IO uint32_t ECR;                               /**< , offset: 0x24 */
  __IO uint32_t MCLR_LSB;                          /**< , offset: 0x28 */
  __IO uint32_t MCLR_MSB;                          /**< , offset: 0x2C */
  __IO uint32_t MCHR_LSB;                          /**< , offset: 0x30 */
  __IO uint32_t MCHR_MSB;                          /**< , offset: 0x34 */
  __IO uint32_t SRR;                               /**< , offset: 0x38 */
  __IO uint32_t UTR_URR_REG_ADR1;                  /**< , offset: 0x3C */
  __IO uint32_t UTR_URR_REG_ADR2;                  /**< , offset: 0x40 */
  __IO uint32_t UTR_URR_REG_ADR3;                  /**< , offset: 0x44 */
  __IO uint32_t UTR_URR_REG_ADR4;                  /**< , offset: 0x48 */
  __O  uint32_t TOR1;                              /**< , offset: 0x4C */
  __O  uint32_t TOR2;                              /**< , offset: 0x50 */
  __O  uint32_t TOR3;                              /**< , offset: 0x54 */
  __IO uint32_t TOC;                               /**< , offset: 0x58 */
  __I  uint32_t FSR;                               /**< , offset: 0x5C */
  __I  uint32_t MSR;                               /**< , offset: 0x60 */
  __I  uint32_t USR1;                              /**< , offset: 0x64 */
  __I  uint32_t USR2;                              /**< , offset: 0x68 */
  __IO uint32_t TBSEL;                             /**< , offset: 0x6C */
  __I  uint32_t TBVAL;                             /**< , offset: 0x70 */
  __IO uint32_t TST1_REF;                          /**< , offset: 0x74 */
} CT_Type;

/* ----------------------------------------------------------------------------
   -- CT Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup CT_Register_Masks CT Register Masks
 * @{
 */

/*! @name SSR -  */
/*! @{ */

#define CT_SSR_NOT_SOFTRESET_MASK                (0x1U)
#define CT_SSR_NOT_SOFTRESET_SHIFT               (0U)
#define CT_SSR_NOT_SOFTRESET(x)                  (((uint32_t)(((uint32_t)(x)) << CT_SSR_NOT_SOFTRESET_SHIFT)) & CT_SSR_NOT_SOFTRESET_MASK)

#define CT_SSR_IOAUXEN_MASK                      (0x2U)
#define CT_SSR_IOAUXEN_SHIFT                     (1U)
#define CT_SSR_IOAUXEN(x)                        (((uint32_t)(((uint32_t)(x)) << CT_SSR_IOAUXEN_SHIFT)) & CT_SSR_IOAUXEN_MASK)

#define CT_SSR_CLKAUXEN_MASK                     (0x4U)
#define CT_SSR_CLKAUXEN_SHIFT                    (2U)
#define CT_SSR_CLKAUXEN(x)                       (((uint32_t)(((uint32_t)(x)) << CT_SSR_CLKAUXEN_SHIFT)) & CT_SSR_CLKAUXEN_MASK)

#define CT_SSR_PRES_PUP_EN_MASK                  (0x8U)
#define CT_SSR_PRES_PUP_EN_SHIFT                 (3U)
#define CT_SSR_PRES_PUP_EN(x)                    (((uint32_t)(((uint32_t)(x)) << CT_SSR_PRES_PUP_EN_SHIFT)) & CT_SSR_PRES_PUP_EN_MASK)

#define CT_SSR_PRES_CON_NO_MASK                  (0x10U)
#define CT_SSR_PRES_CON_NO_SHIFT                 (4U)
#define CT_SSR_PRES_CON_NO(x)                    (((uint32_t)(((uint32_t)(x)) << CT_SSR_PRES_CON_NO_SHIFT)) & CT_SSR_PRES_CON_NO_MASK)
/*! @} */

/*! @name PDRX_LSB -  */
/*! @{ */

#define CT_PDRX_LSB_PD7_PD0_MASK                 (0xFFU)
#define CT_PDRX_LSB_PD7_PD0_SHIFT                (0U)
#define CT_PDRX_LSB_PD7_PD0(x)                   (((uint32_t)(((uint32_t)(x)) << CT_PDRX_LSB_PD7_PD0_SHIFT)) & CT_PDRX_LSB_PD7_PD0_MASK)
/*! @} */

/*! @name PDRX_MSB -  */
/*! @{ */

#define CT_PDRX_MSB_PD15_PD8_MASK                (0xFFU)
#define CT_PDRX_MSB_PD15_PD8_SHIFT               (0U)
#define CT_PDRX_MSB_PD15_PD8(x)                  (((uint32_t)(((uint32_t)(x)) << CT_PDRX_MSB_PD15_PD8_SHIFT)) & CT_PDRX_MSB_PD15_PD8_MASK)
/*! @} */

/*! @name FCR -  */
/*! @{ */

#define CT_FCR_FTC4_FTC0_MASK                    (0x1FU)
#define CT_FCR_FTC4_FTC0_SHIFT                   (0U)
#define CT_FCR_FTC4_FTC0(x)                      (((uint32_t)(((uint32_t)(x)) << CT_FCR_FTC4_FTC0_SHIFT)) & CT_FCR_FTC4_FTC0_MASK)

#define CT_FCR_PEC2_PEC0_MASK                    (0xE0U)
#define CT_FCR_PEC2_PEC0_SHIFT                   (5U)
#define CT_FCR_PEC2_PEC0(x)                      (((uint32_t)(((uint32_t)(x)) << CT_FCR_PEC2_PEC0_SHIFT)) & CT_FCR_PEC2_PEC0_MASK)
/*! @} */

/*! @name GTRX -  */
/*! @{ */

#define CT_GTRX_GT7_GT0_MASK                     (0xFFU)
#define CT_GTRX_GT7_GT0_SHIFT                    (0U)
#define CT_GTRX_GT7_GT0(x)                       (((uint32_t)(((uint32_t)(x)) << CT_GTRX_GT7_GT0_SHIFT)) & CT_GTRX_GT7_GT0_MASK)
/*! @} */

/*! @name UCR1X -  */
/*! @{ */

#define CT_UCR1X_CONV_MASK                       (0x1U)
#define CT_UCR1X_CONV_SHIFT                      (0U)
#define CT_UCR1X_CONV(x)                         (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_CONV_SHIFT)) & CT_UCR1X_CONV_MASK)

#define CT_UCR1X_LCT_MASK                        (0x2U)
#define CT_UCR1X_LCT_SHIFT                       (1U)
#define CT_UCR1X_LCT(x)                          (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_LCT_SHIFT)) & CT_UCR1X_LCT_MASK)

#define CT_UCR1X_T_R_MASK                        (0x4U)
#define CT_UCR1X_T_R_SHIFT                       (2U)
#define CT_UCR1X_T_R(x)                          (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_T_R_SHIFT)) & CT_UCR1X_T_R_MASK)

#define CT_UCR1X_PROT_MASK                       (0x8U)
#define CT_UCR1X_PROT_SHIFT                      (3U)
#define CT_UCR1X_PROT(x)                         (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_PROT_SHIFT)) & CT_UCR1X_PROT_MASK)

#define CT_UCR1X_FC_MASK                         (0x10U)
#define CT_UCR1X_FC_SHIFT                        (4U)
#define CT_UCR1X_FC(x)                           (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_FC_SHIFT)) & CT_UCR1X_FC_MASK)

#define CT_UCR1X_FIP_MASK                        (0x20U)
#define CT_UCR1X_FIP_SHIFT                       (5U)
#define CT_UCR1X_FIP(x)                          (((uint32_t)(((uint32_t)(x)) << CT_UCR1X_FIP_SHIFT)) & CT_UCR1X_FIP_MASK)
/*! @} */

/*! @name UCR2X -  */
/*! @{ */

#define CT_UCR2X_NOT_AUTOCONV_MASK               (0x1U)
#define CT_UCR2X_NOT_AUTOCONV_SHIFT              (0U)
#define CT_UCR2X_NOT_AUTOCONV(x)                 (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_NOT_AUTOCONV_SHIFT)) & CT_UCR2X_NOT_AUTOCONV_MASK)

#define CT_UCR2X_MAN_BGT_MASK                    (0x2U)
#define CT_UCR2X_MAN_BGT_SHIFT                   (1U)
#define CT_UCR2X_MAN_BGT(x)                      (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_MAN_BGT_SHIFT)) & CT_UCR2X_MAN_BGT_MASK)

#define CT_UCR2X_DISFT_MASK                      (0x4U)
#define CT_UCR2X_DISFT_SHIFT                     (2U)
#define CT_UCR2X_DISFT(x)                        (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_DISFT_SHIFT)) & CT_UCR2X_DISFT_MASK)

#define CT_UCR2X_DISPE_MASK                      (0x8U)
#define CT_UCR2X_DISPE_SHIFT                     (3U)
#define CT_UCR2X_DISPE(x)                        (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_DISPE_SHIFT)) & CT_UCR2X_DISPE_MASK)

#define CT_UCR2X_DISATRCOUNTER_MASK              (0x10U)
#define CT_UCR2X_DISATRCOUNTER_SHIFT             (4U)
#define CT_UCR2X_DISATRCOUNTER(x)                (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_DISATRCOUNTER_SHIFT)) & CT_UCR2X_DISATRCOUNTER_MASK)

#define CT_UCR2X_DISINTAUX_MASK                  (0x20U)
#define CT_UCR2X_DISINTAUX_SHIFT                 (5U)
#define CT_UCR2X_DISINTAUX(x)                    (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_DISINTAUX_SHIFT)) & CT_UCR2X_DISINTAUX_MASK)

#define CT_UCR2X_FIFO_FLUSH_MASK                 (0x40U)
#define CT_UCR2X_FIFO_FLUSH_SHIFT                (6U)
#define CT_UCR2X_FIFO_FLUSH(x)                   (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_FIFO_FLUSH_SHIFT)) & CT_UCR2X_FIFO_FLUSH_MASK)

#define CT_UCR2X_WRDACC_MASK                     (0x80U)
#define CT_UCR2X_WRDACC_SHIFT                    (7U)
#define CT_UCR2X_WRDACC(x)                       (((uint32_t)(((uint32_t)(x)) << CT_UCR2X_WRDACC_SHIFT)) & CT_UCR2X_WRDACC_MASK)
/*! @} */

/*! @name CCRX -  */
/*! @{ */

#define CT_CCRX_ACC2_ACC0_MASK                   (0x7U)
#define CT_CCRX_ACC2_ACC0_SHIFT                  (0U)
#define CT_CCRX_ACC2_ACC0(x)                     (((uint32_t)(((uint32_t)(x)) << CT_CCRX_ACC2_ACC0_SHIFT)) & CT_CCRX_ACC2_ACC0_MASK)

#define CT_CCRX_SAN_MASK                         (0x8U)
#define CT_CCRX_SAN_SHIFT                        (3U)
#define CT_CCRX_SAN(x)                           (((uint32_t)(((uint32_t)(x)) << CT_CCRX_SAN_SHIFT)) & CT_CCRX_SAN_MASK)

#define CT_CCRX_CST_MASK                         (0x10U)
#define CT_CCRX_CST_SHIFT                        (4U)
#define CT_CCRX_CST(x)                           (((uint32_t)(((uint32_t)(x)) << CT_CCRX_CST_SHIFT)) & CT_CCRX_CST_MASK)

#define CT_CCRX_SHL_MASK                         (0x20U)
#define CT_CCRX_SHL_SHIFT                        (5U)
#define CT_CCRX_SHL(x)                           (((uint32_t)(((uint32_t)(x)) << CT_CCRX_SHL_SHIFT)) & CT_CCRX_SHL_MASK)
/*! @} */

/*! @name PCR -  */
/*! @{ */

#define CT_PCR_START_MASK                        (0x1U)
#define CT_PCR_START_SHIFT                       (0U)
#define CT_PCR_START(x)                          (((uint32_t)(((uint32_t)(x)) << CT_PCR_START_SHIFT)) & CT_PCR_START_MASK)

#define CT_PCR_WARM_MASK                         (0x2U)
#define CT_PCR_WARM_SHIFT                        (1U)
#define CT_PCR_WARM(x)                           (((uint32_t)(((uint32_t)(x)) << CT_PCR_WARM_SHIFT)) & CT_PCR_WARM_MASK)

#define CT_PCR_VCCSEL1_VCCSEL0_MASK              (0xCU)
#define CT_PCR_VCCSEL1_VCCSEL0_SHIFT             (2U)
#define CT_PCR_VCCSEL1_VCCSEL0(x)                (((uint32_t)(((uint32_t)(x)) << CT_PCR_VCCSEL1_VCCSEL0_SHIFT)) & CT_PCR_VCCSEL1_VCCSEL0_MASK)

#define CT_PCR_RSTIN_MASK                        (0x10U)
#define CT_PCR_RSTIN_SHIFT                       (4U)
#define CT_PCR_RSTIN(x)                          (((uint32_t)(((uint32_t)(x)) << CT_PCR_RSTIN_SHIFT)) & CT_PCR_RSTIN_MASK)

#define CT_PCR_C4_MASK                           (0x40U)
#define CT_PCR_C4_SHIFT                          (6U)
#define CT_PCR_C4(x)                             (((uint32_t)(((uint32_t)(x)) << CT_PCR_C4_SHIFT)) & CT_PCR_C4_MASK)

#define CT_PCR_C8_MASK                           (0x80U)
#define CT_PCR_C8_SHIFT                          (7U)
#define CT_PCR_C8(x)                             (((uint32_t)(((uint32_t)(x)) << CT_PCR_C8_SHIFT)) & CT_PCR_C8_MASK)
/*! @} */

/*! @name ECR -  */
/*! @{ */

#define CT_ECR_EC7_EC0_MASK                      (0xFFU)
#define CT_ECR_EC7_EC0_SHIFT                     (0U)
#define CT_ECR_EC7_EC0(x)                        (((uint32_t)(((uint32_t)(x)) << CT_ECR_EC7_EC0_SHIFT)) & CT_ECR_EC7_EC0_MASK)
/*! @} */

/*! @name MCLR_LSB -  */
/*! @{ */

#define CT_MCLR_LSB_MCL7_MCL0_MASK               (0xFFU)
#define CT_MCLR_LSB_MCL7_MCL0_SHIFT              (0U)
#define CT_MCLR_LSB_MCL7_MCL0(x)                 (((uint32_t)(((uint32_t)(x)) << CT_MCLR_LSB_MCL7_MCL0_SHIFT)) & CT_MCLR_LSB_MCL7_MCL0_MASK)
/*! @} */

/*! @name MCLR_MSB -  */
/*! @{ */

#define CT_MCLR_MSB_MCL15_MCL7_MASK              (0xFFU)
#define CT_MCLR_MSB_MCL15_MCL7_SHIFT             (0U)
#define CT_MCLR_MSB_MCL15_MCL7(x)                (((uint32_t)(((uint32_t)(x)) << CT_MCLR_MSB_MCL15_MCL7_SHIFT)) & CT_MCLR_MSB_MCL15_MCL7_MASK)
/*! @} */

/*! @name MCHR_LSB -  */
/*! @{ */

#define CT_MCHR_LSB_MCH7_MCH0_MASK               (0xFFU)
#define CT_MCHR_LSB_MCH7_MCH0_SHIFT              (0U)
#define CT_MCHR_LSB_MCH7_MCH0(x)                 (((uint32_t)(((uint32_t)(x)) << CT_MCHR_LSB_MCH7_MCH0_SHIFT)) & CT_MCHR_LSB_MCH7_MCH0_MASK)
/*! @} */

/*! @name MCHR_MSB -  */
/*! @{ */

#define CT_MCHR_MSB_MCH15_MCH7_MASK              (0xFFU)
#define CT_MCHR_MSB_MCH15_MCH7_SHIFT             (0U)
#define CT_MCHR_MSB_MCH15_MCH7(x)                (((uint32_t)(((uint32_t)(x)) << CT_MCHR_MSB_MCH15_MCH7_SHIFT)) & CT_MCHR_MSB_MCH15_MCH7_MASK)
/*! @} */

/*! @name SRR -  */
/*! @{ */

#define CT_SRR_IO_SR1_IO_SR0_MASK                (0x3U)
#define CT_SRR_IO_SR1_IO_SR0_SHIFT               (0U)
#define CT_SRR_IO_SR1_IO_SR0(x)                  (((uint32_t)(((uint32_t)(x)) << CT_SRR_IO_SR1_IO_SR0_SHIFT)) & CT_SRR_IO_SR1_IO_SR0_MASK)

#define CT_SRR_CLK_SR1_CLK_SR0_MASK              (0xCU)
#define CT_SRR_CLK_SR1_CLK_SR0_SHIFT             (2U)
#define CT_SRR_CLK_SR1_CLK_SR0(x)                (((uint32_t)(((uint32_t)(x)) << CT_SRR_CLK_SR1_CLK_SR0_SHIFT)) & CT_SRR_CLK_SR1_CLK_SR0_MASK)

#define CT_SRR_VCC_RISE_SEL1_VCC_RISE_SEL0_MASK  (0x30U)
#define CT_SRR_VCC_RISE_SEL1_VCC_RISE_SEL0_SHIFT (4U)
#define CT_SRR_VCC_RISE_SEL1_VCC_RISE_SEL0(x)    (((uint32_t)(((uint32_t)(x)) << CT_SRR_VCC_RISE_SEL1_VCC_RISE_SEL0_SHIFT)) & CT_SRR_VCC_RISE_SEL1_VCC_RISE_SEL0_MASK)
/*! @} */

/*! @name UTR_URR_REG_ADR1 -  */
/*! @{ */

#define CT_UTR_URR_REG_ADR1_UTRURR31_UTRURR0_MASK (0xFFFFFFFFU)
#define CT_UTR_URR_REG_ADR1_UTRURR31_UTRURR0_SHIFT (0U)
#define CT_UTR_URR_REG_ADR1_UTRURR31_UTRURR0(x)  (((uint32_t)(((uint32_t)(x)) << CT_UTR_URR_REG_ADR1_UTRURR31_UTRURR0_SHIFT)) & CT_UTR_URR_REG_ADR1_UTRURR31_UTRURR0_MASK)
/*! @} */

/*! @name UTR_URR_REG_ADR2 -  */
/*! @{ */

#define CT_UTR_URR_REG_ADR2_UTRURR31_UTRURR0_MASK (0xFFFFFFFFU)
#define CT_UTR_URR_REG_ADR2_UTRURR31_UTRURR0_SHIFT (0U)
#define CT_UTR_URR_REG_ADR2_UTRURR31_UTRURR0(x)  (((uint32_t)(((uint32_t)(x)) << CT_UTR_URR_REG_ADR2_UTRURR31_UTRURR0_SHIFT)) & CT_UTR_URR_REG_ADR2_UTRURR31_UTRURR0_MASK)
/*! @} */

/*! @name UTR_URR_REG_ADR3 -  */
/*! @{ */

#define CT_UTR_URR_REG_ADR3_UTRURR31_UTRURR0_MASK (0xFFFFFFFFU)
#define CT_UTR_URR_REG_ADR3_UTRURR31_UTRURR0_SHIFT (0U)
#define CT_UTR_URR_REG_ADR3_UTRURR31_UTRURR0(x)  (((uint32_t)(((uint32_t)(x)) << CT_UTR_URR_REG_ADR3_UTRURR31_UTRURR0_SHIFT)) & CT_UTR_URR_REG_ADR3_UTRURR31_UTRURR0_MASK)
/*! @} */

/*! @name UTR_URR_REG_ADR4 -  */
/*! @{ */

#define CT_UTR_URR_REG_ADR4_UTRURR31_UTRURR0_MASK (0xFFFFFFFFU)
#define CT_UTR_URR_REG_ADR4_UTRURR31_UTRURR0_SHIFT (0U)
#define CT_UTR_URR_REG_ADR4_UTRURR31_UTRURR0(x)  (((uint32_t)(((uint32_t)(x)) << CT_UTR_URR_REG_ADR4_UTRURR31_UTRURR0_SHIFT)) & CT_UTR_URR_REG_ADR4_UTRURR31_UTRURR0_MASK)
/*! @} */

/*! @name TOR1 -  */
/*! @{ */

#define CT_TOR1_TOL7_TOL0_MASK                   (0xFFU)
#define CT_TOR1_TOL7_TOL0_SHIFT                  (0U)
#define CT_TOR1_TOL7_TOL0(x)                     (((uint32_t)(((uint32_t)(x)) << CT_TOR1_TOL7_TOL0_SHIFT)) & CT_TOR1_TOL7_TOL0_MASK)
/*! @} */

/*! @name TOR2 -  */
/*! @{ */

#define CT_TOR2_TOL15_TOL8_MASK                  (0xFFU)
#define CT_TOR2_TOL15_TOL8_SHIFT                 (0U)
#define CT_TOR2_TOL15_TOL8(x)                    (((uint32_t)(((uint32_t)(x)) << CT_TOR2_TOL15_TOL8_SHIFT)) & CT_TOR2_TOL15_TOL8_MASK)
/*! @} */

/*! @name TOR3 -  */
/*! @{ */

#define CT_TOR3_TOL23_TOL16_MASK                 (0xFFU)
#define CT_TOR3_TOL23_TOL16_SHIFT                (0U)
#define CT_TOR3_TOL23_TOL16(x)                   (((uint32_t)(((uint32_t)(x)) << CT_TOR3_TOL23_TOL16_SHIFT)) & CT_TOR3_TOL23_TOL16_MASK)
/*! @} */

/*! @name TOC -  */
/*! @{ */

#define CT_TOC_TOC7_TOC0_MASK                    (0xFFU)
#define CT_TOC_TOC7_TOC0_SHIFT                   (0U)
#define CT_TOC_TOC7_TOC0(x)                      (((uint32_t)(((uint32_t)(x)) << CT_TOC_TOC7_TOC0_SHIFT)) & CT_TOC_TOC7_TOC0_MASK)
/*! @} */

/*! @name FSR -  */
/*! @{ */

#define CT_FSR_FFL5_FFL0_MASK                    (0x3FU)
#define CT_FSR_FFL5_FFL0_SHIFT                   (0U)
#define CT_FSR_FFL5_FFL0(x)                      (((uint32_t)(((uint32_t)(x)) << CT_FSR_FFL5_FFL0_SHIFT)) & CT_FSR_FFL5_FFL0_MASK)
/*! @} */

/*! @name MSR -  */
/*! @{ */

#define CT_MSR_PRES_MASK                         (0x1U)
#define CT_MSR_PRES_SHIFT                        (0U)
#define CT_MSR_PRES(x)                           (((uint32_t)(((uint32_t)(x)) << CT_MSR_PRES_SHIFT)) & CT_MSR_PRES_MASK)

#define CT_MSR_BGT_MASK                          (0x2U)
#define CT_MSR_BGT_SHIFT                         (1U)
#define CT_MSR_BGT(x)                            (((uint32_t)(((uint32_t)(x)) << CT_MSR_BGT_SHIFT)) & CT_MSR_BGT_MASK)

#define CT_MSR_INTAUX_MASK                       (0x4U)
#define CT_MSR_INTAUX_SHIFT                      (2U)
#define CT_MSR_INTAUX(x)                         (((uint32_t)(((uint32_t)(x)) << CT_MSR_INTAUX_SHIFT)) & CT_MSR_INTAUX_MASK)
/*! @} */

/*! @name USR1 -  */
/*! @{ */

#define CT_USR1_FT_MASK                          (0x1U)
#define CT_USR1_FT_SHIFT                         (0U)
#define CT_USR1_FT(x)                            (((uint32_t)(((uint32_t)(x)) << CT_USR1_FT_SHIFT)) & CT_USR1_FT_MASK)

#define CT_USR1_FER_MASK                         (0x2U)
#define CT_USR1_FER_SHIFT                        (1U)
#define CT_USR1_FER(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR1_FER_SHIFT)) & CT_USR1_FER_MASK)

#define CT_USR1_OVR_MASK                         (0x4U)
#define CT_USR1_OVR_SHIFT                        (2U)
#define CT_USR1_OVR(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR1_OVR_SHIFT)) & CT_USR1_OVR_MASK)

#define CT_USR1_PE_MASK                          (0x8U)
#define CT_USR1_PE_SHIFT                         (3U)
#define CT_USR1_PE(x)                            (((uint32_t)(((uint32_t)(x)) << CT_USR1_PE_SHIFT)) & CT_USR1_PE_MASK)

#define CT_USR1_EARLY_MASK                       (0x10U)
#define CT_USR1_EARLY_SHIFT                      (4U)
#define CT_USR1_EARLY(x)                         (((uint32_t)(((uint32_t)(x)) << CT_USR1_EARLY_SHIFT)) & CT_USR1_EARLY_MASK)

#define CT_USR1_MUTE_MASK                        (0x20U)
#define CT_USR1_MUTE_SHIFT                       (5U)
#define CT_USR1_MUTE(x)                          (((uint32_t)(((uint32_t)(x)) << CT_USR1_MUTE_SHIFT)) & CT_USR1_MUTE_MASK)
/*! @} */

/*! @name USR2 -  */
/*! @{ */

#define CT_USR2_PTL_MASK                         (0x1U)
#define CT_USR2_PTL_SHIFT                        (0U)
#define CT_USR2_PTL(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR2_PTL_SHIFT)) & CT_USR2_PTL_MASK)

#define CT_USR2_PRESL_MASK                       (0x2U)
#define CT_USR2_PRESL_SHIFT                      (1U)
#define CT_USR2_PRESL(x)                         (((uint32_t)(((uint32_t)(x)) << CT_USR2_PRESL_SHIFT)) & CT_USR2_PRESL_MASK)

#define CT_USR2_PROTL_MASK                       (0x4U)
#define CT_USR2_PROTL_SHIFT                      (2U)
#define CT_USR2_PROTL(x)                         (((uint32_t)(((uint32_t)(x)) << CT_USR2_PROTL_SHIFT)) & CT_USR2_PROTL_MASK)

#define CT_USR2_INTAUXL_MASK                     (0x8U)
#define CT_USR2_INTAUXL_SHIFT                    (3U)
#define CT_USR2_INTAUXL(x)                       (((uint32_t)(((uint32_t)(x)) << CT_USR2_INTAUXL_SHIFT)) & CT_USR2_INTAUXL_MASK)

#define CT_USR2_WRDACCERR_MASK                   (0x10U)
#define CT_USR2_WRDACCERR_SHIFT                  (4U)
#define CT_USR2_WRDACCERR(x)                     (((uint32_t)(((uint32_t)(x)) << CT_USR2_WRDACCERR_SHIFT)) & CT_USR2_WRDACCERR_MASK)

#define CT_USR2_TO1_MASK                         (0x20U)
#define CT_USR2_TO1_SHIFT                        (5U)
#define CT_USR2_TO1(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR2_TO1_SHIFT)) & CT_USR2_TO1_MASK)

#define CT_USR2_TO2_MASK                         (0x40U)
#define CT_USR2_TO2_SHIFT                        (6U)
#define CT_USR2_TO2(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR2_TO2_SHIFT)) & CT_USR2_TO2_MASK)

#define CT_USR2_TO3_MASK                         (0x80U)
#define CT_USR2_TO3_SHIFT                        (7U)
#define CT_USR2_TO3(x)                           (((uint32_t)(((uint32_t)(x)) << CT_USR2_TO3_SHIFT)) & CT_USR2_TO3_MASK)
/*! @} */

/*! @name TBSEL -  */
/*! @{ */

#define CT_TBSEL_TBSEL_MASK                      (0xFU)
#define CT_TBSEL_TBSEL_SHIFT                     (0U)
#define CT_TBSEL_TBSEL(x)                        (((uint32_t)(((uint32_t)(x)) << CT_TBSEL_TBSEL_SHIFT)) & CT_TBSEL_TBSEL_MASK)
/*! @} */

/*! @name TBVAL -  */
/*! @{ */

#define CT_TBVAL_TBVAL_MASK                      (0xFFU)
#define CT_TBVAL_TBVAL_SHIFT                     (0U)
#define CT_TBVAL_TBVAL(x)                        (((uint32_t)(((uint32_t)(x)) << CT_TBVAL_TBVAL_SHIFT)) & CT_TBVAL_TBVAL_MASK)
/*! @} */

/*! @name TST1_REF -  */
/*! @{ */

#define CT_TST1_REF_DISDEB_MASK                  (0x1U)
#define CT_TST1_REF_DISDEB_SHIFT                 (0U)
#define CT_TST1_REF_DISDEB(x)                    (((uint32_t)(((uint32_t)(x)) << CT_TST1_REF_DISDEB_SHIFT)) & CT_TST1_REF_DISDEB_MASK)

#define CT_TST1_REF_DISPTEMP_MASK                (0x2U)
#define CT_TST1_REF_DISPTEMP_SHIFT               (1U)
#define CT_TST1_REF_DISPTEMP(x)                  (((uint32_t)(((uint32_t)(x)) << CT_TST1_REF_DISPTEMP_SHIFT)) & CT_TST1_REF_DISPTEMP_MASK)

#define CT_TST1_REF_MASK_DCDC_READY_MASK         (0x4U)
#define CT_TST1_REF_MASK_DCDC_READY_SHIFT        (2U)
#define CT_TST1_REF_MASK_DCDC_READY(x)           (((uint32_t)(((uint32_t)(x)) << CT_TST1_REF_MASK_DCDC_READY_SHIFT)) & CT_TST1_REF_MASK_DCDC_READY_MASK)

#define CT_TST1_REF_INHIB_MASK                   (0x8U)
#define CT_TST1_REF_INHIB_SHIFT                  (3U)
#define CT_TST1_REF_INHIB(x)                     (((uint32_t)(((uint32_t)(x)) << CT_TST1_REF_INHIB_SHIFT)) & CT_TST1_REF_INHIB_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group CT_Register_Masks */


/* CT - Peripheral instance base addresses */
/** Peripheral CT base address */
#define CT_BASE                                  (0x40003000u)
/** Peripheral CT base pointer */
#define CT                                       ((CT_Type *)CT_BASE)
/** Array initializer of CT peripheral base addresses */
#define CT_BASE_ADDRS                            { CT_BASE }
/** Array initializer of CT peripheral base pointers */
#define CT_BASE_PTRS                             { CT }
/** Interrupt vectors for the CT peripheral type */
#define CT_IRQS                                  { CT_IRQn }

/*!
 * @}
 */ /* end of group CT_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- GPDMA Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup GPDMA_Peripheral_Access_Layer GPDMA Peripheral Access Layer
 * @{
 */

/** GPDMA - Register Layout Typedef */
typedef struct {
  __I  uint32_t INTSTATUS;                         /**< , offset: 0x0 */
  __I  uint32_t INTTCSTATUS;                       /**< , offset: 0x4 */
  __O  uint32_t INTTCCLEAR;                        /**< , offset: 0x8 */
  __I  uint32_t INTERRORSTATUS;                    /**< , offset: 0xC */
  __O  uint32_t INTERRCLR;                         /**< , offset: 0x10 */
  __I  uint32_t RAWINTTCSTATUS;                    /**< , offset: 0x14 */
  __I  uint32_t RAWINTERRORSTATUS;                 /**< , offset: 0x18 */
  __I  uint32_t ENBLDCHNS;                         /**< , offset: 0x1C */
  __IO uint32_t SOFTBREQ;                          /**< , offset: 0x20 */
  __IO uint32_t SOFTSREQ;                          /**< , offset: 0x24 */
  __IO uint32_t SOFTLBREQ;                         /**< , offset: 0x28 */
  __IO uint32_t SOFTLSREQ;                         /**< , offset: 0x2C */
  __IO uint32_t CONFIGURATION;                     /**< , offset: 0x30 */
  __IO uint32_t SYNC;                              /**< , offset: 0x34 */
       uint8_t RESERVED_0[200];
  struct {                                         /* offset: 0x100, array step: 0x20 */
    __IO uint32_t SRCADDR;                           /**< , array offset: 0x100, array step: 0x20 */
    __IO uint32_t DESTADDR;                          /**< , array offset: 0x104, array step: 0x20 */
    __IO uint32_t LLI;                               /**< , array offset: 0x108, array step: 0x20 */
    __IO uint32_t CONTROL;                           /**< , array offset: 0x10C, array step: 0x20 */
    __IO uint32_t CONFIGURATION;                     /**< , array offset: 0x110, array step: 0x20 */
         uint8_t RESERVED_0[12];
  } DMACC[8];
       uint8_t RESERVED_1[3552];
  __I  uint32_t PERIPHID[4];                       /**< , array offset: 0xFE0, array step: 0x4 */
  __I  uint32_t PCELLID[4];                        /**< , array offset: 0xFF0, array step: 0x4 */
} GPDMA_Type;

/* ----------------------------------------------------------------------------
   -- GPDMA Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup GPDMA_Register_Masks GPDMA Register Masks
 * @{
 */

/*! @name INTSTATUS -  */
/*! @{ */

#define GPDMA_INTSTATUS_INTSTATUS_MASK           (0xFFU)
#define GPDMA_INTSTATUS_INTSTATUS_SHIFT          (0U)
#define GPDMA_INTSTATUS_INTSTATUS(x)             (((uint32_t)(((uint32_t)(x)) << GPDMA_INTSTATUS_INTSTATUS_SHIFT)) & GPDMA_INTSTATUS_INTSTATUS_MASK)
/*! @} */

/*! @name INTTCSTATUS -  */
/*! @{ */

#define GPDMA_INTTCSTATUS_INTTCSTATUS_MASK       (0xFFU)
#define GPDMA_INTTCSTATUS_INTTCSTATUS_SHIFT      (0U)
#define GPDMA_INTTCSTATUS_INTTCSTATUS(x)         (((uint32_t)(((uint32_t)(x)) << GPDMA_INTTCSTATUS_INTTCSTATUS_SHIFT)) & GPDMA_INTTCSTATUS_INTTCSTATUS_MASK)
/*! @} */

/*! @name INTTCCLEAR -  */
/*! @{ */

#define GPDMA_INTTCCLEAR_INTTCCLEAR_MASK         (0xFFU)
#define GPDMA_INTTCCLEAR_INTTCCLEAR_SHIFT        (0U)
#define GPDMA_INTTCCLEAR_INTTCCLEAR(x)           (((uint32_t)(((uint32_t)(x)) << GPDMA_INTTCCLEAR_INTTCCLEAR_SHIFT)) & GPDMA_INTTCCLEAR_INTTCCLEAR_MASK)
/*! @} */

/*! @name INTERRORSTATUS -  */
/*! @{ */

#define GPDMA_INTERRORSTATUS_INTERRORSTATUS_MASK (0xFFU)
#define GPDMA_INTERRORSTATUS_INTERRORSTATUS_SHIFT (0U)
#define GPDMA_INTERRORSTATUS_INTERRORSTATUS(x)   (((uint32_t)(((uint32_t)(x)) << GPDMA_INTERRORSTATUS_INTERRORSTATUS_SHIFT)) & GPDMA_INTERRORSTATUS_INTERRORSTATUS_MASK)
/*! @} */

/*! @name INTERRCLR -  */
/*! @{ */

#define GPDMA_INTERRCLR_INTERRCLR_MASK           (0xFFU)
#define GPDMA_INTERRCLR_INTERRCLR_SHIFT          (0U)
#define GPDMA_INTERRCLR_INTERRCLR(x)             (((uint32_t)(((uint32_t)(x)) << GPDMA_INTERRCLR_INTERRCLR_SHIFT)) & GPDMA_INTERRCLR_INTERRCLR_MASK)
/*! @} */

/*! @name RAWINTTCSTATUS -  */
/*! @{ */

#define GPDMA_RAWINTTCSTATUS_RAWINTTCSTATUS_MASK (0xFFU)
#define GPDMA_RAWINTTCSTATUS_RAWINTTCSTATUS_SHIFT (0U)
#define GPDMA_RAWINTTCSTATUS_RAWINTTCSTATUS(x)   (((uint32_t)(((uint32_t)(x)) << GPDMA_RAWINTTCSTATUS_RAWINTTCSTATUS_SHIFT)) & GPDMA_RAWINTTCSTATUS_RAWINTTCSTATUS_MASK)
/*! @} */

/*! @name RAWINTERRORSTATUS -  */
/*! @{ */

#define GPDMA_RAWINTERRORSTATUS_RAWINTERRORSTATUS_MASK (0xFFU)
#define GPDMA_RAWINTERRORSTATUS_RAWINTERRORSTATUS_SHIFT (0U)
#define GPDMA_RAWINTERRORSTATUS_RAWINTERRORSTATUS(x) (((uint32_t)(((uint32_t)(x)) << GPDMA_RAWINTERRORSTATUS_RAWINTERRORSTATUS_SHIFT)) & GPDMA_RAWINTERRORSTATUS_RAWINTERRORSTATUS_MASK)
/*! @} */

/*! @name ENBLDCHNS -  */
/*! @{ */

#define GPDMA_ENBLDCHNS_ENABLEDCHANNELS_MASK     (0xFFU)
#define GPDMA_ENBLDCHNS_ENABLEDCHANNELS_SHIFT    (0U)
#define GPDMA_ENBLDCHNS_ENABLEDCHANNELS(x)       (((uint32_t)(((uint32_t)(x)) << GPDMA_ENBLDCHNS_ENABLEDCHANNELS_SHIFT)) & GPDMA_ENBLDCHNS_ENABLEDCHANNELS_MASK)
/*! @} */

/*! @name SOFTBREQ -  */
/*! @{ */

#define GPDMA_SOFTBREQ_SOFTBREQ_MASK             (0xFFFFU)
#define GPDMA_SOFTBREQ_SOFTBREQ_SHIFT            (0U)
#define GPDMA_SOFTBREQ_SOFTBREQ(x)               (((uint32_t)(((uint32_t)(x)) << GPDMA_SOFTBREQ_SOFTBREQ_SHIFT)) & GPDMA_SOFTBREQ_SOFTBREQ_MASK)
/*! @} */

/*! @name SOFTSREQ -  */
/*! @{ */

#define GPDMA_SOFTSREQ_SOFTSREQ_MASK             (0xFFFFU)
#define GPDMA_SOFTSREQ_SOFTSREQ_SHIFT            (0U)
#define GPDMA_SOFTSREQ_SOFTSREQ(x)               (((uint32_t)(((uint32_t)(x)) << GPDMA_SOFTSREQ_SOFTSREQ_SHIFT)) & GPDMA_SOFTSREQ_SOFTSREQ_MASK)
/*! @} */

/*! @name SOFTLBREQ -  */
/*! @{ */

#define GPDMA_SOFTLBREQ_SOFTLBREQ_MASK           (0xFFFFU)
#define GPDMA_SOFTLBREQ_SOFTLBREQ_SHIFT          (0U)
#define GPDMA_SOFTLBREQ_SOFTLBREQ(x)             (((uint32_t)(((uint32_t)(x)) << GPDMA_SOFTLBREQ_SOFTLBREQ_SHIFT)) & GPDMA_SOFTLBREQ_SOFTLBREQ_MASK)
/*! @} */

/*! @name SOFTLSREQ -  */
/*! @{ */

#define GPDMA_SOFTLSREQ_SOFTLSREQ_MASK           (0xFFFFU)
#define GPDMA_SOFTLSREQ_SOFTLSREQ_SHIFT          (0U)
#define GPDMA_SOFTLSREQ_SOFTLSREQ(x)             (((uint32_t)(((uint32_t)(x)) << GPDMA_SOFTLSREQ_SOFTLSREQ_SHIFT)) & GPDMA_SOFTLSREQ_SOFTLSREQ_MASK)
/*! @} */

/*! @name CONFIGURATION -  */
/*! @{ */

#define GPDMA_CONFIGURATION_E_MASK               (0x1U)
#define GPDMA_CONFIGURATION_E_SHIFT              (0U)
#define GPDMA_CONFIGURATION_E(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_E_SHIFT)) & GPDMA_CONFIGURATION_E_MASK)

#define GPDMA_CONFIGURATION_M1_MASK              (0x2U)
#define GPDMA_CONFIGURATION_M1_SHIFT             (1U)
#define GPDMA_CONFIGURATION_M1(x)                (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_M1_SHIFT)) & GPDMA_CONFIGURATION_M1_MASK)

#define GPDMA_CONFIGURATION_M2_MASK              (0x4U)
#define GPDMA_CONFIGURATION_M2_SHIFT             (2U)
#define GPDMA_CONFIGURATION_M2(x)                (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_M2_SHIFT)) & GPDMA_CONFIGURATION_M2_MASK)
/*! @} */

/*! @name SYNC -  */
/*! @{ */

#define GPDMA_SYNC_DMACSYNC_MASK                 (0xFFFFU)
#define GPDMA_SYNC_DMACSYNC_SHIFT                (0U)
#define GPDMA_SYNC_DMACSYNC(x)                   (((uint32_t)(((uint32_t)(x)) << GPDMA_SYNC_DMACSYNC_SHIFT)) & GPDMA_SYNC_DMACSYNC_MASK)
/*! @} */

/*! @name SRCADDR -  */
/*! @{ */

#define GPDMA_SRCADDR_SRCADDR_MASK               (0xFFFFFFFFU)
#define GPDMA_SRCADDR_SRCADDR_SHIFT              (0U)
#define GPDMA_SRCADDR_SRCADDR(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_SRCADDR_SRCADDR_SHIFT)) & GPDMA_SRCADDR_SRCADDR_MASK)
/*! @} */

/* The count of GPDMA_SRCADDR */
#define GPDMA_SRCADDR_COUNT                      (8U)

/*! @name DESTADDR -  */
/*! @{ */

#define GPDMA_DESTADDR_DESTADDR_MASK             (0xFFFFFFFFU)
#define GPDMA_DESTADDR_DESTADDR_SHIFT            (0U)
#define GPDMA_DESTADDR_DESTADDR(x)               (((uint32_t)(((uint32_t)(x)) << GPDMA_DESTADDR_DESTADDR_SHIFT)) & GPDMA_DESTADDR_DESTADDR_MASK)
/*! @} */

/* The count of GPDMA_DESTADDR */
#define GPDMA_DESTADDR_COUNT                     (8U)

/*! @name LLI -  */
/*! @{ */

#define GPDMA_LLI_LM_MASK                        (0x1U)
#define GPDMA_LLI_LM_SHIFT                       (0U)
#define GPDMA_LLI_LM(x)                          (((uint32_t)(((uint32_t)(x)) << GPDMA_LLI_LM_SHIFT)) & GPDMA_LLI_LM_MASK)

#define GPDMA_LLI_LLI_MASK                       (0xFFFFFFFCU)
#define GPDMA_LLI_LLI_SHIFT                      (2U)
#define GPDMA_LLI_LLI(x)                         (((uint32_t)(((uint32_t)(x)) << GPDMA_LLI_LLI_SHIFT)) & GPDMA_LLI_LLI_MASK)
/*! @} */

/* The count of GPDMA_LLI */
#define GPDMA_LLI_COUNT                          (8U)

/*! @name CONTROL -  */
/*! @{ */

#define GPDMA_CONTROL_TRANSFERSIZE_MASK          (0xFFFU)
#define GPDMA_CONTROL_TRANSFERSIZE_SHIFT         (0U)
#define GPDMA_CONTROL_TRANSFERSIZE(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_TRANSFERSIZE_SHIFT)) & GPDMA_CONTROL_TRANSFERSIZE_MASK)

#define GPDMA_CONTROL_SBSIZE_MASK                (0x7000U)
#define GPDMA_CONTROL_SBSIZE_SHIFT               (12U)
#define GPDMA_CONTROL_SBSIZE(x)                  (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_SBSIZE_SHIFT)) & GPDMA_CONTROL_SBSIZE_MASK)

#define GPDMA_CONTROL_DBSIZE_MASK                (0x38000U)
#define GPDMA_CONTROL_DBSIZE_SHIFT               (15U)
#define GPDMA_CONTROL_DBSIZE(x)                  (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_DBSIZE_SHIFT)) & GPDMA_CONTROL_DBSIZE_MASK)

#define GPDMA_CONTROL_SWIDTH_MASK                (0x1C0000U)
#define GPDMA_CONTROL_SWIDTH_SHIFT               (18U)
#define GPDMA_CONTROL_SWIDTH(x)                  (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_SWIDTH_SHIFT)) & GPDMA_CONTROL_SWIDTH_MASK)

#define GPDMA_CONTROL_DWIDTH_MASK                (0xE00000U)
#define GPDMA_CONTROL_DWIDTH_SHIFT               (21U)
#define GPDMA_CONTROL_DWIDTH(x)                  (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_DWIDTH_SHIFT)) & GPDMA_CONTROL_DWIDTH_MASK)

#define GPDMA_CONTROL_S_MASK                     (0x1000000U)
#define GPDMA_CONTROL_S_SHIFT                    (24U)
#define GPDMA_CONTROL_S(x)                       (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_S_SHIFT)) & GPDMA_CONTROL_S_MASK)

#define GPDMA_CONTROL_D_MASK                     (0x2000000U)
#define GPDMA_CONTROL_D_SHIFT                    (25U)
#define GPDMA_CONTROL_D(x)                       (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_D_SHIFT)) & GPDMA_CONTROL_D_MASK)

#define GPDMA_CONTROL_SI_MASK                    (0x4000000U)
#define GPDMA_CONTROL_SI_SHIFT                   (26U)
#define GPDMA_CONTROL_SI(x)                      (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_SI_SHIFT)) & GPDMA_CONTROL_SI_MASK)

#define GPDMA_CONTROL_DI_MASK                    (0x8000000U)
#define GPDMA_CONTROL_DI_SHIFT                   (27U)
#define GPDMA_CONTROL_DI(x)                      (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_DI_SHIFT)) & GPDMA_CONTROL_DI_MASK)

#define GPDMA_CONTROL_PROT_MASK                  (0x70000000U)
#define GPDMA_CONTROL_PROT_SHIFT                 (28U)
#define GPDMA_CONTROL_PROT(x)                    (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_PROT_SHIFT)) & GPDMA_CONTROL_PROT_MASK)

#define GPDMA_CONTROL_I_MASK                     (0x80000000U)
#define GPDMA_CONTROL_I_SHIFT                    (31U)
#define GPDMA_CONTROL_I(x)                       (((uint32_t)(((uint32_t)(x)) << GPDMA_CONTROL_I_SHIFT)) & GPDMA_CONTROL_I_MASK)
/*! @} */

/* The count of GPDMA_CONTROL */
#define GPDMA_CONTROL_COUNT                      (8U)

/*! @name CONFIGURATION -  */
/*! @{ */

#define GPDMA_CONFIGURATION_E_MASK               (0x1U)
#define GPDMA_CONFIGURATION_E_SHIFT              (0U)
#define GPDMA_CONFIGURATION_E(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_E_SHIFT)) & GPDMA_CONFIGURATION_E_MASK)

#define GPDMA_CONFIGURATION_SRCPERIPHERAL_MASK   (0x1EU)
#define GPDMA_CONFIGURATION_SRCPERIPHERAL_SHIFT  (1U)
#define GPDMA_CONFIGURATION_SRCPERIPHERAL(x)     (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_SRCPERIPHERAL_SHIFT)) & GPDMA_CONFIGURATION_SRCPERIPHERAL_MASK)

#define GPDMA_CONFIGURATION_DESTPERIPHERAL_MASK  (0x3C0U)
#define GPDMA_CONFIGURATION_DESTPERIPHERAL_SHIFT (6U)
#define GPDMA_CONFIGURATION_DESTPERIPHERAL(x)    (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_DESTPERIPHERAL_SHIFT)) & GPDMA_CONFIGURATION_DESTPERIPHERAL_MASK)

#define GPDMA_CONFIGURATION_FLOWCNTRL_MASK       (0x3800U)
#define GPDMA_CONFIGURATION_FLOWCNTRL_SHIFT      (11U)
#define GPDMA_CONFIGURATION_FLOWCNTRL(x)         (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_FLOWCNTRL_SHIFT)) & GPDMA_CONFIGURATION_FLOWCNTRL_MASK)

#define GPDMA_CONFIGURATION_IE_MASK              (0x4000U)
#define GPDMA_CONFIGURATION_IE_SHIFT             (14U)
#define GPDMA_CONFIGURATION_IE(x)                (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_IE_SHIFT)) & GPDMA_CONFIGURATION_IE_MASK)

#define GPDMA_CONFIGURATION_ITC_MASK             (0x8000U)
#define GPDMA_CONFIGURATION_ITC_SHIFT            (15U)
#define GPDMA_CONFIGURATION_ITC(x)               (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_ITC_SHIFT)) & GPDMA_CONFIGURATION_ITC_MASK)

#define GPDMA_CONFIGURATION_L_MASK               (0x10000U)
#define GPDMA_CONFIGURATION_L_SHIFT              (16U)
#define GPDMA_CONFIGURATION_L(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_L_SHIFT)) & GPDMA_CONFIGURATION_L_MASK)

#define GPDMA_CONFIGURATION_A_MASK               (0x20000U)
#define GPDMA_CONFIGURATION_A_SHIFT              (17U)
#define GPDMA_CONFIGURATION_A(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_A_SHIFT)) & GPDMA_CONFIGURATION_A_MASK)

#define GPDMA_CONFIGURATION_H_MASK               (0x40000U)
#define GPDMA_CONFIGURATION_H_SHIFT              (18U)
#define GPDMA_CONFIGURATION_H(x)                 (((uint32_t)(((uint32_t)(x)) << GPDMA_CONFIGURATION_H_SHIFT)) & GPDMA_CONFIGURATION_H_MASK)
/*! @} */

/* The count of GPDMA_CONFIGURATION */
#define GPDMA_CONFIGURATION_COUNT                (8U)

/*! @name PERIPHID -  */
/*! @{ */

#define GPDMA_PERIPHID_PARTNUMBER0_MASK          (0xFFU)
#define GPDMA_PERIPHID_PARTNUMBER0_SHIFT         (0U)
#define GPDMA_PERIPHID_PARTNUMBER0(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_PARTNUMBER0_SHIFT)) & GPDMA_PERIPHID_PARTNUMBER0_MASK)

#define GPDMA_PERIPHID_PARTNUMBER1_MASK          (0xFU)
#define GPDMA_PERIPHID_PARTNUMBER1_SHIFT         (0U)
#define GPDMA_PERIPHID_PARTNUMBER1(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_PARTNUMBER1_SHIFT)) & GPDMA_PERIPHID_PARTNUMBER1_MASK)

#define GPDMA_PERIPHID_DESIGNER0_MASK            (0xF0U)
#define GPDMA_PERIPHID_DESIGNER0_SHIFT           (4U)
#define GPDMA_PERIPHID_DESIGNER0(x)              (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_DESIGNER0_SHIFT)) & GPDMA_PERIPHID_DESIGNER0_MASK)

#define GPDMA_PERIPHID_DESIGNER1_MASK            (0xFU)
#define GPDMA_PERIPHID_DESIGNER1_SHIFT           (0U)
#define GPDMA_PERIPHID_DESIGNER1(x)              (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_DESIGNER1_SHIFT)) & GPDMA_PERIPHID_DESIGNER1_MASK)

#define GPDMA_PERIPHID_REVISION_MASK             (0xF0U)
#define GPDMA_PERIPHID_REVISION_SHIFT            (4U)
#define GPDMA_PERIPHID_REVISION(x)               (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_REVISION_SHIFT)) & GPDMA_PERIPHID_REVISION_MASK)

#define GPDMA_PERIPHID_CONFIGURATIONNOOFCHANNELS_MASK (0x7U)
#define GPDMA_PERIPHID_CONFIGURATIONNOOFCHANNELS_SHIFT (0U)
#define GPDMA_PERIPHID_CONFIGURATIONNOOFCHANNELS(x) (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_CONFIGURATIONNOOFCHANNELS_SHIFT)) & GPDMA_PERIPHID_CONFIGURATIONNOOFCHANNELS_MASK)

#define GPDMA_PERIPHID_CONFIGURATIONNOOFAHBMASTERS_MASK (0x8U)
#define GPDMA_PERIPHID_CONFIGURATIONNOOFAHBMASTERS_SHIFT (3U)
#define GPDMA_PERIPHID_CONFIGURATIONNOOFAHBMASTERS(x) (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_CONFIGURATIONNOOFAHBMASTERS_SHIFT)) & GPDMA_PERIPHID_CONFIGURATIONNOOFAHBMASTERS_MASK)

#define GPDMA_PERIPHID_CONFIGURATIONBUSWIDTH_MASK (0x70U)
#define GPDMA_PERIPHID_CONFIGURATIONBUSWIDTH_SHIFT (4U)
#define GPDMA_PERIPHID_CONFIGURATIONBUSWIDTH(x)  (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_CONFIGURATIONBUSWIDTH_SHIFT)) & GPDMA_PERIPHID_CONFIGURATIONBUSWIDTH_MASK)

#define GPDMA_PERIPHID_CONFIGURATIONDMASOURCEREQUESTORS_MASK (0x80U)
#define GPDMA_PERIPHID_CONFIGURATIONDMASOURCEREQUESTORS_SHIFT (7U)
#define GPDMA_PERIPHID_CONFIGURATIONDMASOURCEREQUESTORS(x) (((uint32_t)(((uint32_t)(x)) << GPDMA_PERIPHID_CONFIGURATIONDMASOURCEREQUESTORS_SHIFT)) & GPDMA_PERIPHID_CONFIGURATIONDMASOURCEREQUESTORS_MASK)
/*! @} */

/* The count of GPDMA_PERIPHID */
#define GPDMA_PERIPHID_COUNT                     (4U)

/*! @name PCELLID -  */
/*! @{ */

#define GPDMA_PCELLID_DMACPCELLID0_MASK          (0xFFU)
#define GPDMA_PCELLID_DMACPCELLID0_SHIFT         (0U)
#define GPDMA_PCELLID_DMACPCELLID0(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PCELLID_DMACPCELLID0_SHIFT)) & GPDMA_PCELLID_DMACPCELLID0_MASK)

#define GPDMA_PCELLID_DMACPCELLID1_MASK          (0xFFU)
#define GPDMA_PCELLID_DMACPCELLID1_SHIFT         (0U)
#define GPDMA_PCELLID_DMACPCELLID1(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PCELLID_DMACPCELLID1_SHIFT)) & GPDMA_PCELLID_DMACPCELLID1_MASK)

#define GPDMA_PCELLID_DMACPCELLID2_MASK          (0xFFU)
#define GPDMA_PCELLID_DMACPCELLID2_SHIFT         (0U)
#define GPDMA_PCELLID_DMACPCELLID2(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PCELLID_DMACPCELLID2_SHIFT)) & GPDMA_PCELLID_DMACPCELLID2_MASK)

#define GPDMA_PCELLID_DMACPCELLID3_MASK          (0xFFU)
#define GPDMA_PCELLID_DMACPCELLID3_SHIFT         (0U)
#define GPDMA_PCELLID_DMACPCELLID3(x)            (((uint32_t)(((uint32_t)(x)) << GPDMA_PCELLID_DMACPCELLID3_SHIFT)) & GPDMA_PCELLID_DMACPCELLID3_MASK)
/*! @} */

/* The count of GPDMA_PCELLID */
#define GPDMA_PCELLID_COUNT                      (4U)


/*!
 * @}
 */ /* end of group GPDMA_Register_Masks */


/* GPDMA - Peripheral instance base addresses */
/** Peripheral GPDMA base address */
#define GPDMA_BASE                               (0x40020000u)
/** Peripheral GPDMA base pointer */
#define GPDMA                                    ((GPDMA_Type *)GPDMA_BASE)
/** Array initializer of GPDMA peripheral base addresses */
#define GPDMA_BASE_ADDRS                         { GPDMA_BASE }
/** Array initializer of GPDMA peripheral base pointers */
#define GPDMA_BASE_PTRS                          { GPDMA }

/*!
 * @}
 */ /* end of group GPDMA_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- HOSTIF Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup HOSTIF_Peripheral_Access_Layer HOSTIF Peripheral Access Layer
 * @{
 */

/** HOSTIF - Register Layout Typedef */
typedef struct {
  __I  uint32_t STATUS;                            /**< , offset: 0x0 */
  __IO uint32_t CONTROL;                           /**< , offset: 0x4 */
  __IO uint32_t I2C_CONTROL;                       /**< , offset: 0x8 */
  __IO uint32_t SPI_CONTROL;                       /**< , offset: 0xC */
  __IO uint32_t BUFFER_RX0_CFG;                    /**< , offset: 0x10 */
  __IO uint32_t BUFFER_RX1_CFG;                    /**< , offset: 0x14 */
  __IO uint32_t BUFFER_RX2_CFG;                    /**< , offset: 0x18 */
  __IO uint32_t BUFFER_RX3_CFG;                    /**< , offset: 0x1C */
  __IO uint32_t BUFFER_TX_CFG;                     /**< , offset: 0x20 */
  __I  uint32_t BUFFER_RX0_LEN;                    /**< , offset: 0x24 */
  __I  uint32_t BUFFER_RX1_LEN;                    /**< , offset: 0x28 */
  __I  uint32_t BUFFER_RX2_LEN;                    /**< , offset: 0x2C */
  __I  uint32_t BUFFER_RX3_LEN;                    /**< , offset: 0x30 */
  __IO uint32_t BUFFER_TX_LEN;                     /**< , offset: 0x34 */
  __IO uint32_t TIC_TIMEOUT;                       /**< , offset: 0x38 */
  __IO uint32_t WATERLEVEL;                        /**< , offset: 0x3C */
  __O  uint32_t SET_DATA_READY;                    /**< , offset: 0x40 */
  __O  uint32_t CLR_DATA_READY;                    /**< , offset: 0x44 */
  __I  uint32_t DATA_READY_STATUS;                 /**< , offset: 0x48 */
  __IO uint32_t TBSEL;                             /**< , offset: 0x4C */
  __I  uint32_t TBVALUE;                           /**< , offset: 0x50 */
  __IO uint32_t SPARE;                             /**< , offset: 0x54 */
       uint8_t RESERVED_0[4];
  __IO uint32_t HSU_CONTROL;                       /**< , offset: 0x5C */
  __IO uint32_t HSU_SAMPLE;                        /**< , offset: 0x60 */
       uint8_t RESERVED_1[28];
  __IO uint32_t FIFO_CFG;                          /**< , offset: 0x80 */
  __IO uint32_t FIFO_FREE_CFG;                     /**< , offset: 0x84 */
  __IO uint32_t FIFO_STOP_CFG;                     /**< , offset: 0x88 */
  __IO uint32_t FIFO_OVERFLOW_CFG;                 /**< , offset: 0x8C */
  __I  uint32_t FIFO_LEN;                          /**< , offset: 0x90 */
  __I  uint32_t FIFO_READ;                         /**< , offset: 0x94 */
  __I  uint32_t FIFO_WRITE;                        /**< , offset: 0x98 */
  __O  uint32_t FIFO_CMD;                          /**< , offset: 0x9C */
       uint8_t RESERVED_2[96];
  __IO uint32_t I3C_CONFIG;                        /**< , offset: 0x100 */
  __IO uint32_t I3C_CTRL;                          /**< , offset: 0x104 */
  __I  uint32_t I3C_ERROR;                         /**< , offset: 0x108 */
  __O  uint32_t I3C_ERROR_CLEAR;                   /**< , offset: 0x10C */
  __I  uint32_t I3C_ACTIVITY;                      /**< , offset: 0x110 */
  __I  uint32_t I3C_CAPABILITIES;                  /**< , offset: 0x114 */
  __IO uint32_t I3C_DYNADDR;                       /**< , offset: 0x118 */
  __IO uint32_t I3C_PARTNO;                        /**< , offset: 0x11C */
  __IO uint32_t I3C_IDEXT;                         /**< , offset: 0x120 */
  __IO uint32_t I3C_MAXLIMITS;                     /**< , offset: 0x124 */
       uint8_t RESERVED_3[3760];
  __O  uint32_t INT_CLR_ENABLE;                    /**< , offset: 0xFD8 */
  __O  uint32_t INT_SET_ENABLE;                    /**< , offset: 0xFDC */
  __I  uint32_t INT_STATUS;                        /**< , offset: 0xFE0 */
  __I  uint32_t INT_ENABLE;                        /**< , offset: 0xFE4 */
  __O  uint32_t INT_CLR_STATUS;                    /**< , offset: 0xFE8 */
  __O  uint32_t INT_SET_STATUS;                    /**< , offset: 0xFEC */
} HOSTIF_Type;

/* ----------------------------------------------------------------------------
   -- HOSTIF Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup HOSTIF_Register_Masks HOSTIF Register Masks
 * @{
 */

/*! @name STATUS -  */
/*! @{ */

#define HOSTIF_STATUS_RX0_BUFFER_LOCK_MASK       (0x1U)
#define HOSTIF_STATUS_RX0_BUFFER_LOCK_SHIFT      (0U)
#define HOSTIF_STATUS_RX0_BUFFER_LOCK(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_RX0_BUFFER_LOCK_SHIFT)) & HOSTIF_STATUS_RX0_BUFFER_LOCK_MASK)

#define HOSTIF_STATUS_RX1_BUFFER_LOCK_MASK       (0x2U)
#define HOSTIF_STATUS_RX1_BUFFER_LOCK_SHIFT      (1U)
#define HOSTIF_STATUS_RX1_BUFFER_LOCK(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_RX1_BUFFER_LOCK_SHIFT)) & HOSTIF_STATUS_RX1_BUFFER_LOCK_MASK)

#define HOSTIF_STATUS_RX2_BUFFER_LOCK_MASK       (0x4U)
#define HOSTIF_STATUS_RX2_BUFFER_LOCK_SHIFT      (2U)
#define HOSTIF_STATUS_RX2_BUFFER_LOCK(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_RX2_BUFFER_LOCK_SHIFT)) & HOSTIF_STATUS_RX2_BUFFER_LOCK_MASK)

#define HOSTIF_STATUS_RX3_BUFFER_LOCK_MASK       (0x8U)
#define HOSTIF_STATUS_RX3_BUFFER_LOCK_SHIFT      (3U)
#define HOSTIF_STATUS_RX3_BUFFER_LOCK(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_RX3_BUFFER_LOCK_SHIFT)) & HOSTIF_STATUS_RX3_BUFFER_LOCK_MASK)

#define HOSTIF_STATUS_TX_BUFFER_LOCK_MASK        (0x10U)
#define HOSTIF_STATUS_TX_BUFFER_LOCK_SHIFT       (4U)
#define HOSTIF_STATUS_TX_BUFFER_LOCK(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_TX_BUFFER_LOCK_SHIFT)) & HOSTIF_STATUS_TX_BUFFER_LOCK_MASK)

#define HOSTIF_STATUS_TX_BUFFER_PREFETCH_OK_MASK (0x20U)
#define HOSTIF_STATUS_TX_BUFFER_PREFETCH_OK_SHIFT (5U)
#define HOSTIF_STATUS_TX_BUFFER_PREFETCH_OK(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_TX_BUFFER_PREFETCH_OK_SHIFT)) & HOSTIF_STATUS_TX_BUFFER_PREFETCH_OK_MASK)

#define HOSTIF_STATUS_HOSTCOMM_ONGOING_MASK      (0x40U)
#define HOSTIF_STATUS_HOSTCOMM_ONGOING_SHIFT     (6U)
#define HOSTIF_STATUS_HOSTCOMM_ONGOING(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_STATUS_HOSTCOMM_ONGOING_SHIFT)) & HOSTIF_STATUS_HOSTCOMM_ONGOING_MASK)
/*! @} */

/*! @name CONTROL -  */
/*! @{ */

#define HOSTIF_CONTROL_FIFO_MODE_MASK            (0x1U)
#define HOSTIF_CONTROL_FIFO_MODE_SHIFT           (0U)
#define HOSTIF_CONTROL_FIFO_MODE(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_FIFO_MODE_SHIFT)) & HOSTIF_CONTROL_FIFO_MODE_MASK)

#define HOSTIF_CONTROL_HIF_ENABLE_MASK           (0x2U)
#define HOSTIF_CONTROL_HIF_ENABLE_SHIFT          (1U)
#define HOSTIF_CONTROL_HIF_ENABLE(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_HIF_ENABLE_SHIFT)) & HOSTIF_CONTROL_HIF_ENABLE_MASK)

#define HOSTIF_CONTROL_CRC_ENABLE_MASK           (0x4U)
#define HOSTIF_CONTROL_CRC_ENABLE_SHIFT          (2U)
#define HOSTIF_CONTROL_CRC_ENABLE(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_CRC_ENABLE_SHIFT)) & HOSTIF_CONTROL_CRC_ENABLE_MASK)

#define HOSTIF_CONTROL_RX0_UPD_ENABLE_MASK       (0x8U)
#define HOSTIF_CONTROL_RX0_UPD_ENABLE_SHIFT      (3U)
#define HOSTIF_CONTROL_RX0_UPD_ENABLE(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_RX0_UPD_ENABLE_SHIFT)) & HOSTIF_CONTROL_RX0_UPD_ENABLE_MASK)

#define HOSTIF_CONTROL_RX1_UPD_ENABLE_MASK       (0x10U)
#define HOSTIF_CONTROL_RX1_UPD_ENABLE_SHIFT      (4U)
#define HOSTIF_CONTROL_RX1_UPD_ENABLE(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_RX1_UPD_ENABLE_SHIFT)) & HOSTIF_CONTROL_RX1_UPD_ENABLE_MASK)

#define HOSTIF_CONTROL_RX2_UPD_ENABLE_MASK       (0x20U)
#define HOSTIF_CONTROL_RX2_UPD_ENABLE_SHIFT      (5U)
#define HOSTIF_CONTROL_RX2_UPD_ENABLE(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_RX2_UPD_ENABLE_SHIFT)) & HOSTIF_CONTROL_RX2_UPD_ENABLE_MASK)

#define HOSTIF_CONTROL_RX3_UPD_ENABLE_MASK       (0x40U)
#define HOSTIF_CONTROL_RX3_UPD_ENABLE_SHIFT      (6U)
#define HOSTIF_CONTROL_RX3_UPD_ENABLE(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_RX3_UPD_ENABLE_SHIFT)) & HOSTIF_CONTROL_RX3_UPD_ENABLE_MASK)

#define HOSTIF_CONTROL_EXT_IRQ_CTRL_ENABLE_MASK  (0x80U)
#define HOSTIF_CONTROL_EXT_IRQ_CTRL_ENABLE_SHIFT (7U)
#define HOSTIF_CONTROL_EXT_IRQ_CTRL_ENABLE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_CONTROL_EXT_IRQ_CTRL_ENABLE_SHIFT)) & HOSTIF_CONTROL_EXT_IRQ_CTRL_ENABLE_MASK)
/*! @} */

/*! @name I2C_CONTROL -  */
/*! @{ */

#define HOSTIF_I2C_CONTROL_I2C_ADDR_MASK         (0x3U)
#define HOSTIF_I2C_CONTROL_I2C_ADDR_SHIFT        (0U)
#define HOSTIF_I2C_CONTROL_I2C_ADDR(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I2C_CONTROL_I2C_ADDR_SHIFT)) & HOSTIF_I2C_CONTROL_I2C_ADDR_MASK)

#define HOSTIF_I2C_CONTROL_I2C_HS_ENABLE_MASK    (0x4U)
#define HOSTIF_I2C_CONTROL_I2C_HS_ENABLE_SHIFT   (2U)
#define HOSTIF_I2C_CONTROL_I2C_HS_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_I2C_CONTROL_I2C_HS_ENABLE_SHIFT)) & HOSTIF_I2C_CONTROL_I2C_HS_ENABLE_MASK)

#define HOSTIF_I2C_CONTROL_I2C_RESET_ENABLE_MASK (0x8U)
#define HOSTIF_I2C_CONTROL_I2C_RESET_ENABLE_SHIFT (3U)
#define HOSTIF_I2C_CONTROL_I2C_RESET_ENABLE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_I2C_CONTROL_I2C_RESET_ENABLE_SHIFT)) & HOSTIF_I2C_CONTROL_I2C_RESET_ENABLE_MASK)

#define HOSTIF_I2C_CONTROL_I2C_DEVID_ENABLE_MASK (0x10U)
#define HOSTIF_I2C_CONTROL_I2C_DEVID_ENABLE_SHIFT (4U)
#define HOSTIF_I2C_CONTROL_I2C_DEVID_ENABLE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_I2C_CONTROL_I2C_DEVID_ENABLE_SHIFT)) & HOSTIF_I2C_CONTROL_I2C_DEVID_ENABLE_MASK)

#define HOSTIF_I2C_CONTROL_I2C_REV_ID_MASK       (0xE0U)
#define HOSTIF_I2C_CONTROL_I2C_REV_ID_SHIFT      (5U)
#define HOSTIF_I2C_CONTROL_I2C_REV_ID(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_I2C_CONTROL_I2C_REV_ID_SHIFT)) & HOSTIF_I2C_CONTROL_I2C_REV_ID_MASK)
/*! @} */

/*! @name SPI_CONTROL -  */
/*! @{ */

#define HOSTIF_SPI_CONTROL_SPI_CPOL_MASK         (0x1U)
#define HOSTIF_SPI_CONTROL_SPI_CPOL_SHIFT        (0U)
#define HOSTIF_SPI_CONTROL_SPI_CPOL(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPI_CONTROL_SPI_CPOL_SHIFT)) & HOSTIF_SPI_CONTROL_SPI_CPOL_MASK)

#define HOSTIF_SPI_CONTROL_SPI_CPHA_MASK         (0x2U)
#define HOSTIF_SPI_CONTROL_SPI_CPHA_SHIFT        (1U)
#define HOSTIF_SPI_CONTROL_SPI_CPHA(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPI_CONTROL_SPI_CPHA_SHIFT)) & HOSTIF_SPI_CONTROL_SPI_CPHA_MASK)
/*! @} */

/*! @name BUFFER_RX0_CFG -  */
/*! @{ */

#define HOSTIF_BUFFER_RX0_CFG_RX0_START_ADDR_MASK (0xFFFFU)
#define HOSTIF_BUFFER_RX0_CFG_RX0_START_ADDR_SHIFT (0U)
#define HOSTIF_BUFFER_RX0_CFG_RX0_START_ADDR(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX0_CFG_RX0_START_ADDR_SHIFT)) & HOSTIF_BUFFER_RX0_CFG_RX0_START_ADDR_MASK)

#define HOSTIF_BUFFER_RX0_CFG_RX0_MAX_SIZE_MASK  (0x7FF0000U)
#define HOSTIF_BUFFER_RX0_CFG_RX0_MAX_SIZE_SHIFT (16U)
#define HOSTIF_BUFFER_RX0_CFG_RX0_MAX_SIZE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX0_CFG_RX0_MAX_SIZE_SHIFT)) & HOSTIF_BUFFER_RX0_CFG_RX0_MAX_SIZE_MASK)

#define HOSTIF_BUFFER_RX0_CFG_RX0_BUFFER_DISABLE_MASK (0x8000000U)
#define HOSTIF_BUFFER_RX0_CFG_RX0_BUFFER_DISABLE_SHIFT (27U)
#define HOSTIF_BUFFER_RX0_CFG_RX0_BUFFER_DISABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX0_CFG_RX0_BUFFER_DISABLE_SHIFT)) & HOSTIF_BUFFER_RX0_CFG_RX0_BUFFER_DISABLE_MASK)
/*! @} */

/*! @name BUFFER_RX1_CFG -  */
/*! @{ */

#define HOSTIF_BUFFER_RX1_CFG_RX1_START_ADDR_MASK (0xFFFFU)
#define HOSTIF_BUFFER_RX1_CFG_RX1_START_ADDR_SHIFT (0U)
#define HOSTIF_BUFFER_RX1_CFG_RX1_START_ADDR(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX1_CFG_RX1_START_ADDR_SHIFT)) & HOSTIF_BUFFER_RX1_CFG_RX1_START_ADDR_MASK)

#define HOSTIF_BUFFER_RX1_CFG_RX1_MAX_SIZE_MASK  (0x7FF0000U)
#define HOSTIF_BUFFER_RX1_CFG_RX1_MAX_SIZE_SHIFT (16U)
#define HOSTIF_BUFFER_RX1_CFG_RX1_MAX_SIZE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX1_CFG_RX1_MAX_SIZE_SHIFT)) & HOSTIF_BUFFER_RX1_CFG_RX1_MAX_SIZE_MASK)

#define HOSTIF_BUFFER_RX1_CFG_RX1_BUFFER_DISABLE_MASK (0x8000000U)
#define HOSTIF_BUFFER_RX1_CFG_RX1_BUFFER_DISABLE_SHIFT (27U)
#define HOSTIF_BUFFER_RX1_CFG_RX1_BUFFER_DISABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX1_CFG_RX1_BUFFER_DISABLE_SHIFT)) & HOSTIF_BUFFER_RX1_CFG_RX1_BUFFER_DISABLE_MASK)
/*! @} */

/*! @name BUFFER_RX2_CFG -  */
/*! @{ */

#define HOSTIF_BUFFER_RX2_CFG_RX2_START_ADDR_MASK (0xFFFFU)
#define HOSTIF_BUFFER_RX2_CFG_RX2_START_ADDR_SHIFT (0U)
#define HOSTIF_BUFFER_RX2_CFG_RX2_START_ADDR(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX2_CFG_RX2_START_ADDR_SHIFT)) & HOSTIF_BUFFER_RX2_CFG_RX2_START_ADDR_MASK)

#define HOSTIF_BUFFER_RX2_CFG_RX2_MAX_SIZE_MASK  (0x7FF0000U)
#define HOSTIF_BUFFER_RX2_CFG_RX2_MAX_SIZE_SHIFT (16U)
#define HOSTIF_BUFFER_RX2_CFG_RX2_MAX_SIZE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX2_CFG_RX2_MAX_SIZE_SHIFT)) & HOSTIF_BUFFER_RX2_CFG_RX2_MAX_SIZE_MASK)

#define HOSTIF_BUFFER_RX2_CFG_RX2_BUFFER_DISABLE_MASK (0x8000000U)
#define HOSTIF_BUFFER_RX2_CFG_RX2_BUFFER_DISABLE_SHIFT (27U)
#define HOSTIF_BUFFER_RX2_CFG_RX2_BUFFER_DISABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX2_CFG_RX2_BUFFER_DISABLE_SHIFT)) & HOSTIF_BUFFER_RX2_CFG_RX2_BUFFER_DISABLE_MASK)
/*! @} */

/*! @name BUFFER_RX3_CFG -  */
/*! @{ */

#define HOSTIF_BUFFER_RX3_CFG_RX3_START_ADDR_MASK (0xFFFFU)
#define HOSTIF_BUFFER_RX3_CFG_RX3_START_ADDR_SHIFT (0U)
#define HOSTIF_BUFFER_RX3_CFG_RX3_START_ADDR(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX3_CFG_RX3_START_ADDR_SHIFT)) & HOSTIF_BUFFER_RX3_CFG_RX3_START_ADDR_MASK)

#define HOSTIF_BUFFER_RX3_CFG_RX3_MAX_SIZE_MASK  (0x7FF0000U)
#define HOSTIF_BUFFER_RX3_CFG_RX3_MAX_SIZE_SHIFT (16U)
#define HOSTIF_BUFFER_RX3_CFG_RX3_MAX_SIZE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX3_CFG_RX3_MAX_SIZE_SHIFT)) & HOSTIF_BUFFER_RX3_CFG_RX3_MAX_SIZE_MASK)

#define HOSTIF_BUFFER_RX3_CFG_RX3_BUFFER_DISABLE_MASK (0x8000000U)
#define HOSTIF_BUFFER_RX3_CFG_RX3_BUFFER_DISABLE_SHIFT (27U)
#define HOSTIF_BUFFER_RX3_CFG_RX3_BUFFER_DISABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX3_CFG_RX3_BUFFER_DISABLE_SHIFT)) & HOSTIF_BUFFER_RX3_CFG_RX3_BUFFER_DISABLE_MASK)
/*! @} */

/*! @name BUFFER_TX_CFG -  */
/*! @{ */

#define HOSTIF_BUFFER_TX_CFG_TX_START_ADDR_MASK  (0xFFFFU)
#define HOSTIF_BUFFER_TX_CFG_TX_START_ADDR_SHIFT (0U)
#define HOSTIF_BUFFER_TX_CFG_TX_START_ADDR(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_TX_CFG_TX_START_ADDR_SHIFT)) & HOSTIF_BUFFER_TX_CFG_TX_START_ADDR_MASK)
/*! @} */

/*! @name BUFFER_RX0_LEN -  */
/*! @{ */

#define HOSTIF_BUFFER_RX0_LEN_RX0_LENGTH_MASK    (0x7FFU)
#define HOSTIF_BUFFER_RX0_LEN_RX0_LENGTH_SHIFT   (0U)
#define HOSTIF_BUFFER_RX0_LEN_RX0_LENGTH(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX0_LEN_RX0_LENGTH_SHIFT)) & HOSTIF_BUFFER_RX0_LEN_RX0_LENGTH_MASK)

#define HOSTIF_BUFFER_RX0_LEN_RX0_CRC_OK_MASK    (0x800U)
#define HOSTIF_BUFFER_RX0_LEN_RX0_CRC_OK_SHIFT   (11U)
#define HOSTIF_BUFFER_RX0_LEN_RX0_CRC_OK(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX0_LEN_RX0_CRC_OK_SHIFT)) & HOSTIF_BUFFER_RX0_LEN_RX0_CRC_OK_MASK)
/*! @} */

/*! @name BUFFER_RX1_LEN -  */
/*! @{ */

#define HOSTIF_BUFFER_RX1_LEN_RX1_LENGTH_MASK    (0x7FFU)
#define HOSTIF_BUFFER_RX1_LEN_RX1_LENGTH_SHIFT   (0U)
#define HOSTIF_BUFFER_RX1_LEN_RX1_LENGTH(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX1_LEN_RX1_LENGTH_SHIFT)) & HOSTIF_BUFFER_RX1_LEN_RX1_LENGTH_MASK)

#define HOSTIF_BUFFER_RX1_LEN_RX1_CRC_OK_MASK    (0x800U)
#define HOSTIF_BUFFER_RX1_LEN_RX1_CRC_OK_SHIFT   (11U)
#define HOSTIF_BUFFER_RX1_LEN_RX1_CRC_OK(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX1_LEN_RX1_CRC_OK_SHIFT)) & HOSTIF_BUFFER_RX1_LEN_RX1_CRC_OK_MASK)
/*! @} */

/*! @name BUFFER_RX2_LEN -  */
/*! @{ */

#define HOSTIF_BUFFER_RX2_LEN_RX2_LENGTH_MASK    (0x7FFU)
#define HOSTIF_BUFFER_RX2_LEN_RX2_LENGTH_SHIFT   (0U)
#define HOSTIF_BUFFER_RX2_LEN_RX2_LENGTH(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX2_LEN_RX2_LENGTH_SHIFT)) & HOSTIF_BUFFER_RX2_LEN_RX2_LENGTH_MASK)

#define HOSTIF_BUFFER_RX2_LEN_RX2_CRC_OK_MASK    (0x800U)
#define HOSTIF_BUFFER_RX2_LEN_RX2_CRC_OK_SHIFT   (11U)
#define HOSTIF_BUFFER_RX2_LEN_RX2_CRC_OK(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX2_LEN_RX2_CRC_OK_SHIFT)) & HOSTIF_BUFFER_RX2_LEN_RX2_CRC_OK_MASK)
/*! @} */

/*! @name BUFFER_RX3_LEN -  */
/*! @{ */

#define HOSTIF_BUFFER_RX3_LEN_RX3_LENGTH_MASK    (0x7FFU)
#define HOSTIF_BUFFER_RX3_LEN_RX3_LENGTH_SHIFT   (0U)
#define HOSTIF_BUFFER_RX3_LEN_RX3_LENGTH(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX3_LEN_RX3_LENGTH_SHIFT)) & HOSTIF_BUFFER_RX3_LEN_RX3_LENGTH_MASK)

#define HOSTIF_BUFFER_RX3_LEN_RX3_CRC_OK_MASK    (0x800U)
#define HOSTIF_BUFFER_RX3_LEN_RX3_CRC_OK_SHIFT   (11U)
#define HOSTIF_BUFFER_RX3_LEN_RX3_CRC_OK(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_RX3_LEN_RX3_CRC_OK_SHIFT)) & HOSTIF_BUFFER_RX3_LEN_RX3_CRC_OK_MASK)
/*! @} */

/*! @name BUFFER_TX_LEN -  */
/*! @{ */

#define HOSTIF_BUFFER_TX_LEN_TX_LENGTH_MASK      (0x7FFU)
#define HOSTIF_BUFFER_TX_LEN_TX_LENGTH_SHIFT     (0U)
#define HOSTIF_BUFFER_TX_LEN_TX_LENGTH(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_BUFFER_TX_LEN_TX_LENGTH_SHIFT)) & HOSTIF_BUFFER_TX_LEN_TX_LENGTH_MASK)
/*! @} */

/*! @name TIC_TIMEOUT -  */
/*! @{ */

#define HOSTIF_TIC_TIMEOUT_TX_TIMEOUT_VALUE_MASK (0xFFFFU)
#define HOSTIF_TIC_TIMEOUT_TX_TIMEOUT_VALUE_SHIFT (0U)
#define HOSTIF_TIC_TIMEOUT_TX_TIMEOUT_VALUE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_TIC_TIMEOUT_TX_TIMEOUT_VALUE_SHIFT)) & HOSTIF_TIC_TIMEOUT_TX_TIMEOUT_VALUE_MASK)
/*! @} */

/*! @name WATERLEVEL -  */
/*! @{ */

#define HOSTIF_WATERLEVEL_WATERLEVEL_MASK        (0x7FFU)
#define HOSTIF_WATERLEVEL_WATERLEVEL_SHIFT       (0U)
#define HOSTIF_WATERLEVEL_WATERLEVEL(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_WATERLEVEL_WATERLEVEL_SHIFT)) & HOSTIF_WATERLEVEL_WATERLEVEL_MASK)
/*! @} */

/*! @name SET_DATA_READY -  */
/*! @{ */

#define HOSTIF_SET_DATA_READY_SET_RX0_DATA_READY_MASK (0x1U)
#define HOSTIF_SET_DATA_READY_SET_RX0_DATA_READY_SHIFT (0U)
#define HOSTIF_SET_DATA_READY_SET_RX0_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_SET_DATA_READY_SET_RX0_DATA_READY_SHIFT)) & HOSTIF_SET_DATA_READY_SET_RX0_DATA_READY_MASK)

#define HOSTIF_SET_DATA_READY_SET_RX1_DATA_READY_MASK (0x2U)
#define HOSTIF_SET_DATA_READY_SET_RX1_DATA_READY_SHIFT (1U)
#define HOSTIF_SET_DATA_READY_SET_RX1_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_SET_DATA_READY_SET_RX1_DATA_READY_SHIFT)) & HOSTIF_SET_DATA_READY_SET_RX1_DATA_READY_MASK)

#define HOSTIF_SET_DATA_READY_SET_RX2_DATA_READY_MASK (0x4U)
#define HOSTIF_SET_DATA_READY_SET_RX2_DATA_READY_SHIFT (2U)
#define HOSTIF_SET_DATA_READY_SET_RX2_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_SET_DATA_READY_SET_RX2_DATA_READY_SHIFT)) & HOSTIF_SET_DATA_READY_SET_RX2_DATA_READY_MASK)

#define HOSTIF_SET_DATA_READY_SET_RX3_DATA_READY_MASK (0x8U)
#define HOSTIF_SET_DATA_READY_SET_RX3_DATA_READY_SHIFT (3U)
#define HOSTIF_SET_DATA_READY_SET_RX3_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_SET_DATA_READY_SET_RX3_DATA_READY_SHIFT)) & HOSTIF_SET_DATA_READY_SET_RX3_DATA_READY_MASK)

#define HOSTIF_SET_DATA_READY_SET_TX_DATA_READY_MASK (0x10U)
#define HOSTIF_SET_DATA_READY_SET_TX_DATA_READY_SHIFT (4U)
#define HOSTIF_SET_DATA_READY_SET_TX_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_SET_DATA_READY_SET_TX_DATA_READY_SHIFT)) & HOSTIF_SET_DATA_READY_SET_TX_DATA_READY_MASK)
/*! @} */

/*! @name CLR_DATA_READY -  */
/*! @{ */

#define HOSTIF_CLR_DATA_READY_CLR_RX0_DATA_READY_MASK (0x1U)
#define HOSTIF_CLR_DATA_READY_CLR_RX0_DATA_READY_SHIFT (0U)
#define HOSTIF_CLR_DATA_READY_CLR_RX0_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_CLR_DATA_READY_CLR_RX0_DATA_READY_SHIFT)) & HOSTIF_CLR_DATA_READY_CLR_RX0_DATA_READY_MASK)

#define HOSTIF_CLR_DATA_READY_CLR_RX1_DATA_READY_MASK (0x2U)
#define HOSTIF_CLR_DATA_READY_CLR_RX1_DATA_READY_SHIFT (1U)
#define HOSTIF_CLR_DATA_READY_CLR_RX1_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_CLR_DATA_READY_CLR_RX1_DATA_READY_SHIFT)) & HOSTIF_CLR_DATA_READY_CLR_RX1_DATA_READY_MASK)

#define HOSTIF_CLR_DATA_READY_CLR_RX2_DATA_READY_MASK (0x4U)
#define HOSTIF_CLR_DATA_READY_CLR_RX2_DATA_READY_SHIFT (2U)
#define HOSTIF_CLR_DATA_READY_CLR_RX2_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_CLR_DATA_READY_CLR_RX2_DATA_READY_SHIFT)) & HOSTIF_CLR_DATA_READY_CLR_RX2_DATA_READY_MASK)

#define HOSTIF_CLR_DATA_READY_CLR_RX3_DATA_READY_MASK (0x8U)
#define HOSTIF_CLR_DATA_READY_CLR_RX3_DATA_READY_SHIFT (3U)
#define HOSTIF_CLR_DATA_READY_CLR_RX3_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_CLR_DATA_READY_CLR_RX3_DATA_READY_SHIFT)) & HOSTIF_CLR_DATA_READY_CLR_RX3_DATA_READY_MASK)

#define HOSTIF_CLR_DATA_READY_CLR_TX_DATA_READY_MASK (0x10U)
#define HOSTIF_CLR_DATA_READY_CLR_TX_DATA_READY_SHIFT (4U)
#define HOSTIF_CLR_DATA_READY_CLR_TX_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_CLR_DATA_READY_CLR_TX_DATA_READY_SHIFT)) & HOSTIF_CLR_DATA_READY_CLR_TX_DATA_READY_MASK)
/*! @} */

/*! @name DATA_READY_STATUS -  */
/*! @{ */

#define HOSTIF_DATA_READY_STATUS_RX0_DATA_READY_MASK (0x1U)
#define HOSTIF_DATA_READY_STATUS_RX0_DATA_READY_SHIFT (0U)
#define HOSTIF_DATA_READY_STATUS_RX0_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_DATA_READY_STATUS_RX0_DATA_READY_SHIFT)) & HOSTIF_DATA_READY_STATUS_RX0_DATA_READY_MASK)

#define HOSTIF_DATA_READY_STATUS_RX1_DATA_READY_MASK (0x2U)
#define HOSTIF_DATA_READY_STATUS_RX1_DATA_READY_SHIFT (1U)
#define HOSTIF_DATA_READY_STATUS_RX1_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_DATA_READY_STATUS_RX1_DATA_READY_SHIFT)) & HOSTIF_DATA_READY_STATUS_RX1_DATA_READY_MASK)

#define HOSTIF_DATA_READY_STATUS_RX2_DATA_READY_MASK (0x4U)
#define HOSTIF_DATA_READY_STATUS_RX2_DATA_READY_SHIFT (2U)
#define HOSTIF_DATA_READY_STATUS_RX2_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_DATA_READY_STATUS_RX2_DATA_READY_SHIFT)) & HOSTIF_DATA_READY_STATUS_RX2_DATA_READY_MASK)

#define HOSTIF_DATA_READY_STATUS_RX3_DATA_READY_MASK (0x8U)
#define HOSTIF_DATA_READY_STATUS_RX3_DATA_READY_SHIFT (3U)
#define HOSTIF_DATA_READY_STATUS_RX3_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_DATA_READY_STATUS_RX3_DATA_READY_SHIFT)) & HOSTIF_DATA_READY_STATUS_RX3_DATA_READY_MASK)

#define HOSTIF_DATA_READY_STATUS_TX_DATA_READY_MASK (0x10U)
#define HOSTIF_DATA_READY_STATUS_TX_DATA_READY_SHIFT (4U)
#define HOSTIF_DATA_READY_STATUS_TX_DATA_READY(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_DATA_READY_STATUS_TX_DATA_READY_SHIFT)) & HOSTIF_DATA_READY_STATUS_TX_DATA_READY_MASK)
/*! @} */

/*! @name TBSEL -  */
/*! @{ */

#define HOSTIF_TBSEL_TESTBUS_SELECT_MASK         (0xFU)
#define HOSTIF_TBSEL_TESTBUS_SELECT_SHIFT        (0U)
#define HOSTIF_TBSEL_TESTBUS_SELECT(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_TBSEL_TESTBUS_SELECT_SHIFT)) & HOSTIF_TBSEL_TESTBUS_SELECT_MASK)
/*! @} */

/*! @name TBVALUE -  */
/*! @{ */

#define HOSTIF_TBVALUE_TESTBUS_VALUE_MASK        (0xFFU)
#define HOSTIF_TBVALUE_TESTBUS_VALUE_SHIFT       (0U)
#define HOSTIF_TBVALUE_TESTBUS_VALUE(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_TBVALUE_TESTBUS_VALUE_SHIFT)) & HOSTIF_TBVALUE_TESTBUS_VALUE_MASK)
/*! @} */

/*! @name SPARE -  */
/*! @{ */

#define HOSTIF_SPARE_SPARE0_MASK                 (0x1U)
#define HOSTIF_SPARE_SPARE0_SHIFT                (0U)
#define HOSTIF_SPARE_SPARE0(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE0_SHIFT)) & HOSTIF_SPARE_SPARE0_MASK)

#define HOSTIF_SPARE_SPARE1_MASK                 (0x2U)
#define HOSTIF_SPARE_SPARE1_SHIFT                (1U)
#define HOSTIF_SPARE_SPARE1(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE1_SHIFT)) & HOSTIF_SPARE_SPARE1_MASK)

#define HOSTIF_SPARE_SPARE2_MASK                 (0x4U)
#define HOSTIF_SPARE_SPARE2_SHIFT                (2U)
#define HOSTIF_SPARE_SPARE2(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE2_SHIFT)) & HOSTIF_SPARE_SPARE2_MASK)

#define HOSTIF_SPARE_SPARE3_MASK                 (0x8U)
#define HOSTIF_SPARE_SPARE3_SHIFT                (3U)
#define HOSTIF_SPARE_SPARE3(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE3_SHIFT)) & HOSTIF_SPARE_SPARE3_MASK)

#define HOSTIF_SPARE_SPARE4_MASK                 (0x10U)
#define HOSTIF_SPARE_SPARE4_SHIFT                (4U)
#define HOSTIF_SPARE_SPARE4(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE4_SHIFT)) & HOSTIF_SPARE_SPARE4_MASK)

#define HOSTIF_SPARE_SPARE5_MASK                 (0x20U)
#define HOSTIF_SPARE_SPARE5_SHIFT                (5U)
#define HOSTIF_SPARE_SPARE5(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE5_SHIFT)) & HOSTIF_SPARE_SPARE5_MASK)

#define HOSTIF_SPARE_SPARE6_MASK                 (0x40U)
#define HOSTIF_SPARE_SPARE6_SHIFT                (6U)
#define HOSTIF_SPARE_SPARE6(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE6_SHIFT)) & HOSTIF_SPARE_SPARE6_MASK)

#define HOSTIF_SPARE_SPARE7_MASK                 (0x80U)
#define HOSTIF_SPARE_SPARE7_SHIFT                (7U)
#define HOSTIF_SPARE_SPARE7(x)                   (((uint32_t)(((uint32_t)(x)) << HOSTIF_SPARE_SPARE7_SHIFT)) & HOSTIF_SPARE_SPARE7_MASK)
/*! @} */

/*! @name HSU_CONTROL -  */
/*! @{ */

#define HOSTIF_HSU_CONTROL_HSU_RX_DIVIDER_MASK   (0x7FFU)
#define HOSTIF_HSU_CONTROL_HSU_RX_DIVIDER_SHIFT  (0U)
#define HOSTIF_HSU_CONTROL_HSU_RX_DIVIDER(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_CONTROL_HSU_RX_DIVIDER_SHIFT)) & HOSTIF_HSU_CONTROL_HSU_RX_DIVIDER_MASK)

#define HOSTIF_HSU_CONTROL_HSU_TX_DIVIDER_MASK   (0x800U)
#define HOSTIF_HSU_CONTROL_HSU_TX_DIVIDER_SHIFT  (11U)
#define HOSTIF_HSU_CONTROL_HSU_TX_DIVIDER(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_CONTROL_HSU_TX_DIVIDER_SHIFT)) & HOSTIF_HSU_CONTROL_HSU_TX_DIVIDER_MASK)

#define HOSTIF_HSU_CONTROL_HSU_STOPBIT_MASK      (0x1000U)
#define HOSTIF_HSU_CONTROL_HSU_STOPBIT_SHIFT     (12U)
#define HOSTIF_HSU_CONTROL_HSU_STOPBIT(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_CONTROL_HSU_STOPBIT_SHIFT)) & HOSTIF_HSU_CONTROL_HSU_STOPBIT_MASK)

#define HOSTIF_HSU_CONTROL_HSU_EOF_SIZE_MASK     (0xFE000U)
#define HOSTIF_HSU_CONTROL_HSU_EOF_SIZE_SHIFT    (13U)
#define HOSTIF_HSU_CONTROL_HSU_EOF_SIZE(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_CONTROL_HSU_EOF_SIZE_SHIFT)) & HOSTIF_HSU_CONTROL_HSU_EOF_SIZE_MASK)
/*! @} */

/*! @name HSU_SAMPLE -  */
/*! @{ */

#define HOSTIF_HSU_SAMPLE_HSU_RX_CLK_CORRECT_MASK (0x7FFU)
#define HOSTIF_HSU_SAMPLE_HSU_RX_CLK_CORRECT_SHIFT (0U)
#define HOSTIF_HSU_SAMPLE_HSU_RX_CLK_CORRECT(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_SAMPLE_HSU_RX_CLK_CORRECT_SHIFT)) & HOSTIF_HSU_SAMPLE_HSU_RX_CLK_CORRECT_MASK)

#define HOSTIF_HSU_SAMPLE_HSU_TX_CLK_CORRECT_MASK (0x3FF800U)
#define HOSTIF_HSU_SAMPLE_HSU_TX_CLK_CORRECT_SHIFT (11U)
#define HOSTIF_HSU_SAMPLE_HSU_TX_CLK_CORRECT(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_HSU_SAMPLE_HSU_TX_CLK_CORRECT_SHIFT)) & HOSTIF_HSU_SAMPLE_HSU_TX_CLK_CORRECT_MASK)
/*! @} */

/*! @name FIFO_CFG -  */
/*! @{ */

#define HOSTIF_FIFO_CFG_FIFO_START_ADDR_MASK     (0xFFFFU)
#define HOSTIF_FIFO_CFG_FIFO_START_ADDR_SHIFT    (0U)
#define HOSTIF_FIFO_CFG_FIFO_START_ADDR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_CFG_FIFO_START_ADDR_SHIFT)) & HOSTIF_FIFO_CFG_FIFO_START_ADDR_MASK)

#define HOSTIF_FIFO_CFG_FIFO_MAX_SIZE_MASK       (0x7FF0000U)
#define HOSTIF_FIFO_CFG_FIFO_MAX_SIZE_SHIFT      (16U)
#define HOSTIF_FIFO_CFG_FIFO_MAX_SIZE(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_CFG_FIFO_MAX_SIZE_SHIFT)) & HOSTIF_FIFO_CFG_FIFO_MAX_SIZE_MASK)
/*! @} */

/*! @name FIFO_FREE_CFG -  */
/*! @{ */

#define HOSTIF_FIFO_FREE_CFG_FIFO_FREE_SIZE_MASK (0x7FFU)
#define HOSTIF_FIFO_FREE_CFG_FIFO_FREE_SIZE_SHIFT (0U)
#define HOSTIF_FIFO_FREE_CFG_FIFO_FREE_SIZE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_FREE_CFG_FIFO_FREE_SIZE_SHIFT)) & HOSTIF_FIFO_FREE_CFG_FIFO_FREE_SIZE_MASK)
/*! @} */

/*! @name FIFO_STOP_CFG -  */
/*! @{ */

#define HOSTIF_FIFO_STOP_CFG_FIFO_STOP_ADDR_MASK (0xFFFFU)
#define HOSTIF_FIFO_STOP_CFG_FIFO_STOP_ADDR_SHIFT (0U)
#define HOSTIF_FIFO_STOP_CFG_FIFO_STOP_ADDR(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_STOP_CFG_FIFO_STOP_ADDR_SHIFT)) & HOSTIF_FIFO_STOP_CFG_FIFO_STOP_ADDR_MASK)
/*! @} */

/*! @name FIFO_OVERFLOW_CFG -  */
/*! @{ */

#define HOSTIF_FIFO_OVERFLOW_CFG_FIFO_OVERFLOW_MASK (0x7FFU)
#define HOSTIF_FIFO_OVERFLOW_CFG_FIFO_OVERFLOW_SHIFT (0U)
#define HOSTIF_FIFO_OVERFLOW_CFG_FIFO_OVERFLOW(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_OVERFLOW_CFG_FIFO_OVERFLOW_SHIFT)) & HOSTIF_FIFO_OVERFLOW_CFG_FIFO_OVERFLOW_MASK)
/*! @} */

/*! @name FIFO_LEN -  */
/*! @{ */

#define HOSTIF_FIFO_LEN_FIFO_BUF_OCCUPIED_LEN_MASK (0x7FFU)
#define HOSTIF_FIFO_LEN_FIFO_BUF_OCCUPIED_LEN_SHIFT (0U)
#define HOSTIF_FIFO_LEN_FIFO_BUF_OCCUPIED_LEN(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_LEN_FIFO_BUF_OCCUPIED_LEN_SHIFT)) & HOSTIF_FIFO_LEN_FIFO_BUF_OCCUPIED_LEN_MASK)
/*! @} */

/*! @name FIFO_READ -  */
/*! @{ */

#define HOSTIF_FIFO_READ_FIFO_READ_PTR_MASK      (0xFFFFU)
#define HOSTIF_FIFO_READ_FIFO_READ_PTR_SHIFT     (0U)
#define HOSTIF_FIFO_READ_FIFO_READ_PTR(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_READ_FIFO_READ_PTR_SHIFT)) & HOSTIF_FIFO_READ_FIFO_READ_PTR_MASK)
/*! @} */

/*! @name FIFO_WRITE -  */
/*! @{ */

#define HOSTIF_FIFO_WRITE_FIFO_WRITE_PTR_MASK    (0xFFFFU)
#define HOSTIF_FIFO_WRITE_FIFO_WRITE_PTR_SHIFT   (0U)
#define HOSTIF_FIFO_WRITE_FIFO_WRITE_PTR(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_WRITE_FIFO_WRITE_PTR_SHIFT)) & HOSTIF_FIFO_WRITE_FIFO_WRITE_PTR_MASK)
/*! @} */

/*! @name FIFO_CMD -  */
/*! @{ */

#define HOSTIF_FIFO_CMD_FIFO_FREE_N_MASK         (0x1U)
#define HOSTIF_FIFO_CMD_FIFO_FREE_N_SHIFT        (0U)
#define HOSTIF_FIFO_CMD_FIFO_FREE_N(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_CMD_FIFO_FREE_N_SHIFT)) & HOSTIF_FIFO_CMD_FIFO_FREE_N_MASK)

#define HOSTIF_FIFO_CMD_FIFO_RESET_MASK          (0x2U)
#define HOSTIF_FIFO_CMD_FIFO_RESET_SHIFT         (1U)
#define HOSTIF_FIFO_CMD_FIFO_RESET(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_FIFO_CMD_FIFO_RESET_SHIFT)) & HOSTIF_FIFO_CMD_FIFO_RESET_MASK)
/*! @} */

/*! @name I3C_CONFIG -  */
/*! @{ */

#define HOSTIF_I3C_CONFIG_SLVENA_MASK            (0x1U)
#define HOSTIF_I3C_CONFIG_SLVENA_SHIFT           (0U)
#define HOSTIF_I3C_CONFIG_SLVENA(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_SLVENA_SHIFT)) & HOSTIF_I3C_CONFIG_SLVENA_MASK)

#define HOSTIF_I3C_CONFIG_NACK_MASK              (0x2U)
#define HOSTIF_I3C_CONFIG_NACK_SHIFT             (1U)
#define HOSTIF_I3C_CONFIG_NACK(x)                (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_NACK_SHIFT)) & HOSTIF_I3C_CONFIG_NACK_MASK)

#define HOSTIF_I3C_CONFIG_DDROK_MASK             (0x10U)
#define HOSTIF_I3C_CONFIG_DDROK_SHIFT            (4U)
#define HOSTIF_I3C_CONFIG_DDROK(x)               (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_DDROK_SHIFT)) & HOSTIF_I3C_CONFIG_DDROK_MASK)

#define HOSTIF_I3C_CONFIG_TSPOK_MASK             (0x20U)
#define HOSTIF_I3C_CONFIG_TSPOK_SHIFT            (5U)
#define HOSTIF_I3C_CONFIG_TSPOK(x)               (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_TSPOK_SHIFT)) & HOSTIF_I3C_CONFIG_TSPOK_MASK)

#define HOSTIF_I3C_CONFIG_TSLOK_MASK             (0x40U)
#define HOSTIF_I3C_CONFIG_TSLOK_SHIFT            (6U)
#define HOSTIF_I3C_CONFIG_TSLOK(x)               (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_TSLOK_SHIFT)) & HOSTIF_I3C_CONFIG_TSLOK_MASK)

#define HOSTIF_I3C_CONFIG_IDRAND_MASK            (0x100U)
#define HOSTIF_I3C_CONFIG_IDRAND_SHIFT           (8U)
#define HOSTIF_I3C_CONFIG_IDRAND(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_IDRAND_SHIFT)) & HOSTIF_I3C_CONFIG_IDRAND_MASK)

#define HOSTIF_I3C_CONFIG_OFFLINE_MASK           (0x200U)
#define HOSTIF_I3C_CONFIG_OFFLINE_SHIFT          (9U)
#define HOSTIF_I3C_CONFIG_OFFLINE(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_OFFLINE_SHIFT)) & HOSTIF_I3C_CONFIG_OFFLINE_MASK)

#define HOSTIF_I3C_CONFIG_OVF_NACK_MASK          (0x400U)
#define HOSTIF_I3C_CONFIG_OVF_NACK_SHIFT         (10U)
#define HOSTIF_I3C_CONFIG_OVF_NACK(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_OVF_NACK_SHIFT)) & HOSTIF_I3C_CONFIG_OVF_NACK_MASK)

#define HOSTIF_I3C_CONFIG_SADDR_LSB_MASK         (0x6000000U)
#define HOSTIF_I3C_CONFIG_SADDR_LSB_SHIFT        (25U)
#define HOSTIF_I3C_CONFIG_SADDR_LSB(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_SADDR_LSB_SHIFT)) & HOSTIF_I3C_CONFIG_SADDR_LSB_MASK)

#define HOSTIF_I3C_CONFIG_SADDR_MSB_MASK         (0xF8000000U)
#define HOSTIF_I3C_CONFIG_SADDR_MSB_SHIFT        (27U)
#define HOSTIF_I3C_CONFIG_SADDR_MSB(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CONFIG_SADDR_MSB_SHIFT)) & HOSTIF_I3C_CONFIG_SADDR_MSB_MASK)
/*! @} */

/*! @name I3C_CTRL -  */
/*! @{ */

#define HOSTIF_I3C_CTRL_EVENT_REQ_MASK           (0x3U)
#define HOSTIF_I3C_CTRL_EVENT_REQ_SHIFT          (0U)
#define HOSTIF_I3C_CTRL_EVENT_REQ(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CTRL_EVENT_REQ_SHIFT)) & HOSTIF_I3C_CTRL_EVENT_REQ_MASK)

#define HOSTIF_I3C_CTRL_IBDATA_MASK              (0xFF00U)
#define HOSTIF_I3C_CTRL_IBDATA_SHIFT             (8U)
#define HOSTIF_I3C_CTRL_IBDATA(x)                (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CTRL_IBDATA_SHIFT)) & HOSTIF_I3C_CTRL_IBDATA_MASK)
/*! @} */

/*! @name I3C_ERROR -  */
/*! @{ */

#define HOSTIF_I3C_ERROR_ORUN_MASK               (0x1U)
#define HOSTIF_I3C_ERROR_ORUN_SHIFT              (0U)
#define HOSTIF_I3C_ERROR_ORUN(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_ORUN_SHIFT)) & HOSTIF_I3C_ERROR_ORUN_MASK)

#define HOSTIF_I3C_ERROR_URUN_MASK               (0x2U)
#define HOSTIF_I3C_ERROR_URUN_SHIFT              (1U)
#define HOSTIF_I3C_ERROR_URUN(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_URUN_SHIFT)) & HOSTIF_I3C_ERROR_URUN_MASK)

#define HOSTIF_I3C_ERROR_URUNACK_MASK            (0x4U)
#define HOSTIF_I3C_ERROR_URUNACK_SHIFT           (2U)
#define HOSTIF_I3C_ERROR_URUNACK(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_URUNACK_SHIFT)) & HOSTIF_I3C_ERROR_URUNACK_MASK)

#define HOSTIF_I3C_ERROR_TERM_MASK               (0x8U)
#define HOSTIF_I3C_ERROR_TERM_SHIFT              (3U)
#define HOSTIF_I3C_ERROR_TERM(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_TERM_SHIFT)) & HOSTIF_I3C_ERROR_TERM_MASK)

#define HOSTIF_I3C_ERROR_INVSTART_MASK           (0x10U)
#define HOSTIF_I3C_ERROR_INVSTART_SHIFT          (4U)
#define HOSTIF_I3C_ERROR_INVSTART(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_INVSTART_SHIFT)) & HOSTIF_I3C_ERROR_INVSTART_MASK)

#define HOSTIF_I3C_ERROR_SPAR_MASK               (0x100U)
#define HOSTIF_I3C_ERROR_SPAR_SHIFT              (8U)
#define HOSTIF_I3C_ERROR_SPAR(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_SPAR_SHIFT)) & HOSTIF_I3C_ERROR_SPAR_MASK)

#define HOSTIF_I3C_ERROR_HPAR_MASK               (0x200U)
#define HOSTIF_I3C_ERROR_HPAR_SHIFT              (9U)
#define HOSTIF_I3C_ERROR_HPAR(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_HPAR_SHIFT)) & HOSTIF_I3C_ERROR_HPAR_MASK)

#define HOSTIF_I3C_ERROR_HCRC_MASK               (0x400U)
#define HOSTIF_I3C_ERROR_HCRC_SHIFT              (10U)
#define HOSTIF_I3C_ERROR_HCRC(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_HCRC_SHIFT)) & HOSTIF_I3C_ERROR_HCRC_MASK)

#define HOSTIF_I3C_ERROR_S0S1_MASK               (0x800U)
#define HOSTIF_I3C_ERROR_S0S1_SHIFT              (11U)
#define HOSTIF_I3C_ERROR_S0S1(x)                 (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_S0S1_SHIFT)) & HOSTIF_I3C_ERROR_S0S1_MASK)
/*! @} */

/*! @name I3C_ERROR_CLEAR -  */
/*! @{ */

#define HOSTIF_I3C_ERROR_CLEAR_ORUN_CLR_MASK     (0x1U)
#define HOSTIF_I3C_ERROR_CLEAR_ORUN_CLR_SHIFT    (0U)
#define HOSTIF_I3C_ERROR_CLEAR_ORUN_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_ORUN_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_ORUN_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_URUN_CLR_MASK     (0x2U)
#define HOSTIF_I3C_ERROR_CLEAR_URUN_CLR_SHIFT    (1U)
#define HOSTIF_I3C_ERROR_CLEAR_URUN_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_URUN_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_URUN_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_URUNACK_CLR_MASK  (0x4U)
#define HOSTIF_I3C_ERROR_CLEAR_URUNACK_CLR_SHIFT (2U)
#define HOSTIF_I3C_ERROR_CLEAR_URUNACK_CLR(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_URUNACK_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_URUNACK_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_TERM_CLR_MASK     (0x8U)
#define HOSTIF_I3C_ERROR_CLEAR_TERM_CLR_SHIFT    (3U)
#define HOSTIF_I3C_ERROR_CLEAR_TERM_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_TERM_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_TERM_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_INVSTART_CLR_MASK (0x10U)
#define HOSTIF_I3C_ERROR_CLEAR_INVSTART_CLR_SHIFT (4U)
#define HOSTIF_I3C_ERROR_CLEAR_INVSTART_CLR(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_INVSTART_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_INVSTART_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_SPAR_CLR_MASK     (0x100U)
#define HOSTIF_I3C_ERROR_CLEAR_SPAR_CLR_SHIFT    (8U)
#define HOSTIF_I3C_ERROR_CLEAR_SPAR_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_SPAR_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_SPAR_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_HPAR_CLR_MASK     (0x200U)
#define HOSTIF_I3C_ERROR_CLEAR_HPAR_CLR_SHIFT    (9U)
#define HOSTIF_I3C_ERROR_CLEAR_HPAR_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_HPAR_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_HPAR_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_HCRC_CLR_MASK     (0x400U)
#define HOSTIF_I3C_ERROR_CLEAR_HCRC_CLR_SHIFT    (10U)
#define HOSTIF_I3C_ERROR_CLEAR_HCRC_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_HCRC_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_HCRC_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_S0S1_CLR_MASK     (0x800U)
#define HOSTIF_I3C_ERROR_CLEAR_S0S1_CLR_SHIFT    (11U)
#define HOSTIF_I3C_ERROR_CLEAR_S0S1_CLR(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_S0S1_CLR_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_S0S1_CLR_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_TB_FLUSH_MASK (0x40000000U)
#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_TB_FLUSH_SHIFT (30U)
#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_TB_FLUSH(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_DEBUG_TB_FLUSH_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_DEBUG_TB_FLUSH_MASK)

#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_FB_FLUSH_MASK (0x80000000U)
#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_FB_FLUSH_SHIFT (31U)
#define HOSTIF_I3C_ERROR_CLEAR_DEBUG_FB_FLUSH(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ERROR_CLEAR_DEBUG_FB_FLUSH_SHIFT)) & HOSTIF_I3C_ERROR_CLEAR_DEBUG_FB_FLUSH_MASK)
/*! @} */

/*! @name I3C_ACTIVITY -  */
/*! @{ */

#define HOSTIF_I3C_ACTIVITY_STNOTSTOP_MASK       (0x1U)
#define HOSTIF_I3C_ACTIVITY_STNOTSTOP_SHIFT      (0U)
#define HOSTIF_I3C_ACTIVITY_STNOTSTOP(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STNOTSTOP_SHIFT)) & HOSTIF_I3C_ACTIVITY_STNOTSTOP_MASK)

#define HOSTIF_I3C_ACTIVITY_STMSG_MASK           (0x2U)
#define HOSTIF_I3C_ACTIVITY_STMSG_SHIFT          (1U)
#define HOSTIF_I3C_ACTIVITY_STMSG(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STMSG_SHIFT)) & HOSTIF_I3C_ACTIVITY_STMSG_MASK)

#define HOSTIF_I3C_ACTIVITY_STCCCH_MASK          (0x4U)
#define HOSTIF_I3C_ACTIVITY_STCCCH_SHIFT         (2U)
#define HOSTIF_I3C_ACTIVITY_STCCCH(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STCCCH_SHIFT)) & HOSTIF_I3C_ACTIVITY_STCCCH_MASK)

#define HOSTIF_I3C_ACTIVITY_STREQRD_MASK         (0x8U)
#define HOSTIF_I3C_ACTIVITY_STREQRD_SHIFT        (3U)
#define HOSTIF_I3C_ACTIVITY_STREQRD(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STREQRD_SHIFT)) & HOSTIF_I3C_ACTIVITY_STREQRD_MASK)

#define HOSTIF_I3C_ACTIVITY_STREQWR_MASK         (0x10U)
#define HOSTIF_I3C_ACTIVITY_STREQWR_SHIFT        (4U)
#define HOSTIF_I3C_ACTIVITY_STREQWR(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STREQWR_SHIFT)) & HOSTIF_I3C_ACTIVITY_STREQWR_MASK)

#define HOSTIF_I3C_ACTIVITY_STDAA_MASK           (0x20U)
#define HOSTIF_I3C_ACTIVITY_STDAA_SHIFT          (5U)
#define HOSTIF_I3C_ACTIVITY_STDAA(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STDAA_SHIFT)) & HOSTIF_I3C_ACTIVITY_STDAA_MASK)

#define HOSTIF_I3C_ACTIVITY_STHDR_MASK           (0x40U)
#define HOSTIF_I3C_ACTIVITY_STHDR_SHIFT          (6U)
#define HOSTIF_I3C_ACTIVITY_STHDR(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_STHDR_SHIFT)) & HOSTIF_I3C_ACTIVITY_STHDR_MASK)

#define HOSTIF_I3C_ACTIVITY_EVDET_MASK           (0xC0000U)
#define HOSTIF_I3C_ACTIVITY_EVDET_SHIFT          (18U)
#define HOSTIF_I3C_ACTIVITY_EVDET(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_EVDET_SHIFT)) & HOSTIF_I3C_ACTIVITY_EVDET_MASK)

#define HOSTIF_I3C_ACTIVITY_IBIOK_MASK           (0x1000000U)
#define HOSTIF_I3C_ACTIVITY_IBIOK_SHIFT          (24U)
#define HOSTIF_I3C_ACTIVITY_IBIOK(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_IBIOK_SHIFT)) & HOSTIF_I3C_ACTIVITY_IBIOK_MASK)

#define HOSTIF_I3C_ACTIVITY_ACTSTATE_MASK        (0x30000000U)
#define HOSTIF_I3C_ACTIVITY_ACTSTATE_SHIFT       (28U)
#define HOSTIF_I3C_ACTIVITY_ACTSTATE(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_ACTIVITY_ACTSTATE_SHIFT)) & HOSTIF_I3C_ACTIVITY_ACTSTATE_MASK)
/*! @} */

/*! @name I3C_CAPABILITIES -  */
/*! @{ */

#define HOSTIF_I3C_CAPABILITIES_IDENA_MASK       (0x3U)
#define HOSTIF_I3C_CAPABILITIES_IDENA_SHIFT      (0U)
#define HOSTIF_I3C_CAPABILITIES_IDENA(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_IDENA_SHIFT)) & HOSTIF_I3C_CAPABILITIES_IDENA_MASK)

#define HOSTIF_I3C_CAPABILITIES_IDREG_MASK       (0x3CU)
#define HOSTIF_I3C_CAPABILITIES_IDREG_SHIFT      (2U)
#define HOSTIF_I3C_CAPABILITIES_IDREG(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_IDREG_SHIFT)) & HOSTIF_I3C_CAPABILITIES_IDREG_MASK)

#define HOSTIF_I3C_CAPABILITIES_HDRSUPP_MASK     (0x1C0U)
#define HOSTIF_I3C_CAPABILITIES_HDRSUPP_SHIFT    (6U)
#define HOSTIF_I3C_CAPABILITIES_HDRSUPP(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_HDRSUPP_SHIFT)) & HOSTIF_I3C_CAPABILITIES_HDRSUPP_MASK)

#define HOSTIF_I3C_CAPABILITIES_SADDR_MASK       (0xC00U)
#define HOSTIF_I3C_CAPABILITIES_SADDR_SHIFT      (10U)
#define HOSTIF_I3C_CAPABILITIES_SADDR(x)         (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_SADDR_SHIFT)) & HOSTIF_I3C_CAPABILITIES_SADDR_MASK)

#define HOSTIF_I3C_CAPABILITIES_CCCHANDLE_MASK   (0x3000U)
#define HOSTIF_I3C_CAPABILITIES_CCCHANDLE_SHIFT  (12U)
#define HOSTIF_I3C_CAPABILITIES_CCCHANDLE(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_CCCHANDLE_SHIFT)) & HOSTIF_I3C_CAPABILITIES_CCCHANDLE_MASK)

#define HOSTIF_I3C_CAPABILITIES_IBI_MR_HJ_MASK   (0xF0000U)
#define HOSTIF_I3C_CAPABILITIES_IBI_MR_HJ_SHIFT  (16U)
#define HOSTIF_I3C_CAPABILITIES_IBI_MR_HJ(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_IBI_MR_HJ_SHIFT)) & HOSTIF_I3C_CAPABILITIES_IBI_MR_HJ_MASK)

#define HOSTIF_I3C_CAPABILITIES_FIFO_MASK        (0x3000000U)
#define HOSTIF_I3C_CAPABILITIES_FIFO_SHIFT       (24U)
#define HOSTIF_I3C_CAPABILITIES_FIFO(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_FIFO_SHIFT)) & HOSTIF_I3C_CAPABILITIES_FIFO_MASK)

#define HOSTIF_I3C_CAPABILITIES_FIFOTX_MASK      (0xC000000U)
#define HOSTIF_I3C_CAPABILITIES_FIFOTX_SHIFT     (26U)
#define HOSTIF_I3C_CAPABILITIES_FIFOTX(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_FIFOTX_SHIFT)) & HOSTIF_I3C_CAPABILITIES_FIFOTX_MASK)

#define HOSTIF_I3C_CAPABILITIES_FIFORX_MASK      (0x30000000U)
#define HOSTIF_I3C_CAPABILITIES_FIFORX_SHIFT     (28U)
#define HOSTIF_I3C_CAPABILITIES_FIFORX(x)        (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_FIFORX_SHIFT)) & HOSTIF_I3C_CAPABILITIES_FIFORX_MASK)

#define HOSTIF_I3C_CAPABILITIES_I3C_INT_MASK     (0x40000000U)
#define HOSTIF_I3C_CAPABILITIES_I3C_INT_SHIFT    (30U)
#define HOSTIF_I3C_CAPABILITIES_I3C_INT(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_I3C_INT_SHIFT)) & HOSTIF_I3C_CAPABILITIES_I3C_INT_MASK)

#define HOSTIF_I3C_CAPABILITIES_DMA_MASK         (0x80000000U)
#define HOSTIF_I3C_CAPABILITIES_DMA_SHIFT        (31U)
#define HOSTIF_I3C_CAPABILITIES_DMA(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_CAPABILITIES_DMA_SHIFT)) & HOSTIF_I3C_CAPABILITIES_DMA_MASK)
/*! @} */

/*! @name I3C_DYNADDR -  */
/*! @{ */

#define HOSTIF_I3C_DYNADDR_DAVALID_MASK          (0x1U)
#define HOSTIF_I3C_DYNADDR_DAVALID_SHIFT         (0U)
#define HOSTIF_I3C_DYNADDR_DAVALID(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_DYNADDR_DAVALID_SHIFT)) & HOSTIF_I3C_DYNADDR_DAVALID_MASK)

#define HOSTIF_I3C_DYNADDR_DADDR_MASK            (0xFEU)
#define HOSTIF_I3C_DYNADDR_DADDR_SHIFT           (1U)
#define HOSTIF_I3C_DYNADDR_DADDR(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_DYNADDR_DADDR_SHIFT)) & HOSTIF_I3C_DYNADDR_DADDR_MASK)

#define HOSTIF_I3C_DYNADDR_SET_DA_MASK           (0xFF00U)
#define HOSTIF_I3C_DYNADDR_SET_DA_SHIFT          (8U)
#define HOSTIF_I3C_DYNADDR_SET_DA(x)             (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_DYNADDR_SET_DA_SHIFT)) & HOSTIF_I3C_DYNADDR_SET_DA_MASK)
/*! @} */

/*! @name I3C_PARTNO -  */
/*! @{ */

#define HOSTIF_I3C_PARTNO_PARTNO_MASK            (0xFFFFFFFFU)
#define HOSTIF_I3C_PARTNO_PARTNO_SHIFT           (0U)
#define HOSTIF_I3C_PARTNO_PARTNO(x)              (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_PARTNO_PARTNO_SHIFT)) & HOSTIF_I3C_PARTNO_PARTNO_MASK)
/*! @} */

/*! @name I3C_IDEXT -  */
/*! @{ */

#define HOSTIF_I3C_IDEXT_DCR_MASK                (0xFF00U)
#define HOSTIF_I3C_IDEXT_DCR_SHIFT               (8U)
#define HOSTIF_I3C_IDEXT_DCR(x)                  (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_DCR_SHIFT)) & HOSTIF_I3C_IDEXT_DCR_MASK)

#define HOSTIF_I3C_IDEXT_BCR_MAC_SCL_MASK        (0x10000U)
#define HOSTIF_I3C_IDEXT_BCR_MAC_SCL_SHIFT       (16U)
#define HOSTIF_I3C_IDEXT_BCR_MAC_SCL(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_MAC_SCL_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_MAC_SCL_MASK)

#define HOSTIF_I3C_IDEXT_BCR_IBI_CAPABLE_MASK    (0x20000U)
#define HOSTIF_I3C_IDEXT_BCR_IBI_CAPABLE_SHIFT   (17U)
#define HOSTIF_I3C_IDEXT_BCR_IBI_CAPABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_IBI_CAPABLE_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_IBI_CAPABLE_MASK)

#define HOSTIF_I3C_IDEXT_BCR_IBI_PAYLOAD_MASK    (0x40000U)
#define HOSTIF_I3C_IDEXT_BCR_IBI_PAYLOAD_SHIFT   (18U)
#define HOSTIF_I3C_IDEXT_BCR_IBI_PAYLOAD(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_IBI_PAYLOAD_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_IBI_PAYLOAD_MASK)

#define HOSTIF_I3C_IDEXT_BCR_OFFLINE_CAPABLE_MASK (0x80000U)
#define HOSTIF_I3C_IDEXT_BCR_OFFLINE_CAPABLE_SHIFT (19U)
#define HOSTIF_I3C_IDEXT_BCR_OFFLINE_CAPABLE(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_OFFLINE_CAPABLE_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_OFFLINE_CAPABLE_MASK)

#define HOSTIF_I3C_IDEXT_BCR_BRIDGE_MASK         (0x100000U)
#define HOSTIF_I3C_IDEXT_BCR_BRIDGE_SHIFT        (20U)
#define HOSTIF_I3C_IDEXT_BCR_BRIDGE(x)           (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_BRIDGE_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_BRIDGE_MASK)

#define HOSTIF_I3C_IDEXT_BCR_HDR_CAPABLE_MASK    (0x200000U)
#define HOSTIF_I3C_IDEXT_BCR_HDR_CAPABLE_SHIFT   (21U)
#define HOSTIF_I3C_IDEXT_BCR_HDR_CAPABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_HDR_CAPABLE_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_HDR_CAPABLE_MASK)

#define HOSTIF_I3C_IDEXT_BCR_DEVICE_ROL_MASK     (0xC00000U)
#define HOSTIF_I3C_IDEXT_BCR_DEVICE_ROL_SHIFT    (22U)
#define HOSTIF_I3C_IDEXT_BCR_DEVICE_ROL(x)       (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_IDEXT_BCR_DEVICE_ROL_SHIFT)) & HOSTIF_I3C_IDEXT_BCR_DEVICE_ROL_MASK)
/*! @} */

/*! @name I3C_MAXLIMITS -  */
/*! @{ */

#define HOSTIF_I3C_MAXLIMITS_MAXRD_MASK          (0xFFFU)
#define HOSTIF_I3C_MAXLIMITS_MAXRD_SHIFT         (0U)
#define HOSTIF_I3C_MAXLIMITS_MAXRD(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_MAXLIMITS_MAXRD_SHIFT)) & HOSTIF_I3C_MAXLIMITS_MAXRD_MASK)

#define HOSTIF_I3C_MAXLIMITS_MAXWR_MASK          (0xFFF0000U)
#define HOSTIF_I3C_MAXLIMITS_MAXWR_SHIFT         (16U)
#define HOSTIF_I3C_MAXLIMITS_MAXWR(x)            (((uint32_t)(((uint32_t)(x)) << HOSTIF_I3C_MAXLIMITS_MAXWR_SHIFT)) & HOSTIF_I3C_MAXLIMITS_MAXWR_MASK)
/*! @} */

/*! @name INT_CLR_ENABLE -  */
/*! @{ */

#define HOSTIF_INT_CLR_ENABLE_RX0_EOR_CLR_ENABLE_MASK (0x1U)
#define HOSTIF_INT_CLR_ENABLE_RX0_EOR_CLR_ENABLE_SHIFT (0U)
#define HOSTIF_INT_CLR_ENABLE_RX0_EOR_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX0_EOR_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX0_EOR_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX1_EOR_CLR_ENABLE_MASK (0x2U)
#define HOSTIF_INT_CLR_ENABLE_RX1_EOR_CLR_ENABLE_SHIFT (1U)
#define HOSTIF_INT_CLR_ENABLE_RX1_EOR_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX1_EOR_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX1_EOR_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX2_EOR_CLR_ENABLE_MASK (0x4U)
#define HOSTIF_INT_CLR_ENABLE_RX2_EOR_CLR_ENABLE_SHIFT (2U)
#define HOSTIF_INT_CLR_ENABLE_RX2_EOR_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX2_EOR_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX2_EOR_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX3_EOR_CLR_ENABLE_MASK (0x8U)
#define HOSTIF_INT_CLR_ENABLE_RX3_EOR_CLR_ENABLE_SHIFT (3U)
#define HOSTIF_INT_CLR_ENABLE_RX3_EOR_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX3_EOR_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX3_EOR_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_EOT_CLR_ENABLE_MASK (0x10U)
#define HOSTIF_INT_CLR_ENABLE_EOT_CLR_ENABLE_SHIFT (4U)
#define HOSTIF_INT_CLR_ENABLE_EOT_CLR_ENABLE(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_EOT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_EOT_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX_BUFFER_NOT_AVAILABLE_CLR_ENABLE_MASK (0x20U)
#define HOSTIF_INT_CLR_ENABLE_RX_BUFFER_NOT_AVAILABLE_CLR_ENABLE_SHIFT (5U)
#define HOSTIF_INT_CLR_ENABLE_RX_BUFFER_NOT_AVAILABLE_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX_BUFFER_NOT_AVAILABLE_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX_BUFFER_NOT_AVAILABLE_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_TX_FRAME_NOT_AVAILABLE_CLR_ENABLE_MASK (0x40U)
#define HOSTIF_INT_CLR_ENABLE_TX_FRAME_NOT_AVAILABLE_CLR_ENABLE_SHIFT (6U)
#define HOSTIF_INT_CLR_ENABLE_TX_FRAME_NOT_AVAILABLE_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_TX_FRAME_NOT_AVAILABLE_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_TX_FRAME_NOT_AVAILABLE_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_FIFO_TIMEOUT_CLR_ENABLE_MASK (0x80U)
#define HOSTIF_INT_CLR_ENABLE_FIFO_TIMEOUT_CLR_ENABLE_SHIFT (7U)
#define HOSTIF_INT_CLR_ENABLE_FIFO_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_FIFO_TIMEOUT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_FIFO_TIMEOUT_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_FIFO_OVERFLOW_CLR_ENABLE_MASK (0x100U)
#define HOSTIF_INT_CLR_ENABLE_FIFO_OVERFLOW_CLR_ENABLE_SHIFT (8U)
#define HOSTIF_INT_CLR_ENABLE_FIFO_OVERFLOW_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_FIFO_OVERFLOW_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_FIFO_OVERFLOW_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_TIMEOUT_CLR_ENABLE_MASK (0x200U)
#define HOSTIF_INT_CLR_ENABLE_TIMEOUT_CLR_ENABLE_SHIFT (9U)
#define HOSTIF_INT_CLR_ENABLE_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_TIMEOUT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_TIMEOUT_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX0_BUFFER_OVERFLOW_CLR_ENABLE_MASK (0x400U)
#define HOSTIF_INT_CLR_ENABLE_RX0_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT (10U)
#define HOSTIF_INT_CLR_ENABLE_RX0_BUFFER_OVERFLOW_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX0_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX0_BUFFER_OVERFLOW_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX1_BUFFER_OVERFLOW_CLR_ENABLE_MASK (0x800U)
#define HOSTIF_INT_CLR_ENABLE_RX1_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT (11U)
#define HOSTIF_INT_CLR_ENABLE_RX1_BUFFER_OVERFLOW_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX1_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX1_BUFFER_OVERFLOW_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX2_BUFFER_OVERFLOW_CLR_ENABLE_MASK (0x1000U)
#define HOSTIF_INT_CLR_ENABLE_RX2_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT (12U)
#define HOSTIF_INT_CLR_ENABLE_RX2_BUFFER_OVERFLOW_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX2_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX2_BUFFER_OVERFLOW_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_RX3_BUFFER_OVERFLOW_CLR_ENABLE_MASK (0x2000U)
#define HOSTIF_INT_CLR_ENABLE_RX3_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT (13U)
#define HOSTIF_INT_CLR_ENABLE_RX3_BUFFER_OVERFLOW_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_RX3_BUFFER_OVERFLOW_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_RX3_BUFFER_OVERFLOW_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_WATERLEVEL_REACHED_CLR_ENABLE_MASK (0x4000U)
#define HOSTIF_INT_CLR_ENABLE_WATERLEVEL_REACHED_CLR_ENABLE_SHIFT (14U)
#define HOSTIF_INT_CLR_ENABLE_WATERLEVEL_REACHED_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_WATERLEVEL_REACHED_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_WATERLEVEL_REACHED_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_HSU_RX_FER_CLR_ENABLE_MASK (0x8000U)
#define HOSTIF_INT_CLR_ENABLE_HSU_RX_FER_CLR_ENABLE_SHIFT (15U)
#define HOSTIF_INT_CLR_ENABLE_HSU_RX_FER_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_HSU_RX_FER_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_HSU_RX_FER_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_PREFETCH_OK_INT_CLR_ENABLE_MASK (0x10000U)
#define HOSTIF_INT_CLR_ENABLE_PREFETCH_OK_INT_CLR_ENABLE_SHIFT (16U)
#define HOSTIF_INT_CLR_ENABLE_PREFETCH_OK_INT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_PREFETCH_OK_INT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_PREFETCH_OK_INT_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_TX_DATA_READY_INT_CLR_ENABLE_MASK (0x20000U)
#define HOSTIF_INT_CLR_ENABLE_TX_DATA_READY_INT_CLR_ENABLE_SHIFT (17U)
#define HOSTIF_INT_CLR_ENABLE_TX_DATA_READY_INT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_TX_DATA_READY_INT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_TX_DATA_READY_INT_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_START_CLR_ENABLE_MASK (0x200000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_START_CLR_ENABLE_SHIFT (21U)
#define HOSTIF_INT_CLR_ENABLE_I3C_START_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_START_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_START_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_MATCHED_CLR_ENABLE_MASK (0x400000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_MATCHED_CLR_ENABLE_SHIFT (22U)
#define HOSTIF_INT_CLR_ENABLE_I3C_MATCHED_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_MATCHED_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_MATCHED_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_STOP_CLR_ENABLE_MASK (0x800000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_STOP_CLR_ENABLE_SHIFT (23U)
#define HOSTIF_INT_CLR_ENABLE_I3C_STOP_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_STOP_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_STOP_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_RXPEND_CLR_ENABLE_MASK (0x1000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_RXPEND_CLR_ENABLE_SHIFT (24U)
#define HOSTIF_INT_CLR_ENABLE_I3C_RXPEND_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_RXPEND_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_RXPEND_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_TXNOTFULL_CLR_ENABLE_MASK (0x2000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_TXNOTFULL_CLR_ENABLE_SHIFT (25U)
#define HOSTIF_INT_CLR_ENABLE_I3C_TXNOTFULL_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_TXNOTFULL_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_TXNOTFULL_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_DACHG_CLR_ENABLE_MASK (0x4000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_DACHG_CLR_ENABLE_SHIFT (26U)
#define HOSTIF_INT_CLR_ENABLE_I3C_DACHG_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_DACHG_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_DACHG_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_CCC_CLR_ENABLE_MASK (0x8000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_CCC_CLR_ENABLE_SHIFT (27U)
#define HOSTIF_INT_CLR_ENABLE_I3C_CCC_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_CCC_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_CCC_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_ERROR_CLR_ENABLE_MASK (0x10000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_ERROR_CLR_ENABLE_SHIFT (28U)
#define HOSTIF_INT_CLR_ENABLE_I3C_ERROR_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_ERROR_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_ERROR_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_HDRMATCH_CLR_ENABLE_MASK (0x20000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_HDRMATCH_CLR_ENABLE_SHIFT (29U)
#define HOSTIF_INT_CLR_ENABLE_I3C_HDRMATCH_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_HDRMATCH_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_HDRMATCH_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_CHANDLED_CLR_ENABLE_MASK (0x40000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_CHANDLED_CLR_ENABLE_SHIFT (30U)
#define HOSTIF_INT_CLR_ENABLE_I3C_CHANDLED_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_CHANDLED_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_CHANDLED_CLR_ENABLE_MASK)

#define HOSTIF_INT_CLR_ENABLE_I3C_EVENT_CLR_ENABLE_MASK (0x80000000U)
#define HOSTIF_INT_CLR_ENABLE_I3C_EVENT_CLR_ENABLE_SHIFT (31U)
#define HOSTIF_INT_CLR_ENABLE_I3C_EVENT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_ENABLE_I3C_EVENT_CLR_ENABLE_SHIFT)) & HOSTIF_INT_CLR_ENABLE_I3C_EVENT_CLR_ENABLE_MASK)
/*! @} */

/*! @name INT_SET_ENABLE -  */
/*! @{ */

#define HOSTIF_INT_SET_ENABLE_RX0_EOR_SET_ENABLE_MASK (0x1U)
#define HOSTIF_INT_SET_ENABLE_RX0_EOR_SET_ENABLE_SHIFT (0U)
#define HOSTIF_INT_SET_ENABLE_RX0_EOR_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX0_EOR_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX0_EOR_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX1_EOR_SET_ENABLE_MASK (0x2U)
#define HOSTIF_INT_SET_ENABLE_RX1_EOR_SET_ENABLE_SHIFT (1U)
#define HOSTIF_INT_SET_ENABLE_RX1_EOR_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX1_EOR_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX1_EOR_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX2_EOR_SET_ENABLE_MASK (0x4U)
#define HOSTIF_INT_SET_ENABLE_RX2_EOR_SET_ENABLE_SHIFT (2U)
#define HOSTIF_INT_SET_ENABLE_RX2_EOR_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX2_EOR_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX2_EOR_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX3_EOR_SET_ENABLE_MASK (0x8U)
#define HOSTIF_INT_SET_ENABLE_RX3_EOR_SET_ENABLE_SHIFT (3U)
#define HOSTIF_INT_SET_ENABLE_RX3_EOR_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX3_EOR_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX3_EOR_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_EOT_SET_ENABLE_MASK (0x10U)
#define HOSTIF_INT_SET_ENABLE_EOT_SET_ENABLE_SHIFT (4U)
#define HOSTIF_INT_SET_ENABLE_EOT_SET_ENABLE(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_EOT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_EOT_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX_BUFFER_NOT_AVAILABLE_SET_ENABLE_MASK (0x20U)
#define HOSTIF_INT_SET_ENABLE_RX_BUFFER_NOT_AVAILABLE_SET_ENABLE_SHIFT (5U)
#define HOSTIF_INT_SET_ENABLE_RX_BUFFER_NOT_AVAILABLE_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX_BUFFER_NOT_AVAILABLE_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX_BUFFER_NOT_AVAILABLE_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_TX_FRAME_NOT_AVAILABLE_SET_ENABLE_MASK (0x40U)
#define HOSTIF_INT_SET_ENABLE_TX_FRAME_NOT_AVAILABLE_SET_ENABLE_SHIFT (6U)
#define HOSTIF_INT_SET_ENABLE_TX_FRAME_NOT_AVAILABLE_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_TX_FRAME_NOT_AVAILABLE_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_TX_FRAME_NOT_AVAILABLE_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_FIFO_TIMEOUT_SET_ENABLE_MASK (0x80U)
#define HOSTIF_INT_SET_ENABLE_FIFO_TIMEOUT_SET_ENABLE_SHIFT (7U)
#define HOSTIF_INT_SET_ENABLE_FIFO_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_FIFO_TIMEOUT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_FIFO_TIMEOUT_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_FIFO_OVERFLOW_SET_ENABLE_MASK (0x100U)
#define HOSTIF_INT_SET_ENABLE_FIFO_OVERFLOW_SET_ENABLE_SHIFT (8U)
#define HOSTIF_INT_SET_ENABLE_FIFO_OVERFLOW_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_FIFO_OVERFLOW_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_FIFO_OVERFLOW_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_TIMEOUT_SET_ENABLE_MASK (0x200U)
#define HOSTIF_INT_SET_ENABLE_TIMEOUT_SET_ENABLE_SHIFT (9U)
#define HOSTIF_INT_SET_ENABLE_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_TIMEOUT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_TIMEOUT_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX0_BUFFER_OVERFLOW_SET_ENABLE_MASK (0x400U)
#define HOSTIF_INT_SET_ENABLE_RX0_BUFFER_OVERFLOW_SET_ENABLE_SHIFT (10U)
#define HOSTIF_INT_SET_ENABLE_RX0_BUFFER_OVERFLOW_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX0_BUFFER_OVERFLOW_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX0_BUFFER_OVERFLOW_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX1_BUFFER_OVERFLOW_SET_ENABLE_MASK (0x800U)
#define HOSTIF_INT_SET_ENABLE_RX1_BUFFER_OVERFLOW_SET_ENABLE_SHIFT (11U)
#define HOSTIF_INT_SET_ENABLE_RX1_BUFFER_OVERFLOW_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX1_BUFFER_OVERFLOW_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX1_BUFFER_OVERFLOW_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX2_BUFFER_OVERFLOW_SET_ENABLE_MASK (0x1000U)
#define HOSTIF_INT_SET_ENABLE_RX2_BUFFER_OVERFLOW_SET_ENABLE_SHIFT (12U)
#define HOSTIF_INT_SET_ENABLE_RX2_BUFFER_OVERFLOW_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX2_BUFFER_OVERFLOW_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX2_BUFFER_OVERFLOW_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_RX3_BUFFER_OVERFLOW_SET_ENABLE_MASK (0x2000U)
#define HOSTIF_INT_SET_ENABLE_RX3_BUFFER_OVERFLOW_SET_ENABLE_SHIFT (13U)
#define HOSTIF_INT_SET_ENABLE_RX3_BUFFER_OVERFLOW_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_RX3_BUFFER_OVERFLOW_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_RX3_BUFFER_OVERFLOW_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_WATERLEVEL_REACHED_SET_ENABLE_MASK (0x4000U)
#define HOSTIF_INT_SET_ENABLE_WATERLEVEL_REACHED_SET_ENABLE_SHIFT (14U)
#define HOSTIF_INT_SET_ENABLE_WATERLEVEL_REACHED_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_WATERLEVEL_REACHED_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_WATERLEVEL_REACHED_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_HSU_RX_FER_SET_ENABLE_MASK (0x8000U)
#define HOSTIF_INT_SET_ENABLE_HSU_RX_FER_SET_ENABLE_SHIFT (15U)
#define HOSTIF_INT_SET_ENABLE_HSU_RX_FER_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_HSU_RX_FER_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_HSU_RX_FER_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_PREFETCH_OK_INT_SET_ENABLE_MASK (0x10000U)
#define HOSTIF_INT_SET_ENABLE_PREFETCH_OK_INT_SET_ENABLE_SHIFT (16U)
#define HOSTIF_INT_SET_ENABLE_PREFETCH_OK_INT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_PREFETCH_OK_INT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_PREFETCH_OK_INT_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_TX_DATA_READY_INT_SET_ENABLE_MASK (0x20000U)
#define HOSTIF_INT_SET_ENABLE_TX_DATA_READY_INT_SET_ENABLE_SHIFT (17U)
#define HOSTIF_INT_SET_ENABLE_TX_DATA_READY_INT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_TX_DATA_READY_INT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_TX_DATA_READY_INT_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_START_SET_ENABLE_MASK (0x200000U)
#define HOSTIF_INT_SET_ENABLE_I3C_START_SET_ENABLE_SHIFT (21U)
#define HOSTIF_INT_SET_ENABLE_I3C_START_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_START_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_START_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_MATCHED_SET_ENABLE_MASK (0x400000U)
#define HOSTIF_INT_SET_ENABLE_I3C_MATCHED_SET_ENABLE_SHIFT (22U)
#define HOSTIF_INT_SET_ENABLE_I3C_MATCHED_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_MATCHED_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_MATCHED_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_STOP_SET_ENABLE_MASK (0x800000U)
#define HOSTIF_INT_SET_ENABLE_I3C_STOP_SET_ENABLE_SHIFT (23U)
#define HOSTIF_INT_SET_ENABLE_I3C_STOP_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_STOP_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_STOP_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_RXPEND_SET_ENABLE_MASK (0x1000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_RXPEND_SET_ENABLE_SHIFT (24U)
#define HOSTIF_INT_SET_ENABLE_I3C_RXPEND_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_RXPEND_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_RXPEND_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_TXNOTFULL_SET_ENABLE_MASK (0x2000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_TXNOTFULL_SET_ENABLE_SHIFT (25U)
#define HOSTIF_INT_SET_ENABLE_I3C_TXNOTFULL_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_TXNOTFULL_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_TXNOTFULL_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_DACHG_SET_ENABLE_MASK (0x4000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_DACHG_SET_ENABLE_SHIFT (26U)
#define HOSTIF_INT_SET_ENABLE_I3C_DACHG_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_DACHG_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_DACHG_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_CCC_SET_ENABLE_MASK (0x8000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_CCC_SET_ENABLE_SHIFT (27U)
#define HOSTIF_INT_SET_ENABLE_I3C_CCC_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_CCC_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_CCC_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_ERROR_SET_ENABLE_MASK (0x10000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_ERROR_SET_ENABLE_SHIFT (28U)
#define HOSTIF_INT_SET_ENABLE_I3C_ERROR_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_ERROR_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_ERROR_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_HDRMATCH_SET_ENABLE_MASK (0x20000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_HDRMATCH_SET_ENABLE_SHIFT (29U)
#define HOSTIF_INT_SET_ENABLE_I3C_HDRMATCH_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_HDRMATCH_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_HDRMATCH_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_CHANDLED_SET_ENABLE_MASK (0x40000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_CHANDLED_SET_ENABLE_SHIFT (30U)
#define HOSTIF_INT_SET_ENABLE_I3C_CHANDLED_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_CHANDLED_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_CHANDLED_SET_ENABLE_MASK)

#define HOSTIF_INT_SET_ENABLE_I3C_EVENT_SET_ENABLE_MASK (0x80000000U)
#define HOSTIF_INT_SET_ENABLE_I3C_EVENT_SET_ENABLE_SHIFT (31U)
#define HOSTIF_INT_SET_ENABLE_I3C_EVENT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_ENABLE_I3C_EVENT_SET_ENABLE_SHIFT)) & HOSTIF_INT_SET_ENABLE_I3C_EVENT_SET_ENABLE_MASK)
/*! @} */

/*! @name INT_STATUS -  */
/*! @{ */

#define HOSTIF_INT_STATUS_RX0_EOR_STATUS_MASK    (0x1U)
#define HOSTIF_INT_STATUS_RX0_EOR_STATUS_SHIFT   (0U)
#define HOSTIF_INT_STATUS_RX0_EOR_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX0_EOR_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX0_EOR_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX1_EOR_STATUS_MASK    (0x2U)
#define HOSTIF_INT_STATUS_RX1_EOR_STATUS_SHIFT   (1U)
#define HOSTIF_INT_STATUS_RX1_EOR_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX1_EOR_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX1_EOR_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX2_EOR_STATUS_MASK    (0x4U)
#define HOSTIF_INT_STATUS_RX2_EOR_STATUS_SHIFT   (2U)
#define HOSTIF_INT_STATUS_RX2_EOR_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX2_EOR_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX2_EOR_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX3_EOR_STATUS_MASK    (0x8U)
#define HOSTIF_INT_STATUS_RX3_EOR_STATUS_SHIFT   (3U)
#define HOSTIF_INT_STATUS_RX3_EOR_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX3_EOR_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX3_EOR_STATUS_MASK)

#define HOSTIF_INT_STATUS_EOT_STATUS_MASK        (0x10U)
#define HOSTIF_INT_STATUS_EOT_STATUS_SHIFT       (4U)
#define HOSTIF_INT_STATUS_EOT_STATUS(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_EOT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_EOT_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX_BUFFER_NOT_AVAILABLE_STATUS_MASK (0x20U)
#define HOSTIF_INT_STATUS_RX_BUFFER_NOT_AVAILABLE_STATUS_SHIFT (5U)
#define HOSTIF_INT_STATUS_RX_BUFFER_NOT_AVAILABLE_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX_BUFFER_NOT_AVAILABLE_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX_BUFFER_NOT_AVAILABLE_STATUS_MASK)

#define HOSTIF_INT_STATUS_TX_FRAME_NOT_AVAILABLE_STATUS_MASK (0x40U)
#define HOSTIF_INT_STATUS_TX_FRAME_NOT_AVAILABLE_STATUS_SHIFT (6U)
#define HOSTIF_INT_STATUS_TX_FRAME_NOT_AVAILABLE_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_TX_FRAME_NOT_AVAILABLE_STATUS_SHIFT)) & HOSTIF_INT_STATUS_TX_FRAME_NOT_AVAILABLE_STATUS_MASK)

#define HOSTIF_INT_STATUS_FIFO_TIMEOUT_STATUS_MASK (0x80U)
#define HOSTIF_INT_STATUS_FIFO_TIMEOUT_STATUS_SHIFT (7U)
#define HOSTIF_INT_STATUS_FIFO_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_FIFO_TIMEOUT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_FIFO_TIMEOUT_STATUS_MASK)

#define HOSTIF_INT_STATUS_FIFO_OVERFLOW_STATUS_MASK (0x100U)
#define HOSTIF_INT_STATUS_FIFO_OVERFLOW_STATUS_SHIFT (8U)
#define HOSTIF_INT_STATUS_FIFO_OVERFLOW_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_FIFO_OVERFLOW_STATUS_SHIFT)) & HOSTIF_INT_STATUS_FIFO_OVERFLOW_STATUS_MASK)

#define HOSTIF_INT_STATUS_TIMEOUT_STATUS_MASK    (0x200U)
#define HOSTIF_INT_STATUS_TIMEOUT_STATUS_SHIFT   (9U)
#define HOSTIF_INT_STATUS_TIMEOUT_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_TIMEOUT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_TIMEOUT_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX0_BUFFER_OVERFLOW_STATUS_MASK (0x400U)
#define HOSTIF_INT_STATUS_RX0_BUFFER_OVERFLOW_STATUS_SHIFT (10U)
#define HOSTIF_INT_STATUS_RX0_BUFFER_OVERFLOW_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX0_BUFFER_OVERFLOW_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX0_BUFFER_OVERFLOW_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX1_BUFFER_OVERFLOW_STATUS_MASK (0x800U)
#define HOSTIF_INT_STATUS_RX1_BUFFER_OVERFLOW_STATUS_SHIFT (11U)
#define HOSTIF_INT_STATUS_RX1_BUFFER_OVERFLOW_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX1_BUFFER_OVERFLOW_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX1_BUFFER_OVERFLOW_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX2_BUFFER_OVERFLOW_STATUS_MASK (0x1000U)
#define HOSTIF_INT_STATUS_RX2_BUFFER_OVERFLOW_STATUS_SHIFT (12U)
#define HOSTIF_INT_STATUS_RX2_BUFFER_OVERFLOW_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX2_BUFFER_OVERFLOW_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX2_BUFFER_OVERFLOW_STATUS_MASK)

#define HOSTIF_INT_STATUS_RX3_BUFFER_OVERFLOW_STATUS_MASK (0x2000U)
#define HOSTIF_INT_STATUS_RX3_BUFFER_OVERFLOW_STATUS_SHIFT (13U)
#define HOSTIF_INT_STATUS_RX3_BUFFER_OVERFLOW_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_RX3_BUFFER_OVERFLOW_STATUS_SHIFT)) & HOSTIF_INT_STATUS_RX3_BUFFER_OVERFLOW_STATUS_MASK)

#define HOSTIF_INT_STATUS_WATERLEVEL_REACHED_STATUS_MASK (0x4000U)
#define HOSTIF_INT_STATUS_WATERLEVEL_REACHED_STATUS_SHIFT (14U)
#define HOSTIF_INT_STATUS_WATERLEVEL_REACHED_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_WATERLEVEL_REACHED_STATUS_SHIFT)) & HOSTIF_INT_STATUS_WATERLEVEL_REACHED_STATUS_MASK)

#define HOSTIF_INT_STATUS_HSU_RX_FER_STATUS_MASK (0x8000U)
#define HOSTIF_INT_STATUS_HSU_RX_FER_STATUS_SHIFT (15U)
#define HOSTIF_INT_STATUS_HSU_RX_FER_STATUS(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_HSU_RX_FER_STATUS_SHIFT)) & HOSTIF_INT_STATUS_HSU_RX_FER_STATUS_MASK)

#define HOSTIF_INT_STATUS_PREFETCH_OK_INT_STATUS_MASK (0x10000U)
#define HOSTIF_INT_STATUS_PREFETCH_OK_INT_STATUS_SHIFT (16U)
#define HOSTIF_INT_STATUS_PREFETCH_OK_INT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_PREFETCH_OK_INT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_PREFETCH_OK_INT_STATUS_MASK)

#define HOSTIF_INT_STATUS_TX_DATA_READY_INT_STATUS_MASK (0x20000U)
#define HOSTIF_INT_STATUS_TX_DATA_READY_INT_STATUS_SHIFT (17U)
#define HOSTIF_INT_STATUS_TX_DATA_READY_INT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_TX_DATA_READY_INT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_TX_DATA_READY_INT_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_START_STATUS_MASK  (0x200000U)
#define HOSTIF_INT_STATUS_I3C_START_STATUS_SHIFT (21U)
#define HOSTIF_INT_STATUS_I3C_START_STATUS(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_START_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_START_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_MATCHED_STATUS_MASK (0x400000U)
#define HOSTIF_INT_STATUS_I3C_MATCHED_STATUS_SHIFT (22U)
#define HOSTIF_INT_STATUS_I3C_MATCHED_STATUS(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_MATCHED_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_MATCHED_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_STOP_STATUS_MASK   (0x800000U)
#define HOSTIF_INT_STATUS_I3C_STOP_STATUS_SHIFT  (23U)
#define HOSTIF_INT_STATUS_I3C_STOP_STATUS(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_STOP_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_STOP_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_RXPEND_STATUS_MASK (0x1000000U)
#define HOSTIF_INT_STATUS_I3C_RXPEND_STATUS_SHIFT (24U)
#define HOSTIF_INT_STATUS_I3C_RXPEND_STATUS(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_RXPEND_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_RXPEND_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_TXNOTFULL_STATUS_MASK (0x2000000U)
#define HOSTIF_INT_STATUS_I3C_TXNOTFULL_STATUS_SHIFT (25U)
#define HOSTIF_INT_STATUS_I3C_TXNOTFULL_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_TXNOTFULL_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_TXNOTFULL_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_DACHG_STATUS_MASK  (0x4000000U)
#define HOSTIF_INT_STATUS_I3C_DACHG_STATUS_SHIFT (26U)
#define HOSTIF_INT_STATUS_I3C_DACHG_STATUS(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_DACHG_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_DACHG_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_CCC_STATUS_MASK    (0x8000000U)
#define HOSTIF_INT_STATUS_I3C_CCC_STATUS_SHIFT   (27U)
#define HOSTIF_INT_STATUS_I3C_CCC_STATUS(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_CCC_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_CCC_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_ERROR_STATUS_MASK  (0x10000000U)
#define HOSTIF_INT_STATUS_I3C_ERROR_STATUS_SHIFT (28U)
#define HOSTIF_INT_STATUS_I3C_ERROR_STATUS(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_ERROR_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_ERROR_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_HDRMATCH_STATUS_MASK (0x20000000U)
#define HOSTIF_INT_STATUS_I3C_HDRMATCH_STATUS_SHIFT (29U)
#define HOSTIF_INT_STATUS_I3C_HDRMATCH_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_HDRMATCH_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_HDRMATCH_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_CHANDLED_STATUS_MASK (0x40000000U)
#define HOSTIF_INT_STATUS_I3C_CHANDLED_STATUS_SHIFT (30U)
#define HOSTIF_INT_STATUS_I3C_CHANDLED_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_CHANDLED_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_CHANDLED_STATUS_MASK)

#define HOSTIF_INT_STATUS_I3C_EVENT_STATUS_MASK  (0x80000000U)
#define HOSTIF_INT_STATUS_I3C_EVENT_STATUS_SHIFT (31U)
#define HOSTIF_INT_STATUS_I3C_EVENT_STATUS(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_STATUS_I3C_EVENT_STATUS_SHIFT)) & HOSTIF_INT_STATUS_I3C_EVENT_STATUS_MASK)
/*! @} */

/*! @name INT_ENABLE -  */
/*! @{ */

#define HOSTIF_INT_ENABLE_RX0_EOR_ENABLE_MASK    (0x1U)
#define HOSTIF_INT_ENABLE_RX0_EOR_ENABLE_SHIFT   (0U)
#define HOSTIF_INT_ENABLE_RX0_EOR_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX0_EOR_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX0_EOR_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX1_EOR_ENABLE_MASK    (0x2U)
#define HOSTIF_INT_ENABLE_RX1_EOR_ENABLE_SHIFT   (1U)
#define HOSTIF_INT_ENABLE_RX1_EOR_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX1_EOR_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX1_EOR_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX2_EOR_ENABLE_MASK    (0x4U)
#define HOSTIF_INT_ENABLE_RX2_EOR_ENABLE_SHIFT   (2U)
#define HOSTIF_INT_ENABLE_RX2_EOR_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX2_EOR_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX2_EOR_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX3_EOR_ENABLE_MASK    (0x8U)
#define HOSTIF_INT_ENABLE_RX3_EOR_ENABLE_SHIFT   (3U)
#define HOSTIF_INT_ENABLE_RX3_EOR_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX3_EOR_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX3_EOR_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_EOT_ENABLE_MASK        (0x10U)
#define HOSTIF_INT_ENABLE_EOT_ENABLE_SHIFT       (4U)
#define HOSTIF_INT_ENABLE_EOT_ENABLE(x)          (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_EOT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_EOT_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX_BUFFER_NOT_AVAILABLE_ENABLE_MASK (0x20U)
#define HOSTIF_INT_ENABLE_RX_BUFFER_NOT_AVAILABLE_ENABLE_SHIFT (5U)
#define HOSTIF_INT_ENABLE_RX_BUFFER_NOT_AVAILABLE_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX_BUFFER_NOT_AVAILABLE_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX_BUFFER_NOT_AVAILABLE_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_TX_FRAME_NOT_AVAILABLE_ENABLE_MASK (0x40U)
#define HOSTIF_INT_ENABLE_TX_FRAME_NOT_AVAILABLE_ENABLE_SHIFT (6U)
#define HOSTIF_INT_ENABLE_TX_FRAME_NOT_AVAILABLE_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_TX_FRAME_NOT_AVAILABLE_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_TX_FRAME_NOT_AVAILABLE_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_FIFO_TIMEOUT_ENABLE_MASK (0x80U)
#define HOSTIF_INT_ENABLE_FIFO_TIMEOUT_ENABLE_SHIFT (7U)
#define HOSTIF_INT_ENABLE_FIFO_TIMEOUT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_FIFO_TIMEOUT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_FIFO_TIMEOUT_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_FIFO_OVERFLOW_ENABLE_MASK (0x100U)
#define HOSTIF_INT_ENABLE_FIFO_OVERFLOW_ENABLE_SHIFT (8U)
#define HOSTIF_INT_ENABLE_FIFO_OVERFLOW_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_FIFO_OVERFLOW_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_FIFO_OVERFLOW_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_TIMEOUT_ENABLE_MASK    (0x200U)
#define HOSTIF_INT_ENABLE_TIMEOUT_ENABLE_SHIFT   (9U)
#define HOSTIF_INT_ENABLE_TIMEOUT_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_TIMEOUT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_TIMEOUT_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX0_BUFFER_OVERFLOW_ENABLE_MASK (0x400U)
#define HOSTIF_INT_ENABLE_RX0_BUFFER_OVERFLOW_ENABLE_SHIFT (10U)
#define HOSTIF_INT_ENABLE_RX0_BUFFER_OVERFLOW_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX0_BUFFER_OVERFLOW_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX0_BUFFER_OVERFLOW_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX1_BUFFER_OVERFLOW_ENABLE_MASK (0x800U)
#define HOSTIF_INT_ENABLE_RX1_BUFFER_OVERFLOW_ENABLE_SHIFT (11U)
#define HOSTIF_INT_ENABLE_RX1_BUFFER_OVERFLOW_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX1_BUFFER_OVERFLOW_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX1_BUFFER_OVERFLOW_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX2_BUFFER_OVERFLOW_ENABLE_MASK (0x1000U)
#define HOSTIF_INT_ENABLE_RX2_BUFFER_OVERFLOW_ENABLE_SHIFT (12U)
#define HOSTIF_INT_ENABLE_RX2_BUFFER_OVERFLOW_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX2_BUFFER_OVERFLOW_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX2_BUFFER_OVERFLOW_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_RX3_BUFFER_OVERFLOW_ENABLE_MASK (0x2000U)
#define HOSTIF_INT_ENABLE_RX3_BUFFER_OVERFLOW_ENABLE_SHIFT (13U)
#define HOSTIF_INT_ENABLE_RX3_BUFFER_OVERFLOW_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_RX3_BUFFER_OVERFLOW_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_RX3_BUFFER_OVERFLOW_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_WATERLEVEL_REACHED_ENABLE_MASK (0x4000U)
#define HOSTIF_INT_ENABLE_WATERLEVEL_REACHED_ENABLE_SHIFT (14U)
#define HOSTIF_INT_ENABLE_WATERLEVEL_REACHED_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_WATERLEVEL_REACHED_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_WATERLEVEL_REACHED_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_HSU_RX_FER_ENABLE_MASK (0x8000U)
#define HOSTIF_INT_ENABLE_HSU_RX_FER_ENABLE_SHIFT (15U)
#define HOSTIF_INT_ENABLE_HSU_RX_FER_ENABLE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_HSU_RX_FER_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_HSU_RX_FER_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_PREFETCH_OK_INT_ENABLE_MASK (0x10000U)
#define HOSTIF_INT_ENABLE_PREFETCH_OK_INT_ENABLE_SHIFT (16U)
#define HOSTIF_INT_ENABLE_PREFETCH_OK_INT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_PREFETCH_OK_INT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_PREFETCH_OK_INT_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_TX_DATA_READY_INT_ENABLE_MASK (0x20000U)
#define HOSTIF_INT_ENABLE_TX_DATA_READY_INT_ENABLE_SHIFT (17U)
#define HOSTIF_INT_ENABLE_TX_DATA_READY_INT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_TX_DATA_READY_INT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_TX_DATA_READY_INT_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_START_ENABLE_MASK  (0x200000U)
#define HOSTIF_INT_ENABLE_I3C_START_ENABLE_SHIFT (21U)
#define HOSTIF_INT_ENABLE_I3C_START_ENABLE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_START_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_START_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_MATCHED_ENABLE_MASK (0x400000U)
#define HOSTIF_INT_ENABLE_I3C_MATCHED_ENABLE_SHIFT (22U)
#define HOSTIF_INT_ENABLE_I3C_MATCHED_ENABLE(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_MATCHED_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_MATCHED_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_STOP_ENABLE_MASK   (0x800000U)
#define HOSTIF_INT_ENABLE_I3C_STOP_ENABLE_SHIFT  (23U)
#define HOSTIF_INT_ENABLE_I3C_STOP_ENABLE(x)     (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_STOP_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_STOP_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_RXPEND_ENABLE_MASK (0x1000000U)
#define HOSTIF_INT_ENABLE_I3C_RXPEND_ENABLE_SHIFT (24U)
#define HOSTIF_INT_ENABLE_I3C_RXPEND_ENABLE(x)   (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_RXPEND_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_RXPEND_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_TXNOTFULL_ENABLE_MASK (0x2000000U)
#define HOSTIF_INT_ENABLE_I3C_TXNOTFULL_ENABLE_SHIFT (25U)
#define HOSTIF_INT_ENABLE_I3C_TXNOTFULL_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_TXNOTFULL_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_TXNOTFULL_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_DACHG_ENABLE_MASK  (0x4000000U)
#define HOSTIF_INT_ENABLE_I3C_DACHG_ENABLE_SHIFT (26U)
#define HOSTIF_INT_ENABLE_I3C_DACHG_ENABLE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_DACHG_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_DACHG_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_CCC_ENABLE_MASK    (0x8000000U)
#define HOSTIF_INT_ENABLE_I3C_CCC_ENABLE_SHIFT   (27U)
#define HOSTIF_INT_ENABLE_I3C_CCC_ENABLE(x)      (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_CCC_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_CCC_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_ERROR_ENABLE_MASK  (0x10000000U)
#define HOSTIF_INT_ENABLE_I3C_ERROR_ENABLE_SHIFT (28U)
#define HOSTIF_INT_ENABLE_I3C_ERROR_ENABLE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_ERROR_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_ERROR_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_HDRMATCH_ENABLE_MASK (0x20000000U)
#define HOSTIF_INT_ENABLE_I3C_HDRMATCH_ENABLE_SHIFT (29U)
#define HOSTIF_INT_ENABLE_I3C_HDRMATCH_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_HDRMATCH_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_HDRMATCH_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_CHANDLED_ENABLE_MASK (0x40000000U)
#define HOSTIF_INT_ENABLE_I3C_CHANDLED_ENABLE_SHIFT (30U)
#define HOSTIF_INT_ENABLE_I3C_CHANDLED_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_CHANDLED_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_CHANDLED_ENABLE_MASK)

#define HOSTIF_INT_ENABLE_I3C_EVENT_ENABLE_MASK  (0x80000000U)
#define HOSTIF_INT_ENABLE_I3C_EVENT_ENABLE_SHIFT (31U)
#define HOSTIF_INT_ENABLE_I3C_EVENT_ENABLE(x)    (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_ENABLE_I3C_EVENT_ENABLE_SHIFT)) & HOSTIF_INT_ENABLE_I3C_EVENT_ENABLE_MASK)
/*! @} */

/*! @name INT_CLR_STATUS -  */
/*! @{ */

#define HOSTIF_INT_CLR_STATUS_RX0_EOR_CLR_STATUS_MASK (0x1U)
#define HOSTIF_INT_CLR_STATUS_RX0_EOR_CLR_STATUS_SHIFT (0U)
#define HOSTIF_INT_CLR_STATUS_RX0_EOR_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX0_EOR_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX0_EOR_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX1_EOR_CLR_STATUS_MASK (0x2U)
#define HOSTIF_INT_CLR_STATUS_RX1_EOR_CLR_STATUS_SHIFT (1U)
#define HOSTIF_INT_CLR_STATUS_RX1_EOR_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX1_EOR_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX1_EOR_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX2_EOR_CLR_STATUS_MASK (0x4U)
#define HOSTIF_INT_CLR_STATUS_RX2_EOR_CLR_STATUS_SHIFT (2U)
#define HOSTIF_INT_CLR_STATUS_RX2_EOR_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX2_EOR_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX2_EOR_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX3_EOR_CLR_STATUS_MASK (0x8U)
#define HOSTIF_INT_CLR_STATUS_RX3_EOR_CLR_STATUS_SHIFT (3U)
#define HOSTIF_INT_CLR_STATUS_RX3_EOR_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX3_EOR_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX3_EOR_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_EOT_CLR_STATUS_MASK (0x10U)
#define HOSTIF_INT_CLR_STATUS_EOT_CLR_STATUS_SHIFT (4U)
#define HOSTIF_INT_CLR_STATUS_EOT_CLR_STATUS(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_EOT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_EOT_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX_BUFFER_NOT_AVAILABLE_CLR_STATUS_MASK (0x20U)
#define HOSTIF_INT_CLR_STATUS_RX_BUFFER_NOT_AVAILABLE_CLR_STATUS_SHIFT (5U)
#define HOSTIF_INT_CLR_STATUS_RX_BUFFER_NOT_AVAILABLE_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX_BUFFER_NOT_AVAILABLE_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX_BUFFER_NOT_AVAILABLE_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_TX_FRAME_NOT_AVAILABLE_CLR_STATUS_MASK (0x40U)
#define HOSTIF_INT_CLR_STATUS_TX_FRAME_NOT_AVAILABLE_CLR_STATUS_SHIFT (6U)
#define HOSTIF_INT_CLR_STATUS_TX_FRAME_NOT_AVAILABLE_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_TX_FRAME_NOT_AVAILABLE_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_TX_FRAME_NOT_AVAILABLE_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_FIFO_TIMEOUT_CLR_STATUS_MASK (0x80U)
#define HOSTIF_INT_CLR_STATUS_FIFO_TIMEOUT_CLR_STATUS_SHIFT (7U)
#define HOSTIF_INT_CLR_STATUS_FIFO_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_FIFO_TIMEOUT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_FIFO_TIMEOUT_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_FIFO_OVERFLOW_CLR_STATUS_MASK (0x100U)
#define HOSTIF_INT_CLR_STATUS_FIFO_OVERFLOW_CLR_STATUS_SHIFT (8U)
#define HOSTIF_INT_CLR_STATUS_FIFO_OVERFLOW_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_FIFO_OVERFLOW_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_FIFO_OVERFLOW_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_TIMEOUT_CLR_STATUS_MASK (0x200U)
#define HOSTIF_INT_CLR_STATUS_TIMEOUT_CLR_STATUS_SHIFT (9U)
#define HOSTIF_INT_CLR_STATUS_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_TIMEOUT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_TIMEOUT_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX0_BUFFER_OVERFLOW_CLR_STATUS_MASK (0x400U)
#define HOSTIF_INT_CLR_STATUS_RX0_BUFFER_OVERFLOW_CLR_STATUS_SHIFT (10U)
#define HOSTIF_INT_CLR_STATUS_RX0_BUFFER_OVERFLOW_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX0_BUFFER_OVERFLOW_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX0_BUFFER_OVERFLOW_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX1_BUFFER_OVERFLOW_CLR_STATUS_MASK (0x800U)
#define HOSTIF_INT_CLR_STATUS_RX1_BUFFER_OVERFLOW_CLR_STATUS_SHIFT (11U)
#define HOSTIF_INT_CLR_STATUS_RX1_BUFFER_OVERFLOW_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX1_BUFFER_OVERFLOW_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX1_BUFFER_OVERFLOW_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX2_BUFFER_OVERFLOW_CLR_STATUS_MASK (0x1000U)
#define HOSTIF_INT_CLR_STATUS_RX2_BUFFER_OVERFLOW_CLR_STATUS_SHIFT (12U)
#define HOSTIF_INT_CLR_STATUS_RX2_BUFFER_OVERFLOW_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX2_BUFFER_OVERFLOW_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX2_BUFFER_OVERFLOW_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_RX3_BUFFER_OVERFLOW_CLR_STATUS_MASK (0x2000U)
#define HOSTIF_INT_CLR_STATUS_RX3_BUFFER_OVERFLOW_CLR_STATUS_SHIFT (13U)
#define HOSTIF_INT_CLR_STATUS_RX3_BUFFER_OVERFLOW_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_RX3_BUFFER_OVERFLOW_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_RX3_BUFFER_OVERFLOW_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_WATERLEVEL_REACHED_CLR_STATUS_MASK (0x4000U)
#define HOSTIF_INT_CLR_STATUS_WATERLEVEL_REACHED_CLR_STATUS_SHIFT (14U)
#define HOSTIF_INT_CLR_STATUS_WATERLEVEL_REACHED_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_WATERLEVEL_REACHED_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_WATERLEVEL_REACHED_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_HSU_RX_FER_CLR_STATUS_MASK (0x8000U)
#define HOSTIF_INT_CLR_STATUS_HSU_RX_FER_CLR_STATUS_SHIFT (15U)
#define HOSTIF_INT_CLR_STATUS_HSU_RX_FER_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_HSU_RX_FER_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_HSU_RX_FER_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_PREFETCH_OK_INT_CLR_STATUS_MASK (0x10000U)
#define HOSTIF_INT_CLR_STATUS_PREFETCH_OK_INT_CLR_STATUS_SHIFT (16U)
#define HOSTIF_INT_CLR_STATUS_PREFETCH_OK_INT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_PREFETCH_OK_INT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_PREFETCH_OK_INT_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_TX_DATA_READY_INT_CLR_STATUS_MASK (0x20000U)
#define HOSTIF_INT_CLR_STATUS_TX_DATA_READY_INT_CLR_STATUS_SHIFT (17U)
#define HOSTIF_INT_CLR_STATUS_TX_DATA_READY_INT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_TX_DATA_READY_INT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_TX_DATA_READY_INT_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_START_CLR_STATUS_MASK (0x200000U)
#define HOSTIF_INT_CLR_STATUS_I3C_START_CLR_STATUS_SHIFT (21U)
#define HOSTIF_INT_CLR_STATUS_I3C_START_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_START_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_START_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_MATCHED_CLR_STATUS_MASK (0x400000U)
#define HOSTIF_INT_CLR_STATUS_I3C_MATCHED_CLR_STATUS_SHIFT (22U)
#define HOSTIF_INT_CLR_STATUS_I3C_MATCHED_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_MATCHED_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_MATCHED_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_STOP_CLR_STATUS_MASK (0x800000U)
#define HOSTIF_INT_CLR_STATUS_I3C_STOP_CLR_STATUS_SHIFT (23U)
#define HOSTIF_INT_CLR_STATUS_I3C_STOP_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_STOP_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_STOP_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_RXPEND_CLR_STATUS_MASK (0x1000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_RXPEND_CLR_STATUS_SHIFT (24U)
#define HOSTIF_INT_CLR_STATUS_I3C_RXPEND_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_RXPEND_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_RXPEND_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_TXNOTFULL_CLR_STATUS_MASK (0x2000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_TXNOTFULL_CLR_STATUS_SHIFT (25U)
#define HOSTIF_INT_CLR_STATUS_I3C_TXNOTFULL_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_TXNOTFULL_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_TXNOTFULL_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_DACHG_CLR_STATUS_MASK (0x4000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_DACHG_CLR_STATUS_SHIFT (26U)
#define HOSTIF_INT_CLR_STATUS_I3C_DACHG_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_DACHG_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_DACHG_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_CCC_CLR_STATUS_MASK (0x8000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_CCC_CLR_STATUS_SHIFT (27U)
#define HOSTIF_INT_CLR_STATUS_I3C_CCC_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_CCC_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_CCC_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_ERROR_CLR_STATUS_MASK (0x10000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_ERROR_CLR_STATUS_SHIFT (28U)
#define HOSTIF_INT_CLR_STATUS_I3C_ERROR_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_ERROR_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_ERROR_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_HDRMATCH_CLR_STATUS_MASK (0x20000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_HDRMATCH_CLR_STATUS_SHIFT (29U)
#define HOSTIF_INT_CLR_STATUS_I3C_HDRMATCH_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_HDRMATCH_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_HDRMATCH_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_CHANDLED_CLR_STATUS_MASK (0x40000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_CHANDLED_CLR_STATUS_SHIFT (30U)
#define HOSTIF_INT_CLR_STATUS_I3C_CHANDLED_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_CHANDLED_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_CHANDLED_CLR_STATUS_MASK)

#define HOSTIF_INT_CLR_STATUS_I3C_EVENT_CLR_STATUS_MASK (0x80000000U)
#define HOSTIF_INT_CLR_STATUS_I3C_EVENT_CLR_STATUS_SHIFT (31U)
#define HOSTIF_INT_CLR_STATUS_I3C_EVENT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_CLR_STATUS_I3C_EVENT_CLR_STATUS_SHIFT)) & HOSTIF_INT_CLR_STATUS_I3C_EVENT_CLR_STATUS_MASK)
/*! @} */

/*! @name INT_SET_STATUS -  */
/*! @{ */

#define HOSTIF_INT_SET_STATUS_RX0_EOR_SET_STATUS_MASK (0x1U)
#define HOSTIF_INT_SET_STATUS_RX0_EOR_SET_STATUS_SHIFT (0U)
#define HOSTIF_INT_SET_STATUS_RX0_EOR_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX0_EOR_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX0_EOR_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX1_EOR_SET_STATUS_MASK (0x2U)
#define HOSTIF_INT_SET_STATUS_RX1_EOR_SET_STATUS_SHIFT (1U)
#define HOSTIF_INT_SET_STATUS_RX1_EOR_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX1_EOR_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX1_EOR_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX2_EOR_SET_STATUS_MASK (0x4U)
#define HOSTIF_INT_SET_STATUS_RX2_EOR_SET_STATUS_SHIFT (2U)
#define HOSTIF_INT_SET_STATUS_RX2_EOR_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX2_EOR_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX2_EOR_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX3_EOR_SET_STATUS_MASK (0x8U)
#define HOSTIF_INT_SET_STATUS_RX3_EOR_SET_STATUS_SHIFT (3U)
#define HOSTIF_INT_SET_STATUS_RX3_EOR_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX3_EOR_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX3_EOR_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_EOT_SET_STATUS_MASK (0x10U)
#define HOSTIF_INT_SET_STATUS_EOT_SET_STATUS_SHIFT (4U)
#define HOSTIF_INT_SET_STATUS_EOT_SET_STATUS(x)  (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_EOT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_EOT_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX_BUFFER_NOT_AVAILABLE_SET_STATUS_MASK (0x20U)
#define HOSTIF_INT_SET_STATUS_RX_BUFFER_NOT_AVAILABLE_SET_STATUS_SHIFT (5U)
#define HOSTIF_INT_SET_STATUS_RX_BUFFER_NOT_AVAILABLE_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX_BUFFER_NOT_AVAILABLE_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX_BUFFER_NOT_AVAILABLE_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_TX_FRAME_NOT_AVAILABLE_SET_STATUS_MASK (0x40U)
#define HOSTIF_INT_SET_STATUS_TX_FRAME_NOT_AVAILABLE_SET_STATUS_SHIFT (6U)
#define HOSTIF_INT_SET_STATUS_TX_FRAME_NOT_AVAILABLE_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_TX_FRAME_NOT_AVAILABLE_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_TX_FRAME_NOT_AVAILABLE_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_FIFO_TIMEOUT_SET_STATUS_MASK (0x80U)
#define HOSTIF_INT_SET_STATUS_FIFO_TIMEOUT_SET_STATUS_SHIFT (7U)
#define HOSTIF_INT_SET_STATUS_FIFO_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_FIFO_TIMEOUT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_FIFO_TIMEOUT_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_FIFO_OVERFLOW_SET_STATUS_MASK (0x100U)
#define HOSTIF_INT_SET_STATUS_FIFO_OVERFLOW_SET_STATUS_SHIFT (8U)
#define HOSTIF_INT_SET_STATUS_FIFO_OVERFLOW_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_FIFO_OVERFLOW_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_FIFO_OVERFLOW_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_TIMEOUT_SET_STATUS_MASK (0x200U)
#define HOSTIF_INT_SET_STATUS_TIMEOUT_SET_STATUS_SHIFT (9U)
#define HOSTIF_INT_SET_STATUS_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_TIMEOUT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_TIMEOUT_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX0_BUFFER_OVERFLOW_SET_STATUS_MASK (0x400U)
#define HOSTIF_INT_SET_STATUS_RX0_BUFFER_OVERFLOW_SET_STATUS_SHIFT (10U)
#define HOSTIF_INT_SET_STATUS_RX0_BUFFER_OVERFLOW_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX0_BUFFER_OVERFLOW_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX0_BUFFER_OVERFLOW_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX1_BUFFER_OVERFLOW_SET_STATUS_MASK (0x800U)
#define HOSTIF_INT_SET_STATUS_RX1_BUFFER_OVERFLOW_SET_STATUS_SHIFT (11U)
#define HOSTIF_INT_SET_STATUS_RX1_BUFFER_OVERFLOW_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX1_BUFFER_OVERFLOW_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX1_BUFFER_OVERFLOW_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX2_BUFFER_OVERFLOW_SET_STATUS_MASK (0x1000U)
#define HOSTIF_INT_SET_STATUS_RX2_BUFFER_OVERFLOW_SET_STATUS_SHIFT (12U)
#define HOSTIF_INT_SET_STATUS_RX2_BUFFER_OVERFLOW_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX2_BUFFER_OVERFLOW_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX2_BUFFER_OVERFLOW_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_RX3_BUFFER_OVERFLOW_SET_STATUS_MASK (0x2000U)
#define HOSTIF_INT_SET_STATUS_RX3_BUFFER_OVERFLOW_SET_STATUS_SHIFT (13U)
#define HOSTIF_INT_SET_STATUS_RX3_BUFFER_OVERFLOW_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_RX3_BUFFER_OVERFLOW_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_RX3_BUFFER_OVERFLOW_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_WATERLEVEL_REACHED_SET_STATUS_MASK (0x4000U)
#define HOSTIF_INT_SET_STATUS_WATERLEVEL_REACHED_SET_STATUS_SHIFT (14U)
#define HOSTIF_INT_SET_STATUS_WATERLEVEL_REACHED_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_WATERLEVEL_REACHED_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_WATERLEVEL_REACHED_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_HSU_RX_FER_SET_STATUS_MASK (0x8000U)
#define HOSTIF_INT_SET_STATUS_HSU_RX_FER_SET_STATUS_SHIFT (15U)
#define HOSTIF_INT_SET_STATUS_HSU_RX_FER_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_HSU_RX_FER_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_HSU_RX_FER_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_PREFETCH_OK_INT_SET_STATUS_MASK (0x10000U)
#define HOSTIF_INT_SET_STATUS_PREFETCH_OK_INT_SET_STATUS_SHIFT (16U)
#define HOSTIF_INT_SET_STATUS_PREFETCH_OK_INT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_PREFETCH_OK_INT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_PREFETCH_OK_INT_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_TX_DATA_READY_INT_SET_STATUS_MASK (0x20000U)
#define HOSTIF_INT_SET_STATUS_TX_DATA_READY_INT_SET_STATUS_SHIFT (17U)
#define HOSTIF_INT_SET_STATUS_TX_DATA_READY_INT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_TX_DATA_READY_INT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_TX_DATA_READY_INT_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_START_SET_STATUS_MASK (0x200000U)
#define HOSTIF_INT_SET_STATUS_I3C_START_SET_STATUS_SHIFT (21U)
#define HOSTIF_INT_SET_STATUS_I3C_START_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_START_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_START_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_MATCHED_SET_STATUS_MASK (0x400000U)
#define HOSTIF_INT_SET_STATUS_I3C_MATCHED_SET_STATUS_SHIFT (22U)
#define HOSTIF_INT_SET_STATUS_I3C_MATCHED_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_MATCHED_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_MATCHED_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_STOP_SET_STATUS_MASK (0x800000U)
#define HOSTIF_INT_SET_STATUS_I3C_STOP_SET_STATUS_SHIFT (23U)
#define HOSTIF_INT_SET_STATUS_I3C_STOP_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_STOP_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_STOP_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_RXPEND_SET_STATUS_MASK (0x1000000U)
#define HOSTIF_INT_SET_STATUS_I3C_RXPEND_SET_STATUS_SHIFT (24U)
#define HOSTIF_INT_SET_STATUS_I3C_RXPEND_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_RXPEND_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_RXPEND_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_TXNOTFULL_SET_STATUS_MASK (0x2000000U)
#define HOSTIF_INT_SET_STATUS_I3C_TXNOTFULL_SET_STATUS_SHIFT (25U)
#define HOSTIF_INT_SET_STATUS_I3C_TXNOTFULL_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_TXNOTFULL_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_TXNOTFULL_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_DACHG_SET_STATUS_MASK (0x4000000U)
#define HOSTIF_INT_SET_STATUS_I3C_DACHG_SET_STATUS_SHIFT (26U)
#define HOSTIF_INT_SET_STATUS_I3C_DACHG_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_DACHG_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_DACHG_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_CCC_SET_STATUS_MASK (0x8000000U)
#define HOSTIF_INT_SET_STATUS_I3C_CCC_SET_STATUS_SHIFT (27U)
#define HOSTIF_INT_SET_STATUS_I3C_CCC_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_CCC_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_CCC_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_ERROR_SET_STATUS_MASK (0x10000000U)
#define HOSTIF_INT_SET_STATUS_I3C_ERROR_SET_STATUS_SHIFT (28U)
#define HOSTIF_INT_SET_STATUS_I3C_ERROR_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_ERROR_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_ERROR_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_HDRMATCH_SET_STATUS_MASK (0x20000000U)
#define HOSTIF_INT_SET_STATUS_I3C_HDRMATCH_SET_STATUS_SHIFT (29U)
#define HOSTIF_INT_SET_STATUS_I3C_HDRMATCH_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_HDRMATCH_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_HDRMATCH_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_CHANDLED_SET_STATUS_MASK (0x40000000U)
#define HOSTIF_INT_SET_STATUS_I3C_CHANDLED_SET_STATUS_SHIFT (30U)
#define HOSTIF_INT_SET_STATUS_I3C_CHANDLED_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_CHANDLED_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_CHANDLED_SET_STATUS_MASK)

#define HOSTIF_INT_SET_STATUS_I3C_EVENT_SET_STATUS_MASK (0x80000000U)
#define HOSTIF_INT_SET_STATUS_I3C_EVENT_SET_STATUS_SHIFT (31U)
#define HOSTIF_INT_SET_STATUS_I3C_EVENT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << HOSTIF_INT_SET_STATUS_I3C_EVENT_SET_STATUS_SHIFT)) & HOSTIF_INT_SET_STATUS_I3C_EVENT_SET_STATUS_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group HOSTIF_Register_Masks */


/* HOSTIF - Peripheral instance base addresses */
/** Peripheral HOSTIF base address */
#define HOSTIF_BASE                              (0x40000000u)
/** Peripheral HOSTIF base pointer */
#define HOSTIF                                   ((HOSTIF_Type *)HOSTIF_BASE)
/** Array initializer of HOSTIF peripheral base addresses */
#define HOSTIF_BASE_ADDRS                        { HOSTIF_BASE }
/** Array initializer of HOSTIF peripheral base pointers */
#define HOSTIF_BASE_PTRS                         { HOSTIF }
/** Interrupt vectors for the HOSTIF peripheral type */
#define HOSTIF_IRQS                              { HOSTIF_IRQn }

/*!
 * @}
 */ /* end of group HOSTIF_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- I2C Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup I2C_Peripheral_Access_Layer I2C Peripheral Access Layer
 * @{
 */

/** I2C - Register Layout Typedef */
typedef struct {
  __IO uint32_t CFG;                               /**< , offset: 0x0 */
  __IO uint32_t STAT;                              /**< , offset: 0x4 */
  __IO uint32_t INTENSET;                          /**< , offset: 0x8 */
  __IO uint32_t INTENCLR;                          /**< , offset: 0xC */
  __IO uint32_t TIMEOUT;                           /**< , offset: 0x10 */
  __IO uint32_t CLKDIV;                            /**< , offset: 0x14 */
  __I  uint32_t INTSTAT;                           /**< , offset: 0x18 */
  __IO uint32_t CLKDLY;                            /**< , offset: 0x1C */
  __IO uint32_t MSTCTL;                            /**< , offset: 0x20 */
  __IO uint32_t MSTTIME;                           /**< , offset: 0x24 */
  __IO uint32_t MSTDAT;                            /**< , offset: 0x28 */
       uint8_t RESERVED_0[20];
  __IO uint32_t SLVCTL;                            /**< , offset: 0x40 */
  __IO uint32_t SLVDAT;                            /**< , offset: 0x44 */
  __IO uint32_t SLVADR[4];                         /**< , array offset: 0x48, array step: 0x4 */
  __IO uint32_t SLVQUAL0;                          /**< , offset: 0x58 */
  __IO uint32_t SLVTXSIZE;                         /**< , offset: 0x5C */
       uint8_t RESERVED_1[32];
  __I  uint32_t MONRXDAT;                          /**< , offset: 0x80 */
       uint8_t RESERVED_2[3960];
  __I  uint32_t ID;                                /**< , offset: 0xFFC */
} I2C_Type;

/* ----------------------------------------------------------------------------
   -- I2C Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup I2C_Register_Masks I2C Register Masks
 * @{
 */

/*! @name CFG -  */
/*! @{ */

#define I2C_CFG_MST_EN_MASK                      (0x1U)
#define I2C_CFG_MST_EN_SHIFT                     (0U)
#define I2C_CFG_MST_EN(x)                        (((uint32_t)(((uint32_t)(x)) << I2C_CFG_MST_EN_SHIFT)) & I2C_CFG_MST_EN_MASK)

#define I2C_CFG_SLV_EN_MASK                      (0x2U)
#define I2C_CFG_SLV_EN_SHIFT                     (1U)
#define I2C_CFG_SLV_EN(x)                        (((uint32_t)(((uint32_t)(x)) << I2C_CFG_SLV_EN_SHIFT)) & I2C_CFG_SLV_EN_MASK)

#define I2C_CFG_MON_EN_MASK                      (0x4U)
#define I2C_CFG_MON_EN_SHIFT                     (2U)
#define I2C_CFG_MON_EN(x)                        (((uint32_t)(((uint32_t)(x)) << I2C_CFG_MON_EN_SHIFT)) & I2C_CFG_MON_EN_MASK)

#define I2C_CFG_TIMEOUTEN_MASK                   (0x8U)
#define I2C_CFG_TIMEOUTEN_SHIFT                  (3U)
#define I2C_CFG_TIMEOUTEN(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CFG_TIMEOUTEN_SHIFT)) & I2C_CFG_TIMEOUTEN_MASK)

#define I2C_CFG_MONCLKSTR_MASK                   (0x10U)
#define I2C_CFG_MONCLKSTR_SHIFT                  (4U)
#define I2C_CFG_MONCLKSTR(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CFG_MONCLKSTR_SHIFT)) & I2C_CFG_MONCLKSTR_MASK)

#define I2C_CFG_HSCAPABLE_MASK                   (0x20U)
#define I2C_CFG_HSCAPABLE_SHIFT                  (5U)
#define I2C_CFG_HSCAPABLE(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CFG_HSCAPABLE_SHIFT)) & I2C_CFG_HSCAPABLE_MASK)

#define I2C_CFG_IDLE_BYTE_MASK                   (0x40U)
#define I2C_CFG_IDLE_BYTE_SHIFT                  (6U)
#define I2C_CFG_IDLE_BYTE(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CFG_IDLE_BYTE_SHIFT)) & I2C_CFG_IDLE_BYTE_MASK)
/*! @} */

/*! @name STAT -  */
/*! @{ */

#define I2C_STAT_MSTPENDING_MASK                 (0x1U)
#define I2C_STAT_MSTPENDING_SHIFT                (0U)
#define I2C_STAT_MSTPENDING(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MSTPENDING_SHIFT)) & I2C_STAT_MSTPENDING_MASK)

#define I2C_STAT_MSTSTATE_MASK                   (0xEU)
#define I2C_STAT_MSTSTATE_SHIFT                  (1U)
#define I2C_STAT_MSTSTATE(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MSTSTATE_SHIFT)) & I2C_STAT_MSTSTATE_MASK)

#define I2C_STAT_MSTARBLOSS_MASK                 (0x10U)
#define I2C_STAT_MSTARBLOSS_SHIFT                (4U)
#define I2C_STAT_MSTARBLOSS(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MSTARBLOSS_SHIFT)) & I2C_STAT_MSTARBLOSS_MASK)

#define I2C_STAT_MSTSTSTPERR_MASK                (0x40U)
#define I2C_STAT_MSTSTSTPERR_SHIFT               (6U)
#define I2C_STAT_MSTSTSTPERR(x)                  (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MSTSTSTPERR_SHIFT)) & I2C_STAT_MSTSTSTPERR_MASK)

#define I2C_STAT_SLVPENDING_MASK                 (0x100U)
#define I2C_STAT_SLVPENDING_SHIFT                (8U)
#define I2C_STAT_SLVPENDING(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVPENDING_SHIFT)) & I2C_STAT_SLVPENDING_MASK)

#define I2C_STAT_SLVSTATE_MASK                   (0x600U)
#define I2C_STAT_SLVSTATE_SHIFT                  (9U)
#define I2C_STAT_SLVSTATE(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVSTATE_SHIFT)) & I2C_STAT_SLVSTATE_MASK)

#define I2C_STAT_SLVNOTSTR_MASK                  (0x800U)
#define I2C_STAT_SLVNOTSTR_SHIFT                 (11U)
#define I2C_STAT_SLVNOTSTR(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVNOTSTR_SHIFT)) & I2C_STAT_SLVNOTSTR_MASK)

#define I2C_STAT_SLVIDX_MASK                     (0x3000U)
#define I2C_STAT_SLVIDX_SHIFT                    (12U)
#define I2C_STAT_SLVIDX(x)                       (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVIDX_SHIFT)) & I2C_STAT_SLVIDX_MASK)

#define I2C_STAT_SLVSEL_MASK                     (0x4000U)
#define I2C_STAT_SLVSEL_SHIFT                    (14U)
#define I2C_STAT_SLVSEL(x)                       (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVSEL_SHIFT)) & I2C_STAT_SLVSEL_MASK)

#define I2C_STAT_SLVDESEL_MASK                   (0x8000U)
#define I2C_STAT_SLVDESEL_SHIFT                  (15U)
#define I2C_STAT_SLVDESEL(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVDESEL_SHIFT)) & I2C_STAT_SLVDESEL_MASK)

#define I2C_STAT_MONRDY_MASK                     (0x10000U)
#define I2C_STAT_MONRDY_SHIFT                    (16U)
#define I2C_STAT_MONRDY(x)                       (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MONRDY_SHIFT)) & I2C_STAT_MONRDY_MASK)

#define I2C_STAT_MONOV_MASK                      (0x20000U)
#define I2C_STAT_MONOV_SHIFT                     (17U)
#define I2C_STAT_MONOV(x)                        (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MONOV_SHIFT)) & I2C_STAT_MONOV_MASK)

#define I2C_STAT_MONACTIVE_MASK                  (0x40000U)
#define I2C_STAT_MONACTIVE_SHIFT                 (18U)
#define I2C_STAT_MONACTIVE(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MONACTIVE_SHIFT)) & I2C_STAT_MONACTIVE_MASK)

#define I2C_STAT_MONIDLE_MASK                    (0x80000U)
#define I2C_STAT_MONIDLE_SHIFT                   (19U)
#define I2C_STAT_MONIDLE(x)                      (((uint32_t)(((uint32_t)(x)) << I2C_STAT_MONIDLE_SHIFT)) & I2C_STAT_MONIDLE_MASK)

#define I2C_STAT_EVENTTIMEOUT_MASK               (0x1000000U)
#define I2C_STAT_EVENTTIMEOUT_SHIFT              (24U)
#define I2C_STAT_EVENTTIMEOUT(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_STAT_EVENTTIMEOUT_SHIFT)) & I2C_STAT_EVENTTIMEOUT_MASK)

#define I2C_STAT_SCLTIMEOUT_MASK                 (0x2000000U)
#define I2C_STAT_SCLTIMEOUT_SHIFT                (25U)
#define I2C_STAT_SCLTIMEOUT(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SCLTIMEOUT_SHIFT)) & I2C_STAT_SCLTIMEOUT_MASK)

#define I2C_STAT_SLVTXDONE_MASK                  (0x4000000U)
#define I2C_STAT_SLVTXDONE_SHIFT                 (26U)
#define I2C_STAT_SLVTXDONE(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_STAT_SLVTXDONE_SHIFT)) & I2C_STAT_SLVTXDONE_MASK)
/*! @} */

/*! @name INTENSET -  */
/*! @{ */

#define I2C_INTENSET_MSTPENDINGEN_MASK           (0x1U)
#define I2C_INTENSET_MSTPENDINGEN_SHIFT          (0U)
#define I2C_INTENSET_MSTPENDINGEN(x)             (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MSTPENDINGEN_SHIFT)) & I2C_INTENSET_MSTPENDINGEN_MASK)

#define I2C_INTENSET_MSTARBLOSSEN_MASK           (0x10U)
#define I2C_INTENSET_MSTARBLOSSEN_SHIFT          (4U)
#define I2C_INTENSET_MSTARBLOSSEN(x)             (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MSTARBLOSSEN_SHIFT)) & I2C_INTENSET_MSTARBLOSSEN_MASK)

#define I2C_INTENSET_MSTSTSTPERREN_MASK          (0x40U)
#define I2C_INTENSET_MSTSTSTPERREN_SHIFT         (6U)
#define I2C_INTENSET_MSTSTSTPERREN(x)            (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MSTSTSTPERREN_SHIFT)) & I2C_INTENSET_MSTSTSTPERREN_MASK)

#define I2C_INTENSET_SLVPENDINGEN_MASK           (0x100U)
#define I2C_INTENSET_SLVPENDINGEN_SHIFT          (8U)
#define I2C_INTENSET_SLVPENDINGEN(x)             (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_SLVPENDINGEN_SHIFT)) & I2C_INTENSET_SLVPENDINGEN_MASK)

#define I2C_INTENSET_SLVNOTSTREN_MASK            (0x800U)
#define I2C_INTENSET_SLVNOTSTREN_SHIFT           (11U)
#define I2C_INTENSET_SLVNOTSTREN(x)              (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_SLVNOTSTREN_SHIFT)) & I2C_INTENSET_SLVNOTSTREN_MASK)

#define I2C_INTENSET_SLVDESELEN_MASK             (0x8000U)
#define I2C_INTENSET_SLVDESELEN_SHIFT            (15U)
#define I2C_INTENSET_SLVDESELEN(x)               (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_SLVDESELEN_SHIFT)) & I2C_INTENSET_SLVDESELEN_MASK)

#define I2C_INTENSET_MONRDYEN_MASK               (0x10000U)
#define I2C_INTENSET_MONRDYEN_SHIFT              (16U)
#define I2C_INTENSET_MONRDYEN(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MONRDYEN_SHIFT)) & I2C_INTENSET_MONRDYEN_MASK)

#define I2C_INTENSET_MONOVEN_MASK                (0x20000U)
#define I2C_INTENSET_MONOVEN_SHIFT               (17U)
#define I2C_INTENSET_MONOVEN(x)                  (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MONOVEN_SHIFT)) & I2C_INTENSET_MONOVEN_MASK)

#define I2C_INTENSET_MONIDLEEN_MASK              (0x80000U)
#define I2C_INTENSET_MONIDLEEN_SHIFT             (19U)
#define I2C_INTENSET_MONIDLEEN(x)                (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_MONIDLEEN_SHIFT)) & I2C_INTENSET_MONIDLEEN_MASK)

#define I2C_INTENSET_EVENTTIMEOUTEN_MASK         (0x1000000U)
#define I2C_INTENSET_EVENTTIMEOUTEN_SHIFT        (24U)
#define I2C_INTENSET_EVENTTIMEOUTEN(x)           (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_EVENTTIMEOUTEN_SHIFT)) & I2C_INTENSET_EVENTTIMEOUTEN_MASK)

#define I2C_INTENSET_SCLTIMEOUTEN_MASK           (0x2000000U)
#define I2C_INTENSET_SCLTIMEOUTEN_SHIFT          (25U)
#define I2C_INTENSET_SCLTIMEOUTEN(x)             (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_SCLTIMEOUTEN_SHIFT)) & I2C_INTENSET_SCLTIMEOUTEN_MASK)

#define I2C_INTENSET_SLVTXDONEEN_MASK            (0x4000000U)
#define I2C_INTENSET_SLVTXDONEEN_SHIFT           (26U)
#define I2C_INTENSET_SLVTXDONEEN(x)              (((uint32_t)(((uint32_t)(x)) << I2C_INTENSET_SLVTXDONEEN_SHIFT)) & I2C_INTENSET_SLVTXDONEEN_MASK)
/*! @} */

/*! @name INTENCLR -  */
/*! @{ */

#define I2C_INTENCLR_MSTPENDINGENCLR_MASK        (0x1U)
#define I2C_INTENCLR_MSTPENDINGENCLR_SHIFT       (0U)
#define I2C_INTENCLR_MSTPENDINGENCLR(x)          (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MSTPENDINGENCLR_SHIFT)) & I2C_INTENCLR_MSTPENDINGENCLR_MASK)

#define I2C_INTENCLR_MSTARBLOSSENCLR_MASK        (0x10U)
#define I2C_INTENCLR_MSTARBLOSSENCLR_SHIFT       (4U)
#define I2C_INTENCLR_MSTARBLOSSENCLR(x)          (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MSTARBLOSSENCLR_SHIFT)) & I2C_INTENCLR_MSTARBLOSSENCLR_MASK)

#define I2C_INTENCLR_MSTSTSTPERRENCLR_MASK       (0x40U)
#define I2C_INTENCLR_MSTSTSTPERRENCLR_SHIFT      (6U)
#define I2C_INTENCLR_MSTSTSTPERRENCLR(x)         (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MSTSTSTPERRENCLR_SHIFT)) & I2C_INTENCLR_MSTSTSTPERRENCLR_MASK)

#define I2C_INTENCLR_SLVPENDINGENCLR_MASK        (0x100U)
#define I2C_INTENCLR_SLVPENDINGENCLR_SHIFT       (8U)
#define I2C_INTENCLR_SLVPENDINGENCLR(x)          (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_SLVPENDINGENCLR_SHIFT)) & I2C_INTENCLR_SLVPENDINGENCLR_MASK)

#define I2C_INTENCLR_SLVNOTSTRENCLR_MASK         (0x800U)
#define I2C_INTENCLR_SLVNOTSTRENCLR_SHIFT        (11U)
#define I2C_INTENCLR_SLVNOTSTRENCLR(x)           (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_SLVNOTSTRENCLR_SHIFT)) & I2C_INTENCLR_SLVNOTSTRENCLR_MASK)

#define I2C_INTENCLR_SLVDESELENCLR_MASK          (0x8000U)
#define I2C_INTENCLR_SLVDESELENCLR_SHIFT         (15U)
#define I2C_INTENCLR_SLVDESELENCLR(x)            (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_SLVDESELENCLR_SHIFT)) & I2C_INTENCLR_SLVDESELENCLR_MASK)

#define I2C_INTENCLR_MONRDYENCLR_MASK            (0x10000U)
#define I2C_INTENCLR_MONRDYENCLR_SHIFT           (16U)
#define I2C_INTENCLR_MONRDYENCLR(x)              (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MONRDYENCLR_SHIFT)) & I2C_INTENCLR_MONRDYENCLR_MASK)

#define I2C_INTENCLR_MONOVENCLR_MASK             (0x20000U)
#define I2C_INTENCLR_MONOVENCLR_SHIFT            (17U)
#define I2C_INTENCLR_MONOVENCLR(x)               (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MONOVENCLR_SHIFT)) & I2C_INTENCLR_MONOVENCLR_MASK)

#define I2C_INTENCLR_MONIDLEENCLR_MASK           (0x80000U)
#define I2C_INTENCLR_MONIDLEENCLR_SHIFT          (19U)
#define I2C_INTENCLR_MONIDLEENCLR(x)             (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_MONIDLEENCLR_SHIFT)) & I2C_INTENCLR_MONIDLEENCLR_MASK)

#define I2C_INTENCLR_EVENTTIMEOUTENCLR_MASK      (0x1000000U)
#define I2C_INTENCLR_EVENTTIMEOUTENCLR_SHIFT     (24U)
#define I2C_INTENCLR_EVENTTIMEOUTENCLR(x)        (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_EVENTTIMEOUTENCLR_SHIFT)) & I2C_INTENCLR_EVENTTIMEOUTENCLR_MASK)

#define I2C_INTENCLR_SCLTIMEOUTENCLR_MASK        (0x2000000U)
#define I2C_INTENCLR_SCLTIMEOUTENCLR_SHIFT       (25U)
#define I2C_INTENCLR_SCLTIMEOUTENCLR(x)          (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_SCLTIMEOUTENCLR_SHIFT)) & I2C_INTENCLR_SCLTIMEOUTENCLR_MASK)

#define I2C_INTENCLR_SLVTXDONEENCLR_MASK         (0x4000000U)
#define I2C_INTENCLR_SLVTXDONEENCLR_SHIFT        (26U)
#define I2C_INTENCLR_SLVTXDONEENCLR(x)           (((uint32_t)(((uint32_t)(x)) << I2C_INTENCLR_SLVTXDONEENCLR_SHIFT)) & I2C_INTENCLR_SLVTXDONEENCLR_MASK)
/*! @} */

/*! @name TIMEOUT -  */
/*! @{ */

#define I2C_TIMEOUT_TIMEOUT_LSB_MASK             (0xFU)
#define I2C_TIMEOUT_TIMEOUT_LSB_SHIFT            (0U)
#define I2C_TIMEOUT_TIMEOUT_LSB(x)               (((uint32_t)(((uint32_t)(x)) << I2C_TIMEOUT_TIMEOUT_LSB_SHIFT)) & I2C_TIMEOUT_TIMEOUT_LSB_MASK)

#define I2C_TIMEOUT_TIMEOUT_MASK                 (0xFFF0U)
#define I2C_TIMEOUT_TIMEOUT_SHIFT                (4U)
#define I2C_TIMEOUT_TIMEOUT(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_TIMEOUT_TIMEOUT_SHIFT)) & I2C_TIMEOUT_TIMEOUT_MASK)
/*! @} */

/*! @name CLKDIV -  */
/*! @{ */

#define I2C_CLKDIV_CLKDIV_MASK                   (0xFFFFU)
#define I2C_CLKDIV_CLKDIV_SHIFT                  (0U)
#define I2C_CLKDIV_CLKDIV(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CLKDIV_CLKDIV_SHIFT)) & I2C_CLKDIV_CLKDIV_MASK)
/*! @} */

/*! @name INTSTAT -  */
/*! @{ */

#define I2C_INTSTAT_MSTPENDING_MASK              (0x1U)
#define I2C_INTSTAT_MSTPENDING_SHIFT             (0U)
#define I2C_INTSTAT_MSTPENDING(x)                (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MSTPENDING_SHIFT)) & I2C_INTSTAT_MSTPENDING_MASK)

#define I2C_INTSTAT_MSTARBLOSS_MASK              (0x10U)
#define I2C_INTSTAT_MSTARBLOSS_SHIFT             (4U)
#define I2C_INTSTAT_MSTARBLOSS(x)                (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MSTARBLOSS_SHIFT)) & I2C_INTSTAT_MSTARBLOSS_MASK)

#define I2C_INTSTAT_MSTSTSTPERR_MASK             (0x40U)
#define I2C_INTSTAT_MSTSTSTPERR_SHIFT            (6U)
#define I2C_INTSTAT_MSTSTSTPERR(x)               (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MSTSTSTPERR_SHIFT)) & I2C_INTSTAT_MSTSTSTPERR_MASK)

#define I2C_INTSTAT_SLVPENDING_MASK              (0x100U)
#define I2C_INTSTAT_SLVPENDING_SHIFT             (8U)
#define I2C_INTSTAT_SLVPENDING(x)                (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_SLVPENDING_SHIFT)) & I2C_INTSTAT_SLVPENDING_MASK)

#define I2C_INTSTAT_SLVNOTSTR_MASK               (0x800U)
#define I2C_INTSTAT_SLVNOTSTR_SHIFT              (11U)
#define I2C_INTSTAT_SLVNOTSTR(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_SLVNOTSTR_SHIFT)) & I2C_INTSTAT_SLVNOTSTR_MASK)

#define I2C_INTSTAT_SLVDESEL_MASK                (0x8000U)
#define I2C_INTSTAT_SLVDESEL_SHIFT               (15U)
#define I2C_INTSTAT_SLVDESEL(x)                  (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_SLVDESEL_SHIFT)) & I2C_INTSTAT_SLVDESEL_MASK)

#define I2C_INTSTAT_MONRDY_MASK                  (0x10000U)
#define I2C_INTSTAT_MONRDY_SHIFT                 (16U)
#define I2C_INTSTAT_MONRDY(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MONRDY_SHIFT)) & I2C_INTSTAT_MONRDY_MASK)

#define I2C_INTSTAT_MONOV_MASK                   (0x20000U)
#define I2C_INTSTAT_MONOV_SHIFT                  (17U)
#define I2C_INTSTAT_MONOV(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MONOV_SHIFT)) & I2C_INTSTAT_MONOV_MASK)

#define I2C_INTSTAT_MONIDLE_MASK                 (0x80000U)
#define I2C_INTSTAT_MONIDLE_SHIFT                (19U)
#define I2C_INTSTAT_MONIDLE(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_MONIDLE_SHIFT)) & I2C_INTSTAT_MONIDLE_MASK)

#define I2C_INTSTAT_EVENTTIMEOUT_MASK            (0x1000000U)
#define I2C_INTSTAT_EVENTTIMEOUT_SHIFT           (24U)
#define I2C_INTSTAT_EVENTTIMEOUT(x)              (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_EVENTTIMEOUT_SHIFT)) & I2C_INTSTAT_EVENTTIMEOUT_MASK)

#define I2C_INTSTAT_SCLTIMEOUT_MASK              (0x2000000U)
#define I2C_INTSTAT_SCLTIMEOUT_SHIFT             (25U)
#define I2C_INTSTAT_SCLTIMEOUT(x)                (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_SCLTIMEOUT_SHIFT)) & I2C_INTSTAT_SCLTIMEOUT_MASK)

#define I2C_INTSTAT_SLVTXDONE_MASK               (0x4000000U)
#define I2C_INTSTAT_SLVTXDONE_SHIFT              (26U)
#define I2C_INTSTAT_SLVTXDONE(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_INTSTAT_SLVTXDONE_SHIFT)) & I2C_INTSTAT_SLVTXDONE_MASK)
/*! @} */

/*! @name CLKDLY -  */
/*! @{ */

#define I2C_CLKDLY_CLKDLY_MASK                   (0xFFU)
#define I2C_CLKDLY_CLKDLY_SHIFT                  (0U)
#define I2C_CLKDLY_CLKDLY(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_CLKDLY_CLKDLY_SHIFT)) & I2C_CLKDLY_CLKDLY_MASK)
/*! @} */

/*! @name MSTCTL -  */
/*! @{ */

#define I2C_MSTCTL_MSTCONTINUE_MASK              (0x1U)
#define I2C_MSTCTL_MSTCONTINUE_SHIFT             (0U)
#define I2C_MSTCTL_MSTCONTINUE(x)                (((uint32_t)(((uint32_t)(x)) << I2C_MSTCTL_MSTCONTINUE_SHIFT)) & I2C_MSTCTL_MSTCONTINUE_MASK)

#define I2C_MSTCTL_MSTSTART_MASK                 (0x2U)
#define I2C_MSTCTL_MSTSTART_SHIFT                (1U)
#define I2C_MSTCTL_MSTSTART(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_MSTCTL_MSTSTART_SHIFT)) & I2C_MSTCTL_MSTSTART_MASK)

#define I2C_MSTCTL_MSTSTOP_MASK                  (0x4U)
#define I2C_MSTCTL_MSTSTOP_SHIFT                 (2U)
#define I2C_MSTCTL_MSTSTOP(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_MSTCTL_MSTSTOP_SHIFT)) & I2C_MSTCTL_MSTSTOP_MASK)

#define I2C_MSTCTL_MSTDMA_MASK                   (0x8U)
#define I2C_MSTCTL_MSTDMA_SHIFT                  (3U)
#define I2C_MSTCTL_MSTDMA(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_MSTCTL_MSTDMA_SHIFT)) & I2C_MSTCTL_MSTDMA_MASK)

#define I2C_MSTCTL_IGN_SCLO_MASK                 (0x80U)
#define I2C_MSTCTL_IGN_SCLO_SHIFT                (7U)
#define I2C_MSTCTL_IGN_SCLO(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_MSTCTL_IGN_SCLO_SHIFT)) & I2C_MSTCTL_IGN_SCLO_MASK)
/*! @} */

/*! @name MSTTIME -  */
/*! @{ */

#define I2C_MSTTIME_MSTSCLLOW_MASK               (0x7U)
#define I2C_MSTTIME_MSTSCLLOW_SHIFT              (0U)
#define I2C_MSTTIME_MSTSCLLOW(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_MSTTIME_MSTSCLLOW_SHIFT)) & I2C_MSTTIME_MSTSCLLOW_MASK)

#define I2C_MSTTIME_MSTCLHIGH_MASK               (0x70U)
#define I2C_MSTTIME_MSTCLHIGH_SHIFT              (4U)
#define I2C_MSTTIME_MSTCLHIGH(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_MSTTIME_MSTCLHIGH_SHIFT)) & I2C_MSTTIME_MSTCLHIGH_MASK)
/*! @} */

/*! @name MSTDAT -  */
/*! @{ */

#define I2C_MSTDAT_MSTDAT_MASK                   (0xFFU)
#define I2C_MSTDAT_MSTDAT_SHIFT                  (0U)
#define I2C_MSTDAT_MSTDAT(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_MSTDAT_MSTDAT_SHIFT)) & I2C_MSTDAT_MSTDAT_MASK)
/*! @} */

/*! @name SLVCTL -  */
/*! @{ */

#define I2C_SLVCTL_SLVCONTINUE_MASK              (0x1U)
#define I2C_SLVCTL_SLVCONTINUE_SHIFT             (0U)
#define I2C_SLVCTL_SLVCONTINUE(x)                (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_SLVCONTINUE_SHIFT)) & I2C_SLVCTL_SLVCONTINUE_MASK)

#define I2C_SLVCTL_SLVNACK_MASK                  (0x2U)
#define I2C_SLVCTL_SLVNACK_SHIFT                 (1U)
#define I2C_SLVCTL_SLVNACK(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_SLVNACK_SHIFT)) & I2C_SLVCTL_SLVNACK_MASK)

#define I2C_SLVCTL_SLVDMA_MASK                   (0x8U)
#define I2C_SLVCTL_SLVDMA_SHIFT                  (3U)
#define I2C_SLVCTL_SLVDMA(x)                     (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_SLVDMA_SHIFT)) & I2C_SLVCTL_SLVDMA_MASK)

#define I2C_SLVCTL_AUTOACK_MASK                  (0x100U)
#define I2C_SLVCTL_AUTOACK_SHIFT                 (8U)
#define I2C_SLVCTL_AUTOACK(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_AUTOACK_SHIFT)) & I2C_SLVCTL_AUTOACK_MASK)

#define I2C_SLVCTL_AUTOMATCHREAD_MASK            (0x200U)
#define I2C_SLVCTL_AUTOMATCHREAD_SHIFT           (9U)
#define I2C_SLVCTL_AUTOMATCHREAD(x)              (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_AUTOMATCHREAD_SHIFT)) & I2C_SLVCTL_AUTOMATCHREAD_MASK)

#define I2C_SLVCTL_SLVTXREADY_MASK               (0x400U)
#define I2C_SLVCTL_SLVTXREADY_SHIFT              (10U)
#define I2C_SLVCTL_SLVTXREADY(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVCTL_SLVTXREADY_SHIFT)) & I2C_SLVCTL_SLVTXREADY_MASK)
/*! @} */

/*! @name SLVDAT -  */
/*! @{ */

#define I2C_SLVDAT_SLVTDAT_MASK                  (0xFFU)
#define I2C_SLVDAT_SLVTDAT_SHIFT                 (0U)
#define I2C_SLVDAT_SLVTDAT(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVDAT_SLVTDAT_SHIFT)) & I2C_SLVDAT_SLVTDAT_MASK)
/*! @} */

/*! @name SLVADR -  */
/*! @{ */

#define I2C_SLVADR_SA0DISABLE_MASK               (0x1U)
#define I2C_SLVADR_SA0DISABLE_SHIFT              (0U)
#define I2C_SLVADR_SA0DISABLE(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SA0DISABLE_SHIFT)) & I2C_SLVADR_SA0DISABLE_MASK)

#define I2C_SLVADR_SLVADR0_MASK                  (0xFEU)
#define I2C_SLVADR_SLVADR0_SHIFT                 (1U)
#define I2C_SLVADR_SLVADR0(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SLVADR0_SHIFT)) & I2C_SLVADR_SLVADR0_MASK)

#define I2C_SLVADR_AUTONACK_MASK                 (0x8000U)
#define I2C_SLVADR_AUTONACK_SHIFT                (15U)
#define I2C_SLVADR_AUTONACK(x)                   (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_AUTONACK_SHIFT)) & I2C_SLVADR_AUTONACK_MASK)

#define I2C_SLVADR_SA1DISABLE_MASK               (0x1U)
#define I2C_SLVADR_SA1DISABLE_SHIFT              (0U)
#define I2C_SLVADR_SA1DISABLE(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SA1DISABLE_SHIFT)) & I2C_SLVADR_SA1DISABLE_MASK)

#define I2C_SLVADR_SLVADR1_MASK                  (0xFEU)
#define I2C_SLVADR_SLVADR1_SHIFT                 (1U)
#define I2C_SLVADR_SLVADR1(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SLVADR1_SHIFT)) & I2C_SLVADR_SLVADR1_MASK)

#define I2C_SLVADR_SA2DISABLE_MASK               (0x1U)
#define I2C_SLVADR_SA2DISABLE_SHIFT              (0U)
#define I2C_SLVADR_SA2DISABLE(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SA2DISABLE_SHIFT)) & I2C_SLVADR_SA2DISABLE_MASK)

#define I2C_SLVADR_SLVADR2_MASK                  (0xFEU)
#define I2C_SLVADR_SLVADR2_SHIFT                 (1U)
#define I2C_SLVADR_SLVADR2(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SLVADR2_SHIFT)) & I2C_SLVADR_SLVADR2_MASK)

#define I2C_SLVADR_SA3DISABLE_MASK               (0x1U)
#define I2C_SLVADR_SA3DISABLE_SHIFT              (0U)
#define I2C_SLVADR_SA3DISABLE(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SA3DISABLE_SHIFT)) & I2C_SLVADR_SA3DISABLE_MASK)

#define I2C_SLVADR_SLVADR3_MASK                  (0xFEU)
#define I2C_SLVADR_SLVADR3_SHIFT                 (1U)
#define I2C_SLVADR_SLVADR3(x)                    (((uint32_t)(((uint32_t)(x)) << I2C_SLVADR_SLVADR3_SHIFT)) & I2C_SLVADR_SLVADR3_MASK)
/*! @} */

/* The count of I2C_SLVADR */
#define I2C_SLVADR_COUNT                         (4U)

/*! @name SLVQUAL0 -  */
/*! @{ */

#define I2C_SLVQUAL0_QUALMODE0_MASK              (0x1U)
#define I2C_SLVQUAL0_QUALMODE0_SHIFT             (0U)
#define I2C_SLVQUAL0_QUALMODE0(x)                (((uint32_t)(((uint32_t)(x)) << I2C_SLVQUAL0_QUALMODE0_SHIFT)) & I2C_SLVQUAL0_QUALMODE0_MASK)

#define I2C_SLVQUAL0_SLVQUAL0_MASK               (0xFEU)
#define I2C_SLVQUAL0_SLVQUAL0_SHIFT              (1U)
#define I2C_SLVQUAL0_SLVQUAL0(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_SLVQUAL0_SLVQUAL0_SHIFT)) & I2C_SLVQUAL0_SLVQUAL0_MASK)
/*! @} */

/*! @name SLVTXSIZE -  */
/*! @{ */

#define I2C_SLVTXSIZE_I2C_SLVTXSIZE_MASK         (0xFFFFU)
#define I2C_SLVTXSIZE_I2C_SLVTXSIZE_SHIFT        (0U)
#define I2C_SLVTXSIZE_I2C_SLVTXSIZE(x)           (((uint32_t)(((uint32_t)(x)) << I2C_SLVTXSIZE_I2C_SLVTXSIZE_SHIFT)) & I2C_SLVTXSIZE_I2C_SLVTXSIZE_MASK)
/*! @} */

/*! @name MONRXDAT -  */
/*! @{ */

#define I2C_MONRXDAT_MONRXDAT_MASK               (0xFFU)
#define I2C_MONRXDAT_MONRXDAT_SHIFT              (0U)
#define I2C_MONRXDAT_MONRXDAT(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_MONRXDAT_MONRXDAT_SHIFT)) & I2C_MONRXDAT_MONRXDAT_MASK)

#define I2C_MONRXDAT_MONSTART_MASK               (0x100U)
#define I2C_MONRXDAT_MONSTART_SHIFT              (8U)
#define I2C_MONRXDAT_MONSTART(x)                 (((uint32_t)(((uint32_t)(x)) << I2C_MONRXDAT_MONSTART_SHIFT)) & I2C_MONRXDAT_MONSTART_MASK)

#define I2C_MONRXDAT_MONRESTART_MASK             (0x200U)
#define I2C_MONRXDAT_MONRESTART_SHIFT            (9U)
#define I2C_MONRXDAT_MONRESTART(x)               (((uint32_t)(((uint32_t)(x)) << I2C_MONRXDAT_MONRESTART_SHIFT)) & I2C_MONRXDAT_MONRESTART_MASK)

#define I2C_MONRXDAT_MONNACK_MASK                (0x400U)
#define I2C_MONRXDAT_MONNACK_SHIFT               (10U)
#define I2C_MONRXDAT_MONNACK(x)                  (((uint32_t)(((uint32_t)(x)) << I2C_MONRXDAT_MONNACK_SHIFT)) & I2C_MONRXDAT_MONNACK_MASK)
/*! @} */

/*! @name ID -  */
/*! @{ */

#define I2C_ID_SIZE_MASK                         (0xFFU)
#define I2C_ID_SIZE_SHIFT                        (0U)
#define I2C_ID_SIZE(x)                           (((uint32_t)(((uint32_t)(x)) << I2C_ID_SIZE_SHIFT)) & I2C_ID_SIZE_MASK)

#define I2C_ID_MINOR_REV_MASK                    (0xF00U)
#define I2C_ID_MINOR_REV_SHIFT                   (8U)
#define I2C_ID_MINOR_REV(x)                      (((uint32_t)(((uint32_t)(x)) << I2C_ID_MINOR_REV_SHIFT)) & I2C_ID_MINOR_REV_MASK)

#define I2C_ID_ID_MASK                           (0xFFFFF000U)
#define I2C_ID_ID_SHIFT                          (12U)
#define I2C_ID_ID(x)                             (((uint32_t)(((uint32_t)(x)) << I2C_ID_ID_SHIFT)) & I2C_ID_ID_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group I2C_Register_Masks */


/* I2C - Peripheral instance base addresses */
/** Peripheral I2C base address */
#define I2C_BASE                                 (0x40002000u)
/** Peripheral I2C base pointer */
#define I2C                                      ((I2C_Type *)I2C_BASE)
/** Array initializer of I2C peripheral base addresses */
#define I2C_BASE_ADDRS                           { I2C_BASE }
/** Array initializer of I2C peripheral base pointers */
#define I2C_BASE_PTRS                            { I2C }
/** Interrupt vectors for the I2C peripheral type */
#define I2C_IRQS                                 { I2C_IRQn }
/* Backward compatibility */
#define I2C_CFG_MSTEN_MASK                       I2C_CFG_MST_EN_MASK
#define I2C_CFG_MSTEN_SHIFT                      I2C_CFG_MST_EN_SHIFT
#define I2C_CFG_MSTEN(x)                         I2C_CFG_MST_EN(x)
#define I2C_CFG_SLVEN_MASK                       I2C_CFG_SLV_EN_MASK
#define I2C_CFG_SLVEN_SHIFT                      I2C_CFG_SLV_EN_SHIFT
#define I2C_CFG_SLVEN(x)                         I2C_CFG_SLV_EN(x)
#define I2C_CFG_MONEN_MASK                       I2C_CFG_MON_EN_MASK
#define I2C_CFG_MONEN_SHIFT                      I2C_CFG_MON_EN_SHIFT
#define I2C_CFG_MONEN(x)                         I2C_CFG_MON_EN(x)
#define I2C_TIMEOUT_TOMIN_MASK                   I2C_TIMEOUT_TIMEOUT_LSB_MASK
#define I2C_TIMEOUT_TOMIN_SHIFT                  I2C_TIMEOUT_TIMEOUT_LSB_SHIFT
#define I2C_TIMEOUT_TOMIN(x)                     I2C_TIMEOUT_TIMEOUT_LSB(x)
#define I2C_TIMEOUT_TO_MASK                      I2C_TIMEOUT_TIMEOUT_MASK
#define I2C_TIMEOUT_TO_SHIFT                     I2C_TIMEOUT_TIMEOUT_SHIFT
#define I2C_TIMEOUT_TO(x)                        I2C_TIMEOUT_TIMEOUT(x)
#define I2C_CLKDIV_DIVVAL_MASK                   I2C_CLKDIV_CLKDIV_MASK
#define I2C_CLKDIV_DIVVAL_SHIFT                  I2C_CLKDIV_CLKDIV_SHIFT
#define I2C_CLKDIV_DIVVAL(x)                     I2C_CLKDIV_CLKDIV(x)
#define I2C_MSTDAT_DATA_MASK                     I2C_MSTDAT_MSTDAT_MASK
#define I2C_MSTDAT_DATA_SHIFT                    I2C_MSTDAT_MSTDAT_SHIFT
#define I2C_MSTDAT_DATA(x)                       I2C_MSTDAT_MSTDAT(x)
#define I2C_MSTTIME_MSTSCLHIGH_MASK              I2C_MSTTIME_MSTCLHIGH_MASK
#define I2C_MSTTIME_MSTSCLHIGH_SHIFT             I2C_MSTTIME_MSTCLHIGH_SHIFT
#define I2C_MSTTIME_MSTSCLHIGH(x)                I2C_MSTTIME_MSTCLHIGH(x)
#define I2C_SLVDAT_DATA_MASK                     I2C_SLVDAT_SLVTDAT_MASK
#define I2C_SLVDAT_DATA_SHIFT                    I2C_SLVDAT_SLVTDAT_SHIFT
#define I2C_SLVDAT_DATA(x)                       I2C_SLVDAT_SLVTDAT(x)
#define I2C_SLVADR_SADISABLE_MASK                I2C_SLVADR_SA0DISABLE_MASK
#define I2C_SLVADR_SADISABLE_SHIFT               I2C_SLVADR_SA0DISABLE_SHIFT
#define I2C_SLVADR_SADISABLE(x)                  I2C_SLVADR_SA0DISABLE(x)
#define I2C_SLVADR_SLVADR_MASK                   I2C_SLVADR_SLVADR0_MASK
#define I2C_SLVADR_SLVADR_SHIFT                  I2C_SLVADR_SLVADR0_SHIFT
#define I2C_SLVADR_SLVADR(x)                     I2C_SLVADR_SLVADR0(x)
#define I2C_ID_APERTURE_MASK                     I2C_ID_SIZE_MASK
#define I2C_ID_APERTURE_SHIFT                    I2C_ID_SIZE_SHIFT
#define I2C_ID_APERTURE(x)                       I2C_ID_SIZE(x)


/*!
 * @}
 */ /* end of group I2C_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- LPUART Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup LPUART_Peripheral_Access_Layer LPUART Peripheral Access Layer
 * @{
 */

/** LPUART - Register Layout Typedef */
typedef struct {
  __I  uint32_t VERID;                             /**< , offset: 0x0 */
  __I  uint32_t PARAM;                             /**< , offset: 0x4 */
  __IO uint32_t GLOBAL;                            /**< , offset: 0x8 */
  __IO uint32_t PINCFG;                            /**< , offset: 0xC */
  __IO uint32_t BAUD;                              /**< , offset: 0x10 */
  __IO uint32_t STAT;                              /**< , offset: 0x14 */
  __IO uint32_t CTRL;                              /**< , offset: 0x18 */
  __IO uint32_t DATA;                              /**< , offset: 0x1C */
  __IO uint32_t MATCH;                             /**< , offset: 0x20 */
  __IO uint32_t MODIR;                             /**< , offset: 0x24 */
  __IO uint32_t FIFO;                              /**< , offset: 0x28 */
  __IO uint32_t WATER;                             /**< , offset: 0x2C */
} LPUART_Type;

/* ----------------------------------------------------------------------------
   -- LPUART Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup LPUART_Register_Masks LPUART Register Masks
 * @{
 */

/*! @name VERID -  */
/*! @{ */

#define LPUART_VERID_FEATURE_MASK                (0xFFFFU)
#define LPUART_VERID_FEATURE_SHIFT               (0U)
#define LPUART_VERID_FEATURE(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_VERID_FEATURE_SHIFT)) & LPUART_VERID_FEATURE_MASK)

#define LPUART_VERID_MINOR_MASK                  (0xFF0000U)
#define LPUART_VERID_MINOR_SHIFT                 (16U)
#define LPUART_VERID_MINOR(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_VERID_MINOR_SHIFT)) & LPUART_VERID_MINOR_MASK)

#define LPUART_VERID_MAJOR_MASK                  (0xFF000000U)
#define LPUART_VERID_MAJOR_SHIFT                 (24U)
#define LPUART_VERID_MAJOR(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_VERID_MAJOR_SHIFT)) & LPUART_VERID_MAJOR_MASK)
/*! @} */

/*! @name PARAM -  */
/*! @{ */

#define LPUART_PARAM_TXFIFO_MASK                 (0xFFU)
#define LPUART_PARAM_TXFIFO_SHIFT                (0U)
#define LPUART_PARAM_TXFIFO(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_PARAM_TXFIFO_SHIFT)) & LPUART_PARAM_TXFIFO_MASK)

#define LPUART_PARAM_RXFIFO_MASK                 (0xFF00U)
#define LPUART_PARAM_RXFIFO_SHIFT                (8U)
#define LPUART_PARAM_RXFIFO(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_PARAM_RXFIFO_SHIFT)) & LPUART_PARAM_RXFIFO_MASK)
/*! @} */

/*! @name GLOBAL -  */
/*! @{ */

#define LPUART_GLOBAL_RST_MASK                   (0x2U)
#define LPUART_GLOBAL_RST_SHIFT                  (1U)
#define LPUART_GLOBAL_RST(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_GLOBAL_RST_SHIFT)) & LPUART_GLOBAL_RST_MASK)
/*! @} */

/*! @name PINCFG -  */
/*! @{ */

#define LPUART_PINCFG_TRGSEL_MASK                (0x3U)
#define LPUART_PINCFG_TRGSEL_SHIFT               (0U)
#define LPUART_PINCFG_TRGSEL(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_PINCFG_TRGSEL_SHIFT)) & LPUART_PINCFG_TRGSEL_MASK)
/*! @} */

/*! @name BAUD -  */
/*! @{ */

#define LPUART_BAUD_SBR_MASK                     (0x1FFFU)
#define LPUART_BAUD_SBR_SHIFT                    (0U)
#define LPUART_BAUD_SBR(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_SBR_SHIFT)) & LPUART_BAUD_SBR_MASK)

#define LPUART_BAUD_SBNS_MASK                    (0x2000U)
#define LPUART_BAUD_SBNS_SHIFT                   (13U)
#define LPUART_BAUD_SBNS(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_SBNS_SHIFT)) & LPUART_BAUD_SBNS_MASK)

#define LPUART_BAUD_RXEDGIE_MASK                 (0x4000U)
#define LPUART_BAUD_RXEDGIE_SHIFT                (14U)
#define LPUART_BAUD_RXEDGIE(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_RXEDGIE_SHIFT)) & LPUART_BAUD_RXEDGIE_MASK)

#define LPUART_BAUD_LBKDIE_MASK                  (0x8000U)
#define LPUART_BAUD_LBKDIE_SHIFT                 (15U)
#define LPUART_BAUD_LBKDIE(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_LBKDIE_SHIFT)) & LPUART_BAUD_LBKDIE_MASK)

#define LPUART_BAUD_RESYNCDIS_MASK               (0x10000U)
#define LPUART_BAUD_RESYNCDIS_SHIFT              (16U)
#define LPUART_BAUD_RESYNCDIS(x)                 (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_RESYNCDIS_SHIFT)) & LPUART_BAUD_RESYNCDIS_MASK)

#define LPUART_BAUD_BOTHEDGE_MASK                (0x20000U)
#define LPUART_BAUD_BOTHEDGE_SHIFT               (17U)
#define LPUART_BAUD_BOTHEDGE(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_BOTHEDGE_SHIFT)) & LPUART_BAUD_BOTHEDGE_MASK)

#define LPUART_BAUD_MATCFG_MASK                  (0xC0000U)
#define LPUART_BAUD_MATCFG_SHIFT                 (18U)
#define LPUART_BAUD_MATCFG(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_MATCFG_SHIFT)) & LPUART_BAUD_MATCFG_MASK)

#define LPUART_BAUD_RIDMAE_MASK                  (0x100000U)
#define LPUART_BAUD_RIDMAE_SHIFT                 (20U)
#define LPUART_BAUD_RIDMAE(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_RIDMAE_SHIFT)) & LPUART_BAUD_RIDMAE_MASK)

#define LPUART_BAUD_RDMAE_MASK                   (0x200000U)
#define LPUART_BAUD_RDMAE_SHIFT                  (21U)
#define LPUART_BAUD_RDMAE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_RDMAE_SHIFT)) & LPUART_BAUD_RDMAE_MASK)

#define LPUART_BAUD_TDMAE_MASK                   (0x800000U)
#define LPUART_BAUD_TDMAE_SHIFT                  (23U)
#define LPUART_BAUD_TDMAE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_TDMAE_SHIFT)) & LPUART_BAUD_TDMAE_MASK)

#define LPUART_BAUD_OSR_MASK                     (0x1F000000U)
#define LPUART_BAUD_OSR_SHIFT                    (24U)
#define LPUART_BAUD_OSR(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_OSR_SHIFT)) & LPUART_BAUD_OSR_MASK)

#define LPUART_BAUD_M10_MASK                     (0x20000000U)
#define LPUART_BAUD_M10_SHIFT                    (29U)
#define LPUART_BAUD_M10(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_M10_SHIFT)) & LPUART_BAUD_M10_MASK)

#define LPUART_BAUD_MAEN2_MASK                   (0x40000000U)
#define LPUART_BAUD_MAEN2_SHIFT                  (30U)
#define LPUART_BAUD_MAEN2(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_MAEN2_SHIFT)) & LPUART_BAUD_MAEN2_MASK)

#define LPUART_BAUD_MAEN1_MASK                   (0x80000000U)
#define LPUART_BAUD_MAEN1_SHIFT                  (31U)
#define LPUART_BAUD_MAEN1(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_BAUD_MAEN1_SHIFT)) & LPUART_BAUD_MAEN1_MASK)
/*! @} */

/*! @name STAT -  */
/*! @{ */

#define LPUART_STAT_MA2F_MASK                    (0x4000U)
#define LPUART_STAT_MA2F_SHIFT                   (14U)
#define LPUART_STAT_MA2F(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_MA2F_SHIFT)) & LPUART_STAT_MA2F_MASK)

#define LPUART_STAT_MA1F_MASK                    (0x8000U)
#define LPUART_STAT_MA1F_SHIFT                   (15U)
#define LPUART_STAT_MA1F(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_MA1F_SHIFT)) & LPUART_STAT_MA1F_MASK)

#define LPUART_STAT_PF_MASK                      (0x10000U)
#define LPUART_STAT_PF_SHIFT                     (16U)
#define LPUART_STAT_PF(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_PF_SHIFT)) & LPUART_STAT_PF_MASK)

#define LPUART_STAT_FE_MASK                      (0x20000U)
#define LPUART_STAT_FE_SHIFT                     (17U)
#define LPUART_STAT_FE(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_FE_SHIFT)) & LPUART_STAT_FE_MASK)

#define LPUART_STAT_NF_MASK                      (0x40000U)
#define LPUART_STAT_NF_SHIFT                     (18U)
#define LPUART_STAT_NF(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_NF_SHIFT)) & LPUART_STAT_NF_MASK)

#define LPUART_STAT_OR_MASK                      (0x80000U)
#define LPUART_STAT_OR_SHIFT                     (19U)
#define LPUART_STAT_OR(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_OR_SHIFT)) & LPUART_STAT_OR_MASK)

#define LPUART_STAT_IDLE_MASK                    (0x100000U)
#define LPUART_STAT_IDLE_SHIFT                   (20U)
#define LPUART_STAT_IDLE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_IDLE_SHIFT)) & LPUART_STAT_IDLE_MASK)

#define LPUART_STAT_RDRF_MASK                    (0x200000U)
#define LPUART_STAT_RDRF_SHIFT                   (21U)
#define LPUART_STAT_RDRF(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_RDRF_SHIFT)) & LPUART_STAT_RDRF_MASK)

#define LPUART_STAT_TC_MASK                      (0x400000U)
#define LPUART_STAT_TC_SHIFT                     (22U)
#define LPUART_STAT_TC(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_TC_SHIFT)) & LPUART_STAT_TC_MASK)

#define LPUART_STAT_TDRE_MASK                    (0x800000U)
#define LPUART_STAT_TDRE_SHIFT                   (23U)
#define LPUART_STAT_TDRE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_TDRE_SHIFT)) & LPUART_STAT_TDRE_MASK)

#define LPUART_STAT_RAF_MASK                     (0x1000000U)
#define LPUART_STAT_RAF_SHIFT                    (24U)
#define LPUART_STAT_RAF(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_RAF_SHIFT)) & LPUART_STAT_RAF_MASK)

#define LPUART_STAT_LBKDE_MASK                   (0x2000000U)
#define LPUART_STAT_LBKDE_SHIFT                  (25U)
#define LPUART_STAT_LBKDE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_LBKDE_SHIFT)) & LPUART_STAT_LBKDE_MASK)

#define LPUART_STAT_BRK13_MASK                   (0x4000000U)
#define LPUART_STAT_BRK13_SHIFT                  (26U)
#define LPUART_STAT_BRK13(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_BRK13_SHIFT)) & LPUART_STAT_BRK13_MASK)

#define LPUART_STAT_RWUID_MASK                   (0x8000000U)
#define LPUART_STAT_RWUID_SHIFT                  (27U)
#define LPUART_STAT_RWUID(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_RWUID_SHIFT)) & LPUART_STAT_RWUID_MASK)

#define LPUART_STAT_RXINV_MASK                   (0x10000000U)
#define LPUART_STAT_RXINV_SHIFT                  (28U)
#define LPUART_STAT_RXINV(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_RXINV_SHIFT)) & LPUART_STAT_RXINV_MASK)

#define LPUART_STAT_MSBF_MASK                    (0x20000000U)
#define LPUART_STAT_MSBF_SHIFT                   (29U)
#define LPUART_STAT_MSBF(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_MSBF_SHIFT)) & LPUART_STAT_MSBF_MASK)

#define LPUART_STAT_RXEDGIF_MASK                 (0x40000000U)
#define LPUART_STAT_RXEDGIF_SHIFT                (30U)
#define LPUART_STAT_RXEDGIF(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_RXEDGIF_SHIFT)) & LPUART_STAT_RXEDGIF_MASK)

#define LPUART_STAT_LBKDIF_MASK                  (0x80000000U)
#define LPUART_STAT_LBKDIF_SHIFT                 (31U)
#define LPUART_STAT_LBKDIF(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_STAT_LBKDIF_SHIFT)) & LPUART_STAT_LBKDIF_MASK)
/*! @} */

/*! @name CTRL -  */
/*! @{ */

#define LPUART_CTRL_PT_MASK                      (0x1U)
#define LPUART_CTRL_PT_SHIFT                     (0U)
#define LPUART_CTRL_PT(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_PT_SHIFT)) & LPUART_CTRL_PT_MASK)

#define LPUART_CTRL_PE_MASK                      (0x2U)
#define LPUART_CTRL_PE_SHIFT                     (1U)
#define LPUART_CTRL_PE(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_PE_SHIFT)) & LPUART_CTRL_PE_MASK)

#define LPUART_CTRL_ILT_MASK                     (0x4U)
#define LPUART_CTRL_ILT_SHIFT                    (2U)
#define LPUART_CTRL_ILT(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_ILT_SHIFT)) & LPUART_CTRL_ILT_MASK)

#define LPUART_CTRL_WAKE_MASK                    (0x8U)
#define LPUART_CTRL_WAKE_SHIFT                   (3U)
#define LPUART_CTRL_WAKE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_WAKE_SHIFT)) & LPUART_CTRL_WAKE_MASK)

#define LPUART_CTRL_M_MASK                       (0x10U)
#define LPUART_CTRL_M_SHIFT                      (4U)
#define LPUART_CTRL_M(x)                         (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_M_SHIFT)) & LPUART_CTRL_M_MASK)

#define LPUART_CTRL_RSRC_MASK                    (0x20U)
#define LPUART_CTRL_RSRC_SHIFT                   (5U)
#define LPUART_CTRL_RSRC(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_RSRC_SHIFT)) & LPUART_CTRL_RSRC_MASK)

#define LPUART_CTRL_DOZEEN_MASK                  (0x40U)
#define LPUART_CTRL_DOZEEN_SHIFT                 (6U)
#define LPUART_CTRL_DOZEEN(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_DOZEEN_SHIFT)) & LPUART_CTRL_DOZEEN_MASK)

#define LPUART_CTRL_LOOPS_MASK                   (0x80U)
#define LPUART_CTRL_LOOPS_SHIFT                  (7U)
#define LPUART_CTRL_LOOPS(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_LOOPS_SHIFT)) & LPUART_CTRL_LOOPS_MASK)

#define LPUART_CTRL_IDLECFG_MASK                 (0x700U)
#define LPUART_CTRL_IDLECFG_SHIFT                (8U)
#define LPUART_CTRL_IDLECFG(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_IDLECFG_SHIFT)) & LPUART_CTRL_IDLECFG_MASK)

#define LPUART_CTRL_M7_MASK                      (0x800U)
#define LPUART_CTRL_M7_SHIFT                     (11U)
#define LPUART_CTRL_M7(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_M7_SHIFT)) & LPUART_CTRL_M7_MASK)

#define LPUART_CTRL_MA2E_MASK                    (0x4000U)
#define LPUART_CTRL_MA2E_SHIFT                   (14U)
#define LPUART_CTRL_MA2E(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_MA2E_SHIFT)) & LPUART_CTRL_MA2E_MASK)

#define LPUART_CTRL_MA1IE_MASK                   (0x8000U)
#define LPUART_CTRL_MA1IE_SHIFT                  (15U)
#define LPUART_CTRL_MA1IE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_MA1IE_SHIFT)) & LPUART_CTRL_MA1IE_MASK)

#define LPUART_CTRL_SBK_MASK                     (0x10000U)
#define LPUART_CTRL_SBK_SHIFT                    (16U)
#define LPUART_CTRL_SBK(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_SBK_SHIFT)) & LPUART_CTRL_SBK_MASK)

#define LPUART_CTRL_RWU_MASK                     (0x20000U)
#define LPUART_CTRL_RWU_SHIFT                    (17U)
#define LPUART_CTRL_RWU(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_RWU_SHIFT)) & LPUART_CTRL_RWU_MASK)

#define LPUART_CTRL_RE_MASK                      (0x40000U)
#define LPUART_CTRL_RE_SHIFT                     (18U)
#define LPUART_CTRL_RE(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_RE_SHIFT)) & LPUART_CTRL_RE_MASK)

#define LPUART_CTRL_TE_MASK                      (0x80000U)
#define LPUART_CTRL_TE_SHIFT                     (19U)
#define LPUART_CTRL_TE(x)                        (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_TE_SHIFT)) & LPUART_CTRL_TE_MASK)

#define LPUART_CTRL_ILIE_MASK                    (0x100000U)
#define LPUART_CTRL_ILIE_SHIFT                   (20U)
#define LPUART_CTRL_ILIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_ILIE_SHIFT)) & LPUART_CTRL_ILIE_MASK)

#define LPUART_CTRL_RIE_MASK                     (0x200000U)
#define LPUART_CTRL_RIE_SHIFT                    (21U)
#define LPUART_CTRL_RIE(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_RIE_SHIFT)) & LPUART_CTRL_RIE_MASK)

#define LPUART_CTRL_TCIE_MASK                    (0x400000U)
#define LPUART_CTRL_TCIE_SHIFT                   (22U)
#define LPUART_CTRL_TCIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_TCIE_SHIFT)) & LPUART_CTRL_TCIE_MASK)

#define LPUART_CTRL_TIE_MASK                     (0x800000U)
#define LPUART_CTRL_TIE_SHIFT                    (23U)
#define LPUART_CTRL_TIE(x)                       (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_TIE_SHIFT)) & LPUART_CTRL_TIE_MASK)

#define LPUART_CTRL_PEIE_MASK                    (0x1000000U)
#define LPUART_CTRL_PEIE_SHIFT                   (24U)
#define LPUART_CTRL_PEIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_PEIE_SHIFT)) & LPUART_CTRL_PEIE_MASK)

#define LPUART_CTRL_FEIE_MASK                    (0x2000000U)
#define LPUART_CTRL_FEIE_SHIFT                   (25U)
#define LPUART_CTRL_FEIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_FEIE_SHIFT)) & LPUART_CTRL_FEIE_MASK)

#define LPUART_CTRL_NEIE_MASK                    (0x4000000U)
#define LPUART_CTRL_NEIE_SHIFT                   (26U)
#define LPUART_CTRL_NEIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_NEIE_SHIFT)) & LPUART_CTRL_NEIE_MASK)

#define LPUART_CTRL_ORIE_MASK                    (0x8000000U)
#define LPUART_CTRL_ORIE_SHIFT                   (27U)
#define LPUART_CTRL_ORIE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_ORIE_SHIFT)) & LPUART_CTRL_ORIE_MASK)

#define LPUART_CTRL_TXINV_MASK                   (0x10000000U)
#define LPUART_CTRL_TXINV_SHIFT                  (28U)
#define LPUART_CTRL_TXINV(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_TXINV_SHIFT)) & LPUART_CTRL_TXINV_MASK)

#define LPUART_CTRL_TXDIR_MASK                   (0x20000000U)
#define LPUART_CTRL_TXDIR_SHIFT                  (29U)
#define LPUART_CTRL_TXDIR(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_TXDIR_SHIFT)) & LPUART_CTRL_TXDIR_MASK)

#define LPUART_CTRL_R9T8_MASK                    (0x40000000U)
#define LPUART_CTRL_R9T8_SHIFT                   (30U)
#define LPUART_CTRL_R9T8(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_R9T8_SHIFT)) & LPUART_CTRL_R9T8_MASK)

#define LPUART_CTRL_R8T9_MASK                    (0x80000000U)
#define LPUART_CTRL_R8T9_SHIFT                   (31U)
#define LPUART_CTRL_R8T9(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_CTRL_R8T9_SHIFT)) & LPUART_CTRL_R8T9_MASK)
/*! @} */

/*! @name DATA -  */
/*! @{ */

#define LPUART_DATA_R0T0_MASK                    (0x1U)
#define LPUART_DATA_R0T0_SHIFT                   (0U)
#define LPUART_DATA_R0T0(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R0T0_SHIFT)) & LPUART_DATA_R0T0_MASK)

#define LPUART_DATA_R1T1_MASK                    (0x2U)
#define LPUART_DATA_R1T1_SHIFT                   (1U)
#define LPUART_DATA_R1T1(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R1T1_SHIFT)) & LPUART_DATA_R1T1_MASK)

#define LPUART_DATA_R2T2_MASK                    (0x4U)
#define LPUART_DATA_R2T2_SHIFT                   (2U)
#define LPUART_DATA_R2T2(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R2T2_SHIFT)) & LPUART_DATA_R2T2_MASK)

#define LPUART_DATA_R3T3_MASK                    (0x8U)
#define LPUART_DATA_R3T3_SHIFT                   (3U)
#define LPUART_DATA_R3T3(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R3T3_SHIFT)) & LPUART_DATA_R3T3_MASK)

#define LPUART_DATA_R4T4_MASK                    (0x10U)
#define LPUART_DATA_R4T4_SHIFT                   (4U)
#define LPUART_DATA_R4T4(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R4T4_SHIFT)) & LPUART_DATA_R4T4_MASK)

#define LPUART_DATA_R5T5_MASK                    (0x20U)
#define LPUART_DATA_R5T5_SHIFT                   (5U)
#define LPUART_DATA_R5T5(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R5T5_SHIFT)) & LPUART_DATA_R5T5_MASK)

#define LPUART_DATA_R6T6_MASK                    (0x40U)
#define LPUART_DATA_R6T6_SHIFT                   (6U)
#define LPUART_DATA_R6T6(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R6T6_SHIFT)) & LPUART_DATA_R6T6_MASK)

#define LPUART_DATA_R7T7_MASK                    (0x80U)
#define LPUART_DATA_R7T7_SHIFT                   (7U)
#define LPUART_DATA_R7T7(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R7T7_SHIFT)) & LPUART_DATA_R7T7_MASK)

#define LPUART_DATA_R8T8_MASK                    (0x100U)
#define LPUART_DATA_R8T8_SHIFT                   (8U)
#define LPUART_DATA_R8T8(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R8T8_SHIFT)) & LPUART_DATA_R8T8_MASK)

#define LPUART_DATA_R9T9_MASK                    (0x200U)
#define LPUART_DATA_R9T9_SHIFT                   (9U)
#define LPUART_DATA_R9T9(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_R9T9_SHIFT)) & LPUART_DATA_R9T9_MASK)

#define LPUART_DATA_IDLINE_MASK                  (0x800U)
#define LPUART_DATA_IDLINE_SHIFT                 (11U)
#define LPUART_DATA_IDLINE(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_IDLINE_SHIFT)) & LPUART_DATA_IDLINE_MASK)

#define LPUART_DATA_RXEMPT_MASK                  (0x1000U)
#define LPUART_DATA_RXEMPT_SHIFT                 (12U)
#define LPUART_DATA_RXEMPT(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_RXEMPT_SHIFT)) & LPUART_DATA_RXEMPT_MASK)

#define LPUART_DATA_FRETSC_MASK                  (0x2000U)
#define LPUART_DATA_FRETSC_SHIFT                 (13U)
#define LPUART_DATA_FRETSC(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_FRETSC_SHIFT)) & LPUART_DATA_FRETSC_MASK)

#define LPUART_DATA_PARITYE_MASK                 (0x4000U)
#define LPUART_DATA_PARITYE_SHIFT                (14U)
#define LPUART_DATA_PARITYE(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_PARITYE_SHIFT)) & LPUART_DATA_PARITYE_MASK)

#define LPUART_DATA_NOISY_MASK                   (0x8000U)
#define LPUART_DATA_NOISY_SHIFT                  (15U)
#define LPUART_DATA_NOISY(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_DATA_NOISY_SHIFT)) & LPUART_DATA_NOISY_MASK)
/*! @} */

/*! @name MATCH -  */
/*! @{ */

#define LPUART_MATCH_MA1_MASK                    (0x3FFU)
#define LPUART_MATCH_MA1_SHIFT                   (0U)
#define LPUART_MATCH_MA1(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_MATCH_MA1_SHIFT)) & LPUART_MATCH_MA1_MASK)

#define LPUART_MATCH_MA2_MASK                    (0x3FF0000U)
#define LPUART_MATCH_MA2_SHIFT                   (16U)
#define LPUART_MATCH_MA2(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_MATCH_MA2_SHIFT)) & LPUART_MATCH_MA2_MASK)
/*! @} */

/*! @name MODIR -  */
/*! @{ */

#define LPUART_MODIR_TXCTSE_MASK                 (0x1U)
#define LPUART_MODIR_TXCTSE_SHIFT                (0U)
#define LPUART_MODIR_TXCTSE(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TXCTSE_SHIFT)) & LPUART_MODIR_TXCTSE_MASK)

#define LPUART_MODIR_TXRTSE_MASK                 (0x2U)
#define LPUART_MODIR_TXRTSE_SHIFT                (1U)
#define LPUART_MODIR_TXRTSE(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TXRTSE_SHIFT)) & LPUART_MODIR_TXRTSE_MASK)

#define LPUART_MODIR_TXRTSPOL_MASK               (0x4U)
#define LPUART_MODIR_TXRTSPOL_SHIFT              (2U)
#define LPUART_MODIR_TXRTSPOL(x)                 (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TXRTSPOL_SHIFT)) & LPUART_MODIR_TXRTSPOL_MASK)

#define LPUART_MODIR_RXRTSE_MASK                 (0x8U)
#define LPUART_MODIR_RXRTSE_SHIFT                (3U)
#define LPUART_MODIR_RXRTSE(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_RXRTSE_SHIFT)) & LPUART_MODIR_RXRTSE_MASK)

#define LPUART_MODIR_TXCTSC_MASK                 (0x10U)
#define LPUART_MODIR_TXCTSC_SHIFT                (4U)
#define LPUART_MODIR_TXCTSC(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TXCTSC_SHIFT)) & LPUART_MODIR_TXCTSC_MASK)

#define LPUART_MODIR_TXCTSSRC_MASK               (0x20U)
#define LPUART_MODIR_TXCTSSRC_SHIFT              (5U)
#define LPUART_MODIR_TXCTSSRC(x)                 (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TXCTSSRC_SHIFT)) & LPUART_MODIR_TXCTSSRC_MASK)

#define LPUART_MODIR_RTSWATER_MASK               (0x300U)
#define LPUART_MODIR_RTSWATER_SHIFT              (8U)
#define LPUART_MODIR_RTSWATER(x)                 (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_RTSWATER_SHIFT)) & LPUART_MODIR_RTSWATER_MASK)

#define LPUART_MODIR_TNP_MASK                    (0x30000U)
#define LPUART_MODIR_TNP_SHIFT                   (16U)
#define LPUART_MODIR_TNP(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_TNP_SHIFT)) & LPUART_MODIR_TNP_MASK)

#define LPUART_MODIR_IREN_MASK                   (0x40000U)
#define LPUART_MODIR_IREN_SHIFT                  (18U)
#define LPUART_MODIR_IREN(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_MODIR_IREN_SHIFT)) & LPUART_MODIR_IREN_MASK)
/*! @} */

/*! @name FIFO -  */
/*! @{ */

#define LPUART_FIFO_RXFIFOSIZE_MASK              (0x7U)
#define LPUART_FIFO_RXFIFOSIZE_SHIFT             (0U)
#define LPUART_FIFO_RXFIFOSIZE(x)                (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXFIFOSIZE_SHIFT)) & LPUART_FIFO_RXFIFOSIZE_MASK)

#define LPUART_FIFO_RXFE_MASK                    (0x8U)
#define LPUART_FIFO_RXFE_SHIFT                   (3U)
#define LPUART_FIFO_RXFE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXFE_SHIFT)) & LPUART_FIFO_RXFE_MASK)

#define LPUART_FIFO_TXFIFOSIZE_MASK              (0x70U)
#define LPUART_FIFO_TXFIFOSIZE_SHIFT             (4U)
#define LPUART_FIFO_TXFIFOSIZE(x)                (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXFIFOSIZE_SHIFT)) & LPUART_FIFO_TXFIFOSIZE_MASK)

#define LPUART_FIFO_TXFE_MASK                    (0x80U)
#define LPUART_FIFO_TXFE_SHIFT                   (7U)
#define LPUART_FIFO_TXFE(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXFE_SHIFT)) & LPUART_FIFO_TXFE_MASK)

#define LPUART_FIFO_RXUFE_MASK                   (0x100U)
#define LPUART_FIFO_RXUFE_SHIFT                  (8U)
#define LPUART_FIFO_RXUFE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXUFE_SHIFT)) & LPUART_FIFO_RXUFE_MASK)

#define LPUART_FIFO_TXOFE_MASK                   (0x200U)
#define LPUART_FIFO_TXOFE_SHIFT                  (9U)
#define LPUART_FIFO_TXOFE(x)                     (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXOFE_SHIFT)) & LPUART_FIFO_TXOFE_MASK)

#define LPUART_FIFO_RXIDEN_MASK                  (0x1C00U)
#define LPUART_FIFO_RXIDEN_SHIFT                 (10U)
#define LPUART_FIFO_RXIDEN(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXIDEN_SHIFT)) & LPUART_FIFO_RXIDEN_MASK)

#define LPUART_FIFO_RXFLUSH_MASK                 (0x4000U)
#define LPUART_FIFO_RXFLUSH_SHIFT                (14U)
#define LPUART_FIFO_RXFLUSH(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXFLUSH_SHIFT)) & LPUART_FIFO_RXFLUSH_MASK)

#define LPUART_FIFO_TXFLUSH_MASK                 (0x8000U)
#define LPUART_FIFO_TXFLUSH_SHIFT                (15U)
#define LPUART_FIFO_TXFLUSH(x)                   (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXFLUSH_SHIFT)) & LPUART_FIFO_TXFLUSH_MASK)

#define LPUART_FIFO_RXUF_MASK                    (0x10000U)
#define LPUART_FIFO_RXUF_SHIFT                   (16U)
#define LPUART_FIFO_RXUF(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXUF_SHIFT)) & LPUART_FIFO_RXUF_MASK)

#define LPUART_FIFO_TXOF_MASK                    (0x20000U)
#define LPUART_FIFO_TXOF_SHIFT                   (17U)
#define LPUART_FIFO_TXOF(x)                      (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXOF_SHIFT)) & LPUART_FIFO_TXOF_MASK)

#define LPUART_FIFO_RXEMPT_MASK                  (0x400000U)
#define LPUART_FIFO_RXEMPT_SHIFT                 (22U)
#define LPUART_FIFO_RXEMPT(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_RXEMPT_SHIFT)) & LPUART_FIFO_RXEMPT_MASK)

#define LPUART_FIFO_TXEMPT_MASK                  (0x800000U)
#define LPUART_FIFO_TXEMPT_SHIFT                 (23U)
#define LPUART_FIFO_TXEMPT(x)                    (((uint32_t)(((uint32_t)(x)) << LPUART_FIFO_TXEMPT_SHIFT)) & LPUART_FIFO_TXEMPT_MASK)
/*! @} */

/*! @name WATER -  */
/*! @{ */

#define LPUART_WATER_TXWATER_MASK                (0x3U)
#define LPUART_WATER_TXWATER_SHIFT               (0U)
#define LPUART_WATER_TXWATER(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_WATER_TXWATER_SHIFT)) & LPUART_WATER_TXWATER_MASK)

#define LPUART_WATER_TXCOUNT_MASK                (0x700U)
#define LPUART_WATER_TXCOUNT_SHIFT               (8U)
#define LPUART_WATER_TXCOUNT(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_WATER_TXCOUNT_SHIFT)) & LPUART_WATER_TXCOUNT_MASK)

#define LPUART_WATER_RXWATER_MASK                (0x30000U)
#define LPUART_WATER_RXWATER_SHIFT               (16U)
#define LPUART_WATER_RXWATER(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_WATER_RXWATER_SHIFT)) & LPUART_WATER_RXWATER_MASK)

#define LPUART_WATER_RXCOUNT_MASK                (0x7000000U)
#define LPUART_WATER_RXCOUNT_SHIFT               (24U)
#define LPUART_WATER_RXCOUNT(x)                  (((uint32_t)(((uint32_t)(x)) << LPUART_WATER_RXCOUNT_SHIFT)) & LPUART_WATER_RXCOUNT_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group LPUART_Register_Masks */


/* LPUART - Peripheral instance base addresses */
/** Peripheral LPUART base address */
#define LPUART_BASE                              (0x4000B000u)
/** Peripheral LPUART base pointer */
#define LPUART                                   ((LPUART_Type *)LPUART_BASE)
/** Array initializer of LPUART peripheral base addresses */
#define LPUART_BASE_ADDRS                        { LPUART_BASE }
/** Array initializer of LPUART peripheral base pointers */
#define LPUART_BASE_PTRS                         { LPUART }
/** Interrupt vectors for the LPUART peripheral type */
#define LPUART_RX_IRQS                           { LPUART_RX_IRQn }
#define LPUART_TX_IRQS                           { LPUART_TX_IRQn }

/*!
 * @}
 */ /* end of group LPUART_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- SCT Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SCT_Peripheral_Access_Layer SCT Peripheral Access Layer
 * @{
 */

/** SCT - Register Layout Typedef */
typedef struct {
  __IO uint32_t CONFIG;                            /**< SCT configuration register, offset: 0x0 */
  union {                                          /* offset: 0x4 */
    struct {                                         /* offset: 0x4 */
      __IO uint16_t CTRLL;                             /**< SCT_CTRLL register, offset: 0x4 */
      __IO uint16_t CTRLH;                             /**< SCT_CTRLH register, offset: 0x6 */
    } CTRL_ACCESS16BIT;
    __IO uint32_t CTRL;                              /**< SCT control register, offset: 0x4 */
  };
  union {                                          /* offset: 0x8 */
    struct {                                         /* offset: 0x8 */
      __IO uint16_t LIMITL;                            /**< SCT_LIMITL register, offset: 0x8 */
      __IO uint16_t LIMITH;                            /**< SCT_LIMITH register, offset: 0xA */
    } LIMIT_ACCESS16BIT;
    __IO uint32_t LIMIT;                             /**< SCT limit event select register, offset: 0x8 */
  };
  union {                                          /* offset: 0xC */
    struct {                                         /* offset: 0xC */
      __IO uint16_t HALTL;                             /**< SCT_HALTL register, offset: 0xC */
      __IO uint16_t HALTH;                             /**< SCT_HALTH register, offset: 0xE */
    } HALT_ACCESS16BIT;
    __IO uint32_t HALT;                              /**< SCT halt event select register, offset: 0xC */
  };
  union {                                          /* offset: 0x10 */
    struct {                                         /* offset: 0x10 */
      __IO uint16_t STOPL;                             /**< SCT_STOPL register, offset: 0x10 */
      __IO uint16_t STOPH;                             /**< SCT_STOPH register, offset: 0x12 */
    } STOP_ACCESS16BIT;
    __IO uint32_t STOP;                              /**< SCT stop event select register, offset: 0x10 */
  };
  union {                                          /* offset: 0x14 */
    struct {                                         /* offset: 0x14 */
      __IO uint16_t STARTL;                            /**< SCT_STARTL register, offset: 0x14 */
      __IO uint16_t STARTH;                            /**< SCT_STARTH register, offset: 0x16 */
    } START_ACCESS16BIT;
    __IO uint32_t START;                             /**< SCT start event select register, offset: 0x14 */
  };
       uint8_t RESERVED_0[40];
  union {                                          /* offset: 0x40 */
    struct {                                         /* offset: 0x40 */
      __IO uint16_t COUNTL;                            /**< SCT_COUNTL register, offset: 0x40 */
      __IO uint16_t COUNTH;                            /**< SCT_COUNTH register, offset: 0x42 */
    } COUNT_ACCESS16BIT;
    __IO uint32_t COUNT;                             /**< SCT counter register, offset: 0x40 */
  };
  union {                                          /* offset: 0x44 */
    struct {                                         /* offset: 0x44 */
      __IO uint16_t STATEL;                            /**< SCT_STATEL register, offset: 0x44 */
      __IO uint16_t STATEH;                            /**< SCT_STATEH register, offset: 0x46 */
    } STATE_ACCESS16BIT;
    __IO uint32_t STATE;                             /**< SCT state register, offset: 0x44 */
  };
  __I  uint32_t INPUT;                             /**< SCT input register, offset: 0x48 */
  union {                                          /* offset: 0x4C */
    struct {                                         /* offset: 0x4C */
      __IO uint16_t REGMODEL;                          /**< SCT_REGMODEL register, offset: 0x4C */
      __IO uint16_t REGMODEH;                          /**< SCT_REGMODEH register, offset: 0x4E */
    } REGMODE_ACCESS16BIT;
    __IO uint32_t REGMODE;                           /**< SCT match/capture mode register, offset: 0x4C */
  };
  __IO uint32_t OUTPUT;                            /**< SCT output register, offset: 0x50 */
  __IO uint32_t OUTPUTDIRCTRL;                     /**< SCT output counter direction control register, offset: 0x54 */
  __IO uint32_t RES;                               /**< SCT conflict resolution register, offset: 0x58 */
  __IO uint32_t DMAREQ0;                           /**< SCT DMA request 0 register, offset: 0x5C */
  __IO uint32_t DMAREQ1;                           /**< SCT DMA request 1 register, offset: 0x60 */
       uint8_t RESERVED_1[140];
  __IO uint32_t EVEN;                              /**< SCT event interrupt enable register, offset: 0xF0 */
  __IO uint32_t EVFLAG;                            /**< SCT event flag register, offset: 0xF4 */
  __IO uint32_t CONEN;                             /**< SCT conflict interrupt enable register, offset: 0xF8 */
  __IO uint32_t CONFLAG;                           /**< SCT conflict flag register, offset: 0xFC */
  union {                                          /* offset: 0x100 */
    union {                                          /* offset: 0x100, array step: 0x4 */
      struct {                                         /* offset: 0x100, array step: 0x4 */
        __IO uint16_t CAPL;                              /**< SCT_CAPL register, array offset: 0x100, array step: 0x4 */
        __IO uint16_t CAPH;                              /**< SCT_CAPH register, array offset: 0x102, array step: 0x4 */
      } CAP_ACCESS16BIT[10];
      __IO uint32_t CAP[10];                           /**< SCT capture register of capture channel, array offset: 0x100, array step: 0x4 */
    };
    union {                                          /* offset: 0x100, array step: 0x4 */
      struct {                                         /* offset: 0x100, array step: 0x4 */
        __IO uint16_t MATCHL;                            /**< SCT_MATCHL register, array offset: 0x100, array step: 0x4 */
        __IO uint16_t MATCHH;                            /**< SCT_MATCHH register, array offset: 0x102, array step: 0x4 */
      } MATCH_ACCESS16BIT[10];
      __IO uint32_t MATCH[10];                         /**< SCT match value register of match channels, array offset: 0x100, array step: 0x4 */
    };
  };
       uint8_t RESERVED_2[216];
  union {                                          /* offset: 0x200 */
    union {                                          /* offset: 0x200, array step: 0x4 */
      struct {                                         /* offset: 0x200, array step: 0x4 */
        __IO uint16_t CAPCTRLL;                          /**< SCT_CAPCTRLL register, array offset: 0x200, array step: 0x4 */
        __IO uint16_t CAPCTRLH;                          /**< SCT_CAPCTRLH register, array offset: 0x202, array step: 0x4 */
      } CAPCTRL_ACCESS16BIT[10];
      __IO uint32_t CAPCTRL[10];                       /**< SCT capture control register, array offset: 0x200, array step: 0x4 */
    };
    union {                                          /* offset: 0x200, array step: 0x4 */
      struct {                                         /* offset: 0x200, array step: 0x4 */
        __IO uint16_t MATCHRELL;                         /**< SCT_MATCHRELL register, array offset: 0x200, array step: 0x4 */
        __IO uint16_t MATCHRELH;                         /**< SCT_MATCHRELH register, array offset: 0x202, array step: 0x4 */
      } MATCHREL_ACCESS16BIT[10];
      __IO uint32_t MATCHREL[10];                      /**< SCT match reload value register, array offset: 0x200, array step: 0x4 */
    };
  };
       uint8_t RESERVED_3[216];
  struct {                                         /* offset: 0x300, array step: 0x8 */
    __IO uint32_t STATE;                             /**< SCT event state register 0, array offset: 0x300, array step: 0x8 */
    __IO uint32_t CTRL;                              /**< SCT event control register 0, array offset: 0x304, array step: 0x8 */
  } EV[10];
       uint8_t RESERVED_4[432];
  struct {                                         /* offset: 0x500, array step: 0x8 */
    __IO uint32_t SET;                               /**< SCT output 0 set register, array offset: 0x500, array step: 0x8 */
    __IO uint32_t CLR;                               /**< SCT output 0 clear register, array offset: 0x504, array step: 0x8 */
  } OUT[10];
} SCT_Type;

/* ----------------------------------------------------------------------------
   -- SCT Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SCT_Register_Masks SCT Register Masks
 * @{
 */

/*! @name CONFIG - SCT configuration register */
/*! @{ */

#define SCT_CONFIG_UNIFY_MASK                    (0x1U)
#define SCT_CONFIG_UNIFY_SHIFT                   (0U)
/*! UNIFY - SCT operation
 *  0b0..The SCT operates as two 16-bit counters named COUNTER_L and COUNTER_H.
 *  0b1..The SCT operates as a unified 32-bit counter.
 */
#define SCT_CONFIG_UNIFY(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_UNIFY_SHIFT)) & SCT_CONFIG_UNIFY_MASK)

#define SCT_CONFIG_CLKMODE_MASK                  (0x6U)
#define SCT_CONFIG_CLKMODE_SHIFT                 (1U)
/*! CLKMODE - SCT clock mode
 *  0b00..System Clock Mode. The system clock clocks the entire SCT module including the counter(s) and counter prescalers.
 *  0b01..Sampled System Clock Mode. The system clock clocks the SCT module, but the counter and prescalers are
 *        only enabled to count when the designated edge is detected on the input selected by the CKSEL field. The
 *        minimum pulse width on the selected clock-gate input is 1 bus clock period. This mode is the
 *        high-performance, sampled-clock mode.
 *  0b10..SCT Input Clock Mode. The input/edge selected by the CKSEL field clocks the SCT module, including the
 *        counters and prescalers, after first being synchronized to the system clock. The minimum pulse width on the
 *        clock input is 1 bus clock period. This mode is the low-power, sampled-clock mode.
 *  0b11..Asynchronous Mode. The entire SCT module is clocked directly by the input/edge selected by the CKSEL
 *        field. In this mode, the SCT outputs are switched synchronously to the SCT input clock - not the system
 *        clock. The input clock rate must be at least half the system clock rate and can be the same or faster than
 *        the system clock.
 */
#define SCT_CONFIG_CLKMODE(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_CLKMODE_SHIFT)) & SCT_CONFIG_CLKMODE_MASK)

#define SCT_CONFIG_CKSEL_MASK                    (0x78U)
#define SCT_CONFIG_CKSEL_SHIFT                   (3U)
/*! CKSEL - SCT clock select. The specific functionality of the designated input/edge is dependent
 *    on the CLKMODE bit selection in this register.
 *  0b0000..Rising edges on input 0.
 *  0b0001..Falling edges on input 0.
 *  0b0010..Rising edges on input 1.
 *  0b0011..Falling edges on input 1.
 *  0b0100..Rising edges on input 2.
 *  0b0101..Falling edges on input 2.
 *  0b0110..Rising edges on input 3.
 *  0b0111..Falling edges on input 3.
 *  0b1000..Rising edges on input 4.
 *  0b1001..Falling edges on input 4.
 *  0b1010..Rising edges on input 5.
 *  0b1011..Falling edges on input 5.
 *  0b1100..Rising edges on input 6.
 *  0b1101..Falling edges on input 6.
 *  0b1110..Rising edges on input 7.
 *  0b1111..Falling edges on input 7.
 */
#define SCT_CONFIG_CKSEL(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_CKSEL_SHIFT)) & SCT_CONFIG_CKSEL_MASK)

#define SCT_CONFIG_NORELOAD_L_MASK               (0x80U)
#define SCT_CONFIG_NORELOAD_L_SHIFT              (7U)
/*! NORELOAD_L - A 1 in this bit prevents the lower match registers from being reloaded from their
 *    respective reload registers. Setting this bit eliminates the need to write to the reload
 *    registers MATCHREL if the match values are fixed. Software can write to set or clear this bit at any
 *    time. This bit applies to both the higher and lower registers when the UNIFY bit is set.
 */
#define SCT_CONFIG_NORELOAD_L(x)                 (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_NORELOAD_L_SHIFT)) & SCT_CONFIG_NORELOAD_L_MASK)

#define SCT_CONFIG_NORELOAD_H_MASK               (0x100U)
#define SCT_CONFIG_NORELOAD_H_SHIFT              (8U)
/*! NORELOAD_H - A 1 in this bit prevents the higher match registers from being reloaded from their
 *    respective reload registers. Setting this bit eliminates the need to write to the reload
 *    registers MATCHREL if the match values are fixed. Software can write to set or clear this bit at
 *    any time. This bit is not used when the UNIFY bit is set.
 */
#define SCT_CONFIG_NORELOAD_H(x)                 (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_NORELOAD_H_SHIFT)) & SCT_CONFIG_NORELOAD_H_MASK)

#define SCT_CONFIG_INSYNC_MASK                   (0x1E00U)
#define SCT_CONFIG_INSYNC_SHIFT                  (9U)
/*! INSYNC - Synchronization for input N (bit 9 = input 0, bit 10 = input 1,, bit 12 = input 3); all
 *    other bits are reserved. A 1 in one of these bits subjects the corresponding input to
 *    synchronization to the SCT clock, before it is used to create an event. If an input is known to
 *    already be synchronous to the SCT clock, this bit may be set to 0 for faster input response. (Note:
 *    The SCT clock is the system clock for CKMODEs 0-2. It is the selected, asynchronous SCT input
 *    clock for CKMODE3). Note that the INSYNC field only affects inputs used for event generation.
 *    It does not apply to the clock input specified in the CKSEL field.
 */
#define SCT_CONFIG_INSYNC(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_INSYNC_SHIFT)) & SCT_CONFIG_INSYNC_MASK)

#define SCT_CONFIG_AUTOLIMIT_L_MASK              (0x20000U)
#define SCT_CONFIG_AUTOLIMIT_L_SHIFT             (17U)
/*! AUTOLIMIT_L - A one in this bit causes a match on match register 0 to be treated as a de-facto
 *    LIMIT condition without the need to define an associated event. As with any LIMIT event, this
 *    automatic limit causes the counter to be cleared to zero in unidirectional mode or to change
 *    the direction of count in bi-directional mode. Software can write to set or clear this bit at
 *    any time. This bit applies to both the higher and lower registers when the UNIFY bit is set.
 */
#define SCT_CONFIG_AUTOLIMIT_L(x)                (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_AUTOLIMIT_L_SHIFT)) & SCT_CONFIG_AUTOLIMIT_L_MASK)

#define SCT_CONFIG_AUTOLIMIT_H_MASK              (0x40000U)
#define SCT_CONFIG_AUTOLIMIT_H_SHIFT             (18U)
/*! AUTOLIMIT_H - A one in this bit will cause a match on match register 0 to be treated as a
 *    de-facto LIMIT condition without the need to define an associated event. As with any LIMIT event,
 *    this automatic limit causes the counter to be cleared to zero in unidirectional mode or to
 *    change the direction of count in bi-directional mode. Software can write to set or clear this bit
 *    at any time. This bit is not used when the UNIFY bit is set.
 */
#define SCT_CONFIG_AUTOLIMIT_H(x)                (((uint32_t)(((uint32_t)(x)) << SCT_CONFIG_AUTOLIMIT_H_SHIFT)) & SCT_CONFIG_AUTOLIMIT_H_MASK)
/*! @} */

/*! @name CTRLL - SCT_CTRLL register */
/*! @{ */

#define SCT_CTRLL_DOWN_L_MASK                    (0x1U)
#define SCT_CTRLL_DOWN_L_SHIFT                   (0U)
/*! DOWN_L - This bit is 1 when the L or unified counter is counting down. Hardware sets this bit
 *    when the counter is counting up, counter limit occurs, and BIDIR = 1.Hardware clears this bit
 *    when the counter is counting down and a limit condition occurs or when the counter reaches 0.
 */
#define SCT_CTRLL_DOWN_L(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_DOWN_L_SHIFT)) & SCT_CTRLL_DOWN_L_MASK)

#define SCT_CTRLL_STOP_L_MASK                    (0x2U)
#define SCT_CTRLL_STOP_L_SHIFT                   (1U)
/*! STOP_L - When this bit is 1 and HALT is 0, the L or unified counter does not run, but I/O events
 *    related to the counter can occur. If a designated start event occurs, this bit is cleared and
 *    counting resumes.
 */
#define SCT_CTRLL_STOP_L(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_STOP_L_SHIFT)) & SCT_CTRLL_STOP_L_MASK)

#define SCT_CTRLL_HALT_L_MASK                    (0x4U)
#define SCT_CTRLL_HALT_L_SHIFT                   (2U)
/*! HALT_L - When this bit is 1, the L or unified counter does not run and no events can occur. A
 *    reset sets this bit. When the HALT_L bit is one, the STOP_L bit is cleared. It is possible to
 *    remove the halt condition while keeping the SCT in the stop condition (not running) with a
 *    single write to this register to simultaneously clear the HALT bit and set the STOP bit. Once set,
 *    only software can clear this bit to restore counter operation. This bit is set on reset.
 */
#define SCT_CTRLL_HALT_L(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_HALT_L_SHIFT)) & SCT_CTRLL_HALT_L_MASK)

#define SCT_CTRLL_CLRCTR_L_MASK                  (0x8U)
#define SCT_CTRLL_CLRCTR_L_SHIFT                 (3U)
/*! CLRCTR_L - Writing a 1 to this bit clears the L or unified counter. This bit always reads as 0.
 */
#define SCT_CTRLL_CLRCTR_L(x)                    (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_CLRCTR_L_SHIFT)) & SCT_CTRLL_CLRCTR_L_MASK)

#define SCT_CTRLL_BIDIR_L_MASK                   (0x10U)
#define SCT_CTRLL_BIDIR_L_SHIFT                  (4U)
/*! BIDIR_L - L or unified counter direction select
 *  0b0..Up. The counter counts up to a limit condition, then is cleared to zero.
 *  0b1..Up-down. The counter counts up to a limit, then counts down to a limit condition or to 0.
 */
#define SCT_CTRLL_BIDIR_L(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_BIDIR_L_SHIFT)) & SCT_CTRLL_BIDIR_L_MASK)

#define SCT_CTRLL_PRE_L_MASK                     (0x1FE0U)
#define SCT_CTRLL_PRE_L_SHIFT                    (5U)
/*! PRE_L - Specifies the factor by which the SCT clock is prescaled to produce the L or unified
 *    counter clock. The counter clock is clocked at the rate of the SCT clock divided by PRE_L+1.
 *    Clear the counter (by writing a 1 to the CLRCTR bit) whenever changing the PRE value.
 */
#define SCT_CTRLL_PRE_L(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_CTRLL_PRE_L_SHIFT)) & SCT_CTRLL_PRE_L_MASK)
/*! @} */

/*! @name CTRLH - SCT_CTRLH register */
/*! @{ */

#define SCT_CTRLH_DOWN_H_MASK                    (0x1U)
#define SCT_CTRLH_DOWN_H_SHIFT                   (0U)
/*! DOWN_H - This bit is 1 when the H counter is counting down. Hardware sets this bit when the
 *    counter is counting, a counter limit condition occurs, and BIDIR is 1. Hardware clears this bit
 *    when the counter is counting down and a limit condition occurs or when the counter reaches 0.
 */
#define SCT_CTRLH_DOWN_H(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_DOWN_H_SHIFT)) & SCT_CTRLH_DOWN_H_MASK)

#define SCT_CTRLH_STOP_H_MASK                    (0x2U)
#define SCT_CTRLH_STOP_H_SHIFT                   (1U)
/*! STOP_H - When this bit is 1 and HALT is 0, the H counter does not, run but I/O events related to
 *    the counter can occur. If such an event matches the mask in the Start register, this bit is
 *    cleared and counting resumes.
 */
#define SCT_CTRLH_STOP_H(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_STOP_H_SHIFT)) & SCT_CTRLH_STOP_H_MASK)

#define SCT_CTRLH_HALT_H_MASK                    (0x4U)
#define SCT_CTRLH_HALT_H_SHIFT                   (2U)
/*! HALT_H - When this bit is 1, the H counter does not run and no events can occur. A reset sets
 *    this bit. When the HALT_H bit is one, the STOP_H bit is cleared. It is possible to remove the
 *    halt condition while keeping the SCT in the stop condition (not running) with a single write to
 *    this register to simultaneously clear the HALT bit and set the STOP bit. Once set, this bit
 *    can only be cleared by software to restore counter operation. This bit is set on reset.
 */
#define SCT_CTRLH_HALT_H(x)                      (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_HALT_H_SHIFT)) & SCT_CTRLH_HALT_H_MASK)

#define SCT_CTRLH_CLRCTR_H_MASK                  (0x8U)
#define SCT_CTRLH_CLRCTR_H_SHIFT                 (3U)
/*! CLRCTR_H - Writing a 1 to this bit clears the H counter. This bit always reads as 0.
 */
#define SCT_CTRLH_CLRCTR_H(x)                    (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_CLRCTR_H_SHIFT)) & SCT_CTRLH_CLRCTR_H_MASK)

#define SCT_CTRLH_BIDIR_H_MASK                   (0x10U)
#define SCT_CTRLH_BIDIR_H_SHIFT                  (4U)
/*! BIDIR_H - Direction select
 *  0b0..The H counter counts up to its limit condition, then is cleared to zero.
 *  0b1..The H counter counts up to its limit, then counts down to a limit condition or to 0.
 */
#define SCT_CTRLH_BIDIR_H(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_BIDIR_H_SHIFT)) & SCT_CTRLH_BIDIR_H_MASK)

#define SCT_CTRLH_PRE_H_MASK                     (0x1FE0U)
#define SCT_CTRLH_PRE_H_SHIFT                    (5U)
/*! PRE_H - Specifies the factor by which the SCT clock is prescaled to produce the H counter clock.
 *    The counter clock is clocked at the rate of the SCT clock divided by PRELH+1. Clear the
 *    counter (by writing a 1 to the CLRCTR bit) whenever changing the PRE value.
 */
#define SCT_CTRLH_PRE_H(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_CTRLH_PRE_H_SHIFT)) & SCT_CTRLH_PRE_H_MASK)
/*! @} */

/*! @name CTRL - SCT control register */
/*! @{ */

#define SCT_CTRL_DOWN_L_MASK                     (0x1U)
#define SCT_CTRL_DOWN_L_SHIFT                    (0U)
/*! DOWN_L - This bit is 1 when the L or unified counter is counting down. Hardware sets this bit
 *    when the counter is counting up, counter limit occurs, and BIDIR = 1.Hardware clears this bit
 *    when the counter is counting down and a limit condition occurs or when the counter reaches 0.
 */
#define SCT_CTRL_DOWN_L(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_DOWN_L_SHIFT)) & SCT_CTRL_DOWN_L_MASK)

#define SCT_CTRL_STOP_L_MASK                     (0x2U)
#define SCT_CTRL_STOP_L_SHIFT                    (1U)
/*! STOP_L - When this bit is 1 and HALT is 0, the L or unified counter does not run, but I/O events
 *    related to the counter can occur. If a designated start event occurs, this bit is cleared and
 *    counting resumes.
 */
#define SCT_CTRL_STOP_L(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_STOP_L_SHIFT)) & SCT_CTRL_STOP_L_MASK)

#define SCT_CTRL_HALT_L_MASK                     (0x4U)
#define SCT_CTRL_HALT_L_SHIFT                    (2U)
/*! HALT_L - When this bit is 1, the L or unified counter does not run and no events can occur. A
 *    reset sets this bit. When the HALT_L bit is one, the STOP_L bit is cleared. It is possible to
 *    remove the halt condition while keeping the SCT in the stop condition (not running) with a
 *    single write to this register to simultaneously clear the HALT bit and set the STOP bit. Once set,
 *    only software can clear this bit to restore counter operation. This bit is set on reset.
 */
#define SCT_CTRL_HALT_L(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_HALT_L_SHIFT)) & SCT_CTRL_HALT_L_MASK)

#define SCT_CTRL_CLRCTR_L_MASK                   (0x8U)
#define SCT_CTRL_CLRCTR_L_SHIFT                  (3U)
/*! CLRCTR_L - Writing a 1 to this bit clears the L or unified counter. This bit always reads as 0.
 */
#define SCT_CTRL_CLRCTR_L(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_CLRCTR_L_SHIFT)) & SCT_CTRL_CLRCTR_L_MASK)

#define SCT_CTRL_BIDIR_L_MASK                    (0x10U)
#define SCT_CTRL_BIDIR_L_SHIFT                   (4U)
/*! BIDIR_L - L or unified counter direction select
 *  0b0..Up. The counter counts up to a limit condition, then is cleared to zero.
 *  0b1..Up-down. The counter counts up to a limit, then counts down to a limit condition or to 0.
 */
#define SCT_CTRL_BIDIR_L(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_BIDIR_L_SHIFT)) & SCT_CTRL_BIDIR_L_MASK)

#define SCT_CTRL_PRE_L_MASK                      (0x1FE0U)
#define SCT_CTRL_PRE_L_SHIFT                     (5U)
/*! PRE_L - Specifies the factor by which the SCT clock is prescaled to produce the L or unified
 *    counter clock. The counter clock is clocked at the rate of the SCT clock divided by PRE_L+1.
 *    Clear the counter (by writing a 1 to the CLRCTR bit) whenever changing the PRE value.
 */
#define SCT_CTRL_PRE_L(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_PRE_L_SHIFT)) & SCT_CTRL_PRE_L_MASK)

#define SCT_CTRL_DOWN_H_MASK                     (0x10000U)
#define SCT_CTRL_DOWN_H_SHIFT                    (16U)
/*! DOWN_H - This bit is 1 when the H counter is counting down. Hardware sets this bit when the
 *    counter is counting, a counter limit condition occurs, and BIDIR is 1. Hardware clears this bit
 *    when the counter is counting down and a limit condition occurs or when the counter reaches 0.
 */
#define SCT_CTRL_DOWN_H(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_DOWN_H_SHIFT)) & SCT_CTRL_DOWN_H_MASK)

#define SCT_CTRL_STOP_H_MASK                     (0x20000U)
#define SCT_CTRL_STOP_H_SHIFT                    (17U)
/*! STOP_H - When this bit is 1 and HALT is 0, the H counter does not, run but I/O events related to
 *    the counter can occur. If such an event matches the mask in the Start register, this bit is
 *    cleared and counting resumes.
 */
#define SCT_CTRL_STOP_H(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_STOP_H_SHIFT)) & SCT_CTRL_STOP_H_MASK)

#define SCT_CTRL_HALT_H_MASK                     (0x40000U)
#define SCT_CTRL_HALT_H_SHIFT                    (18U)
/*! HALT_H - When this bit is 1, the H counter does not run and no events can occur. A reset sets
 *    this bit. When the HALT_H bit is one, the STOP_H bit is cleared. It is possible to remove the
 *    halt condition while keeping the SCT in the stop condition (not running) with a single write to
 *    this register to simultaneously clear the HALT bit and set the STOP bit. Once set, this bit
 *    can only be cleared by software to restore counter operation. This bit is set on reset.
 */
#define SCT_CTRL_HALT_H(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_HALT_H_SHIFT)) & SCT_CTRL_HALT_H_MASK)

#define SCT_CTRL_CLRCTR_H_MASK                   (0x80000U)
#define SCT_CTRL_CLRCTR_H_SHIFT                  (19U)
/*! CLRCTR_H - Writing a 1 to this bit clears the H counter. This bit always reads as 0.
 */
#define SCT_CTRL_CLRCTR_H(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_CLRCTR_H_SHIFT)) & SCT_CTRL_CLRCTR_H_MASK)

#define SCT_CTRL_BIDIR_H_MASK                    (0x100000U)
#define SCT_CTRL_BIDIR_H_SHIFT                   (20U)
/*! BIDIR_H - Direction select
 *  0b0..The H counter counts up to its limit condition, then is cleared to zero.
 *  0b1..The H counter counts up to its limit, then counts down to a limit condition or to 0.
 */
#define SCT_CTRL_BIDIR_H(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_BIDIR_H_SHIFT)) & SCT_CTRL_BIDIR_H_MASK)

#define SCT_CTRL_PRE_H_MASK                      (0x1FE00000U)
#define SCT_CTRL_PRE_H_SHIFT                     (21U)
/*! PRE_H - Specifies the factor by which the SCT clock is prescaled to produce the H counter clock.
 *    The counter clock is clocked at the rate of the SCT clock divided by PRELH+1. Clear the
 *    counter (by writing a 1 to the CLRCTR bit) whenever changing the PRE value.
 */
#define SCT_CTRL_PRE_H(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_PRE_H_SHIFT)) & SCT_CTRL_PRE_H_MASK)
/*! @} */

/*! @name LIMITL - SCT_LIMITL register */
/*! @{ */

#define SCT_LIMITL_LIMITL_MASK                   (0xFFFFU)
#define SCT_LIMITL_LIMITL_SHIFT                  (0U)
#define SCT_LIMITL_LIMITL(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_LIMITL_LIMITL_SHIFT)) & SCT_LIMITL_LIMITL_MASK)
/*! @} */

/*! @name LIMITH - SCT_LIMITH register */
/*! @{ */

#define SCT_LIMITH_LIMITH_MASK                   (0xFFFFU)
#define SCT_LIMITH_LIMITH_SHIFT                  (0U)
#define SCT_LIMITH_LIMITH(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_LIMITH_LIMITH_SHIFT)) & SCT_LIMITH_LIMITH_MASK)
/*! @} */

/*! @name LIMIT - SCT limit event select register */
/*! @{ */

#define SCT_LIMIT_LIMMSK_L_MASK                  (0xFFFFU)
#define SCT_LIMIT_LIMMSK_L_SHIFT                 (0U)
/*! LIMMSK_L - If bit n is one, event n is used as a counter limit for the L or unified counter
 *    (event 0 = bit 0, event 1 = bit 1, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_LIMIT_LIMMSK_L(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_LIMIT_LIMMSK_L_SHIFT)) & SCT_LIMIT_LIMMSK_L_MASK)

#define SCT_LIMIT_LIMMSK_H_MASK                  (0xFFFF0000U)
#define SCT_LIMIT_LIMMSK_H_SHIFT                 (16U)
/*! LIMMSK_H - If bit n is one, event n is used as a counter limit for the H counter (event 0 = bit
 *    16, event 1 = bit 17, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_LIMIT_LIMMSK_H(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_LIMIT_LIMMSK_H_SHIFT)) & SCT_LIMIT_LIMMSK_H_MASK)
/*! @} */

/*! @name HALTL - SCT_HALTL register */
/*! @{ */

#define SCT_HALTL_HALTL_MASK                     (0xFFFFU)
#define SCT_HALTL_HALTL_SHIFT                    (0U)
#define SCT_HALTL_HALTL(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_HALTL_HALTL_SHIFT)) & SCT_HALTL_HALTL_MASK)
/*! @} */

/*! @name HALTH - SCT_HALTH register */
/*! @{ */

#define SCT_HALTH_HALTH_MASK                     (0xFFFFU)
#define SCT_HALTH_HALTH_SHIFT                    (0U)
#define SCT_HALTH_HALTH(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_HALTH_HALTH_SHIFT)) & SCT_HALTH_HALTH_MASK)
/*! @} */

/*! @name HALT - SCT halt event select register */
/*! @{ */

#define SCT_HALT_HALTMSK_L_MASK                  (0xFFFFU)
#define SCT_HALT_HALTMSK_L_SHIFT                 (0U)
/*! HALTMSK_L - If bit n is one, event n sets the HALT_L bit in the CTRL register (event 0 = bit 0,
 *    event 1 = bit 1, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_HALT_HALTMSK_L(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_HALT_HALTMSK_L_SHIFT)) & SCT_HALT_HALTMSK_L_MASK)

#define SCT_HALT_HALTMSK_H_MASK                  (0xFFFF0000U)
#define SCT_HALT_HALTMSK_H_SHIFT                 (16U)
/*! HALTMSK_H - If bit n is one, event n sets the HALT_H bit in the CTRL register (event 0 = bit 16,
 *    event 1 = bit 17, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_HALT_HALTMSK_H(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_HALT_HALTMSK_H_SHIFT)) & SCT_HALT_HALTMSK_H_MASK)
/*! @} */

/*! @name STOPL - SCT_STOPL register */
/*! @{ */

#define SCT_STOPL_STOPL_MASK                     (0xFFFFU)
#define SCT_STOPL_STOPL_SHIFT                    (0U)
#define SCT_STOPL_STOPL(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_STOPL_STOPL_SHIFT)) & SCT_STOPL_STOPL_MASK)
/*! @} */

/*! @name STOPH - SCT_STOPH register */
/*! @{ */

#define SCT_STOPH_STOPH_MASK                     (0xFFFFU)
#define SCT_STOPH_STOPH_SHIFT                    (0U)
#define SCT_STOPH_STOPH(x)                       (((uint16_t)(((uint16_t)(x)) << SCT_STOPH_STOPH_SHIFT)) & SCT_STOPH_STOPH_MASK)
/*! @} */

/*! @name STOP - SCT stop event select register */
/*! @{ */

#define SCT_STOP_STOPMSK_L_MASK                  (0xFFFFU)
#define SCT_STOP_STOPMSK_L_SHIFT                 (0U)
/*! STOPMSK_L - If bit n is one, event n sets the STOP_L bit in the CTRL register (event 0 = bit 0,
 *    event 1 = bit 1, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_STOP_STOPMSK_L(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_STOP_STOPMSK_L_SHIFT)) & SCT_STOP_STOPMSK_L_MASK)

#define SCT_STOP_STOPMSK_H_MASK                  (0xFFFF0000U)
#define SCT_STOP_STOPMSK_H_SHIFT                 (16U)
/*! STOPMSK_H - If bit n is one, event n sets the STOP_H bit in the CTRL register (event 0 = bit 16,
 *    event 1 = bit 17, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_STOP_STOPMSK_H(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_STOP_STOPMSK_H_SHIFT)) & SCT_STOP_STOPMSK_H_MASK)
/*! @} */

/*! @name STARTL - SCT_STARTL register */
/*! @{ */

#define SCT_STARTL_STARTL_MASK                   (0xFFFFU)
#define SCT_STARTL_STARTL_SHIFT                  (0U)
#define SCT_STARTL_STARTL(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_STARTL_STARTL_SHIFT)) & SCT_STARTL_STARTL_MASK)
/*! @} */

/*! @name STARTH - SCT_STARTH register */
/*! @{ */

#define SCT_STARTH_STARTH_MASK                   (0xFFFFU)
#define SCT_STARTH_STARTH_SHIFT                  (0U)
#define SCT_STARTH_STARTH(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_STARTH_STARTH_SHIFT)) & SCT_STARTH_STARTH_MASK)
/*! @} */

/*! @name START - SCT start event select register */
/*! @{ */

#define SCT_START_STARTMSK_L_MASK                (0xFFFFU)
#define SCT_START_STARTMSK_L_SHIFT               (0U)
/*! STARTMSK_L - If bit n is one, event n clears the STOP_L bit in the CTRL register (event 0 = bit
 *    0, event 1 = bit 1, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_START_STARTMSK_L(x)                  (((uint32_t)(((uint32_t)(x)) << SCT_START_STARTMSK_L_SHIFT)) & SCT_START_STARTMSK_L_MASK)

#define SCT_START_STARTMSK_H_MASK                (0xFFFF0000U)
#define SCT_START_STARTMSK_H_SHIFT               (16U)
/*! STARTMSK_H - If bit n is one, event n clears the STOP_H bit in the CTRL register (event 0 = bit
 *    16, event 1 = bit 17, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_START_STARTMSK_H(x)                  (((uint32_t)(((uint32_t)(x)) << SCT_START_STARTMSK_H_SHIFT)) & SCT_START_STARTMSK_H_MASK)
/*! @} */

/*! @name COUNTL - SCT_COUNTL register */
/*! @{ */

#define SCT_COUNTL_COUNTL_MASK                   (0xFFFFU)
#define SCT_COUNTL_COUNTL_SHIFT                  (0U)
#define SCT_COUNTL_COUNTL(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_COUNTL_COUNTL_SHIFT)) & SCT_COUNTL_COUNTL_MASK)
/*! @} */

/*! @name COUNTH - SCT_COUNTH register */
/*! @{ */

#define SCT_COUNTH_COUNTH_MASK                   (0xFFFFU)
#define SCT_COUNTH_COUNTH_SHIFT                  (0U)
#define SCT_COUNTH_COUNTH(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_COUNTH_COUNTH_SHIFT)) & SCT_COUNTH_COUNTH_MASK)
/*! @} */

/*! @name COUNT - SCT counter register */
/*! @{ */

#define SCT_COUNT_CTR_L_MASK                     (0xFFFFU)
#define SCT_COUNT_CTR_L_SHIFT                    (0U)
/*! CTR_L - When UNIFY = 0, read or write the 16-bit L counter value. When UNIFY = 1, read or write
 *    the lower 16 bits of the 32-bit unified counter.
 */
#define SCT_COUNT_CTR_L(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_COUNT_CTR_L_SHIFT)) & SCT_COUNT_CTR_L_MASK)

#define SCT_COUNT_CTR_H_MASK                     (0xFFFF0000U)
#define SCT_COUNT_CTR_H_SHIFT                    (16U)
/*! CTR_H - When UNIFY = 0, read or write the 16-bit H counter value. When UNIFY = 1, read or write
 *    the upper 16 bits of the 32-bit unified counter.
 */
#define SCT_COUNT_CTR_H(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_COUNT_CTR_H_SHIFT)) & SCT_COUNT_CTR_H_MASK)
/*! @} */

/*! @name STATEL - SCT_STATEL register */
/*! @{ */

#define SCT_STATEL_STATEL_MASK                   (0xFFFFU)
#define SCT_STATEL_STATEL_SHIFT                  (0U)
#define SCT_STATEL_STATEL(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_STATEL_STATEL_SHIFT)) & SCT_STATEL_STATEL_MASK)
/*! @} */

/*! @name STATEH - SCT_STATEH register */
/*! @{ */

#define SCT_STATEH_STATEH_MASK                   (0xFFFFU)
#define SCT_STATEH_STATEH_SHIFT                  (0U)
#define SCT_STATEH_STATEH(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_STATEH_STATEH_SHIFT)) & SCT_STATEH_STATEH_MASK)
/*! @} */

/*! @name STATE - SCT state register */
/*! @{ */

#define SCT_STATE_STATE_L_MASK                   (0x1FU)
#define SCT_STATE_STATE_L_SHIFT                  (0U)
/*! STATE_L - State variable.
 */
#define SCT_STATE_STATE_L(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_STATE_STATE_L_SHIFT)) & SCT_STATE_STATE_L_MASK)

#define SCT_STATE_STATE_H_MASK                   (0x1F0000U)
#define SCT_STATE_STATE_H_SHIFT                  (16U)
/*! STATE_H - State variable.
 */
#define SCT_STATE_STATE_H(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_STATE_STATE_H_SHIFT)) & SCT_STATE_STATE_H_MASK)
/*! @} */

/*! @name INPUT - SCT input register */
/*! @{ */

#define SCT_INPUT_AIN0_MASK                      (0x1U)
#define SCT_INPUT_AIN0_SHIFT                     (0U)
/*! AIN0 - Input 0 state. Input 0 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN0(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN0_SHIFT)) & SCT_INPUT_AIN0_MASK)

#define SCT_INPUT_AIN1_MASK                      (0x2U)
#define SCT_INPUT_AIN1_SHIFT                     (1U)
/*! AIN1 - Input 1 state. Input 1 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN1(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN1_SHIFT)) & SCT_INPUT_AIN1_MASK)

#define SCT_INPUT_AIN2_MASK                      (0x4U)
#define SCT_INPUT_AIN2_SHIFT                     (2U)
/*! AIN2 - Input 2 state. Input 2 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN2(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN2_SHIFT)) & SCT_INPUT_AIN2_MASK)

#define SCT_INPUT_AIN3_MASK                      (0x8U)
#define SCT_INPUT_AIN3_SHIFT                     (3U)
/*! AIN3 - Input 3 state. Input 3 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN3(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN3_SHIFT)) & SCT_INPUT_AIN3_MASK)

#define SCT_INPUT_AIN4_MASK                      (0x10U)
#define SCT_INPUT_AIN4_SHIFT                     (4U)
/*! AIN4 - Input 4 state. Input 4 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN4(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN4_SHIFT)) & SCT_INPUT_AIN4_MASK)

#define SCT_INPUT_AIN5_MASK                      (0x20U)
#define SCT_INPUT_AIN5_SHIFT                     (5U)
/*! AIN5 - Input 5 state. Input 5 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN5(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN5_SHIFT)) & SCT_INPUT_AIN5_MASK)

#define SCT_INPUT_AIN6_MASK                      (0x40U)
#define SCT_INPUT_AIN6_SHIFT                     (6U)
/*! AIN6 - Input 6 state. Input 6 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN6(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN6_SHIFT)) & SCT_INPUT_AIN6_MASK)

#define SCT_INPUT_AIN7_MASK                      (0x80U)
#define SCT_INPUT_AIN7_SHIFT                     (7U)
/*! AIN7 - Input 7 state. Input 7 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN7(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN7_SHIFT)) & SCT_INPUT_AIN7_MASK)

#define SCT_INPUT_AIN8_MASK                      (0x100U)
#define SCT_INPUT_AIN8_SHIFT                     (8U)
/*! AIN8 - Input 8 state. Input 8 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN8(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN8_SHIFT)) & SCT_INPUT_AIN8_MASK)

#define SCT_INPUT_AIN9_MASK                      (0x200U)
#define SCT_INPUT_AIN9_SHIFT                     (9U)
/*! AIN9 - Input 9 state. Input 9 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN9(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN9_SHIFT)) & SCT_INPUT_AIN9_MASK)

#define SCT_INPUT_AIN10_MASK                     (0x400U)
#define SCT_INPUT_AIN10_SHIFT                    (10U)
/*! AIN10 - Input 10 state. Input 10 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN10(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN10_SHIFT)) & SCT_INPUT_AIN10_MASK)

#define SCT_INPUT_AIN11_MASK                     (0x800U)
#define SCT_INPUT_AIN11_SHIFT                    (11U)
/*! AIN11 - Input 11 state. Input 11 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN11(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN11_SHIFT)) & SCT_INPUT_AIN11_MASK)

#define SCT_INPUT_AIN12_MASK                     (0x1000U)
#define SCT_INPUT_AIN12_SHIFT                    (12U)
/*! AIN12 - Input 12 state. Input 12 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN12(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN12_SHIFT)) & SCT_INPUT_AIN12_MASK)

#define SCT_INPUT_AIN13_MASK                     (0x2000U)
#define SCT_INPUT_AIN13_SHIFT                    (13U)
/*! AIN13 - Input 13 state. Input 13 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN13(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN13_SHIFT)) & SCT_INPUT_AIN13_MASK)

#define SCT_INPUT_AIN14_MASK                     (0x4000U)
#define SCT_INPUT_AIN14_SHIFT                    (14U)
/*! AIN14 - Input 14 state. Input 14 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN14(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN14_SHIFT)) & SCT_INPUT_AIN14_MASK)

#define SCT_INPUT_AIN15_MASK                     (0x8000U)
#define SCT_INPUT_AIN15_SHIFT                    (15U)
/*! AIN15 - Input 15 state. Input 15 state on the last SCT clock edge.
 */
#define SCT_INPUT_AIN15(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_AIN15_SHIFT)) & SCT_INPUT_AIN15_MASK)

#define SCT_INPUT_SIN0_MASK                      (0x10000U)
#define SCT_INPUT_SIN0_SHIFT                     (16U)
/*! SIN0 - Input 0 state. Input 0 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN0(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN0_SHIFT)) & SCT_INPUT_SIN0_MASK)

#define SCT_INPUT_SIN1_MASK                      (0x20000U)
#define SCT_INPUT_SIN1_SHIFT                     (17U)
/*! SIN1 - Input 1 state. Input 1 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN1(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN1_SHIFT)) & SCT_INPUT_SIN1_MASK)

#define SCT_INPUT_SIN2_MASK                      (0x40000U)
#define SCT_INPUT_SIN2_SHIFT                     (18U)
/*! SIN2 - Input 2 state. Input 2 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN2(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN2_SHIFT)) & SCT_INPUT_SIN2_MASK)

#define SCT_INPUT_SIN3_MASK                      (0x80000U)
#define SCT_INPUT_SIN3_SHIFT                     (19U)
/*! SIN3 - Input 3 state. Input 3 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN3(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN3_SHIFT)) & SCT_INPUT_SIN3_MASK)

#define SCT_INPUT_SIN4_MASK                      (0x100000U)
#define SCT_INPUT_SIN4_SHIFT                     (20U)
/*! SIN4 - Input 4 state. Input 4 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN4(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN4_SHIFT)) & SCT_INPUT_SIN4_MASK)

#define SCT_INPUT_SIN5_MASK                      (0x200000U)
#define SCT_INPUT_SIN5_SHIFT                     (21U)
/*! SIN5 - Input 5 state. Input 5 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN5(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN5_SHIFT)) & SCT_INPUT_SIN5_MASK)

#define SCT_INPUT_SIN6_MASK                      (0x400000U)
#define SCT_INPUT_SIN6_SHIFT                     (22U)
/*! SIN6 - Input 6 state. Input 6 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN6(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN6_SHIFT)) & SCT_INPUT_SIN6_MASK)

#define SCT_INPUT_SIN7_MASK                      (0x800000U)
#define SCT_INPUT_SIN7_SHIFT                     (23U)
/*! SIN7 - Input 7 state. Input 7 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN7(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN7_SHIFT)) & SCT_INPUT_SIN7_MASK)

#define SCT_INPUT_SIN8_MASK                      (0x1000000U)
#define SCT_INPUT_SIN8_SHIFT                     (24U)
/*! SIN8 - Input 8 state. Input 8 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN8(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN8_SHIFT)) & SCT_INPUT_SIN8_MASK)

#define SCT_INPUT_SIN9_MASK                      (0x2000000U)
#define SCT_INPUT_SIN9_SHIFT                     (25U)
/*! SIN9 - Input 9 state. Input 9 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN9(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN9_SHIFT)) & SCT_INPUT_SIN9_MASK)

#define SCT_INPUT_SIN10_MASK                     (0x4000000U)
#define SCT_INPUT_SIN10_SHIFT                    (26U)
/*! SIN10 - Input 10 state. Input 10 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN10(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN10_SHIFT)) & SCT_INPUT_SIN10_MASK)

#define SCT_INPUT_SIN11_MASK                     (0x8000000U)
#define SCT_INPUT_SIN11_SHIFT                    (27U)
/*! SIN11 - Input 11 state. Input 11 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN11(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN11_SHIFT)) & SCT_INPUT_SIN11_MASK)

#define SCT_INPUT_SIN12_MASK                     (0x10000000U)
#define SCT_INPUT_SIN12_SHIFT                    (28U)
/*! SIN12 - Input 12 state. Input 12 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN12(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN12_SHIFT)) & SCT_INPUT_SIN12_MASK)

#define SCT_INPUT_SIN13_MASK                     (0x20000000U)
#define SCT_INPUT_SIN13_SHIFT                    (29U)
/*! SIN13 - Input 13 state. Input 13 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN13(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN13_SHIFT)) & SCT_INPUT_SIN13_MASK)

#define SCT_INPUT_SIN14_MASK                     (0x40000000U)
#define SCT_INPUT_SIN14_SHIFT                    (30U)
/*! SIN14 - Input 14 state. Input 14 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN14(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN14_SHIFT)) & SCT_INPUT_SIN14_MASK)

#define SCT_INPUT_SIN15_MASK                     (0x80000000U)
#define SCT_INPUT_SIN15_SHIFT                    (31U)
/*! SIN15 - Input 15 state. Input 15 state following the synchronization specified by INSYNC.
 */
#define SCT_INPUT_SIN15(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_INPUT_SIN15_SHIFT)) & SCT_INPUT_SIN15_MASK)
/*! @} */

/*! @name REGMODEL - SCT_REGMODEL register */
/*! @{ */

#define SCT_REGMODEL_REGMODEL_MASK               (0xFFFFU)
#define SCT_REGMODEL_REGMODEL_SHIFT              (0U)
#define SCT_REGMODEL_REGMODEL(x)                 (((uint16_t)(((uint16_t)(x)) << SCT_REGMODEL_REGMODEL_SHIFT)) & SCT_REGMODEL_REGMODEL_MASK)
/*! @} */

/*! @name REGMODEH - SCT_REGMODEH register */
/*! @{ */

#define SCT_REGMODEH_REGMODEH_MASK               (0xFFFFU)
#define SCT_REGMODEH_REGMODEH_SHIFT              (0U)
#define SCT_REGMODEH_REGMODEH(x)                 (((uint16_t)(((uint16_t)(x)) << SCT_REGMODEH_REGMODEH_SHIFT)) & SCT_REGMODEH_REGMODEH_MASK)
/*! @} */

/*! @name REGMODE - SCT match/capture mode register */
/*! @{ */

#define SCT_REGMODE_REGMOD_L_MASK                (0xFFFFU)
#define SCT_REGMODE_REGMOD_L_SHIFT               (0U)
/*! REGMOD_L - Each bit controls one match/capture register (register 0 = bit 0, register 1 = bit 1,
 *    etc.). The number of bits = number of match/captures in this SCT. 0 = register operates as
 *    match register. 1 = register operates as capture register.
 */
#define SCT_REGMODE_REGMOD_L(x)                  (((uint32_t)(((uint32_t)(x)) << SCT_REGMODE_REGMOD_L_SHIFT)) & SCT_REGMODE_REGMOD_L_MASK)

#define SCT_REGMODE_REGMOD_H_MASK                (0xFFFF0000U)
#define SCT_REGMODE_REGMOD_H_SHIFT               (16U)
/*! REGMOD_H - Each bit controls one match/capture register (register 0 = bit 16, register 1 = bit
 *    17, etc.). The number of bits = number of match/captures in this SCT. 0 = register operates as
 *    match registers. 1 = register operates as capture registers.
 */
#define SCT_REGMODE_REGMOD_H(x)                  (((uint32_t)(((uint32_t)(x)) << SCT_REGMODE_REGMOD_H_SHIFT)) & SCT_REGMODE_REGMOD_H_MASK)
/*! @} */

/*! @name OUTPUT - SCT output register */
/*! @{ */

#define SCT_OUTPUT_OUT_MASK                      (0xFFFFU)
#define SCT_OUTPUT_OUT_SHIFT                     (0U)
/*! OUT - Writing a 1 to bit n forces the corresponding output HIGH. Writing a 0 forces the
 *    corresponding output LOW (output 0 = bit 0, output 1 = bit 1, etc.). The number of bits = number of
 *    outputs in this SCT.
 */
#define SCT_OUTPUT_OUT(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUT_OUT_SHIFT)) & SCT_OUTPUT_OUT_MASK)
/*! @} */

/*! @name OUTPUTDIRCTRL - SCT output counter direction control register */
/*! @{ */

#define SCT_OUTPUTDIRCTRL_SETCLR0_MASK           (0x3U)
#define SCT_OUTPUTDIRCTRL_SETCLR0_SHIFT          (0U)
/*! SETCLR0 - Set/clear operation on output 0. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR0(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR0_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR0_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR1_MASK           (0xCU)
#define SCT_OUTPUTDIRCTRL_SETCLR1_SHIFT          (2U)
/*! SETCLR1 - Set/clear operation on output 1. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR1(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR1_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR1_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR2_MASK           (0x30U)
#define SCT_OUTPUTDIRCTRL_SETCLR2_SHIFT          (4U)
/*! SETCLR2 - Set/clear operation on output 2. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR2(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR2_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR2_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR3_MASK           (0xC0U)
#define SCT_OUTPUTDIRCTRL_SETCLR3_SHIFT          (6U)
/*! SETCLR3 - Set/clear operation on output 3. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR3(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR3_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR3_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR4_MASK           (0x300U)
#define SCT_OUTPUTDIRCTRL_SETCLR4_SHIFT          (8U)
/*! SETCLR4 - Set/clear operation on output 4. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR4(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR4_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR4_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR5_MASK           (0xC00U)
#define SCT_OUTPUTDIRCTRL_SETCLR5_SHIFT          (10U)
/*! SETCLR5 - Set/clear operation on output 5. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR5(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR5_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR5_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR6_MASK           (0x3000U)
#define SCT_OUTPUTDIRCTRL_SETCLR6_SHIFT          (12U)
/*! SETCLR6 - Set/clear operation on output 6. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR6(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR6_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR6_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR7_MASK           (0xC000U)
#define SCT_OUTPUTDIRCTRL_SETCLR7_SHIFT          (14U)
/*! SETCLR7 - Set/clear operation on output 7. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR7(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR7_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR7_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR8_MASK           (0x30000U)
#define SCT_OUTPUTDIRCTRL_SETCLR8_SHIFT          (16U)
/*! SETCLR8 - Set/clear operation on output 8. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR8(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR8_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR8_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR9_MASK           (0xC0000U)
#define SCT_OUTPUTDIRCTRL_SETCLR9_SHIFT          (18U)
/*! SETCLR9 - Set/clear operation on output 9. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR9(x)             (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR9_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR9_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR10_MASK          (0x300000U)
#define SCT_OUTPUTDIRCTRL_SETCLR10_SHIFT         (20U)
/*! SETCLR10 - Set/clear operation on output 10. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR10(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR10_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR10_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR11_MASK          (0xC00000U)
#define SCT_OUTPUTDIRCTRL_SETCLR11_SHIFT         (22U)
/*! SETCLR11 - Set/clear operation on output 11. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR11(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR11_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR11_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR12_MASK          (0x3000000U)
#define SCT_OUTPUTDIRCTRL_SETCLR12_SHIFT         (24U)
/*! SETCLR12 - Set/clear operation on output 12. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR12(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR12_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR12_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR13_MASK          (0xC000000U)
#define SCT_OUTPUTDIRCTRL_SETCLR13_SHIFT         (26U)
/*! SETCLR13 - Set/clear operation on output 13. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR13(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR13_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR13_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR14_MASK          (0x30000000U)
#define SCT_OUTPUTDIRCTRL_SETCLR14_SHIFT         (28U)
/*! SETCLR14 - Set/clear operation on output 14. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR14(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR14_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR14_MASK)

#define SCT_OUTPUTDIRCTRL_SETCLR15_MASK          (0xC0000000U)
#define SCT_OUTPUTDIRCTRL_SETCLR15_SHIFT         (30U)
/*! SETCLR15 - Set/clear operation on output 15. Value 0x3 is reserved. Do not program this value.
 *  0b00..Set and clear do not depend on the direction of any counter.
 *  0b01..Set and clear are reversed when counter L or the unified counter is counting down.
 *  0b10..Set and clear are reversed when counter H is counting down. Do not use if UNIFY = 1.
 */
#define SCT_OUTPUTDIRCTRL_SETCLR15(x)            (((uint32_t)(((uint32_t)(x)) << SCT_OUTPUTDIRCTRL_SETCLR15_SHIFT)) & SCT_OUTPUTDIRCTRL_SETCLR15_MASK)
/*! @} */

/*! @name RES - SCT conflict resolution register */
/*! @{ */

#define SCT_RES_O0RES_MASK                       (0x3U)
#define SCT_RES_O0RES_SHIFT                      (0U)
/*! O0RES - Effect of simultaneous set and clear on output 0.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR0 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR0 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O0RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O0RES_SHIFT)) & SCT_RES_O0RES_MASK)

#define SCT_RES_O1RES_MASK                       (0xCU)
#define SCT_RES_O1RES_SHIFT                      (2U)
/*! O1RES - Effect of simultaneous set and clear on output 1.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR1 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR1 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O1RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O1RES_SHIFT)) & SCT_RES_O1RES_MASK)

#define SCT_RES_O2RES_MASK                       (0x30U)
#define SCT_RES_O2RES_SHIFT                      (4U)
/*! O2RES - Effect of simultaneous set and clear on output 2.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR2 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output n (or set based on the SETCLR2 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O2RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O2RES_SHIFT)) & SCT_RES_O2RES_MASK)

#define SCT_RES_O3RES_MASK                       (0xC0U)
#define SCT_RES_O3RES_SHIFT                      (6U)
/*! O3RES - Effect of simultaneous set and clear on output 3.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR3 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR3 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O3RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O3RES_SHIFT)) & SCT_RES_O3RES_MASK)

#define SCT_RES_O4RES_MASK                       (0x300U)
#define SCT_RES_O4RES_SHIFT                      (8U)
/*! O4RES - Effect of simultaneous set and clear on output 4.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR4 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR4 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O4RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O4RES_SHIFT)) & SCT_RES_O4RES_MASK)

#define SCT_RES_O5RES_MASK                       (0xC00U)
#define SCT_RES_O5RES_SHIFT                      (10U)
/*! O5RES - Effect of simultaneous set and clear on output 5.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR5 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR5 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O5RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O5RES_SHIFT)) & SCT_RES_O5RES_MASK)

#define SCT_RES_O6RES_MASK                       (0x3000U)
#define SCT_RES_O6RES_SHIFT                      (12U)
/*! O6RES - Effect of simultaneous set and clear on output 6.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR6 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR6 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O6RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O6RES_SHIFT)) & SCT_RES_O6RES_MASK)

#define SCT_RES_O7RES_MASK                       (0xC000U)
#define SCT_RES_O7RES_SHIFT                      (14U)
/*! O7RES - Effect of simultaneous set and clear on output 7.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR7 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output n (or set based on the SETCLR7 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O7RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O7RES_SHIFT)) & SCT_RES_O7RES_MASK)

#define SCT_RES_O8RES_MASK                       (0x30000U)
#define SCT_RES_O8RES_SHIFT                      (16U)
/*! O8RES - Effect of simultaneous set and clear on output 8.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR8 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR8 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O8RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O8RES_SHIFT)) & SCT_RES_O8RES_MASK)

#define SCT_RES_O9RES_MASK                       (0xC0000U)
#define SCT_RES_O9RES_SHIFT                      (18U)
/*! O9RES - Effect of simultaneous set and clear on output 9.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR9 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR9 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O9RES(x)                         (((uint32_t)(((uint32_t)(x)) << SCT_RES_O9RES_SHIFT)) & SCT_RES_O9RES_MASK)

#define SCT_RES_O10RES_MASK                      (0x300000U)
#define SCT_RES_O10RES_SHIFT                     (20U)
/*! O10RES - Effect of simultaneous set and clear on output 10.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR10 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR10 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O10RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O10RES_SHIFT)) & SCT_RES_O10RES_MASK)

#define SCT_RES_O11RES_MASK                      (0xC00000U)
#define SCT_RES_O11RES_SHIFT                     (22U)
/*! O11RES - Effect of simultaneous set and clear on output 11.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR11 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR11 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O11RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O11RES_SHIFT)) & SCT_RES_O11RES_MASK)

#define SCT_RES_O12RES_MASK                      (0x3000000U)
#define SCT_RES_O12RES_SHIFT                     (24U)
/*! O12RES - Effect of simultaneous set and clear on output 12.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR12 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR12 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O12RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O12RES_SHIFT)) & SCT_RES_O12RES_MASK)

#define SCT_RES_O13RES_MASK                      (0xC000000U)
#define SCT_RES_O13RES_SHIFT                     (26U)
/*! O13RES - Effect of simultaneous set and clear on output 13.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR13 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR13 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O13RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O13RES_SHIFT)) & SCT_RES_O13RES_MASK)

#define SCT_RES_O14RES_MASK                      (0x30000000U)
#define SCT_RES_O14RES_SHIFT                     (28U)
/*! O14RES - Effect of simultaneous set and clear on output 14.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR14 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR14 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O14RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O14RES_SHIFT)) & SCT_RES_O14RES_MASK)

#define SCT_RES_O15RES_MASK                      (0xC0000000U)
#define SCT_RES_O15RES_SHIFT                     (30U)
/*! O15RES - Effect of simultaneous set and clear on output 15.
 *  0b00..No change.
 *  0b01..Set output (or clear based on the SETCLR15 field in the OUTPUTDIRCTRL register).
 *  0b10..Clear output (or set based on the SETCLR15 field).
 *  0b11..Toggle output.
 */
#define SCT_RES_O15RES(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_RES_O15RES_SHIFT)) & SCT_RES_O15RES_MASK)
/*! @} */

/*! @name DMAREQ0 - SCT DMA request 0 register */
/*! @{ */

#define SCT_DMAREQ0_DEV_0_MASK                   (0xFFFFU)
#define SCT_DMAREQ0_DEV_0_SHIFT                  (0U)
/*! DEV_0 - If bit n is one, event n triggers DMA request 0 (event 0 = bit 0, event 1 = bit 1,
 *    etc.). The number of bits = number of events in this SCT.
 */
#define SCT_DMAREQ0_DEV_0(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ0_DEV_0_SHIFT)) & SCT_DMAREQ0_DEV_0_MASK)

#define SCT_DMAREQ0_DRL0_MASK                    (0x40000000U)
#define SCT_DMAREQ0_DRL0_SHIFT                   (30U)
/*! DRL0 - A 1 in this bit triggers DMA request 0 when it loads the MATCH_L/Unified registers from the RELOAD_L/Unified registers.
 */
#define SCT_DMAREQ0_DRL0(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ0_DRL0_SHIFT)) & SCT_DMAREQ0_DRL0_MASK)

#define SCT_DMAREQ0_DRQ0_MASK                    (0x80000000U)
#define SCT_DMAREQ0_DRQ0_SHIFT                   (31U)
/*! DRQ0 - This read-only bit indicates the state of DMA Request 0. Note that if the related DMA
 *    channel is enabled and properly set up, it is unlikely that software will see this flag, it will
 *    be cleared rapidly by the DMA service. The flag remaining set could point to an issue with DMA
 *    setup.
 */
#define SCT_DMAREQ0_DRQ0(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ0_DRQ0_SHIFT)) & SCT_DMAREQ0_DRQ0_MASK)
/*! @} */

/*! @name DMAREQ1 - SCT DMA request 1 register */
/*! @{ */

#define SCT_DMAREQ1_DEV_1_MASK                   (0xFFFFU)
#define SCT_DMAREQ1_DEV_1_SHIFT                  (0U)
/*! DEV_1 - If bit n is one, event n triggers DMA request 1 (event 0 = bit 0, event 1 = bit 1,
 *    etc.). The number of bits = number of events in this SCT.
 */
#define SCT_DMAREQ1_DEV_1(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ1_DEV_1_SHIFT)) & SCT_DMAREQ1_DEV_1_MASK)

#define SCT_DMAREQ1_DRL1_MASK                    (0x40000000U)
#define SCT_DMAREQ1_DRL1_SHIFT                   (30U)
/*! DRL1 - A 1 in this bit triggers DMA request 1 when it loads the Match L/Unified registers from the Reload L/Unified registers.
 */
#define SCT_DMAREQ1_DRL1(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ1_DRL1_SHIFT)) & SCT_DMAREQ1_DRL1_MASK)

#define SCT_DMAREQ1_DRQ1_MASK                    (0x80000000U)
#define SCT_DMAREQ1_DRQ1_SHIFT                   (31U)
/*! DRQ1 - This read-only bit indicates the state of DMA Request 1. Note that if the related DMA
 *    channel is enabled and properly set up, it is unlikely that software will see this flag, it will
 *    be cleared rapidly by the DMA service. The flag remaining set could point to an issue with DMA
 *    setup.
 */
#define SCT_DMAREQ1_DRQ1(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_DMAREQ1_DRQ1_SHIFT)) & SCT_DMAREQ1_DRQ1_MASK)
/*! @} */

/*! @name EVEN - SCT event interrupt enable register */
/*! @{ */

#define SCT_EVEN_IEN_MASK                        (0xFFFFU)
#define SCT_EVEN_IEN_SHIFT                       (0U)
/*! IEN - The SCT requests an interrupt when bit n of this register and the event flag register are
 *    both one (event 0 = bit 0, event 1 = bit 1, etc.). The number of bits = number of events in
 *    this SCT.
 */
#define SCT_EVEN_IEN(x)                          (((uint32_t)(((uint32_t)(x)) << SCT_EVEN_IEN_SHIFT)) & SCT_EVEN_IEN_MASK)
/*! @} */

/*! @name EVFLAG - SCT event flag register */
/*! @{ */

#define SCT_EVFLAG_FLAG_MASK                     (0xFFFFU)
#define SCT_EVFLAG_FLAG_SHIFT                    (0U)
/*! FLAG - Bit n is one if event n has occurred since reset or a 1 was last written to this bit
 *    (event 0 = bit 0, event 1 = bit 1, etc.). The number of bits = number of events in this SCT.
 */
#define SCT_EVFLAG_FLAG(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_EVFLAG_FLAG_SHIFT)) & SCT_EVFLAG_FLAG_MASK)
/*! @} */

/*! @name CONEN - SCT conflict interrupt enable register */
/*! @{ */

#define SCT_CONEN_NCEN_MASK                      (0xFFFFU)
#define SCT_CONEN_NCEN_SHIFT                     (0U)
/*! NCEN - The SCT requests an interrupt when bit n of this register and the SCT conflict flag
 *    register are both one (output 0 = bit 0, output 1 = bit 1, etc.). The number of bits = number of
 *    outputs in this SCT.
 */
#define SCT_CONEN_NCEN(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CONEN_NCEN_SHIFT)) & SCT_CONEN_NCEN_MASK)
/*! @} */

/*! @name CONFLAG - SCT conflict flag register */
/*! @{ */

#define SCT_CONFLAG_NCFLAG_MASK                  (0xFFFFU)
#define SCT_CONFLAG_NCFLAG_SHIFT                 (0U)
/*! NCFLAG - Bit n is one if a no-change conflict event occurred on output n since reset or a 1 was
 *    last written to this bit (output 0 = bit 0, output 1 = bit 1, etc.). The number of bits =
 *    number of outputs in this SCT.
 */
#define SCT_CONFLAG_NCFLAG(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_CONFLAG_NCFLAG_SHIFT)) & SCT_CONFLAG_NCFLAG_MASK)

#define SCT_CONFLAG_BUSERRL_MASK                 (0x40000000U)
#define SCT_CONFLAG_BUSERRL_SHIFT                (30U)
/*! BUSERRL - The most recent bus error from this SCT involved writing CTR L/Unified, STATE
 *    L/Unified, MATCH L/Unified, or the Output register when the L/U counter was not halted. A word write
 *    to certain L and H registers can be half successful and half unsuccessful.
 */
#define SCT_CONFLAG_BUSERRL(x)                   (((uint32_t)(((uint32_t)(x)) << SCT_CONFLAG_BUSERRL_SHIFT)) & SCT_CONFLAG_BUSERRL_MASK)

#define SCT_CONFLAG_BUSERRH_MASK                 (0x80000000U)
#define SCT_CONFLAG_BUSERRH_SHIFT                (31U)
/*! BUSERRH - The most recent bus error from this SCT involved writing CTR H, STATE H, MATCH H, or
 *    the Output register when the H counter was not halted.
 */
#define SCT_CONFLAG_BUSERRH(x)                   (((uint32_t)(((uint32_t)(x)) << SCT_CONFLAG_BUSERRH_SHIFT)) & SCT_CONFLAG_BUSERRH_MASK)
/*! @} */

/*! @name CAPL - SCT_CAPL register */
/*! @{ */

#define SCT_CAPL_CAPL_MASK                       (0xFFFFU)
#define SCT_CAPL_CAPL_SHIFT                      (0U)
#define SCT_CAPL_CAPL(x)                         (((uint16_t)(((uint16_t)(x)) << SCT_CAPL_CAPL_SHIFT)) & SCT_CAPL_CAPL_MASK)
/*! @} */

/* The count of SCT_CAPL */
#define SCT_CAPL_COUNT                           (10U)

/*! @name CAPH - SCT_CAPH register */
/*! @{ */

#define SCT_CAPH_CAPH_MASK                       (0xFFFFU)
#define SCT_CAPH_CAPH_SHIFT                      (0U)
#define SCT_CAPH_CAPH(x)                         (((uint16_t)(((uint16_t)(x)) << SCT_CAPH_CAPH_SHIFT)) & SCT_CAPH_CAPH_MASK)
/*! @} */

/* The count of SCT_CAPH */
#define SCT_CAPH_COUNT                           (10U)

/*! @name CAP - SCT capture register of capture channel */
/*! @{ */

#define SCT_CAP_CAPn_L_MASK                      (0xFFFFU)
#define SCT_CAP_CAPn_L_SHIFT                     (0U)
/*! CAPn_L - When UNIFY = 0, read the 16-bit counter value at which this register was last captured.
 *    When UNIFY = 1, read the lower 16 bits of the 32-bit value at which this register was last
 *    captured.
 */
#define SCT_CAP_CAPn_L(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CAP_CAPn_L_SHIFT)) & SCT_CAP_CAPn_L_MASK)

#define SCT_CAP_CAPn_H_MASK                      (0xFFFF0000U)
#define SCT_CAP_CAPn_H_SHIFT                     (16U)
/*! CAPn_H - When UNIFY = 0, read the 16-bit counter value at which this register was last captured.
 *    When UNIFY = 1, read the upper 16 bits of the 32-bit value at which this register was last
 *    captured.
 */
#define SCT_CAP_CAPn_H(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CAP_CAPn_H_SHIFT)) & SCT_CAP_CAPn_H_MASK)
/*! @} */

/* The count of SCT_CAP */
#define SCT_CAP_COUNT                            (10U)

/*! @name MATCHL - SCT_MATCHL register */
/*! @{ */

#define SCT_MATCHL_MATCHL_MASK                   (0xFFFFU)
#define SCT_MATCHL_MATCHL_SHIFT                  (0U)
#define SCT_MATCHL_MATCHL(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_MATCHL_MATCHL_SHIFT)) & SCT_MATCHL_MATCHL_MASK)
/*! @} */

/* The count of SCT_MATCHL */
#define SCT_MATCHL_COUNT                         (10U)

/*! @name MATCHH - SCT_MATCHH register */
/*! @{ */

#define SCT_MATCHH_MATCHH_MASK                   (0xFFFFU)
#define SCT_MATCHH_MATCHH_SHIFT                  (0U)
#define SCT_MATCHH_MATCHH(x)                     (((uint16_t)(((uint16_t)(x)) << SCT_MATCHH_MATCHH_SHIFT)) & SCT_MATCHH_MATCHH_MASK)
/*! @} */

/* The count of SCT_MATCHH */
#define SCT_MATCHH_COUNT                         (10U)

/*! @name MATCH - SCT match value register of match channels */
/*! @{ */

#define SCT_MATCH_MATCHn_L_MASK                  (0xFFFFU)
#define SCT_MATCH_MATCHn_L_SHIFT                 (0U)
/*! MATCHn_L - When UNIFY = 0, read or write the 16-bit value to be compared to the L counter. When
 *    UNIFY = 1, read or write the lower 16 bits of the 32-bit value to be compared to the unified
 *    counter.
 */
#define SCT_MATCH_MATCHn_L(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_MATCH_MATCHn_L_SHIFT)) & SCT_MATCH_MATCHn_L_MASK)

#define SCT_MATCH_MATCHn_H_MASK                  (0xFFFF0000U)
#define SCT_MATCH_MATCHn_H_SHIFT                 (16U)
/*! MATCHn_H - When UNIFY = 0, read or write the 16-bit value to be compared to the H counter. When
 *    UNIFY = 1, read or write the upper 16 bits of the 32-bit value to be compared to the unified
 *    counter.
 */
#define SCT_MATCH_MATCHn_H(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_MATCH_MATCHn_H_SHIFT)) & SCT_MATCH_MATCHn_H_MASK)
/*! @} */

/* The count of SCT_MATCH */
#define SCT_MATCH_COUNT                          (10U)

/*! @name CAPCTRLL - SCT_CAPCTRLL register */
/*! @{ */

#define SCT_CAPCTRLL_CAPCTRLL_MASK               (0xFFFFU)
#define SCT_CAPCTRLL_CAPCTRLL_SHIFT              (0U)
#define SCT_CAPCTRLL_CAPCTRLL(x)                 (((uint16_t)(((uint16_t)(x)) << SCT_CAPCTRLL_CAPCTRLL_SHIFT)) & SCT_CAPCTRLL_CAPCTRLL_MASK)
/*! @} */

/* The count of SCT_CAPCTRLL */
#define SCT_CAPCTRLL_COUNT                       (10U)

/*! @name CAPCTRLH - SCT_CAPCTRLH register */
/*! @{ */

#define SCT_CAPCTRLH_CAPCTRLH_MASK               (0xFFFFU)
#define SCT_CAPCTRLH_CAPCTRLH_SHIFT              (0U)
#define SCT_CAPCTRLH_CAPCTRLH(x)                 (((uint16_t)(((uint16_t)(x)) << SCT_CAPCTRLH_CAPCTRLH_SHIFT)) & SCT_CAPCTRLH_CAPCTRLH_MASK)
/*! @} */

/* The count of SCT_CAPCTRLH */
#define SCT_CAPCTRLH_COUNT                       (10U)

/*! @name CAPCTRL - SCT capture control register */
/*! @{ */

#define SCT_CAPCTRL_CAPCONn_L_MASK               (0xFFFFU)
#define SCT_CAPCTRL_CAPCONn_L_SHIFT              (0U)
/*! CAPCONn_L - If bit m is one, event m causes the CAPn_L (UNIFY = 0) or the CAPn (UNIFY = 1)
 *    register to be loaded (event 0 = bit 0, event 1 = bit 1, etc.). The number of bits = number of
 *    match/captures in this SCT.
 */
#define SCT_CAPCTRL_CAPCONn_L(x)                 (((uint32_t)(((uint32_t)(x)) << SCT_CAPCTRL_CAPCONn_L_SHIFT)) & SCT_CAPCTRL_CAPCONn_L_MASK)

#define SCT_CAPCTRL_CAPCONn_H_MASK               (0xFFFF0000U)
#define SCT_CAPCTRL_CAPCONn_H_SHIFT              (16U)
/*! CAPCONn_H - If bit m is one, event m causes the CAPn_H (UNIFY = 0) register to be loaded (event
 *    0 = bit 16, event 1 = bit 17, etc.). The number of bits = number of match/captures in this SCT.
 */
#define SCT_CAPCTRL_CAPCONn_H(x)                 (((uint32_t)(((uint32_t)(x)) << SCT_CAPCTRL_CAPCONn_H_SHIFT)) & SCT_CAPCTRL_CAPCONn_H_MASK)
/*! @} */

/* The count of SCT_CAPCTRL */
#define SCT_CAPCTRL_COUNT                        (10U)

/*! @name MATCHRELL - SCT_MATCHRELL register */
/*! @{ */

#define SCT_MATCHRELL_MATCHRELL_MASK             (0xFFFFU)
#define SCT_MATCHRELL_MATCHRELL_SHIFT            (0U)
#define SCT_MATCHRELL_MATCHRELL(x)               (((uint16_t)(((uint16_t)(x)) << SCT_MATCHRELL_MATCHRELL_SHIFT)) & SCT_MATCHRELL_MATCHRELL_MASK)
/*! @} */

/* The count of SCT_MATCHRELL */
#define SCT_MATCHRELL_COUNT                      (10U)

/*! @name MATCHRELH - SCT_MATCHRELH register */
/*! @{ */

#define SCT_MATCHRELH_MATCHRELH_MASK             (0xFFFFU)
#define SCT_MATCHRELH_MATCHRELH_SHIFT            (0U)
#define SCT_MATCHRELH_MATCHRELH(x)               (((uint16_t)(((uint16_t)(x)) << SCT_MATCHRELH_MATCHRELH_SHIFT)) & SCT_MATCHRELH_MATCHRELH_MASK)
/*! @} */

/* The count of SCT_MATCHRELH */
#define SCT_MATCHRELH_COUNT                      (10U)

/*! @name MATCHREL - SCT match reload value register */
/*! @{ */

#define SCT_MATCHREL_RELOADn_L_MASK              (0xFFFFU)
#define SCT_MATCHREL_RELOADn_L_SHIFT             (0U)
/*! RELOADn_L - When UNIFY = 0, specifies the 16-bit value to be loaded into the MATCHn_L register.
 *    When UNIFY = 1, specifies the lower 16 bits of the 32-bit value to be loaded into the MATCHn
 *    register.
 */
#define SCT_MATCHREL_RELOADn_L(x)                (((uint32_t)(((uint32_t)(x)) << SCT_MATCHREL_RELOADn_L_SHIFT)) & SCT_MATCHREL_RELOADn_L_MASK)

#define SCT_MATCHREL_RELOADn_H_MASK              (0xFFFF0000U)
#define SCT_MATCHREL_RELOADn_H_SHIFT             (16U)
/*! RELOADn_H - When UNIFY = 0, specifies the 16-bit to be loaded into the MATCHn_H register. When
 *    UNIFY = 1, specifies the upper 16 bits of the 32-bit value to be loaded into the MATCHn
 *    register.
 */
#define SCT_MATCHREL_RELOADn_H(x)                (((uint32_t)(((uint32_t)(x)) << SCT_MATCHREL_RELOADn_H_SHIFT)) & SCT_MATCHREL_RELOADn_H_MASK)
/*! @} */

/* The count of SCT_MATCHREL */
#define SCT_MATCHREL_COUNT                       (10U)

/*! @name STATE - SCT event state register 0 */
/*! @{ */

#define SCT_STATE_STATEMSKn_MASK                 (0xFFFFU)
#define SCT_STATE_STATEMSKn_SHIFT                (0U)
/*! STATEMSKn - If bit m is one, event n happens in state m of the counter selected by the HEVENT
 *    bit (n = event number, m = state number; state 0 = bit 0, state 1= bit 1, etc.). The number of
 *    bits = number of states in this SCT.
 */
#define SCT_STATE_STATEMSKn(x)                   (((uint32_t)(((uint32_t)(x)) << SCT_STATE_STATEMSKn_SHIFT)) & SCT_STATE_STATEMSKn_MASK)
/*! @} */

/* The count of SCT_STATE */
#define SCT_STATE_COUNT                          (10U)

/*! @name CTRL - SCT event control register 0 */
/*! @{ */

#define SCT_CTRL_MATCHSEL_MASK                   (0xFU)
#define SCT_CTRL_MATCHSEL_SHIFT                  (0U)
/*! MATCHSEL - Selects the Match register associated with this event (if any). A match can occur
 *    only when the counter selected by the HEVENT bit is running.
 */
#define SCT_CTRL_MATCHSEL(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_MATCHSEL_SHIFT)) & SCT_CTRL_MATCHSEL_MASK)

#define SCT_CTRL_HEVENT_MASK                     (0x10U)
#define SCT_CTRL_HEVENT_SHIFT                    (4U)
/*! HEVENT - Select L/H counter. Do not set this bit if UNIFY = 1.
 *  0b0..Selects the L state and the L match register selected by MATCHSEL.
 *  0b1..Selects the H state and the H match register selected by MATCHSEL.
 */
#define SCT_CTRL_HEVENT(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_HEVENT_SHIFT)) & SCT_CTRL_HEVENT_MASK)

#define SCT_CTRL_OUTSEL_MASK                     (0x20U)
#define SCT_CTRL_OUTSEL_SHIFT                    (5U)
/*! OUTSEL - Input/output select
 *  0b0..Selects the inputs selected by IOSEL.
 *  0b1..Selects the outputs selected by IOSEL.
 */
#define SCT_CTRL_OUTSEL(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_OUTSEL_SHIFT)) & SCT_CTRL_OUTSEL_MASK)

#define SCT_CTRL_IOSEL_MASK                      (0x3C0U)
#define SCT_CTRL_IOSEL_SHIFT                     (6U)
/*! IOSEL - Selects the input or output signal number associated with this event (if any). Do not
 *    select an input in this register if CKMODE is 1x. In this case the clock input is an implicit
 *    ingredient of every event.
 */
#define SCT_CTRL_IOSEL(x)                        (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_IOSEL_SHIFT)) & SCT_CTRL_IOSEL_MASK)

#define SCT_CTRL_IOCOND_MASK                     (0xC00U)
#define SCT_CTRL_IOCOND_SHIFT                    (10U)
/*! IOCOND - Selects the I/O condition for event n. (The detection of edges on outputs lag the
 *    conditions that switch the outputs by one SCT clock). In order to guarantee proper edge/state
 *    detection, an input must have a minimum pulse width of at least one SCT clock period .
 *  0b00..LOW
 *  0b01..Rise
 *  0b10..Fall
 *  0b11..HIGH
 */
#define SCT_CTRL_IOCOND(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_IOCOND_SHIFT)) & SCT_CTRL_IOCOND_MASK)

#define SCT_CTRL_COMBMODE_MASK                   (0x3000U)
#define SCT_CTRL_COMBMODE_SHIFT                  (12U)
/*! COMBMODE - Selects how the specified match and I/O condition are used and combined.
 *  0b00..OR. The event occurs when either the specified match or I/O condition occurs.
 *  0b01..MATCH. Uses the specified match only.
 *  0b10..IO. Uses the specified I/O condition only.
 *  0b11..AND. The event occurs when the specified match and I/O condition occur simultaneously.
 */
#define SCT_CTRL_COMBMODE(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_COMBMODE_SHIFT)) & SCT_CTRL_COMBMODE_MASK)

#define SCT_CTRL_STATELD_MASK                    (0x4000U)
#define SCT_CTRL_STATELD_SHIFT                   (14U)
/*! STATELD - This bit controls how the STATEV value modifies the state selected by HEVENT when this
 *    event is the highest-numbered event occurring for that state.
 *  0b0..STATEV value is added into STATE (the carry-out is ignored).
 *  0b1..STATEV value is loaded into STATE.
 */
#define SCT_CTRL_STATELD(x)                      (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_STATELD_SHIFT)) & SCT_CTRL_STATELD_MASK)

#define SCT_CTRL_STATEV_MASK                     (0xF8000U)
#define SCT_CTRL_STATEV_SHIFT                    (15U)
/*! STATEV - This value is loaded into or added to the state selected by HEVENT, depending on
 *    STATELD, when this event is the highest-numbered event occurring for that state. If STATELD and
 *    STATEV are both zero, there is no change to the STATE value.
 */
#define SCT_CTRL_STATEV(x)                       (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_STATEV_SHIFT)) & SCT_CTRL_STATEV_MASK)

#define SCT_CTRL_MATCHMEM_MASK                   (0x100000U)
#define SCT_CTRL_MATCHMEM_SHIFT                  (20U)
/*! MATCHMEM - If this bit is one and the COMBMODE field specifies a match component to the
 *    triggering of this event, then a match is considered to be active whenever the counter value is
 *    GREATER THAN OR EQUAL TO the value specified in the match register when counting up, LESS THEN OR
 *    EQUAL TO the match value when counting down. If this bit is zero, a match is only be active
 *    during the cycle when the counter is equal to the match value.
 */
#define SCT_CTRL_MATCHMEM(x)                     (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_MATCHMEM_SHIFT)) & SCT_CTRL_MATCHMEM_MASK)

#define SCT_CTRL_DIRECTION_MASK                  (0x600000U)
#define SCT_CTRL_DIRECTION_SHIFT                 (21U)
/*! DIRECTION - Direction qualifier for event generation. This field only applies when the counters
 *    are operating in BIDIR mode. If BIDIR = 0, the SCT ignores this field. Value 0x3 is reserved.
 *  0b00..Direction independent. This event is triggered regardless of the count direction.
 *  0b01..Counting up. This event is triggered only during up-counting when BIDIR = 1.
 *  0b10..Counting down. This event is triggered only during down-counting when BIDIR = 1.
 */
#define SCT_CTRL_DIRECTION(x)                    (((uint32_t)(((uint32_t)(x)) << SCT_CTRL_DIRECTION_SHIFT)) & SCT_CTRL_DIRECTION_MASK)
/*! @} */

/* The count of SCT_CTRL */
#define SCT_CTRL_COUNT                           (10U)

/*! @name SET - SCT output 0 set register */
/*! @{ */

#define SCT_SET_SET_MASK                         (0xFFFFU)
#define SCT_SET_SET_SHIFT                        (0U)
/*! SET - A 1 in bit m selects event m to set output n (or clear it if SETCLRn = 0x1 or 0x2) output
 *    0 = bit 0, output 1 = bit 1, etc. The number of bits = number of events in this SCT. When the
 *    counter is used in bi-directional mode, it is possible to reverse the action specified by the
 *    output set and clear registers when counting down, See the OUTPUTCTRL register.
 */
#define SCT_SET_SET(x)                           (((uint32_t)(((uint32_t)(x)) << SCT_SET_SET_SHIFT)) & SCT_SET_SET_MASK)
/*! @} */

/* The count of SCT_SET */
#define SCT_SET_COUNT                            (10U)

/*! @name CLR - SCT output 0 clear register */
/*! @{ */

#define SCT_CLR_CLR_MASK                         (0xFFFFU)
#define SCT_CLR_CLR_SHIFT                        (0U)
/*! CLR - A 1 in bit m selects event m to clear output n (or set it if SETCLRn = 0x1 or 0x2) event 0
 *    = bit 0, event 1 = bit 1, etc. The number of bits = number of events in this SCT. When the
 *    counter is used in bi-directional mode, it is possible to reverse the action specified by the
 *    output set and clear registers when counting down, See the OUTPUTCTRL register.
 */
#define SCT_CLR_CLR(x)                           (((uint32_t)(((uint32_t)(x)) << SCT_CLR_CLR_SHIFT)) & SCT_CLR_CLR_MASK)
/*! @} */

/* The count of SCT_CLR */
#define SCT_CLR_COUNT                            (10U)


/*!
 * @}
 */ /* end of group SCT_Register_Masks */


/* SCT - Peripheral instance base addresses */
/** Peripheral SCT base address */
#define SCT_BASE                                 (0x40021000u)
/** Peripheral SCT base pointer */
#define SCT                                      ((SCT_Type *)SCT_BASE)
/** Array initializer of SCT peripheral base addresses */
#define SCT_BASE_ADDRS                           { SCT_BASE }
/** Array initializer of SCT peripheral base pointers */
#define SCT_BASE_PTRS                            { SCT }
/** Interrupt vectors for the SCT peripheral type */
#define SCT_IRQS                                 { SCT_IRQn }
/* Backward compatibility */
#define SCT_EV_STATE_STATEMSKn_MASK              SCT_STATE_STATEMSKn_MASK
#define SCT_EV_STATE_STATEMSKn_SHIFT             SCT_STATE_STATEMSKn_SHIFT
#define SCT_EV_STATE_STATEMSKn(x)                SCT_STATE_STATEMSKn(x)
#define SCT_EV_STATE_COUNT                       SCT_STATE_COUNT
#define SCT_EV_CTRL_MATCHSEL_MASK                SCT_CTRL_MATCHSEL_MASK
#define SCT_EV_CTRL_MATCHSEL_SHIFT               SCT_CTRL_MATCHSEL_SHIFT
#define SCT_EV_CTRL_MATCHSEL(x)                  SCT_CTRL_MATCHSEL(x)
#define SCT_EV_CTRL_HEVENT_MASK                  SCT_CTRL_HEVENT_MASK
#define SCT_EV_CTRL_HEVENT_SHIFT                 SCT_CTRL_HEVENT_SHIFT
#define SCT_EV_CTRL_HEVENT(x)                    SCT_CTRL_HEVENT(x)
#define SCT_EV_CTRL_OUTSEL_MASK                  SCT_CTRL_OUTSEL_MASK
#define SCT_EV_CTRL_OUTSEL_SHIFT                 SCT_CTRL_OUTSEL_SHIFT
#define SCT_EV_CTRL_OUTSEL(x)                    SCT_CTRL_OUTSEL(x)
#define SCT_EV_CTRL_IOSEL_MASK                   SCT_CTRL_IOSEL_MASK
#define SCT_EV_CTRL_IOSEL_SHIFT                  SCT_CTRL_IOSEL_SHIFT
#define SCT_EV_CTRL_IOSEL(x)                     SCT_CTRL_IOSEL(x)
#define SCT_EV_CTRL_IOCOND_MASK                  SCT_CTRL_IOCOND_MASK
#define SCT_EV_CTRL_IOCOND_SHIFT                 SCT_CTRL_IOCOND_SHIFT
#define SCT_EV_CTRL_IOCOND(x)                    SCT_CTRL_IOCOND(x)
#define SCT_EV_CTRL_COMBMODE_MASK                SCT_CTRL_COMBMODE_MASK
#define SCT_EV_CTRL_COMBMODE_SHIFT               SCT_CTRL_COMBMODE_SHIFT
#define SCT_EV_CTRL_COMBMODE(x)                  SCT_CTRL_COMBMODE(x)
#define SCT_EV_CTRL_STATELD_MASK                 SCT_CTRL_STATELD_MASK
#define SCT_EV_CTRL_STATELD_SHIFT                SCT_CTRL_STATELD_SHIFT
#define SCT_EV_CTRL_STATELD(x)                   SCT_CTRL_STATELD(x)
#define SCT_EV_CTRL_STATEV_MASK                  SCT_CTRL_STATEV_MASK
#define SCT_EV_CTRL_STATEV_SHIFT                 SCT_CTRL_STATEV_SHIFT
#define SCT_EV_CTRL_STATEV(x)                    SCT_CTRL_STATEV(x)
#define SCT_EV_CTRL_MATCHMEM_MASK                SCT_CTRL_MATCHMEM_MASK
#define SCT_EV_CTRL_MATCHMEM_SHIFT               SCT_CTRL_MATCHMEM_SHIFT
#define SCT_EV_CTRL_MATCHMEM(x)                  SCT_CTRL_MATCHMEM(x)
#define SCT_EV_CTRL_DIRECTION_MASK               SCT_CTRL_DIRECTION_MASK
#define SCT_EV_CTRL_DIRECTION_SHIFT              SCT_CTRL_DIRECTION_SHIFT
#define SCT_EV_CTRL_DIRECTION(x)                 SCT_CTRL_DIRECTION(x)
#define SCT_EV_CTRL_COUNT                        SCT_CTRL_COUNT
#define SCT_OUT_SET_SET_MASK                     SCT_SET_SET_MASK
#define SCT_OUT_SET_SET_SHIFT                    SCT_SET_SET_SHIFT
#define SCT_OUT_SET_SET(x)                       SCT_SET_SET(x)
#define SCT_OUT_SET_COUNT                        SCT_SET_COUNT
#define SCT_OUT_CLR_CLR_MASK                     SCT_CLR_CLR_MASK
#define SCT_OUT_CLR_CLR_SHIFT                    SCT_CLR_CLR_SHIFT
#define SCT_OUT_CLR_CLR(x)                       SCT_CLR_CLR(x)
#define SCT_OUT_CLR_COUNT                        SCT_CLR_COUNT


/*!
 * @}
 */ /* end of group SCT_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- SPI Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SPI_Peripheral_Access_Layer SPI Peripheral Access Layer
 * @{
 */

/** SPI - Register Layout Typedef */
typedef struct {
       uint8_t RESERVED_0[1024];
  __IO uint32_t CFG;                               /**< , offset: 0x400 */
  __IO uint32_t DLY;                               /**< , offset: 0x404 */
  __IO uint32_t STAT;                              /**< , offset: 0x408 */
  __IO uint32_t INTENSET;                          /**< , offset: 0x40C */
  __O  uint32_t INTENCLR;                          /**< , offset: 0x410 */
  __I  uint32_t RXDAT;                             /**< , offset: 0x414 */
  __IO uint32_t TXDATCTL;                          /**< , offset: 0x418 */
  __IO uint32_t TXDAT;                             /**< , offset: 0x41C */
  __IO uint32_t TXCTL;                             /**< , offset: 0x420 */
  __IO uint32_t DIV;                               /**< , offset: 0x424 */
  __I  uint32_t INTSTAT;                           /**< , offset: 0x428 */
       uint8_t RESERVED_1[2516];
  __IO uint32_t FIFOCFG;                           /**< , offset: 0xE00 */
  __IO uint32_t FIFOSTAT;                          /**< , offset: 0xE04 */
  __IO uint32_t FIFOTRIG;                          /**< , offset: 0xE08 */
       uint8_t RESERVED_2[4];
  __IO uint32_t FIFOINTENSET;                      /**< , offset: 0xE10 */
  __O  uint32_t FIFOINTENCLR;                      /**< , offset: 0xE14 */
  __I  uint32_t FIFOINTSTAT;                       /**< , offset: 0xE18 */
       uint8_t RESERVED_3[4];
  __O  uint32_t FIFOWR;                            /**< , offset: 0xE20 */
       uint8_t RESERVED_4[12];
  __I  uint32_t FIFORD;                            /**< , offset: 0xE30 */
       uint8_t RESERVED_5[12];
  __I  uint32_t FIFORDNOPOP;                       /**< , offset: 0xE40 */
       uint8_t RESERVED_6[436];
  __IO uint32_t SELID;                             /**< , offset: 0xFF8 */
  __I  uint32_t ID;                                /**< , offset: 0xFFC */
} SPI_Type;

/* ----------------------------------------------------------------------------
   -- SPI Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SPI_Register_Masks SPI Register Masks
 * @{
 */

/*! @name CFG -  */
/*! @{ */

#define SPI_CFG_ENABLE_MASK                      (0x1U)
#define SPI_CFG_ENABLE_SHIFT                     (0U)
#define SPI_CFG_ENABLE(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_CFG_ENABLE_SHIFT)) & SPI_CFG_ENABLE_MASK)

#define SPI_CFG_MASTER_MASK                      (0x4U)
#define SPI_CFG_MASTER_SHIFT                     (2U)
#define SPI_CFG_MASTER(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_CFG_MASTER_SHIFT)) & SPI_CFG_MASTER_MASK)

#define SPI_CFG_LSBF_MASK                        (0x8U)
#define SPI_CFG_LSBF_SHIFT                       (3U)
#define SPI_CFG_LSBF(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_CFG_LSBF_SHIFT)) & SPI_CFG_LSBF_MASK)

#define SPI_CFG_CPHA_MASK                        (0x10U)
#define SPI_CFG_CPHA_SHIFT                       (4U)
#define SPI_CFG_CPHA(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_CFG_CPHA_SHIFT)) & SPI_CFG_CPHA_MASK)

#define SPI_CFG_CPOL_MASK                        (0x20U)
#define SPI_CFG_CPOL_SHIFT                       (5U)
#define SPI_CFG_CPOL(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_CFG_CPOL_SHIFT)) & SPI_CFG_CPOL_MASK)

#define SPI_CFG_LOOP_MASK                        (0x80U)
#define SPI_CFG_LOOP_SHIFT                       (7U)
#define SPI_CFG_LOOP(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_CFG_LOOP_SHIFT)) & SPI_CFG_LOOP_MASK)

#define SPI_CFG_SPOL0_MASK                       (0x100U)
#define SPI_CFG_SPOL0_SHIFT                      (8U)
#define SPI_CFG_SPOL0(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_CFG_SPOL0_SHIFT)) & SPI_CFG_SPOL0_MASK)

#define SPI_CFG_SPOL1_MASK                       (0x200U)
#define SPI_CFG_SPOL1_SHIFT                      (9U)
#define SPI_CFG_SPOL1(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_CFG_SPOL1_SHIFT)) & SPI_CFG_SPOL1_MASK)

#define SPI_CFG_SPOL2_MASK                       (0x400U)
#define SPI_CFG_SPOL2_SHIFT                      (10U)
#define SPI_CFG_SPOL2(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_CFG_SPOL2_SHIFT)) & SPI_CFG_SPOL2_MASK)

#define SPI_CFG_SPOL3_MASK                       (0x800U)
#define SPI_CFG_SPOL3_SHIFT                      (11U)
#define SPI_CFG_SPOL3(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_CFG_SPOL3_SHIFT)) & SPI_CFG_SPOL3_MASK)
/*! @} */

/*! @name DLY -  */
/*! @{ */

#define SPI_DLY_PRE_DELAY_MASK                   (0xFU)
#define SPI_DLY_PRE_DELAY_SHIFT                  (0U)
#define SPI_DLY_PRE_DELAY(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_DLY_PRE_DELAY_SHIFT)) & SPI_DLY_PRE_DELAY_MASK)

#define SPI_DLY_POST_DELAY_MASK                  (0xF0U)
#define SPI_DLY_POST_DELAY_SHIFT                 (4U)
#define SPI_DLY_POST_DELAY(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_DLY_POST_DELAY_SHIFT)) & SPI_DLY_POST_DELAY_MASK)

#define SPI_DLY_FRAME_DELAY_MASK                 (0xF00U)
#define SPI_DLY_FRAME_DELAY_SHIFT                (8U)
#define SPI_DLY_FRAME_DELAY(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_DLY_FRAME_DELAY_SHIFT)) & SPI_DLY_FRAME_DELAY_MASK)

#define SPI_DLY_TRANSFER_DELAY_MASK              (0xF000U)
#define SPI_DLY_TRANSFER_DELAY_SHIFT             (12U)
#define SPI_DLY_TRANSFER_DELAY(x)                (((uint32_t)(((uint32_t)(x)) << SPI_DLY_TRANSFER_DELAY_SHIFT)) & SPI_DLY_TRANSFER_DELAY_MASK)
/*! @} */

/*! @name STAT -  */
/*! @{ */

#define SPI_STAT_RXRDY_MASK                      (0x1U)
#define SPI_STAT_RXRDY_SHIFT                     (0U)
#define SPI_STAT_RXRDY(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_STAT_RXRDY_SHIFT)) & SPI_STAT_RXRDY_MASK)

#define SPI_STAT_TXRDY_MASK                      (0x2U)
#define SPI_STAT_TXRDY_SHIFT                     (1U)
#define SPI_STAT_TXRDY(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_STAT_TXRDY_SHIFT)) & SPI_STAT_TXRDY_MASK)

#define SPI_STAT_RXOV_MASK                       (0x4U)
#define SPI_STAT_RXOV_SHIFT                      (2U)
#define SPI_STAT_RXOV(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_STAT_RXOV_SHIFT)) & SPI_STAT_RXOV_MASK)

#define SPI_STAT_TXUR_MASK                       (0x8U)
#define SPI_STAT_TXUR_SHIFT                      (3U)
#define SPI_STAT_TXUR(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_STAT_TXUR_SHIFT)) & SPI_STAT_TXUR_MASK)

#define SPI_STAT_SSA_MASK                        (0x10U)
#define SPI_STAT_SSA_SHIFT                       (4U)
#define SPI_STAT_SSA(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_STAT_SSA_SHIFT)) & SPI_STAT_SSA_MASK)

#define SPI_STAT_SSD_MASK                        (0x20U)
#define SPI_STAT_SSD_SHIFT                       (5U)
#define SPI_STAT_SSD(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_STAT_SSD_SHIFT)) & SPI_STAT_SSD_MASK)

#define SPI_STAT_STALLED_MASK                    (0x40U)
#define SPI_STAT_STALLED_SHIFT                   (6U)
#define SPI_STAT_STALLED(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_STAT_STALLED_SHIFT)) & SPI_STAT_STALLED_MASK)

#define SPI_STAT_ENDTRASNFER_MASK                (0x80U)
#define SPI_STAT_ENDTRASNFER_SHIFT               (7U)
#define SPI_STAT_ENDTRASNFER(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_STAT_ENDTRASNFER_SHIFT)) & SPI_STAT_ENDTRASNFER_MASK)

#define SPI_STAT_MSTIDLE_MASK                    (0x100U)
#define SPI_STAT_MSTIDLE_SHIFT                   (8U)
#define SPI_STAT_MSTIDLE(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_STAT_MSTIDLE_SHIFT)) & SPI_STAT_MSTIDLE_MASK)
/*! @} */

/*! @name INTENSET -  */
/*! @{ */

#define SPI_INTENSET_RXRDYEN_MASK                (0x1U)
#define SPI_INTENSET_RXRDYEN_SHIFT               (0U)
#define SPI_INTENSET_RXRDYEN(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_RXRDYEN_SHIFT)) & SPI_INTENSET_RXRDYEN_MASK)

#define SPI_INTENSET_TXRDYEN_MASK                (0x2U)
#define SPI_INTENSET_TXRDYEN_SHIFT               (1U)
#define SPI_INTENSET_TXRDYEN(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_TXRDYEN_SHIFT)) & SPI_INTENSET_TXRDYEN_MASK)

#define SPI_INTENSET_RXOVEN_MASK                 (0x4U)
#define SPI_INTENSET_RXOVEN_SHIFT                (2U)
#define SPI_INTENSET_RXOVEN(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_RXOVEN_SHIFT)) & SPI_INTENSET_RXOVEN_MASK)

#define SPI_INTENSET_TXUREN_MASK                 (0x8U)
#define SPI_INTENSET_TXUREN_SHIFT                (3U)
#define SPI_INTENSET_TXUREN(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_TXUREN_SHIFT)) & SPI_INTENSET_TXUREN_MASK)

#define SPI_INTENSET_SSAEN_MASK                  (0x10U)
#define SPI_INTENSET_SSAEN_SHIFT                 (4U)
#define SPI_INTENSET_SSAEN(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_SSAEN_SHIFT)) & SPI_INTENSET_SSAEN_MASK)

#define SPI_INTENSET_SSDEN_MASK                  (0x20U)
#define SPI_INTENSET_SSDEN_SHIFT                 (5U)
#define SPI_INTENSET_SSDEN(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_SSDEN_SHIFT)) & SPI_INTENSET_SSDEN_MASK)

#define SPI_INTENSET_MSTIDLEEN_MASK              (0x100U)
#define SPI_INTENSET_MSTIDLEEN_SHIFT             (8U)
#define SPI_INTENSET_MSTIDLEEN(x)                (((uint32_t)(((uint32_t)(x)) << SPI_INTENSET_MSTIDLEEN_SHIFT)) & SPI_INTENSET_MSTIDLEEN_MASK)
/*! @} */

/*! @name INTENCLR -  */
/*! @{ */

#define SPI_INTENCLR_RXRDYEN_MASK                (0x1U)
#define SPI_INTENCLR_RXRDYEN_SHIFT               (0U)
#define SPI_INTENCLR_RXRDYEN(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_RXRDYEN_SHIFT)) & SPI_INTENCLR_RXRDYEN_MASK)

#define SPI_INTENCLR_TXRDYEN_MASK                (0x2U)
#define SPI_INTENCLR_TXRDYEN_SHIFT               (1U)
#define SPI_INTENCLR_TXRDYEN(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_TXRDYEN_SHIFT)) & SPI_INTENCLR_TXRDYEN_MASK)

#define SPI_INTENCLR_RXOVEN_MASK                 (0x4U)
#define SPI_INTENCLR_RXOVEN_SHIFT                (2U)
#define SPI_INTENCLR_RXOVEN(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_RXOVEN_SHIFT)) & SPI_INTENCLR_RXOVEN_MASK)

#define SPI_INTENCLR_TXUREN_MASK                 (0x8U)
#define SPI_INTENCLR_TXUREN_SHIFT                (3U)
#define SPI_INTENCLR_TXUREN(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_TXUREN_SHIFT)) & SPI_INTENCLR_TXUREN_MASK)

#define SPI_INTENCLR_SSAEN_MASK                  (0x10U)
#define SPI_INTENCLR_SSAEN_SHIFT                 (4U)
#define SPI_INTENCLR_SSAEN(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_SSAEN_SHIFT)) & SPI_INTENCLR_SSAEN_MASK)

#define SPI_INTENCLR_SSDEN_MASK                  (0x20U)
#define SPI_INTENCLR_SSDEN_SHIFT                 (5U)
#define SPI_INTENCLR_SSDEN(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_SSDEN_SHIFT)) & SPI_INTENCLR_SSDEN_MASK)

#define SPI_INTENCLR_MSTIDLEEN_MASK              (0x100U)
#define SPI_INTENCLR_MSTIDLEEN_SHIFT             (8U)
#define SPI_INTENCLR_MSTIDLEEN(x)                (((uint32_t)(((uint32_t)(x)) << SPI_INTENCLR_MSTIDLEEN_SHIFT)) & SPI_INTENCLR_MSTIDLEEN_MASK)
/*! @} */

/*! @name RXDAT -  */
/*! @{ */

#define SPI_RXDAT_RXDATA_MASK                    (0xFFFFU)
#define SPI_RXDAT_RXDATA_SHIFT                   (0U)
#define SPI_RXDAT_RXDATA(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_RXDAT_RXDATA_SHIFT)) & SPI_RXDAT_RXDATA_MASK)

#define SPI_RXDAT_RXSSELN_MASK                   (0xF0000U)
#define SPI_RXDAT_RXSSELN_SHIFT                  (16U)
#define SPI_RXDAT_RXSSELN(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_RXDAT_RXSSELN_SHIFT)) & SPI_RXDAT_RXSSELN_MASK)

#define SPI_RXDAT_SOT_MASK                       (0x100000U)
#define SPI_RXDAT_SOT_SHIFT                      (20U)
#define SPI_RXDAT_SOT(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_RXDAT_SOT_SHIFT)) & SPI_RXDAT_SOT_MASK)
/*! @} */

/*! @name TXDATCTL -  */
/*! @{ */

#define SPI_TXDATCTL_TXDATA_MASK                 (0xFFFFU)
#define SPI_TXDATCTL_TXDATA_SHIFT                (0U)
#define SPI_TXDATCTL_TXDATA(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_TXDATA_SHIFT)) & SPI_TXDATCTL_TXDATA_MASK)

#define SPI_TXDATCTL_TXSSELN0_MASK               (0x10000U)
#define SPI_TXDATCTL_TXSSELN0_SHIFT              (16U)
#define SPI_TXDATCTL_TXSSELN0(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_TXSSELN0_SHIFT)) & SPI_TXDATCTL_TXSSELN0_MASK)

#define SPI_TXDATCTL_TXSSELN1_MASK               (0x20000U)
#define SPI_TXDATCTL_TXSSELN1_SHIFT              (17U)
#define SPI_TXDATCTL_TXSSELN1(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_TXSSELN1_SHIFT)) & SPI_TXDATCTL_TXSSELN1_MASK)

#define SPI_TXDATCTL_TXSSELN2_MASK               (0x40000U)
#define SPI_TXDATCTL_TXSSELN2_SHIFT              (18U)
#define SPI_TXDATCTL_TXSSELN2(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_TXSSELN2_SHIFT)) & SPI_TXDATCTL_TXSSELN2_MASK)

#define SPI_TXDATCTL_TXSSELN3_MASK               (0x80000U)
#define SPI_TXDATCTL_TXSSELN3_SHIFT              (19U)
#define SPI_TXDATCTL_TXSSELN3(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_TXSSELN3_SHIFT)) & SPI_TXDATCTL_TXSSELN3_MASK)

#define SPI_TXDATCTL_EOT_MASK                    (0x100000U)
#define SPI_TXDATCTL_EOT_SHIFT                   (20U)
#define SPI_TXDATCTL_EOT(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_EOT_SHIFT)) & SPI_TXDATCTL_EOT_MASK)

#define SPI_TXDATCTL_EOF_MASK                    (0x200000U)
#define SPI_TXDATCTL_EOF_SHIFT                   (21U)
#define SPI_TXDATCTL_EOF(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_EOF_SHIFT)) & SPI_TXDATCTL_EOF_MASK)

#define SPI_TXDATCTL_RXIGNORE_MASK               (0x400000U)
#define SPI_TXDATCTL_RXIGNORE_SHIFT              (22U)
#define SPI_TXDATCTL_RXIGNORE(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_RXIGNORE_SHIFT)) & SPI_TXDATCTL_RXIGNORE_MASK)

#define SPI_TXDATCTL_FLEN_MASK                   (0xF000000U)
#define SPI_TXDATCTL_FLEN_SHIFT                  (24U)
#define SPI_TXDATCTL_FLEN(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_TXDATCTL_FLEN_SHIFT)) & SPI_TXDATCTL_FLEN_MASK)
/*! @} */

/*! @name TXDAT -  */
/*! @{ */

#define SPI_TXDAT_TXDATA_MASK                    (0xFFFFU)
#define SPI_TXDAT_TXDATA_SHIFT                   (0U)
#define SPI_TXDAT_TXDATA(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_TXDAT_TXDATA_SHIFT)) & SPI_TXDAT_TXDATA_MASK)
/*! @} */

/*! @name TXCTL -  */
/*! @{ */

#define SPI_TXCTL_TXSSELN_MASK                   (0xFU)
#define SPI_TXCTL_TXSSELN_SHIFT                  (0U)
#define SPI_TXCTL_TXSSELN(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_TXCTL_TXSSELN_SHIFT)) & SPI_TXCTL_TXSSELN_MASK)

#define SPI_TXCTL_EOT_MASK                       (0x10U)
#define SPI_TXCTL_EOT_SHIFT                      (4U)
#define SPI_TXCTL_EOT(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_TXCTL_EOT_SHIFT)) & SPI_TXCTL_EOT_MASK)

#define SPI_TXCTL_EOF_MASK                       (0x20U)
#define SPI_TXCTL_EOF_SHIFT                      (5U)
#define SPI_TXCTL_EOF(x)                         (((uint32_t)(((uint32_t)(x)) << SPI_TXCTL_EOF_SHIFT)) & SPI_TXCTL_EOF_MASK)

#define SPI_TXCTL_RXIGNORE_MASK                  (0x40U)
#define SPI_TXCTL_RXIGNORE_SHIFT                 (6U)
#define SPI_TXCTL_RXIGNORE(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_TXCTL_RXIGNORE_SHIFT)) & SPI_TXCTL_RXIGNORE_MASK)

#define SPI_TXCTL_FLEN_MASK                      (0xF00U)
#define SPI_TXCTL_FLEN_SHIFT                     (8U)
#define SPI_TXCTL_FLEN(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_TXCTL_FLEN_SHIFT)) & SPI_TXCTL_FLEN_MASK)
/*! @} */

/*! @name DIV -  */
/*! @{ */

#define SPI_DIV_DIVVAL_MASK                      (0xFFFFU)
#define SPI_DIV_DIVVAL_SHIFT                     (0U)
#define SPI_DIV_DIVVAL(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_DIV_DIVVAL_SHIFT)) & SPI_DIV_DIVVAL_MASK)
/*! @} */

/*! @name INTSTAT -  */
/*! @{ */

#define SPI_INTSTAT_RXRDY_MASK                   (0x1U)
#define SPI_INTSTAT_RXRDY_SHIFT                  (0U)
#define SPI_INTSTAT_RXRDY(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_RXRDY_SHIFT)) & SPI_INTSTAT_RXRDY_MASK)

#define SPI_INTSTAT_TXRDY_MASK                   (0x2U)
#define SPI_INTSTAT_TXRDY_SHIFT                  (1U)
#define SPI_INTSTAT_TXRDY(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_TXRDY_SHIFT)) & SPI_INTSTAT_TXRDY_MASK)

#define SPI_INTSTAT_RXOV_MASK                    (0x4U)
#define SPI_INTSTAT_RXOV_SHIFT                   (2U)
#define SPI_INTSTAT_RXOV(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_RXOV_SHIFT)) & SPI_INTSTAT_RXOV_MASK)

#define SPI_INTSTAT_TXUR_MASK                    (0x8U)
#define SPI_INTSTAT_TXUR_SHIFT                   (3U)
#define SPI_INTSTAT_TXUR(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_TXUR_SHIFT)) & SPI_INTSTAT_TXUR_MASK)

#define SPI_INTSTAT_SSA_MASK                     (0x10U)
#define SPI_INTSTAT_SSA_SHIFT                    (4U)
#define SPI_INTSTAT_SSA(x)                       (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_SSA_SHIFT)) & SPI_INTSTAT_SSA_MASK)

#define SPI_INTSTAT_SSD_MASK                     (0x20U)
#define SPI_INTSTAT_SSD_SHIFT                    (5U)
#define SPI_INTSTAT_SSD(x)                       (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_SSD_SHIFT)) & SPI_INTSTAT_SSD_MASK)

#define SPI_INTSTAT_MSTIDLE_MASK                 (0x100U)
#define SPI_INTSTAT_MSTIDLE_SHIFT                (8U)
#define SPI_INTSTAT_MSTIDLE(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_INTSTAT_MSTIDLE_SHIFT)) & SPI_INTSTAT_MSTIDLE_MASK)
/*! @} */

/*! @name FIFOCFG -  */
/*! @{ */

#define SPI_FIFOCFG_ENABLETX_MASK                (0x1U)
#define SPI_FIFOCFG_ENABLETX_SHIFT               (0U)
#define SPI_FIFOCFG_ENABLETX(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_ENABLETX_SHIFT)) & SPI_FIFOCFG_ENABLETX_MASK)

#define SPI_FIFOCFG_ENABLERX_MASK                (0x2U)
#define SPI_FIFOCFG_ENABLERX_SHIFT               (1U)
#define SPI_FIFOCFG_ENABLERX(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_ENABLERX_SHIFT)) & SPI_FIFOCFG_ENABLERX_MASK)

#define SPI_FIFOCFG_SIZE_MASK                    (0x30U)
#define SPI_FIFOCFG_SIZE_SHIFT                   (4U)
#define SPI_FIFOCFG_SIZE(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_SIZE_SHIFT)) & SPI_FIFOCFG_SIZE_MASK)

#define SPI_FIFOCFG_DMATX_MASK                   (0x1000U)
#define SPI_FIFOCFG_DMATX_SHIFT                  (12U)
#define SPI_FIFOCFG_DMATX(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_DMATX_SHIFT)) & SPI_FIFOCFG_DMATX_MASK)

#define SPI_FIFOCFG_DMARX_MASK                   (0x2000U)
#define SPI_FIFOCFG_DMARX_SHIFT                  (13U)
#define SPI_FIFOCFG_DMARX(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_DMARX_SHIFT)) & SPI_FIFOCFG_DMARX_MASK)

#define SPI_FIFOCFG_WAKETX_MASK                  (0x4000U)
#define SPI_FIFOCFG_WAKETX_SHIFT                 (14U)
#define SPI_FIFOCFG_WAKETX(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_WAKETX_SHIFT)) & SPI_FIFOCFG_WAKETX_MASK)

#define SPI_FIFOCFG_WAKERX_MASK                  (0x8000U)
#define SPI_FIFOCFG_WAKERX_SHIFT                 (15U)
#define SPI_FIFOCFG_WAKERX(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_WAKERX_SHIFT)) & SPI_FIFOCFG_WAKERX_MASK)

#define SPI_FIFOCFG_EMPTYTX_MASK                 (0x10000U)
#define SPI_FIFOCFG_EMPTYTX_SHIFT                (16U)
#define SPI_FIFOCFG_EMPTYTX(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_EMPTYTX_SHIFT)) & SPI_FIFOCFG_EMPTYTX_MASK)

#define SPI_FIFOCFG_EMPTYRX_MASK                 (0x20000U)
#define SPI_FIFOCFG_EMPTYRX_SHIFT                (17U)
#define SPI_FIFOCFG_EMPTYRX(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFOCFG_EMPTYRX_SHIFT)) & SPI_FIFOCFG_EMPTYRX_MASK)
/*! @} */

/*! @name FIFOSTAT -  */
/*! @{ */

#define SPI_FIFOSTAT_TXERR_MASK                  (0x1U)
#define SPI_FIFOSTAT_TXERR_SHIFT                 (0U)
#define SPI_FIFOSTAT_TXERR(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_TXERR_SHIFT)) & SPI_FIFOSTAT_TXERR_MASK)

#define SPI_FIFOSTAT_RXERR_MASK                  (0x2U)
#define SPI_FIFOSTAT_RXERR_SHIFT                 (1U)
#define SPI_FIFOSTAT_RXERR(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_RXERR_SHIFT)) & SPI_FIFOSTAT_RXERR_MASK)

#define SPI_FIFOSTAT_PERINT_MASK                 (0x8U)
#define SPI_FIFOSTAT_PERINT_SHIFT                (3U)
#define SPI_FIFOSTAT_PERINT(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_PERINT_SHIFT)) & SPI_FIFOSTAT_PERINT_MASK)

#define SPI_FIFOSTAT_TXEMPTY_MASK                (0x10U)
#define SPI_FIFOSTAT_TXEMPTY_SHIFT               (4U)
#define SPI_FIFOSTAT_TXEMPTY(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_TXEMPTY_SHIFT)) & SPI_FIFOSTAT_TXEMPTY_MASK)

#define SPI_FIFOSTAT_TXNOFULL_MASK               (0x20U)
#define SPI_FIFOSTAT_TXNOFULL_SHIFT              (5U)
#define SPI_FIFOSTAT_TXNOFULL(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_TXNOFULL_SHIFT)) & SPI_FIFOSTAT_TXNOFULL_MASK)

#define SPI_FIFOSTAT_RXNOTEMPTY_MASK             (0x40U)
#define SPI_FIFOSTAT_RXNOTEMPTY_SHIFT            (6U)
#define SPI_FIFOSTAT_RXNOTEMPTY(x)               (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_RXNOTEMPTY_SHIFT)) & SPI_FIFOSTAT_RXNOTEMPTY_MASK)

#define SPI_FIFOSTAT_RXFULL_MASK                 (0x80U)
#define SPI_FIFOSTAT_RXFULL_SHIFT                (7U)
#define SPI_FIFOSTAT_RXFULL(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_RXFULL_SHIFT)) & SPI_FIFOSTAT_RXFULL_MASK)

#define SPI_FIFOSTAT_TXLVL_MASK                  (0x1F00U)
#define SPI_FIFOSTAT_TXLVL_SHIFT                 (8U)
#define SPI_FIFOSTAT_TXLVL(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_TXLVL_SHIFT)) & SPI_FIFOSTAT_TXLVL_MASK)

#define SPI_FIFOSTAT_RXLVL_MASK                  (0x1F0000U)
#define SPI_FIFOSTAT_RXLVL_SHIFT                 (16U)
#define SPI_FIFOSTAT_RXLVL(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOSTAT_RXLVL_SHIFT)) & SPI_FIFOSTAT_RXLVL_MASK)
/*! @} */

/*! @name FIFOTRIG -  */
/*! @{ */

#define SPI_FIFOTRIG_TXLVLENA_MASK               (0x1U)
#define SPI_FIFOTRIG_TXLVLENA_SHIFT              (0U)
#define SPI_FIFOTRIG_TXLVLENA(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOTRIG_TXLVLENA_SHIFT)) & SPI_FIFOTRIG_TXLVLENA_MASK)

#define SPI_FIFOTRIG_RXLVLENA_MASK               (0x2U)
#define SPI_FIFOTRIG_RXLVLENA_SHIFT              (1U)
#define SPI_FIFOTRIG_RXLVLENA(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOTRIG_RXLVLENA_SHIFT)) & SPI_FIFOTRIG_RXLVLENA_MASK)

#define SPI_FIFOTRIG_TXLVL_MASK                  (0x700U)
#define SPI_FIFOTRIG_TXLVL_SHIFT                 (8U)
#define SPI_FIFOTRIG_TXLVL(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOTRIG_TXLVL_SHIFT)) & SPI_FIFOTRIG_TXLVL_MASK)

#define SPI_FIFOTRIG_RXLVL_MASK                  (0x70000U)
#define SPI_FIFOTRIG_RXLVL_SHIFT                 (16U)
#define SPI_FIFOTRIG_RXLVL(x)                    (((uint32_t)(((uint32_t)(x)) << SPI_FIFOTRIG_RXLVL_SHIFT)) & SPI_FIFOTRIG_RXLVL_MASK)
/*! @} */

/*! @name FIFOINTENSET -  */
/*! @{ */

#define SPI_FIFOINTENSET_TXERR_MASK              (0x1U)
#define SPI_FIFOINTENSET_TXERR_SHIFT             (0U)
#define SPI_FIFOINTENSET_TXERR(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENSET_TXERR_SHIFT)) & SPI_FIFOINTENSET_TXERR_MASK)

#define SPI_FIFOINTENSET_RXERR_MASK              (0x2U)
#define SPI_FIFOINTENSET_RXERR_SHIFT             (1U)
#define SPI_FIFOINTENSET_RXERR(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENSET_RXERR_SHIFT)) & SPI_FIFOINTENSET_RXERR_MASK)

#define SPI_FIFOINTENSET_TXLVL_MASK              (0x4U)
#define SPI_FIFOINTENSET_TXLVL_SHIFT             (2U)
#define SPI_FIFOINTENSET_TXLVL(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENSET_TXLVL_SHIFT)) & SPI_FIFOINTENSET_TXLVL_MASK)

#define SPI_FIFOINTENSET_RXLVL_MASK              (0x8U)
#define SPI_FIFOINTENSET_RXLVL_SHIFT             (3U)
#define SPI_FIFOINTENSET_RXLVL(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENSET_RXLVL_SHIFT)) & SPI_FIFOINTENSET_RXLVL_MASK)
/*! @} */

/*! @name FIFOINTENCLR -  */
/*! @{ */

#define SPI_FIFOINTENCLR_TXERR_MASK              (0x1U)
#define SPI_FIFOINTENCLR_TXERR_SHIFT             (0U)
#define SPI_FIFOINTENCLR_TXERR(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENCLR_TXERR_SHIFT)) & SPI_FIFOINTENCLR_TXERR_MASK)

#define SPI_FIFOINTENCLR_RXERR_MASK              (0x2U)
#define SPI_FIFOINTENCLR_RXERR_SHIFT             (1U)
#define SPI_FIFOINTENCLR_RXERR(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENCLR_RXERR_SHIFT)) & SPI_FIFOINTENCLR_RXERR_MASK)

#define SPI_FIFOINTENCLR_TXLVL_MASK              (0x4U)
#define SPI_FIFOINTENCLR_TXLVL_SHIFT             (2U)
#define SPI_FIFOINTENCLR_TXLVL(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENCLR_TXLVL_SHIFT)) & SPI_FIFOINTENCLR_TXLVL_MASK)

#define SPI_FIFOINTENCLR_RXLVL_MASK              (0x8U)
#define SPI_FIFOINTENCLR_RXLVL_SHIFT             (3U)
#define SPI_FIFOINTENCLR_RXLVL(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTENCLR_RXLVL_SHIFT)) & SPI_FIFOINTENCLR_RXLVL_MASK)
/*! @} */

/*! @name FIFOINTSTAT -  */
/*! @{ */

#define SPI_FIFOINTSTAT_TXERR_MASK               (0x1U)
#define SPI_FIFOINTSTAT_TXERR_SHIFT              (0U)
#define SPI_FIFOINTSTAT_TXERR(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTSTAT_TXERR_SHIFT)) & SPI_FIFOINTSTAT_TXERR_MASK)

#define SPI_FIFOINTSTAT_RXERR_MASK               (0x2U)
#define SPI_FIFOINTSTAT_RXERR_SHIFT              (1U)
#define SPI_FIFOINTSTAT_RXERR(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTSTAT_RXERR_SHIFT)) & SPI_FIFOINTSTAT_RXERR_MASK)

#define SPI_FIFOINTSTAT_TXLVL_MASK               (0x4U)
#define SPI_FIFOINTSTAT_TXLVL_SHIFT              (2U)
#define SPI_FIFOINTSTAT_TXLVL(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTSTAT_TXLVL_SHIFT)) & SPI_FIFOINTSTAT_TXLVL_MASK)

#define SPI_FIFOINTSTAT_RXLVL_MASK               (0x8U)
#define SPI_FIFOINTSTAT_RXLVL_SHIFT              (3U)
#define SPI_FIFOINTSTAT_RXLVL(x)                 (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTSTAT_RXLVL_SHIFT)) & SPI_FIFOINTSTAT_RXLVL_MASK)

#define SPI_FIFOINTSTAT_PERINT_MASK              (0x10U)
#define SPI_FIFOINTSTAT_PERINT_SHIFT             (4U)
#define SPI_FIFOINTSTAT_PERINT(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFOINTSTAT_PERINT_SHIFT)) & SPI_FIFOINTSTAT_PERINT_MASK)
/*! @} */

/*! @name FIFOWR -  */
/*! @{ */

#define SPI_FIFOWR_TXDATA_MASK                   (0xFFFFU)
#define SPI_FIFOWR_TXDATA_SHIFT                  (0U)
#define SPI_FIFOWR_TXDATA(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_TXDATA_SHIFT)) & SPI_FIFOWR_TXDATA_MASK)

#define SPI_FIFOWR_TXSSEL0_N_MASK                (0x10000U)
#define SPI_FIFOWR_TXSSEL0_N_SHIFT               (16U)
#define SPI_FIFOWR_TXSSEL0_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_TXSSEL0_N_SHIFT)) & SPI_FIFOWR_TXSSEL0_N_MASK)

#define SPI_FIFOWR_TXSSEL1_N_MASK                (0x20000U)
#define SPI_FIFOWR_TXSSEL1_N_SHIFT               (17U)
#define SPI_FIFOWR_TXSSEL1_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_TXSSEL1_N_SHIFT)) & SPI_FIFOWR_TXSSEL1_N_MASK)

#define SPI_FIFOWR_TXSSEL2_N_MASK                (0x40000U)
#define SPI_FIFOWR_TXSSEL2_N_SHIFT               (18U)
#define SPI_FIFOWR_TXSSEL2_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_TXSSEL2_N_SHIFT)) & SPI_FIFOWR_TXSSEL2_N_MASK)

#define SPI_FIFOWR_TXSSEL3_N_MASK                (0x80000U)
#define SPI_FIFOWR_TXSSEL3_N_SHIFT               (19U)
#define SPI_FIFOWR_TXSSEL3_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_TXSSEL3_N_SHIFT)) & SPI_FIFOWR_TXSSEL3_N_MASK)

#define SPI_FIFOWR_EOT_MASK                      (0x100000U)
#define SPI_FIFOWR_EOT_SHIFT                     (20U)
#define SPI_FIFOWR_EOT(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_EOT_SHIFT)) & SPI_FIFOWR_EOT_MASK)

#define SPI_FIFOWR_EOF_MASK                      (0x200000U)
#define SPI_FIFOWR_EOF_SHIFT                     (21U)
#define SPI_FIFOWR_EOF(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_EOF_SHIFT)) & SPI_FIFOWR_EOF_MASK)

#define SPI_FIFOWR_RXIGNORE_MASK                 (0x400000U)
#define SPI_FIFOWR_RXIGNORE_SHIFT                (22U)
#define SPI_FIFOWR_RXIGNORE(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_RXIGNORE_SHIFT)) & SPI_FIFOWR_RXIGNORE_MASK)

#define SPI_FIFOWR_LEN_MASK                      (0xF000000U)
#define SPI_FIFOWR_LEN_SHIFT                     (24U)
#define SPI_FIFOWR_LEN(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_FIFOWR_LEN_SHIFT)) & SPI_FIFOWR_LEN_MASK)
/*! @} */

/*! @name FIFORD -  */
/*! @{ */

#define SPI_FIFORD_RXDATA_MASK                   (0xFFFFU)
#define SPI_FIFORD_RXDATA_SHIFT                  (0U)
#define SPI_FIFORD_RXDATA(x)                     (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_RXDATA_SHIFT)) & SPI_FIFORD_RXDATA_MASK)

#define SPI_FIFORD_RXSSEL0_N_MASK                (0x10000U)
#define SPI_FIFORD_RXSSEL0_N_SHIFT               (16U)
#define SPI_FIFORD_RXSSEL0_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_RXSSEL0_N_SHIFT)) & SPI_FIFORD_RXSSEL0_N_MASK)

#define SPI_FIFORD_RXSSEL1_N_MASK                (0x20000U)
#define SPI_FIFORD_RXSSEL1_N_SHIFT               (17U)
#define SPI_FIFORD_RXSSEL1_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_RXSSEL1_N_SHIFT)) & SPI_FIFORD_RXSSEL1_N_MASK)

#define SPI_FIFORD_RXSSEL2_N_MASK                (0x40000U)
#define SPI_FIFORD_RXSSEL2_N_SHIFT               (18U)
#define SPI_FIFORD_RXSSEL2_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_RXSSEL2_N_SHIFT)) & SPI_FIFORD_RXSSEL2_N_MASK)

#define SPI_FIFORD_RXSSEL3_N_MASK                (0x80000U)
#define SPI_FIFORD_RXSSEL3_N_SHIFT               (19U)
#define SPI_FIFORD_RXSSEL3_N(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_RXSSEL3_N_SHIFT)) & SPI_FIFORD_RXSSEL3_N_MASK)

#define SPI_FIFORD_SOT_MASK                      (0x100000U)
#define SPI_FIFORD_SOT_SHIFT                     (20U)
#define SPI_FIFORD_SOT(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_FIFORD_SOT_SHIFT)) & SPI_FIFORD_SOT_MASK)
/*! @} */

/*! @name FIFORDNOPOP -  */
/*! @{ */

#define SPI_FIFORDNOPOP_RXDATA_MASK              (0xFFFFU)
#define SPI_FIFORDNOPOP_RXDATA_SHIFT             (0U)
#define SPI_FIFORDNOPOP_RXDATA(x)                (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_RXDATA_SHIFT)) & SPI_FIFORDNOPOP_RXDATA_MASK)

#define SPI_FIFORDNOPOP_RXSSEL0_N_MASK           (0x10000U)
#define SPI_FIFORDNOPOP_RXSSEL0_N_SHIFT          (16U)
#define SPI_FIFORDNOPOP_RXSSEL0_N(x)             (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_RXSSEL0_N_SHIFT)) & SPI_FIFORDNOPOP_RXSSEL0_N_MASK)

#define SPI_FIFORDNOPOP_RXSSEL1_N_MASK           (0x20000U)
#define SPI_FIFORDNOPOP_RXSSEL1_N_SHIFT          (17U)
#define SPI_FIFORDNOPOP_RXSSEL1_N(x)             (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_RXSSEL1_N_SHIFT)) & SPI_FIFORDNOPOP_RXSSEL1_N_MASK)

#define SPI_FIFORDNOPOP_RXSSEL2_N_MASK           (0x40000U)
#define SPI_FIFORDNOPOP_RXSSEL2_N_SHIFT          (18U)
#define SPI_FIFORDNOPOP_RXSSEL2_N(x)             (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_RXSSEL2_N_SHIFT)) & SPI_FIFORDNOPOP_RXSSEL2_N_MASK)

#define SPI_FIFORDNOPOP_RXSSEL3_N_MASK           (0x80000U)
#define SPI_FIFORDNOPOP_RXSSEL3_N_SHIFT          (19U)
#define SPI_FIFORDNOPOP_RXSSEL3_N(x)             (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_RXSSEL3_N_SHIFT)) & SPI_FIFORDNOPOP_RXSSEL3_N_MASK)

#define SPI_FIFORDNOPOP_SOT_MASK                 (0x100000U)
#define SPI_FIFORDNOPOP_SOT_SHIFT                (20U)
#define SPI_FIFORDNOPOP_SOT(x)                   (((uint32_t)(((uint32_t)(x)) << SPI_FIFORDNOPOP_SOT_SHIFT)) & SPI_FIFORDNOPOP_SOT_MASK)
/*! @} */

/*! @name SELID -  */
/*! @{ */

#define SPI_SELID_PERSEL_MASK                    (0x7U)
#define SPI_SELID_PERSEL_SHIFT                   (0U)
#define SPI_SELID_PERSEL(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_SELID_PERSEL_SHIFT)) & SPI_SELID_PERSEL_MASK)

#define SPI_SELID_LOCK_MASK                      (0x8U)
#define SPI_SELID_LOCK_SHIFT                     (3U)
#define SPI_SELID_LOCK(x)                        (((uint32_t)(((uint32_t)(x)) << SPI_SELID_LOCK_SHIFT)) & SPI_SELID_LOCK_MASK)

#define SPI_SELID_USARTPRESENT_MASK              (0x10U)
#define SPI_SELID_USARTPRESENT_SHIFT             (4U)
#define SPI_SELID_USARTPRESENT(x)                (((uint32_t)(((uint32_t)(x)) << SPI_SELID_USARTPRESENT_SHIFT)) & SPI_SELID_USARTPRESENT_MASK)

#define SPI_SELID_SPIPRESENT_MASK                (0x20U)
#define SPI_SELID_SPIPRESENT_SHIFT               (5U)
#define SPI_SELID_SPIPRESENT(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_SELID_SPIPRESENT_SHIFT)) & SPI_SELID_SPIPRESENT_MASK)

#define SPI_SELID_I2CPRESENT_MASK                (0x40U)
#define SPI_SELID_I2CPRESENT_SHIFT               (6U)
#define SPI_SELID_I2CPRESENT(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_SELID_I2CPRESENT_SHIFT)) & SPI_SELID_I2CPRESENT_MASK)

#define SPI_SELID_I2SPRESENT_MASK                (0x80U)
#define SPI_SELID_I2SPRESENT_SHIFT               (7U)
#define SPI_SELID_I2SPRESENT(x)                  (((uint32_t)(((uint32_t)(x)) << SPI_SELID_I2SPRESENT_SHIFT)) & SPI_SELID_I2SPRESENT_MASK)

#define SPI_SELID_ID_MASK                        (0xFFFFF000U)
#define SPI_SELID_ID_SHIFT                       (12U)
#define SPI_SELID_ID(x)                          (((uint32_t)(((uint32_t)(x)) << SPI_SELID_ID_SHIFT)) & SPI_SELID_ID_MASK)
/*! @} */

/*! @name ID -  */
/*! @{ */

#define SPI_ID_MINOR_REV_MASK                    (0xF00U)
#define SPI_ID_MINOR_REV_SHIFT                   (8U)
#define SPI_ID_MINOR_REV(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_ID_MINOR_REV_SHIFT)) & SPI_ID_MINOR_REV_MASK)

#define SPI_ID_MAJOR_REV_MASK                    (0xF000U)
#define SPI_ID_MAJOR_REV_SHIFT                   (12U)
#define SPI_ID_MAJOR_REV(x)                      (((uint32_t)(((uint32_t)(x)) << SPI_ID_MAJOR_REV_SHIFT)) & SPI_ID_MAJOR_REV_MASK)

#define SPI_ID_ID_MASK                           (0xFFFF0000U)
#define SPI_ID_ID_SHIFT                          (16U)
#define SPI_ID_ID(x)                             (((uint32_t)(((uint32_t)(x)) << SPI_ID_ID_SHIFT)) & SPI_ID_ID_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group SPI_Register_Masks */


/* SPI - Peripheral instance base addresses */
/** Peripheral SPI base address */
#define SPI_BASE                                 (0x40022000u)
/** Peripheral SPI base pointer */
#define SPI                                      ((SPI_Type *)SPI_BASE)
/** Array initializer of SPI peripheral base addresses */
#define SPI_BASE_ADDRS                           { SPI_BASE }
/** Array initializer of SPI peripheral base pointers */
#define SPI_BASE_PTRS                            { SPI }
/** Interrupt vectors for the SPI peripheral type */
#define SPI_IRQS                                 { SPI_IRQn }

/*!
 * @}
 */ /* end of group SPI_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- TIMERS Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup TIMERS_Peripheral_Access_Layer TIMERS Peripheral Access Layer
 * @{
 */

/** TIMERS - Register Layout Typedef */
typedef struct {
  struct {                                         /* offset: 0x0, array step: 0x10 */
    __IO uint32_t TIMEOUT;                           /**< , array offset: 0x0, array step: 0x10 */
    __I  uint32_t COUNT;                             /**< , array offset: 0x4, array step: 0x10 */
         uint8_t RESERVED_0[8];
  } TIMER[4];
  __IO uint32_t WDOG_TIMEOUT;                      /**< , offset: 0x40 */
  __I  uint32_t WDOG_COUNT;                        /**< , offset: 0x44 */
  __IO uint32_t WDOG_TRIGGER_INT;                  /**< , offset: 0x48 */
       uint8_t RESERVED_0[4];
  __IO uint32_t PRESCALER;                         /**< , offset: 0x50 */
       uint8_t RESERVED_1[12];
  __IO uint32_t TBSEL;                             /**< , offset: 0x60 */
  __I  uint32_t TBVALUE;                           /**< , offset: 0x64 */
       uint8_t RESERVED_2[8];
  __IO uint32_t SPARE;                             /**< , offset: 0x70 */
       uint8_t RESERVED_3[3928];
  __I  uint32_t WDOG_INT_STATUS;                   /**< , offset: 0xFCC */
  __O  uint32_t WDOG_INT_CLR_STATUS;               /**< , offset: 0xFD0 */
  __O  uint32_t WDOG_INT_SET_STATUS;               /**< , offset: 0xFD4 */
  __O  uint32_t INT_CLR_ENABLE;                    /**< , offset: 0xFD8 */
  __O  uint32_t INT_SET_ENABLE;                    /**< , offset: 0xFDC */
  __I  uint32_t INT_STATUS;                        /**< , offset: 0xFE0 */
  __I  uint32_t INT_ENABLE;                        /**< , offset: 0xFE4 */
  __O  uint32_t INT_CLR_STATUS;                    /**< , offset: 0xFE8 */
  __O  uint32_t INT_SET_STATUS;                    /**< , offset: 0xFEC */
} TIMERS_Type;

/* ----------------------------------------------------------------------------
   -- TIMERS Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup TIMERS_Register_Masks TIMERS Register Masks
 * @{
 */

/*! @name TIMEOUT -  */
/*! @{ */

#define TIMERS_TIMEOUT_TIMER0_TIMEOUT_MASK       (0xFFFFFU)
#define TIMERS_TIMEOUT_TIMER0_TIMEOUT_SHIFT      (0U)
#define TIMERS_TIMEOUT_TIMER0_TIMEOUT(x)         (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER0_TIMEOUT_SHIFT)) & TIMERS_TIMEOUT_TIMER0_TIMEOUT_MASK)

#define TIMERS_TIMEOUT_TIMER0_MODE_MASK          (0x80000000U)
#define TIMERS_TIMEOUT_TIMER0_MODE_SHIFT         (31U)
#define TIMERS_TIMEOUT_TIMER0_MODE(x)            (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER0_MODE_SHIFT)) & TIMERS_TIMEOUT_TIMER0_MODE_MASK)

#define TIMERS_TIMEOUT_TIMER1_TIMEOUT_MASK       (0xFFFFFU)
#define TIMERS_TIMEOUT_TIMER1_TIMEOUT_SHIFT      (0U)
#define TIMERS_TIMEOUT_TIMER1_TIMEOUT(x)         (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER1_TIMEOUT_SHIFT)) & TIMERS_TIMEOUT_TIMER1_TIMEOUT_MASK)

#define TIMERS_TIMEOUT_TIMER1_MODE_MASK          (0x80000000U)
#define TIMERS_TIMEOUT_TIMER1_MODE_SHIFT         (31U)
#define TIMERS_TIMEOUT_TIMER1_MODE(x)            (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER1_MODE_SHIFT)) & TIMERS_TIMEOUT_TIMER1_MODE_MASK)

#define TIMERS_TIMEOUT_TIMER2_TIMEOUT_MASK       (0xFFFFFU)
#define TIMERS_TIMEOUT_TIMER2_TIMEOUT_SHIFT      (0U)
#define TIMERS_TIMEOUT_TIMER2_TIMEOUT(x)         (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER2_TIMEOUT_SHIFT)) & TIMERS_TIMEOUT_TIMER2_TIMEOUT_MASK)

#define TIMERS_TIMEOUT_TIMER2_MODE_MASK          (0x80000000U)
#define TIMERS_TIMEOUT_TIMER2_MODE_SHIFT         (31U)
#define TIMERS_TIMEOUT_TIMER2_MODE(x)            (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER2_MODE_SHIFT)) & TIMERS_TIMEOUT_TIMER2_MODE_MASK)

#define TIMERS_TIMEOUT_TIMER3_TIMEOUT_MASK       (0xFFFFFU)
#define TIMERS_TIMEOUT_TIMER3_TIMEOUT_SHIFT      (0U)
#define TIMERS_TIMEOUT_TIMER3_TIMEOUT(x)         (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER3_TIMEOUT_SHIFT)) & TIMERS_TIMEOUT_TIMER3_TIMEOUT_MASK)

#define TIMERS_TIMEOUT_TIMER3_MODE_MASK          (0x80000000U)
#define TIMERS_TIMEOUT_TIMER3_MODE_SHIFT         (31U)
#define TIMERS_TIMEOUT_TIMER3_MODE(x)            (((uint32_t)(((uint32_t)(x)) << TIMERS_TIMEOUT_TIMER3_MODE_SHIFT)) & TIMERS_TIMEOUT_TIMER3_MODE_MASK)
/*! @} */

/* The count of TIMERS_TIMEOUT */
#define TIMERS_TIMEOUT_COUNT                     (4U)

/*! @name COUNT -  */
/*! @{ */

#define TIMERS_COUNT_TIMER0_COUNT_MASK           (0xFFFFFU)
#define TIMERS_COUNT_TIMER0_COUNT_SHIFT          (0U)
#define TIMERS_COUNT_TIMER0_COUNT(x)             (((uint32_t)(((uint32_t)(x)) << TIMERS_COUNT_TIMER0_COUNT_SHIFT)) & TIMERS_COUNT_TIMER0_COUNT_MASK)

#define TIMERS_COUNT_TIMER1_COUNT_MASK           (0xFFFFFU)
#define TIMERS_COUNT_TIMER1_COUNT_SHIFT          (0U)
#define TIMERS_COUNT_TIMER1_COUNT(x)             (((uint32_t)(((uint32_t)(x)) << TIMERS_COUNT_TIMER1_COUNT_SHIFT)) & TIMERS_COUNT_TIMER1_COUNT_MASK)

#define TIMERS_COUNT_TIMER2_COUNT_MASK           (0xFFFFFU)
#define TIMERS_COUNT_TIMER2_COUNT_SHIFT          (0U)
#define TIMERS_COUNT_TIMER2_COUNT(x)             (((uint32_t)(((uint32_t)(x)) << TIMERS_COUNT_TIMER2_COUNT_SHIFT)) & TIMERS_COUNT_TIMER2_COUNT_MASK)

#define TIMERS_COUNT_TIMER3_COUNT_MASK           (0xFFFFFU)
#define TIMERS_COUNT_TIMER3_COUNT_SHIFT          (0U)
#define TIMERS_COUNT_TIMER3_COUNT(x)             (((uint32_t)(((uint32_t)(x)) << TIMERS_COUNT_TIMER3_COUNT_SHIFT)) & TIMERS_COUNT_TIMER3_COUNT_MASK)
/*! @} */

/* The count of TIMERS_COUNT */
#define TIMERS_COUNT_COUNT                       (4U)

/*! @name WDOG_TIMEOUT -  */
/*! @{ */

#define TIMERS_WDOG_TIMEOUT_WDOG_TIMEOUT_MASK    (0xFFFFFU)
#define TIMERS_WDOG_TIMEOUT_WDOG_TIMEOUT_SHIFT   (0U)
#define TIMERS_WDOG_TIMEOUT_WDOG_TIMEOUT(x)      (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_TIMEOUT_WDOG_TIMEOUT_SHIFT)) & TIMERS_WDOG_TIMEOUT_WDOG_TIMEOUT_MASK)

#define TIMERS_WDOG_TIMEOUT_WDOG_KICK_MASK       (0x80000000U)
#define TIMERS_WDOG_TIMEOUT_WDOG_KICK_SHIFT      (31U)
#define TIMERS_WDOG_TIMEOUT_WDOG_KICK(x)         (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_TIMEOUT_WDOG_KICK_SHIFT)) & TIMERS_WDOG_TIMEOUT_WDOG_KICK_MASK)
/*! @} */

/*! @name WDOG_COUNT -  */
/*! @{ */

#define TIMERS_WDOG_COUNT_WDOG_COUNT_MASK        (0xFFFFFU)
#define TIMERS_WDOG_COUNT_WDOG_COUNT_SHIFT       (0U)
#define TIMERS_WDOG_COUNT_WDOG_COUNT(x)          (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_COUNT_WDOG_COUNT_SHIFT)) & TIMERS_WDOG_COUNT_WDOG_COUNT_MASK)
/*! @} */

/*! @name WDOG_TRIGGER_INT -  */
/*! @{ */

#define TIMERS_WDOG_TRIGGER_INT_WDOG_INT_THRESHOLD_MASK (0xFFFFFU)
#define TIMERS_WDOG_TRIGGER_INT_WDOG_INT_THRESHOLD_SHIFT (0U)
#define TIMERS_WDOG_TRIGGER_INT_WDOG_INT_THRESHOLD(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_TRIGGER_INT_WDOG_INT_THRESHOLD_SHIFT)) & TIMERS_WDOG_TRIGGER_INT_WDOG_INT_THRESHOLD_MASK)
/*! @} */

/*! @name PRESCALER -  */
/*! @{ */

#define TIMERS_PRESCALER_PRESCALING_VALUE_MASK   (0xFFU)
#define TIMERS_PRESCALER_PRESCALING_VALUE_SHIFT  (0U)
#define TIMERS_PRESCALER_PRESCALING_VALUE(x)     (((uint32_t)(((uint32_t)(x)) << TIMERS_PRESCALER_PRESCALING_VALUE_SHIFT)) & TIMERS_PRESCALER_PRESCALING_VALUE_MASK)
/*! @} */

/*! @name TBSEL -  */
/*! @{ */

#define TIMERS_TBSEL_TESTBUS_SELECT_MASK         (0xFU)
#define TIMERS_TBSEL_TESTBUS_SELECT_SHIFT        (0U)
#define TIMERS_TBSEL_TESTBUS_SELECT(x)           (((uint32_t)(((uint32_t)(x)) << TIMERS_TBSEL_TESTBUS_SELECT_SHIFT)) & TIMERS_TBSEL_TESTBUS_SELECT_MASK)
/*! @} */

/*! @name TBVALUE -  */
/*! @{ */

#define TIMERS_TBVALUE_TESTBUS_VALUE_MASK        (0xFFU)
#define TIMERS_TBVALUE_TESTBUS_VALUE_SHIFT       (0U)
#define TIMERS_TBVALUE_TESTBUS_VALUE(x)          (((uint32_t)(((uint32_t)(x)) << TIMERS_TBVALUE_TESTBUS_VALUE_SHIFT)) & TIMERS_TBVALUE_TESTBUS_VALUE_MASK)
/*! @} */

/*! @name SPARE -  */
/*! @{ */

#define TIMERS_SPARE_SPARE0_MASK                 (0x1U)
#define TIMERS_SPARE_SPARE0_SHIFT                (0U)
#define TIMERS_SPARE_SPARE0(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE0_SHIFT)) & TIMERS_SPARE_SPARE0_MASK)

#define TIMERS_SPARE_SPARE1_MASK                 (0x2U)
#define TIMERS_SPARE_SPARE1_SHIFT                (1U)
#define TIMERS_SPARE_SPARE1(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE1_SHIFT)) & TIMERS_SPARE_SPARE1_MASK)

#define TIMERS_SPARE_SPARE2_MASK                 (0x4U)
#define TIMERS_SPARE_SPARE2_SHIFT                (2U)
#define TIMERS_SPARE_SPARE2(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE2_SHIFT)) & TIMERS_SPARE_SPARE2_MASK)

#define TIMERS_SPARE_SPARE3_MASK                 (0x8U)
#define TIMERS_SPARE_SPARE3_SHIFT                (3U)
#define TIMERS_SPARE_SPARE3(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE3_SHIFT)) & TIMERS_SPARE_SPARE3_MASK)

#define TIMERS_SPARE_SPARE4_MASK                 (0x10U)
#define TIMERS_SPARE_SPARE4_SHIFT                (4U)
#define TIMERS_SPARE_SPARE4(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE4_SHIFT)) & TIMERS_SPARE_SPARE4_MASK)

#define TIMERS_SPARE_SPARE5_MASK                 (0x20U)
#define TIMERS_SPARE_SPARE5_SHIFT                (5U)
#define TIMERS_SPARE_SPARE5(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE5_SHIFT)) & TIMERS_SPARE_SPARE5_MASK)

#define TIMERS_SPARE_SPARE6_MASK                 (0x40U)
#define TIMERS_SPARE_SPARE6_SHIFT                (6U)
#define TIMERS_SPARE_SPARE6(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE6_SHIFT)) & TIMERS_SPARE_SPARE6_MASK)

#define TIMERS_SPARE_SPARE7_MASK                 (0x80U)
#define TIMERS_SPARE_SPARE7_SHIFT                (7U)
#define TIMERS_SPARE_SPARE7(x)                   (((uint32_t)(((uint32_t)(x)) << TIMERS_SPARE_SPARE7_SHIFT)) & TIMERS_SPARE_SPARE7_MASK)
/*! @} */

/*! @name WDOG_INT_STATUS -  */
/*! @{ */

#define TIMERS_WDOG_INT_STATUS_WDOG_TIMEOUT_STATUS_MASK (0x1U)
#define TIMERS_WDOG_INT_STATUS_WDOG_TIMEOUT_STATUS_SHIFT (0U)
#define TIMERS_WDOG_INT_STATUS_WDOG_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_INT_STATUS_WDOG_TIMEOUT_STATUS_SHIFT)) & TIMERS_WDOG_INT_STATUS_WDOG_TIMEOUT_STATUS_MASK)
/*! @} */

/*! @name WDOG_INT_CLR_STATUS -  */
/*! @{ */

#define TIMERS_WDOG_INT_CLR_STATUS_WDOG_TIMEOUT_CLR_STATUS_MASK (0x1U)
#define TIMERS_WDOG_INT_CLR_STATUS_WDOG_TIMEOUT_CLR_STATUS_SHIFT (0U)
#define TIMERS_WDOG_INT_CLR_STATUS_WDOG_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_INT_CLR_STATUS_WDOG_TIMEOUT_CLR_STATUS_SHIFT)) & TIMERS_WDOG_INT_CLR_STATUS_WDOG_TIMEOUT_CLR_STATUS_MASK)
/*! @} */

/*! @name WDOG_INT_SET_STATUS -  */
/*! @{ */

#define TIMERS_WDOG_INT_SET_STATUS_WDOG_TIMEOUT_SET_STATUS_MASK (0x1U)
#define TIMERS_WDOG_INT_SET_STATUS_WDOG_TIMEOUT_SET_STATUS_SHIFT (0U)
#define TIMERS_WDOG_INT_SET_STATUS_WDOG_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_WDOG_INT_SET_STATUS_WDOG_TIMEOUT_SET_STATUS_SHIFT)) & TIMERS_WDOG_INT_SET_STATUS_WDOG_TIMEOUT_SET_STATUS_MASK)
/*! @} */

/*! @name INT_CLR_ENABLE -  */
/*! @{ */

#define TIMERS_INT_CLR_ENABLE_TIMER0_TIMEOUT_CLR_ENABLE_MASK (0x1U)
#define TIMERS_INT_CLR_ENABLE_TIMER0_TIMEOUT_CLR_ENABLE_SHIFT (0U)
#define TIMERS_INT_CLR_ENABLE_TIMER0_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_ENABLE_TIMER0_TIMEOUT_CLR_ENABLE_SHIFT)) & TIMERS_INT_CLR_ENABLE_TIMER0_TIMEOUT_CLR_ENABLE_MASK)

#define TIMERS_INT_CLR_ENABLE_TIMER1_TIMEOUT_CLR_ENABLE_MASK (0x2U)
#define TIMERS_INT_CLR_ENABLE_TIMER1_TIMEOUT_CLR_ENABLE_SHIFT (1U)
#define TIMERS_INT_CLR_ENABLE_TIMER1_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_ENABLE_TIMER1_TIMEOUT_CLR_ENABLE_SHIFT)) & TIMERS_INT_CLR_ENABLE_TIMER1_TIMEOUT_CLR_ENABLE_MASK)

#define TIMERS_INT_CLR_ENABLE_TIMER2_TIMEOUT_CLR_ENABLE_MASK (0x4U)
#define TIMERS_INT_CLR_ENABLE_TIMER2_TIMEOUT_CLR_ENABLE_SHIFT (2U)
#define TIMERS_INT_CLR_ENABLE_TIMER2_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_ENABLE_TIMER2_TIMEOUT_CLR_ENABLE_SHIFT)) & TIMERS_INT_CLR_ENABLE_TIMER2_TIMEOUT_CLR_ENABLE_MASK)

#define TIMERS_INT_CLR_ENABLE_TIMER3_TIMEOUT_CLR_ENABLE_MASK (0x8U)
#define TIMERS_INT_CLR_ENABLE_TIMER3_TIMEOUT_CLR_ENABLE_SHIFT (3U)
#define TIMERS_INT_CLR_ENABLE_TIMER3_TIMEOUT_CLR_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_ENABLE_TIMER3_TIMEOUT_CLR_ENABLE_SHIFT)) & TIMERS_INT_CLR_ENABLE_TIMER3_TIMEOUT_CLR_ENABLE_MASK)
/*! @} */

/*! @name INT_SET_ENABLE -  */
/*! @{ */

#define TIMERS_INT_SET_ENABLE_TIMER0_TIMEOUT_SET_ENABLE_MASK (0x1U)
#define TIMERS_INT_SET_ENABLE_TIMER0_TIMEOUT_SET_ENABLE_SHIFT (0U)
#define TIMERS_INT_SET_ENABLE_TIMER0_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_ENABLE_TIMER0_TIMEOUT_SET_ENABLE_SHIFT)) & TIMERS_INT_SET_ENABLE_TIMER0_TIMEOUT_SET_ENABLE_MASK)

#define TIMERS_INT_SET_ENABLE_TIMER1_TIMEOUT_SET_ENABLE_MASK (0x2U)
#define TIMERS_INT_SET_ENABLE_TIMER1_TIMEOUT_SET_ENABLE_SHIFT (1U)
#define TIMERS_INT_SET_ENABLE_TIMER1_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_ENABLE_TIMER1_TIMEOUT_SET_ENABLE_SHIFT)) & TIMERS_INT_SET_ENABLE_TIMER1_TIMEOUT_SET_ENABLE_MASK)

#define TIMERS_INT_SET_ENABLE_TIMER2_TIMEOUT_SET_ENABLE_MASK (0x4U)
#define TIMERS_INT_SET_ENABLE_TIMER2_TIMEOUT_SET_ENABLE_SHIFT (2U)
#define TIMERS_INT_SET_ENABLE_TIMER2_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_ENABLE_TIMER2_TIMEOUT_SET_ENABLE_SHIFT)) & TIMERS_INT_SET_ENABLE_TIMER2_TIMEOUT_SET_ENABLE_MASK)

#define TIMERS_INT_SET_ENABLE_TIMER3_TIMEOUT_SET_ENABLE_MASK (0x8U)
#define TIMERS_INT_SET_ENABLE_TIMER3_TIMEOUT_SET_ENABLE_SHIFT (3U)
#define TIMERS_INT_SET_ENABLE_TIMER3_TIMEOUT_SET_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_ENABLE_TIMER3_TIMEOUT_SET_ENABLE_SHIFT)) & TIMERS_INT_SET_ENABLE_TIMER3_TIMEOUT_SET_ENABLE_MASK)
/*! @} */

/*! @name INT_STATUS -  */
/*! @{ */

#define TIMERS_INT_STATUS_TIMER0_TIMEOUT_STATUS_MASK (0x1U)
#define TIMERS_INT_STATUS_TIMER0_TIMEOUT_STATUS_SHIFT (0U)
#define TIMERS_INT_STATUS_TIMER0_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_STATUS_TIMER0_TIMEOUT_STATUS_SHIFT)) & TIMERS_INT_STATUS_TIMER0_TIMEOUT_STATUS_MASK)

#define TIMERS_INT_STATUS_TIMER1_TIMEOUT_STATUS_MASK (0x2U)
#define TIMERS_INT_STATUS_TIMER1_TIMEOUT_STATUS_SHIFT (1U)
#define TIMERS_INT_STATUS_TIMER1_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_STATUS_TIMER1_TIMEOUT_STATUS_SHIFT)) & TIMERS_INT_STATUS_TIMER1_TIMEOUT_STATUS_MASK)

#define TIMERS_INT_STATUS_TIMER2_TIMEOUT_STATUS_MASK (0x4U)
#define TIMERS_INT_STATUS_TIMER2_TIMEOUT_STATUS_SHIFT (2U)
#define TIMERS_INT_STATUS_TIMER2_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_STATUS_TIMER2_TIMEOUT_STATUS_SHIFT)) & TIMERS_INT_STATUS_TIMER2_TIMEOUT_STATUS_MASK)

#define TIMERS_INT_STATUS_TIMER3_TIMEOUT_STATUS_MASK (0x8U)
#define TIMERS_INT_STATUS_TIMER3_TIMEOUT_STATUS_SHIFT (3U)
#define TIMERS_INT_STATUS_TIMER3_TIMEOUT_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_STATUS_TIMER3_TIMEOUT_STATUS_SHIFT)) & TIMERS_INT_STATUS_TIMER3_TIMEOUT_STATUS_MASK)
/*! @} */

/*! @name INT_ENABLE -  */
/*! @{ */

#define TIMERS_INT_ENABLE_TIMER0_TIMEOUT_ENABLE_MASK (0x1U)
#define TIMERS_INT_ENABLE_TIMER0_TIMEOUT_ENABLE_SHIFT (0U)
#define TIMERS_INT_ENABLE_TIMER0_TIMEOUT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_ENABLE_TIMER0_TIMEOUT_ENABLE_SHIFT)) & TIMERS_INT_ENABLE_TIMER0_TIMEOUT_ENABLE_MASK)

#define TIMERS_INT_ENABLE_TIMER1_TIMEOUT_ENABLE_MASK (0x2U)
#define TIMERS_INT_ENABLE_TIMER1_TIMEOUT_ENABLE_SHIFT (1U)
#define TIMERS_INT_ENABLE_TIMER1_TIMEOUT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_ENABLE_TIMER1_TIMEOUT_ENABLE_SHIFT)) & TIMERS_INT_ENABLE_TIMER1_TIMEOUT_ENABLE_MASK)

#define TIMERS_INT_ENABLE_TIMER2_TIMEOUT_ENABLE_MASK (0x4U)
#define TIMERS_INT_ENABLE_TIMER2_TIMEOUT_ENABLE_SHIFT (2U)
#define TIMERS_INT_ENABLE_TIMER2_TIMEOUT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_ENABLE_TIMER2_TIMEOUT_ENABLE_SHIFT)) & TIMERS_INT_ENABLE_TIMER2_TIMEOUT_ENABLE_MASK)

#define TIMERS_INT_ENABLE_TIMER3_TIMEOUT_ENABLE_MASK (0x8U)
#define TIMERS_INT_ENABLE_TIMER3_TIMEOUT_ENABLE_SHIFT (3U)
#define TIMERS_INT_ENABLE_TIMER3_TIMEOUT_ENABLE(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_ENABLE_TIMER3_TIMEOUT_ENABLE_SHIFT)) & TIMERS_INT_ENABLE_TIMER3_TIMEOUT_ENABLE_MASK)
/*! @} */

/*! @name INT_CLR_STATUS -  */
/*! @{ */

#define TIMERS_INT_CLR_STATUS_TIMER0_TIMEOUT_CLR_STATUS_MASK (0x1U)
#define TIMERS_INT_CLR_STATUS_TIMER0_TIMEOUT_CLR_STATUS_SHIFT (0U)
#define TIMERS_INT_CLR_STATUS_TIMER0_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_STATUS_TIMER0_TIMEOUT_CLR_STATUS_SHIFT)) & TIMERS_INT_CLR_STATUS_TIMER0_TIMEOUT_CLR_STATUS_MASK)

#define TIMERS_INT_CLR_STATUS_TIMER1_TIMEOUT_CLR_STATUS_MASK (0x2U)
#define TIMERS_INT_CLR_STATUS_TIMER1_TIMEOUT_CLR_STATUS_SHIFT (1U)
#define TIMERS_INT_CLR_STATUS_TIMER1_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_STATUS_TIMER1_TIMEOUT_CLR_STATUS_SHIFT)) & TIMERS_INT_CLR_STATUS_TIMER1_TIMEOUT_CLR_STATUS_MASK)

#define TIMERS_INT_CLR_STATUS_TIMER2_TIMEOUT_CLR_STATUS_MASK (0x4U)
#define TIMERS_INT_CLR_STATUS_TIMER2_TIMEOUT_CLR_STATUS_SHIFT (2U)
#define TIMERS_INT_CLR_STATUS_TIMER2_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_STATUS_TIMER2_TIMEOUT_CLR_STATUS_SHIFT)) & TIMERS_INT_CLR_STATUS_TIMER2_TIMEOUT_CLR_STATUS_MASK)

#define TIMERS_INT_CLR_STATUS_TIMER3_TIMEOUT_CLR_STATUS_MASK (0x8U)
#define TIMERS_INT_CLR_STATUS_TIMER3_TIMEOUT_CLR_STATUS_SHIFT (3U)
#define TIMERS_INT_CLR_STATUS_TIMER3_TIMEOUT_CLR_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_CLR_STATUS_TIMER3_TIMEOUT_CLR_STATUS_SHIFT)) & TIMERS_INT_CLR_STATUS_TIMER3_TIMEOUT_CLR_STATUS_MASK)
/*! @} */

/*! @name INT_SET_STATUS -  */
/*! @{ */

#define TIMERS_INT_SET_STATUS_TIMER0_TIMEOUT_SET_STATUS_MASK (0x1U)
#define TIMERS_INT_SET_STATUS_TIMER0_TIMEOUT_SET_STATUS_SHIFT (0U)
#define TIMERS_INT_SET_STATUS_TIMER0_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_STATUS_TIMER0_TIMEOUT_SET_STATUS_SHIFT)) & TIMERS_INT_SET_STATUS_TIMER0_TIMEOUT_SET_STATUS_MASK)

#define TIMERS_INT_SET_STATUS_TIMER1_TIMEOUT_SET_STATUS_MASK (0x2U)
#define TIMERS_INT_SET_STATUS_TIMER1_TIMEOUT_SET_STATUS_SHIFT (1U)
#define TIMERS_INT_SET_STATUS_TIMER1_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_STATUS_TIMER1_TIMEOUT_SET_STATUS_SHIFT)) & TIMERS_INT_SET_STATUS_TIMER1_TIMEOUT_SET_STATUS_MASK)

#define TIMERS_INT_SET_STATUS_TIMER2_TIMEOUT_SET_STATUS_MASK (0x4U)
#define TIMERS_INT_SET_STATUS_TIMER2_TIMEOUT_SET_STATUS_SHIFT (2U)
#define TIMERS_INT_SET_STATUS_TIMER2_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_STATUS_TIMER2_TIMEOUT_SET_STATUS_SHIFT)) & TIMERS_INT_SET_STATUS_TIMER2_TIMEOUT_SET_STATUS_MASK)

#define TIMERS_INT_SET_STATUS_TIMER3_TIMEOUT_SET_STATUS_MASK (0x8U)
#define TIMERS_INT_SET_STATUS_TIMER3_TIMEOUT_SET_STATUS_SHIFT (3U)
#define TIMERS_INT_SET_STATUS_TIMER3_TIMEOUT_SET_STATUS(x) (((uint32_t)(((uint32_t)(x)) << TIMERS_INT_SET_STATUS_TIMER3_TIMEOUT_SET_STATUS_SHIFT)) & TIMERS_INT_SET_STATUS_TIMER3_TIMEOUT_SET_STATUS_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group TIMERS_Register_Masks */


/* TIMERS - Peripheral instance base addresses */
/** Peripheral TIMERS base address */
#define TIMERS_BASE                              (0x40005000u)
/** Peripheral TIMERS base pointer */
#define TIMERS                                   ((TIMERS_Type *)TIMERS_BASE)
/** Array initializer of TIMERS peripheral base addresses */
#define TIMERS_BASE_ADDRS                        { TIMERS_BASE }
/** Array initializer of TIMERS peripheral base pointers */
#define TIMERS_BASE_PTRS                         { TIMERS }
/** Interrupt vectors for the TIMERS peripheral type */
#define TIMERS_IRQS                              { GPT_IRQn }

/*!
 * @}
 */ /* end of group TIMERS_Peripheral_Access_Layer */


/* ----------------------------------------------------------------------------
   -- USB Peripheral Access Layer
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup USB_Peripheral_Access_Layer USB Peripheral Access Layer
 * @{
 */

/** USB - Register Layout Typedef */
typedef struct {
  __IO uint32_t DEVCMDSTAT;                        /**< , offset: 0x0 */
  __IO uint32_t INFO;                              /**< , offset: 0x4 */
  __IO uint32_t EPLISTSTART;                       /**< , offset: 0x8 */
  __IO uint32_t DATABUFSTART;                      /**< , offset: 0xC */
  __IO uint32_t LPM;                               /**< , offset: 0x10 */
  __IO uint32_t EPSKIP;                            /**< , offset: 0x14 */
  __IO uint32_t EPINUSE;                           /**< , offset: 0x18 */
  __IO uint32_t EPBUFCFG;                          /**< , offset: 0x1C */
  __IO uint32_t INTSTAT;                           /**< , offset: 0x20 */
  __IO uint32_t INTEN;                             /**< , offset: 0x24 */
  __IO uint32_t INTSETSTAT;                        /**< , offset: 0x28 */
  __IO uint32_t INTROUTING;                        /**< , offset: 0x2C */
  __I  uint32_t CONFIGURATION;                     /**< , offset: 0x30 */
  __I  uint32_t EPTOGGLE;                          /**< , offset: 0x34 */
  __I  uint32_t INTPLL;                            /**< , offset: 0x38 */
} USB_Type;

/* ----------------------------------------------------------------------------
   -- USB Register Masks
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup USB_Register_Masks USB Register Masks
 * @{
 */

/*! @name DEVCMDSTAT -  */
/*! @{ */

#define USB_DEVCMDSTAT_DEV_ADDR_MASK             (0x7FU)
#define USB_DEVCMDSTAT_DEV_ADDR_SHIFT            (0U)
#define USB_DEVCMDSTAT_DEV_ADDR(x)               (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DEV_ADDR_SHIFT)) & USB_DEVCMDSTAT_DEV_ADDR_MASK)

#define USB_DEVCMDSTAT_DEV_EN_MASK               (0x80U)
#define USB_DEVCMDSTAT_DEV_EN_SHIFT              (7U)
#define USB_DEVCMDSTAT_DEV_EN(x)                 (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DEV_EN_SHIFT)) & USB_DEVCMDSTAT_DEV_EN_MASK)

#define USB_DEVCMDSTAT_SETUP_MASK                (0x100U)
#define USB_DEVCMDSTAT_SETUP_SHIFT               (8U)
#define USB_DEVCMDSTAT_SETUP(x)                  (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_SETUP_SHIFT)) & USB_DEVCMDSTAT_SETUP_MASK)

#define USB_DEVCMDSTAT_PLL_ON_MASK               (0x200U)
#define USB_DEVCMDSTAT_PLL_ON_SHIFT              (9U)
#define USB_DEVCMDSTAT_PLL_ON(x)                 (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_PLL_ON_SHIFT)) & USB_DEVCMDSTAT_PLL_ON_MASK)

#define USB_DEVCMDSTAT_LPM_SUP_MASK              (0x800U)
#define USB_DEVCMDSTAT_LPM_SUP_SHIFT             (11U)
#define USB_DEVCMDSTAT_LPM_SUP(x)                (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_LPM_SUP_SHIFT)) & USB_DEVCMDSTAT_LPM_SUP_MASK)

#define USB_DEVCMDSTAT_INTONNAK_AO_MASK          (0x1000U)
#define USB_DEVCMDSTAT_INTONNAK_AO_SHIFT         (12U)
#define USB_DEVCMDSTAT_INTONNAK_AO(x)            (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_INTONNAK_AO_SHIFT)) & USB_DEVCMDSTAT_INTONNAK_AO_MASK)

#define USB_DEVCMDSTAT_INTONNAK_AI_MASK          (0x2000U)
#define USB_DEVCMDSTAT_INTONNAK_AI_SHIFT         (13U)
#define USB_DEVCMDSTAT_INTONNAK_AI(x)            (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_INTONNAK_AI_SHIFT)) & USB_DEVCMDSTAT_INTONNAK_AI_MASK)

#define USB_DEVCMDSTAT_INTONNAK_CO_MASK          (0x4000U)
#define USB_DEVCMDSTAT_INTONNAK_CO_SHIFT         (14U)
#define USB_DEVCMDSTAT_INTONNAK_CO(x)            (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_INTONNAK_CO_SHIFT)) & USB_DEVCMDSTAT_INTONNAK_CO_MASK)

#define USB_DEVCMDSTAT_INTONNAK_CI_MASK          (0x8000U)
#define USB_DEVCMDSTAT_INTONNAK_CI_SHIFT         (15U)
#define USB_DEVCMDSTAT_INTONNAK_CI(x)            (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_INTONNAK_CI_SHIFT)) & USB_DEVCMDSTAT_INTONNAK_CI_MASK)

#define USB_DEVCMDSTAT_DCON_MASK                 (0x10000U)
#define USB_DEVCMDSTAT_DCON_SHIFT                (16U)
#define USB_DEVCMDSTAT_DCON(x)                   (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DCON_SHIFT)) & USB_DEVCMDSTAT_DCON_MASK)

#define USB_DEVCMDSTAT_DSUS_MASK                 (0x20000U)
#define USB_DEVCMDSTAT_DSUS_SHIFT                (17U)
#define USB_DEVCMDSTAT_DSUS(x)                   (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DSUS_SHIFT)) & USB_DEVCMDSTAT_DSUS_MASK)

#define USB_DEVCMDSTAT_LPM_SUS_MASK              (0x80000U)
#define USB_DEVCMDSTAT_LPM_SUS_SHIFT             (19U)
#define USB_DEVCMDSTAT_LPM_SUS(x)                (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_LPM_SUS_SHIFT)) & USB_DEVCMDSTAT_LPM_SUS_MASK)

#define USB_DEVCMDSTAT_LPM_REWP_MASK             (0x100000U)
#define USB_DEVCMDSTAT_LPM_REWP_SHIFT            (20U)
#define USB_DEVCMDSTAT_LPM_REWP(x)               (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_LPM_REWP_SHIFT)) & USB_DEVCMDSTAT_LPM_REWP_MASK)

#define USB_DEVCMDSTAT_DCON_C_MASK               (0x1000000U)
#define USB_DEVCMDSTAT_DCON_C_SHIFT              (24U)
#define USB_DEVCMDSTAT_DCON_C(x)                 (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DCON_C_SHIFT)) & USB_DEVCMDSTAT_DCON_C_MASK)

#define USB_DEVCMDSTAT_DSUS_C_MASK               (0x2000000U)
#define USB_DEVCMDSTAT_DSUS_C_SHIFT              (25U)
#define USB_DEVCMDSTAT_DSUS_C(x)                 (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DSUS_C_SHIFT)) & USB_DEVCMDSTAT_DSUS_C_MASK)

#define USB_DEVCMDSTAT_DRES_C_MASK               (0x4000000U)
#define USB_DEVCMDSTAT_DRES_C_SHIFT              (26U)
#define USB_DEVCMDSTAT_DRES_C(x)                 (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_DRES_C_SHIFT)) & USB_DEVCMDSTAT_DRES_C_MASK)

#define USB_DEVCMDSTAT_VBUSDEBOUNCED_MASK        (0x10000000U)
#define USB_DEVCMDSTAT_VBUSDEBOUNCED_SHIFT       (28U)
#define USB_DEVCMDSTAT_VBUSDEBOUNCED(x)          (((uint32_t)(((uint32_t)(x)) << USB_DEVCMDSTAT_VBUSDEBOUNCED_SHIFT)) & USB_DEVCMDSTAT_VBUSDEBOUNCED_MASK)
/*! @} */

/*! @name INFO -  */
/*! @{ */

#define USB_INFO_FRAME_NR_MASK                   (0x7FFU)
#define USB_INFO_FRAME_NR_SHIFT                  (0U)
#define USB_INFO_FRAME_NR(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INFO_FRAME_NR_SHIFT)) & USB_INFO_FRAME_NR_MASK)

#define USB_INFO_ERR_CODE_MASK                   (0x7800U)
#define USB_INFO_ERR_CODE_SHIFT                  (11U)
#define USB_INFO_ERR_CODE(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INFO_ERR_CODE_SHIFT)) & USB_INFO_ERR_CODE_MASK)

#define USB_INFO_CHIP_ID_MASK                    (0xFFFF0000U)
#define USB_INFO_CHIP_ID_SHIFT                   (16U)
#define USB_INFO_CHIP_ID(x)                      (((uint32_t)(((uint32_t)(x)) << USB_INFO_CHIP_ID_SHIFT)) & USB_INFO_CHIP_ID_MASK)
/*! @} */

/*! @name EPLISTSTART -  */
/*! @{ */

#define USB_EPLISTSTART_EP_LIST_MASK             (0x7F00U)
#define USB_EPLISTSTART_EP_LIST_SHIFT            (8U)
#define USB_EPLISTSTART_EP_LIST(x)               (((uint32_t)(((uint32_t)(x)) << USB_EPLISTSTART_EP_LIST_SHIFT)) & USB_EPLISTSTART_EP_LIST_MASK)
/*! @} */

/*! @name DATABUFSTART -  */
/*! @{ */

#define USB_DATABUFSTART_DA_BUF_MASK             (0x4000U)
#define USB_DATABUFSTART_DA_BUF_SHIFT            (14U)
#define USB_DATABUFSTART_DA_BUF(x)               (((uint32_t)(((uint32_t)(x)) << USB_DATABUFSTART_DA_BUF_SHIFT)) & USB_DATABUFSTART_DA_BUF_MASK)
/*! @} */

/*! @name LPM -  */
/*! @{ */

#define USB_LPM_HIRD_HW_MASK                     (0xFU)
#define USB_LPM_HIRD_HW_SHIFT                    (0U)
#define USB_LPM_HIRD_HW(x)                       (((uint32_t)(((uint32_t)(x)) << USB_LPM_HIRD_HW_SHIFT)) & USB_LPM_HIRD_HW_MASK)

#define USB_LPM_HIRD_SW_MASK                     (0xF0U)
#define USB_LPM_HIRD_SW_SHIFT                    (4U)
#define USB_LPM_HIRD_SW(x)                       (((uint32_t)(((uint32_t)(x)) << USB_LPM_HIRD_SW_SHIFT)) & USB_LPM_HIRD_SW_MASK)

#define USB_LPM_DATA_PENDING_MASK                (0x100U)
#define USB_LPM_DATA_PENDING_SHIFT               (8U)
#define USB_LPM_DATA_PENDING(x)                  (((uint32_t)(((uint32_t)(x)) << USB_LPM_DATA_PENDING_SHIFT)) & USB_LPM_DATA_PENDING_MASK)
/*! @} */

/*! @name EPSKIP -  */
/*! @{ */

#define USB_EPSKIP_SKIP_MASK                     (0x3FFFFFFFU)
#define USB_EPSKIP_SKIP_SHIFT                    (0U)
#define USB_EPSKIP_SKIP(x)                       (((uint32_t)(((uint32_t)(x)) << USB_EPSKIP_SKIP_SHIFT)) & USB_EPSKIP_SKIP_MASK)
/*! @} */

/*! @name EPINUSE -  */
/*! @{ */

#define USB_EPINUSE_BUF_MASK                     (0x3FFFFFFCU)
#define USB_EPINUSE_BUF_SHIFT                    (2U)
#define USB_EPINUSE_BUF(x)                       (((uint32_t)(((uint32_t)(x)) << USB_EPINUSE_BUF_SHIFT)) & USB_EPINUSE_BUF_MASK)
/*! @} */

/*! @name EPBUFCFG -  */
/*! @{ */

#define USB_EPBUFCFG_BUF_SB_MASK                 (0x3FFFFFFCU)
#define USB_EPBUFCFG_BUF_SB_SHIFT                (2U)
#define USB_EPBUFCFG_BUF_SB(x)                   (((uint32_t)(((uint32_t)(x)) << USB_EPBUFCFG_BUF_SB_SHIFT)) & USB_EPBUFCFG_BUF_SB_MASK)
/*! @} */

/*! @name INTSTAT -  */
/*! @{ */

#define USB_INTSTAT_EP0OUT_MASK                  (0x1U)
#define USB_INTSTAT_EP0OUT_SHIFT                 (0U)
#define USB_INTSTAT_EP0OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP0OUT_SHIFT)) & USB_INTSTAT_EP0OUT_MASK)

#define USB_INTSTAT_EP0IN_MASK                   (0x2U)
#define USB_INTSTAT_EP0IN_SHIFT                  (1U)
#define USB_INTSTAT_EP0IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP0IN_SHIFT)) & USB_INTSTAT_EP0IN_MASK)

#define USB_INTSTAT_EP1OUT_MASK                  (0x4U)
#define USB_INTSTAT_EP1OUT_SHIFT                 (2U)
#define USB_INTSTAT_EP1OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP1OUT_SHIFT)) & USB_INTSTAT_EP1OUT_MASK)

#define USB_INTSTAT_EP1IN_MASK                   (0x8U)
#define USB_INTSTAT_EP1IN_SHIFT                  (3U)
#define USB_INTSTAT_EP1IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP1IN_SHIFT)) & USB_INTSTAT_EP1IN_MASK)

#define USB_INTSTAT_EP2OUT_MASK                  (0x10U)
#define USB_INTSTAT_EP2OUT_SHIFT                 (4U)
#define USB_INTSTAT_EP2OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP2OUT_SHIFT)) & USB_INTSTAT_EP2OUT_MASK)

#define USB_INTSTAT_EP2IN_MASK                   (0x20U)
#define USB_INTSTAT_EP2IN_SHIFT                  (5U)
#define USB_INTSTAT_EP2IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP2IN_SHIFT)) & USB_INTSTAT_EP2IN_MASK)

#define USB_INTSTAT_EP3OUT_MASK                  (0x40U)
#define USB_INTSTAT_EP3OUT_SHIFT                 (6U)
#define USB_INTSTAT_EP3OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP3OUT_SHIFT)) & USB_INTSTAT_EP3OUT_MASK)

#define USB_INTSTAT_EP3IN_MASK                   (0x80U)
#define USB_INTSTAT_EP3IN_SHIFT                  (7U)
#define USB_INTSTAT_EP3IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP3IN_SHIFT)) & USB_INTSTAT_EP3IN_MASK)

#define USB_INTSTAT_EP4OUT_MASK                  (0x100U)
#define USB_INTSTAT_EP4OUT_SHIFT                 (8U)
#define USB_INTSTAT_EP4OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP4OUT_SHIFT)) & USB_INTSTAT_EP4OUT_MASK)

#define USB_INTSTAT_EP4IN_MASK                   (0x200U)
#define USB_INTSTAT_EP4IN_SHIFT                  (9U)
#define USB_INTSTAT_EP4IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP4IN_SHIFT)) & USB_INTSTAT_EP4IN_MASK)

#define USB_INTSTAT_EP5OUT_MASK                  (0x400U)
#define USB_INTSTAT_EP5OUT_SHIFT                 (10U)
#define USB_INTSTAT_EP5OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP5OUT_SHIFT)) & USB_INTSTAT_EP5OUT_MASK)

#define USB_INTSTAT_EP5IN_MASK                   (0x800U)
#define USB_INTSTAT_EP5IN_SHIFT                  (11U)
#define USB_INTSTAT_EP5IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP5IN_SHIFT)) & USB_INTSTAT_EP5IN_MASK)

#define USB_INTSTAT_EP6OUT_MASK                  (0x1000U)
#define USB_INTSTAT_EP6OUT_SHIFT                 (12U)
#define USB_INTSTAT_EP6OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP6OUT_SHIFT)) & USB_INTSTAT_EP6OUT_MASK)

#define USB_INTSTAT_EP6IN_MASK                   (0x2000U)
#define USB_INTSTAT_EP6IN_SHIFT                  (13U)
#define USB_INTSTAT_EP6IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP6IN_SHIFT)) & USB_INTSTAT_EP6IN_MASK)

#define USB_INTSTAT_EP7OUT_MASK                  (0x4000U)
#define USB_INTSTAT_EP7OUT_SHIFT                 (14U)
#define USB_INTSTAT_EP7OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP7OUT_SHIFT)) & USB_INTSTAT_EP7OUT_MASK)

#define USB_INTSTAT_EP7IN_MASK                   (0x8000U)
#define USB_INTSTAT_EP7IN_SHIFT                  (15U)
#define USB_INTSTAT_EP7IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP7IN_SHIFT)) & USB_INTSTAT_EP7IN_MASK)

#define USB_INTSTAT_EP8OUT_MASK                  (0x10000U)
#define USB_INTSTAT_EP8OUT_SHIFT                 (16U)
#define USB_INTSTAT_EP8OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP8OUT_SHIFT)) & USB_INTSTAT_EP8OUT_MASK)

#define USB_INTSTAT_EP8IN_MASK                   (0x20000U)
#define USB_INTSTAT_EP8IN_SHIFT                  (17U)
#define USB_INTSTAT_EP8IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP8IN_SHIFT)) & USB_INTSTAT_EP8IN_MASK)

#define USB_INTSTAT_EP9OUT_MASK                  (0x40000U)
#define USB_INTSTAT_EP9OUT_SHIFT                 (18U)
#define USB_INTSTAT_EP9OUT(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP9OUT_SHIFT)) & USB_INTSTAT_EP9OUT_MASK)

#define USB_INTSTAT_EP9IN_MASK                   (0x80000U)
#define USB_INTSTAT_EP9IN_SHIFT                  (19U)
#define USB_INTSTAT_EP9IN(x)                     (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP9IN_SHIFT)) & USB_INTSTAT_EP9IN_MASK)

#define USB_INTSTAT_EP10OUT_MASK                 (0x100000U)
#define USB_INTSTAT_EP10OUT_SHIFT                (20U)
#define USB_INTSTAT_EP10OUT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP10OUT_SHIFT)) & USB_INTSTAT_EP10OUT_MASK)

#define USB_INTSTAT_EP10IN_MASK                  (0x200000U)
#define USB_INTSTAT_EP10IN_SHIFT                 (21U)
#define USB_INTSTAT_EP10IN(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP10IN_SHIFT)) & USB_INTSTAT_EP10IN_MASK)

#define USB_INTSTAT_EP11OUT_MASK                 (0x400000U)
#define USB_INTSTAT_EP11OUT_SHIFT                (22U)
#define USB_INTSTAT_EP11OUT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP11OUT_SHIFT)) & USB_INTSTAT_EP11OUT_MASK)

#define USB_INTSTAT_EP11IN_MASK                  (0x800000U)
#define USB_INTSTAT_EP11IN_SHIFT                 (23U)
#define USB_INTSTAT_EP11IN(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP11IN_SHIFT)) & USB_INTSTAT_EP11IN_MASK)

#define USB_INTSTAT_EP12OUT_MASK                 (0x1000000U)
#define USB_INTSTAT_EP12OUT_SHIFT                (24U)
#define USB_INTSTAT_EP12OUT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP12OUT_SHIFT)) & USB_INTSTAT_EP12OUT_MASK)

#define USB_INTSTAT_EP12IN_MASK                  (0x2000000U)
#define USB_INTSTAT_EP12IN_SHIFT                 (25U)
#define USB_INTSTAT_EP12IN(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP12IN_SHIFT)) & USB_INTSTAT_EP12IN_MASK)

#define USB_INTSTAT_EP13OUT_MASK                 (0x4000000U)
#define USB_INTSTAT_EP13OUT_SHIFT                (26U)
#define USB_INTSTAT_EP13OUT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP13OUT_SHIFT)) & USB_INTSTAT_EP13OUT_MASK)

#define USB_INTSTAT_EP13IN_MASK                  (0x8000000U)
#define USB_INTSTAT_EP13IN_SHIFT                 (27U)
#define USB_INTSTAT_EP13IN(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP13IN_SHIFT)) & USB_INTSTAT_EP13IN_MASK)

#define USB_INTSTAT_EP14OUT_MASK                 (0x10000000U)
#define USB_INTSTAT_EP14OUT_SHIFT                (28U)
#define USB_INTSTAT_EP14OUT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP14OUT_SHIFT)) & USB_INTSTAT_EP14OUT_MASK)

#define USB_INTSTAT_EP14IN_MASK                  (0x20000000U)
#define USB_INTSTAT_EP14IN_SHIFT                 (29U)
#define USB_INTSTAT_EP14IN(x)                    (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_EP14IN_SHIFT)) & USB_INTSTAT_EP14IN_MASK)

#define USB_INTSTAT_FRAME_INT_MASK               (0x40000000U)
#define USB_INTSTAT_FRAME_INT_SHIFT              (30U)
#define USB_INTSTAT_FRAME_INT(x)                 (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_FRAME_INT_SHIFT)) & USB_INTSTAT_FRAME_INT_MASK)

#define USB_INTSTAT_DEV_INT_MASK                 (0x80000000U)
#define USB_INTSTAT_DEV_INT_SHIFT                (31U)
#define USB_INTSTAT_DEV_INT(x)                   (((uint32_t)(((uint32_t)(x)) << USB_INTSTAT_DEV_INT_SHIFT)) & USB_INTSTAT_DEV_INT_MASK)
/*! @} */

/*! @name INTEN -  */
/*! @{ */

#define USB_INTEN_INT_EN_MASK                    (0xFFFFFFFFU)
#define USB_INTEN_INT_EN_SHIFT                   (0U)
#define USB_INTEN_INT_EN(x)                      (((uint32_t)(((uint32_t)(x)) << USB_INTEN_INT_EN_SHIFT)) & USB_INTEN_INT_EN_MASK)
/*! @} */

/*! @name INTSETSTAT -  */
/*! @{ */

#define USB_INTSETSTAT_SET_INT_MASK              (0xFFFFFFFFU)
#define USB_INTSETSTAT_SET_INT_SHIFT             (0U)
#define USB_INTSETSTAT_SET_INT(x)                (((uint32_t)(((uint32_t)(x)) << USB_INTSETSTAT_SET_INT_SHIFT)) & USB_INTSETSTAT_SET_INT_MASK)
/*! @} */

/*! @name INTROUTING -  */
/*! @{ */

#define USB_INTROUTING_ROUT_INT_MASK             (0xFFFFFFFFU)
#define USB_INTROUTING_ROUT_INT_SHIFT            (0U)
#define USB_INTROUTING_ROUT_INT(x)               (((uint32_t)(((uint32_t)(x)) << USB_INTROUTING_ROUT_INT_SHIFT)) & USB_INTROUTING_ROUT_INT_MASK)
/*! @} */

/*! @name CONFIGURATION -  */
/*! @{ */

#define USB_CONFIGURATION_PHYSEP_MASK            (0x1FU)
#define USB_CONFIGURATION_PHYSEP_SHIFT           (0U)
#define USB_CONFIGURATION_PHYSEP(x)              (((uint32_t)(((uint32_t)(x)) << USB_CONFIGURATION_PHYSEP_SHIFT)) & USB_CONFIGURATION_PHYSEP_MASK)

#define USB_CONFIGURATION_SB_MASK                (0x20U)
#define USB_CONFIGURATION_SB_SHIFT               (5U)
#define USB_CONFIGURATION_SB(x)                  (((uint32_t)(((uint32_t)(x)) << USB_CONFIGURATION_SB_SHIFT)) & USB_CONFIGURATION_SB_MASK)

#define USB_CONFIGURATION_DB_MASK                (0x40U)
#define USB_CONFIGURATION_DB_SHIFT               (6U)
#define USB_CONFIGURATION_DB(x)                  (((uint32_t)(((uint32_t)(x)) << USB_CONFIGURATION_DB_SHIFT)) & USB_CONFIGURATION_DB_MASK)

#define USB_CONFIGURATION_TREG_MASK              (0x80U)
#define USB_CONFIGURATION_TREG_SHIFT             (7U)
#define USB_CONFIGURATION_TREG(x)                (((uint32_t)(((uint32_t)(x)) << USB_CONFIGURATION_TREG_SHIFT)) & USB_CONFIGURATION_TREG_MASK)
/*! @} */

/*! @name EPTOGGLE -  */
/*! @{ */

#define USB_EPTOGGLE_TOGGLE_MASK                 (0x3FFFFFFFU)
#define USB_EPTOGGLE_TOGGLE_SHIFT                (0U)
#define USB_EPTOGGLE_TOGGLE(x)                   (((uint32_t)(((uint32_t)(x)) << USB_EPTOGGLE_TOGGLE_SHIFT)) & USB_EPTOGGLE_TOGGLE_MASK)
/*! @} */

/*! @name INTPLL -  */
/*! @{ */

#define USB_INTPLL_SEL_EXT_CLK_MASK              (0x1U)
#define USB_INTPLL_SEL_EXT_CLK_SHIFT             (0U)
#define USB_INTPLL_SEL_EXT_CLK(x)                (((uint32_t)(((uint32_t)(x)) << USB_INTPLL_SEL_EXT_CLK_SHIFT)) & USB_INTPLL_SEL_EXT_CLK_MASK)
/*! @} */


/*!
 * @}
 */ /* end of group USB_Register_Masks */


/* USB - Peripheral instance base addresses */
/** Peripheral USB base address */
#define USB_BASE                                 (0x40001000u)
/** Peripheral USB base pointer */
#define USB                                      ((USB_Type *)USB_BASE)
/** Array initializer of USB peripheral base addresses */
#define USB_BASE_ADDRS                           { USB_BASE }
/** Array initializer of USB peripheral base pointers */
#define USB_BASE_PTRS                            { USB }
/** Interrupt vectors for the USB peripheral type */
#define USB_IRQS                                 { USB_IRQn }
/* Backward compatibility */
#define USB_DEVCMDSTAT_FORCE_NEEDCLK_MASK        USB_DEVCMDSTAT_PLL_ON_MASK
#define USB_DEVCMDSTAT_FORCE_NEEDCLK_SHIFT       USB_DEVCMDSTAT_PLL_ON_SHIFT
#define USB_DEVCMDSTAT_FORCE_NEEDCLK(x)          USB_DEVCMDSTAT_PLL_ON(x)


/*!
 * @}
 */ /* end of group USB_Peripheral_Access_Layer */


/*
** End of section using anonymous unions
*/

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang diagnostic pop
  #else
    #pragma pop
  #endif
#elif defined(__GNUC__)
  /* leave anonymous unions enabled */
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma language=default
#else
  #error Not supported compiler type
#endif

/*!
 * @}
 */ /* end of group Peripheral_access_layer */


/* ----------------------------------------------------------------------------
   -- Macros for use with bit field definitions (xxx_SHIFT, xxx_MASK).
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup Bit_Field_Generic_Macros Macros for use with bit field definitions (xxx_SHIFT, xxx_MASK).
 * @{
 */

#if defined(__ARMCC_VERSION)
  #if (__ARMCC_VERSION >= 6010050)
    #pragma clang system_header
  #endif
#elif defined(__IAR_SYSTEMS_ICC__)
  #pragma system_include
#endif

/**
 * @brief Mask and left-shift a bit field value for use in a register bit range.
 * @param field Name of the register bit field.
 * @param value Value of the bit field.
 * @return Masked and shifted value.
 */
#define NXP_VAL2FLD(field, value)    (((value) << (field ## _SHIFT)) & (field ## _MASK))
/**
 * @brief Mask and right-shift a register value to extract a bit field value.
 * @param field Name of the register bit field.
 * @param value Value of the register.
 * @return Masked and shifted bit field value.
 */
#define NXP_FLD2VAL(field, value)    (((value) & (field ## _MASK)) >> (field ## _SHIFT))

/*!
 * @}
 */ /* end of group Bit_Field_Generic_Macros */


/* ----------------------------------------------------------------------------
   -- SDK Compatibility
   ---------------------------------------------------------------------------- */

/*!
 * @addtogroup SDK_Compatibility_Symbols SDK Compatibility
 * @{
 */

/* No SDK compatibility issues. */

/*!
 * @}
 */ /* end of group SDK_Compatibility_Symbols */


#endif  /* _PN7642_H_ */

