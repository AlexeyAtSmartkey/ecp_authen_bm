/*
 * Copyright 2022-2023 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_POWER_H_
#define _FSL_POWER_H_

#include "fsl_common.h"
#include "Pcrm_Hp_Reg.h"
#include "Pcrm_Lp_Reg.h"

/*!
 * @defgroup power POWER: Power Driver
 * @details This driver covers the PMU functions and SMU functions in PCRM module. PMU functions include
 * VBAT and USB VBUS. SMU functions include the lower power modes, such as standby mode,
 * ULP standby mode, ULPCD mode, and so on.
 *
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @brief PMU driver version. */
#define FSL_PMU_DRIVER_VERSION (MAKE_VERSION(2, 1, 0))

#ifndef PMU_USB_VBUS_DEBOUNCE_TIMEOUT
#define PMU_USB_VBUS_DEBOUNCE_TIMEOUT (0x0474) /**< USB VBUS debounce time, used for USB VBUS detection */
#endif

#ifndef PMU_USB_VBUSOK_WAIT_TIME
#define PMU_USB_VBUSOK_WAIT_TIME (5) /**< Timeout for waiting for USB VBUS HI (Unit - us) */
#endif

#ifndef PMU_USB_VBUS_FASTDISCHARGE_ENABLE
#define PMU_USB_VBUS_FASTDISCHARGE_ENABLE (0) /**< Enable/Disable Fast discharge for USB VBUS */
#endif

#define SMU_BOOT_REASON()    (dwBootReason)

/** Definition for the boot reason position according to register definitions */
#define SMU_BOOT1_STS_BOOT_REASON_POS         PCRM_SYS_BOOT1_STS_BOOT_POR_POS
#define SMU_BOOT1_STS_BOOT_REASON_LAST_POS    PCRM_SYS_BOOT1_STS_BOOT_SPI_POS

/** Definition for the boot reason mask according to register definitions */
#define SMU_BOOT1_STS_BOOT_REASON_MASK  (PCRM_SYS_BOOT1_STS_BOOT_SPI_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_I2C_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_I3C_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_HSU_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_GPIO2_MASK 		| \
                                         PCRM_SYS_BOOT1_STS_BOOT_LPDET_MASK 		| \
                                         PCRM_SYS_BOOT1_STS_BOOT_RX_ULPDET_MASK 	| \
                                         PCRM_SYS_BOOT1_STS_BOOT_VDDIO_LOSS_MASK 	| \
                                         PCRM_SYS_BOOT1_STS_BOOT_WUC_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_TEMP_MASK 			| \
                                         PCRM_SYS_BOOT1_STS_BOOT_VUPDET_MASK 		| \
                                         PCRM_SYS_BOOT1_STS_BOOT_RXPROT_MASK 		| \
                                         PCRM_SYS_BOOT1_STS_BOOT_POR_MASK)

/** Definition for the boot reset mask according to register definitions */
#define SMU_BOOT3_STS_RESET_REASON_POS        PCRM_SYS_BOOT3_STS_RST_STS_CPU_POS
#define SMU_BOOT3_STS_RESET_REASON_MASK      (PCRM_SYS_BOOT3_STS_RST_STS_NFC_MASK  | \
                                              PCRM_SYS_BOOT3_STS_RST_STS_FSM_MASK  | \
                                              PCRM_SYS_BOOT3_STS_RST_STS_CMD_MASK  | \
                                              PCRM_SYS_BOOT3_STS_RST_STS_WDG_MASK  | \
                                              PCRM_SYS_BOOT3_STS_RESERVED1_MASK    | \
                                              PCRM_SYS_BOOT3_STS_RST_STS_HOST_MASK | \
                                              PCRM_SYS_BOOT3_STS_RST_STS_CPU_MASK)
/** \name Standby wake-up sources
 * @{
 */
#define SMU_WAKEUP_SOURCE_TIMER      (0x00000001UL) /**< Wake Up source is Timer */
#define SMU_WAKEUP_SOURCE_HOST       (0x00000002UL) /**< Wake Up source is communication on Host Interface */
#define SMU_WAKEUP_SOURCE_RFFIELD    (0x00000004UL) /**< Wake Up source is Presence of External RF Field */
#define SMU_WAKEUP_SOURCE_TEMPSENSOR (0x00000008UL) /**< Wake Up source is Temperature of the IC */

#define SMU_WAKEUP_SOURCE_VUP         (0x00000010UL) /**< Wake Up source is Voltage Monitor */
#define SMU_WAKEUP_SOURCE_VDDIO_LOSS  (0x00000020UL) /**< Wake Up due to VDDIO loss */
#define SMU_WAKEUP_SOURCE_RX_PROT     (0x00000040UL) /**< Wake Up in case of RX_PROT */
#define SMU_WAKEUP_SOURCE_VDDIO_START (0x00000080UL) /**< Wake Up in case of VDDIO Start */
#define SMU_WAKEUP_SOURCE_CT_AUX      (0x00010000UL) /**< Wake Up in case of CT present */

/* GPIOx as wakeup sources */
#define SMU_WAKEUP_SOURCE_GPIO_MASK         (0x00000F00UL)  /**< Bit mask for GPIO wake up sources  */
#define SMU_WAKEUP_SOURCE_GPIO_POS          (8U)            /**< Bit position for GPIO wakeup sourves  */
#define SMU_WAKEUP_SOURCE_GPIO0             (0x00000100UL)  /**< Wake Up source is GPIO0 */
#define SMU_WAKEUP_SOURCE_GPIO1             (0x00000200UL)  /**< Wake Up source is GPIO1 */
#define SMU_WAKEUP_SOURCE_GPIO2             (0x00000400UL)  /**< Wake Up source is GPIO2 */
#define SMU_WAKEUP_SOURCE_GPIO3             (0x00000800UL)  /**< Wake Up source is GPIO3 */
#define SMU_WAKEUP_SOURCE_ULPDET            (0x00001000UL)  /**< Wake Up source is ULPDET */
#define SMU_WAKEUP_SOURCE_VEN_LOW           (0x00002000UL)  /**< Wake Up source is VEN LOW */
#define SMU_WAKEUP_SOURCE_CARD_DET          (0x00004000UL)  /**< Wake Up source is Card detect */
#define SMU_WAKEUP_SOURCE_CURRENT           (0x00008000UL)  /**< Wake Up source is OVER CURRENT */
#define SMU_WAKEUP_SOURCE_XTAL_TIMEOUT      (0x00010000UL)  /**< Wake Up source is XTAL TIME OUT */
#define SMU_WAKEUP_SOURCE_CLKDET_ERROR      (0x00020000UL)  /**< Wake Up source is clk detect error */
#define SMU_WAKEUP_SOURCE_VBAT_MIN          (0x00040000UL)  /**< Wake Up source is VBat min */

/** @} */

#define SMU_PREVENTED_USER_ABORT (0x04000000UL) /**< Prevention reason in case of User aborting standby */


#define SMU_BOOT_REASON_WUC_ONLY  (PCRM_SYS_BOOT1_STS_BOOT_WUC_MASK | (PCRM_SYS_BOOT3_STS_RST_STS_FSM_MASK << (PCRM_SYS_BOOT1_STS_BOOT_SPI_POS + 1)))    /**< For WUC boot reason PCRM_SYS_BOOT1_STS_BOOT_WUC_MASK and PCRM_SYS_BOOT3_STS_RST_STS_FSM_MASK bits are set corresponding value is 0x04000010 */

/* Register Operations */
/** Macro to write a register */
#define PCRM_SETREG(RegAddr, RegVal) (void)PN76_Sys_WriteRegister((RegAddr), (RegVal))
/** Macro to set a bit */
#define PCRM_SETBITN(RegAddr, BitPos) (void)PN76_Sys_WriteRegisterOrMask((RegAddr), (1UL << (uint32_t)(BitPos)))
/** Macro to clear a bit */
#define PCRM_CLEARBITN(RegAddr, BitPos) (void)PN76_Sys_WriteRegisterAndMask((RegAddr), ~(1UL << (uint32_t)(BitPos)))
/** Macro to write a specific field in a register */
#define PCRM_SETFIELD(RegAddr, BitMask, MaskVal) (void)PN76_Sys_WriteRegisterField((RegAddr), (uint32_t)(BitMask), (uint32_t)(MaskVal))
/** Macro to write a specific field at specific position in a register */
#define PCRM_SETFIELDSHIFT(RegAddr, BitMask, BitPos, Value) \
    (void)PN76_Sys_WriteRegisterField((RegAddr), (uint32_t)(BitMask), ((uint32_t)(Value) << (uint32_t)(BitPos)))
/** Macro to to test a bit */
#define PCRM_TESTBITN(RegAddr, BitPos)    PCRM_TestBitN((RegAddr), (BitPos))

#define PMU_USB_VBUS_DEBOUNCE_TIMEOUT     (0x0474) /**< USB VBUS debounce time, used for USB VBUS detection */
/**
 * @brief  Host interface selection
 */
typedef enum _smu_hif_sel
{
    kSMU_HifNone = 0, /**< no Interface selected (Reset state) */
    kSMU_HifI2c  = 1, /**< I2C selected */
    kSMU_HifSpi  = 2, /**< SPI selected */
    kSMU_HifUart = 3, /**< UART selected */
    kSMU_HifI3c  = 4, /**< I3C selected */
} smu_hif_sel_t;

/**
 * @brief Standby Prevention Reasons
 */
typedef enum _smu_standby_prev_reason
{
    /** Standby applied */
    kSMU_Success = 0U,

    /** User Abort */
    kSMU_UserAbort = SMU_PREVENTED_USER_ABORT,

    /** Host communication ongoing */
    kSMU_HostCommOngoing = PCRM_SYS_BOOT2_STS_PREV_HOSTCOMM_MASK,

    /** SPI interface selected and spi_nss pin is low */
    kSMU_SpiSelected = PCRM_SYS_BOOT2_STS_PREV_SPI_MASK,

    /** I2C interface selected and Venus I2C address detected */
    kSMU_I2cAddressSelected = PCRM_SYS_BOOT2_STS_PREV_I2C_MASK,

    /** I3C interface selected and Venus I2C address detected */
    kSMU_I3cAddressSelected = PCRM_SYS_BOOT2_STS_PREV_I3C_MASK,

    /** HSU interface selected and hsu_rx pin is low */
    kSMU_HsuSelected = PCRM_SYS_BOOT2_STS_PREV_HSU_MASK,

    /** GPIO3 selected and GPIO3 pins has polarity as wakeup polarity  */
    kSMU_Gpio3Selected = PCRM_SYS_BOOT2_STS_PREV_GPIO3_MASK,

    /** GPIO2 selected and GPIO2 pins has polarity as wakeup polarity  */
    kSMU_Gpio2Selected = PCRM_SYS_BOOT2_STS_PREV_GPIO2_MASK,

    /** GPIO1 selected and GPIO1 pins has polarity as wakeup polarity  */
    kSMU_Gpio1Selected = PCRM_SYS_BOOT2_STS_PREV_GPIO1_MASK,

    /** GPIO0 selected and GPIO0 pins has polarity as wakeup polarity  */
    kSMU_Gpio0Selected = PCRM_SYS_BOOT2_STS_PREV_GPIO0_MASK,

    /** Wake up counter is enabled but wake up counter value is equal to zero */
    kSMU_WucEqualZero = PCRM_SYS_BOOT2_STS_PREV_WUC_MASK,

    /** Either RF Level detector is activated as wake up source and RF level
         Detector is not enabled or RF Field is already present */
    kSMU_LpdetEvent = PCRM_SYS_BOOT2_STS_PREV_LPDET_MASK,

    /** ULPDET wakeup active */
    kSMU_UlpdetEvent = PCRM_SYS_BOOT2_STS_PREV_RX_ULPDET_MASK,

    /** Host Interface is selected as wake up source and no VDDIO is available */
    kSMU_NoVddioOn = PCRM_SYS_BOOT2_STS_PREV_INT_NO_VDDIO_MASK,

    /** Temperature Error is selected as wake up source AND the temp_error_irq signal is low */
    kSMU_TempErrorLow = PCRM_SYS_BOOT2_STS_PREV_TEMP_MASK,

    /** Wrong HIF Selection or NSS is low */
    kSMU_InterfaceError = PCRM_SYS_BOOT2_STS_PREV_INTERFACE_MASK,

    /** power loss on VDDIO */
    kSMU_VddioLoss = PCRM_SYS_BOOT2_STS_PREV_VDDIO_LOSS_MASK,

    /** No Wake up source in the PCRM_SYS_STBY_CFG is enabled. */
    kSMU_NoWakeupEnabled = PCRM_SYS_BOOT2_STS_PREV_NOENABLE_MASK,

    /** VUP has been switched on */
    kSMU_VupDetected = PCRM_SYS_BOOT2_STS_PREV_VUPDET_MASK,

    /** RX Prot */
    kSMU_RxProt = PCRM_SYS_BOOT2_STS_PREV_RXPROT_MASK,
} smu_standby_prev_reason_t;
/**
 * @brief  Enum for the Storing the LPCD States during standby in GPREG6
 */
typedef enum
{
   // REF DATA AVAILABLE FLAG 1 bit
   PHHAL_HW_PN76XX_GPREG_6_REF_DATA_AVAILABLE_POS        = 0UL,
   PHHAL_HW_PN76XX_GPREG_6_REF_DATA_AVAILABLE_MASK       = 0x00000001UL,

   // DEBUG GPIO 1 bit
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU1_POS                  = 1UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU1_MASK                 = 0x00000002UL,

   // LPCD Event enable
   PHHAL_HW_PN76XX_GPREG_6_LPCD_ENABLED_POS                 = 2UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_ENABLED_MASK                = 0x00000004UL,

   // LPCD command active
   PHHAL_HW_PN76XX_GPREG_6_LPCD_CMD_ACTIVE_POS         = 3UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_CMD_ACTIVE_MASK        = 0x00000008UL,

   // Calibration Done
   PHHAL_HW_PN76XX_GPREG_6_LPCD_CAL_DONE_POS           = 4UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_CAL_DONE_MASK          = 0x00000010UL,

   // External RF Field mask
   PHHAL_HW_PN76XX_GPREG_6_LPCD_EXT_RF_FIELD_POS           = 5UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_EXT_RF_FIELD_MASK          = 0x00000020UL,

   // External RF Field mask
   PHHAL_HW_PN76XX_GPREG_6_LPCD_INT_ONGOING_POS            = 6UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_INT_ONGOING_MASK          = 0x00000040UL,

   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_STARTED_POS         = 7UL,
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_STARTED_MASK        = 0x00000080UL,

   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_SWITCH_WUC_POS         = 8UL,
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_SWITCH_WUC_MASK        = 0x00000100UL,

   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_CAL_EVT_MEAS_MODE_POS         = 9UL,
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_CAL_EVT_MEAS_MODE_MASK        = 0x00000200UL,

   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_CAL_DONE_POS         = 10UL,
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_CAL_DONE_MASK        = 0x00000400UL,

   // single mode wuc counter
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_WUC_POS          = 12UL,
   PHHAL_HW_PN76XX_GPREG_6_SINGLE_LPCD_WUC_MASK         = 0x003FF000UL,

   // NVRAM logger type selection on 2 bits
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU4_POS   = 24UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU4_MASK  = 0x03000000UL,

   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU5_POS   = 26UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU5_MASK  = 0x04000000UL,

   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU6_POS  = 29UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_RFU6_MASK = 0x20000000UL,

   PHHAL_HW_PN76XX_GPREG_6_LPCD_REQUEST_REF_POS          = 30UL,
   PHHAL_HW_PN76XX_GPREG_6_LPCD_REQUEST_REF_MASK         = 0x40000000UL,

} PN76xx_Gpreg_6_PosMask_t;
/**
 * @brief  Enum for the storing wakeup source during LPCD.
 */
typedef enum
{
   PHHAL_HW_PN76XX_GPREG_8_POS_WAKEUP_SOURCE  = 0UL,  /**< Wake source to be used when re-entering into standby */
   PHHAL_HW_PN76XX_GPREG_8_POS_WAKEUP_COUNTER = 22UL  /**< Wake-up counter value */
}PN76xx_Gpreg_8_Pos_t;

/**
 * @brief  Enum for the storing wakeup source and interval during LPCD.
 */
typedef enum
{
   PHHAL_HW_PN76XX_GPREG_8_MASK_WAKEUP_SOURCE  = 0x003FFFFFUL,  /**< Wake source to be used when re-entering into standby */
#ifndef __QAC__
   PHHAL_HW_PN76XX_GPREG_8_MASK_WAKEUP_COUNTER = 0xFFC00000UL   /**< Wake-up counter value */
#else
   PHHAL_HW_PN76XX_GPREG_8_MASK_WAKEUP_COUNTER  /**< to satisfy QAC */
#endif
}PN76xx_Gpreg_8_Mask_t;

/*! @brief PMU event. */
typedef enum
{
    kPMU_EventOverCurrent, /*!< Over current. */
    kPMU_EventOverTemp,    /*!< Over temperature. */
    kPMU_EventVddioOk,     /*!< VDDIO OK. */
} pmu_event_t;

/*! @brief PMU callback. */
typedef void (*pmu_callback_t)(pmu_event_t event);

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/*! @name PMU APIs*/
/*@{*/

/*! @brief    This Initializes the Power Management Unit.
 */
void PMU_Init(void);

/*! @brief    This function is called when Pmu interrupt is triggered.
 */
void PMU_HandleIRQ(void);

/*!
 * @brief This function configures the VBAT monitoring FSM.
 *
 * @param enableMonitor Enable/disable VBAT monitor
 * @param setStandbyCfg  Put the standby configuration if true
 */
void PMU_VbatMonitorConfig(bool enableMonitor, bool setStandbyCfg);

/*!
 * @brief This function enables USB VBUS Monitor and checks USB VBUS.
 *
 * @retval  kStatus_Success Operation successful
 * @retval  kStatus_Timeout Operation Timed out
 */
status_t PMU_UsbVbusCheck(void);

/*!
 * @brief This function checks the USB power.
 *
 * @retval  kStatus_Success USB power is OK.
 * @retval  kStatus_Fail USB power is not available.
 */
status_t POWER_CheckUsbPower(void);

/*!
 * @brief Register PMU callback called when PMU event happens.
 */
void PMU_RegisterCallback(pmu_callback_t callback);

void PCRM_IRQHandler(void);
/* @} */

/*! @name SMU APIs */
/*@{*/

/*!
 * @brief This function is used to Initialize the Smu.
 * @return  Nothing to Return
 */
void SMU_Init(void);

/*!
 *  @brief    This function is used to test a bit
 *
 * @param wRegAddr   : Register Address
 * @param dwBitPos   : Bit position to test.
 * @return    TRUE: If the bit is set
 * @return    FALSE: If the bit is Cleared
 */
extern bool PCRM_TestBitN(uint16_t wRegAddr, uint32_t dwBitPos);
/* @} */
#if defined(__cplusplus)
}
#endif /* __cplusplus */

/*! @} */

#endif /* _FSL_POWER_H_ */
