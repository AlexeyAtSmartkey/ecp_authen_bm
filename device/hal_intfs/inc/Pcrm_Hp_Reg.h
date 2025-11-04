/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                                   */
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

/** @file
 *
 * PCRM APB register and bit definitions
 *
 * $Author: $
 * $Revision: $ (01.01.00)
 */

#ifndef _PCRM_HP_REG_H_
#define _PCRM_HP_REG_H_

/** @addtogroup PN76PCRMHpRegDefs
 *
 * @brief PCRM HP Software register and bit definitions
 * To access these register, use System Service Register Interface API's
 * @{
 *
 */

/**
* @name pcrm_clif_ulpdet_disable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_ULPDET_DISABLE                                                                          0xE1
#define PCRM_CLIF_ULPDET_DISABLE_R                                                                          0xE1
#define PCRM_CLIF_ULPDET_DISABLE_W                                                                          0xE1
#define PCRM_CLIF_ULPDET_DISABLE_RESERVED_POS                                                            (1UL)
#define PCRM_CLIF_ULPDET_DISABLE_RESERVED_MASK                                                           (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_CLIF_ULPDET_DISABLE_RX_ULPDET_DISABLE_POS                                                   (0UL)
#define PCRM_CLIF_ULPDET_DISABLE_RX_ULPDET_DISABLE_MASK                                                  (0x00000001UL)  /**< 0-Write '1' and sequentially write '0' will disable RX ULPDET function.*/
#define PCRM_CLIF_ULPDET_DISABLE__RESET_VALUE                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_clif_ulpdet_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_ULPDET_ENABLE                                                                           0xE2
#define PCRM_CLIF_ULPDET_ENABLE_R                                                                           0xE2
#define PCRM_CLIF_ULPDET_ENABLE_W                                                                           0xE2
#define PCRM_CLIF_ULPDET_ENABLE_RESERVED_POS                                                             (1UL)
#define PCRM_CLIF_ULPDET_ENABLE_RESERVED_MASK                                                            (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_CLIF_ULPDET_ENABLE_RX_ULPDET_ENABLE_POS                                                     (0UL)
#define PCRM_CLIF_ULPDET_ENABLE_RX_ULPDET_ENABLE_MASK                                                    (0x00000001UL)  /**< 0-Write '1'  and sequentially write '0' will enable RX ULPDET function*/
#define PCRM_CLIF_ULPDET_ENABLE__RESET_VALUE                                                         (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ana_usbpll_mode
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ANA_USBPLL_MODE                                                                              0xE3
#define PCRM_ANA_USBPLL_MODE_R                                                                              0xE3
#define PCRM_ANA_USBPLL_MODE_W                                                                              0xE3
#define PCRM_ANA_USBPLL_MODE_RESERVED_POS                                                                (6UL)
#define PCRM_ANA_USBPLL_MODE_RESERVED_MASK                                                               (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_BYPASS_PDIV2_POS                                                     (5UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_BYPASS_PDIV2_MASK                                                    (0x00000020UL)  /**< 5-Bypass of the divide by 2 divider in the post divider.*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_DIRECTO_POS                                                          (4UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_DIRECTO_MASK                                                         (0x00000010UL)  /**< 4-Bypass of the post-divider*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_DIRECTI_POS                                                          (3UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_DIRECTI_MASK                                                         (0x00000008UL)  /**< 3-Bypass of the pre-divider*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_BYPASS_POS                                                           (2UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_BYPASS_MASK                                                          (0x00000004UL)  /**< 2-Bypass of the PLL (input clock to output clock)*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_CLKEN_POS                                                            (1UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_CLKEN_MASK                                                           (0x00000002UL)  /**< 1-Enable of the output clock of the PLL*/
#define PCRM_ANA_USBPLL_MODE_USBPLL_POWER_ENABLE_POS                                                     (0UL)
#define PCRM_ANA_USBPLL_MODE_USBPLL_POWER_ENABLE_MASK                                                    (0x00000001UL)  /**< 0-Power enable input of the PLL (active high)*/
#define PCRM_ANA_USBPLL_MODE__RESET_VALUE                                                         (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ana_usbpll_div
* <b>Reset value:</b> 0x0500B10A
* <b>Access:</b> rw
* @{
*/
#define PCRM_ANA_USBPLL_DIV                                                                               0xE4
#define PCRM_ANA_USBPLL_DIV_R                                                                               0xE4
#define PCRM_ANA_USBPLL_DIV_W                                                                               0xE4
#define PCRM_ANA_USBPLL_DIV_RESERVED_POS                                                                 (29UL)
#define PCRM_ANA_USBPLL_DIV_RESERVED_MASK                                                                (0xE0000000UL)  /**< 29-reserved*/
#define PCRM_ANA_USBPLL_DIV_USBPLL_PDIV_POS                                                              (24UL)
#define PCRM_ANA_USBPLL_DIV_USBPLL_PDIV_MASK                                                             (0x1F000000UL)  /**< 24-Post divider ratio (P-divider)*/
#define PCRM_ANA_USBPLL_DIV_USBPLL_MDIV_POS                                                              (8UL)
#define PCRM_ANA_USBPLL_DIV_USBPLL_MDIV_MASK                                                             (0x00FFFF00UL)  /**< 8-Feedback divider ratio (M-divider)*/
#define PCRM_ANA_USBPLL_DIV_USBPLL_NDIV_POS                                                              (0UL)
#define PCRM_ANA_USBPLL_DIV_USBPLL_NDIV_MASK                                                             (0x000000FFUL)  /**< 0-Predivider ratio (N-divider)*/
#define PCRM_ANA_USBPLL_DIV__RESET_VALUE                                                                  (0x0500B10AUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_ctrl3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ULPCD_CTRL3                                                                                  0xE5
#define PCRM_ULPCD_CTRL3_R                                                                                  0xE5
#define PCRM_ULPCD_CTRL3_W                                                                                  0xE5
#define PCRM_ULPCD_CTRL3_LOAD_POS                                                                        (31UL)
#define PCRM_ULPCD_CTRL3_LOAD_MASK                                                                       (0x80000000UL)  /**< 31-Load ULPCD control signal to PCRM-AON */
#define PCRM_ULPCD_CTRL3_RESERVED_POS                                                                    (29UL)
#define PCRM_ULPCD_CTRL3_RESERVED_MASK                                                                   (0x60000000UL)  /**< 29-reserved*/
#define PCRM_ULPCD_CTRL3_ULP_STANDBY_POS                                                                 (28UL)
#define PCRM_ULPCD_CTRL3_ULP_STANDBY_MASK                                                                (0x10000000UL)  /**< 28-Ultra Low Power Standby*/
#define PCRM_ULPCD_CTRL3_RESERVED1_POS                                                                    (27UL)
#define PCRM_ULPCD_CTRL3_RESERVED1_MASK                                                                   (0x08000000UL)  /**< 27-reserved*/
#define PCRM_ULPCD_CTRL3_RSSI_REFERENCE_POS                                                              (16UL)
#define PCRM_ULPCD_CTRL3_RSSI_REFERENCE_MASK                                                             (0x07FF0000UL)  /**< 16-Relative Signal Strength Reference Level*/
#define PCRM_ULPCD_CTRL3_RESERVED2_POS                                                                    (15UL)
#define PCRM_ULPCD_CTRL3_RESERVED2_MASK                                                                   (0x00008000UL)  /**< 15-reserved*/
#define PCRM_ULPCD_CTRL3_RSSI_THRESHOLD_POS                                                              (10UL)
#define PCRM_ULPCD_CTRL3_RSSI_THRESHOLD_MASK                                                             (0x00007C00UL)  /**< 10-Relative signal Strenght Threshold Level*/
#define PCRM_ULPCD_CTRL3_RSSI_SAMPLES_POS                                                                (8UL)
#define PCRM_ULPCD_CTRL3_RSSI_SAMPLES_MASK                                                               (0x00000300UL)  /**< 8-Number of RSSI samples*/
#define PCRM_ULPCD_CTRL3_RESERVED3_POS                                                                    (7UL)
#define PCRM_ULPCD_CTRL3_RESERVED3_MASK                                                                   (0x00000080UL)  /**< 7-reserved*/
#define PCRM_ULPCD_CTRL3_RSSI_NSPL_POS                                                                   (0UL)
#define PCRM_ULPCD_CTRL3_RSSI_NSPL_MASK                                                                  (0x0000007FUL)  /**< 0-RSSI NSPL for LP GPADC*/
#define PCRM_ULPCD_CTRL3__RESET_VALUE                                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_ctrl2
* <b>Reset value:</b> 0x00000050
* <b>Access:</b> rw
* @{
*/
#define PCRM_ULPCD_CTRL2                                                                                  0xE6
#define PCRM_ULPCD_CTRL2_R                                                                                  0xE6
#define PCRM_ULPCD_CTRL2_W                                                                                  0xE6
#define PCRM_ULPCD_CTRL2_RESERVED_POS                                                                    (23UL)
#define PCRM_ULPCD_CTRL2_RESERVED_MASK                                                                   (0xFF800000UL)  /**< 23-reserved*/
#define PCRM_ULPCD_CTRL2_ULPCD_VCM_TRIM_POS                                                              (19UL)
#define PCRM_ULPCD_CTRL2_ULPCD_VCM_TRIM_MASK                                                             (0x00780000UL)  /**< 19-VCM Trim value */
#define PCRM_ULPCD_CTRL2_ULPCD_GPIO3_ABORT_POLARITY_POS                                                  (18UL)
#define PCRM_ULPCD_CTRL2_ULPCD_GPIO3_ABORT_POLARITY_MASK                                                 (0x00040000UL)  /**< 18-ULPCD GPIO3 abort polarity*/
#define PCRM_ULPCD_CTRL2_ULPCD_GPIO3_ABORT_EN_POS                                                        (17UL)
#define PCRM_ULPCD_CTRL2_ULPCD_GPIO3_ABORT_EN_MASK                                                       (0x00020000UL)  /**< 17-ULPCD GPIO3 abort enable*/
#define PCRM_ULPCD_CTRL2_ULPCD_CALIBRATION_POS                                                           (16UL)
#define PCRM_ULPCD_CTRL2_ULPCD_CALIBRATION_MASK                                                          (0x00010000UL)  /**< 16-ULPCD calibration enable*/
#define PCRM_ULPCD_CTRL2_RESERVED1_POS                                                               (15UL)
#define PCRM_ULPCD_CTRL2_RESERVED1_MASK                                                             (0x00008000UL)  /**< 15-reserved*/
#define PCRM_ULPCD_CTRL2_VBAT_THRESH_SEL_POS                                                             (14UL)
#define PCRM_ULPCD_CTRL2_VBAT_THRESH_SEL_MASK                                                            (0x00004000UL)  /**< 14-VBAT threshold select*/
#define PCRM_ULPCD_CTRL2_VBAT_EN_POS                                                                     (13UL)
#define PCRM_ULPCD_CTRL2_VBAT_EN_MASK                                                                    (0x00002000UL)  /**< 13-VBAT enable*/
#define PCRM_ULPCD_CTRL2_VEN_INTERNAL_POS                                                                (12UL)
#define PCRM_ULPCD_CTRL2_VEN_INTERNAL_MASK                                                               (0x00001000UL)  /**< 12-VEN internal */
#define PCRM_ULPCD_CTRL2_ULPCD_SPARE_POS                                                                 (8UL)
#define PCRM_ULPCD_CTRL2_ULPCD_SPARE_MASK                                                                (0x00000F00UL)  /**< 8-SPARE register for retention*/
#define PCRM_ULPCD_CTRL2_RESERVED2_POS                                                                    (7UL)
#define PCRM_ULPCD_CTRL2_RESERVED2_MASK                                                                   (0x00000080UL)  /**< 7-reserved*/
#define PCRM_ULPCD_CTRL2_XTAL_NOVERLAP_TRIMMING_POS                                                      (4UL)
#define PCRM_ULPCD_CTRL2_XTAL_NOVERLAP_TRIMMING_MASK                                                     (0x00000070UL)  /**< 4-XTAL No-overlap trimming*/
#define PCRM_ULPCD_CTRL2_ULFO_TRIM_POS                                                                   (0UL)
#define PCRM_ULPCD_CTRL2_ULFO_TRIM_MASK                                                                  (0x0000000FUL)  /**< 0-ULFO trim value*/
#define PCRM_ULPCD_CTRL2__RESET_VALUE                                                                       (0x00000050UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_ctrl1
* <b>Reset value:</b> 0x007F0000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ULPCD_CTRL1                                                                                  0xE7
#define PCRM_ULPCD_CTRL1_R                                                                                  0xE7
#define PCRM_ULPCD_CTRL1_W                                                                                  0xE7
#define PCRM_ULPCD_CTRL1_BYPASS_VBAT_MON_CHECK_AT_BOOT_POS                                               (31UL)
#define PCRM_ULPCD_CTRL1_BYPASS_VBAT_MON_CHECK_AT_BOOT_MASK                                              (0x80000000UL)  /**< 31-reserved*/
#define PCRM_ULPCD_CTRL1_TX_SUPPLY_INTERNAL_POS                                                          (30UL)
#define PCRM_ULPCD_CTRL1_TX_SUPPLY_INTERNAL_MASK                                                         (0x40000000UL)  /**< 30-1: Internal TX supply, 0: External TX supply*/
#define PCRM_ULPCD_CTRL1_RFON_GUARD_TIME_POS                                                             (26UL)
#define PCRM_ULPCD_CTRL1_RFON_GUARD_TIME_MASK                                                            (0x3C000000UL)  /**< 26-RFON guard time: Trfon_guard_time = (RFON_GUARD_TIME + 2) * Tlfo*/
#define PCRM_ULPCD_CTRL1_TX_EN_DRV_DELAY_POS                                                             (24UL)
#define PCRM_ULPCD_CTRL1_TX_EN_DRV_DELAY_MASK                                                            (0x03000000UL)  /**< 24-TX enable driver delay:  Ttx_enable_driver_delay = {5, 10, 15, 20} * Tlfo for TX_EN_DRV_DELAY = {0, 1, 2, 3}*/
#define PCRM_ULPCD_CTRL1_TX_EN_DELAY_POS                                                                 (22UL)
#define PCRM_ULPCD_CTRL1_TX_EN_DELAY_MASK                                                                (0x00C00000UL)  /**< 22-TX enable delay:  Ttx_enable_delay = {10, 16, 23, 30} * Tlfo for TX_EN_DELAY = {0, 1, 2, 3} */
#define PCRM_ULPCD_CTRL1_RESERVED_POS                                                                  (21UL)
#define PCRM_ULPCD_CTRL1_RESERVED_MASK                                                                 (0x00200000UL)  /**< 21-reserved*/
#define PCRM_ULPCD_CTRL1_TX_SET_GS_PN_TX12_POS                                                           (16UL)
#define PCRM_ULPCD_CTRL1_TX_SET_GS_PN_TX12_MASK                                                          (0x001F0000UL)  /**< 16-TX Set*/
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_CURRENT_SENSE_EN_POS                                                  (15UL)
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_CURRENT_SENSE_EN_MASK                                                 (0x00008000UL)  /**< 15-LDO VDDPA Current sense enable*/
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_VOUT_SEL_POS                                                          (9UL)
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_VOUT_SEL_MASK                                                         (0x00007E00UL)  /**< 9-LDO VDDPA VOUT select*/
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_LIMITER_EN_POS                                                        (8UL)
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_LIMITER_EN_MASK                                                       (0x00000100UL)  /**< 8-LDO VDDPA limiter enable*/
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_OVERCURRENT_EN_POS                                                    (7UL)
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_OVERCURRENT_EN_MASK                                                   (0x00000080UL)  /**< 7-LDO VDDPA overcurrent enable*/
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_CURMIN_EN_POS                                                         (6UL)
#define PCRM_ULPCD_CTRL1_LDO_VDDPA_CURMIN_EN_MASK                                                        (0x00000040UL)  /**< 6-LDO VDDPA CURMIN enable*/
#define PCRM_ULPCD_CTRL1_RX_AGC_HFATT_CTRL_POS                                                           (0UL)
#define PCRM_ULPCD_CTRL1_RX_AGC_HFATT_CTRL_MASK                                                          (0x0000003FUL)  /**< 0-RX  AGC HF Attenuator control*/
#define PCRM_ULPCD_CTRL1__RESET_VALUE                                                               (0x007F0000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_ctrl0
* <b>Reset value:</b> 0x14590000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ULPCD_CTRL0                                                                                  0xE8
#define PCRM_ULPCD_CTRL0_R                                                                                  0xE8
#define PCRM_ULPCD_CTRL0_W                                                                                  0xE8
#define PCRM_ULPCD_CTRL0_RESERVED_POS                                                                    (29UL)
#define PCRM_ULPCD_CTRL0_RESERVED_MASK                                                                   (0xE0000000UL)  /**< 29-reserved*/
#define PCRM_ULPCD_CTRL0_XTAL_OVER_BOOST_DELAY_POS                                                       (27UL)
#define PCRM_ULPCD_CTRL0_XTAL_OVER_BOOST_DELAY_MASK                                                      (0x18000000UL)  /**< 27-XTAL over boost delay: Txtal_over_boost_delay = {10, 16, 23, 30} * Tlfo for XTAL_OVER_BOOST_DELAY = {0, 1, 2, 3} */
#define PCRM_ULPCD_CTRL0_XTAL_SLICER_DELAY_POS                                                           (23UL)
#define PCRM_ULPCD_CTRL0_XTAL_SLICER_DELAY_MASK                                                          (0x07800000UL)  /**< 23-XTAL Slicer delay:  Txtal_slicer_delay = 66 + (XTAL_SLICER_DELAY * 4) * Tlfo*/
#define PCRM_ULPCD_CTRL0_XTAL_OVER_BOOST_EN_POS                                                          (22UL)
#define PCRM_ULPCD_CTRL0_XTAL_OVER_BOOST_EN_MASK                                                         (0x00400000UL)  /**< 22-XTAL over boost delay enable*/
#define PCRM_ULPCD_CTRL0_XTAL_AMP_CTRL_POS                                                               (16UL)
#define PCRM_ULPCD_CTRL0_XTAL_AMP_CTRL_MASK                                                              (0x003F0000UL)  /**< 16-XTAL control*/
#define PCRM_ULPCD_CTRL0_RESERVED1_POS                                                                    (12UL)
#define PCRM_ULPCD_CTRL0_RESERVED1_MASK                                                                   (0x0000F000UL)  /**< 12-reserved*/
#define PCRM_ULPCD_CTRL0_ULPCD_WKUP_TIME_POS                                                             (0UL)
#define PCRM_ULPCD_CTRL0_ULPCD_WKUP_TIME_MASK                                                            (0x00000FFFUL)  /**< 0-Wakeup Timer Reload Value: Tulpcd_wkup_time = ULPCD_WKUP_TIME * Tulfo*/
#define PCRM_ULPCD_CTRL0__RESET_VALUE                                                                 (0x14590000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_hp_ulpcd_sts
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_HP_ULPCD_STS                                                                                 0xE9
#define PCRM_HP_ULPCD_STS_R                                                                                 0xE9
#define PCRM_HP_ULPCD_STS_RESERVED_POS                                                                   (1UL)
#define PCRM_HP_ULPCD_STS_RESERVED_MASK                                                                  (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_HP_ULPCD_STS_BUSY_POS                                                                       (0UL)
#define PCRM_HP_ULPCD_STS_BUSY_MASK                                                                      (0x00000001UL)  /**< 0-ULPCD register file data transfer in progress*/
#define PCRM_HP_ULPCD_STS__RESET_VALUE                                                                           (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_smps_ctrl
* <b>Reset value:</b> 0x00100000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_SMPS_CTRL                                                                            0xEA
#define PCRM_PMU_ANA_SMPS_CTRL_R                                                                            0xEA
#define PCRM_PMU_ANA_SMPS_CTRL_W                                                                            0xEA
#define PCRM_PMU_ANA_SMPS_CTRL_RESERVED_POS                                                              (30UL)
#define PCRM_PMU_ANA_SMPS_CTRL_RESERVED_MASK                                                             (0xC0000000UL)  /**< 30-reserved*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_MAXDT_SEL_POS                                                        (27UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_MAXDT_SEL_MASK                                                       (0x38000000UL)  /**< 27-SMPS max duty cycle value, valid when SMPS_MAX_DTC_BYPASS is set*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_MAXDT_SEL_BYPASS_POS                                                 (26UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_MAXDT_SEL_BYPASS_MASK                                                (0x04000000UL)  /**< 26-SMPS max duty cycle lookup table bypass */
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_GM_POS                                                               (24UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_GM_MASK                                                              (0x03000000UL)  /**< 24-SMPS Gm set up*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_RSENSE_POS                                                           (22UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_RSENSE_MASK                                                          (0x00C00000UL)  /**< 22-SMPS Rsense set up*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_SOFT_START_POS                                                       (20UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_SOFT_START_MASK                                                      (0x00300000UL)  /**< 20-SMPS Soft Start set up*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_SAWTOOTHGEN_POS                                                      (17UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_SAWTOOTHGEN_MASK                                                     (0x000E0000UL)  /**< 17-SMPS Sawtooth generator set up*/
#define PCRM_PMU_ANA_SMPS_CTRL_RESERVED1_POS                                                              (14UL)
#define PCRM_PMU_ANA_SMPS_CTRL_RESERVED1_MASK                                                             (0x0001C000UL)  /**< 14-reserved*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_PROT_UNDERSHOOT_VTH_POS                                              (12UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_PROT_UNDERSHOOT_VTH_MASK                                             (0x00003000UL)  /**< 12-SMPS */
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_REG_SPARE_0_POS                                                      (10UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_REG_SPARE_0_MASK                                                     (0x00000C00UL)  /**< 10-SMPS */
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_PID_POS                                                              (7UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_PID_MASK                                                             (0x00000380UL)  /**< 7-SMPS PID filter set up*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_VDDBOOST_VOUT_SEL_POS                                                (1UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_VDDBOOST_VOUT_SEL_MASK                                               (0x0000007EUL)  /**< 1-SMPS Ouput voltage selection*/
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_EN_POS                                                               (0UL)
#define PCRM_PMU_ANA_SMPS_CTRL_SMPS_EN_MASK                                                              (0x00000001UL)  /**< 0-SMPS enable*/
#define PCRM_PMU_ANA_SMPS_CTRL__RESET_VALUE                                                                   (0x00100000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_ctrl4
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ULPCD_CTRL4                                                                                  0xEB
#define PCRM_ULPCD_CTRL4_R                                                                                  0xEB
#define PCRM_ULPCD_CTRL4_W                                                                                  0xEB
#define PCRM_ULPCD_CTRL4_ULPCD_LP_SPARE_POS                                                              (28UL)
#define PCRM_ULPCD_CTRL4_ULPCD_LP_SPARE_MASK                                                             (0xF0000000UL)  /**< 28-Spare register control/status between PCRM_AON and PCRM_LP*/
#define PCRM_ULPCD_CTRL4_RESERVED_POS                                                                    (20UL)
#define PCRM_ULPCD_CTRL4_RESERVED_MASK                                                                   (0x0FF00000UL)  /**< 20-reserved*/
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_START_HIGH_TIME_POS                                                 (18UL)
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_START_HIGH_TIME_MASK                                                (0x000C0000UL)  /**< 18-Width of START. 0: 2CLK, 1: 3CLK, 2: 5CLK, 3: 9CLK*/
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_RST_DIS_TO_START_TIME_POS                                           (16UL)
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_RST_DIS_TO_START_TIME_MASK                                          (0x00030000UL)  /**< 16-GPADC RST de-assertion to GPADC START assertion delay. 0: 3CLK, 1: 4CLK, 2: 6CLK, 3: 10CLK*/
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_EN_TO_RST_DIS_TIME_POS                                              (14UL)
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_EN_TO_RST_DIS_TIME_MASK                                             (0x0000C000UL)  /**< 14-GPADC EN to GPADC RST de-assertion delay. 0: 1CLK, 1: 2 CLK,  2: 4CLK, 3: 8CLK */
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_RST_SET_TO_EN_TIME_POS                                              (12UL)
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_RST_SET_TO_EN_TIME_MASK                                             (0x00003000UL)  /**< 12-GPADC RST assertion to GPADC EN time. 0: 1CLK, 1: 2 CLK,  2: 3CLK, 3: 4CLK*/
#define PCRM_ULPCD_CTRL4_ULPCD_CLKDET_CHK_DELAY_WAIT_MULT_POS                                            (10UL)
#define PCRM_ULPCD_CTRL4_ULPCD_CLKDET_CHK_DELAY_WAIT_MULT_MASK                                           (0x00000C00UL)  /**< 10-CLKDET check delay wait multiplier. 0: 12'd1140 1: 12'd3188*/
#define PCRM_ULPCD_CTRL4_ULPCD_TESTBUS_MUX_SEL_POS                                                       (6UL)
#define PCRM_ULPCD_CTRL4_ULPCD_TESTBUS_MUX_SEL_MASK                                                      (0x000003C0UL)  /**< 6-Testbus MUX select*/
#define PCRM_ULPCD_CTRL4_ULPCD_TESTBUS_EN_POS                                                            (5UL)
#define PCRM_ULPCD_CTRL4_ULPCD_TESTBUS_EN_MASK                                                           (0x00000020UL)  /**< 5-Enable ULPCD testbus*/
#define PCRM_ULPCD_CTRL4_ULPCD_FUNC_DEBUG_MODE_POS                                                       (4UL)
#define PCRM_ULPCD_CTRL4_ULPCD_FUNC_DEBUG_MODE_MASK                                                      (0x00000010UL)  /**< 4-ULPCD Functional Debug mode enable*/
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_SHIFT_POS                                                           (3UL)
#define PCRM_ULPCD_CTRL4_ULPCD_GPADC_SHIFT_MASK                                                          (0x00000008UL)  /**< 3-ULPCD GPADC shift*/
#define PCRM_ULPCD_CTRL4_ULPCD_XTAL_SLICER_PSM_POS                                                       (1UL)
#define PCRM_ULPCD_CTRL4_ULPCD_XTAL_SLICER_PSM_MASK                                                      (0x00000006UL)  /**< 1-Set XTAL slicer driving strength*/
#define PCRM_ULPCD_CTRL4_ULPCD_XTAL_BYPASS_EN_POS                                                        (0UL)
#define PCRM_ULPCD_CTRL4_ULPCD_XTAL_BYPASS_EN_MASK                                                       (0x00000001UL)  /**< 0-XTAL bypass enable*/
#define PCRM_ULPCD_CTRL4__RESET_VALUE                                                            (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ana_usbpll_sts
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_ANA_USBPLL_STS                                                                               0xEC
#define PCRM_ANA_USBPLL_STS_R                                                                               0xEC
#define PCRM_ANA_USBPLL_STS_RESERVED_POS                                                                 (5UL)
#define PCRM_ANA_USBPLL_STS_RESERVED_MASK                                                                (0xFFFFFFE0UL)  /**< 5-reserved*/
#define PCRM_ANA_USBPLL_STS_USBPLL_FR_POS                                                                (4UL)
#define PCRM_ANA_USBPLL_STS_USBPLL_FR_MASK                                                               (0x00000010UL)  /**< 4-Free running detector output (active high)*/
#define PCRM_ANA_USBPLL_STS_USBPLL_PACK_POS                                                              (3UL)
#define PCRM_ANA_USBPLL_STS_USBPLL_PACK_MASK                                                             (0x00000008UL)  /**< 3-USB_PLL Post-Divider Ratio Change Acknowledge*/
#define PCRM_ANA_USBPLL_STS_USBPLL_NACK_POS                                                              (2UL)
#define PCRM_ANA_USBPLL_STS_USBPLL_NACK_MASK                                                             (0x00000004UL)  /**< 2-Pre-divider ratio change acknowledge output*/
#define PCRM_ANA_USBPLL_STS_USBPLL_MACK_POS                                                              (1UL)
#define PCRM_ANA_USBPLL_STS_USBPLL_MACK_MASK                                                             (0x00000002UL)  /**< 1-Feedback divider ratio change acknowledge output*/
#define PCRM_ANA_USBPLL_STS_USBPLL_LOCK_POS                                                              (0UL)
#define PCRM_ANA_USBPLL_STS_USBPLL_LOCK_MASK                                                             (0x00000001UL)  /**< 0-Lock detector output (active high)*/
#define PCRM_ANA_USBPLL_STS__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ana_usbpll_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_ANA_USBPLL_CTRL                                                                              0xED
#define PCRM_ANA_USBPLL_CTRL_R                                                                              0xED
#define PCRM_ANA_USBPLL_CTRL_W                                                                              0xED
#define PCRM_ANA_USBPLL_CTRL_RESERVED_POS                                                                (7UL)
#define PCRM_ANA_USBPLL_CTRL_RESERVED_MASK                                                               (0xFFFFFF80UL)  /**< 7-reserved*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_LIMUP_OFF_POS                                                        (6UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_LIMUP_OFF_MASK                                                       (0x00000040UL)  /**< 6-Up limiter control pin*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_FRM_CLOCKSTABLE_POS                                                  (5UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_FRM_CLOCKSTABLE_MASK                                                 (0x00000020UL)  /**< 5-Free running mode clock stable control input*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_PREQ_POS                                                             (4UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_PREQ_MASK                                                            (0x00000010UL)  /**< 4-USB_PLL Post-Divider Ratio Change Request*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_NREQ_POS                                                             (3UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_NREQ_MASK                                                            (0x00000008UL)  /**< 3-USB_PLL Pre-Divider Ratio Change Request*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_MREQ_POS                                                             (2UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_MREQ_MASK                                                            (0x00000004UL)  /**< 2-USB_PLL Feedback Divider Ratio Change Request*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_FRM_POS                                                              (1UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_FRM_MASK                                                             (0x00000002UL)  /**< 1-Free running mode control input*/
#define PCRM_ANA_USBPLL_CTRL_USBPLL_SKEW_EN_POS                                                          (0UL)
#define PCRM_ANA_USBPLL_CTRL_USBPLL_SKEW_EN_MASK                                                         (0x00000001UL)  /**< 0-USB_PLL Skew Mode*/
#define PCRM_ANA_USBPLL_CTRL__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ana_usbpll_bw
* <b>Reset value:</b> 0x00005BF0
* <b>Access:</b> rw
* @{
*/
#define PCRM_ANA_USBPLL_BW                                                                                0xEE
#define PCRM_ANA_USBPLL_BW_R                                                                                0xEE
#define PCRM_ANA_USBPLL_BW_W                                                                                0xEE
#define PCRM_ANA_USBPLL_BW_USBPLL_BAND_DIRECT_POS                                                        (31UL)
#define PCRM_ANA_USBPLL_BW_USBPLL_BAND_DIRECT_MASK                                                       (0x80000000UL)  /**< 31-Bandwidth adjustment pin to modify the bandwidth of the PLL directly*/
#define PCRM_ANA_USBPLL_BW_RESERVED_POS                                                                  (15UL)
#define PCRM_ANA_USBPLL_BW_RESERVED_MASK                                                                 (0x7FFF8000UL)  /**< 15-reserved*/
#define PCRM_ANA_USBPLL_BW_USBPLL_SELI_POS                                                               (9UL)
#define PCRM_ANA_USBPLL_BW_USBPLL_SELI_MASK                                                              (0x00007E00UL)  /**< 9-Bus to select the bandwidth*/
#define PCRM_ANA_USBPLL_BW_USBPLL_SELP_POS                                                               (4UL)
#define PCRM_ANA_USBPLL_BW_USBPLL_SELP_MASK                                                              (0x000001F0UL)  /**< 4-Bus to select the bandwidth*/
#define PCRM_ANA_USBPLL_BW_USBPLL_SELR_POS                                                               (0UL)
#define PCRM_ANA_USBPLL_BW_USBPLL_SELR_MASK                                                              (0x0000000FUL)  /**< 0-Bus to select the bandwidth*/
#define PCRM_ANA_USBPLL_BW__RESET_VALUE                                                                   (0x00005BF0UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_clif_dac
* <b>Reset value:</b> 0x06000600
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_DAC                                                                                     0xEF
#define PCRM_CLIF_DAC_R                                                                                     0xEF
#define PCRM_CLIF_DAC_W                                                                                     0xEF
#define PCRM_CLIF_DAC_RESERVED_POS                                                                       (28UL)
#define PCRM_CLIF_DAC_RESERVED_MASK                                                                      (0xF0000000UL)  /**< 28-reserved*/
#define PCRM_CLIF_DAC_TUNING_DAC_2_OFFSET_CTRL_POS                                                       (24UL)
#define PCRM_CLIF_DAC_TUNING_DAC_2_OFFSET_CTRL_MASK                                                      (0x0F000000UL)  /**< 24-x111=2V, x110=3V,x100=3.45V,x000=3.8V*/
#define PCRM_CLIF_DAC_TUNING_DAC_2_CTRL_POS                                                              (17UL)
#define PCRM_CLIF_DAC_TUNING_DAC_2_CTRL_MASK                                                             (0x00FE0000UL)  /**< 17-Output voltage of DAC2 according to 1/128 *<TUNING_DAC_2_CTRL> *  <Range in V>*/
#define PCRM_CLIF_DAC_TUNING_DAC_2_PD_POS                                                                (16UL)
#define PCRM_CLIF_DAC_TUNING_DAC_2_PD_MASK                                                               (0x00010000UL)  /**< 16-0=DAC Turned off, 1=DAC enabled*/
#define PCRM_CLIF_DAC_RESERVED1_POS                                                                       (12UL)
#define PCRM_CLIF_DAC_RESERVED1_MASK                                                                      (0x0000F000UL)  /**< 12-reserved*/
#define PCRM_CLIF_DAC_TUNING_DAC_1_OFFSET_CTRL_POS                                                       (8UL)
#define PCRM_CLIF_DAC_TUNING_DAC_1_OFFSET_CTRL_MASK                                                      (0x00000F00UL)  /**< 8-x111=2V, x110=3V,x100=3.45V,x000=3.8V*/
#define PCRM_CLIF_DAC_TUNING_DAC_1_CTRL_POS                                                              (1UL)
#define PCRM_CLIF_DAC_TUNING_DAC_1_CTRL_MASK                                                             (0x000000FEUL)  /**< 1-Output voltage of DAC1 according to 1/128 *<TUNING_DAC_1_CTRL> *  <Range in V>*/
#define PCRM_CLIF_DAC_TUNING_DAC_1_PD_POS                                                                (0UL)
#define PCRM_CLIF_DAC_TUNING_DAC_1_PD_MASK                                                               (0x00000001UL)  /**< 0-0=DAC Turned off, 1=DAC enabled*/
#define PCRM_CLIF_DAC__RESET_VALUE                                                                    (0x06000600UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_hp_sys_clk_en
* <b>Reset value:</b> 0x08000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_HP_SYS_CLK_EN                                                                                0xF0
#define PCRM_HP_SYS_CLK_EN_R                                                                                0xF0
#define PCRM_HP_SYS_CLK_EN_W                                                                                0xF0
#define PCRM_HP_SYS_CLK_EN_RESERVED_POS                                                                  (25UL)
#define PCRM_HP_SYS_CLK_EN_RESERVED_MASK                                                                 (0xFE000000UL)  /**< 25-reserved*/
#define PCRM_HP_SYS_CLK_EN_CT_AUX_IF_APB_CLK_ENABLE_POS                                                  (24UL)
#define PCRM_HP_SYS_CLK_EN_CT_AUX_IF_APB_CLK_ENABLE_MASK                                                 (0x01000000UL)  /**< 24-Enables clock source for CT_AUX_IF_APB*/
#define PCRM_HP_SYS_CLK_EN_CT_AUX_IF_CLK_ENABLE_POS                                                      (23UL)
#define PCRM_HP_SYS_CLK_EN_CT_AUX_IF_CLK_ENABLE_MASK                                                     (0x00800000UL)  /**< 23-Enables clock source for CT_AUX_IF*/
#define PCRM_HP_SYS_CLK_EN_LP_UART_CLK_ENABLE_POS                                                        (22UL)
#define PCRM_HP_SYS_CLK_EN_LP_UART_CLK_ENABLE_MASK                                                       (0x00400000UL)  /**< 22-Enables clock source for LP UART*/
#define PCRM_HP_SYS_CLK_EN_HS_UART_CLK_ENABLE_POS                                                        (21UL)
#define PCRM_HP_SYS_CLK_EN_HS_UART_CLK_ENABLE_MASK                                                       (0x00200000UL)  /**< 21-Enables clock source for LP UART*/
#define PCRM_HP_SYS_CLK_EN_PWM_CLK_ENABLE_POS                                                            (20UL)
#define PCRM_HP_SYS_CLK_EN_PWM_CLK_ENABLE_MASK                                                           (0x00100000UL)  /**< 20-Enables clock source for PWM unit*/
#define PCRM_HP_SYS_CLK_EN_PWM_45M_CLK_ENABLE_POS                                                        (19UL)
#define PCRM_HP_SYS_CLK_EN_PWM_45M_CLK_ENABLE_MASK                                                       (0x00080000UL)  /**< 19-Enables clock source for PWM unit*/
#define PCRM_HP_SYS_CLK_EN_RESERVED1_POS                                                                  (14UL)
#define PCRM_HP_SYS_CLK_EN_RESERVED1_MASK                                                                 (0x0007C000UL)  /**< 14-reserved*/
#define PCRM_HP_SYS_CLK_EN_USB_APB_CLK_ENABLE_POS                                                        (13UL)
#define PCRM_HP_SYS_CLK_EN_USB_APB_CLK_ENABLE_MASK                                                       (0x00002000UL)  /**< 13-Enables clock source for USB APB*/
#define PCRM_HP_SYS_CLK_EN_USB_CLK_ENABLE_POS                                                            (12UL)
#define PCRM_HP_SYS_CLK_EN_USB_CLK_ENABLE_MASK                                                           (0x00001000UL)  /**< 12-Enables clock source for USB*/
#define PCRM_HP_SYS_CLK_EN_SPIM_F_CLK_ENABLE_POS                                                         (11UL)
#define PCRM_HP_SYS_CLK_EN_SPIM_F_CLK_ENABLE_MASK                                                        (0x00000800UL)  /**< 11-Enables clock source for SPIM-H CLOCK*/
#define PCRM_HP_SYS_CLK_EN_SPIM_H_CLK_ENABLE_POS                                                         (10UL)
#define PCRM_HP_SYS_CLK_EN_SPIM_H_CLK_ENABLE_MASK                                                        (0x00000400UL)  /**< 10-Enables clock source for SPIM-F CLOCK*/
#define PCRM_HP_SYS_CLK_EN_I2CM_APB_CLK_ENABLE_POS                                                       (9UL)
#define PCRM_HP_SYS_CLK_EN_I2CM_APB_CLK_ENABLE_MASK                                                      (0x00000200UL)  /**< 9-Enables clock source for I2CM APB*/
#define PCRM_HP_SYS_CLK_EN_I2CM_CLK_ENABLE_POS                                                           (8UL)
#define PCRM_HP_SYS_CLK_EN_I2CM_CLK_ENABLE_MASK                                                          (0x00000100UL)  /**< 8-Enables clock source for I2CM*/
#define PCRM_HP_SYS_CLK_EN_CRC_CLK_ENABLE_POS                                                            (7UL)
#define PCRM_HP_SYS_CLK_EN_CRC_CLK_ENABLE_MASK                                                           (0x00000080UL)  /**< 7-Enables clock source for CRC*/
#define PCRM_HP_SYS_CLK_EN_HOSTIF_APB_CLK_ENABLE_POS                                                     (6UL)
#define PCRM_HP_SYS_CLK_EN_HOSTIF_APB_CLK_ENABLE_MASK                                                    (0x00000040UL)  /**< 6-Enables clock source for HostIF_APB*/
#define PCRM_HP_SYS_CLK_EN_HOSTIF_CLK_ENABLE_POS                                                         (5UL)
#define PCRM_HP_SYS_CLK_EN_HOSTIF_CLK_ENABLE_MASK                                                        (0x00000020UL)  /**< 5-Enables clock source for HOSTIF*/
#define PCRM_HP_SYS_CLK_EN_TIMERS_CLK_ENABLE_POS                                                         (4UL)
#define PCRM_HP_SYS_CLK_EN_TIMERS_CLK_ENABLE_MASK                                                        (0x00000010UL)  /**< 4-Enables clock source for TIMERS*/
#define PCRM_HP_SYS_CLK_EN_RESERVED2_POS                                                                  (0UL)
#define PCRM_HP_SYS_CLK_EN_RESERVED2_MASK                                                                 (0x0000000FUL)  /**< 0-reserved*/
#define PCRM_HP_SYS_CLK_EN__RESET_VALUE                                                                      (0x08000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_clk_mux_sel
* <b>Reset value:</b> 0x0000000E
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_CLK_MUX_SEL                                                                              0xF1
#define PCRM_SYS_CLK_MUX_SEL_R                                                                              0xF1
#define PCRM_SYS_CLK_MUX_SEL_W                                                                              0xF1
#define PCRM_SYS_CLK_MUX_SEL_RESERVED_POS                                                                (13UL)
#define PCRM_SYS_CLK_MUX_SEL_RESERVED_MASK                                                               (0xFFFFE000UL)  /**< 13-reserved*/
#define PCRM_SYS_CLK_MUX_SEL_CLIF_CLK_SRC_SEL_A0_POS                                                     (12UL)
#define PCRM_SYS_CLK_MUX_SEL_CLIF_CLK_SRC_SEL_A0_MASK                                                    (0x00001000UL)  /**< 12-ceres option to select ceres A0 or B0 cclif clock*/
#define PCRM_SYS_CLK_MUX_SEL_RESERVED1_POS                                                                (7UL)
#define PCRM_SYS_CLK_MUX_SEL_RESERVED1_MASK                                                               (0x00000F80UL)  /**< 7-reserved*/
#define PCRM_SYS_CLK_MUX_SEL_CTIF_CLK_SRC_SEL_POS                                                        (6UL)
#define PCRM_SYS_CLK_MUX_SEL_CTIF_CLK_SRC_SEL_MASK                                                       (0x00000040UL)  /**< 6-contact interface clock selection (0;27.12 Mhz  1: USBPLL div/2 )*/
#define PCRM_SYS_CLK_MUX_SEL_RESERVED2_POS                                                                (0UL)
#define PCRM_SYS_CLK_MUX_SEL_RESERVED2_MASK                                                               (0x0000003FUL)  /**< 0-Selects the source clock for the GPADC (0:HFO/4, 1: clk_27p12m clock source from CLIF ANA).*/
#define PCRM_SYS_CLK_MUX_SEL__RESET_VALUE                                                                    (0x0000000EUL)  /**< value after reset*/
/**
* @}
*/

/** @} */

#endif /* _PCRM_HP_REG_H_ */