/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023 NXP                                             */
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

#ifndef _PCRM_LP_REG_H_
#define _PCRM_LP_REG_H_

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "driver.hal_intfs"
#endif

/** @addtogroup PN76PCRMLpRegDefs
 *
 * @brief PCRM LP Software register and bit definitions
 * To access these register, use System Service Register Interface API's
 * @{
 *
 */

/**
* @name pcrm_pmu_ana_ctrl
* <b>Reset value:</b> 0x00000040
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_CTRL                                                                                 0xA0
#define PCRM_PMU_ANA_CTRL_R                                                                                 0xA0
#define PCRM_PMU_ANA_CTRL_W                                                                                 0xA0
#define PCRM_PMU_ANA_CTRL_RESERVED_POS                                                                   (18UL)
#define PCRM_PMU_ANA_CTRL_RESERVED_MASK                                                                  (0xFFFC0000UL)  /**< 18-reserved*/
#define PCRM_PMU_ANA_CTRL_AD1_MUX_SEL_POS                                                                (17UL)
#define PCRM_PMU_ANA_CTRL_AD1_MUX_SEL_MASK                                                               (0x00020000UL)  /**< 17-to Enable external input to GPADC*/
#define PCRM_PMU_ANA_CTRL_RESERVED1_POS                                                                  (16UL)
#define PCRM_PMU_ANA_CTRL_RESERVED1_MASK                                                                 (0x0001FFFF)  /**< 16-reserved*/
#define PCRM_PMU_ANA_CTRL__RESET_VALUE                                                                (0x00000040UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_set_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> -w
* @{
*/
#define PCRM_INT_SET_STATUS                                                                               0xA1
#define PCRM_INT_SET_STATUS_RESERVED_POS                                                                 (31UL)
#define PCRM_INT_SET_STATUS_RESERVED_MASK                                                                (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_SET_STATUS_SUSPEND_IRQ_SET_STATUS_POS                                                   (30UL)
#define PCRM_INT_SET_STATUS_SUSPEND_IRQ_SET_STATUS_MASK                                                  (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_SET_STATUS_SUSPEND_PREV_IRQ_SET_STATUS_POS                                              (29UL)
#define PCRM_INT_SET_STATUS_SUSPEND_PREV_IRQ_SET_STATUS_MASK                                             (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_SET_STATUS_PVDDLDO_OVERCURRENT_IRQ_SET_STATUS_POS                                       (28UL)
#define PCRM_INT_SET_STATUS_PVDDLDO_OVERCURRENT_IRQ_SET_STATUS_MASK                                      (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_SET_STATUS_RESERVED1_POS                                                                 (27UL)
#define PCRM_INT_SET_STATUS_RESERVED1_MASK                                                                (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_SET_STATUS_OVERCURRENT_IRQ_SET_STATUS_POS                                               (26UL)
#define PCRM_INT_SET_STATUS_OVERCURRENT_IRQ_SET_STATUS_MASK                                              (0x04000000UL)  /**< 26-Over Current  interrupt*/
#define PCRM_INT_SET_STATUS_VUP_OK_IRQ_SET_STATUS_POS                                                    (25UL)
#define PCRM_INT_SET_STATUS_VUP_OK_IRQ_SET_STATUS_MASK                                                   (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_SET_STATUS_RESERVED2_POS                                                                 (24UL)
#define PCRM_INT_SET_STATUS_RESERVED2_MASK                                                                (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_SET_STATUS_USB_VBUS_PRESENT_IRQ_SET_STATUS_POS                                          (23UL)
#define PCRM_INT_SET_STATUS_USB_VBUS_PRESENT_IRQ_SET_STATUS_MASK                                         (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_SET_STATUS_RESERVED3_POS                                                                 (22UL)
#define PCRM_INT_SET_STATUS_RESERVED3_MASK                                                                (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_SET_STATUS_LPDET_IRQ_SET_STATUS_POS                                                     (21UL)
#define PCRM_INT_SET_STATUS_LPDET_IRQ_SET_STATUS_MASK                                                    (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_SET_STATUS_STBY_PREV_IRQ_SET_STATUS_POS                                                 (20UL)
#define PCRM_INT_SET_STATUS_STBY_PREV_IRQ_SET_STATUS_MASK                                                (0x00100000UL)  /**< 20-standby Prevention interrupt */
#define PCRM_INT_SET_STATUS_VBAT_MON2_LOW_IRQ_SET_STATUS_POS                                             (19UL)
#define PCRM_INT_SET_STATUS_VBAT_MON2_LOW_IRQ_SET_STATUS_MASK                                            (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_SET_STATUS_OVER_TEMP_PMU_IRQ_SET_STATUS_POS                                             (18UL)
#define PCRM_INT_SET_STATUS_OVER_TEMP_PMU_IRQ_SET_STATUS_MASK                                            (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_SET_STATUS_OVER_TEMP_NFC_IRQ_ENABLE_POS                                                 (17UL)
#define PCRM_INT_SET_STATUS_OVER_TEMP_NFC_IRQ_ENABLE_MASK                                                (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_SET_STATUS_ADC_DATA_7_IRQ_SET_STATUS_POS                                                (16UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_7_IRQ_SET_STATUS_MASK                                               (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_6_IRQ_SET_STATUS_POS                                                (15UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_6_IRQ_SET_STATUS_MASK                                               (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_5_IRQ_SET_STATUS_POS                                                (14UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_5_IRQ_SET_STATUS_MASK                                               (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_4_IRQ_SET_STATUS_POS                                                (13UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_4_IRQ_SET_STATUS_MASK                                               (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_3_IRQ_SET_STATUS_POS                                                (12UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_3_IRQ_SET_STATUS_MASK                                               (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_2_IRQ_SET_STATUS_POS                                                (11UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_2_IRQ_SET_STATUS_MASK                                               (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_1_IRQ_SET_STATUS_POS                                                (10UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_1_IRQ_SET_STATUS_MASK                                               (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_SET_STATUS_ADC_DATA_0_IRQ_SET_STATUS_POS                                                (9UL)
#define PCRM_INT_SET_STATUS_ADC_DATA_0_IRQ_SET_STATUS_MASK                                               (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_SET_STATUS_GPIO_COMMON_IRQ_SET_STATUS_POS                                               (8UL)
#define PCRM_INT_SET_STATUS_GPIO_COMMON_IRQ_SET_STATUS_MASK                                              (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_SET_STATUS_RESERVED4_POS                                                                 (7UL)
#define PCRM_INT_SET_STATUS_RESERVED4_MASK                                                                (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_SET_STATUS_RESERVED5_POS                                                                 (5UL)
#define PCRM_INT_SET_STATUS_RESERVED5_MASK                                                                (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_SET_STATUS_VDDIO_OK_IRQ_SET_STATUS_POS                                                  (4UL)
#define PCRM_INT_SET_STATUS_VDDIO_OK_IRQ_SET_STATUS_MASK                                                 (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_SET_STATUS_GPIO3_ZIF_IRQ_SET_STATUS_POS                                                 (3UL)
#define PCRM_INT_SET_STATUS_GPIO3_ZIF_IRQ_SET_STATUS_MASK                                                (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_SET_STATUS_GPIO2_ZIF_IRQ_SET_STATUS_POS                                                 (2UL)
#define PCRM_INT_SET_STATUS_GPIO2_ZIF_IRQ_SET_STATUS_MASK                                                (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_SET_STATUS_GPIO1_ZIF_IRQ_SET_STATUS_POS                                                 (1UL)
#define PCRM_INT_SET_STATUS_GPIO1_ZIF_IRQ_SET_STATUS_MASK                                                (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_SET_STATUS_GPIO0_ZIF_IRQ_SET_STATUS_POS                                                 (0UL)
#define PCRM_INT_SET_STATUS_GPIO0_ZIF_IRQ_SET_STATUS_MASK                                                (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_SET_STATUS__RESET_VALUE                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_clr_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> -w
* @{
*/
#define PCRM_INT_CLR_STATUS                                                                               0xA2
#define PCRM_INT_CLR_STATUS_RESERVED_POS                                                                 (31UL)
#define PCRM_INT_CLR_STATUS_RESERVED_MASK                                                                (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_CLR_STATUS_SUSPEND_IRQ_CLEAR_STATUS_POS                                                 (30UL)
#define PCRM_INT_CLR_STATUS_SUSPEND_IRQ_CLEAR_STATUS_MASK                                                (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_CLR_STATUS_SUSPEND_PREV_IRQ_CLEAR_STATUS_POS                                            (29UL)
#define PCRM_INT_CLR_STATUS_SUSPEND_PREV_IRQ_CLEAR_STATUS_MASK                                           (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_CLR_STATUS_PVDDLDO_OVERCURRENT_IRQ_CLEAR_STATUS_POS                                     (28UL)
#define PCRM_INT_CLR_STATUS_PVDDLDO_OVERCURRENT_IRQ_CLEAR_STATUS_MASK                                    (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_CLR_STATUS_RESERVED1_POS                                                                 (27UL)
#define PCRM_INT_CLR_STATUS_RESERVED1_MASK                                                                (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_CLR_STATUS_OVERCURRENT_IRQ_CLEAR_STATUS_POS                                             (26UL)
#define PCRM_INT_CLR_STATUS_OVERCURRENT_IRQ_CLEAR_STATUS_MASK                                            (0x04000000UL)  /**< 26-OVERCURRENT interrupt*/
#define PCRM_INT_CLR_STATUS_VUP_OK_IRQ_CLEAR_STATUS_POS                                                  (25UL)
#define PCRM_INT_CLR_STATUS_VUP_OK_IRQ_CLEAR_STATUS_MASK                                                 (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_CLR_STATUS_RESERVED2_POS                                                                 (24UL)
#define PCRM_INT_CLR_STATUS_RESERVED2_MASK                                                                (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_CLR_STATUS_USB_VBUS_PRESENT_IRQ_CLEAR_STATUS_POS                                        (23UL)
#define PCRM_INT_CLR_STATUS_USB_VBUS_PRESENT_IRQ_CLEAR_STATUS_MASK                                       (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_CLR_STATUS_RESERVED3_POS                                                                 (22UL)
#define PCRM_INT_CLR_STATUS_RESERVED3_MASK                                                                (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_CLR_STATUS_LPDET_IRQ_CLEAR_STATUS_POS                                                   (21UL)
#define PCRM_INT_CLR_STATUS_LPDET_IRQ_CLEAR_STATUS_MASK                                                  (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_CLR_STATUS_STBY_PREV_IRQ_CLEAR_STATUS_POS                                               (20UL)
#define PCRM_INT_CLR_STATUS_STBY_PREV_IRQ_CLEAR_STATUS_MASK                                              (0x00100000UL)  /**< 20-stby prevention  interrupt */
#define PCRM_INT_CLR_STATUS_VBAT_MON2_LOW_IRQ_CLEAR_STATUS_POS                                           (19UL)
#define PCRM_INT_CLR_STATUS_VBAT_MON2_LOW_IRQ_CLEAR_STATUS_MASK                                          (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_CLR_STATUS_OVER_TEMP_PMU_IRQ_CLEAR_STATUS_POS                                           (18UL)
#define PCRM_INT_CLR_STATUS_OVER_TEMP_PMU_IRQ_CLEAR_STATUS_MASK                                          (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_CLR_STATUS_OVER_TEMP_NFC_IRQ_ENABLE_POS                                                 (17UL)
#define PCRM_INT_CLR_STATUS_OVER_TEMP_NFC_IRQ_ENABLE_MASK                                                (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_CLR_STATUS_ADC_DATA_7_IRQ_CLEAR_STATUS_POS                                              (16UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_7_IRQ_CLEAR_STATUS_MASK                                             (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_6_IRQ_CLEAR_STATUS_POS                                              (15UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_6_IRQ_CLEAR_STATUS_MASK                                             (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_5_IRQ_CLEAR_STATUS_POS                                              (14UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_5_IRQ_CLEAR_STATUS_MASK                                             (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_4_IRQ_CLEAR_STATUS_POS                                              (13UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_4_IRQ_CLEAR_STATUS_MASK                                             (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_3_IRQ_CLEAR_STATUS_POS                                              (12UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_3_IRQ_CLEAR_STATUS_MASK                                             (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_2_IRQ_CLEAR_STATUS_POS                                              (11UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_2_IRQ_CLEAR_STATUS_MASK                                             (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_1_IRQ_CLEAR_STATUS_POS                                              (10UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_1_IRQ_CLEAR_STATUS_MASK                                             (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_CLR_STATUS_ADC_DATA_0_IRQ_CLEAR_STATUS_POS                                              (9UL)
#define PCRM_INT_CLR_STATUS_ADC_DATA_0_IRQ_CLEAR_STATUS_MASK                                             (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_CLR_STATUS_GPIO_COMMON_IRQ_CLEAR_STATUS_POS                                             (8UL)
#define PCRM_INT_CLR_STATUS_GPIO_COMMON_IRQ_CLEAR_STATUS_MASK                                            (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_CLR_STATUS_RESERVED4_POS                                                                 (7UL)
#define PCRM_INT_CLR_STATUS_RESERVED4_MASK                                                                (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_CLR_STATUS_RESERVED5_POS                                                                 (5UL)
#define PCRM_INT_CLR_STATUS_RESERVED5_MASK                                                                (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_CLR_STATUS_VDDIO_OK_IRQ_CLEAR_STATUS_POS                                                (4UL)
#define PCRM_INT_CLR_STATUS_VDDIO_OK_IRQ_CLEAR_STATUS_MASK                                               (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_CLR_STATUS_GPIO3_ZIF_IRQ_CLEAR_STATUS_POS                                               (3UL)
#define PCRM_INT_CLR_STATUS_GPIO3_ZIF_IRQ_CLEAR_STATUS_MASK                                              (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_CLR_STATUS_GPIO2_ZIF_IRQ_CLEAR_STATUS_POS                                               (2UL)
#define PCRM_INT_CLR_STATUS_GPIO2_ZIF_IRQ_CLEAR_STATUS_MASK                                              (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_CLR_STATUS_GPIO1_ZIF_IRQ_CLEAR_STATUS_POS                                               (1UL)
#define PCRM_INT_CLR_STATUS_GPIO1_ZIF_IRQ_CLEAR_STATUS_MASK                                              (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_CLR_STATUS_GPIO0_ZIF_IRQ_CLEAR_STATUS_POS                                               (0UL)
#define PCRM_INT_CLR_STATUS_GPIO0_ZIF_IRQ_CLEAR_STATUS_MASK                                              (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_CLR_STATUS__RESET_VALUE                                                   (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_INT_ENABLE                                                                                   0xA3
#define PCRM_INT_ENABLE_RESERVED_POS                                                                     (31UL)
#define PCRM_INT_ENABLE_RESERVED_MASK                                                                    (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_ENABLE_SUSPEND_IRQ_ENABLE_POS                                                           (30UL)
#define PCRM_INT_ENABLE_SUSPEND_IRQ_ENABLE_MASK                                                          (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_ENABLE_SUSPEND_PREV_IRQ_ENABLE_POS                                                      (29UL)
#define PCRM_INT_ENABLE_SUSPEND_PREV_IRQ_ENABLE_MASK                                                     (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_ENABLE_PVDDLDO_OVERCURRENT_IRQ_ENABLE_POS                                               (28UL)
#define PCRM_INT_ENABLE_PVDDLDO_OVERCURRENT_IRQ_ENABLE_MASK                                              (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_ENABLE_RESERVED1_POS                                                                     (27UL)
#define PCRM_INT_ENABLE_RESERVED1_MASK                                                                    (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_ENABLE_OVERCURRENT_IRQ_ENABLE_POS                                                       (26UL)
#define PCRM_INT_ENABLE_OVERCURRENT_IRQ_ENABLE_MASK                                                      (0x04000000UL)  /**< 26-OVERCURRENT interrupt*/
#define PCRM_INT_ENABLE_VUP_OK_IRQ_ENABLE_POS                                                            (25UL)
#define PCRM_INT_ENABLE_VUP_OK_IRQ_ENABLE_MASK                                                           (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_ENABLE_RESERVED2_POS                                                                     (24UL)
#define PCRM_INT_ENABLE_RESERVED2_MASK                                                                    (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_ENABLE_USB_VBUS_PRESENT_IRQ_IRQ_ENABLE_POS                                              (23UL)
#define PCRM_INT_ENABLE_USB_VBUS_PRESENT_IRQ_IRQ_ENABLE_MASK                                             (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_ENABLE_RESERVED3_POS                                                                     (22UL)
#define PCRM_INT_ENABLE_RESERVED3_MASK                                                                    (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_ENABLE_LPDET_IRQ_ENABLE_POS                                                             (21UL)
#define PCRM_INT_ENABLE_LPDET_IRQ_ENABLE_MASK                                                            (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_ENABLE_STBY_PREV_IRQ_ENABLE_POS                                                         (20UL)
#define PCRM_INT_ENABLE_STBY_PREV_IRQ_ENABLE_MASK                                                        (0x00100000UL)  /**< 20-USB suspend Prev interrupt */
#define PCRM_INT_ENABLE_VBAT_MON2_LOW_IRQ_ENABLE_POS                                                     (19UL)
#define PCRM_INT_ENABLE_VBAT_MON2_LOW_IRQ_ENABLE_MASK                                                    (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_ENABLE_OVER_TEMP_PMU_IRQ_ENABLE_POS                                                     (18UL)
#define PCRM_INT_ENABLE_OVER_TEMP_PMU_IRQ_ENABLE_MASK                                                    (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_ENABLE_OVER_TEMP_NFC_IRQ_ENABLE_POS                                                     (17UL)
#define PCRM_INT_ENABLE_OVER_TEMP_NFC_IRQ_ENABLE_MASK                                                    (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_ENABLE_ADC_DATA_7_IRQ_ENABLE_POS                                                        (16UL)
#define PCRM_INT_ENABLE_ADC_DATA_7_IRQ_ENABLE_MASK                                                       (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_6_IRQ_ENABLE_POS                                                        (15UL)
#define PCRM_INT_ENABLE_ADC_DATA_6_IRQ_ENABLE_MASK                                                       (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_5_IRQ_ENABLE_POS                                                        (14UL)
#define PCRM_INT_ENABLE_ADC_DATA_5_IRQ_ENABLE_MASK                                                       (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_4_IRQ_ENABLE_POS                                                        (13UL)
#define PCRM_INT_ENABLE_ADC_DATA_4_IRQ_ENABLE_MASK                                                       (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_3_IRQ_ENABLE_POS                                                        (12UL)
#define PCRM_INT_ENABLE_ADC_DATA_3_IRQ_ENABLE_MASK                                                       (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_2_IRQ_ENABLE_POS                                                        (11UL)
#define PCRM_INT_ENABLE_ADC_DATA_2_IRQ_ENABLE_MASK                                                       (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_1_IRQ_ENABLE_POS                                                        (10UL)
#define PCRM_INT_ENABLE_ADC_DATA_1_IRQ_ENABLE_MASK                                                       (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_ENABLE_ADC_DATA_0_IRQ_ENABLE_POS                                                        (9UL)
#define PCRM_INT_ENABLE_ADC_DATA_0_IRQ_ENABLE_MASK                                                       (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_ENABLE_GPIO_COMMON_IRQ_ENABLE_POS                                                       (8UL)
#define PCRM_INT_ENABLE_GPIO_COMMON_IRQ_ENABLE_MASK                                                      (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_ENABLE_RESERVED4_POS                                                                     (7UL)
#define PCRM_INT_ENABLE_RESERVED4_MASK                                                                    (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_ENABLE_RESERVED5_POS                                                                     (5UL)
#define PCRM_INT_ENABLE_RESERVED5_MASK                                                                    (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_ENABLE_VDDIO_OK_IRQ_ENABLE_POS                                                          (4UL)
#define PCRM_INT_ENABLE_VDDIO_OK_IRQ_ENABLE_MASK                                                         (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_ENABLE_GPIO3_ZIF_IRQ_ENABLE_POS                                                         (3UL)
#define PCRM_INT_ENABLE_GPIO3_ZIF_IRQ_ENABLE_MASK                                                        (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_ENABLE_GPIO2_ZIF_IRQ_ENABLE_POS                                                         (2UL)
#define PCRM_INT_ENABLE_GPIO2_ZIF_IRQ_ENABLE_MASK                                                        (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_ENABLE_GPIO1_ZIF_IRQ_ENABLE_POS                                                         (1UL)
#define PCRM_INT_ENABLE_GPIO1_ZIF_IRQ_ENABLE_MASK                                                        (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_ENABLE_GPIO0_ZIF_IRQ_ENABLE_POS                                                         (0UL)
#define PCRM_INT_ENABLE_GPIO0_ZIF_IRQ_ENABLE_MASK                                                        (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_ENABLE__RESET_VALUE                                                             (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_INT_STATUS                                                                                   0xA4
#define PCRM_INT_STATUS_RESERVED_POS                                                                     (31UL)
#define PCRM_INT_STATUS_RESERVED_MASK                                                                    (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_STATUS_SUSPEND_IRQ_STATUS_POS                                                           (30UL)
#define PCRM_INT_STATUS_SUSPEND_IRQ_STATUS_MASK                                                          (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_STATUS_SUSPEND_PREV_IRQ_STATUS_POS                                                      (29UL)
#define PCRM_INT_STATUS_SUSPEND_PREV_IRQ_STATUS_MASK                                                     (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_STATUS_PVDDLDO_OVERCURRENT_IRQ_STATUS_POS                                               (28UL)
#define PCRM_INT_STATUS_PVDDLDO_OVERCURRENT_IRQ_STATUS_MASK                                              (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_STATUS_RESERVED1_POS                                                                     (27UL)
#define PCRM_INT_STATUS_RESERVED1_MASK                                                                    (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_STATUS_OVERCURRENT_IRQ_STATUS_POS                                                       (26UL)
#define PCRM_INT_STATUS_OVERCURRENT_IRQ_STATUS_MASK                                                      (0x04000000UL)  /**< 26-OVERCURRENT interrupt*/
#define PCRM_INT_STATUS_VUP_OK_IRQ_STATUS_POS                                                            (25UL)
#define PCRM_INT_STATUS_VUP_OK_IRQ_STATUS_MASK                                                           (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_STATUS_RESERVED2_POS                                                                     (24UL)
#define PCRM_INT_STATUS_RESERVED2_MASK                                                                    (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_STATUS_USB_VBUS_PRESENT_IRQ_STATUS_POS                                                  (23UL)
#define PCRM_INT_STATUS_USB_VBUS_PRESENT_IRQ_STATUS_MASK                                                 (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_STATUS_RESERVED3_POS                                                                     (22UL)
#define PCRM_INT_STATUS_RESERVED3_MASK                                                                    (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_STATUS_LPDET_IRQ_STATUS_POS                                                             (21UL)
#define PCRM_INT_STATUS_LPDET_IRQ_STATUS_MASK                                                            (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_STATUS_STBY_PREV_IRQ_STATUS_POS                                                         (20UL)
#define PCRM_INT_STATUS_STBY_PREV_IRQ_STATUS_MASK                                                        (0x00100000UL)  /**< 20- Stby  prevention interrupt */
#define PCRM_INT_STATUS_VBAT_MON2_LOW_IRQ_STATUS_POS                                                     (19UL)
#define PCRM_INT_STATUS_VBAT_MON2_LOW_IRQ_STATUS_MASK                                                    (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_STATUS_OVER_TEMP_PMU_IRQ_STATUS_POS                                                     (18UL)
#define PCRM_INT_STATUS_OVER_TEMP_PMU_IRQ_STATUS_MASK                                                    (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_STATUS_OVER_TEMP_NFC_IRQ_STATUS_POS                                                     (17UL)
#define PCRM_INT_STATUS_OVER_TEMP_NFC_IRQ_STATUS_MASK                                                    (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_STATUS_ADC_DATA_7_IRQ_STATUS_POS                                                        (16UL)
#define PCRM_INT_STATUS_ADC_DATA_7_IRQ_STATUS_MASK                                                       (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_6_IRQ_STATUS_POS                                                        (15UL)
#define PCRM_INT_STATUS_ADC_DATA_6_IRQ_STATUS_MASK                                                       (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_5_IRQ_STATUS_POS                                                        (14UL)
#define PCRM_INT_STATUS_ADC_DATA_5_IRQ_STATUS_MASK                                                       (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_4_IRQ_STATUS_POS                                                        (13UL)
#define PCRM_INT_STATUS_ADC_DATA_4_IRQ_STATUS_MASK                                                       (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_3_IRQ_STATUS_POS                                                        (12UL)
#define PCRM_INT_STATUS_ADC_DATA_3_IRQ_STATUS_MASK                                                       (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_2_IRQ_STATUS_POS                                                        (11UL)
#define PCRM_INT_STATUS_ADC_DATA_2_IRQ_STATUS_MASK                                                       (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_1_IRQ_STATUS_POS                                                        (10UL)
#define PCRM_INT_STATUS_ADC_DATA_1_IRQ_STATUS_MASK                                                       (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_STATUS_ADC_DATA_0_IRQ_STATUS_POS                                                        (9UL)
#define PCRM_INT_STATUS_ADC_DATA_0_IRQ_STATUS_MASK                                                       (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_STATUS_GPIO_COMMON_IRQ_STATUS_POS                                                       (8UL)
#define PCRM_INT_STATUS_GPIO_COMMON_IRQ_STATUS_MASK                                                      (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_STATUS_RESERVED4_POS                                                                     (7UL)
#define PCRM_INT_STATUS_RESERVED4_MASK                                                                    (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_STATUS_RESERVED5_POS                                                                     (5UL)
#define PCRM_INT_STATUS_RESERVED5_MASK                                                                    (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_STATUS_VDDIO_OK_IRQ_STATUS_POS                                                          (4UL)
#define PCRM_INT_STATUS_VDDIO_OK_IRQ_STATUS_MASK                                                         (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_STATUS_GPIO3_ZIF_IRQ_STATUS_POS                                                         (3UL)
#define PCRM_INT_STATUS_GPIO3_ZIF_IRQ_STATUS_MASK                                                        (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_STATUS_GPIO2_ZIF_IRQ_STATUS_POS                                                         (2UL)
#define PCRM_INT_STATUS_GPIO2_ZIF_IRQ_STATUS_MASK                                                        (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_STATUS_GPIO1_ZIF_IRQ_STATUS_POS                                                         (1UL)
#define PCRM_INT_STATUS_GPIO1_ZIF_IRQ_STATUS_MASK                                                        (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_STATUS_GPIO0_ZIF_IRQ_STATUS_POS                                                         (0UL)
#define PCRM_INT_STATUS_GPIO0_ZIF_IRQ_STATUS_MASK                                                        (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_STATUS__RESET_VALUE                                                             (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_set_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> -w
* @{
*/
#define PCRM_INT_SET_ENABLE                                                                               0xA5
#define PCRM_INT_SET_ENABLE_RESERVED_POS                                                                 (31UL)
#define PCRM_INT_SET_ENABLE_RESERVED_MASK                                                                (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_SET_ENABLE_SUSPEND_IRQ_SET_ENABLE_POS                                                   (30UL)
#define PCRM_INT_SET_ENABLE_SUSPEND_IRQ_SET_ENABLE_MASK                                                  (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_SET_ENABLE_SUSPEND_PREV_IRQ_SET_ENABLE_POS                                              (29UL)
#define PCRM_INT_SET_ENABLE_SUSPEND_PREV_IRQ_SET_ENABLE_MASK                                             (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_SET_ENABLE_PVDDLDO_OVERCURRENT_IRQ_SET_ENABLE_POS                                       (28UL)
#define PCRM_INT_SET_ENABLE_PVDDLDO_OVERCURRENT_IRQ_SET_ENABLE_MASK                                      (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_SET_ENABLE_RESERVED1_POS                                                                 (27UL)
#define PCRM_INT_SET_ENABLE_RESERVED1_MASK                                                                (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_SET_ENABLE_OVERCURRENT_IRQ_SET_ENABLE_POS                                               (26UL)
#define PCRM_INT_SET_ENABLE_OVERCURRENT_IRQ_SET_ENABLE_MASK                                              (0x04000000UL)  /**< 26-OVERCURRENT interrupt*/
#define PCRM_INT_SET_ENABLE_VUP_OK_IRQ_SET_ENABLE_POS                                                    (25UL)
#define PCRM_INT_SET_ENABLE_VUP_OK_IRQ_SET_ENABLE_MASK                                                   (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_SET_ENABLE_RESERVED2_POS                                                                 (24UL)
#define PCRM_INT_SET_ENABLE_RESERVED2_MASK                                                                (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_SET_ENABLE_USB_VBUS_PRESENT_IRQ_SET_ENABLE_POS                                          (23UL)
#define PCRM_INT_SET_ENABLE_USB_VBUS_PRESENT_IRQ_SET_ENABLE_MASK                                         (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_SET_ENABLE_RESERVED3_POS                                                                 (22UL)
#define PCRM_INT_SET_ENABLE_RESERVED3_MASK                                                                (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_SET_ENABLE_LPDET_IRQ_SET_ENABLE_POS                                                     (21UL)
#define PCRM_INT_SET_ENABLE_LPDET_IRQ_SET_ENABLE_MASK                                                    (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_SET_ENABLE_STBY_PREV_IRQ_SET_ENABLE_POS                                                 (20UL)
#define PCRM_INT_SET_ENABLE_STBY_PREV_IRQ_SET_ENABLE_MASK                                                (0x00100000UL)  /**< 20- stby prevention  interrupt */
#define PCRM_INT_SET_ENABLE_VBAT_MON2_LOW_IRQ_SET_ENABLE_POS                                             (19UL)
#define PCRM_INT_SET_ENABLE_VBAT_MON2_LOW_IRQ_SET_ENABLE_MASK                                            (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_SET_ENABLE_OVER_TEMP_PMU_IRQ_SET_ENABLE_POS                                             (18UL)
#define PCRM_INT_SET_ENABLE_OVER_TEMP_PMU_IRQ_SET_ENABLE_MASK                                            (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_SET_ENABLE_OVER_TEMP_NFC_IRQ_SET_ENABLE_POS                                             (17UL)
#define PCRM_INT_SET_ENABLE_OVER_TEMP_NFC_IRQ_SET_ENABLE_MASK                                            (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_SET_ENABLE_ADC_DATA_7_IRQ_SET_ENABLE_POS                                                (16UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_7_IRQ_SET_ENABLE_MASK                                               (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_6_IRQ_SET_ENABLE_POS                                                (15UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_6_IRQ_SET_ENABLE_MASK                                               (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_5_IRQ_SET_ENABLE_POS                                                (14UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_5_IRQ_SET_ENABLE_MASK                                               (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_4_IRQ_SET_ENABLE_POS                                                (13UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_4_IRQ_SET_ENABLE_MASK                                               (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_3_IRQ_SET_ENABLE_POS                                                (12UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_3_IRQ_SET_ENABLE_MASK                                               (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_2_IRQ_SET_ENABLE_POS                                                (11UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_2_IRQ_SET_ENABLE_MASK                                               (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_1_IRQ_SET_ENABLE_POS                                                (10UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_1_IRQ_SET_ENABLE_MASK                                               (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_SET_ENABLE_ADC_DATA_0_IRQ_SET_ENABLE_POS                                                (9UL)
#define PCRM_INT_SET_ENABLE_ADC_DATA_0_IRQ_SET_ENABLE_MASK                                               (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_SET_ENABLE_GPIO_COMMON_IRQ_SET_ENABLE_POS                                               (8UL)
#define PCRM_INT_SET_ENABLE_GPIO_COMMON_IRQ_SET_ENABLE_MASK                                              (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_SET_ENABLE_RESERVED4_POS                                                                 (7UL)
#define PCRM_INT_SET_ENABLE_RESERVED4_MASK                                                                (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_SET_ENABLE_RESERVED5_POS                                                                 (5UL)
#define PCRM_INT_SET_ENABLE_RESERVED5_MASK                                                                (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_SET_ENABLE_VDDIO_OK_IRQ_SET_ENABLE_POS                                                  (4UL)
#define PCRM_INT_SET_ENABLE_VDDIO_OK_IRQ_SET_ENABLE_MASK                                                 (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_SET_ENABLE_GPIO3_ZIF_IRQ_SET_ENABLE_POS                                                 (3UL)
#define PCRM_INT_SET_ENABLE_GPIO3_ZIF_IRQ_SET_ENABLE_MASK                                                (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_SET_ENABLE_GPIO2_ZIF_IRQ_SET_ENABLE_POS                                                 (2UL)
#define PCRM_INT_SET_ENABLE_GPIO2_ZIF_IRQ_SET_ENABLE_MASK                                                (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_SET_ENABLE_GPIO1_ZIF_IRQ_SET_ENABLE_POS                                                 (1UL)
#define PCRM_INT_SET_ENABLE_GPIO1_ZIF_IRQ_SET_ENABLE_MASK                                                (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_SET_ENABLE_GPIO0_ZIF_IRQ_SET_ENABLE_POS                                                 (0UL)
#define PCRM_INT_SET_ENABLE_GPIO0_ZIF_IRQ_SET_ENABLE_MASK                                                (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_SET_ENABLE__RESET_VALUE                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_clr_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> -w
* @{
*/
#define PCRM_INT_CLR_ENABLE                                                                               0xA6
#define PCRM_INT_CLR_ENABLE_RESERVED_POS                                                                 (31UL)
#define PCRM_INT_CLR_ENABLE_RESERVED_MASK                                                                (0x80000000UL)  /**< 31-reserved*/
#define PCRM_INT_CLR_ENABLE_SUSPEND_IRQ_CLEAR_ENABLE_POS                                                 (30UL)
#define PCRM_INT_CLR_ENABLE_SUSPEND_IRQ_CLEAR_ENABLE_MASK                                                (0x40000000UL)  /**< 30-suspend interrupt */
#define PCRM_INT_CLR_ENABLE_SUSPEND_PREV_IRQ_CLEAR_ENABLE_POS                                            (29UL)
#define PCRM_INT_CLR_ENABLE_SUSPEND_PREV_IRQ_CLEAR_ENABLE_MASK                                           (0x20000000UL)  /**< 29-suspend Prevention interrupt */
#define PCRM_INT_CLR_ENABLE_PVDDLDO_OVERCURRENT_IRQ_CLEAR_ENABLE_POS                                     (28UL)
#define PCRM_INT_CLR_ENABLE_PVDDLDO_OVERCURRENT_IRQ_CLEAR_ENABLE_MASK                                    (0x10000000UL)  /**< 28-PVDDLDO Overcurrent interrupt*/
#define PCRM_INT_CLR_ENABLE_RESERVED1_POS                                                                 (27UL)
#define PCRM_INT_CLR_ENABLE_RESERVED1_MASK                                                                (0x08000000UL)  /**< 27-reserved*/
#define PCRM_INT_CLR_ENABLE_OVERCURRENT_IRQ_CLEAR_ENABLE_POS                                             (26UL)
#define PCRM_INT_CLR_ENABLE_OVERCURRENT_IRQ_CLEAR_ENABLE_MASK                                            (0x04000000UL)  /**< 26-OVERCURRENT interrupt*/
#define PCRM_INT_CLR_ENABLE_VUP_OK_IRQ_CLEAR_ENABLE_POS                                                  (25UL)
#define PCRM_INT_CLR_ENABLE_VUP_OK_IRQ_CLEAR_ENABLE_MASK                                                 (0x02000000UL)  /**< 25-VUP_OK edge interrupt*/
#define PCRM_INT_CLR_ENABLE_RESERVED2_POS                                                                 (24UL)
#define PCRM_INT_CLR_ENABLE_RESERVED2_MASK                                                                (0x01000000UL)  /**< 24-reserved*/
#define PCRM_INT_CLR_ENABLE_USB_VBUS_PRESENT_IRQ_CLEAR_ENABLE_POS                                        (23UL)
#define PCRM_INT_CLR_ENABLE_USB_VBUS_PRESENT_IRQ_CLEAR_ENABLE_MASK                                       (0x00800000UL)  /**< 23-USB VBUS Present*/
#define PCRM_INT_CLR_ENABLE_RESERVED3_POS                                                                 (22UL)
#define PCRM_INT_CLR_ENABLE_RESERVED3_MASK                                                                (0x00400000UL)  /**< 22-reserved*/
#define PCRM_INT_CLR_ENABLE_LPDET_IRQ_CLEAR_ENABLE_POS                                                   (21UL)
#define PCRM_INT_CLR_ENABLE_LPDET_IRQ_CLEAR_ENABLE_MASK                                                  (0x00200000UL)  /**< 21-LPDET interrupt */
#define PCRM_INT_CLR_ENABLE_STBY_PREV_IRQ_CLEAR_ENABLE_POS                                               (20UL)
#define PCRM_INT_CLR_ENABLE_STBY_PREV_IRQ_CLEAR_ENABLE_MASK                                              (0x00100000UL)  /**< 20-stby prev interrupt */
#define PCRM_INT_CLR_ENABLE_VBAT_MON2_LOW_IRQ_CLEAR_ENABLE_POS                                           (19UL)
#define PCRM_INT_CLR_ENABLE_VBAT_MON2_LOW_IRQ_CLEAR_ENABLE_MASK                                          (0x00080000UL)  /**< 19-VBAT Monitor2 Low*/
#define PCRM_INT_CLR_ENABLE_OVER_TEMP_PMU_IRQ_CLEAR_ENABLE_POS                                           (18UL)
#define PCRM_INT_CLR_ENABLE_OVER_TEMP_PMU_IRQ_CLEAR_ENABLE_MASK                                          (0x00040000UL)  /**< 18-PMU TWARN Up or Down interrupt */
#define PCRM_INT_CLR_ENABLE_OVER_TEMP_NFC_IRQ_CLEAR_ENABLE_POS                                           (17UL)
#define PCRM_INT_CLR_ENABLE_OVER_TEMP_NFC_IRQ_CLEAR_ENABLE_MASK                                          (0x00020000UL)  /**< 17-CLIF TWARN Up or Down interrupt */
#define PCRM_INT_CLR_ENABLE_ADC_DATA_7_IRQ_CLEAR_ENABLE_POS                                              (16UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_7_IRQ_CLEAR_ENABLE_MASK                                             (0x00010000UL)  /**< 16-GPADC channel 7 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_6_IRQ_CLEAR_ENABLE_POS                                              (15UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_6_IRQ_CLEAR_ENABLE_MASK                                             (0x00008000UL)  /**< 15-GPADC channel 6 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_5_IRQ_CLEAR_ENABLE_POS                                              (14UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_5_IRQ_CLEAR_ENABLE_MASK                                             (0x00004000UL)  /**< 14-GPADC channel 5 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_4_IRQ_CLEAR_ENABLE_POS                                              (13UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_4_IRQ_CLEAR_ENABLE_MASK                                             (0x00002000UL)  /**< 13-GPADC channel 4 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_3_IRQ_CLEAR_ENABLE_POS                                              (12UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_3_IRQ_CLEAR_ENABLE_MASK                                             (0x00001000UL)  /**< 12-GPADC channel 3 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_2_IRQ_CLEAR_ENABLE_POS                                              (11UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_2_IRQ_CLEAR_ENABLE_MASK                                             (0x00000800UL)  /**< 11-GPADC channel 2 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_1_IRQ_CLEAR_ENABLE_POS                                              (10UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_1_IRQ_CLEAR_ENABLE_MASK                                             (0x00000400UL)  /**< 10-GPADC channel 1 interrupt*/
#define PCRM_INT_CLR_ENABLE_ADC_DATA_0_IRQ_CLEAR_ENABLE_POS                                              (9UL)
#define PCRM_INT_CLR_ENABLE_ADC_DATA_0_IRQ_CLEAR_ENABLE_MASK                                             (0x00000200UL)  /**< 9-GPADC channel 0 interrupt*/
#define PCRM_INT_CLR_ENABLE_GPIO_COMMON_IRQ_CLEAR_ENABLE_POS                                             (8UL)
#define PCRM_INT_CLR_ENABLE_GPIO_COMMON_IRQ_CLEAR_ENABLE_MASK                                            (0x00000100UL)  /**< 8-Common GPIO IRQ (OR condition of GPIO0,1,2,3)*/
#define PCRM_INT_CLR_ENABLE_RESERVED4_POS                                                                 (7UL)
#define PCRM_INT_CLR_ENABLE_RESERVED4_MASK                                                                (0x00000080UL)  /**< 7-reserved*/
#define PCRM_INT_CLR_ENABLE_RESERVED5_POS                                                                 (5UL)
#define PCRM_INT_CLR_ENABLE_RESERVED5_MASK                                                                (0x00000060UL)  /**< 5-reserved*/
#define PCRM_INT_CLR_ENABLE_VDDIO_OK_IRQ_CLEAR_ENABLE_POS                                                (4UL)
#define PCRM_INT_CLR_ENABLE_VDDIO_OK_IRQ_CLEAR_ENABLE_MASK                                               (0x00000010UL)  /**< 4-VDDIO OK interrupt*/
#define PCRM_INT_CLR_ENABLE_GPIO3_ZIF_IRQ_CLEAR_ENABLE_POS                                               (3UL)
#define PCRM_INT_CLR_ENABLE_GPIO3_ZIF_IRQ_CLEAR_ENABLE_MASK                                              (0x00000008UL)  /**< 3-GPIO3 IRQ*/
#define PCRM_INT_CLR_ENABLE_GPIO2_ZIF_IRQ_CLEAR_ENABLE_POS                                               (2UL)
#define PCRM_INT_CLR_ENABLE_GPIO2_ZIF_IRQ_CLEAR_ENABLE_MASK                                              (0x00000004UL)  /**< 2-GPIO2 IRQ*/
#define PCRM_INT_CLR_ENABLE_GPIO1_ZIF_IRQ_CLEAR_ENABLE_POS                                               (1UL)
#define PCRM_INT_CLR_ENABLE_GPIO1_ZIF_IRQ_CLEAR_ENABLE_MASK                                              (0x00000002UL)  /**< 1-GPIO1 IRQ*/
#define PCRM_INT_CLR_ENABLE_GPIO0_ZIF_IRQ_CLEAR_ENABLE_POS                                               (0UL)
#define PCRM_INT_CLR_ENABLE_GPIO0_ZIF_IRQ_CLEAR_ENABLE_MASK                                              (0x00000001UL)  /**< 0-GPIO0 IRQ*/
#define PCRM_INT_CLR_ENABLE__RESET_VALUE                                                   (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio5
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO5                                                                                    0xA7
#define PCRM_PAD_GPIO5_R                                                                                    0xA7
#define PCRM_PAD_GPIO5_W                                                                                    0xA7
#define PCRM_PAD_GPIO5_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_GPIO5_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO5_GPIO5_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO5_GPIO5_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Select Driver Strength for GPIO5*/
#define PCRM_PAD_GPIO5_GPIO5_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO5_GPIO5_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enable PullUp/Down for GPIO5 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO5_GPIO5_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO5_GPIO5_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO5*/
#define PCRM_PAD_GPIO5_GPIO5_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO5_GPIO5_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO5*/
#define PCRM_PAD_GPIO5__RESET_VALUE                                                                       (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio4
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO4                                                                                    0xA8
#define PCRM_PAD_GPIO4_R                                                                                    0xA8
#define PCRM_PAD_GPIO4_W                                                                                    0xA8
#define PCRM_PAD_GPIO4_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_GPIO4_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO4_GPIO4_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO4_GPIO4_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Select Driver Strength for GPIO4*/
#define PCRM_PAD_GPIO4_GPIO4_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO4_GPIO4_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enable PullUp/Down for GPIO4 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO4_GPIO4_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO4_GPIO4_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO4*/
#define PCRM_PAD_GPIO4_GPIO4_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO4_GPIO4_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO4*/
#define PCRM_PAD_GPIO4__RESET_VALUE                                                                       (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_ulpcd_sts
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_ULPCD_STS                                                                                    0xA9
#define PCRM_ULPCD_STS_R                                                                                    0xA9
#define PCRM_ULPCD_STS_RESERVED_POS                                                                      (11UL)
#define PCRM_ULPCD_STS_RESERVED_MASK                                                                     (0xFFFFF800UL)  /**< 11-reserved*/
#define PCRM_ULPCD_STS_RSSI_POS                                                                          (0UL)
#define PCRM_ULPCD_STS_RSSI_MASK                                                                         (0x000007FFUL)  /**< 0-RSSI value from ULPCD GPADC*/
#define PCRM_ULPCD_STS__RESET_VALUE                                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_sts2
* <b>Reset value:</b> 0x00000002
* <b>Access:</b> r-
* @{
*/
#define PCRM_PMU_ANA_STS2                                                                                 0xAA
#define PCRM_PMU_ANA_STS2_R                                                                                 0xAA
#define PCRM_PMU_ANA_STS2_RESERVED_POS                                                                   (3UL)
#define PCRM_PMU_ANA_STS2_RESERVED_MASK                                                                  (0xFFFFFFF8UL)  /**< 3-reserved*/
#define PCRM_PMU_ANA_STS2_USB_VBUS_PRESENT_POS                                                           (2UL)
#define PCRM_PMU_ANA_STS2_USB_VBUS_PRESENT_MASK                                                          (0x00000004UL)  /**< 2-USB VBUS Present*/
#define PCRM_PMU_ANA_STS2_VDDIOHI_OK_POS                                                                 (1UL)
#define PCRM_PMU_ANA_STS2_VDDIOHI_OK_MASK                                                                (0x00000002UL)  /**< 1-VDDIOHI Voltage OK (VDDIO>2.1V)*/
#define PCRM_PMU_ANA_STS2_VBAT_MON2_OK_POS                                                               (0UL)
#define PCRM_PMU_ANA_STS2_VBAT_MON2_OK_MASK                                                              (0x00000001UL)  /**< 0-VBAT Voltage 3V8 OK (VBAT > 3.8V)*/
#define PCRM_PMU_ANA_STS2__RESET_VALUE                                                                   (0x00000002UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_misc_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_MISC_CTRL                                                                            0xAB
#define PCRM_PMU_ANA_MISC_CTRL_R                                                                            0xAB
#define PCRM_PMU_ANA_MISC_CTRL_W                                                                            0xAB
#define PCRM_PMU_ANA_MISC_CTRL_RESERVED_POS                                                              (2UL)
#define PCRM_PMU_ANA_MISC_CTRL_RESERVED_MASK                                                             (0xFFFFFFFCUL)  /**< 2-reserved*/
#define PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_MON_EN_POS                                                       (1UL)
#define PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_MON_EN_MASK                                                      (0x00000002UL)  /**< 1-Enables USB VBUS Monitor*/
#define PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_PULLDOWN_EN_POS                                                  (0UL)
#define PCRM_PMU_ANA_MISC_CTRL_USB_VBUS_PULLDOWN_EN_MASK                                                 (0x00000001UL)  /**< 0-Enables the internal pulldown resistance to pulldown the USB_VBUS*/
#define PCRM_PMU_ANA_MISC_CTRL__RESET_VALUE                                                      (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_vbat_mon2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_VBAT_MON2                                                                            0xAC
#define PCRM_PMU_ANA_VBAT_MON2_R                                                                            0xAC
#define PCRM_PMU_ANA_VBAT_MON2_W                                                                            0xAC
#define PCRM_PMU_ANA_VBAT_MON2_RESERVED_POS                                                              (1UL)
#define PCRM_PMU_ANA_VBAT_MON2_RESERVED_MASK                                                             (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_PMU_ANA_VBAT_MON2_VBAT_MON2_EN_POS                                                          (0UL)
#define PCRM_PMU_ANA_VBAT_MON2_VBAT_MON2_EN_MASK                                                         (0x00000001UL)  /**< 0-Enable Voltage Monitor on VBAT (Triggers when VBAT>3.8V)*/
#define PCRM_PMU_ANA_VBAT_MON2__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_dig_vbus_debounce_ctrl
* <b>Reset value:</b> 0x00000474
* <b>Access:</b> rw
* @{
*/
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL                                                                       0xAD
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_R                                                                       0xAD
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_W                                                                       0xAD
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_RESERVED_POS                                                         (13UL)
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_RESERVED_MASK                                                        (0xFFFFE000UL)  /**< 13-reserved*/
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_DEBOUNCE_BYPASS_EN_POS                                               (12UL)
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_DEBOUNCE_BYPASS_EN_MASK                                              (0x00001000UL)  /**< 12-USB VBUS debounce bypass*/
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_RESERVED1_POS                                                         (11UL)
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_RESERVED1_MASK                                                        (0x00000800UL)  /**< 11-reserved*/
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_VBUS_DEBOUNCE_TIME_POS                                               (0UL)
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL_VBUS_DEBOUNCE_TIME_MASK                                              (0x000007FFUL)  /**< 0-USB VBUS debounce time*/
#define PCRM_DIG_VBUS_DEBOUNCE_CTRL__RESET_VALUE                                                   (0x00000474UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_int_edge_sel
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_INT_EDGE_SEL                                                                                 0xAE
#define PCRM_INT_EDGE_SEL_R                                                                                 0xAE
#define PCRM_INT_EDGE_SEL_W                                                                                 0xAE
#define PCRM_INT_EDGE_SEL_RESERVED_POS                                                                   (10UL)
#define PCRM_INT_EDGE_SEL_RESERVED_MASK                                                                  (0xFFFFFC00UL)  /**< 10-reserved*/
#define PCRM_INT_EDGE_SEL_EDGE_SEL_COM_POS                                                               (8UL)
#define PCRM_INT_EDGE_SEL_EDGE_SEL_COM_MASK                                                              (0x00000300UL)  /**< 8-GPIO_COMMON interrupt edge detect selection 00: disable; 01: r edge; 10: f edge; 11: dual edge;*/
#define PCRM_INT_EDGE_SEL_EDGE_SEL_3_POS                                                                 (6UL)
#define PCRM_INT_EDGE_SEL_EDGE_SEL_3_MASK                                                                (0x000000C0UL)  /**< 6-GPIO3 interrupt edge detect selection 00: disable; 01: r edge; 10: f edge; 11: dual edge;*/
#define PCRM_INT_EDGE_SEL_EDGE_SEL_2_POS                                                                 (4UL)
#define PCRM_INT_EDGE_SEL_EDGE_SEL_2_MASK                                                                (0x00000030UL)  /**< 4-GPIO2 interrupt edge detect selection 00: disable; 01: r edge; 10: f edge; 11: dual edge;*/
#define PCRM_INT_EDGE_SEL_EDGE_SEL_1_POS                                                                 (2UL)
#define PCRM_INT_EDGE_SEL_EDGE_SEL_1_MASK                                                                (0x0000000CUL)  /**< 2-GPIO1 interrupt edge detect selection 00: disable; 01: r edge; 10: f edge; 11: dual edge;*/
#define PCRM_INT_EDGE_SEL_EDGE_SEL_0_POS                                                                 (0UL)
#define PCRM_INT_EDGE_SEL_EDGE_SEL_0_MASK                                                                (0x00000003UL)  /**< 0-GPIO0 interrupt edge detect selection 00: disable; 01: r edge; 10: f edge; 11: dual edge;*/
#define PCRM_INT_EDGE_SEL__RESET_VALUE                                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_vddio_loss_det_disable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_VDDIO_LOSS_DET_DISABLE                                                                       0xAF
#define PCRM_VDDIO_LOSS_DET_DISABLE_R                                                                       0xAF
#define PCRM_VDDIO_LOSS_DET_DISABLE_W                                                                       0xAF
#define PCRM_VDDIO_LOSS_DET_DISABLE_RESERVED_POS                                                         (1UL)
#define PCRM_VDDIO_LOSS_DET_DISABLE_RESERVED_MASK                                                        (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_VDDIO_LOSS_DET_DISABLE_VDDIO_LOSS_DET_DISABLE_POS                                           (0UL)
#define PCRM_VDDIO_LOSS_DET_DISABLE_VDDIO_LOSS_DET_DISABLE_MASK                                          (0x00000001UL)  /**< 0-Write '1' and sequentially write '0' after minimum of 1 LFO cycle will disable VDDIO LOSS detection function in PMU_ANA*/
#define PCRM_VDDIO_LOSS_DET_DISABLE__RESET_VALUE                                               (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_vddio_loss_det_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_VDDIO_LOSS_DET_ENABLE                                                                        0xB0
#define PCRM_VDDIO_LOSS_DET_ENABLE_R                                                                        0xB0
#define PCRM_VDDIO_LOSS_DET_ENABLE_W                                                                        0xB0
#define PCRM_VDDIO_LOSS_DET_ENABLE_RESERVED_POS                                                          (1UL)
#define PCRM_VDDIO_LOSS_DET_ENABLE_RESERVED_MASK                                                         (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_VDDIO_LOSS_DET_ENABLE_VDDIO_LOSS_DET_ENABLE_POS                                             (0UL)
#define PCRM_VDDIO_LOSS_DET_ENABLE_VDDIO_LOSS_DET_ENABLE_MASK                                            (0x00000001UL)  /**< 0-Write '1'  and sequentially write '0' after minimum of 1 LFO cycle will enable VDDIO LOSS detection function in PMU_ANA*/
#define PCRM_VDDIO_LOSS_DET_ENABLE__RESET_VALUE                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_dwl_req
* <b>Reset value:</b> 0x00000011
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_DWL_REQ                                                                                  0xB1
#define PCRM_PAD_DWL_REQ_R                                                                                  0xB1
#define PCRM_PAD_DWL_REQ_W                                                                                  0xB1
#define PCRM_PAD_DWL_REQ_RESERVED_POS                                                                    (6UL)
#define PCRM_PAD_DWL_REQ_RESERVED_MASK                                                                   (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_DWL_REQ_DWL_REQ_SLEW_RATE_POS                                                           (4UL)
#define PCRM_PAD_DWL_REQ_DWL_REQ_SLEW_RATE_MASK                                                          (0x00000030UL)  /**< 4-Selects Driver Strength for DWL_REQ*/
#define PCRM_PAD_DWL_REQ_DWL_REQ_PUPD_POS                                                                (2UL)
#define PCRM_PAD_DWL_REQ_DWL_REQ_PUPD_MASK                                                               (0x0000000CUL)  /**< 2-Enables PullUp/Down for DWL_REQ (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_DWL_REQ_DWL_REQ_EN_OUT_POS                                                              (1UL)
#define PCRM_PAD_DWL_REQ_DWL_REQ_EN_OUT_MASK                                                             (0x00000002UL)  /**< 1-Enables Output driver for DWL_REQ*/
#define PCRM_PAD_DWL_REQ_DWL_REQ_EN_IN_POS                                                               (0UL)
#define PCRM_PAD_DWL_REQ_DWL_REQ_EN_IN_MASK                                                              (0x00000001UL)  /**< 0-Enables Input Driver for DWL_REQ*/
#define PCRM_PAD_DWL_REQ__RESET_VALUE                                                                   (0x00000011UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_irq
* <b>Reset value:</b> 0x00000012
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_IRQ                                                                                      0xB2
#define PCRM_PAD_IRQ_R                                                                                      0xB2
#define PCRM_PAD_IRQ_W                                                                                      0xB2
#define PCRM_PAD_IRQ_RESERVED_POS                                                                        (17UL)
#define PCRM_PAD_IRQ_RESERVED_MASK                                                                       (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_IRQ_IRQ_ENABLE_POS                                                                      (16UL)
#define PCRM_PAD_IRQ_IRQ_ENABLE_MASK                                                                     (0x00010000UL)  /**< 16-If set them IRQ unit output  is driving the GPIO*/
#define PCRM_PAD_IRQ_RESERVED1_POS                                                                        (6UL)
#define PCRM_PAD_IRQ_RESERVED1_MASK                                                                       (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_IRQ_IRQ_SLEW_RATE_POS                                                                   (4UL)
#define PCRM_PAD_IRQ_IRQ_SLEW_RATE_MASK                                                                  (0x00000030UL)  /**< 4-Selects Driver Strength for IRQ*/
#define PCRM_PAD_IRQ_IRQ_PUPD_POS                                                                        (2UL)
#define PCRM_PAD_IRQ_IRQ_PUPD_MASK                                                                       (0x0000000CUL)  /**< 2-Enables PullUp/Down for IRQ (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_IRQ_IRQ_EN_OUT_POS                                                                      (1UL)
#define PCRM_PAD_IRQ_IRQ_EN_OUT_MASK                                                                     (0x00000002UL)  /**< 1-Enables Output driver for IRQ*/
#define PCRM_PAD_IRQ_IRQ_EN_IN_POS                                                                       (0UL)
#define PCRM_PAD_IRQ_IRQ_EN_IN_MASK                                                                      (0x00000001UL)  /**< 0-Enables Input Driver for IRQ*/
#define PCRM_PAD_IRQ__RESET_VALUE                                                                           (0x00000012UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_atx_d
* <b>Reset value:</b> 0x00000021
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_ATX_D                                                                                    0xB3
#define PCRM_PAD_ATX_D_R                                                                                    0xB3
#define PCRM_PAD_ATX_D_W                                                                                    0xB3
#define PCRM_PAD_ATX_D_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_ATX_D_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_ATX_D_ATX_D_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_ATX_D_ATX_D_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for ATX_D*/
#define PCRM_PAD_ATX_D_ATX_D_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_ATX_D_ATX_D_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for ATX_D (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_ATX_D_ATX_D_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_ATX_D_ATX_D_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for ATX_D*/
#define PCRM_PAD_ATX_D_ATX_D_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_ATX_D_ATX_D_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for ATX_D*/
#define PCRM_PAD_ATX_D__RESET_VALUE                                                                       (0x00000021UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_atx_c
* <b>Reset value:</b> 0x00000021
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_ATX_C                                                                                    0xB4
#define PCRM_PAD_ATX_C_R                                                                                    0xB4
#define PCRM_PAD_ATX_C_W                                                                                    0xB4
#define PCRM_PAD_ATX_C_RESERVED_POS                                                                      (7UL)
#define PCRM_PAD_ATX_C_RESERVED_MASK                                                                     (0xFFFFFF80UL)  /**< 7-reserved*/
#define PCRM_PAD_ATX_C_ATX_C_EN_RTS_CONTROL_POS                                                          (6UL)
#define PCRM_PAD_ATX_C_ATX_C_EN_RTS_CONTROL_MASK                                                         (0x00000040UL)  /**< 6- Selector for output value in case UART as Host Interface is selected (PCRM_SYS_CTRL_REG.HIF_SELECT == 3 (uart)) 0 - HW control (same as for PN552); 1 - FW control (output value == PCRM_PADOUT_REG.PADOUT_ATX_C)*/
#define PCRM_PAD_ATX_C_ATX_C_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_ATX_C_ATX_C_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for ATX_C*/
#define PCRM_PAD_ATX_C_ATX_C_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_ATX_C_ATX_C_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for ATX_C (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_ATX_C_ATX_C_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_ATX_C_ATX_C_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for ATX_C*/
#define PCRM_PAD_ATX_C_ATX_C_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_ATX_C_ATX_C_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for ATX_C*/
#define PCRM_PAD_ATX_C__RESET_VALUE                                                                       (0x00000021UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_atx_a
* <b>Reset value:</b> 0x00000051
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_ATX_A                                                                                    0xB5
#define PCRM_PAD_ATX_A_R                                                                                    0xB5
#define PCRM_PAD_ATX_A_W                                                                                    0xB5
#define PCRM_PAD_ATX_A_RESERVED_POS                                                                      (9UL)
#define PCRM_PAD_ATX_A_RESERVED_MASK                                                                     (0xFFFFFE00UL)  /**< 9-reserved*/
#define PCRM_PAD_ATX_A_ATX_A_I3C_ZI_ZIF_SEL_POS                                                          (8UL)
#define PCRM_PAD_ATX_A_ATX_A_I3C_ZI_ZIF_SEL_MASK                                                         (0x00000100UL)  /**< 8-Select ZI or ZIF pad pin when I3C is active (0: ZI, 1: ZIF)*/
#define PCRM_PAD_ATX_A_ATX_A_ECS_POS                                                                     (7UL)
#define PCRM_PAD_ATX_A_ATX_A_ECS_MASK                                                                    (0x00000080UL)  /**< 7-Enables Pull-up current source for ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A_ATX_A_EGP_POS                                                                     (6UL)
#define PCRM_PAD_ATX_A_ATX_A_EGP_MASK                                                                    (0x00000040UL)  /**< 6-Enables GPIO mode (0: I2C mode; 1: GPIO mode)for ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A_ATX_A_FSEL_POS                                                                    (5UL)
#define PCRM_PAD_ATX_A_ATX_A_FSEL_MASK                                                                   (0x00000020UL)  /**< 5-Selects Input Filter value for I2C mode (0: 50ns; 1: 10ns) for ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A_ATX_A_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_ATX_A_ATX_A_SLEW_RATE_MASK                                                              (0x00000010UL)  /**< 4-Selects Driver Strength / Speed mode (0: Low speed GPIO / SF and FP I2C mode; 1: Medium speed GPIO / HS I2C mode) on ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A_ATX_A_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_ATX_A_ATX_A_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for ATX_A (I2C_SDA) (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_ATX_A_ATX_A_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_ATX_A_ATX_A_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A_ATX_A_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_ATX_A_ATX_A_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for ATX_A (I2C_SDA)*/
#define PCRM_PAD_ATX_A__RESET_VALUE                                                                       (0x00000051UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_atx_b
* <b>Reset value:</b> 0x00000051
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_ATX_B                                                                                    0xB6
#define PCRM_PAD_ATX_B_R                                                                                    0xB6
#define PCRM_PAD_ATX_B_W                                                                                    0xB6
#define PCRM_PAD_ATX_B_RESERVED_POS                                                                      (9UL)
#define PCRM_PAD_ATX_B_RESERVED_MASK                                                                     (0xFFFFFE00UL)  /**< 9-reserved*/
#define PCRM_PAD_ATX_B_ATX_B_I3C_ZI_ZIF_SEL_POS                                                          (8UL)
#define PCRM_PAD_ATX_B_ATX_B_I3C_ZI_ZIF_SEL_MASK                                                         (0x00000100UL)  /**< 8-Select ZI or ZIF pad pin when I3C is active (0: ZI, 1: ZIF)*/
#define PCRM_PAD_ATX_B_ATX_B_ECS_POS                                                                     (7UL)
#define PCRM_PAD_ATX_B_ATX_B_ECS_MASK                                                                    (0x00000080UL)  /**< 7-Enables Pull-up current source for ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B_ATX_B_EGP_POS                                                                     (6UL)
#define PCRM_PAD_ATX_B_ATX_B_EGP_MASK                                                                    (0x00000040UL)  /**< 6-Enables GPIO mode (0: I2C mode; 1: GPIO mode) for ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B_ATX_B_FSEL_POS                                                                    (5UL)
#define PCRM_PAD_ATX_B_ATX_B_FSEL_MASK                                                                   (0x00000020UL)  /**< 5-Selects Input Filter value for I2C mode (0: 50ns; 1: 10ns) for ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B_ATX_B_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_ATX_B_ATX_B_SLEW_RATE_MASK                                                              (0x00000010UL)  /**< 4-Selects Driver Strength / Speed mode (0: Low speed GPIO / SF and FP I2C mode; 1: Medium speed GPIO / HS I2C mode) on ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B_ATX_B_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_ATX_B_ATX_B_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for ATX_B (I2C_SCL) (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_ATX_B_ATX_B_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_ATX_B_ATX_B_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B_ATX_B_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_ATX_B_ATX_B_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for ATX_B (I2C_SCL)*/
#define PCRM_PAD_ATX_B__RESET_VALUE                                                                       (0x00000051UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio3
* <b>Reset value:</b> 0x00000002
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO3                                                                                    0xB7
#define PCRM_PAD_GPIO3_R                                                                                    0xB7
#define PCRM_PAD_GPIO3_W                                                                                    0xB7
#define PCRM_PAD_GPIO3_RESERVED_POS                                                                      (17UL)
#define PCRM_PAD_GPIO3_RESERVED_MASK                                                                     (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_GPIO3_GPIO3_PWM_ENABLE_POS                                                              (16UL)
#define PCRM_PAD_GPIO3_GPIO3_PWM_ENABLE_MASK                                                             (0x00010000UL)  /**< 16-If set them PWM unit output 3 is driving the GPIO3*/
#define PCRM_PAD_GPIO3_RESERVED1_POS                                                                      (6UL)
#define PCRM_PAD_GPIO3_RESERVED1_MASK                                                                     (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO3_GPIO3_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO3_GPIO3_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Select Driver Strength for GPIO3*/
#define PCRM_PAD_GPIO3_GPIO3_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO3_GPIO3_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enable PullUp/Down for GPIO3 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO3_GPIO3_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO3_GPIO3_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO3*/
#define PCRM_PAD_GPIO3_GPIO3_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO3_GPIO3_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO3*/
#define PCRM_PAD_GPIO3__RESET_VALUE                                                                       (0x00000002UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio2
* <b>Reset value:</b> 0x00000002
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO2                                                                                    0xB8
#define PCRM_PAD_GPIO2_R                                                                                    0xB8
#define PCRM_PAD_GPIO2_W                                                                                    0xB8
#define PCRM_PAD_GPIO2_RESERVED_POS                                                                      (17UL)
#define PCRM_PAD_GPIO2_RESERVED_MASK                                                                     (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_GPIO2_GPIO2_PWM_ENABLE_POS                                                              (16UL)
#define PCRM_PAD_GPIO2_GPIO2_PWM_ENABLE_MASK                                                             (0x00010000UL)  /**< 16-If set them PWM unit output 2 is driving the GPIO2*/
#define PCRM_PAD_GPIO2_RESERVED1_POS                                                                      (6UL)
#define PCRM_PAD_GPIO2_RESERVED1_MASK                                                                     (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO2_GPIO2_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO2_GPIO2_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Select Driver Strength for GPIO2*/
#define PCRM_PAD_GPIO2_GPIO2_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO2_GPIO2_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enable PullUp/Down for GPIO2 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO2_GPIO2_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO2_GPIO2_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO2*/
#define PCRM_PAD_GPIO2_GPIO2_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO2_GPIO2_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO2*/
#define PCRM_PAD_GPIO2__RESET_VALUE                                                                       (0x00000002UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio1
* <b>Reset value:</b> 0x00000003
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO1                                                                                    0xB9
#define PCRM_PAD_GPIO1_R                                                                                    0xB9
#define PCRM_PAD_GPIO1_W                                                                                    0xB9
#define PCRM_PAD_GPIO1_RESERVED_POS                                                                      (17UL)
#define PCRM_PAD_GPIO1_RESERVED_MASK                                                                     (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_GPIO1_GPIO1_PWM_ENABLE_POS                                                              (16UL)
#define PCRM_PAD_GPIO1_GPIO1_PWM_ENABLE_MASK                                                             (0x00010000UL)  /**< 16-If set them PWM unit output 1 is driving the GPIO1*/
#define PCRM_PAD_GPIO1_RESERVED1_POS                                                                      (6UL)
#define PCRM_PAD_GPIO1_RESERVED1_MASK                                                                     (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO1_GPIO1_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO1_GPIO1_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for GPIO1*/
#define PCRM_PAD_GPIO1_GPIO1_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO1_GPIO1_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for GPIO1 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO1_GPIO1_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO1_GPIO1_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO1*/
#define PCRM_PAD_GPIO1_GPIO1_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO1_GPIO1_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO1*/
#define PCRM_PAD_GPIO1__RESET_VALUE                                                                       (0x00000003UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_gpio0
* <b>Reset value:</b> 0x0000000F
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_GPIO0                                                                                    0xBA
#define PCRM_PAD_GPIO0_R                                                                                    0xBA
#define PCRM_PAD_GPIO0_W                                                                                    0xBA
#define PCRM_PAD_GPIO0_RESERVED_POS                                                                      (17UL)
#define PCRM_PAD_GPIO0_RESERVED_MASK                                                                     (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_GPIO0_GPIO0_PWM_ENABLE_POS                                                              (16UL)
#define PCRM_PAD_GPIO0_GPIO0_PWM_ENABLE_MASK                                                             (0x00010000UL)  /**< 16-If set them PWM unit output 0 is driving the GPIO0*/
#define PCRM_PAD_GPIO0_RESERVED1_POS                                                                      (6UL)
#define PCRM_PAD_GPIO0_RESERVED1_MASK                                                                     (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_GPIO0_GPIO0_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_GPIO0_GPIO0_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for GPIO0*/
#define PCRM_PAD_GPIO0_GPIO0_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_GPIO0_GPIO0_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for GPIO0 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_GPIO0_GPIO0_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_GPIO0_GPIO0_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for GPIO0*/
#define PCRM_PAD_GPIO0_GPIO0_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_GPIO0_GPIO0_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for GPIO0*/
#define PCRM_PAD_GPIO0__RESET_VALUE                                                                       (0x0000000FUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_padout
* <b>Reset value:</b> 0x000000F0
* <b>Access:</b> rw
* @{
*/
#define PCRM_PADOUT                                                                                       0xBB
#define PCRM_PADOUT_R                                                                                       0xBB
#define PCRM_PADOUT_W                                                                                       0xBB
#define PCRM_PADOUT_RESERVED_POS                                                                         (27UL)
#define PCRM_PADOUT_RESERVED_MASK                                                                        (0xF8000000UL)  /**< 27-reserved*/
#define PCRM_PADOUT_PADOUT_INT_AUX_POS                                                                   (26UL)
#define PCRM_PADOUT_PADOUT_INT_AUX_MASK                                                                  (0x04000000UL)  /**< 26-Output Value for CT_AUX_INT*/
#define PCRM_PADOUT_PADOUT_CLK_AUX_POS                                                                   (25UL)
#define PCRM_PADOUT_PADOUT_CLK_AUX_MASK                                                                  (0x02000000UL)  /**< 25-Output Value for CT_AUX_CLK*/
#define PCRM_PADOUT_PADOUT_IO_AUX_POS                                                                    (24UL)
#define PCRM_PADOUT_PADOUT_IO_AUX_MASK                                                                   (0x01000000UL)  /**< 24-Output Value for CT_AUX_IO*/
#define PCRM_PADOUT_RESERVED1_POS                                                                         (23UL)
#define PCRM_PADOUT_RESERVED1_MASK                                                                        (0x00800000UL)  /**< 23-reserved*/
#define PCRM_PADOUT_PADOUT_AUX_2_POS                                                                     (22UL)
#define PCRM_PADOUT_PADOUT_AUX_2_MASK                                                                    (0x00400000UL)  /**< 22-Output Value for AUX_2*/
#define PCRM_PADOUT_PADOUT_AUX_1_POS                                                                     (21UL)
#define PCRM_PADOUT_PADOUT_AUX_1_MASK                                                                    (0x00200000UL)  /**< 21-Output Value for AUX_1*/
#define PCRM_PADOUT_PADOUT_GPIO5_POS                                                                     (20UL)
#define PCRM_PADOUT_PADOUT_GPIO5_MASK                                                                    (0x00100000UL)  /**< 20-Output Value for GPIO5*/
#define PCRM_PADOUT_PADOUT_GPIO4_POS                                                                     (19UL)
#define PCRM_PADOUT_PADOUT_GPIO4_MASK                                                                    (0x00080000UL)  /**< 19-Output Value for GPIO4*/
#define PCRM_PADOUT_PADOUT_I2CM_SCL_POS                                                                  (18UL)
#define PCRM_PADOUT_PADOUT_I2CM_SCL_MASK                                                                 (0x00040000UL)  /**< 18-Output Value for I2CM_SCL*/
#define PCRM_PADOUT_PADOUT_I2CM_SDA_POS                                                                  (17UL)
#define PCRM_PADOUT_PADOUT_I2CM_SDA_MASK                                                                 (0x00020000UL)  /**< 17-Output Value for I2CM_SDA*/
#define PCRM_PADOUT_PADOUT_SPIM_SSN_POS                                                                  (16UL)
#define PCRM_PADOUT_PADOUT_SPIM_SSN_MASK                                                                 (0x00010000UL)  /**< 16-Output Value for SPIM_SSN*/
#define PCRM_PADOUT_PADOUT_SPIM_SCLK_POS                                                                 (15UL)
#define PCRM_PADOUT_PADOUT_SPIM_SCLK_MASK                                                                (0x00008000UL)  /**< 15-Output Value for SPIM_SCLK*/
#define PCRM_PADOUT_PADOUT_SPIM_MOSI_POS                                                                 (14UL)
#define PCRM_PADOUT_PADOUT_SPIM_MOSI_MASK                                                                (0x00004000UL)  /**< 14-Output Value for SPIM_MOSI*/
#define PCRM_PADOUT_PADOUT_SPIM_MISO_POS                                                                 (13UL)
#define PCRM_PADOUT_PADOUT_SPIM_MISO_MASK                                                                (0x00002000UL)  /**< 13-Output Value for SPIM_MISO*/
#define PCRM_PADOUT_PADOUT_AUX_3_POS                                                                     (12UL)
#define PCRM_PADOUT_PADOUT_AUX_3_MASK                                                                    (0x00001000UL)  /**< 12-Output Value for AUX_3*/
#define PCRM_PADOUT_RESERVED2_POS                                                                         (10UL)
#define PCRM_PADOUT_RESERVED2_MASK                                                                        (0x00000C00UL)  /**< 10-reserved*/
#define PCRM_PADOUT_PADOUT_DWL_REQ_POS                                                                   (9UL)
#define PCRM_PADOUT_PADOUT_DWL_REQ_MASK                                                                  (0x00000200UL)  /**< 9-Output Value for DWL_REQ*/
#define PCRM_PADOUT_PADOUT_IRQ_POS                                                                       (8UL)
#define PCRM_PADOUT_PADOUT_IRQ_MASK                                                                      (0x00000100UL)  /**< 8-Output Value for IRQ*/
#define PCRM_PADOUT_PADOUT_ATX_D_POS                                                                     (7UL)
#define PCRM_PADOUT_PADOUT_ATX_D_MASK                                                                    (0x00000080UL)  /**< 7-Output Value for HSU_TX (also i2c_adr1 or spi_mosi)*/
#define PCRM_PADOUT_PADOUT_ATX_A_POS                                                                     (6UL)
#define PCRM_PADOUT_PADOUT_ATX_A_MASK                                                                    (0x00000040UL)  /**< 6-Output Value for HSU_RX (also i2c_sda or spi_miso)*/
#define PCRM_PADOUT_PADOUT_ATX_C_POS                                                                     (5UL)
#define PCRM_PADOUT_PADOUT_ATX_C_MASK                                                                    (0x00000020UL)  /**< 5-Output Value for HSU_RTS (also i2c_adr0 or spi_nss)*/
#define PCRM_PADOUT_PADOUT_ATX_B_POS                                                                     (4UL)
#define PCRM_PADOUT_PADOUT_ATX_B_MASK                                                                    (0x00000010UL)  /**< 4-Output Value for HSU_CTS (also i2c_scl or spi_sck)*/
#define PCRM_PADOUT_PADOUT_GPIO3_POS                                                                     (3UL)
#define PCRM_PADOUT_PADOUT_GPIO3_MASK                                                                    (0x00000008UL)  /**< 3-Output Value for GPIO3*/
#define PCRM_PADOUT_PADOUT_GPIO2_POS                                                                     (2UL)
#define PCRM_PADOUT_PADOUT_GPIO2_MASK                                                                    (0x00000004UL)  /**< 2-Output Value for GPIO2*/
#define PCRM_PADOUT_PADOUT_GPIO1_POS                                                                     (1UL)
#define PCRM_PADOUT_PADOUT_GPIO1_MASK                                                                    (0x00000002UL)  /**< 1-Output Value for GPIO1*/
#define PCRM_PADOUT_PADOUT_GPIO0_POS                                                                     (0UL)
#define PCRM_PADOUT_PADOUT_GPIO0_MASK                                                                    (0x00000001UL)  /**< 0-Output Value for GPIO0*/
#define PCRM_PADOUT__RESET_VALUE                                                                         (0x000000F0UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_padin
* <b>Reset value:</b> 0x00000400
* <b>Access:</b> r-
* @{
*/
#define PCRM_PADIN                                                                                        0xBC
#define PCRM_PADIN_R                                                                                        0xBC
#define PCRM_PADIN_RESERVED_POS                                                                          (27UL)
#define PCRM_PADIN_RESERVED_MASK                                                                         (0xF8000000UL)  /**< 27-reserved*/
#define PCRM_PADIN_PADIN_INT_AUX_POS                                                                     (26UL)
#define PCRM_PADIN_PADIN_INT_AUX_MASK                                                                    (0x04000000UL)  /**< 26-Input Value for CT_AUX_INT*/
#define PCRM_PADIN_PADIN_CLK_AUX_POS                                                                     (25UL)
#define PCRM_PADIN_PADIN_CLK_AUX_MASK                                                                    (0x02000000UL)  /**< 25-Input Value for CT_AUX_CLK*/
#define PCRM_PADIN_PADIN_IO_AUX_POS                                                                      (24UL)
#define PCRM_PADIN_PADIN_IO_AUX_MASK                                                                     (0x01000000UL)  /**< 24-Input Value for CT_AUX_IO*/
#define PCRM_PADIN_PADIN_TEST_POS                                                                        (23UL)
#define PCRM_PADIN_PADIN_TEST_MASK                                                                       (0x00800000UL)  /**< 23-Input Value for TEST*/
#define PCRM_PADIN_PADIN_AUX_2_POS                                                                       (22UL)
#define PCRM_PADIN_PADIN_AUX_2_MASK                                                                      (0x00400000UL)  /**< 22-Input Value for AUX_2*/
#define PCRM_PADIN_PADIN_AUX_1_POS                                                                       (21UL)
#define PCRM_PADIN_PADIN_AUX_1_MASK                                                                      (0x00200000UL)  /**< 21-Input Value for AUX_1*/
#define PCRM_PADIN_PADIN_GPIO5_POS                                                                       (20UL)
#define PCRM_PADIN_PADIN_GPIO5_MASK                                                                      (0x00100000UL)  /**< 20-Input Value for GPIO5*/
#define PCRM_PADIN_PADIN_GPIO4_POS                                                                       (19UL)
#define PCRM_PADIN_PADIN_GPIO4_MASK                                                                      (0x00080000UL)  /**< 19-Input Value for GPIO4*/
#define PCRM_PADIN_PADIN_I2CM_SCL_POS                                                                    (18UL)
#define PCRM_PADIN_PADIN_I2CM_SCL_MASK                                                                   (0x00040000UL)  /**< 18-Input Value for I2CM_SCL*/
#define PCRM_PADIN_PADIN_I2CM_SDA_POS                                                                    (17UL)
#define PCRM_PADIN_PADIN_I2CM_SDA_MASK                                                                   (0x00020000UL)  /**< 17-Input Value for I2CM_SDA*/
#define PCRM_PADIN_PADIN_SPIM_SSN_POS                                                                    (16UL)
#define PCRM_PADIN_PADIN_SPIM_SSN_MASK                                                                   (0x00010000UL)  /**< 16-Input Value for SPIM_SSN*/
#define PCRM_PADIN_PADIN_SPIM_SCLK_POS                                                                   (15UL)
#define PCRM_PADIN_PADIN_SPIM_SCLK_MASK                                                                  (0x00008000UL)  /**< 15-Input Value for SPIM_SCLK*/
#define PCRM_PADIN_PADIN_SPIM_MOSI_POS                                                                   (14UL)
#define PCRM_PADIN_PADIN_SPIM_MOSI_MASK                                                                  (0x00004000UL)  /**< 14-Input Value for SPIM_MOSI*/
#define PCRM_PADIN_PADIN_SPIM_MISO_POS                                                                   (13UL)
#define PCRM_PADIN_PADIN_SPIM_MISO_MASK                                                                  (0x00002000UL)  /**< 13-Input Value for SPIM_MISO*/
#define PCRM_PADIN_PADIN_AUX_3_POS                                                                       (12UL)
#define PCRM_PADIN_PADIN_AUX_3_MASK                                                                      (0x00001000UL)  /**< 12-Input Value for AUX_3*/
#define PCRM_PADIN_PADIN_HOSTIF_SEL1_POS                                                                 (11UL)
#define PCRM_PADIN_PADIN_HOSTIF_SEL1_MASK                                                                (0x00000800UL)  /**< 11-Input Value for HOSTIF_SEL1*/
#define PCRM_PADIN_PADIN_HOSTIF_SEL0_POS                                                                 (10UL)
#define PCRM_PADIN_PADIN_HOSTIF_SEL0_MASK                                                                (0x00000400UL)  /**< 10-Input Value for HOSTIF_SEL0*/
#define PCRM_PADIN_PADIN_DWL_REQ_POS                                                                     (9UL)
#define PCRM_PADIN_PADIN_DWL_REQ_MASK                                                                    (0x00000200UL)  /**< 9-Input Value for DWL_REQ*/
#define PCRM_PADIN_PADIN_IRQ_POS                                                                         (8UL)
#define PCRM_PADIN_PADIN_IRQ_MASK                                                                        (0x00000100UL)  /**< 8-Input Value for IRQ*/
#define PCRM_PADIN_PADIN_ATX_D_POS                                                                       (7UL)
#define PCRM_PADIN_PADIN_ATX_D_MASK                                                                      (0x00000080UL)  /**< 7-Input Value for HSU_TX (also i2c_adr1 or spi_mosi)*/
#define PCRM_PADIN_PADIN_ATX_A_POS                                                                       (6UL)
#define PCRM_PADIN_PADIN_ATX_A_MASK                                                                      (0x00000040UL)  /**< 6-Input Value for HSU_RX (also i2c_sda or spi_miso)*/
#define PCRM_PADIN_PADIN_ATX_C_POS                                                                       (5UL)
#define PCRM_PADIN_PADIN_ATX_C_MASK                                                                      (0x00000020UL)  /**< 5-Input Value for HSU_RTS (also i2c_adr0 or spi_nss)*/
#define PCRM_PADIN_PADIN_ATX_B_POS                                                                       (4UL)
#define PCRM_PADIN_PADIN_ATX_B_MASK                                                                      (0x00000010UL)  /**< 4-Input Value for HSU_CTS (also i2c_scl or spi_sck)*/
#define PCRM_PADIN_PADIN_GPIO3_POS                                                                       (3UL)
#define PCRM_PADIN_PADIN_GPIO3_MASK                                                                      (0x00000008UL)  /**< 3-Input Value for GPIO3*/
#define PCRM_PADIN_PADIN_GPIO2_POS                                                                       (2UL)
#define PCRM_PADIN_PADIN_GPIO2_MASK                                                                      (0x00000004UL)  /**< 2-Input Value for GPIO2*/
#define PCRM_PADIN_PADIN_GPIO1_POS                                                                       (1UL)
#define PCRM_PADIN_PADIN_GPIO1_MASK                                                                      (0x00000002UL)  /**< 1-Input Value for GPIO1*/
#define PCRM_PADIN_PADIN_GPIO0_POS                                                                       (0UL)
#define PCRM_PADIN_PADIN_GPIO0_MASK                                                                      (0x00000001UL)  /**< 0-Input Value for GPIO0*/
#define PCRM_PADIN__RESET_VALUE                                                                           (0x00000400UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_gpreg7
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_GPREG7                                                                                       0xBD
#define PCRM_GPREG7_R                                                                                       0xBD
#define PCRM_GPREG7_W                                                                                       0xBD
#define PCRM_GPREG7_PCRM_GPREG7_POS                                                                      (0UL)
#define PCRM_GPREG7_PCRM_GPREG7_MASK                                                                     (0xFFFFFFFFUL)  /**< 0- General Purpose Register 7 for SW*/
#define PCRM_GPREG7__RESET_VALUE                                                                          (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_gpreg6
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_GPREG6                                                                                       0xBE
#define PCRM_GPREG6_R                                                                                       0xBE
#define PCRM_GPREG6_W                                                                                       0xBE
#define PCRM_GPREG6_PCRM_GPREG6_POS                                                                      (0UL)
#define PCRM_GPREG6_PCRM_GPREG6_MASK                                                                     (0xFFFFFFFFUL)  /**< 0- General Purpose Register 6 for SW*/
#define PCRM_GPREG6__RESET_VALUE                                                                          (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_gpreg5
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_GPREG5                                                                                       0xBF
#define PCRM_GPREG5_R                                                                                       0xBF
#define PCRM_GPREG5_W                                                                                       0xBF
#define PCRM_GPREG5_PCRM_GPREG5_POS                                                                      (0UL)
#define PCRM_GPREG5_PCRM_GPREG5_MASK                                                                     (0xFFFFFFFFUL)  /**< 0- General Purpose Register 5 for SW*/
#define PCRM_GPREG5__RESET_VALUE                                                                          (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_gpreg4
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_GPREG4                                                                                       0xC0
#define PCRM_GPREG4_R                                                                                       0xC0
#define PCRM_GPREG4_W                                                                                       0xC0
#define PCRM_GPREG4_PCRM_GPREG4_POS                                                                      (0UL)
#define PCRM_GPREG4_PCRM_GPREG4_MASK                                                                     (0xFFFFFFFFUL)  /**< 0- General Purpose Register 4 for SW*/
#define PCRM_GPREG4__RESET_VALUE                                                                          (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_gpreg3
* <b>Reset value:</b> 0x00000706
* <b>Access:</b> rw
* @{
*/
#define PCRM_GPREG3                                                                                       0xC1
#define PCRM_GPREG3_R                                                                                       0xC1
#define PCRM_GPREG3_W                                                                                       0xC1
#define PCRM_GPREG3_PCRM_GPREG3_POS                                                                      (0UL)
#define PCRM_GPREG3_PCRM_GPREG3_MASK                                                                     (0xFFFFFFFFUL)  /**< 0- General Purpose Register 3 for SW*/
#define PCRM_GPREG3__RESET_VALUE                                                                          (0x00000706UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_clif_ana_tx_standby
* <b>Reset value:</b> 0x009FFFFF
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_ANA_TX_STANDBY                                                                          0xC2
#define PCRM_CLIF_ANA_TX_STANDBY_R                                                                          0xC2
#define PCRM_CLIF_ANA_TX_STANDBY_W                                                                          0xC2
#define PCRM_CLIF_ANA_TX_STANDBY_RESERVED_POS                                                            (31UL)
#define PCRM_CLIF_ANA_TX_STANDBY_RESERVED_MASK                                                           (0x80000000UL)  /**< 31-reserved*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_RESTART_POS                                                          (30UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_RESTART_MASK                                                         (0x40000000UL)  /**< 30-Clears TX_SHUTDOWN flag*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SHUTDOWN_POS                                                         (29UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SHUTDOWN_MASK                                                        (0x20000000UL)  /**< 29-Shutdown of Power Amplifier due to overcurrent detection*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_PROT_DISABLE_POS                                                     (28UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_PROT_DISABLE_MASK                                                    (0x10000000UL)  /**< 28-disable signal for the TX protection circuitry*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_EN_POS                                                               (27UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_EN_MASK                                                              (0x08000000UL)  /**< 27-Main enable signal for the TX section*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_GS_SRC_SEL_POS                                                       (26UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_GS_SRC_SEL_MASK                                                      (0x04000000UL)  /**< 26-Source of GSN value (0: PCRM; 1: CLIF digital)*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_CLK_MODE_TX2_POS                                                     (23UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_CLK_MODE_TX2_MASK                                                    (0x03800000UL)  /**< 23-selects how the TX_SET_GS are controlled; HIGHZ is 000*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_CLK_MODE_TX1_POS                                                     (20UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_CLK_MODE_TX1_MASK                                                    (0x00700000UL)  /**< 20-selects how the TX_SET_GS are controlled; HIGHZ is 000*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_P_TX2_POS                                                     (15UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_P_TX2_MASK                                                    (0x000F8000UL)  /**< 15-GSP Value to be applied suring NFC_STBY power state to TX2 driver; sits here because these are VHV controls*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_P_TX1_POS                                                     (10UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_P_TX1_MASK                                                    (0x00007C00UL)  /**< 10-GSP Value to be applied suring NFC_STBY power state to TX1 driver; sits here because these are VHV controls*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_N_TX2_POS                                                     (5UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_N_TX2_MASK                                                    (0x000003E0UL)  /**< 5-GSN Value to be applied suring NFC_STBY power state to TX2 driver*/
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_N_TX1_POS                                                     (0UL)
#define PCRM_CLIF_ANA_TX_STANDBY_TX_SET_GS_N_TX1_MASK                                                    (0x0000001FUL)  /**< 0-GSN Value to be applied suring NFC_STBY power state to TX1 driver*/
#define PCRM_CLIF_ANA_TX_STANDBY__RESET_VALUE                                                         (0x009FFFFFUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_lp_clk_en
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_LP_CLK_EN                                                                                0xC3
#define PCRM_SYS_LP_CLK_EN_R                                                                                0xC3
#define PCRM_SYS_LP_CLK_EN_W                                                                                0xC3
#define PCRM_SYS_LP_CLK_EN_RESERVED_POS                                                                  (2UL)
#define PCRM_SYS_LP_CLK_EN_RESERVED_MASK                                                                 (0xFFFFFFFCUL)  /**< 2-reserved*/
#define PCRM_SYS_LP_CLK_EN_RECOVERY_CLK_ENABLE_POS                                                       (1UL)
#define PCRM_SYS_LP_CLK_EN_RECOVERY_CLK_ENABLE_MASK                                                      (0x00000002UL)  /**< 1-Enables clock source for recovery logic; will be also manage by FSM*/
#define PCRM_SYS_LP_CLK_EN_LFO_WUC_CLK_ENABLE_POS                                                        (0UL)
#define PCRM_SYS_LP_CLK_EN_LFO_WUC_CLK_ENABLE_MASK                                                       (0x00000001UL)  /**< 0-Enables clock source for WUC  */
#define PCRM_SYS_LP_CLK_EN__RESET_VALUE                                                            (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_boot3_sts
* <b>Reset value:</b> 0x00000071
* <b>Access:</b> r-
* @{
*/
#define PCRM_SYS_BOOT3_STS                                                                                0xC4
#define PCRM_SYS_BOOT3_STS_R                                                                                0xC4
#define PCRM_SYS_BOOT3_STS_RESERVED_POS                                                                  (7UL)
#define PCRM_SYS_BOOT3_STS_RESERVED_MASK                                                                 (0xFFFFFF80UL)  /**< 7-reserved*/
#define PCRM_SYS_BOOT3_STS_RST_STS_NFC_POS                                                               (6UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_NFC_MASK                                                              (0x00000040UL)  /**< 6-Reset source reason NFC SW Reset*/
#define PCRM_SYS_BOOT3_STS_RST_STS_FSM_POS                                                               (5UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_FSM_MASK                                                              (0x00000020UL)  /**< 5-Reset source reason PMU FSM*/
#define PCRM_SYS_BOOT3_STS_RST_STS_CMD_POS                                                               (4UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_CMD_MASK                                                              (0x00000010UL)  /**< 4-Reset source reason VEN CMD*/
#define PCRM_SYS_BOOT3_STS_RST_STS_WDG_POS                                                               (3UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_WDG_MASK                                                              (0x00000008UL)  /**< 3-Reset source reason Watchdog*/
#define PCRM_SYS_BOOT3_STS_RESERVED1_POS                                                               (2UL)
#define PCRM_SYS_BOOT3_STS_RESERVED1_MASK                                                              (0x00000004UL)  /**< 2-reserved*/
#define PCRM_SYS_BOOT3_STS_RST_STS_HOST_POS                                                              (1UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_HOST_MASK                                                             (0x00000002UL)  /**< 1-Reset source reason host command*/
#define PCRM_SYS_BOOT3_STS_RST_STS_CPU_POS                                                               (0UL)
#define PCRM_SYS_BOOT3_STS_RST_STS_CPU_MASK                                                              (0x00000001UL)  /**< 0-Reset source reason cpu command*/
#define PCRM_SYS_BOOT3_STS__RESET_VALUE                                                                   (0x00000071UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_boot2_sts
* <b>Reset value:</b> 0x03FFFCDE
* <b>Access:</b> r-
* @{
*/
#define PCRM_SYS_BOOT2_STS                                                                                0xC5
#define PCRM_SYS_BOOT2_STS_R                                                                                0xC5
#define PCRM_SYS_BOOT2_STS_RESERVED_POS                                                                  (26UL)
#define PCRM_SYS_BOOT2_STS_RESERVED_MASK                                                                 (0xFC000000UL)  /**< 26-reserved*/
#define PCRM_SYS_BOOT2_STS_PREV_USB_POS                                                                  (25UL)
#define PCRM_SYS_BOOT2_STS_PREV_USB_MASK                                                                 (0x02000000UL)  /**< 25-SUSPEND  Prevention Reason, Note: USB prevention is not applicable for standby mode*/
#define PCRM_SYS_BOOT2_STS_PREV_TEMP_POS                                                                 (24UL)
#define PCRM_SYS_BOOT2_STS_PREV_TEMP_MASK                                                                (0x01000000UL)  /**< 24-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_CTAUX_POS                                                                (23UL)
#define PCRM_SYS_BOOT2_STS_PREV_CTAUX_MASK                                                               (0x00800000UL)  /**< 23-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_HOSTCOMM_POS                                                             (22UL)
#define PCRM_SYS_BOOT2_STS_PREV_HOSTCOMM_MASK                                                            (0x00400000UL)  /**< 22-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_SPI_POS                                                                  (21UL)
#define PCRM_SYS_BOOT2_STS_PREV_SPI_MASK                                                                 (0x00200000UL)  /**< 21-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_I2C_POS                                                                  (20UL)
#define PCRM_SYS_BOOT2_STS_PREV_I2C_MASK                                                                 (0x00100000UL)  /**< 20-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_I3C_POS                                                                  (19UL)
#define PCRM_SYS_BOOT2_STS_PREV_I3C_MASK                                                                 (0x00080000UL)  /**< 19-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_HSU_POS                                                                  (18UL)
#define PCRM_SYS_BOOT2_STS_PREV_HSU_MASK                                                                 (0x00040000UL)  /**< 18-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_GPIO3_POS                                                                (17UL)
#define PCRM_SYS_BOOT2_STS_PREV_GPIO3_MASK                                                               (0x00020000UL)  /**< 17-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_GPIO2_POS                                                                (16UL)
#define PCRM_SYS_BOOT2_STS_PREV_GPIO2_MASK                                                               (0x00010000UL)  /**< 16-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_GPIO1_POS                                                                (15UL)
#define PCRM_SYS_BOOT2_STS_PREV_GPIO1_MASK                                                               (0x00008000UL)  /**< 15-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_GPIO0_POS                                                                (14UL)
#define PCRM_SYS_BOOT2_STS_PREV_GPIO0_MASK                                                               (0x00004000UL)  /**< 14-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_WUC_POS                                                                  (13UL)
#define PCRM_SYS_BOOT2_STS_PREV_WUC_MASK                                                                 (0x00002000UL)  /**< 13-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_LPDET_POS                                                                (12UL)
#define PCRM_SYS_BOOT2_STS_PREV_LPDET_MASK                                                               (0x00001000UL)  /**< 12-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_RX_ULPDET_POS                                                            (11UL)
#define PCRM_SYS_BOOT2_STS_PREV_RX_ULPDET_MASK                                                           (0x00000800UL)  /**< 11-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_INT_NO_VDDIO_POS                                                         (10UL)
#define PCRM_SYS_BOOT2_STS_PREV_INT_NO_VDDIO_MASK                                                        (0x00000400UL)  /**< 10-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_RESERVED1_POS                                                                  (9UL)
#define PCRM_SYS_BOOT2_STS_RESERVED1_MASK                                                                 (0x00000200UL)  /**< 9-reserved*/
#define PCRM_SYS_BOOT2_STS_RESERVED2_POS                                                                  (8UL)
#define PCRM_SYS_BOOT2_STS_RESERVED2_MASK                                                                 (0x00000100UL)  /**< 8-reserved*/
#define PCRM_SYS_BOOT2_STS_PREV_PVDDLDO_OVERCURRENT_POS                                                  (7UL)
#define PCRM_SYS_BOOT2_STS_PREV_PVDDLDO_OVERCURRENT_MASK                                                 (0x00000080UL)  /**< 7-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_INTERFACE_POS                                                            (6UL)
#define PCRM_SYS_BOOT2_STS_PREV_INTERFACE_MASK                                                           (0x00000040UL)  /**< 6-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_RESERVED3_POS                                                                  (5UL)
#define PCRM_SYS_BOOT2_STS_RESERVED3_MASK                                                                 (0x00000020UL)  /**< 5-reserved*/
#define PCRM_SYS_BOOT2_STS_PREV_VDDIO_LOSS_POS                                                           (4UL)
#define PCRM_SYS_BOOT2_STS_PREV_VDDIO_LOSS_MASK                                                          (0x00000010UL)  /**< 4-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_VDDIO_START_POS                                                          (3UL)
#define PCRM_SYS_BOOT2_STS_PREV_VDDIO_START_MASK                                                         (0x00000008UL)  /**< 3-Standby/Suspend  Prevention Reason, indicates VDDIO is already available and standby is prevented*/
#define PCRM_SYS_BOOT2_STS_PREV_NOENABLE_POS                                                             (2UL)
#define PCRM_SYS_BOOT2_STS_PREV_NOENABLE_MASK                                                            (0x00000004UL)  /**< 2-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_VUPDET_POS                                                               (1UL)
#define PCRM_SYS_BOOT2_STS_PREV_VUPDET_MASK                                                              (0x00000002UL)  /**< 1-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS_PREV_RXPROT_POS                                                               (0UL)
#define PCRM_SYS_BOOT2_STS_PREV_RXPROT_MASK                                                              (0x00000001UL)  /**< 0-Standby/Suspend  Prevention Reason*/
#define PCRM_SYS_BOOT2_STS__RESET_VALUE                                                                   (0x03FFFCDEUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_boot1_sts
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define PCRM_SYS_BOOT1_STS                                                                                0xC6
#define PCRM_SYS_BOOT1_STS_R                                                                                0xC6
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_XTAL_TIMEOUT_POS                                                   (31UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_XTAL_TIMEOUT_MASK                                                  (0x80000000UL)  /**< 31-ULPCD exit due to XTAL timeout*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CLKDET_ERROR_POS                                                   (30UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CLKDET_ERROR_MASK                                                  (0x40000000UL)  /**< 30-ULPCD CLK_DET error*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CARD_DETECT_POS                                                    (29UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CARD_DETECT_MASK                                                   (0x20000000UL)  /**< 29-ULPCD card detect*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CALIBRATION_DONE_POS                                               (28UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_CALIBRATION_DONE_MASK                                              (0x10000000UL)  /**< 28-ULPCD calibration complete*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_GPIO_ABORT_POS                                                     (27UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_GPIO_ABORT_MASK                                                    (0x08000000UL)  /**< 27-ULPCD GPIO Abort*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULP_STANDBY_POS                                                          (26UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULP_STANDBY_MASK                                                         (0x04000000UL)  /**< 26-ULPCD Standby*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_LDO_VDDPA_OVERCURRENT_POS                                          (25UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_LDO_VDDPA_OVERCURRENT_MASK                                         (0x02000000UL)  /**< 25-ULPCD LDO VDDPA overcurrent*/
#define PCRM_SYS_BOOT1_STS_BOOT_USB_POS                                                                  (24UL)
#define PCRM_SYS_BOOT1_STS_BOOT_USB_MASK                                                                 (0x01000000UL)  /**< 24-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_CTAUX_POS                                                                (23UL)
#define PCRM_SYS_BOOT1_STS_BOOT_CTAUX_MASK                                                               (0x00800000UL)  /**< 23-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_RX_ULPDET_POS                                                      (22UL)
#define PCRM_SYS_BOOT1_STS_BOOT_ULPCD_RX_ULPDET_MASK                                                     (0x00400000UL)  /**< 22-RX ULPDET resulted in boot in ULPCD mode*/
#define PCRM_SYS_BOOT1_STS_WAKEUP_RX_ULP_POS                                                             (21UL)
#define PCRM_SYS_BOOT1_STS_WAKEUP_RX_ULP_MASK                                                            (0x00200000UL)  /**< 21-Indicates if VEN is masked due to  wakeup with rx_ulp. This bit is cleared with ULPDET_WKUP_VEN_MASK_CLR*/
#define PCRM_SYS_BOOT1_STS_BOOT_SPI_POS                                                                  (20UL)
#define PCRM_SYS_BOOT1_STS_BOOT_SPI_MASK                                                                 (0x00100000UL)  /**< 20-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_I2C_POS                                                                  (19UL)
#define PCRM_SYS_BOOT1_STS_BOOT_I2C_MASK                                                                 (0x00080000UL)  /**< 19-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_I3C_POS                                                                  (18UL)
#define PCRM_SYS_BOOT1_STS_BOOT_I3C_MASK                                                                 (0x00040000UL)  /**< 18-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_HSU_POS                                                                  (17UL)
#define PCRM_SYS_BOOT1_STS_BOOT_HSU_MASK                                                                 (0x00020000UL)  /**< 17-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO3_POS                                                                (16UL)
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO3_MASK                                                               (0x00010000UL)  /**< 16-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO2_POS                                                                (15UL)
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO2_MASK                                                               (0x00008000UL)  /**< 15-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO1_POS                                                                (14UL)
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO1_MASK                                                               (0x00004000UL)  /**< 14-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO0_POS                                                                (13UL)
#define PCRM_SYS_BOOT1_STS_BOOT_GPIO0_MASK                                                               (0x00002000UL)  /**< 13-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_LPDET_POS                                                                (12UL)
#define PCRM_SYS_BOOT1_STS_BOOT_LPDET_MASK                                                               (0x00001000UL)  /**< 12-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_RX_ULPDET_POS                                                            (11UL)
#define PCRM_SYS_BOOT1_STS_BOOT_RX_ULPDET_MASK                                                           (0x00000800UL)  /**< 11-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_RESERVED_POS                                                                  (10UL)
#define PCRM_SYS_BOOT1_STS_RESERVED_MASK                                                                 (0x00000400UL)  /**< 10-reserved*/
#define PCRM_SYS_BOOT1_STS_RESERVED1_POS                                                                  (9UL)
#define PCRM_SYS_BOOT1_STS_RESERVED1_MASK                                                                 (0x00000200UL)  /**< 9-reserved*/
#define PCRM_SYS_BOOT1_STS_RESERVED2_POS                                                                  (8UL)
#define PCRM_SYS_BOOT1_STS_RESERVED2_MASK                                                                 (0x00000100UL)  /**< 8-reserved*/
#define PCRM_SYS_BOOT1_STS_BOOT_PVDDLDO_OVERCURRENT_POS                                                  (7UL)
#define PCRM_SYS_BOOT1_STS_BOOT_PVDDLDO_OVERCURRENT_MASK                                                 (0x00000080UL)  /**< 7-Bootup Reason */
#define PCRM_SYS_BOOT1_STS_BOOT_VDDIO_LOSS_POS                                                           (6UL)
#define PCRM_SYS_BOOT1_STS_BOOT_VDDIO_LOSS_MASK                                                          (0x00000040UL)  /**< 6-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_VDDIO_START_POS                                                          (5UL)
#define PCRM_SYS_BOOT1_STS_BOOT_VDDIO_START_MASK                                                         (0x00000020UL)  /**< 5-Bootup Reason this is valid if STBY/SUSPEND entered with VDDIO LOSS*/
#define PCRM_SYS_BOOT1_STS_BOOT_WUC_POS                                                                  (4UL)
#define PCRM_SYS_BOOT1_STS_BOOT_WUC_MASK                                                                 (0x00000010UL)  /**< 4-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_TEMP_POS                                                                 (3UL)
#define PCRM_SYS_BOOT1_STS_BOOT_TEMP_MASK                                                                (0x00000008UL)  /**< 3-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_VUPDET_POS                                                               (2UL)
#define PCRM_SYS_BOOT1_STS_BOOT_VUPDET_MASK                                                              (0x00000004UL)  /**< 2-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_RXPROT_POS                                                               (1UL)
#define PCRM_SYS_BOOT1_STS_BOOT_RXPROT_MASK                                                              (0x00000002UL)  /**< 1-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS_BOOT_POR_POS                                                                  (0UL)
#define PCRM_SYS_BOOT1_STS_BOOT_POR_MASK                                                                 (0x00000001UL)  /**< 0-Bootup Reason*/
#define PCRM_SYS_BOOT1_STS__RESET_VALUE                                                                      (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_stby1_ctrl
* <b>Reset value:</b> 0x00020000
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_STBY1_CTRL                                                                               0xC7
#define PCRM_SYS_STBY1_CTRL_R                                                                               0xC7
#define PCRM_SYS_STBY1_CTRL_W                                                                               0xC7
#define PCRM_SYS_STBY1_CTRL_RESERVED_POS                                                                 (23UL)
#define PCRM_SYS_STBY1_CTRL_RESERVED_MASK                                                                (0xFF800000UL)  /**< 23-reserved*/
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO0_POLARITY_POS                                                      (22UL)
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO0_POLARITY_MASK                                                     (0x00400000UL)  /**< 22-Standby/Suspend Wakeup polarity configuration 0: default active  high , 1: active low */
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO1_POLARITY_POS                                                      (21UL)
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO1_POLARITY_MASK                                                     (0x00200000UL)  /**< 21-Standby/Suspend Wakeup polarity configuration 0: default active  high , 1: active low */
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO2_POLARITY_POS                                                      (20UL)
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO2_POLARITY_MASK                                                     (0x00100000UL)  /**< 20-Standby/Suspend Wakeup polarity configuration 0: default active  high , 1: active low */
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO3_POLARITY_POS                                                      (19UL)
#define PCRM_SYS_STBY1_CTRL_STBY_GPIO3_POLARITY_MASK                                                     (0x00080000UL)  /**< 19-Standby/Suspend Wakeup polarity configuration 0: default active  high , 1: active low */
#define PCRM_SYS_STBY1_CTRL_STBY_VOLT_POS                                                                (17UL)
#define PCRM_SYS_STBY1_CTRL_STBY_VOLT_MASK                                                               (0x00060000UL)  /**< 17-Select Voltage in standby and hard power down mode : 00 = 1V1 ; 01 = 1V0; 10 = 0V9 ; 11 = 0V9*/
#define PCRM_SYS_STBY1_CTRL_CLR_RST_STS_POS                                                              (16UL)
#define PCRM_SYS_STBY1_CTRL_CLR_RST_STS_MASK                                                             (0x00010000UL)  /**< 16-Clears Reset reason status register values in PCRM_SYS_BOOT3_STS_REG*/
#define PCRM_SYS_STBY1_CTRL_WUC_VALUE_POS                                                                (6UL)
#define PCRM_SYS_STBY1_CTRL_WUC_VALUE_MASK                                                               (0x0000FFC0UL)  /**< 6-Wakeup Timer count down Value (10 bits counter; LFO CLK / 1024 = 371Hz.)*/
#define PCRM_SYS_STBY1_CTRL_RESERVED1_POS                                                                 (4UL)
#define PCRM_SYS_STBY1_CTRL_RESERVED1_MASK                                                                (0x00000030UL)  /**< 4-reserved*/
#define PCRM_SYS_STBY1_CTRL_CLR_BOOT_REGS_POS                                                            (3UL)
#define PCRM_SYS_STBY1_CTRL_CLR_BOOT_REGS_MASK                                                           (0x00000008UL)  /**< 3-Clears STBY_PREV_REASON values in the PCRM_SYS_BOOT1_STS_REG and BOOT_REASON values and in PCRM_SYS_BOOT2_STS_REG*/
#define PCRM_SYS_STBY1_CTRL_RESERVED2_POS                                                                 (1UL)
#define PCRM_SYS_STBY1_CTRL_RESERVED2_MASK                                                                (0x00000006UL)  /**< 1-reserved*/
#define PCRM_SYS_STBY1_CTRL_STBY_REQ_WFI_POS                                                             (0UL)
#define PCRM_SYS_STBY1_CTRL_STBY_REQ_WFI_MASK                                                            (0x00000001UL)  /**< 0-standby entry with WFI*/
#define PCRM_SYS_STBY1_CTRL__RESET_VALUE                                                                 (0x00020000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_ulpcd_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_ULPCD_CTRL                                                                               0xC8
#define PCRM_SYS_ULPCD_CTRL_R                                                                               0xC8
#define PCRM_SYS_ULPCD_CTRL_W                                                                               0xC8
#define PCRM_SYS_ULPCD_CTRL_RESERVED_POS                                                                 (1UL)
#define PCRM_SYS_ULPCD_CTRL_RESERVED_MASK                                                                (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_SYS_ULPCD_CTRL_NFC_ULPCD_ENTRY_REQ_POS                                                      (0UL)
#define PCRM_SYS_ULPCD_CTRL_NFC_ULPCD_ENTRY_REQ_MASK                                                     (0x00000001UL)  /**< 0-NFC ULPCD Mode Entry Request (From NFC FW)*/
#define PCRM_SYS_ULPCD_CTRL__RESET_VALUE                                                          (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_stby_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_STBY_CTRL                                                                                0xC9
#define PCRM_SYS_STBY_CTRL_R                                                                                0xC9
#define PCRM_SYS_STBY_CTRL_W                                                                                0xC9
#define PCRM_SYS_STBY_CTRL_RESERVED_POS                                                                  (1UL)
#define PCRM_SYS_STBY_CTRL_RESERVED_MASK                                                                 (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_SYS_STBY_CTRL_NFC_STBY_ENTRY_REQ_POS                                                        (0UL)
#define PCRM_SYS_STBY_CTRL_NFC_STBY_ENTRY_REQ_MASK                                                       (0x00000001UL)  /**< 0-NFC Standby Mode Entry Request (From NFC FW)*/
#define PCRM_SYS_STBY_CTRL__RESET_VALUE                                                            (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_stby_cfg
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_SYS_STBY_CFG                                                                                 0xCA
#define PCRM_SYS_STBY_CFG_R                                                                                 0xCA
#define PCRM_SYS_STBY_CFG_W                                                                                 0xCA
#define PCRM_SYS_STBY_CFG_RESERVED_POS                                                                   (26UL)
#define PCRM_SYS_STBY_CFG_RESERVED_MASK                                                                  (0xFC000000UL)  /**< 26-reserved*/
#define PCRM_SYS_STBY_CFG_SUSPEND_EN_USB_POS                                                             (25UL)
#define PCRM_SYS_STBY_CFG_SUSPEND_EN_USB_MASK                                                            (0x02000000UL)  /**< 25-suspend mode enable with USB*/
#define PCRM_SYS_STBY_CFG_I23C_ADDR_POS                                                                  (18UL)
#define PCRM_SYS_STBY_CFG_I23C_ADDR_MASK                                                                 (0x01FC0000UL)  /**< 18-I2C I3C address for wakeup*/
#define PCRM_SYS_STBY_CFG_STBY_EN_VDDIO_START_POS                                                        (17UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_VDDIO_START_MASK                                                       (0x00020000UL)  /**< 17-Enables VDDIO start detect wakeup, Note: This bit and STBY_EN_VDDIO_LOSS is mutually exclusive */
#define PCRM_SYS_STBY_CFG_RESERVED1_POS                                                             (16UL)
#define PCRM_SYS_STBY_CFG_RESERVED1_MASK                                                           (0x00010000UL)  /**< 16-reserved*/
#define PCRM_SYS_STBY_CFG_STBY_EN_CTAUX_POS                                                              (15UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_CTAUX_MASK                                                             (0x00008000UL)  /**< 15-Enables CTAUX interface */
#define PCRM_SYS_STBY_CFG_STBY_EN_VDDIO_LOSS_POS                                                         (14UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_VDDIO_LOSS_MASK                                                        (0x00004000UL)  /**< 14-Enables VDDIO loss detect wakeup*/
#define PCRM_SYS_STBY_CFG_RESERVED2_POS                                                             (13UL)
#define PCRM_SYS_STBY_CFG_RESERVED2_MASK                                                            (0x00002000UL)  /**< 13-reserved*/
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO0_POS                                                              (12UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO0_MASK                                                             (0x00001000UL)  /**< 12-Enables GPIO0 wakeup */
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO1_POS                                                              (11UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO1_MASK                                                             (0x00000800UL)  /**< 11-Enables GPIO1 wakeup */
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO2_POS                                                              (10UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO2_MASK                                                             (0x00000400UL)  /**< 10-Enables GPIO2 wakeup */
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO3_POS                                                              (9UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_GPIO3_MASK                                                             (0x00000200UL)  /**< 9-Enables GPIO3 wakeup */
#define PCRM_SYS_STBY_CFG_RESERVED3_POS                                                                   (6UL)
#define PCRM_SYS_STBY_CFG_RESERVED3_MASK                                                                  (0x000001C0UL)  /**< 6-reserved*/
#define PCRM_SYS_STBY_CFG_STBY_EN_PVDDLDO_OVERCURRENT_POS                                                (5UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_PVDDLDO_OVERCURRENT_MASK                                               (0x00000020UL)  /**< 5-Enables PVDDLDO Overcurrent indication as wakeup reason*/
#define PCRM_SYS_STBY_CFG_STBY_EN_TEMP_POS                                                               (4UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_TEMP_MASK                                                              (0x00000010UL)  /**< 4-Enables Temperature variation wakeup*/
#define PCRM_SYS_STBY_CFG_STBY_EN_LPDET_POS                                                              (3UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_LPDET_MASK                                                             (0x00000008UL)  /**< 3-Enables RF Level Detector wakeup (LPDET based)*/
#define PCRM_SYS_STBY_CFG_STBY_EN_RF_ULPDET_POS                                                          (2UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_RF_ULPDET_MASK                                                         (0x00000004UL)  /**< 2-Enables RF Level Detector wakeup (ULPDET based)*/
#define PCRM_SYS_STBY_CFG_STBY_EN_HOSTIF_POS                                                             (1UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_HOSTIF_MASK                                                            (0x00000002UL)  /**< 1-Enables wakeup from Host Interface pin activity*/
#define PCRM_SYS_STBY_CFG_STBY_EN_WUC_POS                                                                (0UL)
#define PCRM_SYS_STBY_CFG_STBY_EN_WUC_MASK                                                               (0x00000001UL)  /**< 0-Enables Wakeup Timer wakeup*/
#define PCRM_SYS_STBY_CFG__RESET_VALUE                                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_clif_ana_agc_rxprot_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL                                                                     0xCB
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_R                                                                     0xCB
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_W                                                                     0xCB
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_RESERVED_POS                                                       (6UL)
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_RESERVED_MASK                                                      (0xFFFFF8C0UL)  /**< 6-reserved*/
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_RX_AGC_HFATT_CTRL_POS                                              (0UL)
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL_RX_AGC_HFATT_CTRL_MASK                                             (0x0000003FUL)  /**< 0-HF attenuator control in low power mode*/
#define PCRM_CLIF_ANA_AGC_RXPROT_CTRL__RESET_VALUE                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_lpdet_fsm_ctrl2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_LPDET_FSM_CTRL2                                                                              0xCC
#define PCRM_LPDET_FSM_CTRL2_R                                                                              0xCC
#define PCRM_LPDET_FSM_CTRL2_W                                                                              0xCC
#define PCRM_LPDET_FSM_CTRL2_RESERVED_POS                                                                (21UL)
#define PCRM_LPDET_FSM_CTRL2_RESERVED_MASK                                                               (0xFFE00000UL)  /**< 21-reserved*/
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_LIMIT_POS                                              (18UL)
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_LIMIT_MASK                                             (0x001C0000UL)  /**< 18-Clock recovery check time duration (counted in N+1 LFO clock cycle => reg=0 means 1 clock cycle) / max is 8 LFO cycles*/
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_MAX_POS                                                (9UL)
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_MAX_MASK                                               (0x0003FE00UL)  /**< 9-Maximum clock recovery counter value to enable wake-up from RF field (RFLD function) - based on carrier frequency*/
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_MIN_POS                                                (0UL)
#define PCRM_LPDET_FSM_CTRL2_LPDET_RECOVERY_COUNT_MIN_MASK                                               (0x000001FFUL)  /**< 0-Minimum clock recovery counter value to enable wake-up from RF field (RFLD function) - based on carrier frequency*/
#define PCRM_LPDET_FSM_CTRL2__RESET_VALUE                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_lpdet_fsm_ctrl1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_LPDET_FSM_CTRL1                                                                              0xCD
#define PCRM_LPDET_FSM_CTRL1_R                                                                              0xCD
#define PCRM_LPDET_FSM_CTRL1_W                                                                              0xCD
#define PCRM_LPDET_FSM_CTRL1_RESERVED_POS                                                                (31UL)
#define PCRM_LPDET_FSM_CTRL1_RESERVED_MASK                                                               (0x80000000UL)  /**< 31-reserved*/
#define PCRM_LPDET_FSM_CTRL1_BYPASS_LPDET_FSM_POS                                                        (30UL)
#define PCRM_LPDET_FSM_CTRL1_BYPASS_LPDET_FSM_MASK                                                       (0x40000000UL)  /**< 30-Bypass the LPDET_FSM control and allows to directly control LPDET from PCRM registers*/
#define PCRM_LPDET_FSM_CTRL1_RUN_LPDET_POS                                                               (29UL)
#define PCRM_LPDET_FSM_CTRL1_RUN_LPDET_MASK                                                              (0x20000000UL)  /**< 29-Run LPDET FSM in any power mode*/
#define PCRM_LPDET_FSM_CTRL1_VCM_COUNT_POS                                                               (27UL)
#define PCRM_LPDET_FSM_CTRL1_VCM_COUNT_MASK                                                              (0x18000000UL)  /**< 27-VCM LFO cycle count*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_FSM_EN_POS                                                            (26UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_FSM_EN_MASK                                                           (0x04000000UL)  /**< 26-Enables the LPDET_FSM to run constantly (used for RFLD function during polling loops) in Standby mode*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_ONESHOT_RUN_POS                                                       (25UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_ONESHOT_RUN_MASK                                                      (0x02000000UL)  /**< 25-Enables the LPDET module once (used for collision checks)*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_COUNT_MAX_POS                                                         (17UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_COUNT_MAX_MASK                                                        (0x01FE0000UL)  /**< 17-Maximum LPDET counter value to enable Clock recovery  frequency check - based on carrier frequency / 2*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_COUNT_MIN_POS                                                         (9UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_COUNT_MIN_MASK                                                        (0x0001FE00UL)  /**< 9-Minimum LPDET counter value to enable Clock recovery  frequency check - based on carrier frequency / 2*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_ADD_DELAY_EN_POS                                                      (8UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_ADD_DELAY_EN_MASK                                                     (0x00000100UL)  /**< 8-Minimum LPDET counter value to enable Clock recovery  frequency check - based on carrier frequency / 2*/
#define PCRM_LPDET_FSM_CTRL1_LPDET_T5_COUNT_POS                                                          (0UL)
#define PCRM_LPDET_FSM_CTRL1_LPDET_T5_COUNT_MASK                                                         (0x000000FFUL)  /**< 0-Defines the LPDET_FSM T5 (wait time)  min=1 / max=(to be reviewed)*/
#define PCRM_LPDET_FSM_CTRL1__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_clif_ana_xtal
* <b>Reset value:</b> 0x00000040
* <b>Access:</b> rw
* @{
*/
#define PCRM_CLIF_ANA_XTAL                                                                                0xCE
#define PCRM_CLIF_ANA_XTAL_R                                                                                0xCE
#define PCRM_CLIF_ANA_XTAL_W                                                                                0xCE
#define PCRM_CLIF_ANA_XTAL_RESERVED_POS                                                                  (29UL)
#define PCRM_CLIF_ANA_XTAL_RESERVED_MASK                                                                 (0xE0000000UL)  /**< 29-reserved*/
#define PCRM_CLIF_ANA_XTAL_XTAL_SLICER_PSM_POS                                                           (27UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_SLICER_PSM_MASK                                                          (0x18000000UL)  /**< 27-sets the XTAL slicer driving strength*/
#define PCRM_CLIF_ANA_XTAL_XTAL_PKDET_MON_EN_POS                                                         (26UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_PKDET_MON_EN_MASK                                                        (0x04000000UL)  /**< 26-enable signal for monitoring XTAL outputs*/
#define PCRM_CLIF_ANA_XTAL_TEMP_POS                                                                      (16UL)
#define PCRM_CLIF_ANA_XTAL_TEMP_MASK                                                                     (0x03FF0000UL)  /**< 16-Temperature information for the CLIF main PLL. Post processed from BIST GPADC datas trunk to 4 bits => 5% accuracy*/
#define PCRM_CLIF_ANA_XTAL_XTAL_AUTO_EN_POS                                                              (15UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_AUTO_EN_MASK                                                             (0x00008000UL)  /**< 15-Enable "XTAL automatic start" when RF field detection event is triggered (RFLD function)*/
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_SEL_POS                                                              (13UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_SEL_MASK                                                             (0x00006000UL)  /**< 13-target level for amplitude regulation loop*/
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_CTRL_POS                                                             (7UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_CTRL_MASK                                                            (0x00001F80UL)  /**< 7-Oscillation Amplitude control*/
#define PCRM_CLIF_ANA_XTAL_XTAL_OVER_BOOST_EN_POS                                                        (6UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_OVER_BOOST_EN_MASK                                                       (0x00000040UL)  /**< 6-Enable  BOOST mode ; more GM*/
#define PCRM_CLIF_ANA_XTAL_XTAL_CLKFLAG_EN_POS                                                           (5UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_CLKFLAG_EN_MASK                                                          (0x00000020UL)  /**< 5-CLKFLAG enable*/
#define PCRM_CLIF_ANA_XTAL_XTAL_SLICER_EN_POS                                                            (4UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_SLICER_EN_MASK                                                           (0x00000010UL)  /**< 4-Enable Slicer*/
#define PCRM_CLIF_ANA_XTAL_XTAL_PKDET_EN_POS                                                             (3UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_PKDET_EN_MASK                                                            (0x00000008UL)  /**< 3-Enable for XTAL peak detector*/
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_REG_AUTO_EN_POS                                                      (2UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_AMP_REG_AUTO_EN_MASK                                                     (0x00000004UL)  /**< 2-Enable analog automatic amplitude regulation*/
#define PCRM_CLIF_ANA_XTAL_XTAL_BYPASS_EN_POS                                                            (1UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_BYPASS_EN_MASK                                                           (0x00000002UL)  /**< 1-Bypass GM Buffer*/
#define PCRM_CLIF_ANA_XTAL_XTAL_EN_POS                                                                   (0UL)
#define PCRM_CLIF_ANA_XTAL_XTAL_EN_MASK                                                                  (0x00000001UL)  /**< 0-Enable signal for XTAL Oscillator*/
#define PCRM_CLIF_ANA_XTAL__RESET_VALUE                                                                       (0x00000040UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_ven_mon
* <b>Reset value:</b> 0x00000FFF
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_VEN_MON                                                                              0xCF
#define PCRM_PMU_ANA_VEN_MON_R                                                                              0xCF
#define PCRM_PMU_ANA_VEN_MON_W                                                                              0xCF
#define PCRM_PMU_ANA_VEN_MON_RESERVED_POS                                                                (16UL)
#define PCRM_PMU_ANA_VEN_MON_RESERVED_MASK                                                               (0xFFFF0000UL)  /**< 16-reserved*/
#define PCRM_PMU_ANA_VEN_MON_VEN_OFF_HPD_ENTRY_LIMIT_TIME_POS                                            (4UL)
#define PCRM_PMU_ANA_VEN_MON_VEN_OFF_HPD_ENTRY_LIMIT_TIME_MASK                                           (0x0000FFF0UL)  /**< 4-Counter time limit before going to OFF/HPD state when VEN goes low*/
#define PCRM_PMU_ANA_VEN_MON_NFC_RESET_LIMIT_TIME_POS                                                    (0UL)
#define PCRM_PMU_ANA_VEN_MON_NFC_RESET_LIMIT_TIME_MASK                                                   (0x0000000FUL)  /**< 0-Counter time limit before reseting NFC core*/
#define PCRM_PMU_ANA_VEN_MON__RESET_VALUE                                                        (0x00000FFFUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_vbat_mon
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_VBAT_MON                                                                             0xD0
#define PCRM_PMU_ANA_VBAT_MON_R                                                                             0xD0
#define PCRM_PMU_ANA_VBAT_MON_W                                                                             0xD0
#define PCRM_PMU_ANA_VBAT_MON_RESERVED_POS                                                               (12UL)
#define PCRM_PMU_ANA_VBAT_MON_RESERVED_MASK                                                              (0xFFFFF000UL)  /**< 12-reserved*/
#define PCRM_PMU_ANA_VBAT_MON_VBAT_MON_FSM_EN_POS                                                        (11UL)
#define PCRM_PMU_ANA_VBAT_MON_VBAT_MON_FSM_EN_MASK                                                       (0x00000800UL)  /**< 11-Enable the vbat monitor fsm*/
#define PCRM_PMU_ANA_VBAT_MON_VBAT_MON_CMD_DIS_POS                                                       (10UL)
#define PCRM_PMU_ANA_VBAT_MON_VBAT_MON_CMD_DIS_MASK                                                      (0x00000400UL)  /**< 10-Disable turn off command from VBAT monitor FSM; use mainly for debug purpose.*/
#define PCRM_PMU_ANA_VBAT_MON_VBAT_FSM_OFF_LOOP_TIME_POS                                                 (0UL)
#define PCRM_PMU_ANA_VBAT_MON_VBAT_FSM_OFF_LOOP_TIME_MASK                                                (0x000003FFUL)  /**< 0-Timing between 2 Vbat monitoring (based on LFO_clk cycles)*/
#define PCRM_PMU_ANA_VBAT_MON__RESET_VALUE                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_temp_sns_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_TEMP_SNS_CTRL                                                                        0xD1
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_R                                                                        0xD1
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_W                                                                        0xD1
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_RESERVED_POS                                                          (4UL)
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_RESERVED_MASK                                                         (0xFFFFFFF0UL)  /**< 4-reserved*/
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_NFC_OVER_TEMP_SEL_POS                                                 (2UL)
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_NFC_OVER_TEMP_SEL_MASK                                                (0x0000000CUL)  /**< 2-NFC Thermal warning detection threshold value (00: disabled / 01: 114 C / 10: 125 C / 11: 130 C)*/
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_PMU_OVER_TEMP_SEL_POS                                                 (0UL)
#define PCRM_PMU_ANA_TEMP_SNS_CTRL_PMU_OVER_TEMP_SEL_MASK                                                (0x00000003UL)  /**< 0-PMU Thermal warning detection threshold value (00: disabled / 01: 114 C / 10: 125 C / 11: 130 C)*/
#define PCRM_PMU_ANA_TEMP_SNS_CTRL__RESET_VALUE                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pmu_ana_vmon_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_PMU_ANA_VMON_CTRL                                                                            0xD2
#define PCRM_PMU_ANA_VMON_CTRL_R                                                                            0xD2
#define PCRM_PMU_ANA_VMON_CTRL_W                                                                            0xD2
#define PCRM_PMU_ANA_VMON_CTRL_RESERVED_POS                                                              (7UL)
#define PCRM_PMU_ANA_VMON_CTRL_RESERVED_MASK                                                             (0xFFFFFF80UL)  /**< 7-reserved*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VUP_THRESH_SEL_POS                                                   (6UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VUP_THRESH_SEL_MASK                                                  (0x00000040UL)  /**< 6-Voltage monitor VUP threshold (0: 2.4V falling edge 1: 3.2V falling edge)*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VUP_EN_POS                                                           (5UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VUP_EN_MASK                                                          (0x00000020UL)  /**< 5-Voltage monitor VUP enable*/
#define PCRM_PMU_ANA_VMON_CTRL_RESERVED1_POS                                                              (4UL)
#define PCRM_PMU_ANA_VMON_CTRL_RESERVED1_MASK                                                             (0x00000010UL)  /**< 4-reserved*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VDDC_EN_POS                                                          (3UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VDDC_EN_MASK                                                         (0x00000008UL)  /**< 3-Voltage monitor VDDC enable*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VHV_EN_POS                                                           (2UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VHV_EN_MASK                                                          (0x00000004UL)  /**< 2-Voltage monitor VHV enable*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_THRESH_SEL_POS                                                  (1UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_THRESH_SEL_MASK                                                 (0x00000002UL)  /**< 1-Voltage monitor VBAT threshold (0: 2.4V falling edge 1: 2.5V rising edge)*/
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_EN_POS                                                          (0UL)
#define PCRM_PMU_ANA_VMON_CTRL_VMON_VBAT_EN_MASK                                                         (0x00000001UL)  /**< 0-Voltage monitor VBAT enable*/
#define PCRM_PMU_ANA_VMON_CTRL__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_cfg_offplus
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define PCRM_CFG_OFFPLUS                                                                                  0xD3
#define PCRM_CFG_OFFPLUS_R                                                                                  0xD3
#define PCRM_CFG_OFFPLUS_W                                                                                  0xD3
#define PCRM_CFG_OFFPLUS_RESERVED_POS                                                                    (1UL)
#define PCRM_CFG_OFFPLUS_RESERVED_MASK                                                                   (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_CFG_OFFPLUS_RESERVED1_POS                                                       (0UL)
#define PCRM_CFG_OFFPLUS_RESERVED1_MASK                                                      (0x00000001UL)  /**< 0-reserved */
#define PCRM_CFG_OFFPLUS__RESET_VALUE                                                           (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_aux_3
* <b>Reset value:</b> 0x00000012
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_AUX_3                                                                                    0xD4
#define PCRM_PAD_AUX_3_R                                                                                    0xD4
#define PCRM_PAD_AUX_3_W                                                                                    0xD4
#define PCRM_PAD_AUX_3_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_AUX_3_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_AUX_3_AUX_3_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_AUX_3_AUX_3_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for AUX_3*/
#define PCRM_PAD_AUX_3_AUX_3_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_AUX_3_AUX_3_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for AUX_3 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_AUX_3_AUX_3_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_AUX_3_AUX_3_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for AUX_3*/
#define PCRM_PAD_AUX_3_AUX_3_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_AUX_3_AUX_3_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for AUX_3*/
#define PCRM_PAD_AUX_3__RESET_VALUE                                                                       (0x00000012UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_aux_2
* <b>Reset value:</b> 0x00000012
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_AUX_2                                                                                    0xD5
#define PCRM_PAD_AUX_2_R                                                                                    0xD5
#define PCRM_PAD_AUX_2_W                                                                                    0xD5
#define PCRM_PAD_AUX_2_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_AUX_2_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_AUX_2_AUX_2_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_AUX_2_AUX_2_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for AUX_2*/
#define PCRM_PAD_AUX_2_AUX_2_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_AUX_2_AUX_2_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for AUX_2 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_AUX_2_AUX_2_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_AUX_2_AUX_2_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for AUX_2*/
#define PCRM_PAD_AUX_2_AUX_2_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_AUX_2_AUX_2_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for AUX_2*/
#define PCRM_PAD_AUX_2__RESET_VALUE                                                                       (0x00000012UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_aux_1
* <b>Reset value:</b> 0x00000012
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_AUX_1                                                                                    0xD6
#define PCRM_PAD_AUX_1_R                                                                                    0xD6
#define PCRM_PAD_AUX_1_W                                                                                    0xD6
#define PCRM_PAD_AUX_1_RESERVED_POS                                                                      (6UL)
#define PCRM_PAD_AUX_1_RESERVED_MASK                                                                     (0xFFFFFFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_AUX_1_AUX_1_SLEW_RATE_POS                                                               (4UL)
#define PCRM_PAD_AUX_1_AUX_1_SLEW_RATE_MASK                                                              (0x00000030UL)  /**< 4-Selects Driver Strength for AUX_1*/
#define PCRM_PAD_AUX_1_AUX_1_PUPD_POS                                                                    (2UL)
#define PCRM_PAD_AUX_1_AUX_1_PUPD_MASK                                                                   (0x0000000CUL)  /**< 2-Enables PullUp/Down for AUX_1 (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_AUX_1_AUX_1_EN_OUT_POS                                                                  (1UL)
#define PCRM_PAD_AUX_1_AUX_1_EN_OUT_MASK                                                                 (0x00000002UL)  /**< 1-Enables Output driver for AUX_1*/
#define PCRM_PAD_AUX_1_AUX_1_EN_IN_POS                                                                   (0UL)
#define PCRM_PAD_AUX_1_AUX_1_EN_IN_MASK                                                                  (0x00000001UL)  /**< 0-Enables Input Driver for AUX_1*/
#define PCRM_PAD_AUX_1__RESET_VALUE                                                                       (0x00000012UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_sys_suspend_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> -w
* @{
*/
#define PCRM_SYS_SUSPEND_CTRL                                                                             0xD7
#define PCRM_SYS_SUSPEND_CTRL_W                                                                             0xD7
#define PCRM_SYS_SUSPEND_CTRL_RESERVED_POS                                                               (1UL)
#define PCRM_SYS_SUSPEND_CTRL_RESERVED_MASK                                                              (0xFFFFFFFEUL)  /**< 1-reserved*/
#define PCRM_SYS_SUSPEND_CTRL_NFC_SUSPEND_ENTRY_REQ_POS                                                  (0UL)
#define PCRM_SYS_SUSPEND_CTRL_NFC_SUSPEND_ENTRY_REQ_MASK                                                 (0x00000001UL)  /**< 0-Suspend mode request entry configuration */
#define PCRM_SYS_SUSPEND_CTRL__RESET_VALUE                                                      (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_spim_miso
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_SPIM_MISO                                                                                0xD8
#define PCRM_PAD_SPIM_MISO_R                                                                                0xD8
#define PCRM_PAD_SPIM_MISO_W                                                                                0xD8
#define PCRM_PAD_SPIM_MISO_RESERVED_POS                                                                  (17UL)
#define PCRM_PAD_SPIM_MISO_RESERVED_MASK                                                                 (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_ENABLE_POS                                                          (16UL)
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_ENABLE_MASK                                                         (0x00010000UL)  /**< 16-If set them SPIM_MISO unit output is driving the GPIO*/
#define PCRM_PAD_SPIM_MISO_RESERVED1_POS                                                                  (6UL)
#define PCRM_PAD_SPIM_MISO_RESERVED1_MASK                                                                 (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_SLEW_RATE_POS                                                       (4UL)
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_SLEW_RATE_MASK                                                      (0x00000030UL)  /**< 4-Selects Driver Strength for SPIM_MISO*/
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_PUPD_POS                                                            (2UL)
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_PUPD_MASK                                                           (0x0000000CUL)  /**< 2-Enables PullUp/Down for SPIM_MISO (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_EN_OUT_POS                                                          (1UL)
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_EN_OUT_MASK                                                         (0x00000002UL)  /**< 1-Enables Output driver for SPIM_MISO*/
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_EN_IN_POS                                                           (0UL)
#define PCRM_PAD_SPIM_MISO_SPIM_MISO_EN_IN_MASK                                                          (0x00000001UL)  /**< 0-Enables Input Driver for SPIM_MISO*/
#define PCRM_PAD_SPIM_MISO__RESET_VALUE                                                               (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_spim_mosi
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_SPIM_MOSI                                                                                0xD9
#define PCRM_PAD_SPIM_MOSI_R                                                                                0xD9
#define PCRM_PAD_SPIM_MOSI_W                                                                                0xD9
#define PCRM_PAD_SPIM_MOSI_RESERVED_POS                                                                  (17UL)
#define PCRM_PAD_SPIM_MOSI_RESERVED_MASK                                                                 (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_ENABLE_POS                                                          (16UL)
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_ENABLE_MASK                                                         (0x00010000UL)  /**< 16-If set them SPIM_MOSI unit output is driving the GPIO*/
#define PCRM_PAD_SPIM_MOSI_RESERVED1_POS                                                                  (6UL)
#define PCRM_PAD_SPIM_MOSI_RESERVED1_MASK                                                                 (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_SLEW_RATE_POS                                                       (4UL)
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_SLEW_RATE_MASK                                                      (0x00000030UL)  /**< 4-Selects Driver Strength for SPIM_MOSI*/
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_PUPD_POS                                                            (2UL)
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_PUPD_MASK                                                           (0x0000000CUL)  /**< 2-Enables PullUp/Down for SPIM_MOSI (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_EN_OUT_POS                                                          (1UL)
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_EN_OUT_MASK                                                         (0x00000002UL)  /**< 1-Enables Output driver for SPIM_MOSI*/
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_EN_IN_POS                                                           (0UL)
#define PCRM_PAD_SPIM_MOSI_SPIM_MOSI_EN_IN_MASK                                                          (0x00000001UL)  /**< 0-Enables Input Driver for SPIM_MOSI*/
#define PCRM_PAD_SPIM_MOSI__RESET_VALUE                                                               (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_spim_sclk
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_SPIM_SCLK                                                                                0xDA
#define PCRM_PAD_SPIM_SCLK_R                                                                                0xDA
#define PCRM_PAD_SPIM_SCLK_W                                                                                0xDA
#define PCRM_PAD_SPIM_SCLK_RESERVED_POS                                                                  (17UL)
#define PCRM_PAD_SPIM_SCLK_RESERVED_MASK                                                                 (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_ENABLE_POS                                                          (16UL)
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_ENABLE_MASK                                                         (0x00010000UL)  /**< 16-If set them SPIM_SCLK unit output is driving the GPIO*/
#define PCRM_PAD_SPIM_SCLK_RESERVED1_POS                                                                  (6UL)
#define PCRM_PAD_SPIM_SCLK_RESERVED1_MASK                                                                 (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_SLEW_RATE_POS                                                       (4UL)
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_SLEW_RATE_MASK                                                      (0x00000030UL)  /**< 4-Selects Driver Strength for SPIM_SCLK*/
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_PUPD_POS                                                            (2UL)
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_PUPD_MASK                                                           (0x0000000CUL)  /**< 2-Enables PullUp/Down for SPIM_SCLK (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_EN_OUT_POS                                                          (1UL)
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_EN_OUT_MASK                                                         (0x00000002UL)  /**< 1-Enables Output driver for SPIM_SCLK*/
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_EN_IN_POS                                                           (0UL)
#define PCRM_PAD_SPIM_SCLK_SPIM_SCLK_EN_IN_MASK                                                          (0x00000001UL)  /**< 0-Enables Input Driver for SPIM_SCLK*/
#define PCRM_PAD_SPIM_SCLK__RESET_VALUE                                                               (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_spim_ssn
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_SPIM_SSN                                                                                 0xDB
#define PCRM_PAD_SPIM_SSN_R                                                                                 0xDB
#define PCRM_PAD_SPIM_SSN_W                                                                                 0xDB
#define PCRM_PAD_SPIM_SSN_RESERVED_POS                                                                   (17UL)
#define PCRM_PAD_SPIM_SSN_RESERVED_MASK                                                                  (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_ENABLE_POS                                                            (16UL)
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-If set them SPIM_SSN unit output is driving the GPIO*/
#define PCRM_PAD_SPIM_SSN_RESERVED1_POS                                                                   (6UL)
#define PCRM_PAD_SPIM_SSN_RESERVED1_MASK                                                                  (0x0000FFC0UL)  /**< 6-reserved*/
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_SLEW_RATE_POS                                                         (4UL)
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_SLEW_RATE_MASK                                                        (0x00000030UL)  /**< 4-Selects Driver Strength for SPIM_SSN*/
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_PUPD_POS                                                              (2UL)
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_PUPD_MASK                                                             (0x0000000CUL)  /**< 2-Enables PullUp/Down for SPIM_SSN (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_EN_OUT_POS                                                            (1UL)
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_EN_OUT_MASK                                                           (0x00000002UL)  /**< 1-Enables Output driver for SPIM_SSN*/
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_EN_IN_POS                                                             (0UL)
#define PCRM_PAD_SPIM_SSN_SPIM_SSN_EN_IN_MASK                                                            (0x00000001UL)  /**< 0-Enables Input Driver for SPIM_SSN*/
#define PCRM_PAD_SPIM_SSN__RESET_VALUE                                                                 (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_i2cm_scl
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_I2CM_SCL                                                                                 0xDC
#define PCRM_PAD_I2CM_SCL_R                                                                                 0xDC
#define PCRM_PAD_I2CM_SCL_W                                                                                 0xDC
#define PCRM_PAD_I2CM_SCL_RESERVED_POS                                                                   (17UL)
#define PCRM_PAD_I2CM_SCL_RESERVED_MASK                                                                  (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_ENABLE_POS                                                            (16UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-If set them I2CM_SCL  unit output  is driving the GPIO*/
#define PCRM_PAD_I2CM_SCL_RESERVED1_POS                                                                   (8UL)
#define PCRM_PAD_I2CM_SCL_RESERVED1_MASK                                                                  (0x0000FF00UL)  /**< 8-reserved*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_ECS_POS                                                               (7UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_ECS_MASK                                                              (0x00000080UL)  /**< 7-Enables Pull-up current source for I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EGP_POS                                                               (6UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EGP_MASK                                                              (0x00000040UL)  /**< 6-Enables GPIO mode (0: I2C mode; 1: GPIO mode) for I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_FSEL_POS                                                              (5UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_FSEL_MASK                                                             (0x00000020UL)  /**< 5-Selects Input Filter value for I2C mode (0: 50ns; 1: 10ns) for I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_SLEW_RATE_POS                                                         (4UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_SLEW_RATE_MASK                                                        (0x00000010UL)  /**< 4-Selects Driver Strength / Speed mode (0: Low speed GPIO / SF and FP I2C mode; 1: Medium speed GPIO / HS I2C mode) on I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_PUPD_POS                                                              (2UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_PUPD_MASK                                                             (0x0000000CUL)  /**< 2-Enables PullUp/Down for I2CM_SCL (I2C_SCL) (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EN_OUT_POS                                                            (1UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EN_OUT_MASK                                                           (0x00000002UL)  /**< 1-Enables Output driver for I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EN_IN_POS                                                             (0UL)
#define PCRM_PAD_I2CM_SCL_I2CM_SCL_EN_IN_MASK                                                            (0x00000001UL)  /**< 0-Enables Input Driver for I2CM_SCL (I2C_SCL)*/
#define PCRM_PAD_I2CM_SCL__RESET_VALUE                                                                 (0x00000004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name pcrm_pad_i2cm_sda
* <b>Reset value:</b> 0x00000004
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_I2CM_SDA                                                                                 0xDD
#define PCRM_PAD_I2CM_SDA_R                                                                                 0xDD
#define PCRM_PAD_I2CM_SDA_W                                                                                 0xDD
#define PCRM_PAD_I2CM_SDA_RESERVED_POS                                                                   (17UL)
#define PCRM_PAD_I2CM_SDA_RESERVED_MASK                                                                  (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_ENABLE_POS                                                            (16UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-If set them I2CM_SDA  unit output  is driving the GPIO*/
#define PCRM_PAD_I2CM_SDA_RESERVED1_POS                                                                   (8UL)
#define PCRM_PAD_I2CM_SDA_RESERVED1_MASK                                                                  (0x0000FF00UL)  /**< 8-reserved*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_ECS_POS                                                               (7UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_ECS_MASK                                                              (0x00000080UL)  /**< 7-Enables Pull-up current source for I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EGP_POS                                                               (6UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EGP_MASK                                                              (0x00000040UL)  /**< 6-Enables GPIO mode (0: I2C mode; 1: GPIO mode)for I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_FSEL_POS                                                              (5UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_FSEL_MASK                                                             (0x00000020UL)  /**< 5-Selects Input Filter value for I2C mode (0: 50ns; 1: 10ns) for I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_SLEW_RATE_POS                                                         (4UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_SLEW_RATE_MASK                                                        (0x00000010UL)  /**< 4-Selects Driver Strength / Speed mode (0: Low speed GPIO / SF and FP I2C mode; 1: Medium speed GPIO / HS I2C mode) on I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_PUPD_POS                                                              (2UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_PUPD_MASK                                                             (0x0000000CUL)  /**< 2-Enables PullUp/Down for I2CM_SDA (I2C_SDA) (00: Weak Pull-Down; 01: No Pull; 10: Bus Keeper; 11: Weak Pull-Up)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EN_OUT_POS                                                            (1UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EN_OUT_MASK                                                           (0x00000002UL)  /**< 1-Enables Output driver for I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EN_IN_POS                                                             (0UL)
#define PCRM_PAD_I2CM_SDA_I2CM_SDA_EN_IN_MASK                                                            (0x00000001UL)  /**< 0-Enables Input Driver for I2CM_SDA (I2C_SDA)*/
#define PCRM_PAD_I2CM_SDA__RESET_VALUE                                                                 (0x00000004UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name pcrm_pad_ctaux_io
* <b>Reset value:</b> 0x00000005
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_CTAUX_IO                                                                                 0xDE
#define PCRM_PAD_CTAUX_IO_R                                                                                 0xDE
#define PCRM_PAD_CTAUX_IO_W                                                                                 0xDE
#define PCRM_PAD_CTAUX_IO_RESERVED_POS                                                                   (17UL)
#define PCRM_PAD_CTAUX_IO_RESERVED_MASK                                                                  (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_POS                                                              (16UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_MASK                                                             (0x00010000UL)  /**< 16-If set the CT_AUX IP is driving this pad, otherwise GPIO mode is active.*/
#define PCRM_PAD_CTAUX_IO_RESERVED1_POS                                                                   (7UL)
#define PCRM_PAD_CTAUX_IO_RESERVED1_MASK                                                                  (0x0000FF80UL)  /**< 7-reserved*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_ZIF_SEL_POS                                                             (6UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_ZIF_SEL_MASK                                                            (0x00000040UL)  /**< 6-Select whether ZI or ZIF pad pin shall be used (0:ZI, 1= ZIF)*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_INDEF_POS                                                               (5UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_INDEF_MASK                                                              (0x00000020UL)  /**< 5-Defines receiver output state when receiver is disabled.*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_EHS_POS                                                                 (4UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_EHS_MASK                                                                (0x00000010UL)  /**< 4-Output Driver Speed for CT_AUX_IO (0: Slow, 1:Fast)*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENQN_POS                                                                (3UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENQN_MASK                                                               (0x00000008UL)  /**< 3-Quasi-bidirectional mode control for CT_AUX_IO (0: Disabled, 1: Enabled)*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_EPUN_POS                                                                (2UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_EPUN_MASK                                                               (0x00000004UL)  /**< 2-Enables weak pullup for CT_AUX_IO (Active Low)*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_EPD_POS                                                                 (1UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_EPD_MASK                                                                (0x00000002UL)  /**< 1-Enables weak pulldown for CT_AUX_IO*/
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENZI_POS                                                                (0UL)
#define PCRM_PAD_CTAUX_IO_IO_AUX_ENZI_MASK                                                               (0x00000001UL)  /**< 0-Enables Receiver for CT_AUX_IO (Active Low)*/
#define PCRM_PAD_CTAUX_IO__RESET_VALUE                                                                    (0x00000005UL)  /**< value after reset*/
/**
* @}
*/
/**
* @name pcrm_pad_ctaux_clk
* <b>Reset value:</b> 0x00000005
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_CTAUX_CLK                                                                                0xDF
#define PCRM_PAD_CTAUX_CLK_R                                                                                0xDF
#define PCRM_PAD_CTAUX_CLK_W                                                                                0xDF
#define PCRM_PAD_CTAUX_CLK_RESERVED_POS                                                                  (17UL)
#define PCRM_PAD_CTAUX_CLK_RESERVED_MASK                                                                 (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_POS                                                            (16UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-If set the CT_AUX IP is driving this pad, otherwise GPIO mode is active.*/
#define PCRM_PAD_CTAUX_CLK_RESERVED1_POS                                                                  (7UL)
#define PCRM_PAD_CTAUX_CLK_RESERVED1_MASK                                                                 (0x0000FF80UL)  /**< 7-reserved*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ZIF_SEL_POS                                                           (6UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ZIF_SEL_MASK                                                          (0x00000040UL)  /**< 6-Select whether ZI or ZIF pad pin shall be used (0:ZI, 1= ZIF)*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_INDEF_POS                                                             (5UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_INDEF_MASK                                                            (0x00000020UL)  /**< 5-Defines receiver output state when receiver is disabled.*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_POS                                                               (4UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_MASK                                                              (0x00000010UL)  /**< 4-Output Driver Speed for CT_AUX_CLK (0: Slow, 1:Fast)*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENQN_POS                                                              (3UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENQN_MASK                                                             (0x00000008UL)  /**< 3-Quasi-bidirectional mode control for CT_AUX_CLK (0: Disabled, 1: Enabled)*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EPUN_POS                                                              (2UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EPUN_MASK                                                             (0x00000004UL)  /**< 2-Enables weak pullup for CT_AUX_CLK (Active Low)*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EPD_POS                                                               (1UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_EPD_MASK                                                              (0x00000002UL)  /**< 1-Enables weak pulldown for CT_AUX_CLK*/
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENZI_POS                                                              (0UL)
#define PCRM_PAD_CTAUX_CLK_CLK_AUX_ENZI_MASK                                                             (0x00000001UL)  /**< 0-Enable Receiver for CT_AUX_CLK (Active Low)*/
#define PCRM_PAD_CTAUX_CLK__RESET_VALUE                                                                  (0x00000005UL)  /**< value after reset*/
/**
* @}
*/
/**
* @name pcrm_pad_ctaux_int
* <b>Reset value:</b> 0x00000005
* <b>Access:</b> rw
* @{
*/
#define PCRM_PAD_CTAUX_INT                                                                                0xE0
#define PCRM_PAD_CTAUX_INT_R                                                                                0xE0
#define PCRM_PAD_CTAUX_INT_W                                                                                0xE0
#define PCRM_PAD_CTAUX_INT_RESERVED_POS                                                                  (17UL)
#define PCRM_PAD_CTAUX_INT_RESERVED_MASK                                                                 (0xFFFE0000UL)  /**< 17-reserved*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_POS                                                            (16UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-If set the CT_AUX IP is driving this pad, otherwise GPIO mode is active.*/
#define PCRM_PAD_CTAUX_INT_RESERVED1_POS                                                                  (7UL)
#define PCRM_PAD_CTAUX_INT_RESERVED1_MASK                                                                 (0x0000FF80UL)  /**< 7-reserved*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_ZIF_SEL_POS                                                           (6UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_ZIF_SEL_MASK                                                          (0x00000040UL)  /**< 6-Select whether ZI or ZIF pad pin shall be used (0:ZI, 1= ZIF)*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_INDEF_POS                                                             (5UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_INDEF_MASK                                                            (0x00000020UL)  /**< 5-Defines receiver output state when receiver is disabled.*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_EHS_POS                                                               (4UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_EHS_MASK                                                              (0x00000010UL)  /**< 4-Output Driver Speed for CT_AUX_INT (0: Slow, 1:Fast)*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENQN_POS                                                              (3UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENQN_MASK                                                             (0x00000008UL)  /**< 3-Quasi-bidirectional mode control for CT_AUX_INT (0: Disabled, 1: Enabled)*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_EPUN_POS                                                              (2UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_EPUN_MASK                                                             (0x00000004UL)  /**< 2-Enables weak pullup for CT_AUX_INT (Active Low)*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_EPD_POS                                                               (1UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_EPD_MASK                                                              (0x00000002UL)  /**< 1-Enables weak pulldown for CT_AUX_INT*/
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENZI_POS                                                              (0UL)
#define PCRM_PAD_CTAUX_INT_INT_AUX_ENZI_MASK                                                             (0x00000001UL)  /**< 0-Enable Receiver for CT_AUX_INT (Active Low)*/
#define PCRM_PAD_CTAUX_INT__RESET_VALUE                                                                  (0x00000005UL)  /**< value after reset*/
/**
* @}
*/
/** @} */

#endif /* _PCRM_LP_REG_H_ */