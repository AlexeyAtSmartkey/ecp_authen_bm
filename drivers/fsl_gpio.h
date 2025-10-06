/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _FSL_GPIO_H_
#define _FSL_GPIO_H_

#include "fsl_common.h"
#include "Pcrm_Lp_Reg.h"

/*!
 * @defgroup gpio GPIO: General Purpose Input / Output
 *
 * @{
 */

/*******************************************************************************
 * Definitions
 ******************************************************************************/

/*! @name Driver version */
/*@{*/
/*! @brief GPIO driver version 2.0.2. */
#define FSL_GPIO_DRIVER_VERSION (MAKE_VERSION(2, 0, 2))
/*@}*/

#define GPIO_PIN_ADDRESS(irq, bits, address) (((irq)&1U) | (((bits)&0xFFU) << 8U) | (((address)&0xFFFFU) << 16U))
#define GPIO_PIN_GET_BITS(value)             ((((uint32_t)value) >> 8UL) & 0xFFUL)
#define GPIO_PIN_GET_ADDRESS(value)          ((((uint32_t)value) >> 16UL) & 0xFFFFUL)
#define GPIO_PIN_SUPPORT_IRQ(value)          (((uint8_t)value) & 1U)

/*! @brief GPIO pin definition */
typedef enum _gpio_pin
{
    kGPIO_GPIO0 = GPIO_PIN_ADDRESS(1, PCRM_PADOUT_PADOUT_GPIO0_POS, PCRM_PAD_GPIO0),  /*!< GPIO0 */
    kGPIO_GPIO1 = GPIO_PIN_ADDRESS(1, PCRM_PADOUT_PADOUT_GPIO1_POS, PCRM_PAD_GPIO1),  /*!< GPIO1 */
    kGPIO_GPIO2 = GPIO_PIN_ADDRESS(1, PCRM_PADOUT_PADOUT_GPIO2_POS, PCRM_PAD_GPIO2),  /*!< GPIO2 */
    kGPIO_GPIO3 = GPIO_PIN_ADDRESS(1, PCRM_PADOUT_PADOUT_GPIO3_POS, PCRM_PAD_GPIO3),  /*!< GPIO3 */
    kGPIO_GPIO4 = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_GPIO4_POS, PCRM_PAD_GPIO4),  /*!< GPIO4 */
    kGPIO_GPIO5 = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_GPIO5_POS, PCRM_PAD_GPIO5),  /*!< GPIO5 */

    kGPIO_ATX_A = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_ATX_A_POS, PCRM_PAD_ATX_A), /*!< ATX_A */
    kGPIO_ATX_B = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_ATX_B_POS, PCRM_PAD_ATX_B), /*!< ATX_B */
    kGPIO_ATX_C = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_ATX_C_POS, PCRM_PAD_ATX_C), /*!< ATX_C */
    kGPIO_ATX_D = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_ATX_D_POS, PCRM_PAD_ATX_D), /*!< ATX_D */

    kGPIO_IRQ   = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_IRQ_POS, PCRM_PAD_IRQ), /*!< IRQ */

    kGPIO_DWL_REQ = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_DWL_REQ_POS, PCRM_PAD_DWL_REQ), /*!< DWL REQ */

    kGPIO_AUX_1 = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_AUX_1_POS, PCRM_PAD_AUX_1), /*!< AUX_1 */
    kGPIO_AUX_2 = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_AUX_2_POS, PCRM_PAD_AUX_2), /*!< AUX_2 */
    kGPIO_AUX_3 = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_AUX_3_POS, PCRM_PAD_AUX_3), /*!< AUX_3 */

    kGPIO_SPIM_MISO = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_SPIM_MISO_POS, PCRM_PAD_SPIM_MISO), /*!< SPIM_MISO */
    kGPIO_SPIM_MOSI = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_SPIM_MOSI_POS, PCRM_PAD_SPIM_MOSI), /*!< SPIM_MOSI */
    kGPIO_SPIM_SCLK = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_SPIM_SCLK_POS, PCRM_PAD_SPIM_SCLK), /*!< SPIM_SCLK */
    kGPIO_SPIM_SSN  = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_SPIM_SSN_POS, PCRM_PAD_SPIM_SSN),   /*!< SPIM_SSN  */
    kGPIO_I2CM_SCL  = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_I2CM_SCL_POS, PCRM_PAD_I2CM_SCL),   /*!< I2C_SCL   */
    kGPIO_I2CM_SDA  = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_I2CM_SDA_POS, PCRM_PAD_I2CM_SDA),   /*!< I2C_SDA   */
	kGPIO_CTAUX_IO  = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_IO_AUX_POS,  PCRM_PAD_CTAUX_IO),	 /*!< CTAUX_IO  */
	kGPIO_CTAUX_CLK = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_CLK_AUX_POS, PCRM_PAD_CTAUX_CLK),	 /*!< CTAUX_CLK  */
	kGPIO_CTAUX_INT = GPIO_PIN_ADDRESS(0, PCRM_PADOUT_PADOUT_INT_AUX_POS, PCRM_PAD_CTAUX_INT),	 /*!< CTAUX_INT */
} gpio_pin_t;

/*! @brief GPIO direction definition */
typedef enum _gpio_pin_direction
{
    kGPIO_DigitalInput       = 1U, /*!< Set current pin as digital input*/
    kGPIO_DigitalOutput      = 2U, /*!< Set current pin as digital output*/
    kGPIO_DigitalInputOutput = 3U, /*!< Set current pin as digital input/output*/
} gpio_pin_direction_t;

/*!
 * @brief The GPIO pin configuration structure.
 *
 */
typedef struct _gpio_pin_config
{
    gpio_pin_direction_t pinDirection; /*!< GPIO direction, input or output */
    /* Output configurations; ignore if configured as an input pin */
    uint8_t outputLogic; /*!< Set a default output logic, which has no use in input */
} gpio_pin_config_t;

/*! @brief Configures the interrupt generation condition. */
typedef enum _gpio_interrupt_edge
{
    kGPIO_InterruptEdgeDisable = 0x0U, /*!< Interrupt edge detection disable */
    kGPIO_InterruptEdgeFalling = 0x1U, /*!< Interrupt on falling edge. */
    kGPIO_InterruptEdgeRising  = 0x2U, /*!< Interrupt on rising edge. */
    kGPIO_InterruptEdgeEither  = 0x3U, /*!< Interrupt on either edge. */
} gpio_interrupt_edge_t;

/*! @brief GPIO interrupt callback. */
typedef void (*gpio_callback_t)(void);

/*! @} */

/*******************************************************************************
 * API
 ******************************************************************************/

#if defined(__cplusplus)
extern "C" {
#endif

/*! @name GPIO Configuration */
/*@{*/

/*!
 * @brief Initializes a GPIO pin used by the board.
 *
 * To initialize the GPIO, define a pin configuration, as either input or output, in the user file.
 * Then, call the GPIO_PinInit() function.
 *
 * This is an example to define an input pin or an output pin configuration.
 * @code
 * Define a digital input pin configuration,
 * gpio_pin_config_t config =
 * {
 *   kGPIO_DigitalInput,
 *   0,
 * }
 * Define a digital output pin configuration,
 * gpio_pin_config_t config =
 * {
 *   kGPIO_DigitalOutput,
 *   0,
 * }
 * @endcode
 *
 * @param pin    GPIO pin index
 * @param config GPIO pin configuration pointer
 */
void GPIO_PinInit(gpio_pin_t pin, const gpio_pin_config_t *config);

/*@}*/

/*! @name GPIO Output Operations */
/*@{*/

/*!
 * @brief Sets the output level of the multiple GPIO pins to the logic 1 or 0.
 *
 * @param pin    GPIO pin index
 * @param output  GPIO pin output logic level.
 *        - 0: corresponding pin output low-logic level.
 *        - 1: corresponding pin output high-logic level.
 */
void GPIO_PinWrite(gpio_pin_t pin, uint8_t output);

/*@}*/

/*! @name GPIO Input Operations */
/*@{*/

/*!
 * @brief Reads the current input value of the GPIO port.
 *
 * @param pin     GPIO pin index
 * @retval GPIO port input value
 *        - 0: corresponding pin input low-logic level.
 *        - 1: corresponding pin input high-logic level.
 */
uint32_t GPIO_PinRead(gpio_pin_t pin);

/*@}*/

/*!
 * @brief Configures the gpio pin interrupt.
 *
 * @param pin     GPIO pin index.
 * @param edge  GPIO pin interrupt edge.
 *        - #kGPIO_InterruptEdgeRising : Interrupt on rising edge.
 *        - #kGPIO_InterruptEdgeFalling: Interrupt on falling edge.
 *        - #kGPIO_InterruptEdgeEither : Interrupt on either edge.
 */
void GPIO_PinSetInterruptEdge(gpio_pin_t pin, gpio_interrupt_edge_t edge);

/*!
 * @brief Read the GPIO interrupt status flags.
 *
 * @param pin     GPIO pin index.
 * @return The current GPIO's interrupt status flag.
 *         '1' means the related pin's flag is set, '0' means the related pin's flag not set.
 */
uint32_t GPIO_PinGetInterruptStatus(gpio_pin_t pin);

/*!
 * @brief Clears GPIO pin interrupt status flags.
 *
 * @param pin     GPIO pin index.
 */
void GPIO_PinClearInterruptStatus(gpio_pin_t pin);

/*!
 * @brief Enable pin interrupt.
 *
 * @param pin gpio pin index.
 * @param enable true is enable, false is disable.
 */
void GPIO_PinEnableInterrupt(gpio_pin_t pin, bool enable);

/*!
 * @brief Register callback for GPIO.
 *
 * @param pin GPIO pin index.
 * @param callback The callback to register.
 * @retval kStatus_Success Register succeed.
 * @retval kStatus_InvalidArgument Failed because of invalid parameter.
 */
status_t GPIO_RegisterCallback(gpio_pin_t pin, gpio_callback_t callback);

/*@}*/

#if defined(__cplusplus)
}
#endif

/*!
 * @}
 */

#endif /* _FSL_GPIO_H_*/
