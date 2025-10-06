/*
 * Copyright 2022 NXP
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "fsl_gpio.h"
#include "PN76_Reg_Interface.h"

/* Component ID definition, used by tools. */
#ifndef FSL_COMPONENT_ID
#define FSL_COMPONENT_ID "platform.drivers.pn_gpio"
#endif
/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define GPIO_INT_COUNT 4 /* 4 GPIO interrupt, GPIO0 ~ GPIO3 */

#define GPIO_INT_EDGE_SEL_MASK 3UL
#define GPIO_PIN_DIR_MASK      (PCRM_PAD_GPIO0_GPIO0_EN_OUT_MASK | PCRM_PAD_GPIO0_GPIO0_EN_IN_MASK)

/*******************************************************************************
 * Variables
 ******************************************************************************/
static gpio_callback_t s_gpioCallback[GPIO_INT_COUNT] = {NULL};

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static void GPIO_CommonIRQ(gpio_pin_t pin, gpio_callback_t callback);

/*******************************************************************************
 * Code
 ******************************************************************************/

/*!
 * brief Initializes a GPIO pin used by the board.
 *
 * To initialize the GPIO, define a pin configuration, as either input or output, in the user file.
 * Then, call the GPIO_PinInit() function.
 *
 * This is an example to define an input pin or an output pin configuration.
 * code
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
 * endcode
 *
 * param pin    GPIO pin index
 * param config GPIO pin configuration pointer
 */
void GPIO_PinInit(gpio_pin_t pin, const gpio_pin_config_t *config)
{
    assert(config != NULL);

    uint16_t address = (uint16_t)GPIO_PIN_GET_ADDRESS(pin);
    uint32_t bitPos  = GPIO_PIN_GET_BITS(pin);

    (void)PN76_Sys_WriteRegisterField(address, GPIO_PIN_DIR_MASK, (uint32_t)config->pinDirection);

    if (config->pinDirection == kGPIO_DigitalOutput)
    {
        (void)PN76_Sys_WriteRegisterField(PCRM_PADOUT, 1UL << bitPos, (uint32_t)config->outputLogic << bitPos);
    }
}

/*}*/

/*! name GPIO Output Operations */
/*{*/

/*!
 * brief Sets the output level of the multiple GPIO pins to the logic 1 or 0.
 *
 * param pin    GPIO pin index
 * param output  GPIO pin output logic level.
 *        - 0: corresponding pin output low-logic level.
 *        - 1: corresponding pin output high-logic level.
 */
void GPIO_PinWrite(gpio_pin_t pin, uint8_t output)
{
    (void)PN76_Sys_WriteRegisterField(PCRM_PADOUT, 1UL << GPIO_PIN_GET_BITS(pin),
                                      (uint32_t)output << GPIO_PIN_GET_BITS(pin));
}

/*}*/

/*! name GPIO Input Operations */
/*{*/

/*!
 * brief Reads the current input value of the GPIO port.
 *
 * param pin     GPIO pin index
 * retval GPIO port input value
 *        - 0: corresponding pin input low-logic level.
 *        - 1: corresponding pin input high-logic level.
 */
uint32_t GPIO_PinRead(gpio_pin_t pin)
{
    uint32_t pinInputStatus = 0U;

    pinInputStatus = PN76_Sys_ReadRegister(PCRM_PADIN);

    return (pinInputStatus >> GPIO_PIN_GET_BITS(pin)& 0x01UL);
}

/*}*/

/*!
 * brief Configures the gpio pin interrupt.
 *
 * param pin     GPIO pin index.
 * param edge  GPIO pin interrupt edge.
 *        - #kGPIO_InterruptEdgeRising : Interrupt on rising edge.
 *        - #kGPIO_InterruptEdgeFalling: Interrupt on falling edge.
 *        - #kGPIO_InterruptEdgeEither : Interrupt on either edge.
 */
void GPIO_PinSetInterruptEdge(gpio_pin_t pin, gpio_interrupt_edge_t edge)
{
    assert(GPIO_PIN_SUPPORT_IRQ(pin) != 0U);

    (void)PN76_Sys_WriteRegisterField(PCRM_INT_EDGE_SEL, GPIO_INT_EDGE_SEL_MASK << (GPIO_PIN_GET_BITS(pin) * 2U),
                                      (uint32_t)edge << (GPIO_PIN_GET_BITS(pin) * 2U));
}

/*!
 * brief Read the GPIO interrupt status flags.
 *
 * param pin     GPIO pin index.
 * return The current GPIO's interrupt status flag.
 *         '1' means the related pin's flag is set, '0' means the related pin's flag not set.
 */
uint32_t GPIO_PinGetInterruptStatus(gpio_pin_t pin)
{
    assert(GPIO_PIN_SUPPORT_IRQ(pin) != 0U);

    uint32_t pinInterruptStatus = 0U;

    pinInterruptStatus = PN76_Sys_ReadRegister(PCRM_INT_STATUS);

    return (pinInterruptStatus & (1UL << GPIO_PIN_GET_BITS(pin))) >> GPIO_PIN_GET_BITS(pin);
}

/*!
 * brief Clears GPIO pin interrupt status flags.
 *
 * param pin     GPIO pin index.
 */
void GPIO_PinClearInterruptStatus(gpio_pin_t pin)
{
    assert(GPIO_PIN_SUPPORT_IRQ(pin) != 0U);

    (void)PN76_Sys_WriteRegister(PCRM_INT_CLR_STATUS, 1UL << GPIO_PIN_GET_BITS(pin));
}

/*!
 * brief Enable pin interrupt.
 *
 * param pin gpio pin index.
 * param enable true is enable, false is disable.
 */
void GPIO_PinEnableInterrupt(gpio_pin_t pin, bool enable)
{
    assert(GPIO_PIN_SUPPORT_IRQ(pin) != 0U);

    if (enable)
    {
        (void)PN76_Sys_WriteRegister(PCRM_INT_SET_ENABLE, 1UL << GPIO_PIN_GET_BITS(pin));
    }
    else
    {
        (void)PN76_Sys_WriteRegister(PCRM_INT_CLR_ENABLE, 1UL << GPIO_PIN_GET_BITS(pin));
    }
}

/*
 * brief Register callback for GPIO.
 *
 * param pin GPIO pin index.
 * param callback The callback to register.
 */
status_t GPIO_RegisterCallback(gpio_pin_t pin, gpio_callback_t callback)
{
    status_t status = kStatus_Success;

    if (kGPIO_GPIO0 == pin)
    {
        s_gpioCallback[0] = callback;
    }
    else if (kGPIO_GPIO1 == pin)
    {
        s_gpioCallback[1] = callback;
    }
    else if (kGPIO_GPIO2 == pin)
    {
        s_gpioCallback[2] = callback;
    }
    else if (kGPIO_GPIO3 == pin)
    {
        s_gpioCallback[3] = callback;
    }
    else
    {
        status = kStatus_InvalidArgument;
    }

    return status;
}

static void GPIO_CommonIRQ(gpio_pin_t pin, gpio_callback_t callback)
{
    if (0U != GPIO_PinGetInterruptStatus(pin))
    {
        GPIO_PinClearInterruptStatus(pin);

        if (NULL != callback)
        {
            callback();
        }
    }
}

void GPIO0_IRQHandler(void);
void GPIO0_IRQHandler(void)
{
    GPIO_CommonIRQ(kGPIO_GPIO0, s_gpioCallback[0]);
}

void GPIO1_IRQHandler(void);
void GPIO1_IRQHandler(void)
{
    GPIO_CommonIRQ(kGPIO_GPIO1, s_gpioCallback[1]);
}

void GPIO2_IRQHandler(void);
void GPIO2_IRQHandler(void)
{
    GPIO_CommonIRQ(kGPIO_GPIO2, s_gpioCallback[2]);
}

void GPIO3_IRQHandler(void);
void GPIO3_IRQHandler(void)
{
    GPIO_CommonIRQ(kGPIO_GPIO3, s_gpioCallback[3]);
}
