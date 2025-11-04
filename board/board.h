/*
 * Copyright 2022 NXP
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef _BOARD_H_
#define _BOARD_H_

#include "fsl_common.h"
#include "fsl_gpio.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
/*! @brief The board name */
#define BOARD_NAME "PNEV7642FAMA"

/* Board led color mapping */
#define LOGIC_LED_ON  0U
#define LOGIC_LED_OFF 1U

#ifndef BOARD_LED_BLUE_GPIO
#define BOARD_LED_BLUE_GPIO kGPIO_GPIO1
#endif

#ifndef BOARD_LED_YELLOW_GPIO
#define BOARD_LED_YELLOW_GPIO kGPIO_GPIO0
#endif

#ifndef BOARD_LED_GREEN_GPIO
#define BOARD_LED_GREEN_GPIO kGPIO_GPIO2
#endif

#ifndef BOARD_LED_RED_GPIO
#define BOARD_LED_RED_GPIO kGPIO_GPIO3
#endif

/*! Enable target LED_RED */
#define LED_RED_INIT(output) GPIO_PinInit(BOARD_LED_RED_GPIO, &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)})
/*! Turn on LED RED */
#define LED_RED_ON() GPIO_PinWrite(BOARD_LED_RED_GPIO, 0U)
/*! Turn off LED RED */
#define LED_RED_OFF() GPIO_PinWrite(BOARD_LED_RED_GPIO, 1U)

/*! Enable target LED_BLUE */
#define LED_BLUE_INIT(output) GPIO_PinInit(BOARD_LED_BLUE_GPIO, &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)})
/*! Turn on LED BLUE */
#define LED_BLUE_ON() GPIO_PinWrite(BOARD_LED_BLUE_GPIO, 0U)
/*! Turn off LED BLUE */
#define LED_BLUE_OFF() GPIO_PinWrite(BOARD_LED_BLUE_GPIO, 1U)

/*! Enable target LED_GREEN */
#define LED_GREEN_INIT(output) GPIO_PinInit(BOARD_LED_GREEN_GPIO, &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)})
/*! Turn on LED GREEN */
#define LED_GREEN_ON() GPIO_PinWrite(BOARD_LED_GREEN_GPIO, 0U)
/*! Turn off LED GREEN */
#define LED_GREEN_OFF() GPIO_PinWrite(BOARD_LED_GREEN_GPIO, 1U)

/*! Enable target LED_YELLOW */
#define LED_YELLOW_INIT(output) GPIO_PinInit(BOARD_LED_YELLOW_GPIO, &(gpio_pin_config_t){kGPIO_DigitalOutput, (output)})
/*! Turn on LED YELLOW */
#define LED_YELLOW_ON() GPIO_PinWrite(BOARD_LED_YELLOW_GPIO, 0U)
/*! Turn off LED YELLOW */
#define LED_YELLOW_OFF() GPIO_PinWrite(BOARD_LED_YELLOW_GPIO, 1U)

#if defined(__cplusplus)
extern "C" {
#endif /* __cplusplus */

/*******************************************************************************
 * API
 ******************************************************************************/

void BOARD_InitDebugConsole(void);

#if defined(__cplusplus)
}
#endif /* __cplusplus */

#endif /* _BOARD_H_ */
