#include <taskmanager/taskmanager.h>
#include <taskmanager/peripheral/taskmanager_peripheral.h>
#include <stdint.h>
#include "fsl_gpio.h"

#define TEST_BLINK_PERIOD_MS        500

void TASK_MANAGER_test(void);

void TASK_MANAGER_TEST_init(void)
{
	gpio_pin_config_t gpioConfig = {
			.pinDirection = kGPIO_DigitalOutput,
			.outputLogic  = 1,
		};

	GPIO_PinInit(kGPIO_GPIO4, &gpioConfig);

    TIME_TASK_create(&TASK_MANAGER_test, TEST_BLINK_PERIOD_MS);
}

void TASK_MANAGER_TEST_deinit(void)
{
    TIME_TASK_delete(&TASK_MANAGER_test);
}

void TASK_MANAGER_test(void)
{
	static uint8_t led_state = 0;

	GPIO_PinWrite(kGPIO_GPIO4, led_state);

	led_state ^= 1;
}
