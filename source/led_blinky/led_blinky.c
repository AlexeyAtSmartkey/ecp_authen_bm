#include <phApp_Init.h>
#include "led_blinky.h"
#include "nfc_comm.h"
#include "fsl_gpio.h"
#include "SmartLock.h"
#include "taskmanager.h"

#ifdef LED_BLINK


#define LED_BLINKY_PERIOD_MS			100


static void ledBlinkyTask(void);


//-------------------------------------------------------------
void LED_BLINKY_init(void)
{
	gpio_pin_config_t gpioConfig = {
	        .pinDirection = kGPIO_DigitalOutput,
	        .outputLogic  = 1,
	    };

	GPIO_PinInit(kGPIO_GPIO4, &gpioConfig);

	TIME_TASK_create(&ledBlinkyTask, 200);
}

//-------------------------------------------------------------
void ledBlinkyTask(void)
{
	static uint8_t led_state = 0;

	GPIO_PinWrite(kGPIO_GPIO4, led_state);

	led_state ^= 1;
}

#endif // LED_BLINK
