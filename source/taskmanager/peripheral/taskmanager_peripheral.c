#include <taskmanager/peripheral/taskmanager_peripheral.h>
#include <taskmanager/taskmanager.h>
#include "fsl_gpt.h"

#include "core_cm33.h"


static volatile uint32_t ms_counter = 0;



void TASK_MANAGER_PERIPH_config(void)
{
//	gpt_timer_config_t timerConfig = {
//		.prescalerFactor = 225,
//	};
//
//	NVIC_EnableIRQ(GPT_IRQn);
//
//	GPT_Init(TIMERS, &timerConfig);
//	GPT_SetTimerMode(TIMERS, kGPT_Timer0, kGPT_TimerModeSingleFreeRunning);
//	GPT_EnableTimeoutInterrupt(TIMERS, kGPT_Timer0, true);
//
//	GPT_StartTimer(TIMERS, kGPT_Timer0, 200);


	SysTick->CTRL = 0x0;

	SysTick->LOAD = (uint32_t)(45000);

	SysTick->VAL = 0;

	SysTick->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_ENABLE_Msk;
}

uint32_t Sys_MS_counter_get(void)
{
	return ms_counter;
}

void TASK_MANAGER_PERIPH_deinit(void)
{

}

void GPT_IRQHandler(void)
{
	if (GPT_GetTimeoutStatus(TIMERS, kGPT_Timer0))
	{
		GPT_ClearTimeoutStatus(TIMERS, kGPT_Timer0);

		TASK_MANAGER_TIM_IRQ_handle();
	}
}

void SysTick_Handler(void)
{
	TASK_MANAGER_handle();

	// Increment system ms time counter
	ms_counter++;
}
