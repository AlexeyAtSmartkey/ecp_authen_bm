
#include <stdint.h>
#include "delay_ms.h"
#include "taskmanager.h"


//-------------------------------------------------------------
void delay_ms(uint32_t ms)
{
	uint32_t saved_ms_counter = 0;

	if(ms == 0)
		return;

	saved_ms_counter = Sys_MS_counter_get();

	while(1)
	{
		uint32_t current_ms_counter = Sys_MS_counter_get();
		uint32_t ms_interval;

		if(current_ms_counter < saved_ms_counter)
		{
			ms_interval = 0xFFFFFFFF - saved_ms_counter + current_ms_counter;
		}
		else
		{
			ms_interval = current_ms_counter - saved_ms_counter;
		}

		if(ms_interval >= ms)
			break;
	}
}
