
#include <taskmanager/peripheral/taskmanager_peripheral.h>
#include <taskmanager/taskmanager.h>
#include <stdint.h>

//#define TASK_MANAGER_TEST_RUN

TASK_struct TaskTable[MAX_TASK_NUMBER];

TASK_struct EMPTY_task = {NULL_TASK, NULL_TASK, NULL_TASK};

uint8_t task_index = 0;

void TASK_TABLE_init(void);

uint8_t TASK_TABLE_CHECK_Flag = 0;

void TASK_MANAGER_init(void)
{
    // Initialize task table
    TASK_TABLE_init();
    
    // Initialize timer and test GPIO
    TASK_MANAGER_PERIPH_config();

#ifdef TASK_MANAGER_TEST_RUN
    // Run LED blink task to test task manager timings
    TASK_MANAGER_TEST_init();
#endif
}

void TASK_MANAGER_deinit(void)
{
    // Delete LED blink task to test task manager timings
#ifdef TASK_MANAGER_TEST_RUN
    TASK_MANAGER_TEST_deinit();
#endif

    // Stop timer
    TASK_MANAGER_PERIPH_deinit();

    // Clear task table
    TASK_TABLE_init();
}

void TASK_TABLE_init(void)
{
	uint8_t i;

	for(i = 0; i < MAX_TASK_NUMBER; i++)
	{
		TaskTable[i] = EMPTY_task;
	}
}

void TASK_MANAGER_run(void)
{
    uint8_t i;

    if(TASK_TABLE_CHECK_Flag)
    {
        TASK_TABLE_CHECK_Flag = 0;

        for(i = 0; i < MAX_TASK_NUMBER; i++)
        {
            if(TaskTable[i].func != NULL_TASK)
            {
                if(++TaskTable[i].cntr >= TaskTable[i].period)
                {
                    (*TaskTable[i].func)();
                    TaskTable[i].cntr = 0;
                }
            }
        }
    }
}

void TIME_TASK_create(taskFunc task, uint32_t period)
{
  uint8_t i;
  
  //__disable_irq();
  
  for(i = 0; i < MAX_TASK_NUMBER; i++)
  {
    if(TaskTable[i].func == task)
    {
      //__enable_irq();
      return;
    }
  }
  
  for(i = 0; i < MAX_TASK_NUMBER; i++)
  {
    if(TaskTable[i].func == NULL_TASK)
    {
      TaskTable[i].func = task;
      TaskTable[i].period = period;
      TaskTable[i].cntr = 0;
      
      //__enable_irq();
      return;
    }
  }
  //__enable_irq();
}

void TIME_TASK_delete(taskFunc task)
{
    uint8_t i;
    
    //__disable_irq();
    
    for(i = 0; i < MAX_TASK_NUMBER; i++)
    {
        if(TaskTable[i].func == task)
        {
            TaskTable[i] = EMPTY_task;
            
            //__enable_irq();
            return;
        }
    }
    
    //__enable_irq();
}

uint8_t TIME_TASK_check(taskFunc task)
{
    uint8_t i;

    for(i = 0; i < MAX_TASK_NUMBER; i++)
    {
        if(TaskTable[i].func == task)
        {
            return TIME_TASK_CREATED;
        }
    }

    return TIME_TASK_NOT_CREATED;
}

void TASK_MANAGER_TIM_IRQ_handle(void)
{
	TASK_TABLE_CHECK_Flag = 1;
}


void TASK_MANAGER_handle(void)
{
	for(uint8_t i = 0; i < MAX_TASK_NUMBER; i++)
	{
		if(TaskTable[i].func != NULL_TASK)
		{
			if(++TaskTable[i].cntr >= TaskTable[i].period)
			{
				(*TaskTable[i].func)();
				TaskTable[i].cntr = 0;
			}
		}
	}
}
