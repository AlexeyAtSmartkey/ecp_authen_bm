
#ifndef _TASKMANAGER_H_
#define _TASKMANAGER_H_

#include <stdint.h>

#define NULL_TASK           		0

#define MAX_TASK_NUMBER     		5

#define TIME_TASK_NOT_CREATED		0x00
#define TIME_TASK_CREATED			0x01

#pragma pack(1)

typedef void (*taskFunc)(void);

typedef struct _TASK_struct
{
  taskFunc func;
  uint32_t period;
  uint32_t cntr;
}TASK_struct;

void TASK_MANAGER_init(void);

void TASK_MANAGER_deinit(void);

void TASK_MANAGER_run(void);

void TIME_TASK_create(taskFunc task, uint32_t period);

void TIME_TASK_delete(taskFunc task);

uint8_t TIME_TASK_check(taskFunc task);

void TASK_TABLE_FLAG_set(void);

void TASK_MANAGER_TEST_init(void);

void TASK_MANAGER_TEST_deinit(void);

void TASK_MANAGER_TIM_IRQ_handle(void);

void TASK_MANAGER_handle(void);

uint32_t Sys_MS_counter_get(void);

#endif
