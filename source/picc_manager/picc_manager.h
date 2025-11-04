
#ifndef _PICC_MANAGER_H_
#define _PICC_MANAGER_H_

#include <ph_Status.h>

extern uint8_t PCDcap2[6];
extern uint8_t PCDcap2In[6];
extern uint8_t PDcap2In[6];


phStatus_t PICC_DATA_read(void *pDataParams);

void PICC_DATA_TO_WRITE_set(uint8_t *data);
void PICC_DATA_TO_WRITE_get(uint8_t **data, uint16_t *length);

#endif // _PICC_MANAGER_H_
