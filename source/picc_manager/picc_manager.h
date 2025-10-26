
#ifndef _PICC_MANAGER_H_
#define _PICC_MANAGER_H_

#include <ph_Status.h>

phStatus_t PICC_DATA_read(void *pDataParams);

void PICC_DATA_TO_WRITE_set(uint8_t *data);

#endif // _PICC_MANAGER_H_
