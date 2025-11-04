#ifndef EVX_WRITE_FLOW_H
#define EVX_WRITE_FLOW_H

#include <stdint.h>
#include <ph_Status.h>
#include "key_manager.h"
#include "device_manager.h"

/*
 * EVx write/provisioning helpers.
 * These wrap Authenticate(EV2), optional DES->AES migration,
 * and a "format -> create app -> create files -> write -> commit" flow.
 */

#ifdef __cplusplus
extern "C" {
#endif

// Structure containing card read parameters
#pragma pack(push, 1)
typedef struct _NFC_READ_PARAMS_ {
	uint8_t aid[3];
	uint16_t key_number;
	uint16_t key_version;
	uint8_t *key;
	uint8_t file_number;
	uint8_t data_offset[3];
	uint8_t data_length[3];

}NFC_READ_Params_t;
#pragma pack(pop)


/* Create + select app, authenticate, change App MK to NEW_AES128, end with EV2 session */
phStatus_t NFC_COMM_createApp(void * pAlMfdfEVx, uint16_t wKeyNo, uint16_t wKeyVer, uint8_t *aid);

/* Format PICC, create app/files, write payload, commit */
phStatus_t NFC_COMM_PICC_format_createAPP_write(uint8_t *data);

/* High-level entry: authenticate (with fallback), provision, write, and switch to reader mode */
phStatus_t MifareDESFireEVx_process(uint8_t *data, uint32_t data_len);

#ifdef __cplusplus
}
#endif

#endif /* EVX_WRITE_FLOW_H */
