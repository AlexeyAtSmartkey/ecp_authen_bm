
#ifndef _KEY_MANAGER_H_
#define _KEY_MANAGER_H_


typedef enum _KEY_TYPE_
{
	MASTER_KEY_PICC_DEFAULT,
	MASTER_KEY_PICC,
	APPLICATION_KEY_PICC,
	PICC_WRITE_KEY,
	APPLICATION_KEY_APPLE_PASS,
	ACCESSGRID_READ_KEY_ID
}KEY_Type_e;

typedef struct _KEY_PARAMS_
{
	uint8_t key_address;
	uint8_t key_version;
}KEY_Params_t;

#define PICC_MASTER_KEY			0
#define APP_MASTER_KEY			0


phStatus_t KEY_MANAGER_init(void);

KEY_Params_t *KEY_get(KEY_Type_e key_type);

uint8_t *TRANSACTION_MAC_KEY_get(void);


#endif // _KEY_MANAGER_H_
