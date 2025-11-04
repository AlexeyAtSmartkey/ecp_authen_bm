
#ifndef _KEY_MANAGER_H_
#define _KEY_MANAGER_H_


#define DES_KEY_ADDRESS                             1U      /* PICC Key entry number in key store. */
#define DES_KEY_VERSION                             00      /* PICC Key entry number in key store. */
#define DES_KEY_POS                                 00      /* PICC Key entry Position in keystore */

#define AES128_KEY_ADDRESS      					3U
#define AES128_KEY_VERSION      					00
#define AES128_KEY_POS          					16U

#define PICC_AES128_KEY_ADDRESS  					4U
#define PICC_AES128_KEY_VERSION  					1U
#define PICC_AES128_KEY_POS      					17U

#define APPLE_PASS_AES128_KEY_ADDRESS				5U
#define APPLE_PASS_AES128_KEY_VERSION				1U
#define APPLE_PASS_AES128_KEY_POS					18U

#define APPLE_PASS_APP2_AES128_KEY_1_ADDRESS		6U
#define APPLE_PASS_APP2_AES128_KEY_1_VERSION		0U
#define APPLE_PASS_APP2_AES128_KEY_1_POS			19U

#define APPLE_PASS_APP2_AES128_KEY_2_ADDRESS		7U
#define APPLE_PASS_APP2_AES128_KEY_2_VERSION		0U
#define APPLE_PASS_APP2_AES128_KEY_2_POS			20U

typedef enum _KEY_TYPE_ {
	MASTER_KEY_PICC_DEFAULT,
	MASTER_KEY_PICC,
	APPLICATION_KEY_PICC,
	PICC_WRITE_KEY,
	APPLICATION_KEY_APPLE_PASS,
	ACCESSGRID_READ_KEY_ID,
} KEY_Type_e;

typedef struct _KEY_PARAMS_
{
	uint8_t keyno;
	uint8_t version;
	uint8_t position;
	uint8_t *key;
} KEY_Params_t;

#define PICC_MASTER_KEY 0
#define APP_MASTER_KEY  0

void* getKeyStore(void);
phStatus_t KEY_MANAGER_init(void);
KEY_Params_t *KEY_get(KEY_Type_e key_type);
uint8_t *TRANSACTION_MAC_KEY_get(void);

#endif // _KEY_MANAGER_H_
