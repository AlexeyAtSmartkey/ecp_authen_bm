

#include <phApp_Init.h>

#include "SmartLock.h"
#include "nfc_comm.h"
#include "nrf_comm_protocol.h"
#include "taskmanager.h"
#include "led_blinky.h"
#include "delay_ms.h"
#include "device_manager.h"

#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "NdefEx.h"

#include "PN76_Eeprom.h"
#include "PN76_ChipInfo.h"



void ANTENNA_POWER_config(void);
static void dump_clock_eeprom(void);

//-------------------------------------------------------------
int main (void) {
	BOARD_InitBootPins();
	BOARD_InitBootClocks();
	BOARD_InitDebugConsole();

	phhalHw_Pn76xx_Version_t v; uint8_t part; PN76_Sys_GetVersion(&v); PN76_Sys_GetPartId(&part);
	DEBUG_PRINTF("[PN76] FW v%u.%u (HW 0x%02X ROM 0x%02X)  Cut=%s (0x%02X)\n",
				v.wFW_Version>>8, v.wFW_Version&0xFF, v.bHw_Version, v.bROM_Version,
				(part==0x01?"C101":part==0x00?"C100":"?"), part);
	#ifdef PN7642EV_C101
		if (part != 0x01) {
			DEBUG_PRINTF("ERROR: This firmware is for PN7642 C101 only!\n");
			while(1);
		}
	#endif
	#ifdef PN7642EV_C100
		if (part != 0x00) {
			DEBUG_PRINTF("ERROR: This firmware is for PN7642 C100 only!\n");
			while(1);
		}
	#endif

	ANTENNA_POWER_config();

	dump_clock_eeprom();

	NFC_COMM_init();

	TASK_MANAGER_init();

	delay_ms(500);

	NRF_COMM_PROTOCOL_init();

	APP_InitMbedCrypto();
	APP_DeInitMbedCrypto();	

#ifdef LED_BLINK
	LED_BLINKY_init();
#endif

	while(1) {
		NFC_COMM_process();
		if (HeartbeatReceived) {
			HeartbeatReceived = 0;
			NRF_COMM_PROTOCOL_DATA_send(PN_HEART_BEAT_STATUS, (uint8_t *)DEVICE_STATUS_get(), sizeof(NFC_COMM_Status_t));// Send heart beat data request
		}
	}

	return 0;
}



// uint8_t pwr_mgm_regs[10];
// uint32_t EEPROM_result1 = 0, EEPROM_result2 = 0;

//-------------------------------------------------------------
void ANTENNA_POWER_config(void) {
#ifdef PN7642EV_C101
	uint8_t pwr_mgm_regs[10];
    PN76_ReadEeprom(pwr_mgm_regs, 0, 10, E_PN76_EEPROM_SECURE_LIB_CONFIG);
    if(pwr_mgm_regs[0] != 0x21) {
		pwr_mgm_regs[0] = 0x21;
    	PN76_WriteEeprom(&pwr_mgm_regs[0], 0x0000, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG);
    }
    if(pwr_mgm_regs[7] != 0x10) {
		pwr_mgm_regs[7] = 0x10;
		PN76_WriteEeprom(&pwr_mgm_regs[7], 0x0007, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG);
	}
    PN76_ReadEeprom(pwr_mgm_regs, 0, 10, E_PN76_EEPROM_SECURE_LIB_CONFIG);
#endif // PN7642EV_C101
}


static void dump_clock_eeprom(void){
    uint8_t v[4];
    PN76_ReadEeprom(&v[0], 0x000F, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG); // XTAL_CONFIG
    PN76_ReadEeprom(&v[1], 0x0010, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG); // XTAL_TIMEOUT
    PN76_ReadEeprom(&v[2], 0x0011, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG); // CLK_INPUT_FREQ
    PN76_ReadEeprom(&v[3], 0x0012, 1, E_PN76_EEPROM_SECURE_LIB_CONFIG); // XTAL_CHECK_DELAY
    DEBUG_PRINTF("EEP CLK: XTAL_CFG=%02X TIMEOUT=%02X CLK_IN=%02X CHECK=%02X\n",
                  v[0], v[1], v[2], v[3]);
}

