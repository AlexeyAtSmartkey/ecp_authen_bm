
#include <cr_section_macros.h>
#include "spi_comm.h"
#include "spi_protocol.h"
#include "fsl_spi.h"
#include <PN76_Flc.h>
#include "PN76_DL.h"
#include <cmsis_gcc.h>


#define OTA_SPI_MASTER            							SPI

#define OTA_FRAME_SIZE_BYTES								128

#define OTA_FRAME_RECEIVE_TICKS_DELAY						(uint32_t)(10000)


#define PH_CUSTOMER_ESFWU_PACKET_STORED_DEFUALT_ADD          0x00208000UL


// Function to request FW image frame
__TEXT(Flash2) void OTA_FRAME_REQUEST_send(uint16_t frame_number);

// Function to receive FW image frame
__TEXT(Flash2) uint8_t OTA_FRAME_receive(void);



uint8_t ota_tx_transfer_buf[9];
uint8_t ota_rx_transfer_buf[7 + 1 + OTA_FRAME_SIZE_BYTES]; // 7 bytes - protocol part, 1 byte - active bytes in frame, 128 bytes - frame data

uint32_t delay_cycles = 0;

// Total received image size
uint32_t ota_image_size = 0;

//-------------------------------------------------------------
//-------------------------------------------------------------
// OTA communication hold
//-------------------------------------------------------------
//-------------------------------------------------------------



//-------------------------------------------------------------
__TEXT(Flash2) void OTA_start(void)
//__RAMFUNC(RAM) void OTA_start(void)
{
	uint16_t frame_number = 0;
	uint32_t status = 0;
	uint32_t data_cntr = 0;
	uint32_t flash_write_addr = 0x00208000;


	// Disable all interrupts
	__disable_irq();

	// Reconfig SPI to work in polling mode
	SpiHwReinitForOta();

	// Wait for some ms
	delay_cycles = 0;
	while(++delay_cycles < OTA_FRAME_RECEIVE_TICKS_DELAY);

	// Start infinite loop for data loading
	while(1)
	{
		// Request frame
		OTA_FRAME_REQUEST_send(frame_number);

		// Wait for some ms
		delay_cycles = 0;
		while(++delay_cycles < OTA_FRAME_RECEIVE_TICKS_DELAY);

		// Check received frame
		if(OTA_FRAME_receive() != 0)
		{
			// Repeat request
			continue;
		}

		// Write frame to flash
		status = PN76_Flc_WriteBuffer(&ota_rx_transfer_buf[6], (uint8_t *)flash_write_addr, OTA_FRAME_SIZE_BYTES);

		// Increase address
		flash_write_addr = flash_write_addr + OTA_FRAME_SIZE_BYTES;

		// Check if number of active bytes in received frame is less than frame size
		if(ota_rx_transfer_buf[5] < OTA_FRAME_SIZE_BYTES)
		{
			// Send frame number 0xFFFF to signalize NRF that all frames have been received
			OTA_FRAME_REQUEST_send(0xFFFF);

			// Increase OTA image size
			ota_image_size = ota_image_size + ota_rx_transfer_buf[5];

			// Run IAP
			(void) PN76_EDL_IAP_Init( (uint32_t) PH_CUSTOMER_ESFWU_PACKET_STORED_DEFUALT_ADD, ota_image_size);

			return;
		}

		// Increase OTA image size
		ota_image_size = ota_image_size + OTA_FRAME_SIZE_BYTES;

		frame_number++;

		// Wait for some ms
		delay_cycles = 0;
		while(++delay_cycles < OTA_FRAME_RECEIVE_TICKS_DELAY);
	}
}

//-------------------------------------------------------------
void OTA_FRAME_REQUEST_send(uint16_t frame_number)
{
	spi_transfer_t xfer;
	uint8_t idx = 0;


	// Prepare data to send
	idx = 0;

	// Add header
	*((uint16_t *)&ota_tx_transfer_buf[idx]) = PN_COMM_PROTOCOL_HEADER;
	idx += 2;

	// Add size
	*((uint16_t *)&ota_tx_transfer_buf[idx]) = sizeof(frame_number) + 3;
	idx += 2;

	// Add cmd
	ota_tx_transfer_buf[idx] = PN_OTA_UPDATE;
	idx += 1;

	// Add frame number to request
	*((uint16_t *)&ota_tx_transfer_buf[idx]) = frame_number;
	idx += 2;

	// Add crc16
	*((uint16_t *)&ota_tx_transfer_buf[idx]) = Crc16Modbus(ota_tx_transfer_buf, idx);


	// Send frame request
	xfer.txData      = ota_tx_transfer_buf;
	xfer.rxData      = ota_tx_transfer_buf;
	xfer.dataSize    = sizeof(ota_tx_transfer_buf);
	xfer.configFlags = kSPI_FrameAssert;
	SPI_MasterTransferBlocking(OTA_SPI_MASTER, &xfer);
}

//-------------------------------------------------------------
__TEXT(Flash2) uint8_t OTA_FRAME_receive(void)
{
	spi_transfer_t xfer;
	uint16_t frame_number = 0;

	// Receive data
	xfer.txData      = ota_rx_transfer_buf;
	xfer.rxData      = ota_rx_transfer_buf;
	xfer.dataSize    = sizeof(ota_rx_transfer_buf);
	xfer.configFlags = kSPI_FrameAssert;
	SPI_MasterTransferBlocking(OTA_SPI_MASTER, &xfer);

	// Process received data

	// Check header, size and crc
	if((*((uint16_t *)&ota_rx_transfer_buf[0]) != PN_COMM_PROTOCOL_HEADER) ||
			(*((uint16_t *)&ota_rx_transfer_buf[2]) != (sizeof(ota_rx_transfer_buf) - 4)) ||
			(*((uint16_t *)&ota_rx_transfer_buf[sizeof(ota_rx_transfer_buf) - 2]) != Crc16Modbus(ota_rx_transfer_buf, sizeof(ota_rx_transfer_buf) - 2)))
	{
		return 1;
	}

	return 0;
}

