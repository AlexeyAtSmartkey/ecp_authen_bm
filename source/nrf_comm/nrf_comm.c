
#include "nrf_comm.h"
#include "fsl_spi_gpdma.h"
#include "fsl_gpdma.h"
#include "fsl_gpio.h"

/*******************************************************************************
 * Definitions
 ******************************************************************************/
#define NRF_COMM_SPI_MASTER            	SPI
#define NRF_COMM_SPI_MASTER_IRQ        	SPI_IRQn
#define NRF_COMM_SPI_MASTER_CLK_FREQ   	CLOCK_GetSpiClkFreq(0)
#define NRF_COMM_SPI_SSEL              	0
#define SPI_MASTER_IRQHandler         	SPI_IRQHandler
#define NRF_COMM_SPI_MASTER_TX_CHANNEL 	2
#define NRF_COMM_SPI_MASTER_RX_CHANNEL 	3
#define NRF_COMM_MASTER_SPI_SPOL       	kSPI_SpolActiveAllLow
#define NRF_COMM_GPDMA                 	GPDMA

/*******************************************************************************
 * Prototypes
 ******************************************************************************/
static void NRF_COMM_SPI_MasterUserCallback(SPI_Type *base, spi_gpdma_handle_t *handle, status_t status, void *userData);

static void NRF_COMM_GPIO_UserCallback(void);

/*******************************************************************************
 * Variables
 ******************************************************************************/

// Error callback
void (*NRF_COMM_error_callback)(void) = NULL;
// Read complete callback
void (*NRF_COMM_read_cmplt_callback)(void) = NULL;
// Write complete callback
void (*NRF_COMM_write_cmplt_callback)(void) = NULL;

gpdma_handle_t masterTxHandle;
gpdma_handle_t masterRxHandle;

spi_gpdma_handle_t masterHandle;


/*******************************************************************************
 * Code
 ******************************************************************************/

static void NRF_COMM_SPI_MasterUserCallback(SPI_Type *base, spi_gpdma_handle_t *handle, status_t status, void *userData)
{
    if (status == kStatus_Success)
    {
    	NRF_COMM_write_cmplt_callback();
    }
    else
    {
    	NRF_COMM_error_callback();
    }
}

static void NRF_COMM_GPIO_UserCallback(void)
{
	NRF_COMM_read_cmplt_callback();
}

//-------------------------------------------------------------
void NRF_COMM_init(void (*error_callback)(void), void (*read_cmplt_callback)(void), void (*write_cmplt_callback)(void))
{

	NRF_COMM_error_callback = error_callback;
	NRF_COMM_read_cmplt_callback = read_cmplt_callback;
	NRF_COMM_write_cmplt_callback = write_cmplt_callback;

	// Init external interrupt GPIO
	gpio_pin_config_t gpioConfig;
	gpioConfig.pinDirection = kGPIO_DigitalInput;
	gpioConfig.outputLogic = 0;

	GPIO_PinInit(kGPIO_GPIO1, &gpioConfig);
	GPIO_PinSetInterruptEdge(kGPIO_GPIO1, kGPIO_InterruptEdgeFalling);
	GPIO_RegisterCallback(kGPIO_GPIO1, NRF_COMM_GPIO_UserCallback);
	GPIO_PinEnableInterrupt(kGPIO_GPIO1, true);

	// Clear pending & enable NVIC for GPIO1
	NVIC_ClearPendingIRQ(GPIO1_IRQn);
	NVIC_EnableIRQ(GPIO1_IRQn);


	// SPI init
	uint32_t srcClock_Hz = 0U;
	spi_master_config_t masterConfig;
	srcClock_Hz = NRF_COMM_SPI_MASTER_CLK_FREQ;

	SPI_MasterGetDefaultConfig(&masterConfig);
	masterConfig.sselNum = (spi_ssel_t)NRF_COMM_SPI_SSEL;
	masterConfig.sselPol = (spi_spol_t)NRF_COMM_MASTER_SPI_SPOL;
	SPI_MasterInit(NRF_COMM_SPI_MASTER, &masterConfig, srcClock_Hz);

	// GPDMA init
	GPDMA_Init(NRF_COMM_GPDMA);
	/* Configure the GPDMA handle and request source peripheral. */
	GPDMA_CreateHandle(&masterTxHandle, NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_TX_CHANNEL);
	GPDMA_CreateHandle(&masterRxHandle, NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_RX_CHANNEL);
	GPDMA_SetChannelSourcePeripheral(NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_RX_CHANNEL, kGpdmaRequestMuxSpiMasterRx);
	GPDMA_SetChannelDestinationPeripheral(NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_TX_CHANNEL, kGpdmaRequestMuxSpiMasterTx);

	// Set up handle for spi master
	SPI_MasterTransferCreateHandleGPDMA(NRF_COMM_SPI_MASTER, &masterHandle, NRF_COMM_SPI_MasterUserCallback, NULL,
										&masterTxHandle, &masterRxHandle);
}

//-------------------------------------------------------------
void NRF_COMM_reinitForOta(void)
{
	// Disable Tx and Rx DMA transfers
	SPI_EnableTxDMA(NRF_COMM_SPI_MASTER, false);
	SPI_EnableRxDMA(NRF_COMM_SPI_MASTER, false);

	// Deinit DMA
	GPDMA_Deinit(NRF_COMM_GPDMA);
}

//-------------------------------------------------------------
void NRF_COMM_DATA_exchange(uint8_t *tx_data, uint8_t *rx_data, uint16_t size)
{
	spi_transfer_t masterXfer;

	// Start master transfer
	masterXfer.txData      = tx_data;
	masterXfer.rxData      = rx_data;
	masterXfer.dataSize    = size;
	masterXfer.configFlags = kSPI_FrameAssert;

	SPI_MasterTransferGPDMA(NRF_COMM_SPI_MASTER, &masterHandle, &masterXfer);
}

