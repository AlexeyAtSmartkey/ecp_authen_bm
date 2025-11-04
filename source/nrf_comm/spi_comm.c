#include "spi_comm.h"
#include "spi_protocol.h"
#include "fsl_spi_gpdma.h"
#include "fsl_gpdma.h"
#include "fsl_gpio.h"

#define NRF_COMM_SPI_MASTER SPI
#define NRF_COMM_SPI_MASTER_IRQ SPI_IRQn
#define NRF_COMM_SPI_MASTER_CLK_FREQ CLOCK_GetSpiClkFreq(0)
#define NRF_COMM_SPI_SSEL 0
#define SPI_MASTER_IRQHandler SPI_IRQHandler
#define NRF_COMM_SPI_MASTER_TX_CHANNEL 2
#define NRF_COMM_SPI_MASTER_RX_CHANNEL 3
#define NRF_COMM_MASTER_SPI_SPOL kSPI_SpolActiveAllLow
#define NRF_COMM_GPDMA GPDMA

/* ===== Callbacks ===== */
void (*SpiErCallback)(void) = NULL;
void (*SpiRxCallback)(void) = NULL;
void (*SpiTxCallback)(void) = NULL;

gpdma_handle_t masterTxHandle;
gpdma_handle_t masterRxHandle;
spi_gpdma_handle_t masterHandle;

/* ===== Internals ===== */
static void SpiMasterCallback(SPI_Type *base, spi_gpdma_handle_t *handle, status_t status, void *userData) {
    if (status == kStatus_Success) {
        if (SpiStageIsRx()) {            // we're finishing the RX phase
            if (SpiRxCallback) SpiRxCallback();
        } else {                           // we're finishing the TX phase
            if (SpiTxCallback) SpiTxCallback();
        }
    } else {
        if (SpiErCallback) SpiErCallback();
    }
}

static void SpiGPIOCallback(void)
{
    if (SpiRxCallback) SpiRxCallback();
}

/* ===== Init ===== */
void SpiHwInit(void (*on_error)(void), void (*on_rx_done)(void), void (*on_tx_done)(void)) {
    SpiErCallback = on_error;
    SpiRxCallback = on_rx_done;
    SpiTxCallback = on_tx_done;

    gpio_pin_config_t gpioConfig = {kGPIO_DigitalInput, 0};
    GPIO_PinInit(kGPIO_GPIO1, &gpioConfig);
    GPIO_PinSetInterruptEdge(kGPIO_GPIO1, kGPIO_InterruptEdgeFalling);
    GPIO_RegisterCallback(kGPIO_GPIO1, SpiGPIOCallback);
    GPIO_PinEnableInterrupt(kGPIO_GPIO1, true);

    NVIC_ClearPendingIRQ(GPIO1_IRQn);
    NVIC_EnableIRQ(GPIO1_IRQn);

    uint32_t srcClock_Hz = NRF_COMM_SPI_MASTER_CLK_FREQ;
    spi_master_config_t masterConfig;
    SPI_MasterGetDefaultConfig(&masterConfig);
    masterConfig.sselNum = (spi_ssel_t)NRF_COMM_SPI_SSEL;
    masterConfig.sselPol = (spi_spol_t)NRF_COMM_MASTER_SPI_SPOL;
    SPI_MasterInit(NRF_COMM_SPI_MASTER, &masterConfig, srcClock_Hz);

    GPDMA_Init(NRF_COMM_GPDMA);
    GPDMA_CreateHandle(&masterTxHandle, NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_TX_CHANNEL);
    GPDMA_CreateHandle(&masterRxHandle, NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_RX_CHANNEL);
    GPDMA_SetChannelSourcePeripheral(NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_RX_CHANNEL, kGpdmaRequestMuxSpiMasterRx);
    GPDMA_SetChannelDestinationPeripheral(NRF_COMM_GPDMA, NRF_COMM_SPI_MASTER_TX_CHANNEL, kGpdmaRequestMuxSpiMasterTx);

    SPI_MasterTransferCreateHandleGPDMA(NRF_COMM_SPI_MASTER, &masterHandle, SpiMasterCallback, NULL, &masterTxHandle, &masterRxHandle);
}

/* ===== OTA Reinit ===== */
void SpiHwReinitForOta(void) {
    SPI_EnableTxDMA(NRF_COMM_SPI_MASTER, false);
    SPI_EnableRxDMA(NRF_COMM_SPI_MASTER, false);
    GPDMA_Deinit(NRF_COMM_GPDMA);
}

/* ===== Exchange ===== */
void SpiHwExchange(uint8_t *tx, uint8_t *rx, uint16_t len) {
    spi_transfer_t masterXfer;
    masterXfer.txData = tx;
    masterXfer.rxData = rx;
    masterXfer.dataSize = len;
    masterXfer.configFlags = kSPI_FrameAssert;
    SPI_MasterTransferGPDMA(NRF_COMM_SPI_MASTER, &masterHandle, &masterXfer);
}
