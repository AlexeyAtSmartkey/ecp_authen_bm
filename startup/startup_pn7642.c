//*****************************************************************************
// PN7642 startup code for use with MCUXpresso IDE
//
// Version : 250423
//*****************************************************************************
//
// Copyright 2016-2023 NXP
// All rights reserved.
//
// SPDX-License-Identifier: BSD-3-Clause
//*****************************************************************************

#if defined (DEBUG)
#pragma GCC push_options
#pragma GCC optimize ("Og")
#endif // (DEBUG)

#if defined (__cplusplus)
#ifdef __REDLIB__
#error Redlib does not support C++
#else
//*****************************************************************************
//
// The entry point for the C++ library startup
//
//*****************************************************************************
extern "C" {
    extern void __libc_init_array(void);
}
#endif
#endif

#define WEAK __attribute__ ((weak))
#define WEAK_AV __attribute__ ((weak, section(".after_vectors")))
#define ALIAS(f) __attribute__ ((weak, alias (#f)))

//*****************************************************************************
#if defined (__cplusplus)
extern "C" {
#endif

//*****************************************************************************
// Variable to store CRP value in. Will be placed automatically
// by the linker when "Enable Code Read Protect" selected.
// See crp.h header for more information
//*****************************************************************************
//*****************************************************************************
// Declaration of external SystemInit function
//*****************************************************************************
#if defined (__USE_CMSIS)
extern void SystemInit(void);
#endif // (__USE_CMSIS)
extern void SystemCheckBoot(void);

//*****************************************************************************
// Forward declaration of the core exception handlers.
// When the application defines a handler (with the same name), this will
// automatically take precedence over these weak definitions.
// If your application is a C++ one, then any interrupt handlers defined
// in C++ files within in your main application will need to have C linkage
// rather than C++ linkage. To do this, make sure that you are using extern "C"
// { .... } around the interrupt handler within your main application code.
//*****************************************************************************
     void ResetISR(void);
WEAK void NMI_Handler(void);
WEAK void HardFault_Handler(void);
WEAK void MemManage_Handler(void);
WEAK void BusFault_Handler(void);
WEAK void UsageFault_Handler(void);
WEAK void SecureFault_Handler(void);
WEAK void SVC_Handler(void);
WEAK void DebugMon_Handler(void);
WEAK void PendSV_Handler(void);
WEAK void SysTick_Handler(void);
WEAK void IntDefaultHandler(void);

//*****************************************************************************
// Forward declaration of the application IRQ handlers. When the application
// defines a handler (with the same name), this will automatically take
// precedence over weak definitions below
//*****************************************************************************
WEAK void GPT_IRQHandler(void);
WEAK void BMA_IRQHandler(void);
WEAK void Reserved18_IRQHandler(void);
WEAK void CLIF_IRQHandler(void);
WEAK void SECURE4_IRQHandler(void);
WEAK void SECURE5_IRQHandler(void);
WEAK void GPDMA_IRQHandler(void);
WEAK void PCRM_IRQHandler(void);
WEAK void Reserved24_IRQHandler(void);
WEAK void HOSTIF_IRQHandler(void);
WEAK void SECURE10_IRQHandler(void);
WEAK void SECURE11_IRQHandler(void);
WEAK void SECURE12_IRQHandler(void);
WEAK void Reserved29_IRQHandler(void);
WEAK void Reserved30_IRQHandler(void);
WEAK void Reserved31_IRQHandler(void);
WEAK void Reserved32_IRQHandler(void);
WEAK void SECURE17_IRQHandler(void);
WEAK void I2C_IRQHandler(void);
WEAK void SPI_IRQHandler(void);
WEAK void SPI_FIFO_IRQHandler(void);
WEAK void SECURE21_IRQHandler(void);
WEAK void SECURE22_IRQHandler(void);
WEAK void SECURE23_IRQHandler(void);
WEAK void CT_IRQHandler(void);
WEAK void USB_IRQHandler(void);
WEAK void SCT_IRQHandler(void);
WEAK void Reserved43_IRQHandler(void);
WEAK void LPUART_RX_IRQHandler(void);
WEAK void LPUART_TX_IRQHandler(void);
WEAK void Reserved46_IRQHandler(void);
WEAK void GPIO0_IRQHandler(void);
WEAK void GPIO1_IRQHandler(void);
WEAK void GPIO2_IRQHandler(void);
WEAK void GPIO3_IRQHandler(void);
WEAK void GPIO_IRQHandler(void);
WEAK void Reserved52_IRQHandler(void);
WEAK void USB_VBUS_IRQHandler(void);
WEAK void Reserved54_IRQHandler(void);
WEAK void Reserved55_IRQHandler(void);
WEAK void Reserved56_IRQHandler(void);
WEAK void Reserved57_IRQHandler(void);
WEAK void SECURE42_IRQHandler(void);
WEAK void SECURE43_IRQHandler(void);
WEAK void SECURE44_IRQHandler(void);
WEAK void SECURE45_IRQHandler(void);

//*****************************************************************************
// Forward declaration of the driver IRQ handlers. These are aliased
// to the IntDefaultHandler, which is a 'forever' loop. When the driver
// defines a handler (with the same name), this will automatically take
// precedence over these weak definitions
//*****************************************************************************
void GPT_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void BMA_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved18_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void CLIF_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE4_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE5_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPDMA_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void PCRM_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved24_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void HOSTIF_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE10_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE11_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE12_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved29_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved30_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved31_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved32_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE17_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void I2C_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SPI_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SPI_FIFO_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE21_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE22_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE23_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void CT_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void USB_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SCT_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved43_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void LPUART_RX_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void LPUART_TX_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved46_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPIO0_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPIO1_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPIO2_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPIO3_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void GPIO_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved52_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void USB_VBUS_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved54_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved55_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved56_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void Reserved57_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE42_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE43_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE44_DriverIRQHandler(void) ALIAS(IntDefaultHandler);
void SECURE45_DriverIRQHandler(void) ALIAS(IntDefaultHandler);

//*****************************************************************************
// The entry point for the application.
// __main() is the entry point for Redlib based applications
// main() is the entry point for Newlib based applications
//*****************************************************************************
#if defined (__REDLIB__)
extern void __main(void);
#endif
extern int main(void);

//*****************************************************************************
// External declaration for the pointer to the stack top from the Linker Script
//*****************************************************************************
extern void _vStackTop(void);
extern void _vStackBase(void);
//*****************************************************************************
#if defined (__cplusplus)
} // extern "C"
#endif
//*****************************************************************************
// The vector table.
// This relies on the linker script to place at correct location in memory.
//*****************************************************************************

extern void (* const g_pfnVectors[])(void);
extern void * __Vectors __attribute__ ((alias ("g_pfnVectors")));

__attribute__ ((used, section(".isr_vector")))
void (* const g_pfnVectors[])(void) = {
    // Core Level - CM33
    &_vStackTop,                       // The initial stack pointer
    ResetISR,                          // The reset handler
    NMI_Handler,                       // NMI Handler
    HardFault_Handler,                 // Hard Fault Handler
    MemManage_Handler,                 // MPU Fault Handler
    BusFault_Handler,                  // Bus Fault Handler
    UsageFault_Handler,                // Usage Fault Handler
    SecureFault_Handler,               // Secure Fault Handler
    0,                                 // Reserved
    0,                                 // Reserved
    0,                                 // Reserved
    SVC_Handler,                       // SVCall Handler
    DebugMon_Handler,                  // Debug Monitor Handler
    0,                                 // Reserved
    PendSV_Handler,                    // PendSV Handler
    SysTick_Handler,                   // SysTick Handler

    // Chip Level - PN7642
    GPT_IRQHandler,          // 16: General Purpose Timers
    BMA_IRQHandler,          // 17: Buffer Mapping/Arbitration Unit
    Reserved18_IRQHandler,   // 18: Reserved interrupt
    CLIF_IRQHandler,         // 19: Contactless Interface
    SECURE4_IRQHandler,      // 20: Not available to non-secure state, secure interrupt 4
    SECURE5_IRQHandler,      // 21: Not available to non-secure state, secure interrupt 5
    GPDMA_IRQHandler,        // 22: Non-secure DMA
    PCRM_IRQHandler,         // 23: Power, Clock, Reset Management Unit
    Reserved24_IRQHandler,   // 24: Reserved interrupt
    HOSTIF_IRQHandler,       // 25: Host Interface Module
    SECURE10_IRQHandler,     // 26: Not available to non-secure state, secure interrupt 10
    SECURE11_IRQHandler,     // 27: Not available to non-secure state, secure interrupt 11
    SECURE12_IRQHandler,     // 28: Not available to non-secure state, secure interrupt 12
    Reserved29_IRQHandler,   // 29: Reserved interrupt
    Reserved30_IRQHandler,   // 30: Reserved interrupt
    Reserved31_IRQHandler,   // 31: Reserved interrupt
    Reserved32_IRQHandler,   // 32: Reserved interrupt
    SECURE17_IRQHandler,     // 33: Not available to non-secure state, secure interrupt 17
    I2C_IRQHandler,          // 34: I2C Master Interface
    SPI_IRQHandler,          // 35: SPI Master Interface
    SPI_FIFO_IRQHandler,     // 36: SPI Master FIFO Interrupt
    SECURE21_IRQHandler,     // 37: Not available to non-secure state, secure interrupt 21
    SECURE22_IRQHandler,     // 38: Not available to non-secure state, secure interrupt 22
    SECURE23_IRQHandler,     // 39: Not available to non-secure state, secure interrupt 23
    CT_IRQHandler,           // 40: Contact Interface Unit
    USB_IRQHandler,          // 41: USB
    SCT_IRQHandler,          // 42: SCTimer/PWM
    Reserved43_IRQHandler,   // 43: Reserved interrupt
    LPUART_RX_IRQHandler,    // 44: LP UART RX
    LPUART_TX_IRQHandler,    // 45: LP UART TX
    Reserved46_IRQHandler,   // 46: Reserved interrupt
    GPIO0_IRQHandler,        // 47: Power, Clock, Reset Management Unit: GPIO0
    GPIO1_IRQHandler,        // 48: Power, Clock, Reset Management Unit: GPIO1
    GPIO2_IRQHandler,        // 49: Power, Clock, Reset Management Unit: GPIO2
    GPIO3_IRQHandler,        // 50: Power, Clock, Reset Management Unit: GPIO3
    GPIO_IRQHandler,         // 51: Power, Clock, Reset Management Unit: GPIO Common
    Reserved52_IRQHandler,   // 52: Reserved interrupt
    USB_VBUS_IRQHandler,     // 53: Power, Clock, Reset Management Unit: USB_VBUS Monitor
    Reserved54_IRQHandler,   // 54: Reserved interrupt
    Reserved55_IRQHandler,   // 55: Reserved interrupt
    Reserved56_IRQHandler,   // 56: Reserved interrupt
    Reserved57_IRQHandler,   // 57: Reserved interrupt
    SECURE42_IRQHandler,     // 58: Not available to non-secure state, secure interrupt 42
    SECURE43_IRQHandler,     // 59: Not available to non-secure state, secure interrupt 43
    SECURE44_IRQHandler,     // 60: Not available to non-secure state, secure interrupt 44
    SECURE45_IRQHandler,     // 61: Not available to non-secure state, secure interrupt 45
    IntDefaultHandler,        // 62
    IntDefaultHandler,        // 63
    (void (* const)(void))0x00000100UL,             //Upper 2 bytes 0x0000 --> Major FW Version 0.0 , lower 2 bytes 0x0100 --> Minor FW Version 1.0
    (void (* const)(void))0xFFFFFEFFUL              //Inverse of FW version.
}; /* End of g_pfnVectors */

//*****************************************************************************
// Functions to carry out the initialization of RW and BSS data sections. These
// are written as separate functions rather than being inlined within the
// ResetISR() function in order to cope with MCUs with multiple banks of
// memory.
//*****************************************************************************
__attribute__ ((section(".after_vectors.init_data")))
void data_init(unsigned int romstart, unsigned int start, unsigned int len) {
    unsigned int *pulDest = (unsigned int*) start;
    unsigned int *pulSrc = (unsigned int*) romstart;
    unsigned int loop;
    for (loop = 0; loop < len; loop = loop + 4)
        *pulDest++ = *pulSrc++;
}

__attribute__ ((section(".after_vectors.init_bss")))
void bss_init(unsigned int start, unsigned int len) {
    unsigned int *pulDest = (unsigned int*) start;
    unsigned int loop;
    for (loop = 0; loop < len; loop = loop + 4)
        *pulDest++ = 0;
}

//*****************************************************************************
// The following symbols are constructs generated by the linker, indicating
// the location of various points in the "Global Section Table". This table is
// created by the linker via the Code Red managed linker script mechanism. It
// contains the load address, execution address and length of each RW data
// section and the execution and length of each BSS (zero initialized) section.
//*****************************************************************************
extern unsigned int __data_section_table;
extern unsigned int __data_section_table_end;
extern unsigned int __bss_section_table;
extern unsigned int __bss_section_table_end;

//*****************************************************************************
// Reset entry point for your code.
// Sets up a simple runtime environment and initializes the C/C++
// library.
//*****************************************************************************
__attribute__ ((naked, section(".after_vectors.reset")))
void ResetISR(void) {
    // Disable interrupts
    __asm volatile ("cpsid i");
    // Config VTOR & MSPLIM register
    __asm volatile ("MOV R3, R0\t\n"
                    "LDR R0, =0xE000ED08\t\n"
                    "LDR R1, =g_pfnVectors\t\n"
                    "STR R1, [R0]\t\n"
                    "LDR R2, [R1]\t\n"
                    "MSR MSP, R2\t\n"
                    "LDR R0, =_vStackBase\t\n"
                    "MSR MSPLIM, R0\t\n"
                    "PUSH {R3}\t\n");  // Save the boot status

#if defined (__USE_CMSIS)
// If __USE_CMSIS defined, then call CMSIS SystemInit code
    SystemInit();

#endif // (__USE_CMSIS)
// Restore the boot status
    __asm volatile ("POP {R0}");
// Check boot status
    SystemCheckBoot();

    //
    // Copy the data sections from flash to SRAM.
    //
    unsigned int LoadAddr, ExeAddr, SectionLen;
    unsigned int *SectionTableAddr;

    // Load base address of Global Section Table
    SectionTableAddr = &__data_section_table;

    // Copy the data sections from flash to SRAM.
    while (SectionTableAddr < &__data_section_table_end) {
        LoadAddr = *SectionTableAddr++;
        ExeAddr = *SectionTableAddr++;
        SectionLen = *SectionTableAddr++;
        data_init(LoadAddr, ExeAddr, SectionLen);
    }

    // At this point, SectionTableAddr = &__bss_section_table;
    // Zero fill the bss segment
    while (SectionTableAddr < &__bss_section_table_end) {
        ExeAddr = *SectionTableAddr++;
        SectionLen = *SectionTableAddr++;
        bss_init(ExeAddr, SectionLen);
    }

#if !defined (__USE_CMSIS)
// Assume that if __USE_CMSIS defined, then CMSIS SystemInit code
// will setup the VTOR register

    // Check to see if we are running the code from a non-zero
    // address (eg RAM, external flash), in which case we need
    // to modify the VTOR register to tell the CPU that the
    // vector table is located at a non-0x0 address.
    unsigned int * pSCB_VTOR = (unsigned int *) 0xE000ED08;
    if ((unsigned int *)g_pfnVectors!=(unsigned int *) 0x00000000) {
        *pSCB_VTOR = (unsigned int)g_pfnVectors;
    }
#endif // (__USE_CMSIS)
#if defined (__cplusplus)
    //
    // Call C++ library initialisation
    //
    __libc_init_array();
#endif

    // Reenable interrupts
    __asm volatile ("cpsie i");

#if defined (__REDLIB__)
    // Call the Redlib library, which in turn calls main()
    __main();
#else
    main();
#endif

    //
    // main() shouldn't return, but if it does, we'll just enter an infinite loop
    //
    while (1) {
        ;
    }
}

//*****************************************************************************
// Default core exception handlers. Override the ones here by defining your own
// handler routines in your application code.
//*****************************************************************************
WEAK_AV void NMI_Handler(void)
{ while(1) {}
}

WEAK_AV void HardFault_Handler(void)
{ while(1) {}
}

WEAK_AV void MemManage_Handler(void)
{ while(1) {}
}

WEAK_AV void BusFault_Handler(void)
{ while(1) {}
}

WEAK_AV void UsageFault_Handler(void)
{ while(1) {}
}

WEAK_AV void SecureFault_Handler(void)
{ while(1) {}
}

WEAK_AV void SVC_Handler(void)
{ while(1) {}
}

WEAK_AV void DebugMon_Handler(void)
{ while(1) {}
}

WEAK_AV void PendSV_Handler(void)
{ while(1) {}
}

WEAK_AV void SysTick_Handler(void)
{ while(1) {}
}

//*****************************************************************************
// Processor ends up here if an unexpected interrupt occurs or a specific
// handler is not present in the application code.
//*****************************************************************************
WEAK_AV void IntDefaultHandler(void)
{ while(1) {}
}

//*****************************************************************************
// Default application exception handlers. Override the ones here by defining
// your own handler routines in your application code. These routines call
// driver exception handlers or IntDefaultHandler() if no driver exception
// handler is included.
//*****************************************************************************
WEAK void GPT_IRQHandler(void)
{   GPT_DriverIRQHandler();
}

WEAK void BMA_IRQHandler(void)
{   BMA_DriverIRQHandler();
}

WEAK void Reserved18_IRQHandler(void)
{   Reserved18_DriverIRQHandler();
}

WEAK void CLIF_IRQHandler(void)
{   CLIF_DriverIRQHandler();
}

WEAK void SECURE4_IRQHandler(void)
{   SECURE4_DriverIRQHandler();
}

WEAK void SECURE5_IRQHandler(void)
{   SECURE5_DriverIRQHandler();
}

WEAK void GPDMA_IRQHandler(void)
{   GPDMA_DriverIRQHandler();
}

WEAK void PCRM_IRQHandler(void)
{   PCRM_DriverIRQHandler();
}

WEAK void Reserved24_IRQHandler(void)
{   Reserved24_DriverIRQHandler();
}

WEAK void HOSTIF_IRQHandler(void)
{   HOSTIF_DriverIRQHandler();
}

WEAK void SECURE10_IRQHandler(void)
{   SECURE10_DriverIRQHandler();
}

WEAK void SECURE11_IRQHandler(void)
{   SECURE11_DriverIRQHandler();
}

WEAK void SECURE12_IRQHandler(void)
{   SECURE12_DriverIRQHandler();
}

WEAK void Reserved29_IRQHandler(void)
{   Reserved29_DriverIRQHandler();
}

WEAK void Reserved30_IRQHandler(void)
{   Reserved30_DriverIRQHandler();
}

WEAK void Reserved31_IRQHandler(void)
{   Reserved31_DriverIRQHandler();
}

WEAK void Reserved32_IRQHandler(void)
{   Reserved32_DriverIRQHandler();
}

WEAK void SECURE17_IRQHandler(void)
{   SECURE17_DriverIRQHandler();
}

WEAK void I2C_IRQHandler(void)
{   I2C_DriverIRQHandler();
}

WEAK void SPI_IRQHandler(void)
{   SPI_DriverIRQHandler();
}

WEAK void SPI_FIFO_IRQHandler(void)
{   SPI_FIFO_DriverIRQHandler();
}

WEAK void SECURE21_IRQHandler(void)
{   SECURE21_DriverIRQHandler();
}

WEAK void SECURE22_IRQHandler(void)
{   SECURE22_DriverIRQHandler();
}

WEAK void SECURE23_IRQHandler(void)
{   SECURE23_DriverIRQHandler();
}

WEAK void CT_IRQHandler(void)
{   CT_DriverIRQHandler();
}

WEAK void USB_IRQHandler(void)
{   USB_DriverIRQHandler();
}

WEAK void SCT_IRQHandler(void)
{   SCT_DriverIRQHandler();
}

WEAK void Reserved43_IRQHandler(void)
{   Reserved43_DriverIRQHandler();
}

WEAK void LPUART_RX_IRQHandler(void)
{   LPUART_RX_DriverIRQHandler();
}

WEAK void LPUART_TX_IRQHandler(void)
{   LPUART_TX_DriverIRQHandler();
}

WEAK void Reserved46_IRQHandler(void)
{   Reserved46_DriverIRQHandler();
}

WEAK void GPIO0_IRQHandler(void)
{   GPIO0_DriverIRQHandler();
}

WEAK void GPIO1_IRQHandler(void)
{   GPIO1_DriverIRQHandler();
}

WEAK void GPIO2_IRQHandler(void)
{   GPIO2_DriverIRQHandler();
}

WEAK void GPIO3_IRQHandler(void)
{   GPIO3_DriverIRQHandler();
}

WEAK void GPIO_IRQHandler(void)
{   GPIO_DriverIRQHandler();
}

WEAK void Reserved52_IRQHandler(void)
{   Reserved52_DriverIRQHandler();
}

WEAK void USB_VBUS_IRQHandler(void)
{   USB_VBUS_DriverIRQHandler();
}

WEAK void Reserved54_IRQHandler(void)
{   Reserved54_DriverIRQHandler();
}

WEAK void Reserved55_IRQHandler(void)
{   Reserved55_DriverIRQHandler();
}

WEAK void Reserved56_IRQHandler(void)
{   Reserved56_DriverIRQHandler();
}

WEAK void Reserved57_IRQHandler(void)
{   Reserved57_DriverIRQHandler();
}

WEAK void SECURE42_IRQHandler(void)
{   SECURE42_DriverIRQHandler();
}

WEAK void SECURE43_IRQHandler(void)
{   SECURE43_DriverIRQHandler();
}

WEAK void SECURE44_IRQHandler(void)
{   SECURE44_DriverIRQHandler();
}

WEAK void SECURE45_IRQHandler(void)
{   SECURE45_DriverIRQHandler();
}

//*****************************************************************************

#if defined (DEBUG)
#pragma GCC pop_options
#endif // (DEBUG)
