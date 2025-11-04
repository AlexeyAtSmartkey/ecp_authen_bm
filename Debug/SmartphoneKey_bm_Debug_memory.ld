/*
 * GENERATED FILE - DO NOT EDIT
 * Copyright 2008-2013 Code Red Technologies Ltd,
 * Copyright 2013-2025 NXP
 * SPDX-License-Identifier: BSD-3-Clause
 * Generated linker script file for PN7642
 * Created from memory.ldt by FMCreateLinkMemory
 * Using Freemarker v2.3.30
 * MCUXpresso IDE v24.12 [Build 148] [2025-01-10] on Jul 21, 2025, 8:28:46 PM
 */

MEMORY
{
  /* Define each memory region */
  PROGRAM_FLASH (rx) : ORIGIN = 0x208000, LENGTH = 0x2b000 /* 172K bytes (alias Flash) */  
  OTA_FLASF (rx) : ORIGIN = 0x233000, LENGTH = 0x2000 /* 8K bytes (alias Flash2) */  
  SRAM (rwx) : ORIGIN = 0x20003000, LENGTH = 0x5000 /* 20K bytes (alias RAM) */  
  AO_SRAM (rwx) : ORIGIN = 0x20008000, LENGTH = 0x600 /* 1536 bytes (alias RAM2) */  
}

  /* Define a symbol for the top of each memory region */
  __base_PROGRAM_FLASH = 0x208000  ; /* PROGRAM_FLASH */  
  __base_Flash = 0x208000 ; /* Flash */  
  __top_PROGRAM_FLASH = 0x208000 + 0x2b000 ; /* 172K bytes */  
  __top_Flash = 0x208000 + 0x2b000 ; /* 172K bytes */  
  __base_OTA_FLASF = 0x233000  ; /* OTA_FLASF */  
  __base_Flash2 = 0x233000 ; /* Flash2 */  
  __top_OTA_FLASF = 0x233000 + 0x2000 ; /* 8K bytes */  
  __top_Flash2 = 0x233000 + 0x2000 ; /* 8K bytes */  
  __base_SRAM = 0x20003000  ; /* SRAM */  
  __base_RAM = 0x20003000 ; /* RAM */  
  __top_SRAM = 0x20003000 + 0x5000 ; /* 20K bytes */  
  __top_RAM = 0x20003000 + 0x5000 ; /* 20K bytes */  
  __base_AO_SRAM = 0x20008000  ; /* AO_SRAM */  
  __base_RAM2 = 0x20008000 ; /* RAM2 */  
  __top_AO_SRAM = 0x20008000 + 0x600 ; /* 1536 bytes */  
  __top_RAM2 = 0x20008000 + 0x600 ; /* 1536 bytes */  
