/*
 *                    Copyright (c), NXP Semiconductors
 *
 *                       (C) NXP Semiconductors 2014,2015
 *
 *         All rights are reserved. Reproduction in whole or in part is
 *        prohibited without the written consent of the copyright owner.
 *    NXP reserves the right to make changes without notice at any time.
 *   NXP makes no warranty, expressed, implied or statutory, including but
 *   not limited to any implied warranty of merchantability or fitness for any
 *  particular purpose, or that the use will not infringe any third party patent,
 *   copyright or trademark. NXP must not be liable for any loss or damage
 *                            arising from its use.
.*/

/** @file
 *
 *
 * @{
 */

#ifndef PHHALCT_REG_H
#define PHHALCT_REG_H

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"
#include "ph_Datatypes.h"


#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "PN7642.h"
#include "Pcrm_Lp_Reg.h"
#include "Pcrm_Hp_Reg.h"
#include "PN76_Reg_Interface.h"
#include "ph_Registers.h"

/* *****************************************************************************************************************
 * MACROS/Defines
 * ***************************************************************************************************************** */
/* Warm Reset Initialization Delay between 40000 & 45000 cycles, below calculation produce 42673 cycles */
#define WARM_RESET_INITIALIZATION_DELAY         8000

/* CT Register Operations */
#define CT_SETREG(RegAddr, RegVal)                        PN76_Sys_WriteRegister(RegAddr, RegVal)   /**< Macro to write a register */
#define CT_SETBITN(RegAddr, BitPos)                       PN76_Sys_WriteRegisterOrMask(RegAddr, (1<<BitPos))  /**< Macro to set a bit */
#define CT_CLEARBITN(RegAddr, BitPos)                     PN76_Sys_WriteRegisterAndMask(RegAddr, ~(1 << BitPos)) /**< Macro to clear a bit */
#define CT_SETFIELD(RegAddr,BitMask,MaskVal)              PN76_Sys_WriteRegisterField(RegAddr,BitMask,MaskVal)   /**< Macro to write a specific field in a register */
#define CT_SETFIELDSHIFT(RegAddr,BitMask,BitPos,Value)    PN76_Sys_WriteRegisterField(RegAddr,BitMask,(Value << BitPos))  /**< Macro to write a specific field at specific position in a register */
#define CT_TESTBITN(RegAddr, BitPos)                      PCRM_TestBitN(RegAddr, BitPos)   /**< Macro to to test a bit */

#define PH_HAL_CT_ISCARDPRESENT						(PN76_Sys_ReadRegister(PCRM_PADIN) & (1 << PCRM_PADIN_PADIN_INT_AUX_POS))? 1 : 0

#if defined(NXPBUILD__PHHAL_HW_GOC_7642)
#define PH_HAL_CT_RESET_LOW                     CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO3_POS)
#define PH_HAL_CT_RESET_HIGH                    CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO3_POS)

#define PH_HAL_CT_CMDVCCN_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_I2CM_SDA_POS)
#define PH_HAL_CT_CMDVCCN_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_I2CM_SDA_POS)

#define PH_HAL_CT_CLKDIV1_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MISO_POS)
#define PH_HAL_CT_CLKDIV1_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MISO_POS)

#define PH_HAL_CT_CLKDIV2_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MOSI_POS)
#define PH_HAL_CT_CLKDIV2_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MOSI_POS)

#define PH_HAL_CT_1V8_LOW                       CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SSN_POS)
#define PH_HAL_CT_1V8_HIGH                      CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SSN_POS)

#define PH_HAL_CT_5V3_LOW                       CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SCLK_POS)
#define PH_HAL_CT_5V3_HIGH                      CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SCLK_POS)

#define PH_HAL_CT_TDA1_CS_LOW						   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);
#define PH_HAL_CT_TDA1_CS_HIGH						CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);

#define PH_HAL_CT_TDA2_CS_LOW						   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO1_POS);
#define PH_HAL_CT_TDA2_CS_HIGH						CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO1_POS);

#define PH_HAL_CT_BD_SEL_HIGH                   CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO2_POS)

#define ALL_TDA_CS_UNSELECT      					{  PH_HAL_CT_BD_SEL_HIGH;       \
                                                   PH_HAL_CT_TDA1_CS_LOW;       \
                                    				   PH_HAL_CT_TDA2_CS_LOW;   }

#define CARD_TDA1_SELECT             			   PH_HAL_CT_TDA1_CS_HIGH;
#define CARD_TDA2_SELECT            				PH_HAL_CT_TDA2_CS_HIGH;

#define CONFIG_GOC_BOARD_PINS                   {  CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_IO,  PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_POS, 0x1);   \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_CLK, PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_POS, 0x1);   \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_CLK, PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_MASK, PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_POS, 0x1);  \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_INT, PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_POS, 0x1);  \
                                                   CT_SETREG(PCRM_PAD_SPIM_MISO,0x00000006);   \
		                                             CT_SETREG(PCRM_PAD_SPIM_MOSI,0x00000006);   \
		                                             CT_SETREG(PCRM_PAD_SPIM_SSN,0x00000006);    \
		                                             CT_SETREG(PCRM_PAD_SPIM_SCLK,0x00000006);   \
		                                             CT_SETREG(PCRM_PAD_GPIO0,0x2);   \
		                                             CT_SETREG(PCRM_PAD_GPIO1,0x2);   \
                                                   CT_SETREG(PCRM_PAD_GPIO2,0x2);   \
                                                   CT_SETREG(PCRM_PAD_GPIO3,0x2);   \
                                                   CT_SETREG(PCRM_PAD_I2CM_SDA,0x00000006);   }

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 */

#if defined(NXPBUILD__PHHAL_HW_PALLAS)
#define PH_HAL_CT_RESET_LOW                     CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO4_POS)
#define PH_HAL_CT_RESET_HIGH                    CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO4_POS)

#define PH_HAL_CT_CMDVCCN_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO5_POS)
#define PH_HAL_CT_CMDVCCN_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO5_POS)

#define PH_HAL_CT_CLKDIV1_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MISO_POS)
#define PH_HAL_CT_CLKDIV1_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MISO_POS)

#define PH_HAL_CT_CLKDIV2_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MOSI_POS)
#define PH_HAL_CT_CLKDIV2_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_MOSI_POS)

#define PH_HAL_CT_1V8_LOW                       CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SSN_POS)
#define PH_HAL_CT_1V8_HIGH                      CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SSN_POS)

#define PH_HAL_CT_5V3_LOW                       CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SCLK_POS)
#define PH_HAL_CT_5V3_HIGH                      CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_SPIM_SCLK_POS)

#define PH_HAL_CT_TDA1_CS_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);
#define PH_HAL_CT_TDA1_CS_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO0_POS);

#define PH_HAL_CT_TDA2_CS_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO1_POS);
#define PH_HAL_CT_TDA2_CS_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_GPIO1_POS);

#define PH_HAL_CT_TDA3_CS_LOW                   CT_CLEARBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_DWL_REQ_POS);
#define PH_HAL_CT_TDA3_CS_HIGH                  CT_SETBITN(PCRM_PADOUT, PCRM_PADOUT_PADOUT_DWL_REQ_POS);

#define ALL_TDA_CS_UNSELECT                     {   PH_HAL_CT_TDA1_CS_LOW;       \
                                                    PH_HAL_CT_TDA2_CS_LOW;       \
                                                    PH_HAL_CT_TDA3_CS_LOW;  }

#define CARD_TDA1_SELECT                        PH_HAL_CT_TDA1_CS_HIGH;
#define CARD_TDA2_SELECT                        PH_HAL_CT_TDA2_CS_HIGH;
#define CARD_TDA3_SELECT                        PH_HAL_CT_TDA3_CS_HIGH;

#define CONFIG_PALLAS_BOARD_PINS                {  CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_IO,  PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_IO_IO_AUX_ENABLE_POS, 0x1);   \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_CLK, PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_CLK_CLK_AUX_ENABLE_POS, 0x1);   \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_CLK, PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_MASK, PCRM_PAD_CTAUX_CLK_CLK_AUX_EHS_POS, 0x1);  \
                                                   CT_SETFIELDSHIFT(PCRM_PAD_CTAUX_INT, PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_MASK, PCRM_PAD_CTAUX_INT_INT_AUX_ENABLE_POS, 0x1);  \
                                                   CT_SETREG(PCRM_PAD_SPIM_MISO,0x00000006);   \
                                                   CT_SETREG(PCRM_PAD_SPIM_MOSI,0x00000006);   \
                                                   CT_SETREG(PCRM_PAD_SPIM_SSN,0x00000006);    \
                                                   CT_SETREG(PCRM_PAD_SPIM_SCLK,0x00000006);   \
                                                   CT_SETREG(PCRM_PAD_GPIO0, 0x2);   \
                                                   CT_SETREG(PCRM_PAD_GPIO1, 0x2);   \
                                                   CT_SETREG(PCRM_PAD_GPIO4, 0x2);   \
                                                   CT_SETREG(PCRM_PAD_GPIO5, 0x2);   \
                                                   CT_SETREG(PCRM_PAD_DWL_REQ, 0x2); }
#endif /* NXPBUILD__PHHAL_HW_PALLAS */
/* *****************************************************************************************************************
 * Types/Structure Declarations
 * *****************************************************************************************************************.*/

/** CT - Register Layout Typedef e-numbered */
typedef enum
{
	  eSSR = 0,                           /**< , offset: 0x0 */
	  ePDRX_LSB,                          /**< , offset: 0x4 */
	  ePDRX_MSB,                          /**< , offset: 0x8 */
	  eFCR,                               /**< , offset: 0xC */
	  eGTRX,                              /**< , offset: 0x10 */
	  eUCR1X,                             /**< , offset: 0x14 */
	  eUCR2X,                             /**< , offset: 0x18 */
	  eCCRX,                              /**< , offset: 0x1C */
	  ePCR,                               /**< , offset: 0x20 */
	  eECR,                               /**< , offset: 0x24 */
	  eMCLR_LSB,                          /**< , offset: 0x28 */
	  eMCLR_MSB,                          /**< , offset: 0x2C */
	  eMCHR_LSB,                          /**< , offset: 0x30 */
	  eMCHR_MSB,                          /**< , offset: 0x34 */
	  eSRR,                               /**< , offset: 0x38 */
	  eUTR_URR_REG_ADR1,                  /**< , offset: 0x3C */
	  eUTR_URR_REG_ADR2,                  /**< , offset: 0x40 */
	  eUTR_URR_REG_ADR3,                  /**< , offset: 0x44 */
	  eUTR_URR_REG_ADR4,                  /**< , offset: 0x48 */
	  eTOR1,                              /**< , offset: 0x4C */
	  eTOR2,                              /**< , offset: 0x50 */
	  eTOR3,                              /**< , offset: 0x54 */
	  eTOC,                               /**< , offset: 0x58 */
	  eFSR,                               /**< , offset: 0x5C */
	  eMSR,                               /**< , offset: 0x60 */
	  eUSR1,                              /**< , offset: 0x64 */
	  eUSR2,                              /**< , offset: 0x68 */
	  eTBSEL,                             /**< , offset: 0x6C */
	  eTBVAL,                             /**< , offset: 0x70 */
	  eTST1_REF                           /**< , offset: 0x74 */

}phhalCt_CT_RegLayout_t;

/* *****************************************************************************************************************
 * Extern Variables
 * *****************************************************************************************************************.*/

/* *****************************************************************************************************************
 * Function Prototypes
 * *****************************************************************************************************************.*/
void phhalCt_SETREG( phhalCt_CT_RegLayout_t bReg, uint32_t bValue );

uint32_t phhalCt_GETREG( phhalCt_CT_RegLayout_t bReg );

void phhalCt_SETBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos );

void phhalCt_CLEARBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos );

uint8_t phhalCT_TESTBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos );

uint32_t phhalCT_GETFIELD( phhalCt_CT_RegLayout_t bReg, uint32_t bMask );

void phhalCT_SETFIELD( phhalCt_CT_RegLayout_t bReg, uint32_t bMask, uint32_t bValue );

void phhalCT_SETFIELDSHIFT( phhalCt_CT_RegLayout_t bReg, uint32_t bMask, uint32_t bPos, uint32_t bValue );

void phhalCT_TDAUnselect( void );

void phhalCT_TDASelect( phhalCt_SlotType_t eSlot_Index );

#endif /* NXPBUILD__PHHAL_HW_GOC_7642 || NXPBUILD__PHHAL_HW_PALLAS */

/** @}.*/
#endif /* PHHALCT_REG_H.*/
