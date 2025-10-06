/*
 * phhalCt_TDA.c
 *
 *  Created on: Feb 16, 2022
 *      Author: nxf80132
 */

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
 */

/** @file
 *
 *
 * $Date$
 * $Author$
 * $Revision$
 */

/* *****************************************************************************************************************
 * Includes
 * ***************************************************************************************************************** */
#include "ph_NxpCTBuild.h"

#if defined(NXPBUILD__PHHAL_HW_GOC_7642) || defined(NXPBUILD__PHHAL_HW_PALLAS)
#include "phhalCt_platform.h"


/* *****************************************************************************************************************
 * Internal Definitions
 * ***************************************************************************************************************** */

/* *****************************************************************************************************************
 * Type Definitions
 * ***************************************************************************************************************** */


/* *****************************************************************************************************************
 * Global and Static Variables
 *
 * ***************************************************************************************************************** */
volatile const uint32_t * pCTReg_t[] = {	&(CT->SSR),
											&(CT->PDRX_LSB),
											&(CT->PDRX_MSB),
											&(CT->FCR),
											&(CT->GTRX),
											&(CT->UCR1X),
											&(CT->UCR2X),
											&(CT->CCRX),
											&(CT->PCR),
											&(CT->ECR),
											&(CT->MCLR_LSB),
											&(CT->MCLR_MSB),
											&(CT->MCHR_LSB),
											&(CT->MCHR_MSB),
											&(CT->SRR),
											&(CT->UTR_URR_REG_ADR1),
											&(CT->UTR_URR_REG_ADR2),
											&(CT->UTR_URR_REG_ADR3),
											&(CT->UTR_URR_REG_ADR4),
											&(CT->TOR1),
											&(CT->TOR2),
											&(CT->TOR3),
											&(CT->TOC),
											&(CT->FSR),
											&(CT->MSR),
											&(CT->USR1),
											&(CT->USR2),
											&(CT->TBSEL),
											&(CT->TBVAL),
											&(CT->TST1_REF)
						   	   	   	   };

/* *****************************************************************************************************************
 * Private Functions Prototypes
 * ***************************************************************************************************************** */


/* *****************************************************************************************************************
 * Public Functions
 * ***************************************************************************************************************** */


void phhalCt_SETREG( phhalCt_CT_RegLayout_t bReg, uint32_t bValue )
{
	PH_HALREG_SETREG( pCTReg_t[bReg], bValue );
}

uint32_t phhalCt_GETREG( phhalCt_CT_RegLayout_t bReg )
{
	return PH_HALREG_GETREG( pCTReg_t[bReg] );
}

void phhalCt_SETBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos )
{
	PH_HALREG_SETBITN( pCTReg_t[bReg], bPos );
}

void phhalCt_CLEARBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos )
{
	PH_HALREG_CLEARBITN( pCTReg_t[bReg], bPos );
}

uint8_t phhalCT_TESTBITN( phhalCt_CT_RegLayout_t bReg, uint32_t bPos )
{
	return PH_HALREG_TESTBITN( pCTReg_t[bReg], bPos );
}

uint32_t phhalCT_GETFIELD( phhalCt_CT_RegLayout_t bReg, uint32_t bMask )
{
	return PH_HALREG_GETFIELD( pCTReg_t[bReg], bMask );
}

void phhalCT_SETFIELD( phhalCt_CT_RegLayout_t bReg, uint32_t bMask, uint32_t bValue )
{
	PH_HALREG_SETFIELD( pCTReg_t[bReg], bMask, bValue );
}

void phhalCT_SETFIELDSHIFT( phhalCt_CT_RegLayout_t bReg, uint32_t bMask, uint32_t bPos, uint32_t bValue )
{
	PH_HALREG_SETFIELDSHIFT( pCTReg_t[bReg], bMask, bPos, bValue );
}

#endif /* NXPBUILD__PHHAL_HW_PALLAS*/
