/*----------------------------------------------------------------------------*/
/* Copyright 2021 NXP                                                         */
/*                                                                            */
/* NXP Confidential. This software is owned or controlled by NXP and may only */
/* be used strictly in accordance with the applicable license terms.          */
/* By expressly accepting such terms or by downloading, installing,           */
/* activating and/or otherwise using the software, you are agreeing that you  */
/* have read, and that you agree to comply with and are bound by, such        */
/* license terms. If you do not agree to be bound by the applicable license   */
/* terms, then you may not retain, install, activate or otherwise use the     */
/* software.                                                                  */
/*----------------------------------------------------------------------------*/

/** \file
* Example Source Header for NfcrdlibEx2_ECP application.
*
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*/


#ifndef NFCRDLIBEX2_ECP_H
#define NFCRDLIBEX2_ECP_H

#include <ph_Status.h>
#include <phacDiscLoop.h>
#include "evx_write_flow.h"

#define LISTEN_PHASE_TIME_MS              300       /* Listen Phase TIME in NFC forum mode */

#ifdef PH_OSAL_FREERTOS
    #ifdef PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION
        #define ECP_DEMO_TASK_STACK              (1800/4)
    #else /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
        #if defined( __PN74XXXX__) || defined(__PN76XX__)
            #define ECP_DEMO_TASK_STACK          (1600/4)
        #else /* defined( __PN74XXXX__) || defined(__PN76XX__) */
            #define ECP_DEMO_TASK_STACK          (1650)
        #endif /* defined( __PN74XXXX__) || defined(__PN76XX__) */
    #endif /* PHOSAL_FREERTOS_STATIC_MEM_ALLOCATION */
    #define ECP_DEMO_TASK_PRIO                   4
#endif /* PH_OSAL_FREERTOS */

#ifdef PH_OSAL_LINUX
#define ECP_DEMO_TASK_STACK                0x20000
#define ECP_DEMO_TASK_PRIO                 0
#endif /* PH_OSAL_LINUX */

/* Enabled the required Transport Keys. */
#ifdef NXPBUILD__PH_KEYSTORE_PN76XX
	#ifdef NXPBUILD__PHHAL_HW_PN7640
		/* #define PN7640EV_C100 */
		/* #define PN7640EV_C101 */
		/* #define PN7640EV_C102 */
	#endif /* NXPBUILD__PHHAL_HW_PN7640 */

	#ifdef NXPBUILD__PHHAL_HW_PN7642
		/* #define PN7642EV_C100 */	#define PN7642EV_C101//#define PN7642EV_C101//
		/* #define PN7642EV_C101 */
		/* #define PN7642EV_INT */
	#endif /* NXPBUILD__PHHAL_HW_PN7642 */
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */



		typedef enum _NFC_READ_ERR_CODE_
		{
			NFC_READ_SUCCESS,		// Used for logical compatibility with write result codes
			NFC_READ_PICC_AUT_ERR,
			NFC_READ_APP_SELECT_ERR,
			NFC_READ_APP_AUT_ERR,
			NFC_READ_FILE_AUT_ERR,
			NFC_READ_DATA_READ_ERR,
			NFC_READ_COMMIT_ERR,

		}NFC_READ_ERR_Code_t;

		typedef enum _NFC_WRITE_ERR_CODE_
		{
			NFC_WRITE_SUCCESS,
			NFC_WRITE_PICC_AUT_ERR,
			NFC_WRITE_PICC_FORMAT_ERR,
			NFC_WRITE_APP_CREATE_ERR,
			NFC_WRITE_MAC_FILE_CREATE_ERR,
			NFC_WRITE_STD_FILE_CREATE_ERR,
			NFC_WRITE_FILE_AUT_ERR,
			NFC_WRITE_DATA_WRITE_ERR,
			NFC_WRITE_COMMIT_ERR,

		}NFC_WRITE_ERR_Code_t;



		phStatus_t NFC_COMM_init (void);

		void NFC_COMM_process(void);

#endif /* NFCRDLIBEX2_ECP_H */
