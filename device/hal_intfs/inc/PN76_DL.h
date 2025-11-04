/*----------------------------------------------------------------------------*/
/* Copyright 2021-2022 NXP                                                    */
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

/** @file
 *
 * Implementation of DL mode interfaces for secondary boot-loader application
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_DL_H_
#define _PN76_DL_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALDL
 *
 * @brief System Services for In-application download of encrypted firmware functionality
 *
 *
 * This module briefs all the interfaces of download module accessible from the Non-secure application.
 *
 *
 * \section DL_MEMMAP Typical memory map of In-application FW download flow
 *
   \image html PN7642_IAP_FW_Download_MemMap.PNG
 * \section DL_FLOW In-application FW download flow from application point of view
@msc In-Application FW Download Flow
# Options section
    hscale = "2";
# The entities
    APP_NS, PN76xx_SECURE, PN76xx_IAP_EDL;
# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];
    PN76xx_IAP_EDL box PN76xx_IAP_EDL [label="PN76xx IC IAP EDL mode", textbgcolour="#7fff7f"];
# Small gap before the boxes
    |||;
# Next four on same line due to ','
    PN76xx_SECURE box PN76xx_SECURE    [ label = "PN76xx IC boots"];
    APP_NS box APP_NS                  [ label = "PN76xx IC jumps to Application"];
    APP_NS=>PN76xx_SECURE              [ label = "PN76_EDL_IAP_Init()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE       [ label = "Parameters are checked.." ];
    APP_NS<<PN76xx_SECURE              [ label = "PN76_EDL_IAP_Init() returns incase of any errors with parameters"];
    APP_NS box APP_NS                  [ label = "If PN76_EDL_IAP_Init() error is returned, means the parameter values are not proper.\nIAP download process not started."];
    APP_NS->APP_NS                     [ label = "Check the error value returned."];
    PN76xx_SECURE=>PN76xx_SECURE       [ label = "All parameters valid. Does internal validation \nand stores relevant details." ];
    PN76xx_SECURE=>PN76xx_IAP_EDL      [ label = "Soft-Resets the IC" ];
    PN76xx_IAP_EDL box PN76xx_IAP_EDL  [ label = "IC enters IAP_EDL mode" ];
    PN76xx_IAP_EDL->PN76xx_IAP_EDL     [ label = "IC performs the encrypted FW download" ];
    PN76xx_IAP_EDL box PN76xx_IAP_EDL  [ label = "Soft-Resets the IC after performing encrypted FW download" ];
    APP_NS<<PN76xx_IAP_EDL             [ label = "If NXP FW download is successfull OR \nIf NXP FW download is failed and if failure status is within E_PN76_IAPDL_STAGE_AFT_SIG_CHECK OR \nIf APP FW download is successfull/failure." ];
    PN76xx_IAP_EDL box PN76xx_IAP_EDL  [ label = "IC enters into HIF polling mode, as NXP FW download is not successfull and NXP_FW download session is OPEN\nThe host can download commands to re-perform the NXP FW download" ];
    APP_NS box APP_NS                  [ label = "If it is entered here, means that IAP download is either successfull/failure.\nThe reason for failure can be retrieved by calling either PN76_EDL_GetStatus_NXP_Fw() or PN76_EDL_GetStatus_APP_Fw()" ];
    APP_NS=>PN76xx_SECURE              [ label = "Calls either PN76_EDL_GetData_NXP_Fw() or PN76_EDL_GetData_APP_Fw() \nto get the versioning information of the respective firmware" ];
    APP_NS<<PN76xx_SECURE              [ label = "Returns FW version" ];
@endmsc
 * \section DL_CHECK Deduce of FW update status through IAP
 The following table shows on how to deduce the validity of IAP Download when it occurs for both NXP FW download or Customer application download
 * \subsection DL_CHECK_APP_FWP Decoding of application firmware update status when firmware is updated thorugh IAP system service calls
 Session status is retrieved by calling API \ref PN76_EDL_GetData_App_Fw().
 bStatus is retrieved by calling API \ref PN76_EDL_GetStatus_App_Fw().
 | Session Status | bStatus[0]  (Status) | bStatus[1] (Stage) | Decoded final firmware update status                       |
 |-------------- :|: ------------------: | :----------------: | :--------------------------------------------------------- |
 |  01(CLOSE)     |  any value between 0x33 and 0x37   |  any value less than  \ref E_PN76_IAPDL_STAGE_STARTED        | Application FW download did not happen. Either provided parameters are not proper, or invalid data was present. For the reason, please refer to bStatus[0] =  \ref E_PN76_EDL_STATUS_t. |
 |  01(CLOSE)     |  NA                                |  any value more than  \ref E_PN76_IAPDL_STAGE_AFT_SIG_CHECK  | Indicates the Application download completed. Please check the application version got through  \ref PN76_EDL_GetData_App_Fw()  |
 |  00(OPEN)      |  NA                                |  NA                                                          | Indicates that application FW download session is open, and application FW is not valid. There are errors returned. For the errors, refer to the value of bStatus[0] in enum PN76_Status_t |
 * \subsection DL_CHECK_NXP_FW Decoding of NXP firmware update status when firmware is updated thorugh IAP system service calls
 Session status is retrieved by calling API \ref PN76_EDL_GetData_NXP_Fw().
 bStatus is retrieved by calling API \ref PN76_EDL_GetStatus_NXP_Fw().
 | Session Status | bStatus[0]  (Status) | bStatus[1] (Stage) | Decoded final firmware update status                       |
 |-------------- :|: ------------------: | :----------------: | :--------------------------------------------------------- |
 |  01(CLOSE)     |  any value between 0x33 and 0x37   |  any value less than \ref E_PN76_IAPDL_STAGE_STARTED         | NXP FW download did not happen. Either provided parameters are not proper, or invalid data was present. For the reason, please refer to bStatus[0] = \ref E_PN76_EDL_STATUS_t. |
 |  01(CLOSE)     |  NA                                |  any value more than \ref E_PN76_IAPDL_STAGE_AFT_SIG_CHECK   | Indicates the NXP FW download completed. Please check the NXP FW version got through \ref PN76_EDL_GetData_NXP_Fw()  |
 |  00(OPEN)      |  NA                                |  NA                                                          | This condition does not arise. If NXP FW download session is OPEN it will be always in HIF polling mode. To recover, you need to put the IC in DL mode and perform download operation through external host. |
 *
 * \warning  If host performs a hard-reset of IC or VEN reset of the IC, the IAP FW download status (bStatus[0], bStatus[1]) of \ref PN76_EDL_Status_t would be lost.\n
 * \note     It is advised that secondary boot-loader area must not be over written using the InApplication download.
 *
 * @{
 *
 */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/** @brief This enum contains the status values of IAPDL process after the API \ref PN76_EDL_IAP_Init() is called */
typedef enum {
   E_PN76_IAPDL_STATUS_SUCCESS                 = 0x00, /**< IAPDL command execution successful. Valid only if IAPDL stage is \ref E_PN76_IAPDL_STAGE_COMPLETE.  */
   E_PN76_IAPDL_STATUS_INVALID_ADDR            = 0x01, /**< IAPDL error. Invalid address is present in the decoded address */
   E_PN76_IAPDL_STATUS_INVALID_CMD             = 0x0B, /**< IAPDL error. Unknown command  */
   E_PN76_IAPDL_STATUS_ABORTED_CMD             = 0x0C, /**< IAPDL error. Aborted command, as chunk sequence is too big */
   E_PN76_IAPDL_STATUS_ADDR_RANGE_OFL          = 0x1E, /**< IAPDL error. Address is out of range */
   E_PN76_IAPDL_STATUS_MEM_BUSY                = 0x20, /**< Memory access is busy or internal error.  */
   E_PN76_IAPDL_STATUS_SIGNATURE_ERROR         = 0x21, /**< IAPDL error. Signature mismatch  */
   E_PN76_IAPDL_STATUS_FW_VERSION_ERROR        = 0x24, /**< IAPDL error. Firmware version error */
   E_PN76_IAPDL_STATUS_PROTOCOL_ERROR          = 0x28, /**< IAPDL error. Protocol error.  */
   E_PN76_IAPDL_STATUS_SFWU_DEGRADED           = 0x2A, /**< IAPDL error. Flash data is corrupted */
   E_PN76_IAPDL_STATUS_FIRST_CHUNK             = 0x2D, /**< IAPDL error.  First chunk received */
   E_PN76_IAPDL_STATUS_NEXT_CHUNK              = 0x2E, /**< IAPDL error.  Waiting for next chunk */
   E_PN76_IAPDL_STATUS_INVALID_SFWU_ADDR_LOC   = 0x33, /**< IAPDL error. Combination of address and size of the encrypted payload is not correct. */
   E_PN76_IAPDL_STATUS_INVALID_SFWU_CRC        = 0x34, /**< IAPDL error. Invalid CRC was referred. Means the encrypted payload is corrupted since \ref PN76_EDL_IAP_Init() API call */
   E_PN76_IAPDL_STATUS_INVALID_FW_TYPE         = 0x36, /**< IAPDL error. The encrypted payload contains an invalid FW type. NXP FW or APP FW. */
   E_PN76_IAPDL_STATUS_INVALID_CHUNK_LEN       = 0x37, /**< IAPDL error. The chunk length present in the encrypted payload data is not correct. */
} E_PN76_EDL_STATUS_t;

/** @brief This enum contains the stage at which the IAPDL process is terminated after the API \ref PN76_EDL_IAP_Init() is called */
typedef enum {
   E_PN76_IAPDL_STAGE_NOT_VALID             = 0x00, /** IAPDL stage not valid */
   E_PN76_IAPDL_STAGE_INITIATED             = 0x01, /** IAPDL stage where the IAP download is initiated. */
   E_PN76_IAPDL_STAGE_PARAM_CHECK_0         = 0x02, /** IAPDL stage where the IAP download was initiated and IAP process initiates checks of provided encrypted FW image data. */
   E_PN76_IAPDL_STAGE_PARAM_CHECK_1         = 0x03, /** IAPDL stage where the IAP download was process is initiated and interrupted before completion of successfull IAP process. */
   E_PN76_IAPDL_STAGE_STARTED               = 0x04, /** IAPDL stage where the IAP download parameters are checked and IAP download process is started. */
   E_PN76_IAPDL_STAGE_AFT_SIG_CHECK         = 0x05, /** IAPDL stage where the provided encrypted FW data is checked for signature check. */
   E_PN76_IAPDL_STAGE_INCOMPLETE            = 0x06, /** IAPDL stage where the IAP download process is incompleted due to errors in encrypted FW data. */
   E_PN76_IAPDL_STAGE_COMPLETE              = 0x07, /** IAPDL stage where the IAP download process is completed with successfull update of concerned FW data. */
} E_PN76_EDL_STAGE_t;


/** @brief This structure contains the status of IAP download execution */
typedef struct {
   uint8_t bStatus[4];                 /**< IAP download execution status

                                            |Byte  | Field   | Values   |     Description                                                |
                                            |------|:-------:|:--------:|:-------------------------------------------------------------- |
                                            |[0]   | Status  |  XXXX    | Consists the status of IAP download process. If the value of <b>Stage</b> is within \ref E_PN76_IAPDL_STAGE_AFT_SIG_CHECK, then values present in \ref E_PN76_EDL_STATUS_t enum is valid. If the value of <b>Stage</b> is more than \ref E_PN76_IAPDL_STAGE_AFT_SIG_CHECK, then values present in \ref PN76_Status_t is valid. |
                                            |[1]   | Stage   |  XXXX    | Consists the values present in \ref E_PN76_EDL_STAGE_t enum.   |
                                            |[3:2] | RFU     |  00      | Reserved for future use.                                       |

                                        */
} PN76_EDL_Status_t;

/** @brief This structure contains the integrity status of different areas of NXP FW in the IC. */
typedef struct {
  uint8_t  Status;         /**< Status of the check integrity API */
  uint8_t  LenDataArea;    /**< Number of data sections present in the NXP FW */
  uint8_t  LenCodeArea;    /**< Number of code sections present in the NXP FW.*/
  uint8_t  RFU;            /**< Reserved for future use. */
  uint32_t CRCInfo;        /**< Each bit indicates the status of the corresponding section CRC check.
                                If the corresponding bit is <b>0</b> means, that section CRC is not correct, if <b>1</b> indicates, that section CRC is correct.
								|Bit    | Area integrity status               |
								|------:|:------------------------------------|
								| [0]   | APP_VERSION_AREA (Mirrored)         |
								| [1]   | APP_RSA_PUBLIC_KEY_AREA (Mirrored)  |
								| [2]   | APP_VERSION_AREA                    |
								| [3]   | APP_RSA_PUBLIC_KEY_AREA             |
								| [4]   | NXP_DATA_AREA_1                     |
								| [5]   | NXP_DATA_AREA_2                     |
								| [6]   | NXP_DATA_AREA_3                     |
								| [7]   | NXP_DATA_AREA_4                     |
								| [8]   | NXP_DATA_AREA_5                     |
								| [9]   | NXP_DATA_AREA_6                     |
								| [10]  | NXP_DATA_AREA_7                     |
								| [11]  | NXP_DATA_AREA_8                     |
								| [12]  | APP_RF_CFG_IC                       |
								| [13]  | APP_RF_CFG_LIB                      |
								| [14]  | APP_RF_CFG                          |
								| [15]  | NXP_DATA_AREA_9                     |
								| [16]  | NXP_DATA_AREA_10                    |
								| [17]  | NXP_DATA_AREA_11                    |
								| [18]  | NXP_DATA_AREA_12                    |
								| [19]  | NXP_DATA_AREA_13                    |
								| [20]  | NXP_DATA_AREA_14                    |
								| [21]  | NXP_DATA_AREA_15                    |
								| [22]  | NXP_DATA_AREA_16                    |
								| [23]  | NXP_DATA_AREA_17                    |
								| [24]  | NXP_DATA_AREA_18                    |
								| [25]  | NXP_DATA_AREA_19                    |
								| [26]  | NXP_CODE_AREA_1                     |
								| [27]  | NXP_CODE_AREA_2                     |
								| [28]  | NXP_CODE_AREA_3                     |
								| [29]  | NXP_CODE_AREA_4                     |
								| [30]  | NXP_CODE_AREA_5                     |
								| [31]  | NXP_CODE_AREA_6                     |
                                */	
  uint32_t aCRC32[32];     /**< CRC32 of the 32 sections */
} PN76_EDL_IntegrityStatus_t;

/*****************************************************************************
 * Public functions declarations
 ****************************************************************************/

/*!
 * @brief   This API will initiate the IAP download process to update the FW at the corresponding FW area.
 *
 * @note    This API will never return if the provided paramters are proper. It will perform the IAP download process
 *          and after IAP download process completion, and when the non-secure application is booted, application shall
 *          call \ref PN76_EDL_GetStatus_NXP_Fw() or \ref PN76_EDL_GetStatus_App_Fw() to know the IAP download status.
 *
 * @param   dwFwDataAddr_InNSF   Address in application flash area that contains encrypted FW data.
 * @param   dwSize               Size of encrypted FW data in bytes.
 *
 * @retval  Any value  Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 */
__TEXT(Flash2) PN76_Status_t PN76_EDL_IAP_Init(
            uint32_t dwFwDataAddr_InNSF,
            uint32_t dwSize );

/*!
 * @brief   This API will get the NXP FW version information.
 *
 * @param   *pbSession     Pointer to memory location where the session information to be stored. The returned value shall be referred to the below table.
                             |Bits  | Values   |     Description
                             |------|: -------:| :--------------------------------------------------------------
                             |[7:0] |   0x00   | Download session is closed
                             |^     |   0x01   | Download session is open. --> No valid FW
                             |^     |   0x02   | Download session is blocked. FW download is not possible.
 *
 * @param   *pwVersion     Pointer to memory location where the version information to be stored. The returned value shall be referred to the below table.
                             |Bits  | Values   |     Description
                             |------|: -------:| :--------------------------------------------------------------
                             |[15:8]|          | Consists of FW version Major number
                             |[7:0] |          | Consists of FW version Minor number
 *
 * @retval  PN76_STATUS_SUCCESS  Successfully received NXP FW information.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_EDL_GetData_NXP_Fw(
            uint8_t *pbSession,
            uint16_t *pwVersion );

/*!
 * @brief   This API will get the Application FW version information.
 *
 * @param   *pbSession     Pointer to memory location where the session information to be stored. The returned value shall be referred to the below table.
                             |Bits  | Values   |     Description
                             |------|: -------:| :--------------------------------------------------------------
                             |[7:0] |   0x00   | Download session is closed
                             |^     |   0x01   | Download session is open. --> No valid FW
                             |^     |   0x02   | Download session is blocked. FW download is not possible.
 *
 * @param   *pwVersion     Pointer to memory location where the version information to be stored. The returned value shall be referred to the below table.
                             |Bits  | Values   |     Description
                             |------|: -------:| :--------------------------------------------------------------
                             |[15:8]|          | Consists of FW version Major number
                             |[7:0] |          | Consists of FW version Minor number
 *
 *
 * @retval  PN76_STATUS_SUCCESS  Successfully received Application FW information.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_EDL_GetData_App_Fw(
            uint8_t *pbSession,
            uint16_t *pwVersion );

/*!
 * @brief   This API will get the integrity status of NXP FW.
 *
 * @param   *pIntgStatus   Pointer to \ref PN76_EDL_IntegrityStatus_t() structure, where the integrity status of NXP FW to be stored.
 * @note    Please make sure that the structure passed contains all zeros.
 *
 * @retval  PN76_STATUS_SUCCESS  Successfully retrieved the NXP FW integrity information.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_EDL_Get_Integrity_NXP_Fw(
            PN76_EDL_IntegrityStatus_t *pIntgStatus );

/*!
 * @brief   This API will get the IAP download process status if IAP download involves NXP FW.
 *
 * @param   *pStatusData   Pointer to \ref PN76_EDL_Status_t() structure, where the previous IAP download process involves NXP FW.
 *
 * @note    Please make sure that the structure passed contains all zeros.
 * @retval  PN76_STATUS_SUCCESS  Successfully retrieved the status.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_EDL_GetStatus_NXP_Fw(
            PN76_EDL_Status_t *pStatusData );

/*!
 * @brief   This API will get the IAP download process status if IAP download involves Application FW.
 *
 * @param   *pStatusData   Pointer to \ref PN76_EDL_Status_t() structure, where the previous IAP download process involves Application FW.
 * @note    Please make sure that the structure passed contains all zeros.
 *
 * @retval  PN76_STATUS_SUCCESS  Successfully retrieved the status.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_EDL_GetStatus_App_Fw(
            PN76_EDL_Status_t *pStatusData );


#ifdef __cplusplus
}
#endif

/** @} */

#endif /* _PN76_DL_H_ */


