/*----------------------------------------------------------------------------*/
/* Copyright 2020-2023 NXP                                                    */
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
 * Clif Software Register Definition of PN76XX IC
 *
 * $Author: $
 * $Revision: $
 * $Date: $
 */

#ifndef _PN76_CLIF_REGDEFS_H
#define _PN76_CLIF_REGDEFS_H


#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** @addtogroup PN76CLIFRegDefs
 *
 * The CLIF Software Register definitions of PN76XX IC.
 * To access these register, use System Service Register Interface API's
 *
 * @{
 *
 */


/**
* @name system_config
* <b>Reset value:</b>
* <b>Access:</b> 
* @{
*/
#define SYSTEM_CONFIG                                                                                     0x0
#define SYSTEM_CONFIG_RFU2_POS                                                                           (7UL)
#define SYSTEM_CONFIG_RFU2_MASK                                                                          (0xFFFFFF80UL)  /**< 7-Reserved */
#define SYSTEM_CONFIG_15693_CHANGE_DATARATE_POS                                                          (5UL)
#define SYSTEM_CONFIG_15693_CHANGE_DATARATE_MASK                                                         (0x00000060UL)  /**< 0-0 - RFU
1 - Change Data Rate to 53kB/sec
2 -  Change Data Rate to 106kB/sec
3 -  Change Data Rate to 212kB/sec*/
#define SYSTEM_CONFIG_RFU1_POS                                                                           (2UL)
#define SYSTEM_CONFIG_RFU1_MASK                                                                          (0x0000001CUL)  /**< -*/
#define SYSTEM_CONFIG_MFC_CRYPTO_ON_POS                                                                  (1UL)
#define SYSTEM_CONFIG_MFC_CRYPTO_ON_MASK                                                                 (0x00000002UL)  /**< 8-If set to 1 the mfc-crypto bit is generated for end-/de-cryption*/
#define SYSTEM_CONFIG_AUTOCOLL_STATE_A_POS                                                               (0UL)
#define SYSTEM_CONFIG_AUTOCOLL_STATE_A_MASK                                                              (0x00000001UL)  /**< 0: Type A Listen mode is set to IDLE State. 1: Type A Listen mode is set to HALT State. */
/**
* @}
*/


/**
* @name emd_control
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define EMD_CONTROL                                                                                       0x3
#define EMD_CONTROL_EMD_RM_EMD_SENSITIVITY_POS                                                           (10UL)
#define EMD_CONTROL_EMD_RM_EMD_SENSITIVITY_MASK                                                          (0x00000C00UL)  /**< 10-RM EMD SENSITIVITY value that will be applied to SIGPRO_RM_CONFIG*/
#define EMD_CONTROL_EMD_TRANSMISSION_TIMER_USED_POS                                                      (8UL)
#define EMD_CONTROL_EMD_TRANSMISSION_TIMER_USED_MASK                                                     (0x00000300UL)  /**< 8-Timer used for RF communication. */
#define EMD_CONTROL_EMD_MISSING_CRC_IS_PROTOCOL_ERROR_TYPE_B_POS                                         (7UL)
#define EMD_CONTROL_EMD_MISSING_CRC_IS_PROTOCOL_ERROR_TYPE_B_MASK                                        (0x00000080UL)  /**< 7-Missing CRC treated as protocol error in case of Type B based communication*/
#define EMD_CONTROL_EMD_MISSING_CRC_IS_PROTOCOL_ERROR_TYPE_A_POS                                         (6UL)
#define EMD_CONTROL_EMD_MISSING_CRC_IS_PROTOCOL_ERROR_TYPE_A_MASK                                        (0x00000040UL)  /**< 6-Missing CRC treated as protocol error in case of Type A based communication*/
#define EMD_CONTROL_EMD_NOISE_BYTES_THRESHOLD_POS                                                        (2UL)
#define EMD_CONTROL_EMD_NOISE_BYTES_THRESHOLD_MASK                                                       (0x0000003CUL)  /**< 2-Defines the threshold under which transmission errors are treated as noise. Note: CRC bytes are NOT included/counted!*/
#define EMD_CONTROL_EMD_TRANSMISSION_ERROR_ABOVE_NOISE_THRESHOLD_IS_NO_EMD_POS                           (1UL)
#define EMD_CONTROL_EMD_TRANSMISSION_ERROR_ABOVE_NOISE_THRESHOLD_IS_NO_EMD_MASK                          (0x00000002UL)  /**< 1-Transmission errors with received byte length >= EMD_NOISE_BYTES_THRESHOLD is never treated as EMD (EMVCo 2.5 standard)*/
#define EMD_CONTROL_EMD_ENABLE_POS                                                                       (0UL)
#define EMD_CONTROL_EMD_ENABLE_MASK                                                                      (0x00000001UL)  /**< 0-EMD handling enabled*/
/**
* @}
*/

/**
* @name felica_emd_control
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define FELICA_EMD_CONTROL                                                                                0x4
#define FELICA_EMD_CONTROL_FELICA_EMD_RC_BYTE_VALUE_POS                                                  (24UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_RC_BYTE_VALUE_MASK                                                 (0xFF000000UL)  /**< -RC byte value that needs to be received to not treat the frame as EMD*/
#define FELICA_EMD_CONTROL_FELICA_EMD_LENGTH_BYTE_MAX_POS                                                (16UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_LENGTH_BYTE_MAX_MASK                                               (0x00FF0000UL)  /**< -Maximum Legth byte value that needs to be received to not treat the frame as EMD*/
#define FELICA_EMD_CONTROL_FELICA_EMD_LENGTH_BYTE_MIN_POS                                                (8UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_LENGTH_BYTE_MIN_MASK                                               (0x0000FF00UL)  /**< -Minimum Legth byte value that needs to be received to not treat the frame as EMD*/
#define FELICA_EMD_CONTROL_RESERVED_POS                                                                  (5UL)
#define FELICA_EMD_CONTROL_RESERVED_MASK                                                                 (0x000000E0UL)  /**< -Reserved */
#define FELICA_EMD_CONTROL_FELICA_EMD_INTEGRITY_ERR_CHECK_ENABLE_POS                                     (4UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_INTEGRITY_ERR_CHECK_ENABLE_MASK                                    (0x00000010UL)  /**< -FeliCa EMD handling enabled when integrity error is set*/
#define FELICA_EMD_CONTROL_FELICA_EMD_PROTOCOL_ERR_CHECK_ENABLE_POS                                      (3UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_PROTOCOL_ERR_CHECK_ENABLE_MASK                                     (0x00000008UL)  /**< -FeliCa EMD handling enabled when protocol error is set*/
#define FELICA_EMD_CONTROL_FELICA_EMD_RC_CHECK_ENABLE_POS                                                (2UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_RC_CHECK_ENABLE_MASK                                               (0x00000004UL)  /**< -FeliCa RC byte check enabled for FeliCa EMD handling*/
#define FELICA_EMD_CONTROL_FELICA_EMD_LEN_CHECK_ENABLE_POS                                               (1UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_LEN_CHECK_ENABLE_MASK                                              (0x00000002UL)  /**< -FeliCa Length byte check enabled for FeliCa EMD handling*/
#define FELICA_EMD_CONTROL_FELICA_EMD_ENABLE_POS                                                         (0UL)
#define FELICA_EMD_CONTROL_FELICA_EMD_ENABLE_MASK                                                        (0x00000001UL)  /**< -FeliCa EMD handling enabled*/
/**
* @}
*/

/**
* @name clif_rx_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_RX_STATUS                                                                                    0x5
#define CLIF_RX_STATUS_R                                                                                    0x5
#define CLIF_RX_STATUS_RESERVED_POS                                                                      (27UL)
#define CLIF_RX_STATUS_RESERVED_MASK                                                                     (0xF8000000UL)  /**< 27-Reserved*/
#define CLIF_RX_STATUS_RX_COLL_POS_POS                                                                   (20UL)
#define CLIF_RX_STATUS_RX_COLL_POS_MASK                                                                  (0x07F00000UL)  /**< 20-Status indicating the bit position of the first collision detected in the data bit. The value is valid only when RX_COLLISION_DETECTED==1. The value of the RX_BIT_ALIGN is also taken intoaccount (RX_COLL_POS = physical bit position in the flow + RX_BIT_ALIGN value).Indicates the collision position in the first 8 bytes only. Can be used during the TypeA/ICODE/EPC anticollision procedure.0x00 - 1st bit 0x01 - 2nd bit...0x7F - 128th bit.The status register is not updated by the collision detected on stop or parity bit.*/
#define CLIF_RX_STATUS_RX_NUM_LAST_BITS_POS                                                              (17UL)
#define CLIF_RX_STATUS_RX_NUM_LAST_BITS_MASK                                                             (0x000E0000UL)  /**< 17-Status indicating the number of valid bits in the last byte written to the System RAM.0x0 - all bits are valid 0x1 - 1 bit is valid...0x7 - 7 bits are valid*/
#define CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_POS                                                        (13UL)
#define CLIF_RX_STATUS_RX_NUM_FRAMES_RECEIVED_MASK                                                       (0x0001E000UL)  /**< 13-Indicates the number of frames received. The value is updated after every normal frame reception in RX_MULTIPLE mode.The value is valid only if the bit RX_MULTIPLE_ENABLE==1.*/
#define CLIF_RX_STATUS_RX_NUM_BYTES_RECEIVED_POS                                                         (0UL)
#define CLIF_RX_STATUS_RX_NUM_BYTES_RECEIVED_MASK                                                        (0x00001FFFUL)  /**< 0-Status indicating the number of bytes written to the System RAM.0x0000 - no data0x0001 - 1 byte...0x1000 - 4K bytes.0x1001 - 0x1FFF - not supported*/
#define CLIF_RX_STATUS__RESET_VALUE                                                                      (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_rx_status_error
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_RX_STATUS_ERROR                                                                              0x6
#define CLIF_RX_STATUS_ERROR_R                                                                              0x6
#define CLIF_RX_STATUS_ERROR_RESERVED_POS                                                                (30UL)
#define CLIF_RX_STATUS_ERROR_RESERVED_MASK                                                               (0xC0000000UL)  /**< 30-Reserved*/
#define CLIF_RX_STATUS_ERROR_EMD_DETECTED_IN_RXDEC_POS                                                   (29UL)
#define CLIF_RX_STATUS_ERROR_EMD_DETECTED_IN_RXDEC_MASK                                                  (0x20000000UL)  /**< 29-The high level indicates that the EMD was detected (in the SigPro or in the RxDecoder or in both) during the reception.*/
#define CLIF_RX_STATUS_ERROR_EMD_DETECTED_IN_SIGPRO_POS                                                  (28UL)
#define CLIF_RX_STATUS_ERROR_EMD_DETECTED_IN_SIGPRO_MASK                                                 (0x10000000UL)  /**< 28-The high level indicates that the EMD was detected on the Physical layer (in the SigPro) during the reception.*/
#define CLIF_RX_STATUS_ERROR_EXT_RFOFF_DETECTED_POS                                                      (27UL)
#define CLIF_RX_STATUS_ERROR_EXT_RFOFF_DETECTED_MASK                                                     (0x08000000UL)  /**< 27-The high level indicates that the external RF-field vanished during the reception.*/
#define CLIF_RX_STATUS_ERROR_RX_FRAME_MAXLEN_VIOL_POS                                                    (26UL)
#define CLIF_RX_STATUS_ERROR_RX_FRAME_MAXLEN_VIOL_MASK                                                   (0x04000000UL)  /**< 26-The high level indicates that the received frame length violated the configured maximum limit.*/
#define CLIF_RX_STATUS_ERROR_RX_FRAME_MINLEN_VIOL_POS                                                    (25UL)
#define CLIF_RX_STATUS_ERROR_RX_FRAME_MINLEN_VIOL_MASK                                                   (0x02000000UL)  /**< 25-The high level indicates that the received frame length violated the configured minimum limit.*/
#define CLIF_RX_STATUS_ERROR_RX_FRAME_LE_CRC_POS                                                         (24UL)
#define CLIF_RX_STATUS_ERROR_RX_FRAME_LE_CRC_MASK                                                        (0x01000000UL)  /**< 24-The high level indicates that the received frame length is less or equal to the expected CRC field length.*/
#define CLIF_RX_STATUS_ERROR_RX_NOT_FULL_BYTE_POS                                                        (23UL)
#define CLIF_RX_STATUS_ERROR_RX_NOT_FULL_BYTE_MASK                                                       (0x00800000UL)  /**< 23-The high level indicates that the last received character in the frame has less than 8 bits.*/
#define CLIF_RX_STATUS_ERROR_RX_MISSING_PARBIT_DETECTED_POS                                              (22UL)
#define CLIF_RX_STATUS_ERROR_RX_MISSING_PARBIT_DETECTED_MASK                                             (0x00400000UL)  /**< 22-The high level indicates that the last received character in the frame has 8 data bits but the expected parity bit is absent.*/
#define CLIF_RX_STATUS_ERROR_RX_MISSING_STOPBIT_DETECTED_POS                                             (21UL)
#define CLIF_RX_STATUS_ERROR_RX_MISSING_STOPBIT_DETECTED_MASK                                            (0x00200000UL)  /**< 21-The high level indicates that the last received character in the frame has 8 data bits but the expected stop bit is absent.*/
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_PARBIT_DETECTED_POS                                            (20UL)
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_PARBIT_DETECTED_MASK                                           (0x00100000UL)  /**< 20-The high level indicates that the collision was detected on the parity bit position.*/
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_STOPBIT_DETECTED_POS                                           (19UL)
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_STOPBIT_DETECTED_MASK                                          (0x00080000UL)  /**< 19- The high level indicates that the collision was detected on the stop bit position.*/
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_POS                                                   (18UL)
#define CLIF_RX_STATUS_ERROR_RX_COLLISION_DETECTED_MASK                                                  (0x00040000UL)  /**< 18-The high level indicates that the collision was detected during the frame reception.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_RXOVER_POS                                                       (17UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_RXOVER_MASK                                                      (0x00020000UL)  /**< 17-The high level indicates that the frame reception was stopped by SGP_MSG_RXOVER_* message reception.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_RFOFF_POS                                                        (16UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_RFOFF_MASK                                                       (0x00010000UL)  /**< 16-The high level indicates that the frame reception was interrupted by external RF-field vanishing event.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_ERR_POS                                                          (15UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_ERR_MASK                                                         (0x00008000UL)  /**< 15-The high level indicates that the frame reception was stopped by detected communication error event.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_LEN_POS                                                          (14UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_LEN_MASK                                                         (0x00004000UL)  /**< 14-The high level indicates that the frame reception was normally stopped by byte counter expiration event. Relates to the protocols where the LEN field is used in the frame format (Felica RM/CM, FWEC RM/CM).*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_INVPAR_POS                                                       (13UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_INVPAR_MASK                                                      (0x00002000UL)  /**< 13-The high level indicates that the frame reception was normally stopped by the inverted parity detection event. Relates to the TypeA RM 212-848 kbps modes. 12 RX_STOP_ON_PATTERN R 0h The high level indicates that the frame reception was normally stopped by EOF pattern detection event. Relates to the TypeB RM/CM, B prime RM/CM modes.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_PATTERN_POS                                                      (12UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_PATTERN_MASK                                                     (0x00001000UL)  /**< 12-The high level indicates that the frame reception was normally stopped by EOF pattern detection event. Relates to the TypeB RM/CM, B prime RM/CM modes.*/
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_ANTICOLL_POS                                                     (11UL)
#define CLIF_RX_STATUS_ERROR_RX_STOP_ON_ANTICOLL_MASK                                                    (0x00000800UL)  /**< 11-The high level indicates that the frame reception was normally stopped by collision detected on data bit position. Relates to the bit-oriented frame reception in TypeA RM 106 kbps mode during the anticollision procedure.*/
#define CLIF_RX_STATUS_ERROR_RX_CRC_ERROR_POS                                                            (10UL)
#define CLIF_RX_STATUS_ERROR_RX_CRC_ERROR_MASK                                                           (0x00000400UL)  /**< 10-The high level indicates that the CRC error is detected in the received frame.*/
#define CLIF_RX_STATUS_ERROR_RX_LEN_ERROR_POS                                                            (9UL)
#define CLIF_RX_STATUS_ERROR_RX_LEN_ERROR_MASK                                                           (0x00000200UL)  /**< 9-The high level is set if the received frame is shorter than the length stated in the received frame LEN field OR if the LEN parameter in the received frame violates the configured [RX_FRAME_MINLEN:RX_FRAME_MAX LEN] limits. Can assert only in the mode swhere the LEN field is used in the frame format (Felica RM/CM, FWEC RM/CM).*/
#define CLIF_RX_STATUS_ERROR_RX_SIGPRO_ERROR_POS                                                         (8UL)
#define CLIF_RX_STATUS_ERROR_RX_SIGPRO_ERROR_MASK                                                        (0x00000100UL)  /**< 8-The high level indicates that the communication error/errors were detected during the frame reception on physical layer(in the SigPro).*/
#define CLIF_RX_STATUS_ERROR_RX_PARITY_ERROR_POS                                                         (7UL)
#define CLIF_RX_STATUS_ERROR_RX_PARITY_ERROR_MASK                                                        (0x00000080UL)  /**< 7-The high level indicates that the parity error was detected during the frame reception.*/
#define CLIF_RX_STATUS_ERROR_RX_STOPBIT_ERROR_POS                                                        (6UL)
#define CLIF_RX_STATUS_ERROR_RX_STOPBIT_ERROR_MASK                                                       (0x00000040UL)  /**< 6-The high level indicates that the stop bit error (0 level instead of 1 on the stop bit position) was detected during the frame reception.*/
#define CLIF_RX_STATUS_ERROR_RX_WRITE_ERROR_POS                                                          (5UL)
#define CLIF_RX_STATUS_ERROR_RX_WRITE_ERROR_MASK                                                         (0x00000020UL)  /**< 5-The high level indicates that the error acknowledge status was received on the CLIF-system interface during the received frame transmission to the System RAM.*/
#define CLIF_RX_STATUS_ERROR_RX_BUFFER_OVFL_ERROR_POS                                                    (4UL)
#define CLIF_RX_STATUS_ERROR_RX_BUFFER_OVFL_ERROR_MASK                                                   (0x00000010UL)  /**< 4-The high level indicates that the data payload length in the received frame exceeds the 28 bytes limit. Relates to the PollReq procedure in the Felica RM mode only.*/
#define CLIF_RX_STATUS_ERROR_RX_LATENCY_ERROR_POS                                                        (3UL)
#define CLIF_RX_STATUS_ERROR_RX_LATENCY_ERROR_MASK                                                       (0x00000008UL)  /**< 3-The high level indicates that the write request flow was corrupted due to traffic congestion on the system interface during the received frame transmission to the System RAM.*/
#define CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_POS                                                 (2UL)
#define CLIF_RX_STATUS_ERROR_RX_DATA_INTEGRITY_ERROR_MASK                                                (0x00000004UL)  /**< 2-The high level indicates that the data integrity corruption (parity/CRC/etc error)was detected in the received frame.*/
#define CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_POS                                                       (1UL)
#define CLIF_RX_STATUS_ERROR_RX_PROTOCOL_ERROR_MASK                                                      (0x00000002UL)  /**< 1-The high level indicates that the protocol requirements violation (stop bit error,missing parity bit, not full byte received, etc) was detected in the received frame.*/
#define CLIF_RX_STATUS_ERROR_RX_CL_ERROR_POS                                                             (0UL)
#define CLIF_RX_STATUS_ERROR_RX_CL_ERROR_MASK                                                            (0x00000001UL)  /**< 0-The high level indicates that some protocol/data integrity erorr/errors were detected during the frame reception*/
#define CLIF_RX_STATUS_ERROR__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_status
* <b>Reset value:</b> 0x20000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_STATUS                                                                                       0x7
#define CLIF_STATUS_R                                                                                       0x7
#define CLIF_STATUS_RESERVED_POS                                                                         (30UL)
#define CLIF_STATUS_RESERVED_MASK                                                                        (0xC0000000UL)  /**< 30-Reserved */
#define CLIF_STATUS_CRC_OK_POS                                                                           (29UL)
#define CLIF_STATUS_CRC_OK_MASK                                                                          (0x20000000UL)  /**< 29-This bit indicates the status of the actual CRC calculation. If 1 the CRC is correct. meaning the CRC register has the value 0 or the residue value if inverted CRC is used. Note: This flag should only by evaluated at the end of a communication */
#define CLIF_STATUS_RX_SC_DETECTED_POS                                                                   (28UL)
#define CLIF_STATUS_RX_SC_DETECTED_MASK                                                                  (0x10000000UL)  /**< 28-Status signal indicating that a sub-carrier is detected.*/
#define CLIF_STATUS_RX_SOF_DETECTED_POS                                                                  (27UL)
#define CLIF_STATUS_RX_SOF_DETECTED_MASK                                                                 (0x08000000UL)  /**< 27-Status signal indicating that a SOF has been detected.*/
#define CLIF_STATUS_TX_RF_STATUS_POS                                                                     (26UL)
#define CLIF_STATUS_TX_RF_STATUS_MASK                                                                    (0x04000000UL)  /**< 26-If set to 1 this bit indicates that the drivers are turned on. meaning an RF-Field is created by the device itself. */
#define CLIF_STATUS_RF_DET_STATUS_POS                                                                    (25UL)
#define CLIF_STATUS_RF_DET_STATUS_MASK                                                                   (0x02000000UL)  /**< 25-If set to 1 this bit indicates that an external RF-Field is detected by the rf level detectors (after digital filtering) */
#define CLIF_STATUS_ADC_Q_CLIPPING_POS                                                                   (24UL)
#define CLIF_STATUS_ADC_Q_CLIPPING_MASK                                                                  (0x01000000UL)  /**< 24-Indicates that the Q-Channel ADC has clipped (value 0 or 63), This bit is reset with Rx-reset (enabling of receiver).*/
#define CLIF_STATUS_ADC_I_CLIPPING_POS                                                                   (23UL)
#define CLIF_STATUS_ADC_I_CLIPPING_MASK                                                                  (0x00800000UL)  /**< 23-Indicates that the I-Channel ADC has clipped (value 0 or 63), This bit is reset with Rx-reset (enabling of receiver).*/
#define CLIF_STATUS_RESERVED1_POS                                                                        (12UL)
#define CLIF_STATUS_RESERVED1_MASK                                                                       (0x007FF000UL)  /**< 12-22 Reserved */
#define CLIF_STATUS_TX_NO_DATA_ERROR_POS                                                                 (11UL)
#define CLIF_STATUS_TX_NO_DATA_ERROR_MASK                                                                (0x00000800UL)  /**< 11-This error flag is set to 1. in case a transmission is started but no data is available (register NumBytesToSend == 0). */
#define CLIF_STATUS_RF_ACTIVE_ERROR_CAUSE_POS                                                            (8UL)
#define CLIF_STATUS_RF_ACTIVE_ERROR_CAUSE_MASK                                                           (0x00000700UL)  /**< 8-This status flag indicates the cause of an NFC-Active error. Note: This bits are only valid when the RF_ACTIVE_ERROR_IRQ is raised and will be cleared as soon as the bit TX_RF_ENABLE is set to 1. 0* No Error. reset value 1 External field was detected on within TIDT timing 2 External field was detected on within TADT timing 3 No external field was detected within TADT timings 4 Peer did switch off RFField without but no Rx event was raised (no data received) 5 - 7 Reserved.*/
#define CLIF_STATUS_RESERVED2_POS                                                                        (6UL)
#define CLIF_STATUS_RESERVED2_MASK                                                                       (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_STATUS_RX_ENABLE_POS                                                                        (5UL)
#define CLIF_STATUS_RX_ENABLE_MASK                                                                       (0x00000020UL)  /**< 5-This bit indicates if the RxDecoder is enalbed. If 1 the RxDecoder was enabled by the Transceive Unit and is now ready for data reception */
#define CLIF_STATUS_TX_ACTIVE_POS                                                                        (4UL)
#define CLIF_STATUS_TX_ACTIVE_MASK                                                                       (0x00000010UL)  /**< 4-This bit indicates activity of the TxEncoder. If 1 a transmission is ongoing otherwise the TxEncoder is in idle state.*/
#define CLIF_STATUS_RX_ACTIVE_POS                                                                        (3UL)
#define CLIF_STATUS_RX_ACTIVE_MASK                                                                       (0x00000008UL)  /**< 3-This bit indicates activity of the RxDecoder. If 1 a data reception is ongoing. otherwise the RxDecoder is in idle state. */
#define CLIF_STATUS_TRANSCEIVE_STATE_POS                                                                 (0UL)
#define CLIF_STATUS_TRANSCEIVE_STATE_MASK                                                                (0x00000007UL)  /**< 0-This registers hold the command bits 0* IDLE state 1 WaitTransmit state 2 Transmitting state 3 WaitReceive state 4 WaitForData state 5 Receiving state 6 LoopBack state 7 reserved*/
#define CLIF_STATUS__RESET_VALUE                                                                         (0x20000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_transceive_control
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TRANSCEIVE_CONTROL                                                                           0x8
#define CLIF_TRANSCEIVE_CONTROL_R                                                                           0x8
#define CLIF_TRANSCEIVE_CONTROL_W                                                                           0x8
#define CLIF_TRANSCEIVE_CONTROL_RESERVED_POS                                                             (16UL)
#define CLIF_TRANSCEIVE_CONTROL_RESERVED_MASK                                                            (0xFFFF0000UL)  /**< 16-Reserved */
#define CLIF_TRANSCEIVE_CONTROL_TX_BITPHASE_POS                                                          (8UL)
#define CLIF_TRANSCEIVE_CONTROL_TX_BITPHASE_MASK                                                         (0x0000FF00UL)  /**< 8-Defines the number of 13.56MHz cycles used for adjustment of tx_wait to meet the FDT. */
#define CLIF_TRANSCEIVE_CONTROL_RESERVED1_POS                                                            (6UL)
#define CLIF_TRANSCEIVE_CONTROL_RESERVED1_MASK                                                           (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_TRANSCEIVE_CONTROL_TX_SKIP_SEND_ENABLE_POS                                                  (5UL)
#define CLIF_TRANSCEIVE_CONTROL_TX_SKIP_SEND_ENABLE_MASK                                                 (0x00000020UL)  /**< 5-If set to 1 not transmission is started after tx_wait is expired and START_SEND was set Note: The bit is cleared by HW when the WaitReceive state is entered.*/
#define CLIF_TRANSCEIVE_CONTROL_RESERVED2_POS                                                            (4UL)
#define CLIF_TRANSCEIVE_CONTROL_RESERVED2_MASK                                                           (0x00000010UL)  /**< 4-Reserved */
#define CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_POS                                                  (3UL)
#define CLIF_TRANSCEIVE_CONTROL_TX_FRAMESTEP_ENABLE_MASK                                                 (0x00000008UL)  /**< 3-If set to 1. at every start of transmission. each byte of data is sent in a seperate frame. SOF and EOF is appended to the data byte according to the framing settings. After one byte is transmitted. the TxEncoder waits for a new start trigger to continue with the next byte. */
#define CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_POS                                                   (2UL)
#define CLIF_TRANSCEIVE_CONTROL_RX_MULTIPLE_ENABLE_MASK                                                  (0x00000004UL)  /**< 2-If this bit is set to 1. the receiver is re-activated after the end of a reception. A statusbyte is written to the RAM containing all relevant status information of the frame. Note: Data in RAM is word aligned therefore empty bytes of a data Word in RAM are padded with 0x00 bytes. SW has to calculate the correct address for the following frame. */
#define CLIF_TRANSCEIVE_CONTROL_RESERVED3_POS                                                            (1UL)
#define CLIF_TRANSCEIVE_CONTROL_RESERVED3_MASK                                                           (0x00000002UL)  /**< 1-Reserved */
#define CLIF_TRANSCEIVE_CONTROL_INITIATOR_POS                                                            (0UL)
#define CLIF_TRANSCEIVE_CONTROL_INITIATOR_MASK                                                           (0x00000001UL)  /**< 0-Set to 1. the CLIF is configured for initiator mode. Depending on this setting the behavior of the transceive command is different*/
#define CLIF_TRANSCEIVE_CONTROL__RESET_VALUE                                                             (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol01_mod
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL01_MOD                                                                              0x9
#define CLIF_TX_SYMBOL01_MOD_R                                                                              0x9
#define CLIF_TX_SYMBOL01_MOD_W                                                                              0x9
#define CLIF_TX_SYMBOL01_MOD_RESERVED_POS                                                                (24UL)
#define CLIF_TX_SYMBOL01_MOD_RESERVED_MASK                                                               (0xFF000000UL)  /**< 24-Reserved */
#define CLIF_TX_SYMBOL01_MOD_TX_S01_MODWIDTH_POS                                                         (16UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_MODWIDTH_MASK                                                        (0x00FF0000UL)  /**< 16-Specifies the length of a pulse for sending data of symbol 0/1. The length is given by the number of carrier clocks + 1. */
#define CLIF_TX_SYMBOL01_MOD_RESERVED1_POS                                                               (9UL)
#define CLIF_TX_SYMBOL01_MOD_RESERVED1_MASK                                                              (0x0000FE00UL)  /**< 9-Reserved */
#define CLIF_TX_SYMBOL01_MOD_TX_S01_MILLER_ENABLE_POS                                                    (8UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_MILLER_ENABLE_MASK                                                   (0x00000100UL)  /**< 8-If set to 1. pulse modulation is applied according to modified miller coding. */
#define CLIF_TX_SYMBOL01_MOD_TX_S01_INV_ENV_POS                                                          (7UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_INV_ENV_MASK                                                         (0x00000080UL)  /**< 7-If set to 1. the output envelope is inverted. */
#define CLIF_TX_SYMBOL01_MOD_TX_S01_ENV_TYPE_POS                                                         (4UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_ENV_TYPE_MASK                                                        (0x00000070UL)  /**< 4-Specifies the type of envelope used for transmission of data packets. The selected envelope type is applied to the pseudo bit stream. 000b Direct output 001b Manchester code 010b Manchster code with subcarrier 011b BPSK 100b RZ (pulse of half bit length at beginning of second half of bit) 101b RZ (pulse of half bit length at beginning of bit) 110b Manchester tupple 111b RFU*/
#define CLIF_TX_SYMBOL01_MOD_TX_S01_SC_FREQ_POS                                                          (3UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_SC_FREQ_MASK                                                         (0x00000008UL)  /**< 3-Specifies the frequency of the subcarrier. 0 424 kHz 1 848 kHz */
#define CLIF_TX_SYMBOL01_MOD_TX_S01_BIT_FREQ_POS                                                         (0UL)
#define CLIF_TX_SYMBOL01_MOD_TX_S01_BIT_FREQ_MASK                                                        (0x00000007UL)  /**< 0-Specifies the frequency of the bit-stream.  000b -> 1.695 MHz. 001b -> Reserved. 010b -> 26 kHz. 011b -> 53 kHz. 100b -> 106 kHz. 101b -> 212 kHz. 110b -> 424 kHz. 111b -> 848 kHz.*/
#define CLIF_TX_SYMBOL01_MOD__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol1_def
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL1_DEF                                                                               0xA
#define CLIF_TX_SYMBOL1_DEF_R                                                                               0xA
#define CLIF_TX_SYMBOL1_DEF_W                                                                               0xA
#define CLIF_TX_SYMBOL1_DEF_TX_SYMBOL1_DEF_POS                                                           (0UL)
#define CLIF_TX_SYMBOL1_DEF_TX_SYMBOL1_DEF_MASK                                                          (0xFFFFFFFFUL)  /**< 0-Pattern definition for Symbol1 */
#define CLIF_TX_SYMBOL1_DEF__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol0_def
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL0_DEF                                                                               0xB
#define CLIF_TX_SYMBOL0_DEF_R                                                                               0xB
#define CLIF_TX_SYMBOL0_DEF_W                                                                               0xB
#define CLIF_TX_SYMBOL0_DEF_TX_SYMBOL0_DEF_POS                                                           (0UL)
#define CLIF_TX_SYMBOL0_DEF_TX_SYMBOL0_DEF_MASK                                                          (0xFFFFFFFFUL)  /**< 0-Pattern definition for Symbol0*/
#define CLIF_TX_SYMBOL0_DEF__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol23_mod
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL23_MOD                                                                              0xC
#define CLIF_TX_SYMBOL23_MOD_R                                                                              0xC
#define CLIF_TX_SYMBOL23_MOD_W                                                                              0xC
#define CLIF_TX_SYMBOL23_MOD_RESERVED_POS                                                                (24UL)
#define CLIF_TX_SYMBOL23_MOD_RESERVED_MASK                                                               (0xFF000000UL)  /**< 24-Reserved */
#define CLIF_TX_SYMBOL23_MOD_TX_S23_MODWIDTH_POS                                                         (16UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_MODWIDTH_MASK                                                        (0x00FF0000UL)  /**< 16-Specifies the length of a pulse for sending data of symbol 2/3. The length is given by the number of carrier clocks + 1.*/
#define CLIF_TX_SYMBOL23_MOD_RESERVED1_POS                                                               (9UL)
#define CLIF_TX_SYMBOL23_MOD_RESERVED1_MASK                                                              (0x0000FE00UL)  /**< 9-Reserved */
#define CLIF_TX_SYMBOL23_MOD_TX_S23_MILLER_ENABLE_POS                                                    (8UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_MILLER_ENABLE_MASK                                                   (0x00000100UL)  /**< 8-If set to 1 pulse modulation is applied according to modified miller coding.*/
#define CLIF_TX_SYMBOL23_MOD_TX_S23_INV_ENV_POS                                                          (7UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_INV_ENV_MASK                                                         (0x00000080UL)  /**< 7-If set to 1 the output envelope is inverted.*/
#define CLIF_TX_SYMBOL23_MOD_TX_S23_ENV_TYPE_POS                                                         (4UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_ENV_TYPE_MASK                                                        (0x00000070UL)  /**< 4-Specifies the type of envelope used for transmission of data packets. The selected envelope type is applied to the pseudo bit stream. 000b Direct output 001b Manchester code 010b Manchster code with subcarrier 011b BPSK 100b RZ (pulse of half bit length at beginning of second half of bit) 101b RZ (pulse of half bit length at beginning of bit) 110b Manchester tupple 111b RFU*/
#define CLIF_TX_SYMBOL23_MOD_TX_S23_SC_FREQ_POS                                                          (3UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_SC_FREQ_MASK                                                         (0x00000008UL)  /**< 3-Specifies the frequency of the subcarrier. 0 424 kHz 1 848 kHz*/
#define CLIF_TX_SYMBOL23_MOD_TX_S23_BIT_FREQ_POS                                                         (0UL)
#define CLIF_TX_SYMBOL23_MOD_TX_S23_BIT_FREQ_MASK                                                        (0x00000007UL)  /**< 0-Specifies the frequency of the bit-stream.  000b -> 1.695 MHz. 001b -> Reserved. 010b -> 26 kHz. 011b -> 53 kHz. 100b -> 106 kHz. 101b -> 212 kHz. 110b -> 424 kHz. 111b -> 848 kHz.*/
#define CLIF_TX_SYMBOL23_MOD__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol23_def
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL23_DEF                                                                              0xD
#define CLIF_TX_SYMBOL23_DEF_R                                                                              0xD
#define CLIF_TX_SYMBOL23_DEF_W                                                                              0xD
#define CLIF_TX_SYMBOL23_DEF_RESERVED_POS                                                                (24UL)
#define CLIF_TX_SYMBOL23_DEF_RESERVED_MASK                                                               (0xFF000000UL)  /**< 24-Reserved */
#define CLIF_TX_SYMBOL23_DEF_TX_SYMBOL3_DEF_POS                                                          (16UL)
#define CLIF_TX_SYMBOL23_DEF_TX_SYMBOL3_DEF_MASK                                                         (0x00FF0000UL)  /**< 16-Pattern definition for Symbol3 */
#define CLIF_TX_SYMBOL23_DEF_RESERVED1_POS                                                                (8UL)
#define CLIF_TX_SYMBOL23_DEF_RESERVED1_MASK                                                               (0x0000FF00UL)  /**< 8-Reserved */
#define CLIF_TX_SYMBOL23_DEF_TX_SYMBOL2_DEF_POS                                                          (0UL)
#define CLIF_TX_SYMBOL23_DEF_TX_SYMBOL2_DEF_MASK                                                         (0x000000FFUL)  /**< 0-Pattern definition for Symbol2*/
#define CLIF_TX_SYMBOL23_DEF__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_symbol_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_SYMBOL_CONFIG                                                                             0xE
#define CLIF_TX_SYMBOL_CONFIG_R                                                                             0xE
#define CLIF_TX_SYMBOL_CONFIG_W                                                                             0xE
#define CLIF_TX_SYMBOL_CONFIG_RESERVED_POS                                                               (31UL)
#define CLIF_TX_SYMBOL_CONFIG_RESERVED_MASK                                                              (0x80000000UL)  /**< 31-Reserved */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_LEN_POS                                                   (27UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_LEN_MASK                                                  (0x78000000UL)  /**< 27-Specifies the number of bits issued for symbol 1 burst. The 3 bits encode a range from 8 to 256 bit length: 0000b 8 bit 0001b 12 bit 0010b 16 bit 0011b 24 bit 0100b 32 bit 0101b 40 bit 0110b 48 bit 0111b 64 bit 1000b 80 bit 1001b 96 bit 1010b 112 bit 1011b 128 bit 1100b 160 bit 1101b 192 bit 1110b 224 bit 1111b 256 bit*/
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_TYPE_POS                                                  (26UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_TYPE_MASK                                                 (0x04000000UL)  /**< 26-Specifies the type of the burst of Symbol1 (logical zero / logical one) */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_ONLY_POS                                                  (25UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_ONLY_MASK                                                 (0x02000000UL)  /**< 25-If set to 1. Symbol1 consists only of a burst and no symbol pattern */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_ENABLE_POS                                                (24UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_BURST_ENABLE_MASK                                               (0x01000000UL)  /**< 24-If set to 1. the burst of Symbol0 of the length defined in bit field SYMBOL1_BURST_LEN is enabled         */
#define CLIF_TX_SYMBOL_CONFIG_RESERVED1_POS                                                              (23UL)
#define CLIF_TX_SYMBOL_CONFIG_RESERVED1_MASK                                                             (0x00800000UL)  /**< 23-Reserved */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_LEN_POS                                                   (19UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_LEN_MASK                                                  (0x00780000UL)  /**< 19-Specifies the number of bits issued for symbol 0 burst. The 3 bits encode a range from 8 to 256 bit length: 0000b 8 bit 0001b 12 bit 0010b 16 bit 0011b 24 bit 0100b 32 bit 0101b 40 bit 0110b 48 bit 0111b 64 bit 1000b 80 bit 1001b 96 bit 1010b 112 bit 1011b 128 bit 1100b 160 bit 1101b 192 bit 1110b 224 bit 1111b 256 bit*/
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_TYPE_POS                                                  (18UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_TYPE_MASK                                                 (0x00040000UL)  /**< 18-Specifies the type of the burst of Symbol0 (logical zero / logical one) */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_ONLY_POS                                                  (17UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_ONLY_MASK                                                 (0x00020000UL)  /**< 17-If set to 1. Symbol0 consists only of a burst and no symbol pattern */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_ENABLE_POS                                                (16UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_BURST_ENABLE_MASK                                               (0x00010000UL)  /**< 16-If set to 1. the burst of Symbol0 of the length defined in bit field SYMBOL0_BURST_LEN is enabled */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL3_LEN_POS                                                         (13UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL3_LEN_MASK                                                        (0x0000E000UL)  /**< 13-Specifies the number of valid bits of the symbol definition of Symbol3. The range is from 1 bit (value 0000) to 8 bit (value 111) */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL2_LEN_POS                                                         (10UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL2_LEN_MASK                                                        (0x00001C00UL)  /**< 10-Specifies the number of valid bits of the symbol definition of Symbol2. The range is from 1 bit (value 0000) to 8bit (value 111) */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_LEN_POS                                                         (5UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL1_LEN_MASK                                                        (0x000003E0UL)  /**< 5-Specifies the number of valid bits of the symbol definition of Symbol1. The range is from 1 bit (value 0000) to 31 bits (value 11110) */
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_LEN_POS                                                         (0UL)
#define CLIF_TX_SYMBOL_CONFIG_TX_SYMBOL0_LEN_MASK                                                        (0x0000001FUL)  /**< 0-Specifies the number of valid bits of the symbol definition of Symbol0. The range is from 1 bit (value 0000) to 31 bits (value 11110)*/
#define CLIF_TX_SYMBOL_CONFIG__RESET_VALUE                                                               (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_frame_config
* <b>Reset value:</b> 0x00000200
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_FRAME_CONFIG                                                                              0xF
#define CLIF_TX_FRAME_CONFIG_R                                                                              0xF
#define CLIF_TX_FRAME_CONFIG_W                                                                              0xF
#define CLIF_TX_FRAME_CONFIG_RESERVED_POS                                                                (19UL)
#define CLIF_TX_FRAME_CONFIG_RESERVED_MASK                                                               (0xFFF80000UL)  /**< 19-Reserved */
#define CLIF_TX_FRAME_CONFIG_TX_DATA_CODE_TYPE_POS                                                       (16UL)
#define CLIF_TX_FRAME_CONFIG_TX_DATA_CODE_TYPE_MASK                                                      (0x00070000UL)  /**< 16-Specifies the type of encoding of data to be used 000b No special code 001b 1 out of 4 code [I-Code SLI] 010b 1 out of 256 code [I-Code SLI] 011b Pulse interval encoding (PIE) [I-Code EPC-V2] 100b 2bit tuple code (intended only for test purpose) 101-111b Reserved */
#define CLIF_TX_FRAME_CONFIG_TX_STOPBIT_TYPE_POS                                                         (13UL)
#define CLIF_TX_FRAME_CONFIG_TX_STOPBIT_TYPE_MASK                                                        (0x0000E000UL)  /**< 13-Enables the stop bit (logic 1) and extra guard time (logic 1). The value 0 disables transmission of stop-bits. 000b no stop-bit. no EGT 001b stop-bit. no EGT 010b stop-bit + 1 EGT 011b stop-bit + 2 EGT 100b stop-bit + 3 EGT 101b stop-bit + 4 EGT 110b stop-bit + 5 EGT 111b stop-bit + 6 EGT */
#define CLIF_TX_FRAME_CONFIG_TX_STARTBIT_ENABLE_POS                                                      (12UL)
#define CLIF_TX_FRAME_CONFIG_TX_STARTBIT_ENABLE_MASK                                                     (0x00001000UL)  /**< 12-If set to 1. a start-bit (logic 0) will be send */
#define CLIF_TX_FRAME_CONFIG_TX_MSB_FIRST_POS                                                            (11UL)
#define CLIF_TX_FRAME_CONFIG_TX_MSB_FIRST_MASK                                                           (0x00000800UL)  /**< 11-If set to 1. data bytes are interpreted MSB first for data transmission */
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_LAST_INV_ENABLE_POS                                               (10UL)
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_LAST_INV_ENABLE_MASK                                              (0x00000400UL)  /**< 10-If set to 1. the parity bit of last sent data byte is inverted */
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_TYPE_POS                                                          (9UL)
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_TYPE_MASK                                                         (0x00000200UL)  /**< 9-Defines the type of the parity bit 0 Even Parity is calculated 1 Odd parity is calculated       */
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_ENABLE_POS                                                        (8UL)
#define CLIF_TX_FRAME_CONFIG_TX_PARITY_ENABLE_MASK                                                       (0x00000100UL)  /**< 8-If set to 1. a parity bit is calculated and appended to each byte transmitted. If the Transmission Of Data Is Enabled and TX_NUM_BYTES_2_SEND is zero. then a NO_DATA_ERROR occurs. */
#define CLIF_TX_FRAME_CONFIG_RESERVED1_POS                                                               (5UL)
#define CLIF_TX_FRAME_CONFIG_RESERVED1_MASK                                                              (0x000000E0UL)  /**< 5-Reserved */
#define CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_POS                                                          (4UL)
#define CLIF_TX_FRAME_CONFIG_TX_DATA_ENABLE_MASK                                                         (0x00000010UL)  /**< 4-If set to 1. transmission of data is enabled otherwise only symbols are transmitted. */
#define CLIF_TX_FRAME_CONFIG_TX_STOP_SYMBOL_POS                                                          (2UL)
#define CLIF_TX_FRAME_CONFIG_TX_STOP_SYMBOL_MASK                                                         (0x0000000CUL)  /**< 2-Defines which pattern symbol is sent as frame stop-symbol 00b No symbol is sent 01b Symbol1 is sent 10b Symbol2 is sent 11b Symbol3 is sent */
#define CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_POS                                                         (0UL)
#define CLIF_TX_FRAME_CONFIG_TX_START_SYMBOL_MASK                                                        (0x00000003UL)  /**< 0-Defines which symbol pattern is sent as frame start-symbol 00b No symbol pattern is sent 01b Symbol0 is sent 10b Symbol1 is sent 11b Symbol2 is sent*/
#define CLIF_TX_FRAME_CONFIG__RESET_VALUE                                                                (0x00000200UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_data_mod
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_DATA_MOD                                                                                  0x10
#define CLIF_TX_DATA_MOD_R                                                                                  0x10
#define CLIF_TX_DATA_MOD_W                                                                                  0x10
#define CLIF_TX_DATA_MOD_RESERVED_POS                                                                    (25UL)
#define CLIF_TX_DATA_MOD_RESERVED_MASK                                                                   (0xFE000000UL)  /**< 25-Reserved*/
#define CLIF_TX_DATA_MOD_TX_ICODE_DATA_MODWIDTH_ENABLE_POS                                               (24UL)
#define CLIF_TX_DATA_MOD_TX_ICODE_DATA_MODWIDTH_ENABLE_MASK                                              (0x01000000UL)  /**< 24-Enables modulation width of icode data. Width of modulation is defined by the TX_DATA_MODWIDTH field. When 1, we should have TX_DATA_ENV_TYPE=0 and TX_DATA_INV_ENV=0*/
#define CLIF_TX_DATA_MOD_TX_DATA_MODWIDTH_POS                                                            (16UL)
#define CLIF_TX_DATA_MOD_TX_DATA_MODWIDTH_MASK                                                           (0x00FF0000UL)  /**< 16-Specifies the length of a pulse for sending data with miller pulse modulation enabled. The length is given by the number of carrier clocks + 1.*/
#define CLIF_TX_DATA_MOD_RESERVED1_POS                                                                   (9UL)
#define CLIF_TX_DATA_MOD_RESERVED1_MASK                                                                  (0x0000FE00UL)  /**< 9-Reserved*/
#define CLIF_TX_DATA_MOD_TX_DATA_MILLER_ENABLE_POS                                                       (8UL)
#define CLIF_TX_DATA_MOD_TX_DATA_MILLER_ENABLE_MASK                                                      (0x00000100UL)  /**< 8-If set to 1 pulse modulation is applied according to modified miller coding*/
#define CLIF_TX_DATA_MOD_TX_DATA_INV_ENV_POS                                                             (7UL)
#define CLIF_TX_DATA_MOD_TX_DATA_INV_ENV_MASK                                                            (0x00000080UL)  /**< 7-If set to 1 the output envelope is inverted*/
#define CLIF_TX_DATA_MOD_TX_DATA_ENV_TYPE_POS                                                            (4UL)
#define CLIF_TX_DATA_MOD_TX_DATA_ENV_TYPE_MASK                                                           (0x00000070UL)  /**< 4-Specifies the type of envelope used for transmission of data packets. The selected envelope type is applied to the pseudo bit stream. 000b Direct output 001b Manchester code 010b Manchster code with subcarrier 011b BPSK 100b RZ (pulse of half bit length at beginning of second half of bit) 101b RZ (pulse of half bit length at beginning of bit) 110b Manchester tupple coding 111b RFU*/
#define CLIF_TX_DATA_MOD_TX_DATA_SC_FREQ_POS                                                             (3UL)
#define CLIF_TX_DATA_MOD_TX_DATA_SC_FREQ_MASK                                                            (0x00000008UL)  /**< 3-Specifies the frequency of the subcarrier. 0 424 kHz 1 848 kHz*/
#define CLIF_TX_DATA_MOD_TX_DATA_BIT_FREQ_POS                                                            (0UL)
#define CLIF_TX_DATA_MOD_TX_DATA_BIT_FREQ_MASK                                                           (0x00000007UL)  /**< 0-Specifies the frequency of the bit-stream.  000b -> 1.695 MHz. 001b -> Reserved. 010b -> 26 kHz. 011b -> 53 kHz. 100b -> 106 kHz. 101b -> 212 kHz. 110b -> 424 kHz. 111b -> 848 kHz.*/
#define CLIF_TX_DATA_MOD__RESET_VALUE                                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_tx_wait
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_WAIT                                                                                      0x11
#define CLIF_TX_WAIT_R                                                                                      0x11
#define CLIF_TX_WAIT_W                                                                                      0x11
#define CLIF_TX_WAIT_RESERVED_POS                                                                        (28UL)
#define CLIF_TX_WAIT_RESERVED_MASK                                                                       (0xF0000000UL)  /**< 28-Reserved */
#define CLIF_TX_WAIT_TX_WAIT_VALUE_POS                                                                   (8UL)
#define CLIF_TX_WAIT_TX_WAIT_VALUE_MASK                                                                  (0x0FFFFF00UL)  /**< 8-Defines the tx_wait timer reload value. Note: If set to 00000h the tx_wait guard time is disabled Note: This bit is set by HW a protocol is detected in automatic mode detection*/
#define CLIF_TX_WAIT_TX_WAIT_PRESCALER_POS                                                               (0UL)
#define CLIF_TX_WAIT_TX_WAIT_PRESCALER_MASK                                                              (0x000000FFUL)  /**< 0-Defines the prescaler reload value for the tx_wait timer. Note: This bit is set by HW a protocol is  detected in automatic mode detection*/
#define CLIF_TX_WAIT__RESET_VALUE                                                                        (0x00000000UL)  /**< value after reset*/

/**
* @name clif_crc_tx_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_CRC_TX_CONFIG                                                                                0x12
#define CLIF_CRC_TX_CONFIG_R                                                                                0x12
#define CLIF_CRC_TX_CONFIG_W                                                                                0x12
#define CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_VALUE_POS                                                       (16UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_VALUE_MASK                                                      (0xFFFF0000UL)  /**< 16-Arbitrary preset value for the Tx-Encoder CRC calculation. */
#define CLIF_CRC_TX_CONFIG_RESERVED_POS                                                                  (7UL)
#define CLIF_CRC_TX_CONFIG_RESERVED_MASK                                                                 (0x0000FF80UL)  /**< 7-Reserved */
#define CLIF_CRC_TX_CONFIG_TX_CRC_BYTE2_ENABLE_POS                                                       (6UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_BYTE2_ENABLE_MASK                                                      (0x00000040UL)  /**< 6-If set. the CRC is calculated from the 2nd byte onwards (intended for HID). Note that this option is used in the Tx-Encoder.           */
#define CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_POS                                                         (3UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_PRESET_SEL_MASK                                                        (0x00000038UL)  /**< 3-Preset value of the CRC register for the Tx-Encoder. For a CRC calculation using 5bits. only the LSByte is used. 000b* 0000h. reset value 001b  6363h 010b A671h 011b  FFFFh 100b 0012h 101b E012h 110b RFU 111b Use arbitrary preset value TX_CRC_PRESET_VALUE*/
#define CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_POS                                                               (2UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_TYPE_MASK                                                              (0x00000004UL)  /**< 2-Controls the type of CRC calulation for the Tx-Encoder 0* 16bit CRC calculation. reset value 1 5bit CRC calculation */
#define CLIF_CRC_TX_CONFIG_TX_CRC_INV_POS                                                                (1UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_INV_MASK                                                               (0x00000002UL)  /**< 1-Controls the sending of an inverted CRC value by the Tx-Encoder 0* Not inverted CRC checksum. reset value 1 Inverted CRC checksum */
#define CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_POS                                                             (0UL)
#define CLIF_CRC_TX_CONFIG_TX_CRC_ENABLE_MASK                                                            (0x00000001UL)  /**< 0-If set to one. the Tx-Encoder will compute and transmit a CRC.*/
#define CLIF_CRC_TX_CONFIG__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_undershoot_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_UNDERSHOOT_CONFIG                                                                         0x13
#define CLIF_TX_UNDERSHOOT_CONFIG_R                                                                         0x13
#define CLIF_TX_UNDERSHOOT_CONFIG_W                                                                         0x13
#define CLIF_TX_UNDERSHOOT_CONFIG_RESERVED_POS                                                           (0UL)
#define CLIF_TX_UNDERSHOOT_CONFIG_RESERVED_MASK                                                          (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_TX_UNDERSHOOT_CONFIG__RESET_VALUE                                                           (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_tx_overshoot_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_OVERSHOOT_CONFIG                                                                          0x14
#define CLIF_TX_OVERSHOOT_CONFIG_R                                                                          0x14
#define CLIF_TX_OVERSHOOT_CONFIG_W                                                                          0x14
#define CLIF_TX_OVERSHOOT_CONFIG_RESERVED_POS                                                            (0UL)
#define CLIF_TX_OVERSHOOT_CONFIG_RESERVED_MASK                                                           (0xFFFFFFFFUL)  /**< 0-Reserved */
#define CLIF_TX_OVERSHOOT_CONFIG__RESET_VALUE                                                            (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ss_tx_cfg
* <b>Reset value:</b> 0x00000280
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX_CFG                                                                                    0x15
#define CLIF_SS_TX_CFG_R                                                                                    0x15
#define CLIF_SS_TX_CFG_W                                                                                    0x15
#define CLIF_SS_TX_CFG_RESERVED_POS                                                                      (14UL)
#define CLIF_SS_TX_CFG_RESERVED_MASK                                                                     (0xFFFFC000UL)  /**< 14-Reserved*/
#define CLIF_SS_TX_CFG_TX2_USE_TX1_CONF_POS                                                              (13UL)
#define CLIF_SS_TX_CFG_TX2_USE_TX1_CONF_MASK                                                             (0x00002000UL)  /**< 13-When 1, the tx1 configuration is used also for tx2: all CLIF_SS_TX2_* registers are discarded and configurations from corresponding CLIF_SS_TX1 register is used.*/
#define CLIF_SS_TX_CFG_RESERVED1_POS                                                                     (6UL)
#define CLIF_SS_TX_CFG_RESERVED1_MASK                                                                    (0x00001FC0UL)  /**< 6-Reserved*/
#define CLIF_SS_TX_CFG_TX2_CLK_MODE_DEFAULT_POS                                                          (3UL)
#define CLIF_SS_TX_CFG_TX2_CLK_MODE_DEFAULT_MASK                                                         (0x00000038UL)  /**< 3-TX2 clk mode without field (RM and CM)*/
#define CLIF_SS_TX_CFG_TX1_CLK_MODE_DEFAULT_POS                                                          (0UL)
#define CLIF_SS_TX_CFG_TX1_CLK_MODE_DEFAULT_MASK                                                         (0x00000007UL)  /**< 0-TX1 clk mode without field (RM and CM)*/
#define CLIF_SS_TX_CFG__RESET_VALUE                                                                      (0x00000280UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ss_tx1_rmcfg
* <b>Reset value:</b> 0x000000FF
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_RMCFG                                                                                 0x16
#define CLIF_SS_TX1_RMCFG_R                                                                                 0x16
#define CLIF_SS_TX1_RMCFG_W                                                                                 0x16
#define CLIF_SS_TX1_RMCFG_RESERVED_POS                                                                   (25UL)
#define CLIF_SS_TX1_RMCFG_RESERVED_MASK                                                                  (0xFE000000UL)  /**< 25-Reserved*/
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_TRANS_RM_POS                                                      (22UL)
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_TRANS_RM_MASK                                                     (0x01C00000UL)  /**< 22-TX1 clock mode in RM during transition*/
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_MOD_RM_POS                                                        (19UL)
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_MOD_RM_MASK                                                       (0x00380000UL)  /**< 19-TX1 clock mode of modulated wave in RM*/
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_CW_RM_POS                                                         (16UL)
#define CLIF_SS_TX1_RMCFG_TX1_CLK_MODE_CW_RM_MASK                                                        (0x00070000UL)  /**< 16-TX1 clock mode of unmodulated wave in RM*/
#define CLIF_SS_TX1_RMCFG_TX1_AMP_MOD_RM_POS                                                             (8UL)
#define CLIF_SS_TX1_RMCFG_TX1_AMP_MOD_RM_MASK                                                            (0x0000FF00UL)  /**< 8-TX1 amplitude of modulated wave in RM ( 0x00 = 0%modulaton, 0xFF: 100% modulation)*/
#define CLIF_SS_TX1_RMCFG_TX1_AMP_CW_RM_POS                                                              (0UL)
#define CLIF_SS_TX1_RMCFG_TX1_AMP_CW_RM_MASK                                                             (0x000000FFUL)  /**< 0-TX1 amplitude of unmodulated wave in RM ( 0x00 =0% signal, 0xFF: 100% signal)*/
#define CLIF_SS_TX1_RMCFG__RESET_VALUE                                                                   (0x0x000000FFUL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_rmcfg
* <b>Reset value:</b> 0x000000FF
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_RMCFG                                                                                 0x17
#define CLIF_SS_TX2_RMCFG_R                                                                                 0x17
#define CLIF_SS_TX2_RMCFG_W                                                                                 0x17
#define CLIF_SS_TX2_RMCFG_RESERVED_POS                                                                   (25UL)
#define CLIF_SS_TX2_RMCFG_RESERVED_MASK                                                                  (0xFE000000UL)  /**< 25-Reserved*/
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_TRANS_RM_POS                                                      (22UL)
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_TRANS_RM_MASK                                                     (0x01C00000UL)  /**< 22-TX2 clock mode in RM during transition*/
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_MOD_RM_POS                                                        (19UL)
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_MOD_RM_MASK                                                       (0x00380000UL)  /**< 19-TX2 clock mode of modulated wave in RM*/
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_CW_RM_POS                                                         (16UL)
#define CLIF_SS_TX2_RMCFG_TX2_CLK_MODE_CW_RM_MASK                                                        (0x00070000UL)  /**< 16-TX2 clock mode of unmodulated wave in RM*/
#define CLIF_SS_TX2_RMCFG_TX2_AMP_MOD_RM_POS                                                             (8UL)
#define CLIF_SS_TX2_RMCFG_TX2_AMP_MOD_RM_MASK                                                            (0x0000FF00UL)  /**< 8-TX2 amplitude of modulated wave in RM ( 0x00 = 0%modulaton, 0xFF: 100% modulation)*/
#define CLIF_SS_TX2_RMCFG_TX2_AMP_CW_RM_POS                                                              (0UL)
#define CLIF_SS_TX2_RMCFG_TX2_AMP_CW_RM_MASK                                                             (0x000000FFUL)  /**< 0-TX2 amplitude of unmodulated wave in RM ( 0x00 =0% signal, 0xFF: 100% signal)*/
#define CLIF_SS_TX2_RMCFG__RESET_VALUE                                                                   (0x000000FFUL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx_scale_cfg
* <b>Reset value:</b> 0x0000FFFF
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX_SCALE_CFG                                                                              0x18
#define CLIF_SS_TX_SCALE_CFG_R                                                                              0x18
#define CLIF_SS_TX_SCALE_CFG_W                                                                              0x18
#define CLIF_SS_TX_SCALE_CFG_TX2_SS_SCALE_UPD_TIME_POS                                                   (24UL)
#define CLIF_SS_TX_SCALE_CFG_TX2_SS_SCALE_UPD_TIME_MASK                                                  (0xFF000000UL)  /**< 24-time between scaling factor inc/decrement to reach TX2_SS_TARGET_SCALE in 8/13.56MHz multiples (0: immediate update with target value)*/
#define CLIF_SS_TX_SCALE_CFG_TX1_SS_SCALE_UPD_TIME_POS                                                   (16UL)
#define CLIF_SS_TX_SCALE_CFG_TX1_SS_SCALE_UPD_TIME_MASK                                                  (0x00FF0000UL)  /**< 16-time between scaling factor inc/decrement to reach TX1_SS_TARGET_SCALE in 8/13.56MHz multiples (0: immediate update with target value)*/
#define CLIF_SS_TX_SCALE_CFG_TX2_SS_TARGET_SCALE_POS                                                     (8UL)
#define CLIF_SS_TX_SCALE_CFG_TX2_SS_TARGET_SCALE_MASK                                                    (0x0000FF00UL)  /**< 8-TX2 scaling factor*/
#define CLIF_SS_TX_SCALE_CFG_TX1_SS_TARGET_SCALE_POS                                                     (0UL)
#define CLIF_SS_TX_SCALE_CFG_TX1_SS_TARGET_SCALE_MASK                                                    (0x000000FFUL)  /**< 0-TX1 scaling factor*/
#define CLIF_SS_TX_SCALE_CFG__RESET_VALUE																 (0x0000FFFFUL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx_trans_cfg
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX_TRANS_CFG                                                                              0x19
#define CLIF_SS_TX_TRANS_CFG_R                                                                              0x19
#define CLIF_SS_TX_TRANS_CFG_W                                                                              0x19
#define CLIF_SS_TX_TRANS_CFG_RESERVED_POS                                                                (12UL)
#define CLIF_SS_TX_TRANS_CFG_RESERVED_MASK                                                               (0xFFFFF000UL)  /**< 12-Reserved*/
#define CLIF_SS_TX_TRANS_CFG_TX2_SS_TRANS_RATE_POS                                                       (11UL)
#define CLIF_SS_TX_TRANS_CFG_TX2_SS_TRANS_RATE_MASK                                                      (0x00000800UL)  /**< 11-TX2 shaping edge rate: 0: 1/fc, 1: 2/fc. 1/fc should be selected for CM.*/
#define CLIF_SS_TX_TRANS_CFG_TX1_SS_TRANS_RATE_POS                                                       (10UL)
#define CLIF_SS_TX_TRANS_CFG_TX1_SS_TRANS_RATE_MASK                                                      (0x00000400UL)  /**< 10-TX2 shaping edge rate: 0: 1/fc, 1: 2/fc. 1/fc should be selected for CM*/
#define CLIF_SS_TX_TRANS_CFG_TX2_SS_TRANS_LENGTH_POS                                                     (5UL)
#define CLIF_SS_TX_TRANS_CFG_TX2_SS_TRANS_LENGTH_MASK                                                    (0x000003E0UL)  /**< 5-TX2 shaping edge length: from 0 (disable) to 16. for CM, only 0 or 4 values are valid*/
#define CLIF_SS_TX_TRANS_CFG_TX1_SS_TRANS_LENGTH_POS                                                     (0UL)
#define CLIF_SS_TX_TRANS_CFG_TX1_SS_TRANS_LENGTH_MASK                                                    (0x0000001FUL)  /**< 0-TX1 shaping edge length: from 0 (disable) to 16. for CM, only 0 or 4 values are valid*/
#define CLIF_SS_TX_TRANS_CFG__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_anactrl_tx1_gsn
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANACTRL_TX1_GSN                                                                              0x1A
#define CLIF_ANACTRL_TX1_GSN_R                                                                              0x1A
#define CLIF_ANACTRL_TX1_GSN_W                                                                              0x1A
#define CLIF_ANACTRL_TX1_GSN_RESERVED_POS                                                                (25UL)
#define CLIF_ANACTRL_TX1_GSN_RESERVED_MASK                                                               (0xFE000000UL)  /**< 25-Reserved */
#define CLIF_ANACTRL_TX1_GSN_GSN_DEFAULT_TX1_POS                                                         (20UL)
#define CLIF_ANACTRL_TX1_GSN_GSN_DEFAULT_TX1_MASK                                                        (0x01F00000UL)  /**< 20-low side transistor default conductance for tx1*/
#define CLIF_ANACTRL_TX1_GSN_GSN_MOD_CM_TX1_POS                                                          (15UL)
#define CLIF_ANACTRL_TX1_GSN_GSN_MOD_CM_TX1_MASK                                                         (0x000F8000UL)  /**< 15-low side transistor conductance in card mode, mod, for tx1*/
#define CLIF_ANACTRL_TX1_GSN_GSN_CW_CM_TX1_POS                                                           (10UL)
#define CLIF_ANACTRL_TX1_GSN_GSN_CW_CM_TX1_MASK                                                          (0x00007C00UL)  /**< 10-low side transistor conductance in card mode, cw, for tx1*/
#define CLIF_ANACTRL_TX1_GSN_GSN_MOD_RM_TX1_POS                                                          (5UL)
#define CLIF_ANACTRL_TX1_GSN_GSN_MOD_RM_TX1_MASK                                                         (0x000003E0UL)  /**< 5-low side transistor conductance in reader mode, mod, for tx1*/
#define CLIF_ANACTRL_TX1_GSN_GSN_CW_RM_TX1_POS                                                           (0UL)
#define CLIF_ANACTRL_TX1_GSN_GSN_CW_RM_TX1_MASK                                                          (0x0000001FUL)  /**< 0-low side transistor conductance in reader mode, cw, for tx1*/
#define CLIF_ANACTRL_TX1_GSN__RESET_VALUE																 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_anactrl_tx2_gsn
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANACTRL_TX2_GSN                                                                              0x1B
#define CLIF_ANACTRL_TX2_GSN_R                                                                              0x1B
#define CLIF_ANACTRL_TX2_GSN_W                                                                              0x1B
#define CLIF_ANACTRL_TX2_GSN_RESERVED_POS                                                                (25UL)
#define CLIF_ANACTRL_TX2_GSN_RESERVED_MASK                                                               (0xFE000000UL)  /**< 25-Reserved */
#define CLIF_ANACTRL_TX2_GSN_GSN_DEFAULT_TX2_POS                                                         (20UL)
#define CLIF_ANACTRL_TX2_GSN_GSN_DEFAULT_TX2_MASK                                                        (0x01F00000UL)  /**< 20-low side transistor default conductance for tx2*/
#define CLIF_ANACTRL_TX2_GSN_GSN_MOD_CM_TX2_POS                                                          (15UL)
#define CLIF_ANACTRL_TX2_GSN_GSN_MOD_CM_TX2_MASK                                                         (0x000F8000UL)  /**< 15-low side transistor conductance in card mode, mod, for tx2*/
#define CLIF_ANACTRL_TX2_GSN_GSN_CW_CM_TX2_POS                                                           (10UL)
#define CLIF_ANACTRL_TX2_GSN_GSN_CW_CM_TX2_MASK                                                          (0x00007C00UL)  /**< 10-low side transistor conductance in card mode, cw, for tx2*/
#define CLIF_ANACTRL_TX2_GSN_GSN_MOD_RM_TX2_POS                                                          (5UL)
#define CLIF_ANACTRL_TX2_GSN_GSN_MOD_RM_TX2_MASK                                                         (0x000003E0UL)  /**< 5-low side transistor conductance in reader mode, mod, for tx2*/
#define CLIF_ANACTRL_TX2_GSN_GSN_CW_RM_TX2_POS                                                           (0UL)
#define CLIF_ANACTRL_TX2_GSN_GSN_CW_RM_TX2_MASK                                                          (0x0000001FUL)  /**< 0-low side transistor conductance in reader mode, cw, for tx2*/
#define CLIF_ANACTRL_TX2_GSN__RESET_VALUE																 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_anactrl_tx_gsp
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANACTRL_TX_GSP                                                                               0x1C
#define CLIF_ANACTRL_TX_GSP_R                                                                               0x1C
#define CLIF_ANACTRL_TX_GSP_W                                                                               0x1C
#define CLIF_ANACTRL_TX_GSP_RESERVED_POS                                                                 (30UL)
#define CLIF_ANACTRL_TX_GSP_RESERVED_MASK                                                                (0xC0000000UL)  /**< 30-Reserved */
#define CLIF_ANACTRL_TX_GSP_GSP_DEFAULT_TX2_POS                                                          (25UL)
#define CLIF_ANACTRL_TX_GSP_GSP_DEFAULT_TX2_MASK                                                         (0x3E000000UL)  /**< 25-high side transistor default conductance for tx2*/
#define CLIF_ANACTRL_TX_GSP_GSP_DEFAULT_TX1_POS                                                          (20UL)
#define CLIF_ANACTRL_TX_GSP_GSP_DEFAULT_TX1_MASK                                                         (0x01F00000UL)  /**< 20-high side transistor default conductance for tx1*/
#define CLIF_ANACTRL_TX_GSP_GSP_CM_TX2_POS                                                               (15UL)
#define CLIF_ANACTRL_TX_GSP_GSP_CM_TX2_MASK                                                              (0x000F8000UL)  /**< 15-high side transistor conductance in card mode for tx2*/
#define CLIF_ANACTRL_TX_GSP_GSP_CM_TX1_POS                                                               (10UL)
#define CLIF_ANACTRL_TX_GSP_GSP_CM_TX1_MASK                                                              (0x00007C00UL)  /**< 10-high side transistor conductance in card mode for tx1*/
#define CLIF_ANACTRL_TX_GSP_GSP_RM_TX2_POS                                                               (5UL)
#define CLIF_ANACTRL_TX_GSP_GSP_RM_TX2_MASK                                                              (0x000003E0UL)  /**< 5-high side transistor conductance in reader mode for tx2*/
#define CLIF_ANACTRL_TX_GSP_GSP_RM_TX1_POS                                                               (0UL)
#define CLIF_ANACTRL_TX_GSP_GSP_RM_TX1_MASK                                                              (0x0000001FUL)  /**< 0-high side transistor conductance in reader mode for tx1*/
#define CLIF_ANACTRL_TX_GSP__RESET_VALUE																 (0x00000000UL)  /**< value after reset*/  
/**
* @}
*/

/**
* @name clif_sigpro_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CONFIG                                                                                0x1D
#define CLIF_SIGPRO_CONFIG_R                                                                                0x1D
#define CLIF_SIGPRO_CONFIG_W                                                                                0x1D
#define CLIF_SIGPRO_CONFIG_RESERVED_POS                                                                  (0UL)
#define CLIF_SIGPRO_CONFIG_RESERVED_MASK                                                                 (0xFFFFFFFFUL)  /**< 0-RFU*/
#define CLIF_SIGPRO_CONFIG__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_rm_wait
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_RM_WAIT                                                                               0x1E
#define CLIF_SIGPRO_RM_WAIT_R                                                                               0x1E
#define CLIF_SIGPRO_RM_WAIT_W                                                                               0x1E
#define CLIF_SIGPRO_RM_WAIT_RM_NOISE_COLL_TH_POS                                                         (25UL)
#define CLIF_SIGPRO_RM_WAIT_RM_NOISE_COLL_TH_MASK                                                        (0xFE000000UL)  /**< 25-Noise threshold used to declare collision.*/
#define CLIF_SIGPRO_RM_WAIT_RM_MF_SC_TH_POS                                                              (20UL)
#define CLIF_SIGPRO_RM_WAIT_RM_MF_SC_TH_MASK                                                             (0x01F00000UL)  /**< 20-Threshold to compare MF output inorder to detect sub-carriers in A106*/
#define CLIF_SIGPRO_RM_WAIT_RM_SC_CNT_RECEIVE_TH_POS                                                     (16UL)
#define CLIF_SIGPRO_RM_WAIT_RM_SC_CNT_RECEIVE_TH_MASK                                                    (0x000F0000UL)  /**< 16-Number of sub-carriers to be received before transitioning to RECEIVE state in Type A106.*/
#define CLIF_SIGPRO_RM_WAIT_RM_BBA_DECR_WAIT_POS                                                         (8UL)
#define CLIF_SIGPRO_RM_WAIT_RM_BBA_DECR_WAIT_MASK                                                        (0x0000FF00UL)  /**< 8-Number of (13.56MHz/2) cycles to supperss A106 re-sync mechanism after reduction in BBA gain*/
#define CLIF_SIGPRO_RM_WAIT_RM_HF_ATT_UPDATE_WAIT_POS                                                    (0UL)
#define CLIF_SIGPRO_RM_WAIT_RM_HF_ATT_UPDATE_WAIT_MASK                                                   (0x000000FFUL)  /**< 0-Number of (13.56MHz/2) cycles to supperss A106 SoF detection after change in HF-attenuator*/
#define CLIF_SIGPRO_RM_WAIT__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_rm_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_RM_CONFIG                                                                             0x1F
#define CLIF_SIGPRO_RM_CONFIG_R                                                                             0x1F
#define CLIF_SIGPRO_RM_CONFIG_W                                                                             0x1F
#define CLIF_SIGPRO_RM_CONFIG_RESERVED_POS                                                               (0UL)
#define CLIF_SIGPRO_RM_CONFIG_RESERVED_MASK                                                              (0xFFFFFFFFUL)  /**< 0-RFU*/
#define CLIF_SIGPRO_RM_CONFIG__RESET_VALUE                                                               (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_rm_pattern
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_RM_PATTERN                                                                            0x20
#define CLIF_SIGPRO_RM_PATTERN_R                                                                            0x20
#define CLIF_SIGPRO_RM_PATTERN_W                                                                            0x20
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_POS                                                       (16UL)
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_MASK                                                      (0xFFFF0000UL)  /**< 16-Sync pattern for Felica. LSB transmitted last*/
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_EXT4_POS                                                  (15UL)
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_EXT4_MASK                                                 (0x00008000UL)  /**< 15-extend Felica sync pattern with 16 leading 0s*/
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_EXT2_POS                                                  (14UL)
#define CLIF_SIGPRO_RM_PATTERN_RM_SYNC_PATTERN_EXT2_MASK                                                 (0x00004000UL)  /**< 14-extend Felica sync pattern with 8 leading 0s*/
#define CLIF_SIGPRO_RM_PATTERN_RM_RECEIVE_TILL_END_POS                                                   (13UL)
#define CLIF_SIGPRO_RM_PATTERN_RM_RECEIVE_TILL_END_MASK                                                  (0x00002000UL)  /**< 13-do not stop the reception before RxDecoder sends a stop command*/
#define CLIF_SIGPRO_RM_PATTERN_RESERVED_POS                                                              (12UL)
#define CLIF_SIGPRO_RM_PATTERN_RESERVED_MASK                                                             (0x00001000UL)  /**< 12-Reserved*/
#define CLIF_SIGPRO_RM_PATTERN_RM_SOF_PATTERN_POS                                                        (0UL)
#define CLIF_SIGPRO_RM_PATTERN_RM_SOF_PATTERN_MASK                                                       (0x00000FFFUL)  /**< 0-SOF pattern for Type B. LSB transmitted last or Start Byte pattern for NFC passive.*/
#define CLIF_SIGPRO_RM_PATTERN__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_rm_enables
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_RM_ENABLES                                                                            0x21
#define CLIF_SIGPRO_RM_ENABLES_R                                                                            0x21
#define CLIF_SIGPRO_RM_ENABLES_W                                                                            0x21
#define CLIF_SIGPRO_RM_ENABLES_RESERVED_POS                                                              (2UL)
#define CLIF_SIGPRO_RM_ENABLES_RESERVED_MASK                                                             (0xFFFFFFFCUL)  /**< 2-Reserved*/
#define CLIF_SIGPRO_RM_ENABLES_RM_RESYNC_RESET_ENABLE_POS                                                (1UL)
#define CLIF_SIGPRO_RM_ENABLES_RM_RESYNC_RESET_ENABLE_MASK                                               (0x00000002UL)  /**< 1-Enables receiver reset due to re-sync*/
#define CLIF_SIGPRO_RM_ENABLES_RESERVED1_POS                                                             (0UL)
#define CLIF_SIGPRO_RM_ENABLES_RESERVED1_MASK                                                            (0x00000001UL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_RM_ENABLES__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_rm_tech
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_RM_TECH                                                                               0x22
#define CLIF_SIGPRO_RM_TECH_R                                                                               0x22
#define CLIF_SIGPRO_RM_TECH_W                                                                               0x22
#define CLIF_SIGPRO_RM_TECH_RESERVED_POS                                                                 (17UL)
#define CLIF_SIGPRO_RM_TECH_RESERVED_MASK                                                                (0xFFFE0000UL)  /**< 17-Reserved*/
#define CLIF_SIGPRO_RM_TECH_RM_MF_GAIN_POS                                                               (15UL)
#define CLIF_SIGPRO_RM_TECH_RM_MF_GAIN_MASK                                                              (0x00018000UL)  /**< 15-Defines the gain of the Matched-Filters*/
#define CLIF_SIGPRO_RM_TECH_RESERVED1_POS                                                                (0UL)
#define CLIF_SIGPRO_RM_TECH__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_noise_config1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_NOISE_CONFIG1                                                                         0x23
#define CLIF_SIGPRO_NOISE_CONFIG1_R                                                                         0x23
#define CLIF_SIGPRO_NOISE_CONFIG1_W                                                                         0x23
#define CLIF_SIGPRO_NOISE_CONFIG1_RESERVED_POS                                                           (0UL)
#define CLIF_SIGPRO_NOISE_CONFIG1_RESERVED_MASK                                                          (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_NOISE_CONFIG1__RESET_VALUE                                                           (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_noise_config2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_NOISE_CONFIG2                                                                         0x24
#define CLIF_SIGPRO_NOISE_CONFIG2_R                                                                         0x24
#define CLIF_SIGPRO_NOISE_CONFIG2_W                                                                         0x24
#define CLIF_SIGPRO_NOISE_CONFIG2_RESERVED_POS                                                           (0UL)
#define CLIF_SIGPRO_NOISE_CONFIG2_RESERVED_MASK                                                          (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_NOISE_CONFIG2__RESET_VALUE                                                           (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_rx_protocol_config
* <b>Reset value:</b> 0x00005004
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_PROTOCOL_CONFIG                                                                           0x25
#define CLIF_RX_PROTOCOL_CONFIG_R                                                                           0x25
#define CLIF_RX_PROTOCOL_CONFIG_W                                                                           0x25
#define CLIF_RX_PROTOCOL_CONFIG_RESERVED_POS                                                             (6UL)
#define CLIF_RX_PROTOCOL_CONFIG_RESERVED_MASK                                                            (0xFFFFFFC0UL)  /**< 6-Reserved*/
#define CLIF_RX_PROTOCOL_CONFIG_RX_BIT_ALIGN_POS                                                         (3UL)
#define CLIF_RX_PROTOCOL_CONFIG_RX_BIT_ALIGN_MASK                                                        (0x00000038UL)  /**< 3-Defines the position of the 1st received data bit in the formed data byte.000b - 0 position...111b - 7th position*/
#define CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_TYPE_POS                                                       (2UL)
#define CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_TYPE_MASK                                                      (0x00000004UL)  /**< 2-0 - data + parity bits contain even number of 1. 1 - data + parity bits contain odd number of 1. Valid if cfg_rx_parity_enable_i ==1.*/
#define CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_ENABLE_POS                                                     (1UL)
#define CLIF_RX_PROTOCOL_CONFIG_RX_PARITY_ENABLE_MASK                                                    (0x00000002UL)  /**< 1-If set to 1, the bit following last data bit in the frame character is considered as parity bit.*/
#define CLIF_RX_PROTOCOL_CONFIG_RESERVED1_POS                                                            (0UL)
#define CLIF_RX_PROTOCOL_CONFIG_RESERVED1_MASK                                                           (0x00000001UL)  /**< 0-Reserved.*/
#define CLIF_RX_PROTOCOL_CONFIG__RESET_VALUE                                                             (0x00005004UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_rx_frame_length
* <b>Reset value:</b> 0x7FFF0003
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_FRAME_LENGTH                                                                              0x26
#define CLIF_RX_FRAME_LENGTH_R                                                                              0x26
#define CLIF_RX_FRAME_LENGTH_W                                                                              0x26
#define CLIF_RX_FRAME_LENGTH_RESERVED_POS                                                                (31UL)
#define CLIF_RX_FRAME_LENGTH_RESERVED_MASK                                                               (0x80000000UL)  /**< 31-Reserved*/
#define CLIF_RX_FRAME_LENGTH_RX_FRAME_MAXLEN_POS                                                         (16UL)
#define CLIF_RX_FRAME_LENGTH_RX_FRAME_MAXLEN_MASK                                                        (0x7FFF0000UL)  /**< 16-Maximal number of received [DATA + CRC] bits in theframe. The violation of the maximum length limit can be also configured as an Error/EMD condition. If the max length violation is configured as error - the frame reception is stopped in case of maximum length limit exceeding. Otherwise the reception is continued.0x0000 - 1 bit...0x7FFF - 32K bits*/
#define CLIF_RX_FRAME_LENGTH_RESERVED1_POS                                                                (15UL)
#define CLIF_RX_FRAME_LENGTH_RESERVED1_MASK                                                               (0x00008000UL)  /**< 15-Reserved*/
#define CLIF_RX_FRAME_LENGTH_RX_FRAME_MINLEN_POS                                                         (0UL)
#define CLIF_RX_FRAME_LENGTH_RX_FRAME_MINLEN_MASK                                                        (0x00007FFFUL)  /**< 0-Minimal number of received [DATA + CRC] bits in the frame. The violation of the minimum length limit can be also configured as an Error/EMD condition.The parameter also defines the number of received[DATA + CRC] bits before which any of the EOF pattern or INVPAR stop condition events are ignored.0x0000 - 1 bit...0x7FFF - 32K bits*/
#define CLIF_RX_FRAME_LENGTH__RESET_VALUE                                                                (0x7FFF0003UL)


/**
* @name clif_rx_error_config
* <b>Reset value:</b> 0x00003178
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_ERROR_CONFIG                                                                              0x27
#define CLIF_RX_ERROR_CONFIG_R                                                                              0x27
#define CLIF_RX_ERROR_CONFIG_W                                                                              0x27
#define CLIF_RX_ERROR_CONFIG_RESERVED_POS                                                                (0UL)
#define CLIF_RX_ERROR_CONFIG_RESERVED_MASK                                                               (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_RX_ERROR_CONFIG__RESET_VALUE                                                                (0x00003178UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_rxctrl_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_RXCTRL_STATUS                                                                                0x28
#define CLIF_RXCTRL_STATUS_R                                                                                0x28
#define CLIF_RXCTRL_STATUS_RXCTRL_RESERVED_POS                                                           (9UL)
#define CLIF_RXCTRL_STATUS_RXCTRL_RESERVED_MASK                                                          (0xFFFFFE00UL)  /**< 9-Reserved*/
#define CLIF_RXCTRL_STATUS_RXCTRL_HF_ATT_VAL_POS                                                         (3UL)
#define CLIF_RXCTRL_STATUS_RXCTRL_HF_ATT_VAL_MASK                                                        (0x000001F8UL)  /**< 3-HF attenuator value*/
#define CLIF_RXCTRL_STATUS_RXCTRL_RESERVED1_POS                                                          (0UL)
#define CLIF_RXCTRL_STATUS_RXCTRL_RESERVED1_MASK                                                         (0x00000007UL)  /**< 0-Reserved*/
#define CLIF_RXCTRL_STATUS__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_iir_config1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_IIR_CONFIG1                                                                           0x29
#define CLIF_SIGPRO_IIR_CONFIG1_R                                                                           0x29
#define CLIF_SIGPRO_IIR_CONFIG1_W                                                                           0x29
#define CLIF_SIGPRO_IIR_CONFIG1_RESERVED_POS                                                             (0UL)
#define CLIF_SIGPRO_IIR_CONFIG1_RESERVED_MASK                                                            (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_IIR_CONFIG1__RESET_VALUE                                                             (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_iir_config0
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_IIR_CONFIG0                                                                           0x2A
#define CLIF_SIGPRO_IIR_CONFIG0_R                                                                           0x2A
#define CLIF_SIGPRO_IIR_CONFIG0_W                                                                           0x2A
#define CLIF_SIGPRO_IIR_CONFIG0_RESERVED_POS                                                             (0UL)
#define CLIF_SIGPRO_IIR_CONFIG0_RESERVED_MASK                                                            (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_IIR_CONFIG0__RESET_VALUE                                                             (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_dac_filter
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_DGRM_DAC_FILTER                                                                              0x2B
#define CLIF_DGRM_DAC_FILTER_R                                                                              0x2B
#define CLIF_DGRM_DAC_FILTER_W                                                                              0x2B
#define CLIF_DGRM_DAC_FILTER_RESERVED_POS                                                                (0UL)
#define CLIF_DGRM_DAC_FILTER_RESERVED_MASK                                                               (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_DGRM_DAC_FILTER__RESET_VALUE                                                                (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_DGRM_CONFIG                                                                                  0x2C
#define CLIF_DGRM_CONFIG_R                                                                                  0x2C
#define CLIF_DGRM_CONFIG_W                                                                                  0x2C
#define CLIF_DGRM_CONFIG_RESERVED_POS                                                                    (0UL)
#define CLIF_DGRM_CONFIG_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_DGRM_CONFIG__RESET_VALUE                                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_bba
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_DGRM_BBA                                                                                     0x2D
#define CLIF_DGRM_BBA_R                                                                                     0x2D
#define CLIF_DGRM_BBA_W                                                                                     0x2D
#define CLIF_DGRM_BBA_RESERVED_POS                                                                       (17UL)
#define CLIF_DGRM_BBA_RESERVED_MASK                                                                      (0xFFFE0000UL)  /**< 17-31 Reserved*/
#define CLIF_DGRM_BBA_DGRM_BBA_MIN_VAL_POS                                                               (14UL)
#define CLIF_DGRM_BBA_DGRM_BBA_MIN_VAL_MASK                                                              (0x0001C000UL)  /**< 14-Defines the minimum value of BBA gain. */
#define CLIF_DGRM_BBA_DGRM_BBA_MAX_VAL_POS                                                               (11UL)
#define CLIF_DGRM_BBA_DGRM_BBA_MAX_VAL_MASK                                                              (0x00003800UL)  /**< 11-Defines the maximum value of BBA gain.*/
#define CLIF_DGRM_BBA_DGRM_BBA_INIT_VAL_POS                                                              (8UL)
#define CLIF_DGRM_BBA_DGRM_BBA_INIT_VAL_MASK                                                             (0x00000700UL)  /**< 8-Defines initial value of BBA gain. If BBA fast and slow modes are disabled, this value defines the forced value.*/
#define CLIF_DGRM_BBA_RESERVED1_POS                                                                       (0UL)
#define CLIF_DGRM_BBA_RESERVED1_MASK                                                                     (0x000000FFUL)  /**< 0-7 Reserved */
#define CLIF_DGRM_BBA__RESET_VALUE                                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_dco
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_DGRM_DCO                                                                                     0x2E
#define CLIF_DGRM_DCO_R                                                                                     0x2E
#define CLIF_DGRM_DCO_W                                                                                     0x2E
#define CLIF_DGRM_DCO_RESERVED_POS                                                                       (0UL)
#define CLIF_DGRM_DCO_RESERVED_MASK                                                                      (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_DGRM_DCO__RESET_VALUE                                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_hf_att
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_DGRM_HF_ATT                                                                                  0x2F
#define CLIF_DGRM_HF_ATT_R                                                                                  0x2F
#define CLIF_DGRM_HF_ATT_W                                                                                  0x2F
#define CLIF_DGRM_HF_ATT_RESERVED_POS                                                                    (0UL)
#define CLIF_DGRM_HF_ATT_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_DGRM_HF_ATT__RESET_VALUE                                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dgrm_rssi
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_DGRM_RSSI                                                                                    0x30
#define CLIF_DGRM_RSSI_R                                                                                    0x30
#define CLIF_DGRM_RSSI_W                                                                                    0x30
#define CLIF_DGRM_RSSI_RESERVED_POS                                                                      (30UL)
#define CLIF_DGRM_RSSI_RESERVED_MASK                                                                     (0xC0000000UL)  /**< 30-Reserved*/
#define CLIF_DGRM_RSSI_DGRM_SIGNAL_DETECT_TH_OVR_POS                                                     (29UL)
#define CLIF_DGRM_RSSI_DGRM_SIGNAL_DETECT_TH_OVR_MASK                                                    (0x20000000UL)  /**< 29-Enables the override of signal detect threshold. Override value is set based on DGRM_SIGNAL_DETECT_TH_OVR_VAL.*/
#define CLIF_DGRM_RSSI_RESERVED1_POS                                                                     (23UL)
#define CLIF_DGRM_RSSI_RESERVED1_MASK                                                                    (0x1F800000UL)  /**< 23-28 Reserved*/
#define CLIF_DGRM_RSSI_DGRM_RSSI_HYST_POS                                                                (17UL)
#define CLIF_DGRM_RSSI_DGRM_RSSI_HYST_MASK                                                               (0x007E0000UL)  /**< 17-Hysteresis value for RSSI target*/
#define CLIF_DGRM_RSSI_DGRM_RSSI_TARGET_POS                                                              (7UL)
#define CLIF_DGRM_RSSI_DGRM_RSSI_TARGET_MASK                                                             (0x0001FF80UL)  /**< 7-RSSI target value*/
#define CLIF_DGRM_RSSI_DGRM_SIGNAL_DETECT_TH_OVR_VAL_POS                                                 (0UL)
#define CLIF_DGRM_RSSI_DGRM_SIGNAL_DETECT_TH_OVR_VAL_MASK                                                (0x0000007FUL)  /**< 0-Defines the override value for signal detect threshold when DGRM_SIGNAL_DETECT_TH_OVR is set.*/
#define CLIF_DGRM_RSSI__RESET_VALUE                                                                      (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_crc_rx_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_CRC_RX_CONFIG                                                                                0x31
#define CLIF_CRC_RX_CONFIG_R                                                                                0x31
#define CLIF_CRC_RX_CONFIG_W                                                                                0x31
#define CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_VALUE_POS                                                       (16UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_VALUE_MASK                                                      (0xFFFF0000UL)  /**< 16-Arbitrary preset value for the Rx-Decoder CRC calculation. */
#define CLIF_CRC_RX_CONFIG_RESERVED_POS                                                                  (8UL)
#define CLIF_CRC_RX_CONFIG_RESERVED_MASK                                                                 (0x0000FF00UL)  /**< 8-Reserved */
#define CLIF_CRC_RX_CONFIG_RX_FORCE_CRC_WRITE_POS                                                        (7UL)
#define CLIF_CRC_RX_CONFIG_RX_FORCE_CRC_WRITE_MASK                                                       (0x00000080UL)  /**< 7-If set. the Rx-Decoder will send to the RAM the CRC bits as well.*/
#define CLIF_CRC_RX_CONFIG_RX_CRC_ALLOW_BITS_POS                                                         (6UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_ALLOW_BITS_MASK                                                        (0x00000040UL)  /**< 6-If activated the frame with length =< CRC_length will be always sent to the System RAM as is, without CRC bits removal.*/
#define CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_POS                                                         (3UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_PRESET_SEL_MASK                                                        (0x00000038UL)  /**< 3-Preset value of the CRC register for the Rx-Decoder. For a CRC calculation using 5bits only the LSByte is used. 000b* 0000h reset value Note that this configuration is set by the Mode detector for FeliCa. 001b  6363h Note that this configuration is set by the Mode detector for ISO14443 type A. 010b  A671h 011b FFFFh Note that this configuration is set by the Mode detector for ISO14443 type B. 100b 0012h 101b E012h 110b RFU 111b Use arbitrary preset value RX_CRC_PRESET_VALUE*/
#define CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_POS                                                               (2UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_TYPE_MASK                                                              (0x00000004UL)  /**< 2-Controls the type of CRC calulation for the Rx-Decoder 0* 16bit CRC calculation. reset value 1 5bit CRC calculation */
#define CLIF_CRC_RX_CONFIG_RX_CRC_INV_POS                                                                (1UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_INV_MASK                                                               (0x00000002UL)  /**< 1-Controls the comparison of the CRC checksum for the Rx-Decoder 0* Not inverted CRC value: 0000h reset value Note that this nit is cleared by the Mode detector for ISO14443 type A and FeliCa. 1 Inverted CRC value: F0B8h Note that this bit is set by the Mode detector for ISO14443 type B.*/
#define CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_POS                                                             (0UL)
#define CLIF_CRC_RX_CONFIG_RX_CRC_ENABLE_MASK                                                            (0x00000001UL)  /**< 0-If set. the Rx-Decoder will check the CRC for correctness. Note that this bit is set by the Mode Detector. when ISO14443 type B. or FeliCa (212 or 424kBd) is detected.*/
#define CLIF_CRC_RX_CONFIG__RESET_VALUE                                                                  (0x00000000UL) /**< value after reset */
/**
* @}
*/


/**
* @name clif_rx_wait
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_WAIT                                                                                      0x32
#define CLIF_RX_WAIT_R                                                                                      0x32
#define CLIF_RX_WAIT_W                                                                                      0x32
#define CLIF_RX_WAIT_RESERVED_POS                                                                        (28UL)
#define CLIF_RX_WAIT_RESERVED_MASK                                                                       (0xF0000000UL)  /**< 28-Reserved */
#define CLIF_RX_WAIT_RX_WAIT_VALUE_POS                                                                   (8UL)
#define CLIF_RX_WAIT_RX_WAIT_VALUE_MASK                                                                  (0x0FFFFF00UL)  /**< 8-Defines the rx_wait timer reload value. Note: If set to 00000h the rx_wait guard time is disabled */
#define CLIF_RX_WAIT_RX_WAIT_PRESCALER_POS                                                               (0UL)
#define CLIF_RX_WAIT_RX_WAIT_PRESCALER_MASK                                                              (0x000000FFUL)  /**< 0-Defines the prescaler reload value for the rx_wait timer.*/
#define CLIF_RX_WAIT__RESET_VALUE                                                                        (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_dcoc_config
* <b>Reset value:</b> 0x000000F4
* <b>Access:</b> rw
* @{
*/
#define CLIF_DCOC_CONFIG                                                                                  0x33
#define CLIF_DCOC_CONFIG_R                                                                                  0x33
#define CLIF_DCOC_CONFIG_W                                                                                  0x33
#define CLIF_DCOC_CONFIG_RESERVED_POS                                                                    (0UL)
#define CLIF_DCOC_CONFIG_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_DCOC_CONFIG__RESET_VALUE                                                                    (0x000000F4UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rxm_nfcld_lvl
* <b>Reset value:</b> 0x00330066
* <b>Access:</b> rw
* @{
*/
#define CLIF_RXM_NFCLD_LVL                                                                                0x34
#define CLIF_RXM_NFCLD_LVL_R                                                                                0x34
#define CLIF_RXM_NFCLD_LVL_W                                                                                0x34
#define CLIF_RXM_NFCLD_LVL_RESERVED_POS                                                                  (30UL)
#define CLIF_RXM_NFCLD_LVL_RESERVED_MASK                                                                 (0xC0000000UL)  /**< 30-reserved*/
#define CLIF_RXM_NFCLD_LVL_RXM_NFCLD_OFF_TH_POS                                                          (16UL)
#define CLIF_RXM_NFCLD_LVL_RXM_NFCLD_OFF_TH_MASK                                                         (0x3FFF0000UL)  /**< 16-RSSI OFF threshold*/
#define CLIF_RXM_NFCLD_LVL_RESERVED1_POS                                                                  (14UL)
#define CLIF_RXM_NFCLD_LVL_RESERVED1_MASK                                                                 (0x0000C000UL)  /**< 14-reserved*/
#define CLIF_RXM_NFCLD_LVL_RXM_NFCLD_ON_TH_POS                                                           (0UL)
#define CLIF_RXM_NFCLD_LVL_RXM_NFCLD_ON_TH_MASK                                                          (0x00003FFFUL)  /**< 0-RSSI ON threshold*/
#define CLIF_RXM_NFCLD_LVL__RESET_VALUE                                                                  (0x00330066UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rxm_ctrl
* <b>Reset value:</b> 0x0044893E
* <b>Access:</b> rw
* @{
*/
#define CLIF_RXM_CTRL                                                                                     0x35
#define CLIF_RXM_CTRL_R                                                                                     0x35
#define CLIF_RXM_CTRL_W                                                                                     0x35
#define CLIF_RXM_CTRL_RESERVED_POS                                                                       (0UL)
#define CLIF_RXM_CTRL_RESERVED_MASK                                                                      (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_RXM_CTRL__RESET_VALUE                                                                       (0x0044893EUL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ana_agc_dco_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANA_AGC_DCO_CTRL                                                                             0x36
#define CLIF_ANA_AGC_DCO_CTRL_R                                                                             0x36
#define CLIF_ANA_AGC_DCO_CTRL_W                                                                             0x36
#define CLIF_ANA_AGC_DCO_CTRL_RESERVED_POS                                                               (0UL)
#define CLIF_ANA_AGC_DCO_CTRL_RESERVED_MASK                                                              (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_ANA_AGC_DCO_CTRL__RESET_VALUE                                                               (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_sigpro_cm_config
* <b>Reset value:</b> 0x1F800001
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_CONFIG                                                                             0x37
#define CLIF_SIGPRO_CM_CONFIG_R                                                                             0x37
#define CLIF_SIGPRO_CM_CONFIG_W                                                                             0x37
#define CLIF_SIGPRO_CM_CONFIG_RESERVED_POS                                                               (0UL)
#define CLIF_SIGPRO_CM_CONFIG_RESERVED_MASK                                                              (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_SIGPRO_CM_CONFIG__RESET_VALUE                                                               (0x1F800001UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_gcm_config2
* <b>Reset value:</b> 0x00024820
* <b>Access:</b> rw
* @{
*/
#define CLIF_GCM_CONFIG2                                                                                  0x38
#define CLIF_GCM_CONFIG2_R                                                                                  0x38
#define CLIF_GCM_CONFIG2_W                                                                                  0x38
#define CLIF_GCM_CONFIG2_RESERVED_POS                                                                    (0UL)
#define CLIF_GCM_CONFIG2_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_GCM_CONFIG2__RESET_VALUE                                                                    (0x00024820UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_gcm_config1
* <b>Reset value:</b> 0x00000FC0
* <b>Access:</b> rw
* @{
*/
#define CLIF_GCM_CONFIG1                                                                                  0x39
#define CLIF_GCM_CONFIG1_R                                                                                  0x39
#define CLIF_GCM_CONFIG1_W                                                                                  0x39
#define CLIF_GCM_CONFIG1_RESERVED_POS                                                                    (0UL)
#define CLIF_GCM_CONFIG1_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_GCM_CONFIG1__RESET_VALUE                                                                    (0x00000FC0UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_gcm_config0
* <b>Reset value:</b> 0x00D03939
* <b>Access:</b> rw
* @{
*/
#define CLIF_GCM_CONFIG0                                                                                  0x3A
#define CLIF_GCM_CONFIG0_R                                                                                  0x3A
#define CLIF_GCM_CONFIG0_W                                                                                  0x3A
#define CLIF_GCM_CONFIG0_RESERVED_POS                                                                    (0UL)
#define CLIF_GCM_CONFIG0_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_GCM_CONFIG0__RESET_VALUE                                                                    (0x00D03939UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ss_tx1_cmcfg
* <b>Reset value:</b> 0x000000FF
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_CMCFG                                                                                 0x3B
#define CLIF_SS_TX1_CMCFG_R                                                                                 0x3B
#define CLIF_SS_TX1_CMCFG_W                                                                                 0x3B
#define CLIF_SS_TX1_CMCFG_RESERVED_POS                                                                   (22UL)
#define CLIF_SS_TX1_CMCFG_RESERVED_MASK                                                                  (0xFFC00000UL)  /**< 22-Reserved*/
#define CLIF_SS_TX1_CMCFG_TX1_CLK_MODE_MOD_CM_POS                                                        (19UL)
#define CLIF_SS_TX1_CMCFG_TX1_CLK_MODE_MOD_CM_MASK                                                       (0x00380000UL)  /**< 19-TX1 clock mode of modulated wave in CM*/
#define CLIF_SS_TX1_CMCFG_TX1_CLK_MODE_CW_CM_POS                                                         (16UL)
#define CLIF_SS_TX1_CMCFG_TX1_CLK_MODE_CW_CM_MASK                                                        (0x00070000UL)  /**< 16-TX1 clock mode of unmodulated wave in CM*/
#define CLIF_SS_TX1_CMCFG_TX1_AMP_MOD_CM_POS                                                             (8UL)
#define CLIF_SS_TX1_CMCFG_TX1_AMP_MOD_CM_MASK                                                            (0x0000FF00UL)  /**< 8-TX1 amplitude of modulated wave in CM*/
#define CLIF_SS_TX1_CMCFG_TX1_AMP_CW_CM_POS                                                              (0UL)
#define CLIF_SS_TX1_CMCFG_TX1_AMP_CW_CM_MASK                                                             (0x000000FFUL)  /**< 0-TX1 amplitude of unmodulated wave in CM*/
#define CLIF_SS_TX1_CMCFG__RESET_VALUE                                                                   (0x000000FFUL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_cmcfg
* <b>Reset value:</b> 0x000000FF
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_CMCFG                                                                                 0x3C
#define CLIF_SS_TX2_CMCFG_R                                                                                 0x3C
#define CLIF_SS_TX2_CMCFG_W                                                                                 0x3C
#define CLIF_SS_TX2_CMCFG_RESERVED_POS                                                                   (22UL)
#define CLIF_SS_TX2_CMCFG_RESERVED_MASK                                                                  (0xFFC00000UL)  /**< 22-Reserved*/
#define CLIF_SS_TX2_CMCFG_TX2_CLK_MODE_MOD_CM_POS                                                        (19UL)
#define CLIF_SS_TX2_CMCFG_TX2_CLK_MODE_MOD_CM_MASK                                                       (0x00380000UL)  /**< 19-TX2 clock mode of modulated wave in CM*/
#define CLIF_SS_TX2_CMCFG_TX2_CLK_MODE_CW_CM_POS                                                         (16UL)
#define CLIF_SS_TX2_CMCFG_TX2_CLK_MODE_CW_CM_MASK                                                        (0x00070000UL)  /**< 16-TX2 clock mode of unmodulated wave in CM*/
#define CLIF_SS_TX2_CMCFG_TX2_AMP_MOD_CM_POS                                                             (8UL)
#define CLIF_SS_TX2_CMCFG_TX2_AMP_MOD_CM_MASK                                                            (0x0000FF00UL)  /**< 8-TX2 amplitude of modulated wave in CM*/
#define CLIF_SS_TX2_CMCFG_TX2_AMP_CW_CM_POS                                                              (0UL)
#define CLIF_SS_TX2_CMCFG_TX2_AMP_CW_CM_MASK                                                             (0x000000FFUL)  /**< 0-TX2 amplitude of unmodulated wave in CM*/
#define CLIF_SS_TX2_CMCFG__RESET_VALUE                                                                   (0x000000FFUL)  /**< value after reset*/
/**
* @}
*/

/**
* @}
*/
/**
* @name clif_timer0_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER0_CONFIG                                                                                0x3D
#define CLIF_TIMER0_CONFIG_R                                                                                0x3D
#define CLIF_TIMER0_CONFIG_W                                                                                0x3D
#define CLIF_TIMER0_CONFIG_RESERVED_POS                                                                  (31UL)
#define CLIF_TIMER0_CONFIG_RESERVED_MASK                                                                 (0x80000000UL)  /**< 31-Reserved */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_STARTED_POS                                                     (30UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_STARTED_MASK                                                    (0x40000000UL)  /**< 30-T0_STOP_EVENT: If set. the timer T0 is stopped when a data reception begins (1st bit is received). */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_TX_STARTED_POS                                                     (29UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_TX_STARTED_MASK                                                    (0x20000000UL)  /**< 29-T0_STOP_EVENT: If set. the timer T0 is stopped when a data transmission begins. */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_EXT_POS                                                      (28UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_EXT_MASK                                                     (0x10000000UL)  /**< 28-T0_STOP_EVENT: If set. the timer T0 is stopped when the external RF field is detected.*/
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_EXT_POS                                                     (27UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_EXT_MASK                                                    (0x08000000UL)  /**< 27-T0_STOP_EVENT: If set. the timer T0 is stopped when the external RF field vanishes. */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_INT_POS                                                      (26UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_ON_INT_MASK                                                     (0x04000000UL)  /**< 26-T0_STOP_EVENT: If set. the timer T0 is stopped when the internal RF field is turned on. */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_INT_POS                                                     (25UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RF_OFF_INT_MASK                                                    (0x02000000UL)  /**< 25-T0_STOP_EVENT: If set. the timer T0 is stopped when the internal RF field is turned off. */
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_ENDED_POS                                                       (24UL)
#define CLIF_TIMER0_CONFIG_T0_STOP_ON_RX_ENDED_MASK                                                      (0x01000000UL)  /**< 24-T0_STOP_EVENT: If set the timer T0 is stopped when an activity on RX is detected.*/
#define CLIF_TIMER0_CONFIG_RESERVED1_POS                                                                  (18UL)
#define CLIF_TIMER0_CONFIG_RESERVED1_MASK                                                                 (0x00FC0000UL)  /**< 18-Reserved */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RX_STARTED_POS                                                    (17UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RX_STARTED_MASK                                                   (0x00020000UL)  /**< 17-T0_START_EVENT: If set. the timer T0 is started when a data reception begins (1st bit is received). */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RX_ENDED_POS                                                      (16UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RX_ENDED_MASK                                                     (0x00010000UL)  /**< 16-T0_START_EVENT: If set. the timer T0 is started when a data reception ends. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_STARTED_POS                                                    (15UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_STARTED_MASK                                                   (0x00008000UL)  /**< 15-T0_START_EVENT: If set. the timer T0 is started when a data transmission begins. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_ENDED_POS                                                      (14UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_ENDED_MASK                                                     (0x00004000UL)  /**< 14-T0_START_EVENT: If set. the timer T0 is started when a data transmission ends. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_EXT_POS                                                     (13UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_EXT_MASK                                                    (0x00002000UL)  /**< 13-T0_START_EVENT: If set. the timer T0 is startedwhen the external RF field is detected. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_EXT_POS                                                    (12UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_EXT_MASK                                                   (0x00001000UL)  /**< 12-T0_START_EVENT: If set. the timer T0 is started when the external RF field is not detected any more. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_INT_POS                                                     (11UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_ON_INT_MASK                                                    (0x00000800UL)  /**< 11-T0_START_EVENT: If set. the timer T0 is started when an internal RF field is turned on. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_INT_POS                                                    (10UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_RF_OFF_INT_MASK                                                   (0x00000400UL)  /**< 10-T0_START_EVENT: If set. the timer T0 is started when an internal RF field is turned off. */
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_FRAMESTEP_POS                                                  (9UL)
#define CLIF_TIMER0_CONFIG_T0_START_ON_TX_FRAMESTEP_MASK                                                 (0x00000200UL)  /**< 9-T0_START_EVENT: If set the timer T0 is started when an activity on Framestep is detected.*/
#define CLIF_TIMER0_CONFIG_T0_START_NOW_POS                                                              (8UL)
#define CLIF_TIMER0_CONFIG_T0_START_NOW_MASK                                                             (0x00000100UL)  /**< 8-T0_START_EVENT: If set. the timer T0 is started immediatly. */
#define CLIF_TIMER0_CONFIG_RESERVED2_POS                                                                 (7UL)
#define CLIF_TIMER0_CONFIG_RESERVED2_MASK                                                                (0x00000080UL)  /**< 7-Reserved */
#define CLIF_TIMER0_CONFIG_T0_ONE_SHOT_MODE_POS                                                          (6UL)
#define CLIF_TIMER0_CONFIG_T0_ONE_SHOT_MODE_MASK                                                         (0x00000040UL)  /**< 6-When set to 1 the counter value does not reload again until the counter value has reached zero*/
#define CLIF_TIMER0_CONFIG_T0_PRESCALE_SEL_POS                                                           (3UL)
#define CLIF_TIMER0_CONFIG_T0_PRESCALE_SEL_MASK                                                          (0x00000038UL)  /**< 3-Controls frequency/period of the timer T0 when the prescaler is activated in T0_MODE_SEL. 000b* 6.78MHz counter 001b 3.39MHz counter 010b 1.70MHz counter 011b 848kHz counter 100b 424kHz counter 101b 212kHz counter 110b 106kHz counter 111b 53kHz counter   */
#define CLIF_TIMER0_CONFIG_T0_MODE_SEL_POS                                                               (2UL)
#define CLIF_TIMER0_CONFIG_T0_MODE_SEL_MASK                                                              (0x00000004UL)  /**< 2-Configuration of the timer T0 clock. 0b* Prescaler is disabled: the timer frequency matches CLIF clock frequency (13.56MHz). 1b Prescaler is enabled: the timer operates on the prescaler signal frequency (chosen by T0_PRESCALE_SEL).*/
#define CLIF_TIMER0_CONFIG_T0_RELOAD_ENABLE_POS                                                          (1UL)
#define CLIF_TIMER0_CONFIG_T0_RELOAD_ENABLE_MASK                                                         (0x00000002UL)  /**< 1-If set to 0.the timer T0 will stop on expiration. 0* After expiration the timer T0 will stop counting. i.e.. remain zero. reset value. 1 After expiration the timer T0 will reload its preset value and continue counting down. */
#define CLIF_TIMER0_CONFIG_T0_ENABLE_POS                                                                 (0UL)
#define CLIF_TIMER0_CONFIG_T0_ENABLE_MASK                                                                (0x00000001UL)  /**< 0-Enables the timer T0*/
#define CLIF_TIMER0_CONFIG__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer0_reload
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER0_RELOAD                                                                                0x3E
#define CLIF_TIMER0_RELOAD_R                                                                                0x3E
#define CLIF_TIMER0_RELOAD_W                                                                                0x3E
#define CLIF_TIMER0_RELOAD_RESERVED_POS                                                                  (20UL)
#define CLIF_TIMER0_RELOAD_RESERVED_MASK                                                                 (0xFFF00000UL)  /**< 20-Reserved */
#define CLIF_TIMER0_RELOAD_T0_RELOAD_VALUE_POS                                                           (0UL)
#define CLIF_TIMER0_RELOAD_T0_RELOAD_VALUE_MASK                                                          (0x000FFFFFUL)  /**< 0-Reload value of the timer T0. */
#define CLIF_TIMER0_RELOAD__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer1_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER1_CONFIG                                                                                0x3F
#define CLIF_TIMER1_CONFIG_R                                                                                0x3F
#define CLIF_TIMER1_CONFIG_W                                                                                0x3F
#define CLIF_TIMER1_CONFIG_RESERVED_POS                                                                  (31UL)
#define CLIF_TIMER1_CONFIG_RESERVED_MASK                                                                 (0x80000000UL)  /**< 31-Reserved */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_POS                                                     (30UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_STARTED_MASK                                                    (0x40000000UL)  /**< 30-T1_STOP_EVENT: If set. the timer T1 is stopped when a data reception begins (1st bit is received). */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_TX_STARTED_POS                                                     (29UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_TX_STARTED_MASK                                                    (0x20000000UL)  /**< 29-T1_STOP_EVENT: If set. the timer T1 is stopped when a data transmission begins. */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_ON_EXT_POS                                                      (28UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_ON_EXT_MASK                                                     (0x10000000UL)  /**< 28-T1_STOP_EVENT: If set. the timer T1 is stopped when the external RF field is detected. */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_OFF_EXT_POS                                                     (27UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_OFF_EXT_MASK                                                    (0x08000000UL)  /**< 27-T1_STOP_EVENT: If set. the timer T1 is stopped when the external RF field vanishes. */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_ON_INT_POS                                                      (26UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_ON_INT_MASK                                                     (0x04000000UL)  /**< 26-T1_STOP_EVENT: If set. the timer T1 is stopped when the internal RF field is turned on. */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_OFF_INT_POS                                                     (25UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RF_OFF_INT_MASK                                                    (0x02000000UL)  /**< 25-T1_STOP_EVENT: If set. the timer T1 is stopped when the internal RF field is turned off. */
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_ENDED_POS                                                       (24UL)
#define CLIF_TIMER1_CONFIG_T1_STOP_ON_RX_ENDED_MASK                                                      (0x01000000UL)  /**< 24-T1_STOP_EVENT: If set the timer T1 is stopped when an activity on RX is detected.*/
#define CLIF_TIMER1_CONFIG_RESERVED1_POS                                                                  (18UL)
#define CLIF_TIMER1_CONFIG_RESERVED1_MASK                                                                 (0x00FC0000UL)  /**< 18-Reserved */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RX_STARTED_POS                                                    (17UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RX_STARTED_MASK                                                   (0x00020000UL)  /**< 17-T1_START_EVENT: If set. the timer T1 is started when a data reception begins (1st bit is received). */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RX_ENDED_POS                                                      (16UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RX_ENDED_MASK                                                     (0x00010000UL)  /**< 16-T1_START_EVENT: If set. the timer T1 is started when a data reception ends. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_STARTED_POS                                                    (15UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_STARTED_MASK                                                   (0x00008000UL)  /**< 15-T1_START_EVENT: If set. the timer T1 is started when a data transmission begins.   */
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_POS                                                      (14UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_ENDED_MASK                                                     (0x00004000UL)  /**< 14-T1_START_EVENT: If set. the timer T1 is started when a data transmission ends. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_ON_EXT_POS                                                     (13UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_ON_EXT_MASK                                                    (0x00002000UL)  /**< 13-T1_START_EVENT: If set. the timer T1 is startedwhen the external RF field is detected. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_OFF_EXT_POS                                                    (12UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_OFF_EXT_MASK                                                   (0x00001000UL)  /**< 12-T1_START_EVENT: If set. the timer T1 is started when the external RF field is not detected any more. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_ON_INT_POS                                                     (11UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_ON_INT_MASK                                                    (0x00000800UL)  /**< 11-T1_START_EVENT: If set. the timer T1 is started when an internal RF field is turned on. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_OFF_INT_POS                                                    (10UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_RF_OFF_INT_MASK                                                   (0x00000400UL)  /**< 10-T1_START_EVENT: If set. the timer T1 is started when an internal RF field is turned off. */
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_FRAMESTEP_POS                                                  (9UL)
#define CLIF_TIMER1_CONFIG_T1_START_ON_TX_FRAMESTEP_MASK                                                 (0x00000200UL)  /**< 9-T1_START_EVENT: If set. the timer T1 is started when an activity on Framestep is detected.*/
#define CLIF_TIMER1_CONFIG_T1_START_NOW_POS                                                              (8UL)
#define CLIF_TIMER1_CONFIG_T1_START_NOW_MASK                                                             (0x00000100UL)  /**< 8-T1_START_EVENT: If set. the timer T1 is started immediatly. */
#define CLIF_TIMER1_CONFIG_RESERVED2_POS                                                                  (7UL)
#define CLIF_TIMER1_CONFIG_RESERVED2_MASK                                                                 (0x00000080UL)  /**< 7-Reserved */
#define CLIF_TIMER1_CONFIG_T1_ONE_SHOT_MODE_POS                                                          (6UL)
#define CLIF_TIMER1_CONFIG_T1_ONE_SHOT_MODE_MASK                                                         (0x00000040UL)  /**< 6-When set to 1 the counter value does not reload again until the counter value has reached zero*/
#define CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_POS                                                           (3UL)
#define CLIF_TIMER1_CONFIG_T1_PRESCALE_SEL_MASK                                                          (0x00000038UL)  /**< 3-Controls frequency/period of the timer T1 when the prescaler is activated by T1_MODE_SEL. 000b* 6.78MHz counter 001b 3.39MHz counter 010b 1.70MHz counter 011b 848kHz counter 100b 424kHz counter 101b 212kHz counter 110b 106kHz counter 111b 53kHz counter */
#define CLIF_TIMER1_CONFIG_T1_MODE_SEL_POS                                                               (2UL)
#define CLIF_TIMER1_CONFIG_T1_MODE_SEL_MASK                                                              (0x00000004UL)  /**< 2-If set. the timer T1 is started the prescaler for the timer T1 is enabled. 0* Prescaler is disabled: the timer frequency matches CLIF clock frequency (13.56MHz). 1 Prescaler is enabled: the timer operates on the prescaler signal frequency (chosen by T1_PRESCALE_SEL). */
#define CLIF_TIMER1_CONFIG_T1_RELOAD_ENABLE_POS                                                          (1UL)
#define CLIF_TIMER1_CONFIG_T1_RELOAD_ENABLE_MASK                                                         (0x00000002UL)  /**< 1-If set to 0.the timer T1 will stop on expiration. 0* After expiration the timer T1 will stop counting. i.e.. remain zero. reset value. 1 After expiration the timer T1 will reload its preset value and continue counting down. */
#define CLIF_TIMER1_CONFIG_T1_ENABLE_POS                                                                 (0UL)
#define CLIF_TIMER1_CONFIG_T1_ENABLE_MASK                                                                (0x00000001UL)  /**< 0-Enables the timer T1*/
#define CLIF_TIMER1_CONFIG__RESET_VALUE                                                                  (0x00000000UL) /**< value after reset */

/**
* @name clif_timer1_reload
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER1_RELOAD                                                                                0x40
#define CLIF_TIMER1_RELOAD_R                                                                                0x40
#define CLIF_TIMER1_RELOAD_W                                                                                0x40
#define CLIF_TIMER1_RELOAD_RESERVED_POS                                                                  (20UL)
#define CLIF_TIMER1_RELOAD_RESERVED_MASK                                                                 (0xFFF00000UL)  /**< 20-Reserved */
#define CLIF_TIMER1_RELOAD_T1_RELOAD_VALUE_POS                                                           (0UL)
#define CLIF_TIMER1_RELOAD_T1_RELOAD_VALUE_MASK                                                          (0x000FFFFFUL)  /**< 0-Reload value of the timer T1.*/
#define CLIF_TIMER1_RELOAD__RESET_VALUE                                                                  (0x00000000UL) /**< value after reset */

/**
* @name clif_ana_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_ANA_STATUS                                                                                   0x41
#define CLIF_ANA_STATUS_R                                                                                   0x41
#define CLIF_ANA_STATUS_RESERVED_POS                                                                     (21UL)
#define CLIF_ANA_STATUS_RESERVED_MASK                                                                    (0xFFE00000UL)  /**< 21-reserved*/
#define CLIF_ANA_STATUS_ADC_DATA_I_POS                                                                   (11UL)
#define CLIF_ANA_STATUS_ADC_DATA_I_MASK                                                                  (0x001FF800UL)  /**< 11-RX adc I output for validation purposes*/
#define CLIF_ANA_STATUS_ADC_DATA_Q_POS                                                                   (1UL)
#define CLIF_ANA_STATUS_ADC_DATA_Q_MASK                                                                  (0x000007FEUL)  /**< 1-RX adc Q output for validation purposes*/
#define CLIF_ANA_STATUS_PLL_LOCK_STATUS_POS                                                              (0UL)
#define CLIF_ANA_STATUS_PLL_LOCK_STATUS_MASK                                                             (0x00000001UL)  /**< 0-PLL lock status indicator*/
#define CLIF_ANA_STATUS__RESET_VALUE                                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ana_rx_ctrl
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANA_RX_CTRL                                                                                  0x43
#define CLIF_ANA_RX_CTRL_R                                                                                  0x43
#define CLIF_ANA_RX_CTRL_W                                                                                  0x43
#define CLIF_ANA_RX_CTRL_RESERVED_POS                                                                    (0UL)
#define CLIF_ANA_RX_CTRL_RESERVED_MASK                                                                   (0xFFFFFFFFUL)  /**< 0-Reserved*/
#define CLIF_ANA_RX_CTRL__RESET_VALUE                                                                    (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_anactrl_tx_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANACTRL_TX_CONFIG                                                                            0x44
#define CLIF_ANACTRL_TX_CONFIG_R                                                                            0x44
#define CLIF_ANACTRL_TX_CONFIG_W                                                                            0x44
#define CLIF_ANACTRL_TX_CONFIG_RESERVED_POS                                                              (22UL)
#define CLIF_ANACTRL_TX_CONFIG_RESERVED_MASK                                                             (0xFFC00000UL)  /**< 22-Reserved */
#define CLIF_ANACTRL_TX_CONFIG_TX_PH_SHIFT_MOD10_POS                                                     (18UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_PH_SHIFT_MOD10_MASK                                                    (0x003C0000UL)  /**< 18-Applies a tx_ph_shift_mod10x0.9 degree on ck13m56_tx wrt ck13m56. Value is unsigned, ranging from 0 to 9. Final tx phase shift is the following: (tx_ph_shift_div10x10+tx_ph_shift_mod10)x0.9 degree*/
#define CLIF_ANACTRL_TX_CONFIG_TX_PH_SHIFT_DIV10_POS                                                     (13UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_PH_SHIFT_DIV10_MASK                                                    (0x0003E000UL)  /**< 13-Applies a tx_ph_shift_div10x10x0.9 degree on ck13m56_tx wrt ck13m56. Value is signed 2s complement, ranging from -16 to 15, corresponding to -144 degree to 135 degree, with steps of 9 degree*/
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_CW_CM_POS                                                         (11UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_CW_CM_MASK                                                        (0x00001800UL)  /**< 11-Shift driver waves of 180 degrees in CM Continuous Wave. Index 0: TX1; index 1: TX2*/
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_MOD_CM_POS                                                        (9UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_MOD_CM_MASK                                                       (0x00000600UL)  /**< 9-Shift driver waves of 180 degrees in CM Modulated Wave. Index 0: TX1; index 1: TX2*/
#define CLIF_ANACTRL_TX_CONFIG_TX_INVL_CM_POS                                                            (7UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_INVL_CM_MASK                                                           (0x00000180UL)  /**< 7-inverse polarity of driver waves in CM. Index 0: TX1; index 1: TX2*/
#define CLIF_ANACTRL_TX_CONFIG_TX_PWM_MODE_CM_POS                                                        (6UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_PWM_MODE_CM_MASK                                                       (0x00000040UL)  /**< 6-PWM scheme for CM: 0: TX1/2 3-levels (If at least either clk_mode_tx1 or clk_mode_tx2 is set on a clocked mode) 1: TX1/2 2-levels with differentiated pulses*/
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_RM_POS                                                            (4UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_INVP_RM_MASK                                                           (0x00000030UL)  /**< 4-shift driver waves of 180 in RM. Index 0: TX1; index 1: TX2*/
#define CLIF_ANACTRL_TX_CONFIG_TX_INVL_POS                                                               (2UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_INVL_MASK                                                              (0x0000000CUL)  /**< 2-inverse polarity of driver waves in RM. Index 0: TX1; index 1: TX2*/
#define CLIF_ANACTRL_TX_CONFIG_TX_PWM_MODE_RM_POS                                                        (1UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_PWM_MODE_RM_MASK                                                       (0x00000002UL)  /**< 1-PWM scheme for RM: 0: TX1/2 3-levels (If at least either clk_mode_tx1 or clk_mode_tx2 is set on a clocked mode) 1: TX1/2 2-levels with differentiated pulses*/
#define CLIF_ANACTRL_TX_CONFIG_TX_EN_POS                                                                 (0UL)
#define CLIF_ANACTRL_TX_CONFIG_TX_EN_MASK                                                                (0x00000001UL)  /**< 0-Enables transmitter*/
#define CLIF_ANACTRL_TX_CONFIG__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/ 
/**
* @}
*/

/**
* @name clif_anactrl_tx_nov
* <b>Reset value:</b> 0x00000AE1
* <b>Access:</b> rw
* @{
*/
#define CLIF_ANACTRL_TX_NOV                                                                               0x45
#define CLIF_ANACTRL_TX_NOV_R                                                                               0x45
#define CLIF_ANACTRL_TX_NOV_W                                                                               0x45
#define CLIF_ANACTRL_TX_NOV_RESERVED_POS                                                                 (27UL)
#define CLIF_ANACTRL_TX_NOV_RESERVED_MASK                                                                (0xF8000000UL)  /**< 27-Returns non-overlap regulation counter selected by SEL_OF FSET_CNT*/
#define CLIF_ANACTRL_TX_NOV_TX_NOV_OFFSET_IN_POS                                                         (22UL)
#define CLIF_ANACTRL_TX_NOV_TX_NOV_OFFSET_IN_MASK                                                        (0x07C00000UL)  /**< 22-Offset value to be loaded based on SEL_OFFSET_CNT*/
#define CLIF_ANACTRL_TX_NOV_TX_SEL_OFFSET_CNT_POS                                                        (19UL)
#define CLIF_ANACTRL_TX_NOV_TX_SEL_OFFSET_CNT_MASK                                                       (0x00380000UL)  /**< 19-Non-overlap regulation counter selection*/
#define CLIF_ANACTRL_TX_NOV_TX_OFFSET_LOAD_POS                                                           (18UL)
#define CLIF_ANACTRL_TX_NOV_TX_OFFSET_LOAD_MASK                                                          (0x00040000UL)  /**< 18-If set to 1, overrides the non-overlap regulation counter selected by SEL_OFFSET_CNT with NOV_OFFSET_IN*/
#define CLIF_ANACTRL_TX_NOV_TX_SET_NOV_TIME_FW_POS                                                       (15UL)
#define CLIF_ANACTRL_TX_NOV_TX_SET_NOV_TIME_FW_MASK                                                      (0x00038000UL)  /**< 15-Non-overlap window target setting for the PMOS/NMOS/free-wheel in the 3-levels mode (400ps*(set_nov_time+1))*/
#define CLIF_ANACTRL_TX_NOV_TX_SET_NOV_TIME_FP_POS                                                       (12UL)
#define CLIF_ANACTRL_TX_NOV_TX_SET_NOV_TIME_FP_MASK                                                      (0x00007000UL)  /**< 12-Non-overlap window target setting for the PMOS/NMOS in 2-levels modes (400ps*(set_nov_time+1))*/
#define CLIF_ANACTRL_TX_NOV_TX_FRWH_THRESH_POS                                                           (5UL)
#define CLIF_ANACTRL_TX_NOV_TX_FRWH_THRESH_MASK                                                          (0x00000FE0UL)  /**< 5-Digital threshold below which the freewheel / 3 levels operation is fully activated */
#define CLIF_ANACTRL_TX_NOV_TX_AUTO_NOV_POS                                                              (1UL)
#define CLIF_ANACTRL_TX_NOV_TX_AUTO_NOV_MASK                                                             (0x0000001EUL)  /**< 1-Automatic triggering of non overlap regulation loop at RF. 0 : disable, /=0 :  enable regulation during 128/13.56MHz*AUTO_NOV after Rfon*/
#define CLIF_ANACTRL_TX_NOV_TX_FREEZE_NOV_POS                                                            (0UL)
#define CLIF_ANACTRL_TX_NOV_TX_FREEZE_NOV_MASK                                                           (0x00000001UL)  /**< 0-Freezes the automatic non-overlap regulation mechanism*/
#define CLIF_ANACTRL_TX_NOV__RESET_VALUE                                                                 (0x00000AE1UL)  /**< value after reset*/ 
/**
* @}
*/

/**
* @name clif_rx_eof_pattern
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_EOF_PATTERN                                                                               0x46
#define CLIF_RX_EOF_PATTERN_R                                                                               0x46
#define CLIF_RX_EOF_PATTERN_W                                                                               0x46
#define CLIF_RX_EOF_PATTERN_RX_EOF_PATTERN_POS                                                           (0UL)
#define CLIF_RX_EOF_PATTERN_RX_EOF_PATTERN_MASK                                                          (0xFFFFFFFFUL)  /**< 0-*/
#define CLIF_RX_EOF_PATTERN__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rx_emd_1_config
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_EMD_1_CONFIG                                                                              0x47
#define CLIF_RX_EMD_1_CONFIG_R                                                                              0x47
#define CLIF_RX_EMD_1_CONFIG_W                                                                              0x47
#define CLIF_RX_EMD_1_CONFIG_RESERVED_POS                                                                (17UL)
#define CLIF_RX_EMD_1_CONFIG_RESERVED_MASK                                                               (0xFFFE0000UL)  /**< 17-Reserved*/
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_IRQ_MASK_POS                                                         (16UL)
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_IRQ_MASK_MASK                                                        (0x00010000UL)  /**< 16-If asserted, the detected EMD is not reported via EMD IRQ. Otherwise every detected EMD causes the EMD IRQ assertion.*/
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_LEVEL_THRESH_1_POS                                                   (8UL)
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_LEVEL_THRESH_1_MASK                                                  (0x0000FF00UL)  /**< 8-Defines the EMD detection threshold when the number of received bits >RX_EMD_LENGTH_THRESH_0 If currently calculated EMD level more than RX_EMD_LEVEL_THRESH_1 - the frame is classified as EMD, otherwise its normal Frame.*/
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_LEVEL_THRESH_0_POS                                                   (0UL)
#define CLIF_RX_EMD_1_CONFIG_RX_EMD_LEVEL_THRESH_0_MASK                                                  (0x000000FFUL)  /**< 0-Defines the EMD detection threshold when the number of received bits =< RX_EMD_LENGTH_THRESH_0 If currently calculated EMD level more than RX_EMD_LEVEL_THRESH_0 - the frame is classified as EMD, otherwise its normal Frame.*/
#define CLIF_RX_EMD_1_CONFIG__RESET_VALUE                                                                (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rx_emd_0_config
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_RX_EMD_0_CONFIG                                                                              0x48
#define CLIF_RX_EMD_0_CONFIG_R                                                                              0x48
#define CLIF_RX_EMD_0_CONFIG_W                                                                              0x48
#define CLIF_RX_EMD_0_CONFIG_RX_EMD_LENGTH_THRESH_0_POS                                                  (24UL)
#define CLIF_RX_EMD_0_CONFIG_RX_EMD_LENGTH_THRESH_0_MASK                                                 (0xFF000000UL)  /**< 24-Threshold in number of received data bits which defines which group of EMD config parameters must be used for the EMD detection.If the number of received bits >RX_EMD_LENGTH_THRESH_0  the *_IS_EMD_1 group of parameters must be used for the EMD classification, otherwise the*_IS_EMD_0 group.*/
#define CLIF_RX_EMD_0_CONFIG_RESERVED_POS                                                                (23UL)
#define CLIF_RX_EMD_0_CONFIG_RESERVED_MASK                                                               (0x00800000UL)  /**< 23-Reserved*/
#define CLIF_RX_EMD_0_CONFIG_RX_MAXLEN_FRAME_IS_EMD_POS                                                  (22UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MAXLEN_FRAME_IS_EMD_MASK                                                 (0x00400000UL)  /**< 22-If asserted and the received frame length violates the max frame length configured via the RX_FRAME_MAXLEN register - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_MINLEN_FRAME_IS_EMD_POS                                                  (21UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MINLEN_FRAME_IS_EMD_MASK                                                 (0x00200000UL)  /**< 21-If asserted and the received frame length violates the min frame length configured via the RX_FRAME_MINLEN register - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_LEN_ERR_IS_EMD_POS                                                       (20UL)
#define CLIF_RX_EMD_0_CONFIG_RX_LEN_ERR_IS_EMD_MASK                                                      (0x00100000UL)  /**< 20-If asserted and the LEN field is a part of the frame, the wrong received value in the field is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_TERM_IS_EMD_1_POS                                                 (19UL)
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_TERM_IS_EMD_1_MASK                                                (0x00080000UL)  /**< 19-If asserted, the number of received bits>RX_EMD_LENGTH_THRESH_0 and the SGP_MSG_RXOVER_TERM message is received - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_ERR_IS_EMD_1_POS                                                  (18UL)
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_ERR_IS_EMD_1_MASK                                                 (0x00040000UL)  /**< 18-If asserted, the number of received bits >RX_EMD_LENGTH_THRESH_0 and either SGP_MSG_RXOVER_ERROR or SGP_MSG_ERROR message is received - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_NOSTOP_DET_IS_EMD_1_POS                                                  (17UL)
#define CLIF_RX_EMD_0_CONFIG_RX_NOSTOP_DET_IS_EMD_1_MASK                                                 (0x00020000UL)  /**< 17-If asserted, the number of received bits >RX_EMD_LENGTH_THRESH_0 and the frame reception is over being not interrupted by any detected error or external rf-off event but no any stop conditions, configured via EOF_COND_SCALE register, were detected -the scenario is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_CRC_ERR_IS_EMD_1_POS                                                     (16UL)
#define CLIF_RX_EMD_0_CONFIG_RX_CRC_ERR_IS_EMD_1_MASK                                                    (0x00010000UL)  /**< 16-If asserted and the number of received bits>RX_EMD_LENGTH_THRESH_0 - the detection of the CRC error is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_NOT_FULL_BYTE_IS_EMD_1_POS                                               (15UL)
#define CLIF_RX_EMD_0_CONFIG_RX_NOT_FULL_BYTE_IS_EMD_1_MASK                                              (0x00008000UL)  /**< 15-If asserted and the number of received bits>RX_EMD_LENGTH_THRESH_0 - the reception of last byte with size < 8 data bits is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_STOPBIT_IS_EMD_1_POS                                             (14UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_STOPBIT_IS_EMD_1_MASK                                            (0x00004000UL)  /**< 14-If asserted, the number of received bits >RX_EMD_LENGTH_THRESH_0 and the stop bit is a part of the frame character, the reception of the last character with 8 data bits but without stop bit is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_PARITY_IS_EMD_1_POS                                              (13UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_PARITY_IS_EMD_1_MASK                                             (0x00002000UL)  /**< 13-If asserted, the number of received bits >RX_EMD_LENGTH_THRESH_0 and the parity bit is a part of the frame character, the reception of the last character with 8 data bits but without parity bit is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_PARBIT_ERR_IS_EMD_1_POS                                                  (12UL)
#define CLIF_RX_EMD_0_CONFIG_RX_PARBIT_ERR_IS_EMD_1_MASK                                                 (0x00001000UL)  /**< 12-If asserted and the number of received bits >RX_EMD_LENGTH_THRESH_0 - the detected parity error is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_STOPBIT_ERR_IS_EMD_1_POS                                                 (11UL)
#define CLIF_RX_EMD_0_CONFIG_RX_STOPBIT_ERR_IS_EMD_1_MASK                                                (0x00000800UL)  /**< 11-If asserted and the number of received bits >RX_EMD_LENGTH_THRESH_0 - the detected stop bit error (0 level instead of 1 on the stop bit position) is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_COLL_IS_EMD_1_POS                                                        (10UL)
#define CLIF_RX_EMD_0_CONFIG_RX_COLL_IS_EMD_1_MASK                                                       (0x00000400UL)  /**< 10-If asserted and the number of received bits >RX_EMD_LENGTH_THRESH_0 - the collision is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_TERM_IS_EMD_0_POS                                                 (9UL)
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_TERM_IS_EMD_0_MASK                                                (0x00000200UL)  /**< 9-If asserted, the number of received bits =<RX_EMD_LENGTH_THRESH_0 and the SGP_MSG_RXOVER_TERM message is received - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_ERR_IS_EMD_0_POS                                                  (8UL)
#define CLIF_RX_EMD_0_CONFIG_RX_SIGPRO_ERR_IS_EMD_0_MASK                                                 (0x00000100UL)  /**< 8- If asserted, the number of received bits =<RX_EMD_LENGTH_THRESH_0 and either SGP_MSG_RXOVER_ERROR or SGP_MSG_ERROR message is received - the event is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_NOSTOP_DET_IS_EMD_0_POS                                                  (7UL)
#define CLIF_RX_EMD_0_CONFIG_RX_NOSTOP_DET_IS_EMD_0_MASK                                                 (0x00000080UL)  /**< 7-If asserted, the number of received bits =<RX_EMD_LENGTH_THRESH_0 and the frame reception is over being not interrupted by any detected error or external rf-off event but no any stop conditions, configured via EOF_COND_SCALE register, were detected  -the scenario is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_CRC_ERR_IS_EMD_0_POS                                                     (6UL)
#define CLIF_RX_EMD_0_CONFIG_RX_CRC_ERR_IS_EMD_0_MASK                                                    (0x00000040UL)  /**< 6-If asserted and the number of received bits =<RX_EMD_LENGTH_THRESH_0 - the detection of the CRC error is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_NOT_FULL_BYTE_IS_EMD_0_POS                                               (5UL)
#define CLIF_RX_EMD_0_CONFIG_RX_NOT_FULL_BYTE_IS_EMD_0_MASK                                              (0x00000020UL)  /**< 5-If asserted and the number of received bits =<RX_EMD_LENGTH_THRESH_0 - the reception of last byte with size < 8 data bits is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_STOPBIT_IS_EMD_0_POS                                             (4UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_STOPBIT_IS_EMD_0_MASK                                            (0x00000010UL)  /**< 4-If asserted, the number of received bits =<RX_EMD_LENGTH_THRESH_0 and the stop bit is a part of the frame character, the reception of the last character with 8 data bits but without stop bit is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_PARITY_IS_EMD_0_POS                                              (3UL)
#define CLIF_RX_EMD_0_CONFIG_RX_MISSING_PARITY_IS_EMD_0_MASK                                             (0x00000008UL)  /**< 3-If asserted, the number of received bits =<RX_EMD_LENGTH_THRESH_0 and the parity bit is a part of the frame character, the reception of the last character with 8 data bits but without parity bit is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_PARBIT_ERR_IS_EMD_0_POS                                                  (2UL)
#define CLIF_RX_EMD_0_CONFIG_RX_PARBIT_ERR_IS_EMD_0_MASK                                                 (0x00000004UL)  /**< 2-If asserted and the number of received bits =<RX_EMD_LENGTH_THRESH_0 - the detected parity error is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_STOPBIT_ERR_IS_EMD_0_POS                                                 (1UL)
#define CLIF_RX_EMD_0_CONFIG_RX_STOPBIT_ERR_IS_EMD_0_MASK                                                (0x00000002UL)  /**< 1-If asserted and the number of received bits =<RX_EMD_LENGTH_THRESH_0 - the detected stop bit error (0 level instead of 1 on the stop bit position) is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG_RX_COLL_IS_EMD_0_POS                                                        (0UL)
#define CLIF_RX_EMD_0_CONFIG_RX_COLL_IS_EMD_0_MASK                                                       (0x00000001UL)  /**< 0-If asserted and the number of received bits=<RX_EMD_LENGTH_THRESH_0 - the collision is considered as EMD symptom.*/
#define CLIF_RX_EMD_0_CONFIG__RESET_VALUE                                                                (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_filt128b
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_FILT128B                                                                           0x49
#define CLIF_SIGPRO_CM_FILT128B_R                                                                           0x49
#define CLIF_SIGPRO_CM_FILT128B_W                                                                           0x49
#define CLIF_SIGPRO_CM_FILT128B_RESERVED_POS                                                             (31UL)
#define CLIF_SIGPRO_CM_FILT128B_RESERVED_MASK                                                            (0x80000000UL)  /**< 31-RESERVED*/
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_INIT_GAIN_128B_POS                                               (29UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_INIT_GAIN_128B_MASK                                              (0x60000000UL)  /**< 30-*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_DLY_128B_POS                                                     (25UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_DLY_128B_MASK                                                    (0x1E000000UL)  /**< 25-number of clock cycles used for consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_DLY_128B_ENABLE_POS                                              (24UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_DLY_128B_ENABLE_MASK                                             (0x01000000UL)  /**< 24-enables consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_0_8_POS                                                (21UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_0_8_MASK                                               (0x00E00000UL)  /**< 21-Filter coefficient for the 128 tap length TypeB filter*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_1_7_POS                                                (18UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_1_7_MASK                                               (0x001C0000UL)  /**< 18-Filter coefficient for the 128 tap length TypeB filter*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_2_6_POS                                                (15UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_2_6_MASK                                               (0x00038000UL)  /**< 15-Filter coefficient for the 128 tap length TypeB filter*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_3_5_POS                                                (12UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_3_5_MASK                                               (0x00007000UL)  /**< 12-Filter coefficient for the 128 tap length TypeB filter*/
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_4_POS                                                  (10UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_FILT_COEF_128B_4_MASK                                                 (0x00000C00UL)  /**< 10-Filter coefficient for the 128 tap length TypeB filter*/
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_DYN_FACTOR_128B_POS                                              (7UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_DYN_FACTOR_128B_MASK                                             (0x00000380UL)  /**< 7-initial value of the typeB 128-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_INIT_128B_POS                                                    (0UL)
#define CLIF_SIGPRO_CM_FILT128B_CM_THLD_INIT_128B_MASK                                                   (0x0000007FUL)  /**< 0-initial value of the typeB 128-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT128B__RESET_VALUE                                                             (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_filt128a
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_FILT128A                                                                           0x4A
#define CLIF_SIGPRO_CM_FILT128A_R                                                                           0x4A
#define CLIF_SIGPRO_CM_FILT128A_W                                                                           0x4A
#define CLIF_SIGPRO_CM_FILT128A_RESERVED_POS                                                             (31UL)
#define CLIF_SIGPRO_CM_FILT128A_RESERVED_MASK                                                            (0x80000000UL)  /**< 31-RESERVED*/
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_INIT_GAIN_128A_POS                                               (29UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_INIT_GAIN_128A_MASK                                              (0x60000000UL)  /**< 29-*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_DLY_128A_POS                                                     (25UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_DLY_128A_MASK                                                    (0x1E000000UL)  /**< 25-number of clock cycles used for consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_DLY_128A_ENABLE_POS                                              (24UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_DLY_128A_ENABLE_MASK                                             (0x01000000UL)  /**< 24-enables consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_0_8_POS                                                (21UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_0_8_MASK                                               (0x00E00000UL)  /**< 21-Filter coefficient for the 128 tap length TypeA filter*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_1_7_POS                                                (18UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_1_7_MASK                                               (0x001C0000UL)  /**< 18-Filter coefficient for the 128 tap length TypeA filter*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_2_6_POS                                                (15UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_2_6_MASK                                               (0x00038000UL)  /**< 15-Filter coefficient for the 128 tap length TypeA filter*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_3_5_POS                                                (12UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_3_5_MASK                                               (0x00007000UL)  /**< 12-Filter coefficient for the 128 tap length TypeA filter*/
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_4_POS                                                  (10UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_FILT_COEF_128A_4_MASK                                                 (0x00000C00UL)  /**< 10-Filter coefficient for the 128 tap length TypeA filter*/
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_DYN_FACTOR_128A_POS                                              (7UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_DYN_FACTOR_128A_MASK                                             (0x00000380UL)  /**< 7-initial value of the typeA 128-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_INIT_128A_POS                                                    (0UL)
#define CLIF_SIGPRO_CM_FILT128A_CM_THLD_INIT_128A_MASK                                                   (0x0000007FUL)  /**< 0-initial value of the typeA 128-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT128A__RESET_VALUE                                                             (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_filt64
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_FILT64                                                                             0x4B
#define CLIF_SIGPRO_CM_FILT64_R                                                                             0x4B
#define CLIF_SIGPRO_CM_FILT64_W                                                                             0x4B
#define CLIF_SIGPRO_CM_FILT64_RESERVED_POS                                                               (31UL)
#define CLIF_SIGPRO_CM_FILT64_RESERVED_MASK                                                              (0x80000000UL)  /**< 31-RESERVED*/
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_INIT_GAIN_64_POS                                                   (29UL)
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_INIT_GAIN_64_MASK                                                  (0x60000000UL)  /**< 29-*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_DLY_64_POS                                                         (25UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_DLY_64_MASK                                                        (0x1E000000UL)  /**< 25-number of clock cycles used for consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_DLY_64_ENABLE_POS                                                  (24UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_DLY_64_ENABLE_MASK                                                 (0x01000000UL)  /**< 24-enables consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_0_8_POS                                                    (21UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_0_8_MASK                                                   (0x00E00000UL)  /**< 21-Filter coefficient for the 64 tap length filter*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_1_7_POS                                                    (18UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_1_7_MASK                                                   (0x001C0000UL)  /**< 18-Filter coefficient for the 64 tap length filter*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_2_6_POS                                                    (15UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_2_6_MASK                                                   (0x00038000UL)  /**< 15-Filter coefficient for the 64 tap length filter*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_3_5_POS                                                    (12UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_3_5_MASK                                                   (0x00007000UL)  /**< 12-Filter coefficient for the 64 tap length filter*/
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_4_POS                                                      (10UL)
#define CLIF_SIGPRO_CM_FILT64_CM_FILT_COEF_64_4_MASK                                                     (0x00000C00UL)  /**< 10-Filter coefficient for the 64 tap length filter*/
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_DYN_FACTOR_64_POS                                                  (7UL)
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_DYN_FACTOR_64_MASK                                                 (0x00000380UL)  /**< 7-initial value of the 64-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_INIT_64_POS                                                        (0UL)
#define CLIF_SIGPRO_CM_FILT64_CM_THLD_INIT_64_MASK                                                       (0x0000007FUL)  /**< 0-initial value of the 64-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT64__RESET_VALUE                                                               (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_filt16_32
* <b>Reset value:</b> 0x00040000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_FILT16_32                                                                          0x4C
#define CLIF_SIGPRO_CM_FILT16_32_R                                                                          0x4C
#define CLIF_SIGPRO_CM_FILT16_32_W                                                                          0x4C
#define CLIF_SIGPRO_CM_FILT16_32_RESERVED_POS                                                            (31UL)
#define CLIF_SIGPRO_CM_FILT16_32_RESERVED_MASK                                                           (0x80000000UL)  /**< 31-RESERVED*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_INIT_GAIN_16_32_POS                                             (29UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_INIT_GAIN_16_32_MASK                                            (0x60000000UL)  /**< 29-*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_DLY_16_32_POS                                                   (25UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_DLY_16_32_MASK                                                  (0x1E000000UL)  /**< 25-number of clock cycles used for consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_DLY_16_32_ENABLE_POS                                            (24UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_DLY_16_32_ENABLE_MASK                                           (0x01000000UL)  /**< 24-enables consecutive edges decision logic*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_0_8_POS                                              (21UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_0_8_MASK                                             (0x00E00000UL)  /**< 21-Filter coefficient for the 16/32 tap length filter*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_1_7_POS                                              (18UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_1_7_MASK                                             (0x001C0000UL)  /**< 18-Filter coefficient for the  16/32 tap length filter*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_2_6_POS                                              (15UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_2_6_MASK                                             (0x00038000UL)  /**< 15-Filter coefficient for the  16/32 tap length filter*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_3_5_POS                                              (12UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_3_5_MASK                                             (0x00007000UL)  /**< 12-Filter coefficient for the  16/32 tap length filter*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_4_POS                                                (10UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_FILT_COEF_16_32_4_MASK                                               (0x00000C00UL)  /**< 10-Filter coefficient for the  16/32 tap length filter*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_DYN_FACTOR_16_32_POS                                            (7UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_DYN_FACTOR_16_32_MASK                                           (0x00000380UL)  /**< 7-initial value of the  16/32-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_INIT_16_32_POS                                                  (0UL)
#define CLIF_SIGPRO_CM_FILT16_32_CM_THLD_INIT_16_32_MASK                                                 (0x0000007FUL)  /**< 0-initial value of the  16/32-filter threshold value*/
#define CLIF_SIGPRO_CM_FILT16_32__RESET_VALUE                                                            (0x00040000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_config2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_CONFIG2                                                                            0x4D
#define CLIF_SIGPRO_CM_CONFIG2_R                                                                            0x4D
#define CLIF_SIGPRO_CM_CONFIG2_W                                                                            0x4D
#define CLIF_SIGPRO_CM_CONFIG2_RESERVED_POS                                                              (24UL)
#define CLIF_SIGPRO_CM_CONFIG2_RESERVED_MASK                                                             (0xFF000000UL)  /**< 24-Reserved */
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_HLF_LGTH_POS                                          (20UL)
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_HLF_LGTH_MASK                                         (0x00F00000UL)  /**< 20-filter threshold factor half window length*/
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_SLOPE_POS                                             (16UL)
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_SLOPE_MASK                                            (0x000F0000UL)  /**< 16-filter threshold factor update rate*/
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_MIN_POS                                               (10UL)
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_MIN_MASK                                              (0x0000FC00UL)  /**< 10-filter threshold factor min value*/
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_MAX_POS                                               (4UL)
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_ADPT_MAX_MASK                                              (0x000003F0UL)  /**< 4-filter threshold factor max value*/
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_DLY_POS                                                    (0UL)
#define CLIF_SIGPRO_CM_CONFIG2_CM_TYPEF2_BITG_DLY_MASK                                                   (0x0000000FUL)  /**< 0-number of clock cycle required to align the bitgrid to the filter*/
#define CLIF_SIGPRO_CM_CONFIG2__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_cm_config3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_CM_CONFIG3                                                                            0x4E
#define CLIF_SIGPRO_CM_CONFIG3_R                                                                            0x4E
#define CLIF_SIGPRO_CM_CONFIG3_W                                                                            0x4E
#define CLIF_SIGPRO_CM_CONFIG3_RESERVED_POS                                                              (24UL)
#define CLIF_SIGPRO_CM_CONFIG3_RESERVED_MASK                                                             (0xFF000000UL)  /**< 24-Reserved */
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_HLF_LGTH_POS                                          (20UL)
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_HLF_LGTH_MASK                                         (0x00F00000UL)  /**< 20-filter threshold factor half window length*/
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_SLOPE_POS                                             (16UL)
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_SLOPE_MASK                                            (0x000F0000UL)  /**< 16-filter threshold factor update rate*/
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_MIN_POS                                               (10UL)
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_MIN_MASK                                              (0x0000FC00UL)  /**< 10-filter threshold factor min value*/
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_MAX_POS                                               (4UL)
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_ADPT_MAX_MASK                                              (0x000003F0UL)  /**< 4-filter threshold factor max value*/
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_DLY_POS                                                    (0UL)
#define CLIF_SIGPRO_CM_CONFIG3_CM_TYPEF4_BITG_DLY_MASK                                                   (0x0000000FUL)  /**< 0-number of clock cycle required to align the bitgrid to the filter*/
#define CLIF_SIGPRO_CM_CONFIG3__RESET_VALUE                                                              (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_sigpro_pre_config
* <b>Reset value:</b> 0x0000027C
* <b>Access:</b> rw
* @{
*/
#define CLIF_SIGPRO_PRE_CONFIG                                                                            0x4F
#define CLIF_SIGPRO_PRE_CONFIG_R                                                                            0x4F
#define CLIF_SIGPRO_PRE_CONFIG_W                                                                            0x4F
#define CLIF_SIGPRO_PRE_CONFIG_RESERVED_POS                                                              (10UL)
#define CLIF_SIGPRO_PRE_CONFIG_RESERVED_MASK                                                             (0xFFFFFC00UL)  /**< 10-Reserved*/
#define CLIF_SIGPRO_PRE_CONFIG_PRE_ENABLE_STEP_RANGE_POS                                                 (9UL)
#define CLIF_SIGPRO_PRE_CONFIG_PRE_ENABLE_STEP_RANGE_MASK                                                (0x00000200UL)  /**< 9-Defines the input selection for the sync filter.*/
#define CLIF_SIGPRO_PRE_CONFIG_PRE_PHASE_FREEZE_POS                                                      (8UL)
#define CLIF_SIGPRO_PRE_CONFIG_PRE_PHASE_FREEZE_MASK                                                     (0x00000100UL)  /**< 8-Freezes the current value of the phase rotator*/
#define CLIF_SIGPRO_PRE_CONFIG_PRE_COMB_SETTING_POS                                                      (7UL)
#define CLIF_SIGPRO_PRE_CONFIG_PRE_COMB_SETTING_MASK                                                     (0x00000080UL)  /**< 7-Selects the gain combiner mode*/
#define CLIF_SIGPRO_PRE_CONFIG_PRE_WINDOW_STOP_POS                                                       (3UL)
#define CLIF_SIGPRO_PRE_CONFIG_PRE_WINDOW_STOP_MASK                                                      (0x00000078UL)  /**< 3-gain cancelation window end count*/
#define CLIF_SIGPRO_PRE_CONFIG_PRE_WINDOW_START_POS                                                      (0UL)
#define CLIF_SIGPRO_PRE_CONFIG_PRE_WINDOW_START_MASK                                                     (0x00000007UL)  /**< 0-gain cancelation window start count*/
#define CLIF_SIGPRO_PRE_CONFIG__RESET_VALUE                                                              (0x0000027CUL)  /**< value after reset*/
/**
* @}
*/



/**
* @name lpcd_calibrate_ctrl
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define LPCD_CALIBRATE_CTRL                                                                               0x50
#define LPCD_CALIBRATE_CTRL_FREEZE_VALUES_POS                                                            (30UL)
#define LPCD_CALIBRATE_CTRL_FREEZE_VALUES_MASK                                                           (0x40000000UL)  /**< 30-Freeze the RSSI Target and hysteresis values into UserArea*/
#define LPCD_CALIBRATE_CTRL_RFU_POS                                                                      (24UL)
#define LPCD_CALIBRATE_CTRL_RFU_MASK                                                                     (0x3F000000UL)  /**< 24-Reserved*/
#define LPCD_CALIBRATE_CTRL_RSSI_HYSTERESIS_POS                                                          (16UL)
#define LPCD_CALIBRATE_CTRL_RSSI_HYSTERESIS_MASK                                                         (0x00FF0000UL)  /**< 16-[REG] Value to be set in CLIF_DGRM_RSSI_REG_DGRM_RSSI_HYST used for calibration*/
#define LPCD_CALIBRATE_CTRL_RSSI_TARGET_POS                                                              (0UL)
#define LPCD_CALIBRATE_CTRL_RSSI_TARGET_MASK                                                             (0x0000FFFFUL)  /**< 0-[REG] Value to be set in CLIF_DGRM_RSSI_REG_DGRM_RSSI_TARGET used for calibration*/
/**
* @}
*/


/**
* @name lpcd_read_vals
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define IQ_CHANNEL_VALS                                                                                   0x51
#define IQ_CHANNEL_VALS_Q_CHANNEL_VAL_POS                                                                (16UL)
#define IQ_CHANNEL_VALS_Q_CHANNEL_VAL_MASK                                                               (0xFFFF0000UL)  /**< 16-Q Channel value*/
#define IQ_CHANNEL_VALS_I_CHANNEL_VAL_POS                                                                (0UL)
#define IQ_CHANNEL_VALS_I_CHANNEL_VAL_MASK                                                               (0x0000FFFFUL)  /**< 0-I Channel value*/
/**
* @}
*/

/**
* @name general_status
* <b>Reset value:</b>
* <b>Access:</b> r
* @{
*/
#define GENERAL_STATUS                                                                                    0x53
#define GENERAL_STATUS_LPCD_CALIBRATION_STATUS_POS                                                       (31UL)
#define GENERAL_STATUS_LPCD_CALIBRATION_STATUS_MASK                                                      (0x80000000UL)  /**< 31-LPD Calibration Status 0 - Calibration Not Done, 1- Calibration Done*/
#define GENERAL_STATUS_TXNOV_CALIBRATION_STATUS_POS                                                      (0UL)
#define GENERAL_STATUS_TXNOV_CALIBRATION_STATUS_MASK                                                     (0x00000001UL)  /**< 0-TXNOV Calibration Status 0 - Calibration Not Done, 1- Calibration Done*/
/**
* @}
*/


/**
* @name txldo_vddpa_config
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define TXLDO_VDDPA_CONFIG                                                                                0x54
#define TXLDO_VDDPA_CONFIG_RESERVED_POS                                                                  (8UL)
#define TXLDO_VDDPA_CONFIG_RESERVED_MASK                                                                 (0xFFFFFF00UL)  /**< 8-Reserved*/
#define TXLDO_VDDPA_CONFIG_VDDPA_CONFIG_POS                                                              (0UL)
#define TXLDO_VDDPA_CONFIG_VDDPA_CONFIG_MASK                                                             (0x000000FFUL)  /**< 0-Configures the VDDPA to the value set*/
/**
* @}
*/

/**
* @name txldo_vout_curr
* <b>Reset value:</b>
* <b>Access:</b> r-
* @{
*/
#define TXLDO_VOUT_CURR                                                                                   0x56
#define TXLDO_VOUT_CURR_TXLDO_CURRENT_POS                                                                (8UL)
#define TXLDO_VOUT_CURR_TXLDO_CURRENT_MASK                                                               (0x00FFFF00UL)  /**< 8-Incdicates the TXLDO Current*/
#define TXLDO_VOUT_CURR_VDDPA_VOUT_POS                                                                   (0UL)
#define TXLDO_VOUT_CURR_VDDPA_VOUT_MASK                                                                  (0x000000FFUL)  /**< 0-Indicates the current VDDPA Voltage configured*/
/**
* @}
*/

/**
* @name clif_rxm_freq
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_RXM_FREQ                                                                                     0x59
#define CLIF_RXM_FREQ_R                                                                                     0x59
#define CLIF_RXM_FREQ_RXM_FREQ_REG_VALID_POS                                                             (31UL)
#define CLIF_RXM_FREQ_RXM_FREQ_REG_VALID_MASK                                                            (0x80000000UL)  /**< 31-CLIF_RXM_FREQ_REG fields are valid*/
#define CLIF_RXM_FREQ_RESERVED_POS                                                                       (25UL)
#define CLIF_RXM_FREQ_RESERVED_MASK                                                                      (0x7E000000UL)  /**< 25-Reserved*/
#define CLIF_RXM_FREQ_RXM_FREQ_POS                                                                       (16UL)
#define CLIF_RXM_FREQ_RXM_FREQ_MASK                                                                      (0x01FF0000UL)  /**< 16-frequence difference between the last two consecutive measures at 1.7 MHz (multiple of 13.56MHz/4096). Signed. 2-Complement coded.*/
#define CLIF_RXM_FREQ_RESERVED1_POS                                                                      (9UL)
#define CLIF_RXM_FREQ_RESERVED1_MASK                                                                     (0x0000FE00UL)  /**< 9-Reserved*/
#define CLIF_RXM_FREQ_RXM_PHASE_POS                                                                      (0UL)
#define CLIF_RXM_FREQ_RXM_PHASE_MASK                                                                     (0x000001FFUL)  /**< 0-phase value from CORDIC*/
#define CLIF_RXM_FREQ__RESET_VALUE                                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rxm_rssi
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_RXM_RSSI                                                                                     0x5A
#define CLIF_RXM_RSSI_R                                                                                     0x5A
#define CLIF_RXM_RSSI_RESERVED_POS                                                                       (23UL)
#define CLIF_RXM_RSSI_RESERVED_MASK                                                                      (0xFF800000UL)  /**< 23-Reserved*/
#define CLIF_RXM_RSSI_RXM_RSSI_FROZEN_POS                                                                (22UL)
#define CLIF_RXM_RSSI_RXM_RSSI_FROZEN_MASK                                                               (0x00400000UL)  /**< 22-The RSSI value is not currently updated*/
#define CLIF_RXM_RSSI_RXM_FRQ_OK_POS                                                                     (21UL)
#define CLIF_RXM_RSSI_RXM_FRQ_OK_MASK                                                                    (0x00200000UL)  /**< 21-The carrier frequency detected is OK.*/
#define CLIF_RXM_RSSI_RXM_RSSI_REG_VALID_POS                                                             (20UL)
#define CLIF_RXM_RSSI_RXM_RSSI_REG_VALID_MASK                                                            (0x00100000UL)  /**< 20-CLIF_RXM_RSSI_REG fields are valid*/
#define CLIF_RXM_RSSI_RXM_HFATT_POS                                                                      (14UL)
#define CLIF_RXM_RSSI_RXM_HFATT_MASK                                                                     (0x000FC000UL)  /**< 14-HFAtt latched with RSSI*/
#define CLIF_RXM_RSSI_RXM_RSSI_POS                                                                       (0UL)
#define CLIF_RXM_RSSI_RXM_RSSI_MASK                                                                      (0x00003FFFUL)  /**< 0-RSSI value*/
#define CLIF_RXM_RSSI__RESET_VALUE                                                                       (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name interpolated_rssi_reg
* <b>Reset value:</b>
* <b>Access:</b> r-
* @{
*/
#define INTERPOLATED_RSSI_REG                                                                             0x5C
#define INTERPOLATED_RSSI_REG_INTERPOLATED_RSSI_POS                                                      (0UL)
#define INTERPOLATED_RSSI_REG_INTERPOLATED_RSSI_MASK                                                     (0xFFFFFFFFUL)  /**< 0-Calculated Interpolated RSSI*/
/**
* @}
*/

/**
* @name tx_nov_calibrate_and_store_val_reg
* <b>Reset value:</b>
* <b>Access:</b> rw
* @{
*/
#define TX_NOV_CALIBRATE_AND_STORE_VAL_REG                                                                0x5D
#define TX_NOV_CALIBRATE_AND_STORE_VAL_REG_RFU_POS                                                       (2UL)
#define TX_NOV_CALIBRATE_AND_STORE_VAL_REG_RFU_MASK                                                      (0xFFFFFFFCUL)  /**< 2-Reserved*/
#define TX_NOV_CALIBRATE_AND_STORE_VAL_REG_TX_NOV_CALIBRATE_STORE_POS                                    (0UL)
#define TX_NOV_CALIBRATE_AND_STORE_VAL_REG_TX_NOV_CALIBRATE_STORE_MASK                                   (0x00000003UL)  /**< 0-Perform TX_NOV Calibration and store in User Area*/
/**
* @}
*/

/**
* @name clif_timer0_output
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER0_OUTPUT                                                                                0x5F
#define CLIF_TIMER0_OUTPUT_R                                                                                0x5F
#define CLIF_TIMER0_OUTPUT_RESERVED_POS                                                                  (25UL)
#define CLIF_TIMER0_OUTPUT_RESERVED_MASK                                                                 (0xFE000000UL)  /**< 25-Reserved */
#define CLIF_TIMER0_OUTPUT_T0_RUNNING_POS                                                                (24UL)
#define CLIF_TIMER0_OUTPUT_T0_RUNNING_MASK                                                               (0x01000000UL)  /**< 24-Indicates that timer T0 is running (busy) */
#define CLIF_TIMER0_OUTPUT_T0_VALUE_POS                                                                  (0UL)
#define CLIF_TIMER0_OUTPUT_T0_VALUE_MASK                                                                 (0x000FFFFFUL)  /**< 0-Value of 20bit counter in timer T0 */
#define CLIF_TIMER0_OUTPUT__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer1_output
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER1_OUTPUT                                                                                0x60
#define CLIF_TIMER1_OUTPUT_R                                                                                0x60
#define CLIF_TIMER1_OUTPUT_RESERVED_POS                                                                  (25UL)
#define CLIF_TIMER1_OUTPUT_RESERVED_MASK                                                                 (0xFE000000UL)  /**< 25-Reserved */
#define CLIF_TIMER1_OUTPUT_T1_RUNNING_POS                                                                (24UL)
#define CLIF_TIMER1_OUTPUT_T1_RUNNING_MASK                                                               (0x01000000UL)  /**< 24-Indicates that timer T1 is running (busy) */
#define CLIF_TIMER1_OUTPUT_T1_VALUE_POS                                                                  (0UL)
#define CLIF_TIMER1_OUTPUT_T1_VALUE_MASK                                                                 (0x000FFFFFUL)  /**< 0-Value of 20bit counter in timer T1 */
#define CLIF_TIMER1_OUTPUT__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer2_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER2_CONFIG                                                                                0x61
#define CLIF_TIMER2_CONFIG_R                                                                                0x61
#define CLIF_TIMER2_CONFIG_W                                                                                0x61
#define CLIF_TIMER2_CONFIG_RESERVED_POS                                                                  (31UL)
#define CLIF_TIMER2_CONFIG_RESERVED_MASK                                                                 (0x80000000UL)  /**< 31-Reserved */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RX_STARTED_POS                                                     (30UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RX_STARTED_MASK                                                    (0x40000000UL)  /**< 30-T2_STOP_EVENT: If set. the timer T2 is stopped when a data reception begins (1st bit is received). */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_TX_STARTED_POS                                                     (29UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_TX_STARTED_MASK                                                    (0x20000000UL)  /**< 29-T2_STOP_EVENT: If set. the timer T2 is stopped when a data transmission begins. */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_ON_EXT_POS                                                      (28UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_ON_EXT_MASK                                                     (0x10000000UL)  /**< 28-T2_STOP_EVENT: If set. the timer T2 is stopped when the external RF field is detected. */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_OFF_EXT_POS                                                     (27UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_OFF_EXT_MASK                                                    (0x08000000UL)  /**< 27-T2_STOP_EVENT: If set. the timer T2 is stopped when the external RF field vanishes. */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_ON_INT_POS                                                      (26UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_ON_INT_MASK                                                     (0x04000000UL)  /**< 26-T2_STOP_EVENT: If set. the timer T2 is stopped when the internal RF field is turned on. */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_OFF_INT_POS                                                     (25UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RF_OFF_INT_MASK                                                    (0x02000000UL)  /**< 25-T2_STOP_EVENT: If set. the timer T2 is stopped when the internal RF field is turned off. */
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RX_ENDED_POS                                                       (24UL)
#define CLIF_TIMER2_CONFIG_T2_STOP_ON_RX_ENDED_MASK                                                      (0x01000000UL)  /**< 24-T2_STOP_EVENT: If set the timer T2 is stopped when an activity on RX is detected.*/
#define CLIF_TIMER2_CONFIG_RESERVED1_POS                                                                  (18UL)
#define CLIF_TIMER2_CONFIG_RESERVED1_MASK                                                                 (0x00FC0000UL)  /**< 18-Reserved */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RX_STARTED_POS                                                    (17UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RX_STARTED_MASK                                                   (0x00020000UL)  /**< 17-T2_START_EVENT: If set. the timer T2 is started when a data reception begins (1st bit is received). */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RX_ENDED_POS                                                      (16UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RX_ENDED_MASK                                                     (0x00010000UL)  /**< 16-T2_START_EVENT: If set. the timer T2 is started when a data reception ends. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_STARTED_POS                                                    (15UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_STARTED_MASK                                                   (0x00008000UL)  /**< 15-T2_START_EVENT: If set. the timer T2 is started when a data transmission begins. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_ENDED_POS                                                      (14UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_ENDED_MASK                                                     (0x00004000UL)  /**< 14-T2_START_EVENT: If set. the timer T2 is started when a data transmission ends. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_ON_EXT_POS                                                     (13UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_ON_EXT_MASK                                                    (0x00002000UL)  /**< 13-T2_START_EVENT: If set. the timer T2 is started when the external RF field is detected. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_OFF_EXT_POS                                                    (12UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_OFF_EXT_MASK                                                   (0x00001000UL)  /**< 12-T2_START_EVENT: If set. the timer T2 is started when the external RF field is not detected any more. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_ON_INT_POS                                                     (11UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_ON_INT_MASK                                                    (0x00000800UL)  /**< 11-T2_START_EVENT: If set. the timer T2 is started when an internal RF field is turned on. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_OFF_INT_POS                                                    (10UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_RF_OFF_INT_MASK                                                   (0x00000400UL)  /**< 10-T2_START_EVENT: If set. the timer T2 is started when an internal RF field is turned off. */
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_FRAMESTEP_POS                                                  (9UL)
#define CLIF_TIMER2_CONFIG_T2_START_ON_TX_FRAMESTEP_MASK                                                 (0x00000200UL)  /**< 9-T2_START_EVENT: If set the timer T2 is started when an activity on Framestep is detected.*/
#define CLIF_TIMER2_CONFIG_T2_START_NOW_POS                                                              (8UL)
#define CLIF_TIMER2_CONFIG_T2_START_NOW_MASK                                                             (0x00000100UL)  /**< 8-T2_START_EVENT: If set. the timer T2 is started immediatly. */
#define CLIF_TIMER2_CONFIG_RESERVED2_POS                                                                  (7UL)
#define CLIF_TIMER2_CONFIG_RESERVED2_MASK                                                                 (0x00000080UL)  /**< 7-Reserved           */
#define CLIF_TIMER2_CONFIG_T2_ONE_SHOT_MODE_POS                                                          (6UL)
#define CLIF_TIMER2_CONFIG_T2_ONE_SHOT_MODE_MASK                                                         (0x00000040UL)  /**< 6-When set to 1 the counter value does not reload again until the counter value has reached zero*/
#define CLIF_TIMER2_CONFIG_T2_PRESCALE_SEL_POS                                                           (3UL)
#define CLIF_TIMER2_CONFIG_T2_PRESCALE_SEL_MASK                                                          (0x00000038UL)  /**< 3-Controls frequency/period of the timer T2 when the prescaler is activated by T2_MODE_SEL. 000b* 6.78MHz counter 001b 3.39MHz counter 010b 1.70MHz counter 011b 848kHz counter 100b 424kHz counter 101b 212kHz counter 110b 106kHz counter 111b 53kHz counter */
#define CLIF_TIMER2_CONFIG_T2_MODE_SEL_POS                                                               (2UL)
#define CLIF_TIMER2_CONFIG_T2_MODE_SEL_MASK                                                              (0x00000004UL)  /**< 2-If set. the timer T2 is started the prescaler for the timer T2 is enabled. 0* Prescaler is disabled: the timer frequency matches CLIF clock frequency (13.56MHz). 1 Prescaler is enabled: the timer operates on the prescaler signal frequency (chosen by T2_PRESCALE_SEL). */
#define CLIF_TIMER2_CONFIG_T2_RELOAD_ENABLE_POS                                                          (1UL)
#define CLIF_TIMER2_CONFIG_T2_RELOAD_ENABLE_MASK                                                         (0x00000002UL)  /**< 1-If set to 0.the timer T2 will stop on expiration. 0* After expiration the timer T2 will stop counting. i.e.. remain zero. reset value. 1 After expiration the timer T2 will reload its preset value and continue counting down. */
#define CLIF_TIMER2_CONFIG_T2_ENABLE_POS                                                                 (0UL)
#define CLIF_TIMER2_CONFIG_T2_ENABLE_MASK                                                                (0x00000001UL)  /**< 0-Enables the timer T2 */
#define CLIF_TIMER2_CONFIG__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer2_reload
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER2_RELOAD                                                                                0x62
#define CLIF_TIMER2_RELOAD_R                                                                                0x62
#define CLIF_TIMER2_RELOAD_W                                                                                0x62
#define CLIF_TIMER2_RELOAD_RESERVED_POS                                                                  (20UL)
#define CLIF_TIMER2_RELOAD_RESERVED_MASK                                                                 (0xFFF00000UL)  /**< 20-Reserved */
#define CLIF_TIMER2_RELOAD_T2_RELOAD_VALUE_POS                                                           (0UL)
#define CLIF_TIMER2_RELOAD_T2_RELOAD_VALUE_MASK                                                          (0x000FFFFFUL)  /**< 0-Reload value of the timer T2. */
#define CLIF_TIMER2_RELOAD__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_timer2_output
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TIMER2_OUTPUT                                                                                0x63
#define CLIF_TIMER2_OUTPUT_R                                                                                0x63
#define CLIF_TIMER2_OUTPUT_RESERVED_POS                                                                  (25UL)
#define CLIF_TIMER2_OUTPUT_RESERVED_MASK                                                                 (0xFE000000UL)  /**< 25-Reserved */
#define CLIF_TIMER2_OUTPUT_T2_RUNNING_POS                                                                (24UL)
#define CLIF_TIMER2_OUTPUT_T2_RUNNING_MASK                                                               (0x01000000UL)  /**< 24-Indicates that timer T2 is running (busy) */
#define CLIF_TIMER2_OUTPUT_T2_VALUE_POS                                                                  (0UL)
#define CLIF_TIMER2_OUTPUT_T2_VALUE_MASK                                                                 (0x000FFFFFUL)  /**< 0-Value of 20bit counter in timer T2*/
#define CLIF_TIMER2_OUTPUT__RESET_VALUE                                                                  (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_bm_tx_buffer
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_BM_TX_BUFFER                                                                                 0x66
#define CLIF_BM_TX_BUFFER_R                                                                                 0x66
#define CLIF_BM_TX_BUFFER_W                                                                                 0x66
#define CLIF_BM_TX_BUFFER_RESERVED_POS                                                                   (28UL)
#define CLIF_BM_TX_BUFFER_RESERVED_MASK                                                                  (0xF0000000UL)  /**< 28-Reserved */
#define CLIF_BM_TX_BUFFER_TX_HEADER_BYTE_OFFSET_POS                                                      (26UL)
#define CLIF_BM_TX_BUFFER_TX_HEADER_BYTE_OFFSET_MASK                                                     (0x0C000000UL)  /**< 26-Defines the number of bytes to be skipped of the 1st data word transmitted */
#define CLIF_BM_TX_BUFFER_TX_BUFFER_LENGTH_POS                                                           (16UL)
#define CLIF_BM_TX_BUFFER_TX_BUFFER_LENGTH_MASK                                                          (0x03FF0000UL)  /**< 16-Defines the number of bytes to be skipped of the 1st data word transmitted */
#define CLIF_BM_TX_BUFFER_RESERVED1_POS                                                                   (14UL)
#define CLIF_BM_TX_BUFFER_RESERVED1_MASK                                                                  (0x0000C000UL)  /**< 14-Reserved */
#define CLIF_BM_TX_BUFFER_TX_BUFFER_START_ADDRESS_POS                                                    (0UL)
#define CLIF_BM_TX_BUFFER_TX_BUFFER_START_ADDRESS_MASK                                                   (0x00003FFFUL)  /**< 0-Defines the relative buffer (word) address of the Tx buffer. Note: Changing the buffer address while the transmitter is active will trigger a BMA error.*/
#define CLIF_BM_TX_BUFFER__RESET_VALUE                                                                   (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_bm_rx_waterlevel
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_BM_RX_WATERLEVEL                                                                             0x67
#define CLIF_BM_RX_WATERLEVEL_R                                                                             0x67
#define CLIF_BM_RX_WATERLEVEL_W                                                                             0x67
#define CLIF_BM_RX_WATERLEVEL_RESERVED_POS                                                               (11UL)
#define CLIF_BM_RX_WATERLEVEL_RESERVED_MASK                                                              (0xFFFFF800UL)  /**< 11-Reserved */
#define CLIF_BM_RX_WATERLEVEL_RX_WATERLEVEL_POS                                                          (0UL)
#define CLIF_BM_RX_WATERLEVEL_RX_WATERLEVEL_MASK                                                         (0x000007FFUL)  /**< 0-Defines a warning level to indicate that RX_WATERLEVEL number of words were already received in the actual frame. When this level is reached the corresponding IRQ is set. Note: 0 disables the waterlevel*/
#define CLIF_BM_RX_WATERLEVEL__RESET_VALUE                                                               (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_bm_rx_buffer
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_BM_RX_BUFFER                                                                                 0x68
#define CLIF_BM_RX_BUFFER_R                                                                                 0x68
#define CLIF_BM_RX_BUFFER_W                                                                                 0x68
#define CLIF_BM_RX_BUFFER_RESERVED_POS                                                                   (26UL)
#define CLIF_BM_RX_BUFFER_RESERVED_MASK                                                                  (0xFC000000UL)  /**< 26-Reserved */
#define CLIF_BM_RX_BUFFER_RX_BUFFER_LENGTH_POS                                                           (16UL)
#define CLIF_BM_RX_BUFFER_RX_BUFFER_LENGTH_MASK                                                          (0x03FF0000UL)  /**< 16-Defines the length of the Rx buffer (in data words)*/
#define CLIF_BM_RX_BUFFER_RESERVED1_POS                                                                   (14UL)
#define CLIF_BM_RX_BUFFER_RESERVED1_MASK                                                                  (0x0000C000UL)  /**< 14-Reserved */
#define CLIF_BM_RX_BUFFER_RX_BUFFER_START_ADDRESS_POS                                                    (0UL)
#define CLIF_BM_RX_BUFFER_RX_BUFFER_START_ADDRESS_MASK                                                   (0x00003FFFUL)  /**< 0-Defines the relative buffer (word) address of the Rx buffer. Note: Changing the buffer address while the receiver is enabled will trigger a BMA error.*/
#define CLIF_BM_RX_BUFFER__RESET_VALUE                                                                   (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_rf_control
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_RF_CONTROL                                                                                   0x69
#define CLIF_RF_CONTROL_R                                                                                   0x69
#define CLIF_RF_CONTROL_W                                                                                   0x69
#define CLIF_RF_CONTROL_RESERVED_POS                                                                     (5UL)
#define CLIF_RF_CONTROL_RESERVED_MASK                                                                    (0xFFFFFFE0UL)  /**< 5-Reserved */
#define CLIF_RF_CONTROL_TX_RF_ENABLE_POS                                                                 (4UL)
#define CLIF_RF_CONTROL_TX_RF_ENABLE_MASK                                                                (0x00000010UL)  /**< 4-Set to 1. turning on the driver in reader or active mode is requested. Note: According to the setting of InitialRFOn. AutoRFOn and CAOn the driver is turned after a defined time and depended on the presence of an external RF field. Note: In case of an RFActiveError this bit is cleared by HW */
#define CLIF_RF_CONTROL_TX_COLL_AV_ENABLE_POS                                                            (3UL)
#define CLIF_RF_CONTROL_TX_COLL_AV_ENABLE_MASK                                                           (0x00000008UL)  /**< 3-Set to 1.enables automatic collision avoidance. See ISO18092 for more details. */
#define CLIF_RF_CONTROL_TX_INITIAL_RFON_POS                                                              (2UL)
#define CLIF_RF_CONTROL_TX_INITIAL_RFON_MASK                                                             (0x00000004UL)  /**< 2-Set to 1. the drivers are automatically turned on when no external field is present. In the case an external field is detected. the turning on the drivers is delay until the external field vanishes. Note: The driver on procedure must be triggered by setting TX_RF_ENABLE. Note: This bit is reset to 0 as soon as the drivers turned on. */
#define CLIF_RF_CONTROL_TX_AUTO_RFON_POS                                                                 (1UL)
#define CLIF_RF_CONTROL_TX_AUTO_RFON_MASK                                                                (0x00000002UL)  /**< 1-Set to 1. the drivers are automatically turned on after a before present external field vanished. Note: The driver on procedure must be triggered by setting TX_RF_ENABLE. */
#define CLIF_RF_CONTROL_TX_AUTO_RFOFF_POS                                                                (0UL)
#define CLIF_RF_CONTROL_TX_AUTO_RFOFF_MASK                                                               (0x00000001UL)  /**< 0-Set to 1. the drivers are automatically turned off after data is transmitted.*/
#define CLIF_RF_CONTROL__RESET_VALUE                                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_tx_data_config
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_TX_DATA_CONFIG                                                                               0x6A
#define CLIF_TX_DATA_CONFIG_R                                                                               0x6A
#define CLIF_TX_DATA_CONFIG_W                                                                               0x6A
#define CLIF_TX_DATA_CONFIG_TX_PICC2_NUM_BYTES_2_SEND_POS                                                (19UL)
#define CLIF_TX_DATA_CONFIG_TX_PICC2_NUM_BYTES_2_SEND_MASK                                               (0xFFF80000UL)  /**< 19-Defines the number of bytes to be transmit in case a second PICC response is enabled. The maximum number of bytes is 260 (0x104). If the Transmission Of Data Is Enabled (TX_DATA_ENABLE) and TX_PICC2_NUM_BYTES_2_SEND is zero then a NO_DATA_ERROR occurs.*/
#define CLIF_TX_DATA_CONFIG_TX_LAST_BITS_POS                                                             (16UL)
#define CLIF_TX_DATA_CONFIG_TX_LAST_BITS_MASK                                                            (0x00070000UL)  /**< 16-Defines how many bits of the last data byte to be sent. If set to 000b all bits of the last data byte are sent. Note: Bits are skipped at the end of the byte */
#define CLIF_TX_DATA_CONFIG_TX_FIRST_BITS_POS                                                            (13UL)
#define CLIF_TX_DATA_CONFIG_TX_FIRST_BITS_MASK                                                           (0x0000E000UL)  /**< 13-Defines how many bits of the first data byte to be sent. If set to 000b all bits of the last data byte are sent. Note: Bits are skipped at the beginning of the byte */
#define CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_POS                                                      (0UL)
#define CLIF_TX_DATA_CONFIG_TX_NUM_BYTES_2_SEND_MASK                                                     (0x00001FFFUL)  /**< 0-Defines the number of bytes to be transmit. The maximum number of bytes is 260 (0x104). If the Transmission Of Data Is Enabled (TX_DATA_ENABLE) and TX_NUM_BYTES_2_SEND is zero. then a NO_DATA_ERROR occurs.*/
#define CLIF_TX_DATA_CONFIG__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_control
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_CONTROL                                                                                      0x6B
#define CLIF_CONTROL_R                                                                                      0x6B
#define CLIF_CONTROL_W                                                                                      0x6B
#define CLIF_CONTROL_RESERVED_POS                                                                        (4UL)
#define CLIF_CONTROL_RESERVED_MASK                                                                       (0xFFFFFFF0UL)  /**< 4-Reserved */
#define CLIF_CONTROL_START_SEND_POS                                                                      (3UL)
#define CLIF_CONTROL_START_SEND_MASK                                                                     (0x00000008UL)  /**< 3-Set to logic 1. the data transmission is started. Note: This bit is only valid in combination with the Transceive command Note: If TxWait is set to a value other than zero the TxWait period configured must be expired as well that the transmission starts Note: As soon as the transmission started this bit is cleared by HW. */
#define CLIF_CONTROL_COMMAND_POS                                                                         (0UL)
#define CLIF_CONTROL_COMMAND_MASK                                                                        (0x00000007UL)  /**< 0-This registers hold the command bits 0* IDLE/StopCom Command. stops all ongoing communication and set the CLIF to IDLE mode. reset value 1 Transmit command. starts a transmission immediately 2 Receive command. enables the receiver. After end of reception the bits are clear and IDLE 3 Transceive command. initiates a transceive cycle. Note: Depending on the value of the Initiator bit a transmission is started or the receiver is enabled Note: The transceive command does not finish automatically. It stays in the transceive cycle until stopped via the IDLE/StopCom command 4 KeepCommand command. This command does not change the content of the command register and might be used in case other bits in the register are to be changed 5 LoopBack command. This command is for test purposes only. It starts a transmission and at the same enables the receiver. 6 - 7 Reserved: Do not use this settings  1*/
#define CLIF_CONTROL__RESET_VALUE                                                                        (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_int_set_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> w-
* @{
*/
#define CLIF_INT_SET_ENABLE                                                                               0x6C
#define CLIF_INT_SET_ENABLE_CTS_IRQ_SET_ENABLE_POS                                                       (31UL)
#define CLIF_INT_SET_ENABLE_CTS_IRQ_SET_ENABLE_MASK                                                      (0x80000000UL)  /**< 31-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RESERVED_POS                                                                 (29UL)
#define CLIF_INT_SET_ENABLE_RESERVED_MASK                                                                (0x60000000UL)  /**< 29-Reserved        */
#define CLIF_INT_SET_ENABLE_TX_DATA_REQ_IRQ_SET_ENABLE_POS                                               (28UL)
#define CLIF_INT_SET_ENABLE_TX_DATA_REQ_IRQ_SET_ENABLE_MASK                                              (0x10000000UL)  /**< 28-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_DATA_AV_IRQ_SET_ENABLE_POS                                                (27UL)
#define CLIF_INT_SET_ENABLE_RX_DATA_AV_IRQ_SET_ENABLE_MASK                                               (0x08000000UL)  /**< 27-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_BUFFER_OVERFLOW_IRQ_SET_ENABLE_POS                                        (26UL)
#define CLIF_INT_SET_ENABLE_RX_BUFFER_OVERFLOW_IRQ_SET_ENABLE_MASK                                       (0x04000000UL)  /**< 26-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TX_WATERLEVEL_IRQ_SET_ENABLE_POS                                             (25UL)
#define CLIF_INT_SET_ENABLE_TX_WATERLEVEL_IRQ_SET_ENABLE_MASK                                            (0x02000000UL)  /**< 25-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_WATERLEVEL_IRQ_SET_ENABLE_POS                                             (24UL)
#define CLIF_INT_SET_ENABLE_RX_WATERLEVEL_IRQ_SET_ENABLE_MASK                                            (0x01000000UL)  /**< 24-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RESERVED1_POS                                                                 (23UL)
#define CLIF_INT_SET_ENABLE_RESERVED1_MASK                                                                (0x00800000UL)  /**< 23-Reserved */
#define CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_POS                                                 (22UL)
#define CLIF_INT_SET_ENABLE_RX_SC_DET_IRQ_SET_ENABLE_MASK                                                (0x00400000UL)  /**< 22-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_SOF_DET_IRQ_SET_ENABLE_POS                                                (21UL)
#define CLIF_INT_SET_ENABLE_RX_SOF_DET_IRQ_SET_ENABLE_MASK                                               (0x00200000UL)  /**< 21-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_EMD_IRQ_SET_ENABLE_POS                                                    (20UL)
#define CLIF_INT_SET_ENABLE_RX_EMD_IRQ_SET_ENABLE_MASK                                                   (0x00100000UL)  /**< 20-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TIMER4_IRQ_SET_ENABLE_POS                                                    (19UL)
#define CLIF_INT_SET_ENABLE_TIMER4_IRQ_SET_ENABLE_MASK                                                   (0x00080000UL)  /**< 19-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TIMER3_IRQ_SET_ENABLE_POS                                                    (18UL)
#define CLIF_INT_SET_ENABLE_TIMER3_IRQ_SET_ENABLE_MASK                                                   (0x00040000UL)  /**< 18-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TIMER2_IRQ_SET_ENABLE_POS                                                    (17UL)
#define CLIF_INT_SET_ENABLE_TIMER2_IRQ_SET_ENABLE_MASK                                                   (0x00020000UL)  /**< 17-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TIMER1_IRQ_SET_ENABLE_POS                                                    (16UL)
#define CLIF_INT_SET_ENABLE_TIMER1_IRQ_SET_ENABLE_MASK                                                   (0x00010000UL)  /**< 16-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TIMER0_IRQ_SET_ENABLE_POS                                                    (15UL)
#define CLIF_INT_SET_ENABLE_TIMER0_IRQ_SET_ENABLE_MASK                                                   (0x00008000UL)  /**< 15-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RESERVED2_POS                                                                 (13UL)
#define CLIF_INT_SET_ENABLE_RESERVED2_MASK                                                                (0x00006000UL)  /**< 13-Reserved        */
#define CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_POS                                           (12UL)
#define CLIF_INT_SET_ENABLE_RF_ACTIVE_ERROR_IRQ_SET_ENABLE_MASK                                          (0x00001000UL)  /**< 12-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TX_RFON_IRQ_SET_ENABLE_POS                                                   (11UL)
#define CLIF_INT_SET_ENABLE_TX_RFON_IRQ_SET_ENABLE_MASK                                                  (0x00000800UL)  /**< 11-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TX_RFOFF_IRQ_SET_ENABLE_POS                                                  (10UL)
#define CLIF_INT_SET_ENABLE_TX_RFOFF_IRQ_SET_ENABLE_MASK                                                 (0x00000400UL)  /**< 10-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RFON_DET_IRQ_SET_ENABLE_POS                                                  (9UL)
#define CLIF_INT_SET_ENABLE_RFON_DET_IRQ_SET_ENABLE_MASK                                                 (0x00000200UL)  /**< 9-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RFOFF_DET_IRQ_SET_ENABLE_POS                                                 (8UL)
#define CLIF_INT_SET_ENABLE_RFOFF_DET_IRQ_SET_ENABLE_MASK                                                (0x00000100UL)  /**< 8-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RESERVED3_POS                                                                 (6UL)
#define CLIF_INT_SET_ENABLE_RESERVED3_MASK                                                                (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_INT_SET_ENABLE_STATE_CHANGE_IRQ_SET_ENABLE_POS                                              (5UL)
#define CLIF_INT_SET_ENABLE_STATE_CHANGE_IRQ_SET_ENABLE_MASK                                             (0x00000020UL)  /**< 5-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_CARD_ACTIVATED_IRQ_SET_ENABLE_POS                                            (4UL)
#define CLIF_INT_SET_ENABLE_CARD_ACTIVATED_IRQ_SET_ENABLE_MASK                                           (0x00000010UL)  /**< 4-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_MODE_DETECTED_IRQ_SET_ENABLE_POS                                             (3UL)
#define CLIF_INT_SET_ENABLE_MODE_DETECTED_IRQ_SET_ENABLE_MASK                                            (0x00000008UL)  /**< 3-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_IDLE_IRQ_SET_ENABLE_POS                                                      (2UL)
#define CLIF_INT_SET_ENABLE_IDLE_IRQ_SET_ENABLE_MASK                                                     (0x00000004UL)  /**< 2-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_POS                                                        (1UL)
#define CLIF_INT_SET_ENABLE_TX_IRQ_SET_ENABLE_MASK                                                       (0x00000002UL)  /**< 1-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE_RX_IRQ_SET_ENABLE_POS                                                        (0UL)
#define CLIF_INT_SET_ENABLE_RX_IRQ_SET_ENABLE_MASK                                                       (0x00000001UL)  /**< 0-Writing 1 to this register sets the corresponding IRQ ENABLE flag */
#define CLIF_INT_SET_ENABLE__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_int_clr_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> w-
* @{
*/
#define CLIF_INT_CLR_ENABLE                                                                               0x6D
#define CLIF_INT_CLR_ENABLE_CTS_IRQ_CLR_ENABLE_POS                                                       (31UL)
#define CLIF_INT_CLR_ENABLE_CTS_IRQ_CLR_ENABLE_MASK                                                      (0x80000000UL)  /**< 31-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RESERVED_POS                                                                 (29UL)
#define CLIF_INT_CLR_ENABLE_RESERVED_MASK                                                                (0x60000000UL)  /**< 29-Reserved        */
#define CLIF_INT_CLR_ENABLE_TX_DATA_REQ_IRQ_CLR_ENABLE_POS                                               (28UL)
#define CLIF_INT_CLR_ENABLE_TX_DATA_REQ_IRQ_CLR_ENABLE_MASK                                              (0x10000000UL)  /**< 28-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_DATA_AV_IRQ_CLR_ENABLE_POS                                                (27UL)
#define CLIF_INT_CLR_ENABLE_RX_DATA_AV_IRQ_CLR_ENABLE_MASK                                               (0x08000000UL)  /**< 27-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_BUFFER_OVERFLOW_IRQ_CLR_ENABLE_POS                                        (26UL)
#define CLIF_INT_CLR_ENABLE_RX_BUFFER_OVERFLOW_IRQ_CLR_ENABLE_MASK                                       (0x04000000UL)  /**< 26-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TX_WATERLEVEL_IRQ_CLR_ENABLE_POS                                             (25UL)
#define CLIF_INT_CLR_ENABLE_TX_WATERLEVEL_IRQ_CLR_ENABLE_MASK                                            (0x02000000UL)  /**< 25-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_WATERLEVEL_IRQ_CLR_ENABLE_POS                                             (24UL)
#define CLIF_INT_CLR_ENABLE_RX_WATERLEVEL_IRQ_CLR_ENABLE_MASK                                            (0x01000000UL)  /**< 24-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RESERVED1_POS                                                                 (23UL)
#define CLIF_INT_CLR_ENABLE_RESERVED1_MASK                                                                (0x00800000UL)  /**< 23-Reserved */
#define CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_POS                                                 (22UL)
#define CLIF_INT_CLR_ENABLE_RX_SC_DET_IRQ_CLR_ENABLE_MASK                                                (0x00400000UL)  /**< 22-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_POS                                                (21UL)
#define CLIF_INT_CLR_ENABLE_RX_SOF_DET_IRQ_CLR_ENABLE_MASK                                               (0x00200000UL)  /**< 21-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_EMD_IRQ_CLR_ENABLE_POS                                                    (20UL)
#define CLIF_INT_CLR_ENABLE_RX_EMD_IRQ_CLR_ENABLE_MASK                                                   (0x00100000UL)  /**< 20-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TIMER4_IRQ_CLR_ENABLE_POS                                                    (19UL)
#define CLIF_INT_CLR_ENABLE_TIMER4_IRQ_CLR_ENABLE_MASK                                                   (0x00080000UL)  /**< 19-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TIMER3_IRQ_CLR_ENABLE_POS                                                    (18UL)
#define CLIF_INT_CLR_ENABLE_TIMER3_IRQ_CLR_ENABLE_MASK                                                   (0x00040000UL)  /**< 18-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TIMER2_IRQ_CLR_ENABLE_POS                                                    (17UL)
#define CLIF_INT_CLR_ENABLE_TIMER2_IRQ_CLR_ENABLE_MASK                                                   (0x00020000UL)  /**< 17-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_POS                                                    (16UL)
#define CLIF_INT_CLR_ENABLE_TIMER1_IRQ_CLR_ENABLE_MASK                                                   (0x00010000UL)  /**< 16-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_POS                                                    (15UL)
#define CLIF_INT_CLR_ENABLE_TIMER0_IRQ_CLR_ENABLE_MASK                                                   (0x00008000UL)  /**< 15-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RESERVED2_POS                                                                 (13UL)
#define CLIF_INT_CLR_ENABLE_RESERVED2_MASK                                                                (0x00006000UL)  /**< 13-Reserved        */
#define CLIF_INT_CLR_ENABLE_RF_ACTIVE_ERROR_IRQ_CLR_ENABLE_POS                                           (12UL)
#define CLIF_INT_CLR_ENABLE_RF_ACTIVE_ERROR_IRQ_CLR_ENABLE_MASK                                          (0x00001000UL)  /**< 12-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TX_RFON_IRQ_CLR_ENABLE_POS                                                   (11UL)
#define CLIF_INT_CLR_ENABLE_TX_RFON_IRQ_CLR_ENABLE_MASK                                                  (0x00000800UL)  /**< 11-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TX_RFOFF_IRQ_CLR_ENABLE_POS                                                  (10UL)
#define CLIF_INT_CLR_ENABLE_TX_RFOFF_IRQ_CLR_ENABLE_MASK                                                 (0x00000400UL)  /**< 10-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RFON_DET_IRQ_CLR_ENABLE_POS                                                  (9UL)
#define CLIF_INT_CLR_ENABLE_RFON_DET_IRQ_CLR_ENABLE_MASK                                                 (0x00000200UL)  /**< 9-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RFOFF_DET_IRQ_CLR_ENABLE_POS                                                 (8UL)
#define CLIF_INT_CLR_ENABLE_RFOFF_DET_IRQ_CLR_ENABLE_MASK                                                (0x00000100UL)  /**< 8-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RESERVED3_POS                                                                 (6UL)
#define CLIF_INT_CLR_ENABLE_RESERVED3_MASK                                                                (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_INT_CLR_ENABLE_STATE_CHANGE_IRQ_CLR_ENABLE_POS                                              (5UL)
#define CLIF_INT_CLR_ENABLE_STATE_CHANGE_IRQ_CLR_ENABLE_MASK                                             (0x00000020UL)  /**< 5-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_CARD_ACTIVATED_IRQ_CLR_ENABLE_POS                                            (4UL)
#define CLIF_INT_CLR_ENABLE_CARD_ACTIVATED_IRQ_CLR_ENABLE_MASK                                           (0x00000010UL)  /**< 4-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_MODE_DETECTED_IRQ_CLR_ENABLE_POS                                             (3UL)
#define CLIF_INT_CLR_ENABLE_MODE_DETECTED_IRQ_CLR_ENABLE_MASK                                            (0x00000008UL)  /**< 3-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_IDLE_IRQ_CLR_ENABLE_POS                                                      (2UL)
#define CLIF_INT_CLR_ENABLE_IDLE_IRQ_CLR_ENABLE_MASK                                                     (0x00000004UL)  /**< 2-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_POS                                                        (1UL)
#define CLIF_INT_CLR_ENABLE_TX_IRQ_CLR_ENABLE_MASK                                                       (0x00000002UL)  /**< 1-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_POS                                                        (0UL)
#define CLIF_INT_CLR_ENABLE_RX_IRQ_CLR_ENABLE_MASK                                                       (0x00000001UL)  /**< 0-Writing 1 to this register clears the corresponding IRQ ENABLE flag */
#define CLIF_INT_CLR_ENABLE__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_int_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_INT_STATUS                                                                                   0x6E
#define CLIF_INT_STATUS_CTS_IRQ_POS                                                                      (31UL)
#define CLIF_INT_STATUS_CTS_IRQ_MASK                                                                     (0x80000000UL)  /**< 31-Set to 1 by HW when the CLIF Test-Station wants to communicate the FW the end of an acquisition or a faulty condition.*/
#define CLIF_INT_STATUS_RESERVED_POS                                                                     (29UL)
#define CLIF_INT_STATUS_RESERVED_MASK                                                                    (0x60000000UL)  /**< 29-Reserved        */
#define CLIF_INT_STATUS_TX_DATA_REQ_IRQ_POS                                                              (28UL)
#define CLIF_INT_STATUS_TX_DATA_REQ_IRQ_MASK                                                             (0x10000000UL)  /**< 28-Set to 1 by HW when the BufferManager requests data for transmission from RAM. Note: Only valid if the bit DIRECT_DATA_ACCESS_ENABLE is set to 1*/
#define CLIF_INT_STATUS_RX_DATA_AV_IRQ_POS                                                               (27UL)
#define CLIF_INT_STATUS_RX_DATA_AV_IRQ_MASK                                                              (0x08000000UL)  /**< 27-Set to 1 by HW when the BufferManager holds received data from reception to be written to RAM. Note: Only valid if the bit DIRECT_DATA_ACCESS_ENABLE is set to 1*/
#define CLIF_INT_STATUS_RX_BUFFER_OVERFLOW_IRQ_POS                                                       (26UL)
#define CLIF_INT_STATUS_RX_BUFFER_OVERFLOW_IRQ_MASK                                                      (0x04000000UL)  /**< 26-Set to 1 by HW when the number of bytes received exceds the size of the RX buffer. Note: Reception is stoped in that case. Note: If RX_MULTIPLE is set to 1 this an this IRQ is raised when the sum of all frames exceed the RX buffer size */
#define CLIF_INT_STATUS_TX_WATERLEVEL_IRQ_POS                                                            (25UL)
#define CLIF_INT_STATUS_TX_WATERLEVEL_IRQ_MASK                                                           (0x02000000UL)  /**< 25-Set to 1 by HW when the number of bytes transmitted is equal to the TX_WATERLEVEL */
#define CLIF_INT_STATUS_RX_WATERLEVEL_IRQ_POS                                                            (24UL)
#define CLIF_INT_STATUS_RX_WATERLEVEL_IRQ_MASK                                                           (0x01000000UL)  /**< 24-Set to 1 by HW when the number of bytes received is equal to the RX_WATERLEVEL */
#define CLIF_INT_STATUS_RESERVED1_POS                                                                     (23UL)
#define CLIF_INT_STATUS_RESERVED1_MASK                                                                    (0x00800000UL)  /**< 23-Reserved */
#define CLIF_INT_STATUS_RX_SC_DET_IRQ_POS                                                                (22UL)
#define CLIF_INT_STATUS_RX_SC_DET_IRQ_MASK                                                               (0x00400000UL)  /**< 22-Set to 1 by HW when in reader mode a subcarrier is detected */
#define CLIF_INT_STATUS_RX_SOF_DET_IRQ_POS                                                               (21UL)
#define CLIF_INT_STATUS_RX_SOF_DET_IRQ_MASK                                                              (0x00200000UL)  /**< 21-Set to 1 by HW when in reader mode an SOF is detected */
#define CLIF_INT_STATUS_RX_EMD_IRQ_POS                                                                   (20UL)
#define CLIF_INT_STATUS_RX_EMD_IRQ_MASK                                                                  (0x00100000UL)  /**< 20-Set to 1 by HW when an EMD event is detected */
#define CLIF_INT_STATUS_TIMER4_IRQ_POS                                                                   (19UL)
#define CLIF_INT_STATUS_TIMER4_IRQ_MASK                                                                  (0x00080000UL)  /**< 19-Set to 1 by HW when the Timer4 is expired. */
#define CLIF_INT_STATUS_TIMER3_IRQ_POS                                                                   (18UL)
#define CLIF_INT_STATUS_TIMER3_IRQ_MASK                                                                  (0x00040000UL)  /**< 18-Set to 1 by HW when the Timer3 is expired. */
#define CLIF_INT_STATUS_TIMER2_IRQ_POS                                                                   (17UL)
#define CLIF_INT_STATUS_TIMER2_IRQ_MASK                                                                  (0x00020000UL)  /**< 17-Set to 1 by HW when the Timer2 is expired. */
#define CLIF_INT_STATUS_TIMER1_IRQ_POS                                                                   (16UL)
#define CLIF_INT_STATUS_TIMER1_IRQ_MASK                                                                  (0x00010000UL)  /**< 16-Set to 1 by HW when the Timer1 is expired. */
#define CLIF_INT_STATUS_TIMER0_IRQ_POS                                                                   (15UL)
#define CLIF_INT_STATUS_TIMER0_IRQ_MASK                                                                  (0x00008000UL)  /**< 15-Set to 1 by HW when the Timer0 is expired.        */
#define CLIF_INT_STATUS_RESERVED2_POS                                                                     (13UL)
#define CLIF_INT_STATUS_RESERVED2_MASK                                                                    (0x00006000UL)  /**< 13-Reserved        */
#define CLIF_INT_STATUS_RF_ACTIVE_ERROR_IRQ_POS                                                          (12UL)
#define CLIF_INT_STATUS_RF_ACTIVE_ERROR_IRQ_MASK                                                         (0x00001000UL)  /**< 12-Set to 1 by HW when an RF error case occurred */
#define CLIF_INT_STATUS_TX_RFON_IRQ_POS                                                                  (11UL)
#define CLIF_INT_STATUS_TX_RFON_IRQ_MASK                                                                 (0x00000800UL)  /**< 11-Set to 1 by HW when the internally generated RF-field was switched on. */
#define CLIF_INT_STATUS_TX_RFOFF_IRQ_POS                                                                 (10UL)
#define CLIF_INT_STATUS_TX_RFOFF_IRQ_MASK                                                                (0x00000400UL)  /**< 10-Set to 1 by HW when the internally generated RF-field was switched off. */
#define CLIF_INT_STATUS_RFON_DET_IRQ_POS                                                                 (9UL)
#define CLIF_INT_STATUS_RFON_DET_IRQ_MASK                                                                (0x00000200UL)  /**< 9-Set to 1 by HW when an external RF-field is detected. */
#define CLIF_INT_STATUS_RFOFF_DET_IRQ_POS                                                                (8UL)
#define CLIF_INT_STATUS_RFOFF_DET_IRQ_MASK                                                               (0x00000100UL)  /**< 8-Set to 1 by HW when an until then preset external RF-field is switched off. */
#define CLIF_INT_STATUS_RESERVED3_POS                                                                     (6UL)
#define CLIF_INT_STATUS_RESERVED3_MASK                                                                    (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_INT_STATUS_STATE_CHANGE_IRQ_POS                                                             (5UL)
#define CLIF_INT_STATUS_STATE_CHANGE_IRQ_MASK                                                            (0x00000020UL)  /**< 5-Set to 1 by HW when a transceive state is entered selected in the register field STATE_TRIGGER_SELECT */
#define CLIF_INT_STATUS_CARD_ACTIVATED_IRQ_POS                                                           (4UL)
#define CLIF_INT_STATUS_CARD_ACTIVATED_IRQ_MASK                                                          (0x00000010UL)  /**< 4-Set to 1 by HW when TypeA card mode activation FSM reached the ACTIVATED or ACTIVATE_S state */
#define CLIF_INT_STATUS_MODE_DETECTED_IRQ_POS                                                            (3UL)
#define CLIF_INT_STATUS_MODE_DETECTED_IRQ_MASK                                                           (0x00000008UL)  /**< 3-Set to 1 by HW when the card mode has been detected by the ModeDetector Note: While the TypeA activation FSM is active no IRQ is issued any more */
#define CLIF_INT_STATUS_IDLE_IRQ_POS                                                                     (2UL)
#define CLIF_INT_STATUS_IDLE_IRQ_MASK                                                                    (0x00000004UL)  /**< 2-Set to 1 by HW when the IDLE state is entered */
#define CLIF_INT_STATUS_TX_IRQ_POS                                                                       (1UL)
#define CLIF_INT_STATUS_TX_IRQ_MASK                                                                      (0x00000002UL)  /**< 1-Set to 1 by HW when an ongoing transmission is finished. */
#define CLIF_INT_STATUS_RX_IRQ_POS                                                                       (0UL)
#define CLIF_INT_STATUS_RX_IRQ_MASK                                                                      (0x00000001UL)  /**< 0-Set to 1 by HW when an ongoing reception is finished*/
#define CLIF_INT_STATUS__RESET_VALUE                                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_int_enable
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> r-
* @{
*/
#define CLIF_INT_ENABLE                                                                                   0x6F
#define CLIF_INT_ENABLE_R                                                                                   0x6F
#define CLIF_INT_ENABLE_CTS_IRQ_ENABLE_POS                                                               (31UL)
#define CLIF_INT_ENABLE_CTS_IRQ_ENABLE_MASK                                                              (0x80000000UL)  /**< 31-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RESERVED_POS                                                                     (29UL)
#define CLIF_INT_ENABLE_RESERVED_MASK                                                                    (0x60000000UL)  /**< 29-Reserved        */
#define CLIF_INT_ENABLE_TX_DATA_REQ_IRQ_ENABLE_POS                                                       (28UL)
#define CLIF_INT_ENABLE_TX_DATA_REQ_IRQ_ENABLE_MASK                                                      (0x10000000UL)  /**< 28-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_DATA_AV_IRQ_ENABLE_POS                                                        (27UL)
#define CLIF_INT_ENABLE_RX_DATA_AV_IRQ_ENABLE_MASK                                                       (0x08000000UL)  /**< 27-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_BUFFER_OVERFLOW_IRQ_ENABLE_POS                                                (26UL)
#define CLIF_INT_ENABLE_RX_BUFFER_OVERFLOW_IRQ_ENABLE_MASK                                               (0x04000000UL)  /**< 26-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TX_WATERLEVEL_IRQ_ENABLE_POS                                                     (25UL)
#define CLIF_INT_ENABLE_TX_WATERLEVEL_IRQ_ENABLE_MASK                                                    (0x02000000UL)  /**< 25-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_WATERLEVEL_IRQ_ENABLE_POS                                                     (24UL)
#define CLIF_INT_ENABLE_RX_WATERLEVEL_IRQ_ENABLE_MASK                                                    (0x01000000UL)  /**< 24-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RESERVED1_POS                                                                     (23UL)
#define CLIF_INT_ENABLE_RESERVED1_MASK                                                                    (0x00800000UL)  /**< 23-Reserved */
#define CLIF_INT_ENABLE_RX_SC_DET_IRQ_ENABLE_POS                                                         (22UL)
#define CLIF_INT_ENABLE_RX_SC_DET_IRQ_ENABLE_MASK                                                        (0x00400000UL)  /**< 22-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_SOF_DET_IRQ_ENABLE_POS                                                        (21UL)
#define CLIF_INT_ENABLE_RX_SOF_DET_IRQ_ENABLE_MASK                                                       (0x00200000UL)  /**< 21-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_EMD_IRQ_ENABLE_POS                                                            (20UL)
#define CLIF_INT_ENABLE_RX_EMD_IRQ_ENABLE_MASK                                                           (0x00100000UL)  /**< 20-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TIMER4_IRQ_ENABLE_POS                                                            (19UL)
#define CLIF_INT_ENABLE_TIMER4_IRQ_ENABLE_MASK                                                           (0x00080000UL)  /**< 19-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TIMER3_IRQ_ENABLE_POS                                                            (18UL)
#define CLIF_INT_ENABLE_TIMER3_IRQ_ENABLE_MASK                                                           (0x00040000UL)  /**< 18-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TIMER2_IRQ_ENABLE_POS                                                            (17UL)
#define CLIF_INT_ENABLE_TIMER2_IRQ_ENABLE_MASK                                                           (0x00020000UL)  /**< 17-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TIMER1_IRQ_ENABLE_POS                                                            (16UL)
#define CLIF_INT_ENABLE_TIMER1_IRQ_ENABLE_MASK                                                           (0x00010000UL)  /**< 16-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TIMER0_IRQ_ENABLE_POS                                                            (15UL)
#define CLIF_INT_ENABLE_TIMER0_IRQ_ENABLE_MASK                                                           (0x00008000UL)  /**< 15-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RESERVED2_POS                                                                     (13UL)
#define CLIF_INT_ENABLE_RESERVED2_MASK                                                                    (0x00006000UL)  /**< 13-Reserved */
#define CLIF_INT_ENABLE_RF_ACTIVE_ERROR_IRQ_ENABLE_POS                                                   (12UL)
#define CLIF_INT_ENABLE_RF_ACTIVE_ERROR_IRQ_ENABLE_MASK                                                  (0x00001000UL)  /**< 12-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TX_RFON_IRQ_ENABLE_POS                                                           (11UL)
#define CLIF_INT_ENABLE_TX_RFON_IRQ_ENABLE_MASK                                                          (0x00000800UL)  /**< 11-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TX_RFOFF_IRQ_ENABLE_POS                                                          (10UL)
#define CLIF_INT_ENABLE_TX_RFOFF_IRQ_ENABLE_MASK                                                         (0x00000400UL)  /**< 10-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RFON_DET_IRQ_ENABLE_POS                                                          (9UL)
#define CLIF_INT_ENABLE_RFON_DET_IRQ_ENABLE_MASK                                                         (0x00000200UL)  /**< 9-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RFOFF_DET_IRQ_ENABLE_POS                                                         (8UL)
#define CLIF_INT_ENABLE_RFOFF_DET_IRQ_ENABLE_MASK                                                        (0x00000100UL)  /**< 8-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RESERVED3_POS                                                                     (6UL)
#define CLIF_INT_ENABLE_RESERVED3_MASK                                                                    (0x000000C0UL)  /**< 6-Reserved */
#define CLIF_INT_ENABLE_STATE_CHANGE_IRQ_ENABLE_POS                                                      (5UL)
#define CLIF_INT_ENABLE_STATE_CHANGE_IRQ_ENABLE_MASK                                                     (0x00000020UL)  /**< 5-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_CARD_ACTIVATED_IRQ_ENABLE_POS                                                    (4UL)
#define CLIF_INT_ENABLE_CARD_ACTIVATED_IRQ_ENABLE_MASK                                                   (0x00000010UL)  /**< 4-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_MODE_DETECTED_IRQ_ENABLE_POS                                                     (3UL)
#define CLIF_INT_ENABLE_MODE_DETECTED_IRQ_ENABLE_MASK                                                    (0x00000008UL)  /**< 3-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_IDLE_IRQ_ENABLE_POS                                                              (2UL)
#define CLIF_INT_ENABLE_IDLE_IRQ_ENABLE_MASK                                                             (0x00000004UL)  /**< 2-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_TX_IRQ_ENABLE_POS                                                                (1UL)
#define CLIF_INT_ENABLE_TX_IRQ_ENABLE_MASK                                                               (0x00000002UL)  /**< 1-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE_RX_IRQ_ENABLE_POS                                                                (0UL)
#define CLIF_INT_ENABLE_RX_IRQ_ENABLE_MASK                                                               (0x00000001UL)  /**< 0-When this bit is set to 1 the corresponding status bit is enabled to propagate to the CORE IRQ controller.*/
#define CLIF_INT_ENABLE__RESET_VALUE                                                                     (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_int_clr_status
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> w-
* @{
*/
#define CLIF_INT_CLR_STATUS                                                                               0x70
#define CLIF_INT_CLR_STATUS_CTS_IRQ_CLR_STATUS_POS                                                       (31UL)
#define CLIF_INT_CLR_STATUS_CTS_IRQ_CLR_STATUS_MASK                                                      (0x80000000UL)  /**< 31-*/
#define CLIF_INT_CLR_STATUS_RESERVED_POS                                                                 (29UL)
#define CLIF_INT_CLR_STATUS_RESERVED_MASK                                                                (0x60000000UL)  /**< 29-*/
#define CLIF_INT_CLR_STATUS_TX_DATA_REQ_IRQ_CLR_STATUS_POS                                               (28UL)
#define CLIF_INT_CLR_STATUS_TX_DATA_REQ_IRQ_CLR_STATUS_MASK                                              (0x10000000UL)  /**< 28-*/
#define CLIF_INT_CLR_STATUS_RX_DATA_AV_IRQ_CLR_STATUS_POS                                                (27UL)
#define CLIF_INT_CLR_STATUS_RX_DATA_AV_IRQ_CLR_STATUS_MASK                                               (0x08000000UL)  /**< 27-*/
#define CLIF_INT_CLR_STATUS_RX_BUFFER_OVERFLOW_IRQ_CLR_STATUS_POS                                        (26UL)
#define CLIF_INT_CLR_STATUS_RX_BUFFER_OVERFLOW_IRQ_CLR_STATUS_MASK                                       (0x04000000UL)  /**< 26-*/
#define CLIF_INT_CLR_STATUS_TX_WATERLEVEL_IRQ_CLR_STATUS_POS                                             (25UL)
#define CLIF_INT_CLR_STATUS_TX_WATERLEVEL_IRQ_CLR_STATUS_MASK                                            (0x02000000UL)  /**< 25-*/
#define CLIF_INT_CLR_STATUS_RX_WATERLEVEL_IRQ_CLR_STATUS_POS                                             (24UL)
#define CLIF_INT_CLR_STATUS_RX_WATERLEVEL_IRQ_CLR_STATUS_MASK                                            (0x01000000UL)  /**< 24-*/
#define CLIF_INT_CLR_STATUS_RESERVED1_POS                                                                 (23UL)
#define CLIF_INT_CLR_STATUS_RESERVED1_MASK                                                                (0x00800000UL)  /**< 23-*/
#define CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_POS                                                 (22UL)
#define CLIF_INT_CLR_STATUS_RX_SC_DET_IRQ_CLR_STATUS_MASK                                                (0x00400000UL)  /**< 22-*/
#define CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_POS                                                (21UL)
#define CLIF_INT_CLR_STATUS_RX_SOF_DET_IRQ_CLR_STATUS_MASK                                               (0x00200000UL)  /**< 21-*/
#define CLIF_INT_CLR_STATUS_RX_EMD_IRQ_CLR_STATUS_POS                                                    (20UL)
#define CLIF_INT_CLR_STATUS_RX_EMD_IRQ_CLR_STATUS_MASK                                                   (0x00100000UL)  /**< 20-*/
#define CLIF_INT_CLR_STATUS_TIMER4_IRQ_CLR_STATUS_POS                                                    (19UL)
#define CLIF_INT_CLR_STATUS_TIMER4_IRQ_CLR_STATUS_MASK                                                   (0x00080000UL)  /**< 19-*/
#define CLIF_INT_CLR_STATUS_TIMER3_IRQ_CLR_STATUS_POS                                                    (18UL)
#define CLIF_INT_CLR_STATUS_TIMER3_IRQ_CLR_STATUS_MASK                                                   (0x00040000UL)  /**< 18-*/
#define CLIF_INT_CLR_STATUS_TIMER2_IRQ_CLR_STATUS_POS                                                    (17UL)
#define CLIF_INT_CLR_STATUS_TIMER2_IRQ_CLR_STATUS_MASK                                                   (0x00020000UL)  /**< 17-*/
#define CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_POS                                                    (16UL)
#define CLIF_INT_CLR_STATUS_TIMER1_IRQ_CLR_STATUS_MASK                                                   (0x00010000UL)  /**< 16-*/
#define CLIF_INT_CLR_STATUS_TIMER0_IRQ_CLR_STATUS_POS                                                    (15UL)
#define CLIF_INT_CLR_STATUS_TIMER0_IRQ_CLR_STATUS_MASK                                                   (0x00008000UL)  /**< 15-*/
#define CLIF_INT_CLR_STATUS_RESERVED2_POS                                                                 (13UL)
#define CLIF_INT_CLR_STATUS_RESERVED2_MASK                                                                (0x00006000UL)  /**< 13-*/
#define CLIF_INT_CLR_STATUS_RF_ACTIVE_ERROR_IRQ_CLR_STATUS_POS                                           (12UL)
#define CLIF_INT_CLR_STATUS_RF_ACTIVE_ERROR_IRQ_CLR_STATUS_MASK                                          (0x00001000UL)  /**< 12-*/
#define CLIF_INT_CLR_STATUS_TX_RFON_IRQ_CLR_STATUS_POS                                                   (11UL)
#define CLIF_INT_CLR_STATUS_TX_RFON_IRQ_CLR_STATUS_MASK                                                  (0x00000800UL)  /**< 11-*/
#define CLIF_INT_CLR_STATUS_TX_RFOFF_IRQ_CLR_STATUS_POS                                                  (10UL)
#define CLIF_INT_CLR_STATUS_TX_RFOFF_IRQ_CLR_STATUS_MASK                                                 (0x00000400UL)  /**< 10-*/
#define CLIF_INT_CLR_STATUS_RFON_DET_IRQ_CLR_STATUS_POS                                                  (9UL)
#define CLIF_INT_CLR_STATUS_RFON_DET_IRQ_CLR_STATUS_MASK                                                 (0x00000200UL)  /**< 9-*/
#define CLIF_INT_CLR_STATUS_RFOFF_DET_IRQ_CLR_STATUS_POS                                                 (8UL)
#define CLIF_INT_CLR_STATUS_RFOFF_DET_IRQ_CLR_STATUS_MASK                                                (0x00000100UL)  /**< 8-*/
#define CLIF_INT_CLR_STATUS_RESERVED3_POS                                                                 (6UL)
#define CLIF_INT_CLR_STATUS_RESERVED3_MASK                                                                (0x000000C0UL)  /**< 6-*/
#define CLIF_INT_CLR_STATUS_STATE_CHANGE_IRQ_CLR_STATUS_POS                                              (5UL)
#define CLIF_INT_CLR_STATUS_STATE_CHANGE_IRQ_CLR_STATUS_MASK                                             (0x00000020UL)  /**< 5-*/
#define CLIF_INT_CLR_STATUS_CARD_ACTIVATED_IRQ_CLR_STATUS_POS                                            (4UL)
#define CLIF_INT_CLR_STATUS_CARD_ACTIVATED_IRQ_CLR_STATUS_MASK                                           (0x00000010UL)  /**< 4-*/
#define CLIF_INT_CLR_STATUS_MODE_DETECTED_IRQ_CLR_STATUS_POS                                             (3UL)
#define CLIF_INT_CLR_STATUS_MODE_DETECTED_IRQ_CLR_STATUS_MASK                                            (0x00000008UL)  /**< 3-*/
#define CLIF_INT_CLR_STATUS_IDLE_IRQ_CLR_STATUS_POS                                                      (2UL)
#define CLIF_INT_CLR_STATUS_IDLE_IRQ_CLR_STATUS_MASK                                                     (0x00000004UL)  /**< 2-*/
#define CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_POS                                                        (1UL)
#define CLIF_INT_CLR_STATUS_TX_IRQ_CLR_STATUS_MASK                                                       (0x00000002UL)  /**< 1-*/
#define CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_POS                                                        (0UL)
#define CLIF_INT_CLR_STATUS_RX_IRQ_CLR_STATUS_MASK                                                       (0x00000001UL)  /**< 0-*/
#define CLIF_INT_CLR_STATUS__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name bma_int_enable
* <b>Reset value:</b>
* <b>Access:</b> r-
* @{
*/
#define BMA_INT_ENABLE                                                                                    0x71
#define BMA_INT_ENABLE_RESERVED_POS                                                                      (7UL)
#define BMA_INT_ENABLE_RESERVED_MASK                                                                     (0xFFFFFF80UL)  /**< 31-reserved*/
#define BMA_INT_ENABLE_BMA_AHB_ERROR_ENABLE_POS                                                          (6UL)
#define BMA_INT_ENABLE_BMA_AHB_ERROR_ENABLE_MASK                                                         (0x00000040UL)  /**< 6-enable of functional interrupt AHB slave error*/
#define BMA_INT_ENABLE_BMA_ADDR_RANGE_ERROR_ENABLE_POS                                                   (5UL)
#define BMA_INT_ENABLE_BMA_ADDR_RANGE_ERROR_ENABLE_MASK                                                  (0x00000020UL)  /**< 5-enable of functional interrupt Absolute address incompatible with SRAM mapping*/
#define BMA_INT_ENABLE_RESERVED1_POS                                                                     (4UL)
#define BMA_INT_ENABLE_RESERVED1_MASK                                                                    (0x00000010UL)  /**< 4-reserved*/
#define BMA_INT_ENABLE_RESERVED2_POS                                                                     (3UL)
#define BMA_INT_ENABLE_RESERVED2_MASK                                                                    (0x00000008UL)  /**< 3-reserved*/
#define BMA_INT_ENABLE_RESERVED3_POS                                                                     (2UL)
#define BMA_INT_ENABLE_RESERVED3_MASK                                                                    (0x00000004UL)  /**< 2-reserved*/
#define BMA_INT_ENABLE_CLIF_SYS_ERROR_ENABLE_POS                                                         (1UL)
#define BMA_INT_ENABLE_CLIF_SYS_ERROR_ENABLE_MASK                                                        (0x00000002UL)  /**< 1-enable of functional interrupt System error in Contactless interface*/
#define BMA_INT_ENABLE_HOSTIF_SYS_ERROR_ENABLE_POS                                                       (0UL)
#define BMA_INT_ENABLE_HOSTIF_SYS_ERROR_ENABLE_MASK                                                      (0x00000001UL)  /**< 0-enable of functional interrupt System error in Host interface*/
/**
* @}
*/

/**
* @name bma_int_clr_enable
* <b>Reset value:</b>
* <b>Access:</b> w-
* @{
*/
#define BMA_INT_CLR_ENABLE                                                                                0x72
#define BMA_INT_CLR_ENABLE_RESERVED_POS                                                                  (7UL)
#define BMA_INT_CLR_ENABLE_RESERVED_MASK                                                                 (0xFFFFFF80UL)  /**< 31-reserved*/
#define BMA_INT_CLR_ENABLE_BMA_AHB_ERROR_CLR_ENABLE_POS                                                  (6UL)
#define BMA_INT_CLR_ENABLE_BMA_AHB_ERROR_CLR_ENABLE_MASK                                                 (0x00000040UL)  /**< 6-clr of functional interrupt AHB slave error*/
#define BMA_INT_CLR_ENABLE_BMA_ADDR_RANGE_ERROR_CLR_ENABLE_POS                                           (5UL)
#define BMA_INT_CLR_ENABLE_BMA_ADDR_RANGE_ERROR_CLR_ENABLE_MASK                                          (0x00000020UL)  /**< 5-clr of functional interrupt Absolute address incompatible with SRAM mapping*/
#define BMA_INT_CLR_ENABLE_RESERVED1_POS                                                                 (4UL)
#define BMA_INT_CLR_ENABLE_RESERVED1_MASK                                                                (0x00000010UL)  /**< 4-reserved*/
#define BMA_INT_CLR_ENABLE_RESERVED2_POS                                                                 (3UL)
#define BMA_INT_CLR_ENABLE_RESERVED2_MASK                                                                (0x00000008UL)  /**< 3-reserved*/
#define BMA_INT_CLR_ENABLE_RESERVED3_POS                                                                 (2UL)
#define BMA_INT_CLR_ENABLE_RESERVED3_MASK                                                                (0x00000004UL)  /**< 2-reserved*/
#define BMA_INT_CLR_ENABLE_CLIF_SYS_ERROR_CLR_ENABLE_POS                                                 (1UL)
#define BMA_INT_CLR_ENABLE_CLIF_SYS_ERROR_CLR_ENABLE_MASK                                                (0x00000002UL)  /**< 1-clr of functional interrupt System error in Contactless interface*/
#define BMA_INT_CLR_ENABLE_HOSTIF_SYS_ERROR_CLR_ENABLE_POS                                               (0UL)
#define BMA_INT_CLR_ENABLE_HOSTIF_SYS_ERROR_CLR_ENABLE_MASK                                              (0x00000001UL)  /**< 0-clr of functional interrupt System error in Host interface*/
/**
* @}
*/

/**
* @name bma_int_set_enable
* <b>Reset value:</b>
* <b>Access:</b> w-
* @{
*/
#define BMA_INT_SET_ENABLE                                                                                0x73
#define BMA_INT_SET_ENABLE_RESERVED_POS                                                                  (7UL)
#define BMA_INT_SET_ENABLE_RESERVED_MASK                                                                 (0xFFFFFF80UL)  /**< 31-reserved*/
#define BMA_INT_SET_ENABLE_BMA_AHB_ERROR_SET_ENABLE_POS                                                  (6UL)
#define BMA_INT_SET_ENABLE_BMA_AHB_ERROR_SET_ENABLE_MASK                                                 (0x00000040UL)  /**< 6-set of functional interrupt AHB slave error*/
#define BMA_INT_SET_ENABLE_BMA_ADDR_RANGE_ERROR_SET_ENABLE_POS                                           (5UL)
#define BMA_INT_SET_ENABLE_BMA_ADDR_RANGE_ERROR_SET_ENABLE_MASK                                          (0x00000020UL)  /**< 5-set of functional interrupt Absolute address incompatible with SRAM mapping*/
#define BMA_INT_SET_ENABLE_RESERVED1_POS                                                                 (4UL)
#define BMA_INT_SET_ENABLE_RESERVED1_MASK                                                                (0x00000010UL)  /**< 4-reserved*/
#define BMA_INT_SET_ENABLE_RESERVED2_POS                                                                 (3UL)
#define BMA_INT_SET_ENABLE_RESERVED2_MASK                                                                (0x00000008UL)  /**< 3-reserved*/
#define BMA_INT_SET_ENABLE_RESERVED3_POS                                                                 (2UL)
#define BMA_INT_SET_ENABLE_RESERVED3_MASK                                                                (0x00000004UL)  /**< 2-reserved*/
#define BMA_INT_SET_ENABLE_CLIF_SYS_ERROR_SET_ENABLE_POS                                                 (1UL)
#define BMA_INT_SET_ENABLE_CLIF_SYS_ERROR_SET_ENABLE_MASK                                                (0x00000002UL)  /**< 1-set of functional interrupt System error in Contactless interface*/
#define BMA_INT_SET_ENABLE_HOSTIF_SYS_ERROR_SET_ENABLE_POS                                               (0UL)
#define BMA_INT_SET_ENABLE_HOSTIF_SYS_ERROR_SET_ENABLE_MASK                                              (0x00000001UL)  /**< 0-set of functional interrupt System error in Host interface*/
/**
* @}
*/

/**
* @name bma_int_status
* <b>Reset value:</b>
* <b>Access:</b> r-
* @{
*/
#define BMA_INT_STATUS                                                                                    0x74
#define BMA_INT_STATUS_RESERVED_POS                                                                      (7UL)
#define BMA_INT_STATUS_RESERVED_MASK                                                                     (0xFFFFFF80UL)  /**< 31-reserved*/
#define BMA_INT_STATUS_BMA_AHB_ERROR_STATUS_POS                                                          (6UL)
#define BMA_INT_STATUS_BMA_AHB_ERROR_STATUS_MASK                                                         (0x00000040UL)  /**< 6-status of functional interrupt AHB slave error*/
#define BMA_INT_STATUS_BMA_ADDR_RANGE_ERROR_STATUS_POS                                                   (5UL)
#define BMA_INT_STATUS_BMA_ADDR_RANGE_ERROR_STATUS_MASK                                                  (0x00000020UL)  /**< 5-status of functional interrupt Absolute address incompatible with SRAM mapping*/
#define BMA_INT_STATUS_RESERVED1_POS                                                                     (4UL)
#define BMA_INT_STATUS_RESERVED1_MASK                                                                    (0x00000010UL)  /**< 4-reserved*/
#define BMA_INT_STATUS_RESERVED2_POS                                                                     (3UL)
#define BMA_INT_STATUS_RESERVED2_MASK                                                                    (0x00000008UL)  /**< 3-reserved*/
#define BMA_INT_STATUS_RESERVED3_POS                                                                     (2UL)
#define BMA_INT_STATUS_RESERVED3_MASK                                                                    (0x00000004UL)  /**< 2-reserved*/
#define BMA_INT_STATUS_CLIF_SYS_ERROR_STATUS_POS                                                         (1UL)
#define BMA_INT_STATUS_CLIF_SYS_ERROR_STATUS_MASK                                                        (0x00000002UL)  /**< 1-status of functional interrupt System error in Contactless interface*/
#define BMA_INT_STATUS_HOSTIF_SYS_ERROR_STATUS_POS                                                       (0UL)
#define BMA_INT_STATUS_HOSTIF_SYS_ERROR_STATUS_MASK                                                      (0x00000001UL)  /**< 0-status of functional interrupt System error in Host interface*/
/**
* @}
*/

/**
* @name bma_int_clr_status
* <b>Reset value:</b>
* <b>Access:</b> w-
* @{
*/
#define BMA_INT_CLR_STATUS                                                                                0x75
#define BMA_INT_CLR_STATUS_RESERVED_POS                                                                  (7UL)
#define BMA_INT_CLR_STATUS_RESERVED_MASK                                                                 (0xFFFFFF80UL)  /**< 31-reserved*/
#define BMA_INT_CLR_STATUS_BMA_AHB_ERROR_CLR_STATUS_POS                                                  (6UL)
#define BMA_INT_CLR_STATUS_BMA_AHB_ERROR_CLR_STATUS_MASK                                                 (0x00000040UL)  /**< 6-clr of functional interrupt AHB slave error*/
#define BMA_INT_CLR_STATUS_BMA_ADDR_RANGE_ERROR_CLR_STATUS_POS                                           (5UL)
#define BMA_INT_CLR_STATUS_BMA_ADDR_RANGE_ERROR_CLR_STATUS_MASK                                          (0x00000020UL)  /**< 5-clr of functional interrupt Absolute address incompatible with SRAM mapping*/
#define BMA_INT_CLR_STATUS_RESERVED1_POS                                                                 (4UL)
#define BMA_INT_CLR_STATUS_RESERVED1_MASK                                                                (0x00000010UL)  /**< 4-reserved*/
#define BMA_INT_CLR_STATUS_RESERVED2_POS                                                                 (3UL)
#define BMA_INT_CLR_STATUS_RESERVED2_MASK                                                                (0x00000008UL)  /**< 3-reserved*/
#define BMA_INT_CLR_STATUS_RESERVED3_POS                                                                 (2UL)
#define BMA_INT_CLR_STATUS_RESERVED3_MASK                                                                (0x00000004UL)  /**< 2-reserved*/
#define BMA_INT_CLR_STATUS_CLIF_SYS_ERROR_CLR_STATUS_POS                                                 (1UL)
#define BMA_INT_CLR_STATUS_CLIF_SYS_ERROR_CLR_STATUS_MASK                                                (0x00000002UL)  /**< 1-clr of functional interrupt System error in Contactless interface*/
#define BMA_INT_CLR_STATUS_HOSTIF_SYS_ERROR_CLR_STATUS_POS                                               (0UL)
#define BMA_INT_CLR_STATUS_HOSTIF_SYS_ERROR_CLR_STATUS_MASK                                              (0x00000001UL)  /**< 0-clr of functional interrupt System error in Host interface*/
/**
* @}
*/

/**
* @name clif_ss_tx1_rtrans0
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_RTRANS0                                                                               0x80
#define CLIF_SS_TX1_RTRANS0_R                                                                               0x80
#define CLIF_SS_TX1_RTRANS0_W                                                                               0x80
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS3_POS                                                           (24UL)
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS3_MASK                                                          (0xFF000000UL)  /**< 24-TX1 rising transition value 3*/
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS2_POS                                                           (16UL)
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS2_MASK                                                          (0x00FF0000UL)  /**< 16-TX1 rising transition value 2*/
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS1_POS                                                           (8UL)
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS1_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 rising transition value 1*/
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS0_POS                                                           (0UL)
#define CLIF_SS_TX1_RTRANS0_TX1_SS_RTRANS0_MASK                                                          (0x000000FFUL)  /**< 0-TX1 rising transition value 0*/
#define CLIF_SS_TX1_RTRANS0__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_rtrans1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_RTRANS1                                                                               0x81
#define CLIF_SS_TX1_RTRANS1_R                                                                               0x81
#define CLIF_SS_TX1_RTRANS1_W                                                                               0x81
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS7_POS                                                           (24UL)
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS7_MASK                                                          (0xFF000000UL)  /**< 24-TX1 rising transition value 7*/
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS6_POS                                                           (16UL)
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS6_MASK                                                          (0x00FF0000UL)  /**< 16-TX1 rising transition value 6*/
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS5_POS                                                           (8UL)
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS5_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 rising transition value 5*/
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS4_POS                                                           (0UL)
#define CLIF_SS_TX1_RTRANS1_TX1_SS_RTRANS4_MASK                                                          (0x000000FFUL)  /**< 0-TX1 rising transition value 4*/
#define CLIF_SS_TX1_RTRANS1__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_rtrans2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_RTRANS2                                                                               0x82
#define CLIF_SS_TX1_RTRANS2_R                                                                               0x82
#define CLIF_SS_TX1_RTRANS2_W                                                                               0x82
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS11_POS                                                          (24UL)
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS11_MASK                                                         (0xFF000000UL)  /**< 24-TX1 rising transition value 11*/
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS10_POS                                                          (16UL)
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS10_MASK                                                         (0x00FF0000UL)  /**< 16-TX1 rising transition value 10*/
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS9_POS                                                           (8UL)
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS9_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 rising transition value 9*/
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS8_POS                                                           (0UL)
#define CLIF_SS_TX1_RTRANS2_TX1_SS_RTRANS8_MASK                                                          (0x000000FFUL)  /**< 0-TX1 rising transition value 8*/
#define CLIF_SS_TX1_RTRANS2__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_rtrans3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_RTRANS3                                                                               0x83
#define CLIF_SS_TX1_RTRANS3_R                                                                               0x83
#define CLIF_SS_TX1_RTRANS3_W                                                                               0x83
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS15_POS                                                          (24UL)
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS15_MASK                                                         (0xFF000000UL)  /**< 24-TX1 rising transition value 15*/
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS14_POS                                                          (16UL)
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS14_MASK                                                         (0x00FF0000UL)  /**< 16-TX1 rising transition value 14*/
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS13_POS                                                          (8UL)
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS13_MASK                                                         (0x0000FF00UL)  /**< 8-TX1 rising transition value 13*/
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS12_POS                                                          (0UL)
#define CLIF_SS_TX1_RTRANS3_TX1_SS_RTRANS12_MASK                                                         (0x000000FFUL)  /**< 0-TX1 rising transition value 12*/
#define CLIF_SS_TX1_RTRANS3__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_rtrans0
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_RTRANS0                                                                               0x84
#define CLIF_SS_TX2_RTRANS0_R                                                                               0x84
#define CLIF_SS_TX2_RTRANS0_W                                                                               0x84
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS3_POS                                                           (24UL)
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS3_MASK                                                          (0xFF000000UL)  /**< 24-TX2 rising transition value 3*/
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS2_POS                                                           (16UL)
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS2_MASK                                                          (0x00FF0000UL)  /**< 16-TX2 rising transition value 2*/
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS1_POS                                                           (8UL)
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS1_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 rising transition value 1*/
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS0_POS                                                           (0UL)
#define CLIF_SS_TX2_RTRANS0_TX2_SS_RTRANS0_MASK                                                          (0x000000FFUL)  /**< 0-TX2 rising transition value 0*/
#define CLIF_SS_TX2_RTRANS0__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_rtrans1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_RTRANS1                                                                               0x85
#define CLIF_SS_TX2_RTRANS1_R                                                                               0x85
#define CLIF_SS_TX2_RTRANS1_W                                                                               0x85
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS7_POS                                                           (24UL)
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS7_MASK                                                          (0xFF000000UL)  /**< 24-TX2 rising transition value 7*/
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS6_POS                                                           (16UL)
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS6_MASK                                                          (0x00FF0000UL)  /**< 16-TX2 rising transition value 6*/
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS5_POS                                                           (8UL)
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS5_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 rising transition value 5*/
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS4_POS                                                           (0UL)
#define CLIF_SS_TX2_RTRANS1_TX2_SS_RTRANS4_MASK                                                          (0x000000FFUL)  /**< 0-TX2 rising transition value 4*/
#define CLIF_SS_TX2_RTRANS1__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_rtrans2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_RTRANS2                                                                               0x86
#define CLIF_SS_TX2_RTRANS2_R                                                                               0x86
#define CLIF_SS_TX2_RTRANS2_W                                                                               0x86
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS11_POS                                                          (24UL)
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS11_MASK                                                         (0xFF000000UL)  /**< 24-TX2 rising transition value 11*/
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS10_POS                                                          (16UL)
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS10_MASK                                                         (0x00FF0000UL)  /**< 16-TX2 rising transition value 10*/
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS9_POS                                                           (8UL)
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS9_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 rising transition value 9*/
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS8_POS                                                           (0UL)
#define CLIF_SS_TX2_RTRANS2_TX2_SS_RTRANS8_MASK                                                          (0x000000FFUL)  /**< 0-TX2 rising transition value 8*/
#define CLIF_SS_TX2_RTRANS2__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_rtrans3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_RTRANS3                                                                               0x87
#define CLIF_SS_TX2_RTRANS3_R                                                                               0x87
#define CLIF_SS_TX2_RTRANS3_W                                                                               0x87
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS15_POS                                                          (24UL)
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS15_MASK                                                         (0xFF000000UL)  /**< 24-TX2 rising transition value 15*/
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS14_POS                                                          (16UL)
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS14_MASK                                                         (0x00FF0000UL)  /**< 16-TX2 rising transition value 14*/
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS13_POS                                                          (8UL)
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS13_MASK                                                         (0x0000FF00UL)  /**< 8-TX2 rising transition value 13*/
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS12_POS                                                          (0UL)
#define CLIF_SS_TX2_RTRANS3_TX2_SS_RTRANS12_MASK                                                         (0x000000FFUL)  /**< 0-TX2 rising transition value 12*/
#define CLIF_SS_TX2_RTRANS3__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_ftrans0
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_FTRANS0                                                                               0x88
#define CLIF_SS_TX1_FTRANS0_R                                                                               0x88
#define CLIF_SS_TX1_FTRANS0_W                                                                               0x88
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS3_POS                                                           (24UL)
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS3_MASK                                                          (0xFF000000UL)  /**< 24-TX1 falling transition value 3*/
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS2_POS                                                           (16UL)
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS2_MASK                                                          (0x00FF0000UL)  /**< 16-TX1 falling transition value 2*/
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS1_POS                                                           (8UL)
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS1_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 falling transition value 1*/
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS0_POS                                                           (0UL)
#define CLIF_SS_TX1_FTRANS0_TX1_SS_FTRANS0_MASK                                                          (0x000000FFUL)  /**< 0-TX1 falling transition value 0*/
#define CLIF_SS_TX1_FTRANS0__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_ftrans1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_FTRANS1                                                                               0x89
#define CLIF_SS_TX1_FTRANS1_R                                                                               0x89
#define CLIF_SS_TX1_FTRANS1_W                                                                               0x89
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS7_POS                                                           (24UL)
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS7_MASK                                                          (0xFF000000UL)  /**< 24-TX1 falling transition value 7*/
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS6_POS                                                           (16UL)
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS6_MASK                                                          (0x00FF0000UL)  /**< 16-TX1 falling transition value 6*/
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS5_POS                                                           (8UL)
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS5_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 falling transition value 5*/
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS4_POS                                                           (0UL)
#define CLIF_SS_TX1_FTRANS1_TX1_SS_FTRANS4_MASK                                                          (0x000000FFUL)  /**< 0-TX1 falling transition value 4*/
#define CLIF_SS_TX1_FTRANS1__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_ftrans2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_FTRANS2                                                                               0x8A
#define CLIF_SS_TX1_FTRANS2_R                                                                               0x8A
#define CLIF_SS_TX1_FTRANS2_W                                                                               0x8A
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS11_POS                                                          (24UL)
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS11_MASK                                                         (0xFF000000UL)  /**< 24-TX1 falling transition value 11*/
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS10_POS                                                          (16UL)
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS10_MASK                                                         (0x00FF0000UL)  /**< 16-TX1 falling transition value 10*/
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS9_POS                                                           (8UL)
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS9_MASK                                                          (0x0000FF00UL)  /**< 8-TX1 falling transition value 9*/
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS8_POS                                                           (0UL)
#define CLIF_SS_TX1_FTRANS2_TX1_SS_FTRANS8_MASK                                                          (0x000000FFUL)  /**< 0-TX1 falling transition value 8*/
#define CLIF_SS_TX1_FTRANS2__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx1_ftrans3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX1_FTRANS3                                                                               0x8B
#define CLIF_SS_TX1_FTRANS3_R                                                                               0x8B
#define CLIF_SS_TX1_FTRANS3_W                                                                               0x8B
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS15_POS                                                          (24UL)
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS15_MASK                                                         (0xFF000000UL)  /**< 24-TX1 falling transition value 15*/
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS14_POS                                                          (16UL)
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS14_MASK                                                         (0x00FF0000UL)  /**< 16-TX1 falling transition value 14*/
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS13_POS                                                          (8UL)
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS13_MASK                                                         (0x0000FF00UL)  /**< 8-TX1 falling transition value 13*/
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS12_POS                                                          (0UL)
#define CLIF_SS_TX1_FTRANS3_TX1_SS_FTRANS12_MASK                                                         (0x000000FFUL)  /**< 0-TX1 falling transition value 12*/
#define CLIF_SS_TX1_FTRANS3__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_ftrans0
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_FTRANS0                                                                               0x8C
#define CLIF_SS_TX2_FTRANS0_R                                                                               0x8C
#define CLIF_SS_TX2_FTRANS0_W                                                                               0x8C
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS3_POS                                                           (24UL)
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS3_MASK                                                          (0xFF000000UL)  /**< 24-TX2 falling transition value 3*/
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS2_POS                                                           (16UL)
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS2_MASK                                                          (0x00FF0000UL)  /**< 16-TX2 falling transition value 2*/
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS1_POS                                                           (8UL)
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS1_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 falling transition value 1*/
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS0_POS                                                           (0UL)
#define CLIF_SS_TX2_FTRANS0_TX2_SS_FTRANS0_MASK                                                          (0x000000FFUL)  /**< 0-TX2 falling transition value 0*/
#define CLIF_SS_TX2_FTRANS0__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_ftrans1
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_FTRANS1                                                                               0x8D
#define CLIF_SS_TX2_FTRANS1_R                                                                               0x8D
#define CLIF_SS_TX2_FTRANS1_W                                                                               0x8D
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS7_POS                                                           (24UL)
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS7_MASK                                                          (0xFF000000UL)  /**< 24-TX2 falling transition value 7*/
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS6_POS                                                           (16UL)
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS6_MASK                                                          (0x00FF0000UL)  /**< 16-TX2 falling transition value 6*/
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS5_POS                                                           (8UL)
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS5_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 falling transition value 5*/
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS4_POS                                                           (0UL)
#define CLIF_SS_TX2_FTRANS1_TX2_SS_FTRANS4_MASK                                                          (0x000000FFUL)  /**< 0-TX2 falling transition value 4*/
#define CLIF_SS_TX2_FTRANS1__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/

/**
* @name clif_ss_tx2_ftrans2
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_FTRANS2                                                                               0x8E
#define CLIF_SS_TX2_FTRANS2_R                                                                               0x8E
#define CLIF_SS_TX2_FTRANS2_W                                                                               0x8E
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS11_POS                                                          (24UL)
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS11_MASK                                                         (0xFF000000UL)  /**< 24-TX2 falling transition value 11*/
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS10_POS                                                          (16UL)
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS10_MASK                                                         (0x00FF0000UL)  /**< 16-TX2 falling transition value 10*/
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS9_POS                                                           (8UL)
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS9_MASK                                                          (0x0000FF00UL)  /**< 8-TX2 falling transition value 9*/
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS8_POS                                                           (0UL)
#define CLIF_SS_TX2_FTRANS2_TX2_SS_FTRANS8_MASK                                                          (0x000000FFUL)  /**< 0-TX2 falling transition value 8*/
#define CLIF_SS_TX2_FTRANS2__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/


/**
* @name clif_ss_tx2_ftrans3
* <b>Reset value:</b> 0x00000000
* <b>Access:</b> rw
* @{
*/
#define CLIF_SS_TX2_FTRANS3                                                                               0x8F
#define CLIF_SS_TX2_FTRANS3_R                                                                               0x8F
#define CLIF_SS_TX2_FTRANS3_W                                                                               0x8F
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS15_POS                                                          (24UL)
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS15_MASK                                                         (0xFF000000UL)  /**< 24-TX2 falling transition value 15*/
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS14_POS                                                          (16UL)
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS14_MASK                                                         (0x00FF0000UL)  /**< 16-TX2 falling transition value 14*/
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS13_POS                                                          (8UL)
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS13_MASK                                                         (0x0000FF00UL)  /**< 8-TX2 falling transition value 13*/
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS12_POS                                                          (0UL)
#define CLIF_SS_TX2_FTRANS3_TX2_SS_FTRANS12_MASK                                                         (0x000000FFUL)  /**< 0-TX2 falling transition value 12*/
#define CLIF_SS_TX2_FTRANS3__RESET_VALUE                                                                 (0x00000000UL)  /**< value after reset*/
/**
* @}
*/
/** @} */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* _PN76_CLIF_REGDEFS_H */
