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
 *
 * Implementation of Secure Key Mode (SKM) Interfaces for for non-secure code execution.
 *
 * $Author: $
 * $Revision: $
 *
 */

#ifndef _PN76_SKM_H_
#define _PN76_SKM_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/

#include "ph_Datatypes.h"
#include "PN76_Status.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

/** @addtogroup PN76SYSHALSKM
 *
 * @brief System Services for Secure Key Mode functionality
 *
 * This module briefs all the interfaces of Secure Key Mode module.
 *
 * \section SKM_INTRO Introduction
 PN76xx IC and software provides storing of symmetric keys securely which are encrypted and stored either
 in secure key store IP within the IC (where in the either secure-CPU or non-secure CPU) does not have the access to the keys, instead
 a secure gateway interface IP has.

 PN76xx IC and software also provides a secure key storage extension, where in the few symmetric keys and asymmetric private keys
 are encrypted and stored in the secure flash, where in only the secure-CPU has access to the encrypted key.

 In order to access the Secure Key Mode system services, the application should first initialize the SKM and avail the different
 services of key provisioning.

 The key provisioning operations are always protected by an session authentication of existing key in the IC using the challenge-response method.

 The secure key mode also performs the key integrity check and provides the necessary information to the application so that remedial actions performed by the application.

 There are different types of keys supported in the PN76xx secure key mode. They are described as below:

 
 * \section SKM_KEY_TYPE Different KEY types
 NXP KEY management system on the IC has following key types:
 * \subsection SKM_KEY_TYPE_TPT NXP_TPT_KEY
 Both 128-bit and 256-bit symmetric keys are by default provisioned in the NXP factory in each of the IC.
 Each IC will come with a documentation of the NXP Transport key programmed in it.
 The host must be authenticate itself first to operate on the keys present in the IC.
 These keys are stored in secure key storage enclave, where no CPU have access to it.

 * \subsection SKM_KEY_TYPE_APP_ROOT APP_ROOT_KEY
 These Application root keys which are provisioned in-place of NXP_TPT_KEYs for both 128-bit and 256-bit symmetric key.
 These keys are the application root keys which can be provisioned as long as these are not locked out for provisioning.
 Once these keys are provisioned, the NXP_TPT_KEY will no longer be present in the IC.
 Once the customer application development is complete and ready for roll out, customer can lock the APP_ROOT_KEYs from further provisioning.
 These keys are stored in secure key storage enclave, where no CPU have access to it.

 * \subsection SKM_KEY_TYPE_APP_MASTER APP_MASTER_KEY
 Upto 13 128-bit keys OR upto 6 256-bit symmetric keys can be stored.
 These keys are derived from the NXP_TPT_KEY or APP_ROOT_KEY and are stored  in the secure storage enclave.
 A mix of 128-bit and 256-bit keys can also be stored.
 A 128-bit key takes only one KeyIndex to store, where as 256-bit key takes two KeyIndexes to store. 256-bit keys are always stored at even numbered KeyIndex + next KeyIndex.
 These keys are stored in secure key storage enclave, where no CPU have access to it.

 * \note  This type of Key will always derived from APP_ROOT_KEY_128 or APP_ROOT_KEY_256 (if the APP_ROOT_KEYs are provisioned) otherwise are derived from NXP_TPT_KEY_128 or NXP_TPT_KEY_256.
 It is advised that application should provision the APP_ROOT_KEY first before provisioning the APP_MASTER_KEY, 
 as the derivation of this key is dependent upon the key present in KeyIndex 00 (for 128-bit key) or 02&03 (for 256-bit key).
 \nOnly this key type must be used when encryption/decryption operations tobe carried using the MBED APIs. 
 The encryption/decryption key derivation is done from this key with a derivation message stored in a configuration parameter. 
 \nPlease refer EEPROM configuration of \ref PN76_SKM_EncrDecrDerMsg

 * \subsection SKM_KEY_TYPE_APP_FIXED APP_FIXED_KEY
 These are symmetric keys of 128-bit or 256-bit key. These are stored in the secure key store extension (secure flash).
 Only the encrypted keydata and wrapping key derivation message is stored in secure flash.

 * \note  This type of Key is always decrypted with the wrapping key from APP_ROOT_KEY_128/APP_ROOT_KEY_256 (if provisioned) or
 NXP_TPT_KEY_128/NXP_TPT_KEY_256 with the provided encrypted data.
 It is advised that application should provision the APP_ROOT_KEY first before provisioning the APP_FIXED_KEY, 
 as the derivation of this key is dependent upon the key present in KeyIndex 00 (for 128-bit key) or 02&03 (for 256-bit key).

 * \note Only this key type must be used when encryption/decryption operations tobe carried using the MBED APIs. 
 The APP_FIXED_KEY shall be directly used and there is no derivation required for encryption/decryption operations.
 * \subsection SKM_KEY_TYPE_APP_ASYMM APP_ASYMM_KEY
 The asymmetric keys (private key) are stored in the secure flash (Key Store Extension). Asymmetric private key is encrypted and stored.

 * \note  The asymmetric key is encrypted using ECB encryption on 128-bit APP_ROOT_KEY (if provisioned), otherwise 128-bit NXP_TPT_KEY is used.
 It is advised that application should provision the APP_ROOT_KEY first before provisioning the APP_ASYMM_KEY, 
 as the derivation of this key is dependent upon the key present in KeyIndex 00 (which is nothing but 128-bit NXP_TPT_KEY if APP_ROOT_KEY is not provisioned,
 or 128-bit APP_ROOT_KEY if it is provisioned). 
 \nPlease refer EEPROM configuration of \ref PN76_SKM_Asym_KeyDerMsg

 * \section SKM_KEY_MAP KeyStore map of PN76xx device
 * \subsection SKM_KEY_MAP_DEF Default PN76xx KeyStore Map
 Default PN76xx KeyStore map 
 The diagram below shows the default keystore map on PN76xx device, which contains the NXP_TPT_KEY for 128-bit and 256-bit provisioned.

 |KeyIndex  |      KEY Data        |     Description                    |                                                  |
 |-------- :|: ------------------: | :--------------------------------: | :----------------------------------------------- |
 |  00      |   NXP_TPT_KEY_128    |  128-bit NXP Transport Key data    | Keys stored in PN76xx Secure Key Store enclave. For storing 256-bit key, two KeyIndexes are used and must provide even numbered KeyIndex |
 |  01      |                      |  Free for APP_MASTER_KEY           | ^                                                |
 |  02      |   NXP_TPT_KEY_256    |  256-bit NXP Transport Key data    | ^                                                |
 |  03      |   NXP_TPT_KEY_256    |  256-bit NXP Transport Key data    | ^                                                |
 |  04      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  05      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  15      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  16      |           :          |  Free for APP_FIXED_KEY            | Encrypted fixed keys stored in PN76xx Secure Flash. 128-bit or 256-bit key can be stored in one KeyIndex. |
 |  17      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |   :      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |  26      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |  27      |           :          |  Free for APP_ASYMM_KEY            | Encrypted Asymmetric keys stored in PN76xx Secure Flash. 256-bit or 384-bit key can be stored in one KeyIndex. |
 |   :      |           :          |  Free for APP_ASYMM_KEY            | ^                                                |
 |  33      |           :          |  Free for APP_ASYMM_KEY            | ^                                                |

 * \subsection SKM_KEY_MAP_APP Keystore map after APP_ROOT_KEYs are provisioned
 Default PN76xx KeyStore map 
 The diagram below shows the keystore map on PN76xx device, after APP_ROOT_KEY (both 128-bit and 256-bit) are provisioned.

 |KeyIndex  |      KEY Data        |     Description                    |                                                  |
 |-------- :|: ------------------: | :--------------------------------: | :----------------------------------------------- |
 |  00      |   APP_ROOT_KEY_128   |  128-bit APP_ROOT_KEY data         | Keys stored in PN76xx Secure Key Store enclave. For storing 256-bit key, two KeyIndexes are used and must provide even numbered KeyIndex |
 |  01      |                      |  Free for APP_MASTER_KEY           | ^                                                |
 |  02      |   APP_ROOT_KEY_256   |  256-bit APP_ROOT_KEY data         | ^                                                |
 |  03      |   APP_ROOT_KEY_256   |  256-bit APP_ROOT_KEY data         | ^                                                |
 |  04      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  05      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |   :      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  15      |           :          |  Free for APP_MASTER_KEY           | ^                                                |
 |  16      |           :          |  Free for APP_FIXED_KEY            | Encrypted fixed keys stored in PN76xx Secure Flash. 128-bit or 256-bit key can be stored in one KeyIndex. |
 |  17      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |   :      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |  26      |           :          |  Free for APP_FIXED_KEY            | ^                                                |
 |  27      |           :          |  Free for APP_ASYMM_KEY            | Encrypted Asymmetric keys stored in PN76xx Secure Flash. 256-bit or 384-bit key can be stored in one KeyIndex. |
 |   :      |           :          |  Free for APP_ASYMM_KEY            | ^                                                |
 |  33      |           :          |  Free for APP_ASYMM_KEY            | ^                                                |


 * \section SKM_INFO_API Important information of Secure Key Mode APIs
 * \subsection INFO_CLOSE_SESSION Sessions
 In order to work with the keys, you have to open the session to work on corresponding keys using \ref PN76_Sys_SKM_OpenSession() everytime.
 Once the key operation is complete regardless of its successfull execution, the session to work on the corresponding key will closed automatically.
 Only exceptions are the APIs \ref PN76_Sys_SKM_Get_SKM_Info().
 When operating on ASYMM keys, and when session is opened, the domain parameters information is reset. You have to set the domain parameters using 
 \ref PN76_Sys_SKM_AsymmKey_SetDP().

 * @{
 *
 */
#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

#define ASYMM_PVT_KEY_LENGTH_P256   (32)    /**< Definition of private key length for 256-bit key */
#define ASYMM_PVT_KEY_LENGTH_P384   (48)    /**< Definition of private key length for 384-bit key */

#define ASYMM_PUB_KEY_LENGTH_P256   (64)    /**< Definition of public key length for corresponding 256-bit private key */
#define ASYMM_PUB_KEY_LENGTH_P384   (96)    /**< Definition of public key length for corresponding 384-bit private key */

#define ASYMM_DOMAIN_PARAMS_LEN_P256    (32)/**< Definition for domain parameter length for a 256-bit private key */
#define ASYMM_DOMAIN_PARAMS_LEN_P384    (48)/**< Definition for domain parameter length for a 384-bit private key */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/** @brief This structure contains the data required to be provided to open session to operate on application keys */
typedef struct {
    uint8_t bId;                       /**< Reserved. Value not considered */
    uint8_t bSubId;                    /**< Reserved. Value not considered */
    uint8_t bAuthType;                 /**< Session Type

                                            |Values  |      Description
                                            |--------|: --------------------------------------------------------------------
                                            |0x00    | for operating on APP_ROOT_KEYs.
                                            |0x01    | for operating on APP_MASTER_KEYs/APP_FIXED_KEYs
                                            |0x02    | for operating on APP_ASYMM_KEYs
                                            |0x03    | for purging application keys
                                            |Other   | Invalid
                                        */
    uint8_t bKeyLen;                   /**< Authenticate session with which key.

                                            |Values  |      Description
                                            |--------|: --------------------------------------------------------------------
                                            |0x00    | Authenticating with 128-bit Symmetric Key.
                                            |0x01    | Authenticating with 256-bit Symmetric Key
                                            |Other   | Invalid
                                        */
    uint32_t adwDerivMsgDecryptKey[6]; /**< Derivation message for generating a encryption/decryption key from provisioned NXP_TPT_KEY or APP_ROOT_KEY (if it was provisioned earlier).
                                            \note Should be provided in Little-endian format */
    uint8_t abEncryptedData[16];       /**< Encrypted data with the encryption key - Challenge */
    uint8_t abExpDecryptedData[16];    /**< Expected decrypted data - Response */
} PN76_SKM_Data_OpenSession_t;

/** @brief This structure contains the data required to be provided for provisioning the APP_ROOT_KEYs */
typedef struct {
    uint8_t bId;                       /**< Reserved. Value not considered */
    uint8_t bSubId;                    /**< Reserved. Value not considered */
    uint8_t bRfu;                      /**< Reserved. Value not considered */
    uint8_t bKeyLen;                   /**< Provisioning key length :

                                            |Values  |      Description
                                            |--------|: --------------------------------------------------------------------
                                            |0x00    | Provisioning 128-bit Symmetric Key.
                                            |0x01    | Provisioning 256-bit Symmetric Key
                                            |Other   | Invalid
                                        */
    uint32_t adwDerivMsgWrappingKey[6];/**< Derivation message to derive a wrapping key from existing NXP_TPT_KEY or APP_ROOT_KEY (if it was provisioned earlier)
                                            \note Should be provided in Little-endian format */
    uint32_t adwWrappedData[20];       /**< Encrypted APP_ROOT_KEY data
                                            \note Should be provided in Little-endian format */
} PN76_SKM_Data_RootKey_t;

/** @brief This structure contains the data required to be provided for provisioning or updating of APP_MASTER_KEYs */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_MASTER_KEY to be provisioned or to be updated.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x01      | Only 128-bit symmetric key can be provisioned/updated.
                                           |0x04-0x0F | For 256-bit Symmetric Key provisioning/updating only even number should be provided.
                                           |Other     | Invalid
                                       */
   uint8_t bKeyLen;                    /**< APP_MASTER_KEY key length :
   
                                           |Values  |      Description
                                           |--------|: --------------------------------------------------------------------
                                           |0x00    | 128-bit Symmetric Key.
                                           |0x01    | 256-bit Symmetric Key
                                           |Other   | Invalid
                                       */
   uint32_t adwDerivMsgNewKey[6];      /**< Derivation message to derive the APP_MASTER_KEY from NXP_TPT_KEY or APP_ROOT_KEY (if it is provisioned earlier)
                                           \note Should be provided in Little-endian format */
} PN76_SKM_Data_ProvUpd_MasterKey_t;

/** @brief This structure contains the data required to be provided for provisioning or updating of APP_FIXED_KEYs */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_FIXED_KEY to be provisioned or to be updated.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x10-0x1A | Key index for 128-bit/256-bit FIXED key provisioning or updating
                                           |Other     | Invalid
                                       */
   uint8_t bKeyLen;                    /**< Provisioning key length :
   
                                           |Values  |      Description
                                           |--------|: --------------------------------------------------------------------
                                           |0x00    | Provisioning 128-bit Symmetric Key.
                                           |0x01    | Provisioning 256-bit Symmetric Key
                                           |Other   | Invalid
                                       */
   uint32_t adwDerivMsgWrappingKey[6];/**< Derivation message to derive a wrapping key from existing NXP_TPT_KEY or APP_ROOT_KEY (if it was provisioned earlier)
                                           \note Should be provided in Little-endian format */
   uint32_t adwWrappedData[20];       /**< Encrypted APP_FIXED_KEY data
                                           \note Should be provided in Little-endian format */
} PN76_SKM_Data_ProvUpd_FixedKey_t;

/** @brief This structure contains the data required to be provided for deleting the application keys */
typedef struct {
    uint8_t bId;                       /**< Reserved. Value not considered */
    uint8_t bSubId;                    /**< Reserved. Value not considered */
    uint8_t bKeyId;                    /**< Key Index where the existing key (APP_MASTER_KEY or APP_FIXED_KEY) to be deleted.
                                            |Values    |      Description
                                            |----------|: --------------------------------------------------------------------
                                            |0x01      | Key index
                                            |0x04-0x1A | Key index
                                            |Other     | Invalid
                                        */
    uint8_t bRfu;                      /**< Reserved. Value not considered */
} PN76_SKM_Data_Delete_Key_t;

/** @brief This structure contains the data required to be provided for locking the APP_ROOT_KEY of given key length from further provisioning */
typedef struct {
    uint8_t bId;                       /**< Reserved. Value not considered */
    uint8_t bSubId;                    /**< Reserved. Value not considered */
    uint8_t bRfu;                      /**< Reserved. Value not considered */
    uint8_t bKeyLen;                   /**< APP_ROOT_KEY length to be locked from further provisioning.
                                        
                                            |Values  |      Description
                                            |--------|: --------------------------------------------------------------------
                                            |0x00    | 128-bit Symmetric Key.
                                            |0x01    | 256-bit Symmetric Key
                                        */
} PN76_SKM_Data_LockRootKey_t;

/** @brief This structure provides the data retrieved from the Secure Key Mode status information */
typedef struct {
    uint32_t dwRfu;                    /**< Reserved. Value not considered */
    uint8_t  bSessionStatus;           /**< SKM session open status.
                                            
                                            |Bits  | Values   |     Description
                                            |------|: -------:| :--------------------------------------------------------------
                                            |[0]   |   0x00   | Session to operate on APP_ROOT_KEY is not open 
                                            |      |   0x01   | Session to operate on APP_ROOT_KEY is open  
                                            |[1]   |   0x00   | Session to operate on APP_MASTER_KEY/APP_FIXED_KEY is not open
                                            |      |   0x01   | Session to operate on APP_MASTER_KEY/APP_FIXED_KEY is open
                                            |[2]   |   0x00   | Session to operate on APP_ASYMM_KEY is not open
                                            |      |   0x01   | Session to operate on APP_ASYMM_KEY is open
                                            |[7:3] |   0x00   | Reserved for future use.
                                       */
    uint8_t  bSkmState;                /**< Secure Key Mode locked out status.

                                            |Bits  | Values   |     Description
                                            |------|: -------:| :--------------------------------------------------------------
                                            |[0]   |   0x00   | SKM is not locked.
                                            |^     |   0x01   | SKM is locked. Application will not be able to operate on application keys.
                                            |[3:1] |   0x00   | Reserved for future use.
                                            |[5:4] |   0x00   | Application root key 128-bit is not provisioned.
                                            |^     |   0x01   | Application root key 128-bit is provisioned.
                                            |^     |   0x02   | Application root key 128-bit is locked from further provisioning.
                                            |^     |   0x03   | Application keys are purged.
                                            |[7:6] |   0x00   | Application root key 256-bit is not provisioned.
                                            |^     |   0x01   | Application root key 256-bit is provisioned.
                                            |^     |   0x02   | Application root key 256-bit is locked from further provisioning.
                                            |^     |   0x03   | Application keys are purged.
                                       */
    uint8_t  bSkmIntgStatus;           /**< SKM Key storage area anti-tearing and rollback status.

                                            |bits  |  Values  |                    Description
                                            |------|: -------:| :------------------------------------------------------------------
                                            |[0]   |   0x00   | Indicates that successfull rollback or restore of the keys.
                                            |^     |   0x01   | Indicates that rollback or restore of the keys failed.
                                            |[3:2] |   0x00   | Invalid value. This should not occur.
                                            |^     |   0x03   | Indicates that keys are stored successfully in the HW key store.
                                            |^     |   0x01   | Indicates that last set of keys (APP_ROOT_KEY or APP_MASTER_KEY or NXP_TPT_KEY) were not stored properly.
                                            |^     |   0x02   | Invalid value. This should not occur.
                                            |[7:4] |   0x00   | No area is corrupted
                                            |^     |   0x01   | Primary area corrupted. If rollback/restore is successfull, the SKM contains the previous status of keys.
                                            |^     |   0x02   | Secondary area corrupted. If rollback/restore is successfull, the SKM contains the present status of keys (new provioned keys).
                                            |^     |   0x04   | Both Primary and Secondary area corrupted. Reverting to factory default settings. All application keys are lost.
                                       */
    uint8_t  bSkmAsymmDpStatus;        /**< SKM Asymmetric key domain parameters present set condition

                                            |bits  |  Values  |                    Description
                                            |------|: -------:| :------------------------------------------------------------------
                                            |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                            |^     |   0x02   | Key curve and key length. SECP384R1
                                            |^     |   0x03   | Key curve and key length. BP256R1
                                            |^     |   0x04   | Key curve and key length. BP384R1
                                            |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                            |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                            |^     |   Other  | Invalid
                                            |[5:4] |   0x00   | Reserved. Value not considered
                                            |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                            |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                            |[7]   |   0x00   | Domain parameters were not set
                                            |^     |   0x01   | Domain parameters were set
                                       */
    uint32_t dwCounter;                /**< The Counter value indicated for the next authentication. This value must be used by the host to encrypt the challenge with the key derived from NXP_TPT_KEY or APP_ROOT_KEY with a derivation message as provided in the \ref PN76_Sys_SKM_OpenSession and the last 4-bytes used would be this Counter (in Little Endian format) */
} PN76_SKM_Data_SKM_Info_t;

/** @brief Generic structure for Secure Key Mode */
typedef struct {
    uint8_t bId;                       /**< Reserved. Value not considered */
    uint8_t bSubId;                    /**< Reserved. Value not considered */
    uint8_t bRfu0;                     /**< Reserved. Value not considered */
    uint8_t bRfu1;                     /**< Reserved. Value not considered */
} PN76_SKM_Data_Generic_t;


/** @brief This structure contains the data required to be provided for provisioning of generated APP_ASYMM_KEY */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_ASYMM_KEY to be provisioned.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x1B-0x21 | Key ID of Asymmetric Key
                                           |Other     | Invalid
                                       */
   uint8_t bKeyCfg;                    /**< APP_ASYMM_KEYs key configuration :
   
                                           |bits  |  Values  |                    Description
                                           |------|: -------:| :------------------------------------------------------------------
                                           |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                           |^     |   0x02   | Key curve and key length. SECP384R1
                                           |^     |   0x03   | Key curve and key length. BP256R1
                                           |^     |   0x04   | Key curve and key length. BP384R1
                                           |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                           |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                           |^     |   Other  | Invalid
                                           |[5:4] |   0x00   | Reserved. Value not considered
                                           |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                           |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                           |[7]   |   0x00   | No return of PUB key corresponding to the private key
                                           |^     |   0x01   | Return of PUB key corresponding to the private key

                                       */
} PN76_SKM_Data_AsymmKey_Prov_t;

/** @brief This structure contains the data required to be provided for provisioning of APP_ASYMM_KEY which is provided in plain */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_ASYMM_KEY to be provisioned.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x1B-0x21 | Key ID of Asymmetric Key
                                           |Other     | Invalid
                                       */
   uint8_t bKeyCfg;                    /**< APP_ASYMM_KEYs key configuration :
   
                                           |bits  |  Values  |                    Description
                                           |------|: -------:| :------------------------------------------------------------------
                                           |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                           |^     |   0x02   | Key curve and key length. SECP384R1
                                           |^     |   0x03   | Key curve and key length. BP256R1
                                           |^     |   0x04   | Key curve and key length. BP384R1
                                           |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                           |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                           |^     |   Other  | Invalid
                                           |[5:4] |   0x00   | Reserved. Value not considered
                                           |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                           |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                           |[7]   |   0x00   | No return of PUB key corresponding to the private key
                                           |^     |   0x01   | Return of PUB key corresponding to the private key

                                       */
   union {                     
      uint8_t abPvtKey_256[ASYMM_PVT_KEY_LENGTH_P256];  /**< plain private key of 256-bit key length */
      uint8_t abPvtKey_384[ASYMM_PVT_KEY_LENGTH_P384];  /**< plain private key of 384-bit key length */
   } PvtKey;    /**< Private key in plain to be provisioned */
} PN76_SKM_Data_AsymmKey_Plain_Prov_t;


/** @brief This structure contains the data required to be provided for provisioning of APP_ASYMM_KEY which is provided in plain */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_ASYMM_KEY to be provisioned.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x1B-0x21 | Key ID of Asymmetric Key
                                           |Other     | Invalid
                                       */
   uint8_t bKeyCfg;                    /**< APP_ASYMM_KEYs key configuration :
   
                                           |bits  |  Values  |                    Description
                                           |------|: -------:| :------------------------------------------------------------------
                                           |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                           |^     |   0x02   | Key curve and key length. SECP384R1
                                           |^     |   0x03   | Key curve and key length. BP256R1
                                           |^     |   0x04   | Key curve and key length. BP384R1
                                           |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                           |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                           |^     |   Other  | Invalid
                                           |[5:4] |   0x00   | Reserved. Value not considered
                                           |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                           |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                           |[7]   |   0x00   | No return of PUB key corresponding to the private key
                                           |^     |   0x01   | Return of PUB key corresponding to the private key

                                       */
   uint32_t adwDerivMsgNewKey[6];      /**< Derivation message to derive the encrypted key from APP_ROOT_KEY (128-bit) to decrypt provided encrypted private key
                                            \note Should be provided in Little-endian format */
   union {
      uint8_t abPvtKey_256_Encry[ASYMM_PVT_KEY_LENGTH_P256];    /**< encrypted private key of 256-bit key length */
      uint8_t abPvtKey_384_Encry[ASYMM_PVT_KEY_LENGTH_P384];    /**< encrypted private key of 384-bit key length */
   } PvtKey;                           /**< Private key in encrypted format to be provisioned */
} PN76_SKM_Data_AsymmKey_Encry_Prov_t;


/** @brief This structure contains the data required to be provided for deleting a provisioned APP_ASYMM_KEY */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index where the APP_ASYMM_KEY to be deleted.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x1B-0x21 | Key ID of Asymmetric Key
                                           |Other     | Invalid
                                       */
   uint8_t bRfu0;                      /**< Reserved. Value not considered */
} PN76_SKM_Data_AsymmKey_Delete_t;

/** @brief This structure contains the data required to be provided for getting the public key for the provisioned APP_ASYMM_KEY */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bRfu0;                      /**< Reserved. Value not considered */
   uint8_t bKeyCfg;                    /**< APP_ASYMM_KEYs key configuration :
   
                                           |bits  |  Values  |                    Description
                                           |------|: -------:| :------------------------------------------------------------------
                                           |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                           |^     |   0x02   | Key curve and key length. SECP384R1
                                           |^     |   0x03   | Key curve and key length. BP256R1
                                           |^     |   0x04   | Key curve and key length. BP384R1
                                           |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                           |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                           |^     |   Other  | Invalid
                                           |[5:4] |   0x00   | Reserved. Value not considered
                                           |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                           |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                           |[7]   |   0x00   | Reserved. Value not considered
                                       */
    union {                            /**< union of domian parameters for the private key */
       struct {
           uint8_t abDP_P256_P[ASYMM_DOMAIN_PARAMS_LEN_P256];   /**< Domain parameters for 256-bit key - P */
           uint8_t abDP_P256_A[ASYMM_DOMAIN_PARAMS_LEN_P256];   /**< Domain parameters for 256-bit key - A */
           uint8_t abDP_P256_B[ASYMM_DOMAIN_PARAMS_LEN_P256];   /**< Domain parameters for 256-bit key - B */
           uint8_t abDP_P256_N[ASYMM_DOMAIN_PARAMS_LEN_P256];   /**< Domain parameters for 256-bit key - N */
           uint8_t abDP_P256_G[ASYMM_DOMAIN_PARAMS_LEN_P256 * 2];   /**< Domain parameters for 256-bit key - G */
       } DP_P256;                      /**< structure for domain parameters for 256-bit private key */
       struct {
           uint8_t abDP_P384_P[ASYMM_DOMAIN_PARAMS_LEN_P384];   /**< Domain parameters for 384-bit key - P */
           uint8_t abDP_P384_A[ASYMM_DOMAIN_PARAMS_LEN_P384];   /**< Domain parameters for 384-bit key - A */
           uint8_t abDP_P384_B[ASYMM_DOMAIN_PARAMS_LEN_P384];   /**< Domain parameters for 384-bit key - B */
           uint8_t abDP_P384_N[ASYMM_DOMAIN_PARAMS_LEN_P384];   /**< Domain parameters for 384-bit key - N */
           uint8_t abDP_P384_G[ASYMM_DOMAIN_PARAMS_LEN_P384 * 2];   /**< Domain parameters for 384-bit key - G */
       } DP_P384;                      /**< structure for domain parameters for 384-bit private key */
    } DP;                              /**< union of domain parameters for 256-bit and 384-bit private key */
                                       
} PN76_SKM_Data_AsymmKey_SetDP_t;


/** @brief This structure contains the data required to be provided for getting the public key for the provisioned APP_ASYMM_KEY */
typedef struct {
   uint8_t bId;                        /**< Reserved. Value not considered */
   uint8_t bSubId;                     /**< Reserved. Value not considered */
   uint8_t bKeyId;                     /**< Key Index from where public key of provisioned APP_ASYMM_KEY to be returned.

                                           |Values    |      Description
                                           |----------|: --------------------------------------------------------------------
                                           |0x1B-0x21 | Key ID of Asymmetric Key
                                           |Other     | Invalid
                                       */
   uint8_t bRfu0;                      /**< Reserved. Value not considered */
} PN76_SKM_Data_AsymmKey_GetPubKey_t;


/** @brief This structure contains the data returned from respective APIs for public key corresponding to the private key */
typedef struct {
   uint32_t dwRfu;                     /**< Reserved */
   uint8_t bKeyId;                     /**< Key Index of APP_ASYMM_KEY used to generate the public key. */
   uint8_t bKeyCfg;                    /**< Provided public APP_ASYMM_KEYs key configuration :
   
                                           |bits  |  Values  |                    Description
                                           |------|: -------:| :------------------------------------------------------------------
                                           |[3:0] |   0x01   | Key curve and key length. SECP256R1
                                           |^     |   0x02   | Key curve and key length. SECP384R1
                                           |^     |   0x03   | Key curve and key length. BP256R1
                                           |^     |   0x04   | Key curve and key length. BP384R1
                                           |^     |   0x05   | Key curve and key length for a custom curve using ecc.
                                           |^     |   0x06   | Key curve and key length. EDDSA 256-bit length
                                           |^     |   Other  | Invalid
                                           |[5:4] |   0x00   | Reserved. Value not considered
                                           |[6]   |   0x00   | Key length in case of key curve is set to Custom. Indicates 256-bit key
                                           |^     |   0x01   | Key length in case of key curve is set to Custom. Indicates 384-bit key
                                           |[7]   |   0x00   | Reserved. Value not considered

                                       */
   union {
      uint8_t abPubKey_256[ASYMM_PUB_KEY_LENGTH_P256];  /**< contains the public key corresponding to 256-bit private key */
      uint8_t abPubKey_384[ASYMM_PUB_KEY_LENGTH_P384];  /**< contains the public key corresponding to 384-bit private key */
   } PubKey;                           /**< public key corresponds to the private key */
} PN76_SKM_Data_AsymmKey_Pub_t;

/*****************************************************************************
 * Public functions declarations
 ****************************************************************************/

/*!
 * @brief   This API will initialize the Secure Key Store for PN76xx IC.
 *
 * @param   *pKeyStoreStat   Pointer to uint8_t that contains the keystore status.
 *
 * @retval  PN76_STATUS_SUCCESS When Secure Key Store is initialized.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    This API must be called whenever Secure Key Mode operations and/or mbed related APIs are called.
 * After this API is called, please check the Key Store status as below to proceed further on key store access.
 *
                                         |bits  |  Values  |                    Description                                                 
                                         |-----:|: -------:| :-----------------------------------------------------------------------------
                                         |[0]   |   0x00   | Indicates that successfull rollback or restore of the keys.
                                         |^     |   0x01   | Indicates that rollback or restore of the keys failed.
                                         |[3:2] |   0x00   | Invalid value. This should not occur.
                                         |^     |   0x03   | Indicates that keys are stored successfully in the HW key store.
                                         |^     |   0x01   | Indicates that last set of keys (APP_ROOT_KEY or APP_MASTER_KEY or NXP_TPT_KEY) were not stored properly.
                                         |^     |   0x02   | Invalid value. This should not occur.
                                         |[7:4] |   0x00   | No area is corrupted
                                         |^     |   0x01   | Primary area corrupted. If rollback/restore is successfull, the SKM contains the previous status of keys.
                                         |^     |   0x02   | Secondary area corrupted. If rollback/restore is successfull, the SKM contains the present status of keys (new provioned keys).
                                         |^     |   0x04   | Both Primary and Secondary area corrupted. Reverting to factory default settings. All application keys are lost.
 *
 */
PN76_Status_t PN76_Sys_KeyStore_Init(
    uint8_t *pKeyStoreStat
    );

/*!
 * @brief   This API will De-initialize the Secure Key Store.
 *
 * @note    When exiting the Secure Key Store service or completed using the mbed crypto services, 
            this API must be called.
 *
 * @retval  PN76_STATUS_SUCCESS When successfull.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 */
PN76_Status_t PN76_Sys_KeyStore_DeInit( void );



/*!
 * @brief   This API will initialize the Secure Key Mode for key provisioning
 *          functionality. Secure Key Mode will be active until \ref PN76_Sys_SKM_DeInit is called.
 *
 * @note    This API must be called whenever Secure Key Mode operations need to be carried out.
 * @note    When this API is called, whatever previous sessions opened, will be closed.
 *
 * @retval  PN76_STATUS_SUCCESS When Secure Key Mode is initialized.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc SKM_Init
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Init()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "PN76 SKM mode initialized" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Init() returns"];
    APP_NS box APP_NS               [ label = "Check the parameter value for SKM integrity check. If all is well, the SKM is initialized"];

@endmsc
 */
PN76_Status_t PN76_Sys_SKM_Init( void );

/*!
 * @brief   This API will De-initialize the Secure Key Mode from key provisioning. Once this function
 *          is called, the Secure Key Mode will not be active for key provisioning.
 *
 * @note    When exiting the Secure Key Mode for provisioning, this API must be called.
 * @note    When this API is called, whatever sessions were opened, will be closed.
 *
 * @retval  PN76_STATUS_SUCCESS When Secure Key Mode is initialized.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc SKM_DeInit
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_DeInit()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "PN76 SKM mode De initialized" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_DeInit() returns"];

@endmsc
 */
PN76_Status_t PN76_Sys_SKM_DeInit( void );


/*!
 * @brief   This API will open a Secure Key Mode session for different operations on the application keys.
 *          This API must be called before performing any operations on the application keys.
 *
 * @note    After a number of unsuccessful execution of this API in challenge-response
 *          (PN76xx decrypted data does not match with the provided expected decrypted data),
 *          the Secured Key Mode will be locked forever for further key operations.
 *          Only \ref PN76_Sys_SKM_Get_SKM_Info API is valid when Secure Key Mode is locked out.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_OpenSession_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  Secure Key mode provisioning session is open to operate on application keys
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc SKM_OpenSession
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that SKM is already initialized by calling PN76_Sys_SKM_Init()", URL="\ref PN76_Sys_SKM_Init()" ] ;
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Get_SKM_Info()" ] ;
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Init() returns"];
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_OpenSession_t() structure with corresponding values (bAuthType=0x00), challenge and response values for corresponding dwCounter from SKM_Info structure available from PN76_Sys_SKM_Get_SKM_Info()", URL="\ref PN76_Sys_SKM_Get_SKM_Info()"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_OpenSession()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "PN76 SKM session opened for operating on APP_ROOT_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_OpenSession() returns"];
    APP_NS box APP_NS               [ label = "Now the session is open to provision the APP_ROOT_KEY"];

@endmsc
    *
 */
PN76_Status_t PN76_Sys_SKM_OpenSession(
            PN76_SKM_Data_OpenSession_t *pSkmData
            );

/*!
 * @brief   This API will provision the APP_ROOT_KEY of given key length. It wil generate a wrapping key
 *          from the provisioned NXP_TPT_KEY or earlier provisioned APP_ROOT_KEY and decrypt the actual
 *          APP_ROOT_KEY and provision it in PN76xx secure key store.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_RootKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ROOT_KEY of given key length is provisioned successfully.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Prov_App_RootKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ROOT_KEY using PN76_Sys_SKM_OpenSession()", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_RootKey_t() structure with corresponding values for APP_ROOT_KEY 128-bit provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_RootKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "128-bit APP_ROOT_KEY is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ROOT_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_RootKey() returns"];
    APP_NS box APP_NS               [ label = "Now the 128-bit APP_ROOT_KEY is provisioned (if successful)"];

    APP_NS box APP_NS               [ label = "Now again the open session for working on APP_ROOT_KEY as per the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ];

    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_RootKey_t() structure with corresponding values for APP_ROOT_KEY 256-bit provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_RootKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "256-bit APP_ROOT_KEY is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ROOT_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_RootKey() returns"];
    APP_NS box APP_NS               [ label = "Now the 256-bit APP_ROOT_KEY is provisioned (if successful)"];

@endmsc
    *

 */
PN76_Status_t PN76_Sys_SKM_Prov_App_RootKey(
            PN76_SKM_Data_RootKey_t *pSkmData
            );

/*!
 * @brief   This API will provision the APP_MASTER_KEY in the provided key index with provided key length.
 *          The APP_MASTER_KEY will be derived from APP_ROOT_KEY with the derivation message provided in the parameter structure
 *          and provisions in the PN76xx secure key store.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_ProvUpd_MasterKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_MASTER_KEY of given key length is provisioned successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Prov_App_MasterKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_ProvUpd_MasterKey_t() structure with corresponding values for APP_MASTER_KEY (128-bit or 256-bit) provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_MasterKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_MASTER_KEY (128-bit or 256-bit) is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_MasterKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_MASTER_KEY is provisioned (if successful)"];

@endmsc
  *
  */
PN76_Status_t PN76_Sys_SKM_Prov_App_MasterKey(
            PN76_SKM_Data_ProvUpd_MasterKey_t *pSkmData
            );

/*!
 * @brief   This API will update the provisioned APP_MASTER_KEY with a new APP_MASTER_KEY in the provided key index.
 *          The new APP_MASTER_KEY will be derived from APP_ROOT_KEY with the derivation message provided in the parameter structure
 *          and provisions in the PN76xx secure key store.
 *
 * @note    The updated APP_MASTER_KEY will be provisioned is of same key length only.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_ProvUpd_MasterKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  New APP_MASTER_KEY is updated successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Update_App_MasterKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_ProvUpd_MasterKey_t() structure with corresponding values for APP_MASTER_KEY (128-bit or 256-bit) updation "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Update_App_MasterKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_MASTER_KEY (128-bit or 256-bit) is updated (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Update_App_MasterKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_MASTER_KEY is updated (if successful)"];

@endmsc

 */
PN76_Status_t PN76_Sys_SKM_Update_App_MasterKey(
            PN76_SKM_Data_ProvUpd_MasterKey_t *pSkmData
            );

/*!
 * @brief   This API will delete the provisioned APP_MASTER_KEY from the given key index.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_Delete_Key_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_MASTER_KEY in the given key index is deleted successfully.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Delete_App_MasterKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_Delete_Key_t() structure with corresponding values for APP_MASTER_KEY (128-bit or 256-bit) to be deleted "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Delete_App_MasterKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_MASTER_KEY (128-bit or 256-bit) is deleted (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Delete_App_MasterKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_MASTER_KEY is deleted (if successful)"];

@endmsc
 */
PN76_Status_t PN76_Sys_SKM_Delete_App_MasterKey(
            PN76_SKM_Data_Delete_Key_t *pSkmData
            );

/*!
 * @brief   This API will provision the APP_FIXED_KEY in the provided key index with provided key length.
 *          The APP_FIXED_KEY will be unwrapped from the given encrypted key data provided in the parameter structure
 *          and stored in the PN76xx secure key store.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_ProvUpd_FixedKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_FIXED_KEY of given key length is provisioned successfully in the provided key index.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Prov_App_FixedKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_ProvUpd_FixedKey_t() structure with corresponding values for APP_FIXED_KEY (128-bit or 256-bit) provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_FixedKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_FIXED_KEY (128-bit or 256-bit) is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Prov_App_FixedKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_FIXED_KEY is provisioned (if successful)"];

@endmsc
 *
 */
PN76_Status_t PN76_Sys_SKM_Prov_App_FixedKey(
            PN76_SKM_Data_ProvUpd_FixedKey_t *pSkmData
            );

/*!
 * @brief   This API will update the provisioned APP_FIXED_KEY with a new APP_FIXED_KEY in the provided key index.
 *          The new APP_FIXED_KEY will be unwrapped from the given encrypted key data provided in the parameter structure
 *          and stored in the PN76xx secure key store.
 *
 * @note    The updated APP_FIXED_KEY will be provisioned is of same key length only.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_ProvUpd_FixedKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  New APP_FIXED_KEY is updated successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Update_App_FixedKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_ProvUpd_FixedKey_t() structure with corresponding values for APP_FIXED_KEY (128-bit or 256-bit) updation "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Update_App_FixedKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_FIXED_KEY (128-bit or 256-bit) is updated (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Update_App_FixedKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_FIXED_KEY is updated (if successful)"];

@endmsc


 *
 */
PN76_Status_t PN76_Sys_SKM_Update_App_FixedKey(
            PN76_SKM_Data_ProvUpd_FixedKey_t *pSkmData
            );

/*!
 * @brief   This API will delete the provisioned APP_FIXED_KEY from the given key index.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_Delete_Key_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_FIXED_KEY in the given key index is deleted successfully.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Delete_App_FixedKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_MASTER_KEY/APP_FIXED_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_Delete_Key_t() structure with corresponding values for APP_FIXED_KEY (128-bit or 256-bit) to be deleted "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Delete_App_FixedKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_FIXED_KEY (128-bit or 256-bit) is deleted (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_MASTER_KEY/APP_FIXED_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Delete_App_FixedKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_FIXED_KEY is deleted (if successful)"];

@endmsc
 *
 */
PN76_Status_t PN76_Sys_SKM_Delete_App_FixedKey(
            PN76_SKM_Data_Delete_Key_t *pSkmData
            );

/*!
 * @brief   This API will lock the APP_ROOT_KEY of given key length in the parameter data from further provisioning.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_LockRootKey_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ROOT_KEY of given key length is locked successfully from further provisioning.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Lock_App_RootKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ROOT_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_LockRootKey_t() structure with corresponding values for APP_ROOT_KEY (128-bit or 256-bit) to be locked from further provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Lock_App_RootKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_ROOT_KEY (128-bit or 256-bit) is locked from further provisioning (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ROOT_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Lock_App_RootKey() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_ROOT_KEY is locked (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_Lock_App_RootKey(
            PN76_SKM_Data_LockRootKey_t *pSkmData
            );

/*!
 * @brief   This API will get the Secure Key Mode information such as session status for key provisioning, lock status 
 *          SKM integrity status and the domain parameter status for asymmetric keys. It also contians the counter value
 *          that is used to provide the encrypted data during opening of session to work on the keys.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_SKM_Info_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  Secure Key Mode session data, lock status etc.. are retrieved successfully and stored in the parameter.
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Get_SKM_Info
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "For this API, it does not matter whether the session is opened or not, but but SKM should be initialized", URL="\ref PN76_Sys_SKM_Init()" ] ;
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Get_SKM_Info()" ] ;
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Get_SKM_Info() returns"];
    APP_NS box APP_NS               [ label = "Now the information regarding the SKM is stored in the parameter (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_Get_SKM_Info(
            PN76_SKM_Data_SKM_Info_t *pSkmData
            );



/*!
 * @brief   This API will destroy all the APP_ROOT_KEYs and APP_MASTER_KEYs which are stored in secure key store.
 *
 * @retval  PN76_STATUS_SUCCESS  When the application keys are destroyed..
 * @retval  Other values Indicates an error occurred. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc Get_SKM_Info
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ROOT_KEY purging using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_Purge_AppKeys()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "All application keys are purged or destroyed." ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on application keys purging" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_Purge_AppKeys() returns"];
    APP_NS box APP_NS               [ label = "All application keys are purged. (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_Purge_AppKeys( void );


/*!
 * @brief   This API will provision the generated APP_ASYMM_KEY (Private) in the provided key index with provided key configuration.
 *          Generated public key for the private key will be returned as part of the parameter.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Prov_t containing the input data required for this API.
 * @param   *pPubKeyData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Pub_t where pub key related data is stored
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ASYMM_KEY (private) of given key configuration is provisioned successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc AsymmKey_Prov_PvtKey_Gen
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Assuming that the domain parameters for the asymmetric key is already been set using PN76_Sys_SKM_AsymmKey_SetDP() API", URL="\ref PN76_Sys_SKM_AsymmKey_SetDP()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_Prov_t() structure with corresponding values for APP_ASYMM_KEY provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Gen()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_ASYMM_KEY is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ASYMM_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Gen() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_ASYMM_KEY is provisioned (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Gen(
            PN76_SKM_Data_AsymmKey_Prov_t *pSkmData,
            PN76_SKM_Data_AsymmKey_Pub_t *pPubKeyData
            );


/*!
 * @brief   This API will provision the given plain APP_ASYMM_KEY (Private) in the provided key index with provided key configuration.
 *          Generated public key for the private key will be returned as part of the parameter.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Plain_Prov_t containing the input data required for this API.
 * @param   *pPubKeyData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Pub_t where pub key related data is stored
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ASYMM_KEY (private) of given key configuration is provisioned successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc AsymmKey_Prov_PvtKey_Plain
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Assuming that the domain parameters for the asymmetric key is already been set using PN76_Sys_SKM_AsymmKey_SetDP() API", URL="\ref PN76_Sys_SKM_AsymmKey_SetDP()"  ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_Plain_Prov_t() structure with corresponding values for APP_ASYMM_KEY provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Plain()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_ASYMM_KEY is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ASYMM_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Plain() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_ASYMM_KEY is provisioned (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Plain(
            PN76_SKM_Data_AsymmKey_Plain_Prov_t *pSkmData,
            PN76_SKM_Data_AsymmKey_Pub_t *pPubKeyData
            );

/*!
 * @brief   This API will provision the given encrypted APP_ASYMM_KEY (Private) in the provided key index with provided key configuration.
 *          The given encrypted private key will be decrypted using a key derived from APP_ROOT_KEY (128-bit) with the derivation message
 *          provided in the parameter. The ECB encryption scheme should be used to encrypt the private APP_ASYMM_KEY.
 *          Generated public key for the private key will be returned as part of the parameter.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Encry_Prov_t containing the input data required for this API.
 * @param   *pPubKeyData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Pub_t where pub key related data is stored
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ASYMM_KEY (private) of given key configuration is provisioned successfully in the provided key index.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc AsymmKey_Prov_PvtKey_Encry
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Assuming that the domain parameters for the asymmetric key is already been set using PN76_Sys_SKM_AsymmKey_SetDP() API", URL="\ref PN76_Sys_SKM_AsymmKey_SetDP()"  ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_Encry_Prov_t() structure with corresponding values for APP_ASYMM_KEY provisioning "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Encry()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_ASYMM_KEY is provisioned (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ASYMM_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Encry() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_ASYMM_KEY is provisioned (if successful)"];

@endmsc
 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_Prov_PvtKey_Encry(
            PN76_SKM_Data_AsymmKey_Encry_Prov_t *pSkmData,
            PN76_SKM_Data_AsymmKey_Pub_t *pPubKeyData
            );


/*!
 * @brief   This API delete the APP_ASYMM_KEY (Private) in the provided key index from key store.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Delete_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ASYMM_KEY (private) in the provided key index is deleted.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc AsymmKey_Delete
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_Delete_t() structure with corresponding values for deleting APP_ASYMM_KEY "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Delete()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "APP_ASYMM_KEY is deleted (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ASYMM_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_Delete() returns"];
    APP_NS box APP_NS               [ label = "Now the desired APP_ASYMM_KEY is deleted (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_Delete(
            PN76_SKM_Data_AsymmKey_Delete_t *pSkmData
            );

/*!
 * @brief   This API will set the domain parameters required for the asymmetric key.
 * @note    The provided domain parameters data must not be altered until the required provisioning of pvt key or getting the pub key operation is completed.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_SetDP_t containing the input data required for this API.
 *
 * @retval  PN76_STATUS_SUCCESS  Domain parameters were set properly.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
@msc AsymmKey_SetDP
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_SetDP_t() structure with corresponding values of domain parameters for given key curve "];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_SetDP()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Domain parameters are stored in SKM (if successful)" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_SetDP() returns"];
    APP_NS box APP_NS               [ label = "Now the desired domain parameters were set (if successful)"];

@endmsc
 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_SetDP(
            PN76_SKM_Data_AsymmKey_SetDP_t *pSkmData
            );

/*!
 * @brief   This API will generate the pub key of the provisioned APP_ASYMM_KEY (Private) in the provided key index. 
 *          Generated public key for the private key will be returned as part of the parameter.
 *
 * @param   *pSkmData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_GetPubKey_t containing the input data required for this API.
 * @param   *pPubKeyData   Pointer to structure \ref PN76_SKM_Data_AsymmKey_Pub_t where pub key related data is stored
 *
 * @retval  PN76_STATUS_SUCCESS  APP_ASYMM_KEY (public) of given key configuration is generated successfully and returned as part of the parameter.
 * @retval  Other values Indicates an error occured. Please refer to \ref PN76_Status_t enum.
 *
 * @note    Typical flow to use this API
 *
@msc AsymmKey_GetPubKey
# Options section
    hscale = "2";

# The entities
    APP_NS, PN76xx_SECURE;

# Arcs
    APP_NS box APP_NS [label="Non-Secure App", textbgcolour="#7fff7f"],
    PN76xx_SECURE box PN76xx_SECURE [label="PN76xx_Secure IC execution", textbgcolour="#7fff7f"];

# Small gap before the boxes
    |||;

# Next four on same line due to ','
    APP_NS box APP_NS               [ label = "Assuming that Session is already opened for working on APP_ASYMM_KEY using the flow in PN76_Sys_SKM_OpenSession() API", URL="\ref PN76_Sys_SKM_OpenSession()" ] ;
    APP_NS box APP_NS               [ label = "Assuming that the domain parameters for the asymmetric key is already been set using PN76_Sys_SKM_AsymmKey_SetDP() API", URL="\ref PN76_Sys_SKM_AsymmKey_SetDP()"  ] ;
    APP_NS box APP_NS               [ label = "Fill PN76_SKM_Data_AsymmKey_GetPubKey_t() structure with corresponding values of asymmetric key for which public key to be get"];
    APP_NS=>PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_GetPubKey()" ] ;
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Public key corresponding the private key is stored in the parameter (if successful)" ];
    PN76xx_SECURE=>PN76xx_SECURE    [ label = "Session is closed for working on APP_ASYMM_KEY" ];
    APP_NS<=PN76xx_SECURE           [ label = "PN76_Sys_SKM_AsymmKey_GetPubKey() returns"];
    APP_NS box APP_NS               [ label = "Now the public key for the corresponding key is stored in the parameter  (if successful)"];

@endmsc

 *
 */
PN76_Status_t PN76_Sys_SKM_AsymmKey_GetPubKey(
            PN76_SKM_Data_AsymmKey_GetPubKey_t *pSkmData,
            PN76_SKM_Data_AsymmKey_Pub_t *pPubKeyData
            );


#ifdef __cplusplus
}
#endif



/** @} */

#endif /* _PN76_SKM_H_ */


