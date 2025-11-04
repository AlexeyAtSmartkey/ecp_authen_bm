/*----------------------------------------------------------------------------*/
/* Copyright 2006-2024 NXP                                                    */
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
* Generic KeyStore Component of Reader Library Framework.
* $Author: NXP $
* $Revision: $ (v07.10.00)
* $Date: $
*
*/

#ifndef PHKEYSTORE_H
#define PHKEYSTORE_H

#include <ph_Status.h>

#ifdef __cplusplus
extern "C" {
#endif  /* __cplusplus */

#ifdef NXPBUILD__PH_KEYSTORE_SW

/**
 * \defgroup phKeyStore_Sw Component : Software
 * \brief KeyStore implementation in Software.
 * @{
 */

#define PH_KEYSTORE_SW_ID                                       0x01U   /**< ID for Software KeyStore component. */


#ifndef NXPBUILD__PH_KEYSTORE_ASYM
#define PH_KEYSTORE_SW_MAX_KEY_SIZE                             32U     /**< Maximum size of a Symmetric Key. */
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */

#define PH_KEYSTORE_MAX_KEY_SIZE                                PH_KEYSTORE_SW_MAX_KEY_SIZE

/** \brief Software KeyVersionPair structure for Symmetric and ASymmetric keys. */
typedef struct
{
    uint8_t pKey[PH_KEYSTORE_MAX_KEY_SIZE];                             /**< Array containing a Symmetric Key or ASymmetric Private Key. */
    uint16_t wVersion;                                                  /**< Versions related to the Symmetric Key. Not applicable for ASymmetric keys storage. */

} phKeyStore_Sw_KeyVersionPair_t;

/** \brief Software KeyEntry structure. */
typedef struct
{
    uint16_t wKeyType;                                                  /**< Type of the keys in \ref phKeyStore_Sw_KeyVersionPair_t. */
    uint16_t wRefNoKUC;                                                 /**< Key usage counter number of the keys in pKeys. */
} phKeyStore_Sw_KeyEntry_t;

/** \brief Software KeyUsageCounter structure. */
typedef struct
{
    uint32_t dwLimit;                                                   /**< Limit of the Key Usage Counter. */
    uint32_t dwCurVal;                                                  /**< Current Value of the KUC. */
} phKeyStore_Sw_KUCEntry_t;

/** \brief Software parameter structure. */
typedef struct
{
    uint16_t  wId;                                                      /**< Layer ID for this component, NEVER MODIFY! */
    phKeyStore_Sw_KeyEntry_t * pKeyEntries;                             /**< Key entry storage, size = sizeof(#phKeyStore_Sw_KeyEntry_t) * wNumKeyEntries. */
    phKeyStore_Sw_KeyVersionPair_t * pKeyVersionPairs;                  /**< Key version pairs, size = sizeof(#phKeyStore_Sw_KeyVersionPair_t)* wNumKeyEntries * wNumVersions. */
    uint16_t wNoOfKeyEntries;                                           /**< Number of key entries in that storage. */
    uint16_t wNoOfVersions;                                             /**< Number of versions in each key entry. */
    phKeyStore_Sw_KUCEntry_t * pKUCEntries;                             /**< Key usage counter entry storage, size = sizeof(#phKeyStore_Sw_KUCEntry_t) * wNumKUCEntries. */
    uint16_t wNoOfKUCEntries;                                           /**< Number of Key usage counter entries. */
} phKeyStore_Sw_DataParams_t;

/**
 * \brief Initializes the KeyStore component as software component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phKeyStore_Sw_Init(
        phKeyStore_Sw_DataParams_t * pDataParams,                       /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                     /**< [In] Specifies the size of the data parameter structure. */
        phKeyStore_Sw_KeyEntry_t * pKeyEntries,                         /**< [In] Pointer to a storage containing the key entries. */
        uint16_t wNoOfKeyEntries,                                       /**< [In] Size of pKeyEntries. */
        phKeyStore_Sw_KeyVersionPair_t * pKeyVersionPairs,              /**< [In] Pointer to a storage containing the key version pairs. */
        uint16_t wNoOfVersionPairs,                                     /**< [In] Amount of key versions available in each key entry. */
        phKeyStore_Sw_KUCEntry_t * pKUCEntries,                         /**< [In] Key usage counter entry storage, size = sizeof(phKeyStore_Sw_KUCEntry_t) * wNumKUCEntries */
        uint16_t wNoOfKUCEntries                                        /**< [In] Number of Key usage counter entries. */
    );

/**
 * end of group phKeyStore_Sw
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE_SW */

#ifdef NXPBUILD__PH_KEYSTORE_RC663

#include <phhalHw.h>

/**
 * \defgroup phKeyStore_Rc663 Component : Rc663
 * @{
 */
#define PH_KEYSTORE_RC663_ID                                    0x02U   /**< ID for Rc663 KeyStore component. */
#define PH_KEYSTORE_RC663_NUM_KEYS                              0x80U   /**< Maximum number of keys storable in Rc663. */
#define PH_KEYSTORE_RC663_NUM_VERSIONS                          0x01U   /**< Amount of versions for each key entry in the key store. */

/** \brief Rc663 parameter structure. */
typedef struct
{
    uint16_t  wId;                                                      /**< Layer ID for this component, NEVER MODIFY! */
    void * pHalDataParams;                                              /**< Pointer to the parameter structure of the underlying layer. */
} phKeyStore_Rc663_DataParams_t;

/**
 * \brief Initializes the KeyStore component as RC663 component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phKeyStore_Rc663_Init(
        phKeyStore_Rc663_DataParams_t * pDataParams,                    /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                     /**< [In] Specifies the size of the data parameter structure. */
        void * pHalDataParams                                           /**< [In] Pointer to a HAL based on NXP RC663 IC. */
    );

/**
 * end of group phKeyStore_Rc663
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE_RC663 */




#ifdef NXPBUILD__PH_KEYSTORE_SAMAV3

#include <phhalHw.h>

#define PH_KEYSTORE_SAMAV3_ID                                       0x06U       /**< ID for SamAV3 KeyStore component. */

/**
 * \defgroup phKeyStore_SamAV3 Component : SamAV3
 * \brief SamAV3 implementation of the phSam interface
 * @{
 */

#define PH_KEYSTORE_SAMAV3_AV2_MODE                                 0x02U       /**< Define the AV2 mode of the KeyStore */
#define PH_KEYSTORE_SAMAV3_AV3_MODE                                 0x03U       /**< Define the AV3 mode of the KeyStore */

/** \name Key Classes. Should be used to set the ExtSET information. */
/** @{ */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_HOST                           0x00U       /**< Configuring key entry as Host. */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_PICC                           0x01U       /**< Configuring key entry as PICC. */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_OFFLINE_CHANGE                 0x02U       /**< Configuring key entry as Offline Change. */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_OFFLINE_CRYPTO                 0x04U       /**< Configuring key entry as Offline Crypto. */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_OFFLINE_UPLOAD                 0x05U       /**< Configuring key entry as Offline Upload. */
#define PH_KEYSTORE_SAMAV3_KEY_CLASS_OFFLINE_PERSO                  0x06U       /**< Configuring key entry as Offline Perso. */
/** @} */

/** \name DES Key Options */
/** @{ */
#define PH_KEYSTORE_SAMAV3_DES_OPTION_DESFIRE4                      0x00U       /**< DESFire 4 compatibility mode. */
#define PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC16                     0x01U       /**< ISO 10116 mode with CRC16 protection and 4 bytes MAC. */
#define PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC32                     0x02U       /**< ISO 10116 mode with CRC32 protection and 8 bytes MAC. */
/** @} */

/** \name KeyStore Configs for SET configurations. */
/** @{ */
#define PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY            0x0000U     /**< Enable or Disable SAM_ChangeKeyMIFARE and SAM_DumpSessionKey command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEEP_IV                           0x0001U     /**< Enable or Disable the reset of init vector after a crypto command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_PL_KEY                            0x0002U     /**< Enable or Disable the Host key type to provide permissions for Cmd.PLExec execution. */
#define PH_KEYSTORE_SAMAV3_CONFIG_AUTH_KEY                          0x0003U     /**< Enable or Disable Host Authentication with key other that MasterKey. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_KEY_ENTRY                 0x0004U     /**< Enable or Disable Key Entry. */
#define PH_KEYSTORE_SAMAV3_CONFIG_LOCK_KEY                          0x0005U     /**< Enable or Disable LockUnlock. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_CHANGE_KEY_PICC           0x0006U     /**< Enable or Disable writing the key to a PICC. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_DECRYPTION                0x0007U     /**< Enable or Disable SAM_DecipherData command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_ENCRYPTION                0x0008U     /**< Enable or Disable SAM_EncipherData command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_VERIFY_MAC                0x0009U     /**< Enable or Disable SAM_VerifyMAC command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DISABLE_GENERATE_MAC              0x000AU     /**< Enable or Disable SAM_GenerateMAC command. */
/** @} */

/** \name KeyStore Configs for ExtSET configurations. */
/** @{ */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYCLASS                          0x000BU     /**< Key Class used in key store. */
#define PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY             0x000CU     /**< Enable or Disable SAM_DumpSecretKey command. */
#define PH_KEYSTORE_SAMAV3_CONFIG_MANDATE_KEY_DIVERSIFICATION       0x000DU     /**< Mandate or not key diversification. */
#define PH_KEYSTORE_SAMAV3_CONFIG_RESERVED_SAM_PRESONALIZATION      0x000EU     /**< Enable or disable the Key Entry for Sam Personalization. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEY_USAGE_INT_HOST                0x000FU     /**< Enable or disable the Key Entry usage by Internal Host. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEY_CHANGE_INT_HOST               0x0010U     /**< Enable or disable the Key Entry change by Internal Host. */
#define PH_KEYSTORE_SAMAV3_CONFIG_SESSION_KEY_USAGE_INT_HOST        0x0011U     /**< Enable or disable the Session Key usage by Internal Host. */
#define PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SECRET_KEY_INT_HOST    0x0012U     /**< Enable or disable the dumping of Secret Key by Internal Host. */
#define PH_KEYSTORE_SAMAV3_CONFIG_ALLOW_DUMP_SESSION_KEY_INT_HOST   0x0013U     /**< Enable or disable the dumping of Session Key by Internal Host. */
/** @} */

/** \name KeyStore Configs for SAM Key Storage Table's Key Entry. */
/** @{ */
#define PH_KEYSTORE_SAMAV3_CONFIG_DF_AID                            0x0014U     /**< DESFire application ID. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DF_KEY_NO                         0x0015U     /**< DESFire key number. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CEK                         0x0016U     /**< Key Number of Change Entry key. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CEK                          0x0017U     /**< Key Version of Change Entry key. */
#define PH_KEYSTORE_SAMAV3_CONFIG_REF_NO_KUC                        0x0018U     /**< Reference number of key usage counter. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_AEK                         0x0019U     /**< Key Number of Access Entry key. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYV_AEK                          0x001AU     /**< Key Version of Access Entry key. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_CKUC                        0x001BU     /**< Key Number of Change KUC. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYV_CKUC                         0x001CU     /**< Key Version of Change KUC. */
#define PH_KEYSTORE_SAMAV3_CONFIG_DES_KEY_OPTION                    0x001DU     /**< Option for single DES and 2 Key Triple DES keys. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_A                    0x001EU     /**< Key Number used for MIFARE key A diversification. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_A                     0x001FU     /**< Key Version used for MIFARE key A diversification. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYNO_MF_DIV_B                    0x0020U     /**< Key Number used for MIFARE key B diversification. */
#define PH_KEYSTORE_SAMAV3_CONFIG_KEYV_MF_DIV_B                     0x0021U     /**< Key Version used for MIFARE key B diversification. */
#define PH_KEYSTORE_SAMAV3_CONFIG_ENABLE_LRP                        0x0022U     /**< The AES key to be used is for LRP algorithm. */
/** @} */

/** \brief Sam parameter structure */
typedef struct
{
    uint16_t  wId;                                                              /**< Layer ID for this component, NEVER MODIFY! */
    phhalHw_SamAV3_DataParams_t * pHalDataParams;                               /**< Pointer to the parameter structure of the underlying layer.*/
    uint8_t aSet[2U];                                                           /**< Configuration settings. */
    uint8_t aExtSet[2U];                                                        /**< Extended configuration settings. */
    uint8_t aDFAid[3U];                                                         /**< DESFire application ID. */
    uint8_t bDFKeyNo;                                                           /**< DESFire key number. */
    uint8_t bKeyNoCEK;                                                          /**< Key Number of Change Entry Key. */
    uint8_t bKeyVCEK;                                                           /**< Key Version of Change Entry Key. */
    uint8_t bRefNoKUC;                                                          /**< Reference number of key usage counter. */
    uint8_t bKeyNoAEK;                                                          /**< Key Number of Access Entry Key. */
    uint8_t bKeyVAEK;                                                           /**< Key Version of Access Entry Key. */
    uint8_t bKeyNoCKUC;                                                         /**< Key Number of Change KUC. */
    uint8_t bKeyVCKUC;                                                          /**< Key Version of Change KUC. */
    uint8_t bKeyNoMfDivA;                                                       /**< Key Number used for MIFARE key A diversification (has to point to a DES key). */
    uint8_t bKeyVMfDivA;                                                        /**< Key Version used for MIFARE key A diversification (has to point to a DES key). */
    uint8_t bKeyNoMfDivB;                                                       /**< Key Number used for MIFARE key B diversification (has to point to a DES key). */
    uint8_t bKeyVMfDivB;                                                        /**< Key Version used for MIFARE key B diversification (has to point to a DES key). */
    uint8_t b2K3DESOption;                                                      /**< Option for single DES and 2 Key Triple DES keys. Can be set either to
                                                                                 *   #PH_KEYSTORE_SAMAV3_DES_OPTION_DESFIRE4, #PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC16
                                                                                 *   or #PH_KEYSTORE_SAMAV3_DES_OPTION_ISO_CRC32
                                                                                 */
    uint8_t bIsLRPKey;                                                          /**< Option for LRP key type. If set indicated that the AES key is of LRP type. */
} phKeyStore_SamAV3_DataParams_t;

/**
 * \brief Initializes the KeyStore component as SAM AV3 component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 */
phStatus_t phKeyStore_SamAV3_Init(
        phKeyStore_SamAV3_DataParams_t * pDataParams,                           /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                             /**< [In] Specifies the size of the data parameter structure. */
        phhalHw_SamAV3_DataParams_t * pHalDataParams                            /**< [In] Pointer to the parameter structure of the underlying layer.*/
    );
/**
 * end of group phKeyStore_SamAV3
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE_SAMAV3 */

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX

/**
 * \defgroup phKeyStore_PN76XX Component : PN76XX
 * \brief PN76XX hardware KeyStore implementation.
 *
 * \note
 *      - It recommended to set the required keys once prior performing other operations.
 *      - This is to avoid increment of hardware counter that is linked to provisioning of keys.
 * @{
 */

#define PH_KEYSTORE_PN76XX_ID                                           0x07U   /**< ID for PN76XX KeyStore component. */
#ifdef NXPBUILD__PHHAL_HW_PN7642
#include <PN76_Status.h>
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

#ifdef NXPBUILD__PHHAL_HW_PN7640
#include <ph_FlashInterface.h>
#endif /* NXPBUILD__PHHAL_HW_PN7640 */

/**
 * \defgroup phKeyStore_PN76XX_Defines Defines
 * \brief PN76XX hardware KeyStore implementation.
 * @{
 */

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX_NDA
/** \defgroup phKeyStore_PN76XX_Defines_Errors ErrorCodes
 * \brief Actual Error codes returned by PN7462 hardware and equivalent mapped
 * error code from Reader Library.
 * @{
 */

/**
 * \defgroup phKeyStore_PN76XX_Defines_ErrorActual Error_Actual
 * \brief Actual error codes returned by PN76XX hardware.
 * @{
 */
#define PH_KEYSTORE_PN76XX_SUCCESS                             PN76_STATUS_SUCCESS                      /**< Success.*/
#define PH_KEYSTORE_PN76XX_ERR_BUSY                            PN76_STATUS_SKM_BUSY                     /**< Secure Key Module Busy Error.*/
#define PH_KEYSTORE_PN76XX_ERR_PARAMETER_ERROR                 PN76_STATUS_SKM_PARAMETER_ERROR          /**< Value to be returned in case of wrong parameter.*/
#define PH_KEYSTORE_PN76XX_ERR_SKTU_ERROR                      PN76_STATUS_SKM_SKTU_ERROR               /**< Secure Key Module Internal SKTU Error.*/
#define PH_KEYSTORE_PN76XX_ERR_SKTU_AUTH_ERROR                 PN76_STATUS_SKM_SKTU_AUTH_ERROR          /**< Authentication Error.*/
#define PH_KEYSTORE_PN76XX_ERR_LOCKED                          PN76_STATUS_SKM_LOCKED                   /**< Secure Key Module Locked Error. */
#define PH_KEYSTORE_PN76XX_ERR_SESSION_NOT_OPEN                PN76_STATUS_SKM_SESSION_NOT_OPEN         /**< SKM Session is not open for provisioning of keys Error.*/
#define PH_KEYSTORE_PN76XX_ERR_KEY_ERROR                       PN76_STATUS_SKM_KEY_ERROR                /**< Key is either already provisioned or not present Error.*/
#define PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_LOCKED             PN76_STATUS_SKM_APP_ROOT_KEY_LOCKED      /**< Provisioning of APP_ROOT_KEY is locked Error.*/
#define PH_KEYSTORE_PN76XX_ERR_NOT_INITIALIZED                 PN76_STATUS_SKM_NOT_INITIALIZED          /**< SKM is not initialized Error.*/
#define PH_KEYSTORE_PN76XX_ERR_INTEGRITY_ERROR                 PN76_STATUS_SKM_INTEGRITY_ERROR          /**< SKM Key configuration integrity Error.*/
#define PH_KEYSTORE_PN76XX_ERR_ASYMM_HW_ACC_ERROR              PN76_STATUS_SKM_ASYMM_HW_ACC_ERROR       /**< Asymmetric key HW acceleration Error.*/
#define PH_KEYSTORE_PN76XX_ERR_DP_NOT_SET                      PN76_STATUS_SKM_DP_NOT_SET               /**< Domain parameters are not set Error.*/

#ifdef NXPBUILD__PHHAL_HW_PN7642
#define PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_PROVISION          PN76_STATUS_SKM_APP_ROOT_KEY_PROVISION   /**< APP_ROOT_KEY provision Error.*/
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

/**
 * end of group phKeyStore_PN76XX_Defines_ErrorActual
 * @}
 */

/**
 * \defgroup phKeyStore_PN76XX_Defines_ErrorMapped Error_Mapped
 * \brief Library mapped error codes with respect to \ref phKeyStore_PN76XX_Defines_ErrorActual "Actual Error" codes.
 * These are the values that will be returned to the user from the interface in case of error.
 * @{
 */
/**
 * \brief Secure Key Module Busy Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_BUSY error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_BUSY                       (PH_ERR_CUSTOM_BEGIN + 0U)

/**
 * \brief Secure Key Module Internal SKTU Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_SKTU_ERROR error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_SKTU_ERROR                 (PH_ERR_CUSTOM_BEGIN + 1U)

/**
 * \brief Secure Key Module Locked Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_LOCKED error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_LOCKED                     (PH_ERR_CUSTOM_BEGIN + 2U)

/**
 * \brief Secure Key Module Session Not open Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_SESSION_NOT_OPEN error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_SESSION_NOT_OPEN           (PH_ERR_CUSTOM_BEGIN + 3U)

/**
 * \brief Secure Key Module Application Root Key locked Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_LOCKED error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_APP_ROOT_KEY_LOCKED        (PH_ERR_CUSTOM_BEGIN + 4U)

/**
 * \brief Secure Key Module Not Initialized Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_NOT_INITIALIZED error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_NOT_INITIALIZED            (PH_ERR_CUSTOM_BEGIN + 5U)

/**
 * \brief Secure Key Module ASymmetric Hardware Accelerator Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_ASYMM_HW_ACC_ERROR error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_ASYMM_HW_ACC_ERROR         (PH_ERR_CUSTOM_BEGIN + 6U)

/**
 * \brief Secure Key Module Domain Parameter Not Set Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_DP_NOT_SET error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_DP_NOT_SET                 (PH_ERR_CUSTOM_BEGIN + 7U)

#ifdef NXPBUILD__PHHAL_HW_PN7642
/**
 * \brief Secure Key Module Application Root Key Provisioning Error.
 * This error represents #PH_KEYSTORE_PN76XX_ERR_APP_ROOT_KEY_PROVISION error.
 */
#define PH_KEYSTORE_PN76XX_ERR_RSP_APP_ROOT_KEY_PROVISION     (PH_ERR_CUSTOM_BEGIN + 8U)
#endif /* NXPBUILD__PHHAL_HW_PN7642 */

/**
 * end of group phKeyStore_PN76XX_Defines_ErrorMapped
 * @}
 */

/**
 * end of group phKeyStore_PN76XX_Defines_Errors
 * @}
 */

/**
 * \defgroup phKeyStore_PN76XX_Defines_Provision KeyProvision
 * \brief Option indicating the type of key to be provisioned.
 * @{
 */
#define PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_DISABLED           0x0000U /**< Option to exclude of provisioning of AES 128Bit and AES 256Bit Application Root Key. */
#define PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_ENABLED            0x0001U /**< Option to provision both AES 128Bit and 256Bit Application Root Keys. */
/**
 * end of group phKeyStore_PN76XX_Defines_Provision
 * @}
 */

/**
 * \defgroup phKeyStore_PN76XX_Defines_ProvisionConfigs Configs
 * \brief Option to update the provisioning data like Expected Decrypted data, Initialization Vector for Wrapping,
 * Application Root Keys,etc...
 * @{
 */

/** \brief Updates the existing AES 128-Bit Application root key used during component
 * \ref phKeyStore_PN76XX_Init "Initialization".
 *
 * \note
 *  - Using this configuration, the key will be stored in the DataParams for further
 *    Provisioning of Fixed or ASymmetric Keys.
 *  - Updating the Application root key will not provision the key in hardware.
 *    Application Root Key configured will be used from next operations.
 */
#define PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES128_BIT                      0x00A1U

/** \brief Updates the existing AES 256-Bit Application root key used during component
 * \ref phKeyStore_PN76XX_Init "Initialization".
 *
 * \note
 *  - Using this configuration, the key will be stored in the DataParams for further
 *    Provisioning Fixed or ASymmetric Keys.
 *  - Updating the Application root key will not provision the key in hardware.
 *    Application Root Key configured will be used from next operations.
 */
#define PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES256_BIT                      0x00A2U

/** \brief Updates the existing Derivation message used for opening a Session or wrapping key during
 * component \ref phKeyStore_PN76XX_Init "Initialization".
 * \note
 *  - Should be 24 bytes.
 *  - Using this configuration, the information will be stored in the DataParams.
 *  - Updating the Initialization Vector will not perform activities of Key Provisioning.
 *    Initialization Vector configured will be used from next operations.
 */
#define PH_KEYSTORE_CONFIG_DERIV_MSG                                    0x00A3U

/** \brief Expected Updates the existing Expected Decryption Data used for opening a Session or wrapping key during
 * component \ref phKeyStore_PN76XX_Init "Initialization".
 *
 * \note
 *  - Should be 24 bytes.
 *  - Using this configuration, the information will be stored in the DataParams.
 *  - Updating the Initialization Vector will not perform activities of Key Provisioning.
 *    Initialization Vector configured will be used from next operations.
 */
#define PH_KEYSTORE_CONFIG_EXPECTED_DEC_DATA                            0x00A4U

/** \brief Updates the existing Initialization Vector (WIV) used for opening a Session or wrapping key during
 * component \ref phKeyStore_PN76XX_Init "Initialization".
 *
 * \note
 *  - Should be 16 bytes.
 *  - Using this configuration, the information will be stored in the DataParams.
 *  - Updating the Initialization Vector will not perform activities of Key Provisioning.
 *    Initialization Vector configured will be used from next operations.
 */
#define PH_KEYSTORE_CONFIG_WRAP_IV                                      0x00A5U
/**
 * end of group phKeyStore_PN76XX_Defines_ProvisionConfigs
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX_NDA */

/**
 * \defgroup phKeyStore_PN76XX_Defines_KeySize KeySize
 * \brief Options indicating buffer size.
 * @{
 */

#ifndef NXPBUILD__PH_KEYSTORE_ASYM
#define PH_KEYSTORE_MAX_KEY_SIZE                                        32U     /**< Maximum size of a Symmetric Key. */
#endif /* NXPBUILD__PH_KEYSTORE_ASYM */
/**
 * end of group phKeyStore_PN76XX_Defines_KeySize
 * @}
 */

/**
 * end of group phKeyStore_PN76XX_Defines
 * @}
 */

/** \brief PN76XX KeyVersionPair structure for Symmetric and ASymmetric keys. */
typedef struct
{
    uint8_t aKey[PH_KEYSTORE_MAX_KEY_SIZE];                                     /**< Array containing a Symmetric Key. Will contain the following
                                                                                 *      - Symmetric Key
                                                                                 *          - \ref PH_KEYSTORE_KEY_TYPE_2K3DES "TripleDES - Two Key"
                                                                                 *          - \ref PH_KEYSTORE_KEY_TYPE_3K3DES "TripleDES - Three Key"
                                                                                 *          - \ref PH_KEYSTORE_KEY_TYPE_MIFARE "CRYPTO-1 (MIFARE) Key"
                                                                                 *          - \ref PH_KEYSTORE_KEY_TYPE_AES128 "AES 128-Bit Fixed Key" and
                                                                                 *            \ref PH_KEYSTORE_KEY_TYPE_AES128 "AES 256-Bit Fixed Key" will be
                                                                                 *            stored in the hardware.
                                                                                 *      \cond NXPBUILD__PH_KEYSTORE_ASYM
                                                                                 *      - ASymmetric Key
                                                                                 *          - Private \ref PH_KEYSTORE_KEY_TYPE_ECC "ECC Key" will be stored in the hardware.
                                                                                 *          - Public \ref PH_KEYSTORE_KEY_TYPE_ECC "ECC Key" will be stored in this buffer.
                                                                                 *      \endcond
                                                                                 */
    uint8_t bKeyLen;                                                            /**< Length of bytes available in \b aKey buffer. */
    uint16_t wKeyType;                                                          /**< Type of the keys. Refer
                                                                                 *      - \ref phKeyStore_Sym_Defines_KeyType "Symmetric KeyTypes".
                                                                                 *      \cond NXPBUILD__PH_KEYSTORE_ASYM
                                                                                 *      - \ref phKeyStore_ASym_Defines_KeyType "ASymmetric KeyTypes".
                                                                                 *      \endcond
                                                                                 */
    uint8_t bKeyIndex;                                                          /**< Internal Key Storage number. Will be utilized for hardware implementation.
                                                                                 *      - For Symmetric Keys it will be 10h - 1Ah
                                                                                 *      \cond NXPBUILD__PH_KEYSTORE_ASYM
                                                                                 *      - For ASymmetric Keys it will be 1Bh - 21h
                                                                                 *      \endcond
                                                                                 */
} phKeyStore_PN76XX_KeyEntry_t;

/** \brief PN76XX parameter structure. */
typedef struct
{
    uint16_t  wId;                                                              /**< Layer ID for this component, NEVER MODIFY! */
    phKeyStore_PN76XX_KeyEntry_t * pKeyEntries;                                 /**< Key entry storage. */
    void * pCryptoSymDataParams;                                                /**< Pointer to a Symmetric Crypto structure. */
    uint16_t wNoOfKeyEntries;                                                   /**< Number of key entries in that storage. */
} phKeyStore_PN76XX_DataParams_t;

/**
 * \brief Initializes the KeyStore component as PN76XX component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If the input size do not match the DataParams size of this component.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If any of the parameter is null.
 *                                      - If Derivation message \b pDervMsg does not hold 24 bytes of information.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_Init(
        phKeyStore_PN76XX_DataParams_t * pDataParams,                           /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                             /**< [In] Specifies the size of the data parameter structure. */
        phKeyStore_PN76XX_KeyEntry_t * pKeyEntries,                             /**< [In] Pointer to a storage containing the key entries. Should not be Null. */
        uint16_t wNoOfKeyEntries                                                /**< [In] Length of \b pKeyEntries buffer. */
    );

/**
 * \brief De-Initializes the KeyStore component as PN76XX component.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_DeInit(
        phKeyStore_PN76XX_DataParams_t * pDataParams                            /**< [In] Pointer to this layer's parameter structure. */
    );

#ifdef NXPBUILD__PH_KEYSTORE_PN76XX_NDA

/** \brief PN76XX provisioning parameter structure. */
typedef struct
{
    void * pCryptoSymDataParams;                                                /**< Pointer to a Symmetric Crypto structure. */
    uint8_t aAppRootKey_AES128[16U];                                            /**< Array holds AES 128-Bit Application Root Key. This will be filled during
                                                                                 *   \ref phKeyStore_PN76XX_Init "Initialization".
                                                                                 */
    uint8_t aAppRootKey_AES256[32U];                                            /**< Array holds AES 256-Bit Application Root Key. This will be filled during
                                                                                 *   \ref phKeyStore_PN76XX_Init "Initialization".
                                                                                 */
    uint8_t aExpDecData[16U];                                                   /**< Array containing AES 128-Bit expected Decrypted data to be used while opening the Session. */
    uint8_t aDervMsg[24U];                                                      /**< Array holds the derivation message.
                                                                                 *      - Derivation message to derive a wrapping key from existing Transport Key
                                                                                 *        (NXP_TPT_KEY) or Application Root Key (APP_ROOT_KEY)
                                                                                 *      - Will be used while opening a session and provisioning the Keys.
                                                                                 */
    uint8_t aWrapIV[16U];                                                       /**< Array containing AES 128-Bit initialization vector to be used while provisioning the key. */
} phKeyStore_PN76XX_Provision_DataParams_t;

/**
 * \brief Initializes the PN76XX KeyStore component for Key provisioning.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If the input size do not match the DataParams size of this component.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If any of the parameter is null.
 *                                      - If Derivation message \b pDervMsg does not hold 24 bytes of information.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_Provision_Init(
        phKeyStore_PN76XX_Provision_DataParams_t * pDataParams,                 /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wSizeOfDataParams,                                             /**< [In] Specifies the size of the data parameter structure. */
        void * pCryptoSymDataParams,                                            /**< [In] Pointer to a Symmetric Crypto structure. Should not be NULL. */
        uint16_t wOption,                                                       /**< [In] Options to perform the following.
                                                                                 *          - #PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_DISABLED: Provisioning of Application Root Key not required.
                                                                                 *          - #PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_ENABLED : Provision both 128-Bit and 256-Bit Application Root Key.
                                                                                 */
        uint8_t *pTransportKey_AES128,                                          /**< [In] Array containing AES 128-Bit [16 Byte] Transport Key.
                                                                                 *        Can be NULL if \b wOption = #PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_DISABLED
                                                                                 */
        uint8_t *pTransportKey_AES256,                                          /**< [In] Array containing AES 256-Bit [32 Byte] Transport Key.
                                                                                 *        Can be NULL if \b wOption = #PH_KEYSTORE_PROVISION_APP_ROOT_KEY_PROVISION_DISABLED
                                                                                 */
        uint8_t *pAppRootKey_AES128,                                            /**< [In] Array containing AES 128-Bit [16 Byte]  Application Root Key. Should not be Null. */
        uint8_t *pAppRootKey_AES256,                                            /**< [In] Array containing AES 256-Bit [32 Byte]  Application Root Key. Should not be Null. */
        uint8_t *pExpDecData,                                                   /**< [In] Array containing AES 128-Bit  [16 Byte] expected Decrypted data to be used while
                                                                                 *        opening the Session. Should not be NULL.
                                                                                 */
        uint8_t *pDervMsg,                                                      /**< [In] Array containing derivation message. Should not be NULL.
                                                                                 *          - Derivation message to derive a wrapping key from existing Transport Key
                                                                                 *            (NXP_TPT_KEY) or Application Root Key (APP_ROOT_KEY)
                                                                                 *          - Will be used while opening a session and provisioning the Keys.
                                                                                 *          - Should be 24 bytes in length.
                                                                                 */
        uint8_t *pWrapIV                                                        /**< [In] IV used for wrapping the key. This information will be used while provisioning the Key.
                                                                                 *          - Should be 16 bytes in length.
                                                                                 *          - If NULL, Zero IV will be used for wrapping the key.
                                                                                 */
    );

/**
 * \brief De-Initializes PN76XX KeyStore component for Key provisioning.
 */
void phKeyStore_PN76XX_Provision_DeInit(
        phKeyStore_PN76XX_Provision_DataParams_t * pDataParams                  /**< [In] Pointer to this layer's parameter structure. */
    );

/**
 * \brief Provision Application Fixed Keys.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS              Operation successful.
 * \retval #PH_ERR_INVALID_DATA_PARAMS  If the input size do not match the DataParams size of this component.
 * \retval #PH_ERR_INVALID_PARAMETER
 *                                      - If any of the parameter is null.
 *                                      - If Derivation message \b pDervMsg does not hold 24 bytes of information.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_Provision_AppFixedKeys(
        phKeyStore_PN76XX_Provision_DataParams_t * pDataParams,                 /**< [In] Pointer to this layer's parameter structure. */
        uint8_t bKeyIndex,                                                      /**< [In] Key number of the hardware keys store to be provisioned.
                                                                                 *      - Keys Index will be 10h - 1Ah
                                                                                 */
        uint16_t wKeyType,                                                      /**< [In] Key type of the key to be loaded. Should be one of the following
                                                                                 *           - \arg PH_KEYSTORE_KEY_TYPE_AES128 "AES 128-Bit Key"
                                                                                 *           - \arg PH_KEYSTORE_KEY_TYPE_AES256 "AES 256-Bit Key"
                                                                                 */
        uint8_t * pNewKey                                                       /**< [In] Pointer to the key itself. */
    );

/**
 * \brief Set configuration parameter. This interface is supported only for PN76XX hardware.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_SetConfig_Ext(
        phKeyStore_PN76XX_Provision_DataParams_t * pDataParams,                 /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier.
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES128_BIT "AES 128-Bit Application Root Key".
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES256_BIT "AES 256-Bit Application Root Key".
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_DERIV_MSG "AES128 / AES256 Bit Derivation Message"
                                                                                 *            for Fixed or ASymmetric key.
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_EXPECTED_DEC_DATA "Expected Decrypted Data"
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_WRAP_IV "Initialization Vector"
                                                                                 */
        uint8_t * pValue,                                                       /**< [In] Configuration Value to update. */
        uint16_t wValueLen                                                      /**< [In] Length of byte available in \b pValue buffer. */
    );

/**
 * \brief Get configuration parameter. This interface is supported only for PN76XX hardware.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_PN76XX_GetConfig_Ext(
        phKeyStore_PN76XX_Provision_DataParams_t * pDataParams,                 /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier.
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES128_BIT "AES 128-Bit Application Root Key".
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_APP_ROOT_KEY_AES256_BIT "AES 256-Bit Application Root Key".
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_DERIV_MSG "AES128 / AES256 Bit Derivation Message"
                                                                                 *            for Fixed or ASymmetric key.
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_EXPECTED_DEC_DATA "Expected Decrypted Data"
                                                                                 *          - \ref PH_KEYSTORE_CONFIG_WRAP_IV "Initialization Vector"
                                                                                 */
        uint8_t * pValue,                                                       /**< [In] Configuration Value to retrieve. */
        uint16_t * pValueLen                                                    /**< [In] Length of byte available in \b pValue buffer. */
    );
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX_NDA */

/**
 * end of group phKeyStore_PN76XX
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE_PN76XX */

#ifdef NXPBUILD__PH_KEYSTORE

/**
 * \defgroup phKeyStore KeyStore
 *
 * \brief This is only a wrapper layer to abstract the different KeyStore implementations.
 * @{
 */

/**
 * \defgroup phKeyStore_Defines_Config Configuration
 * \brief Definitions for KeyStore layer configuration.
 * @{
 */
#define PH_KEYSTORE_CONFIG_SET_DEFAULT                                  0xFFFFU /**< Reset all bit of SET param. */

/**
 * end of group phKeyStore_Defines_Config
 * @}
 */

/**
 * \addtogroup phKeyStore_Sym
 * @{
 */

/**
 * \defgroup phKeyStore_Sym_Defines Common Definitions
 * \brief Definitions for Symmetric keys of KeyStore component.
 * @{
 */

/**
 * \defgroup phKeyStore_Sym_Defines_KeyType KeyType
 * \brief Definitions for Symmetric Key types.
 * @{
 */
#define PH_KEYSTORE_KEY_TYPE_AES128                                     0x00U   /**< AES 128 Key [16]. */
#define PH_KEYSTORE_KEY_TYPE_AES192                                     0x01U   /**< AES 192 Key [24]. */
#define PH_KEYSTORE_KEY_TYPE_AES256                                     0x02U   /**< AES 256 Key [32]. */
#define PH_KEYSTORE_KEY_TYPE_DES                                        0x03U   /**< DES Single Key [8 Bytes]. This is basically the 56-Bit DES key. */
#define PH_KEYSTORE_KEY_TYPE_2K3DES                                     0x04U   /**< 2 Key Triple Des [16 Bytes]. This is basically the 112-Bit DES key. */
#define PH_KEYSTORE_KEY_TYPE_3K3DES                                     0x05U   /**< 3 Key Triple Des [24 Bytes]. This is basically the 168-Bit DES key. */
#define PH_KEYSTORE_KEY_TYPE_MIFARE                                     0x06U   /**< MIFARE (R) Key. */
/**
 * end of group phKeyStore_Sym_Defines_KeyType
 * @}
 */

/**
 * \defgroup phKeyStore_Sym_Defines_Size Key Size
 * \brief Definitions for Symmetric Key sizes.
 * @{
 */
#define PH_KEYSTORE_KEY_TYPE_MIFARE_SIZE                                0x0CU   /**< Size of an MIFARE Key. */
#define PH_KEYSTORE_KEY_TYPE_AES128_SIZE                                0x10U   /**< Size of an AES128 Key. */
#define PH_KEYSTORE_KEY_TYPE_AES192_SIZE                                0x18U   /**< Size of an AES192 Key. */
#define PH_KEYSTORE_KEY_TYPE_AES256_SIZE                                0x20U   /**< Size of an AES256 Key. */
/**
 * end of group phKeyStore_Sym_Defines_Size
 * @}
 */

/**
 * end of group phKeyStore_Sym_Defines
 * @}
 */

/**
 * end of group phKeyStore_Sym
 * @}
 */

#define PH_KEYSTORE_INVALID_ID                                          0xFFFFU /**< ID used for various parameters as a invalid default **/
#define PH_KEYSTORE_DEFAULT_ID                                          0x0000U /**< ID used for various parameters as a default **/

#ifdef NXPRDLIB_REM_GEN_INTFS

#if defined(NXPBUILD__PH_KEYSTORE_SW)
#include "../comps/phKeyStore/src/Sw/phKeyStore_Sw.h"

#define phKeyStore_FormatKeyEntry(pDataParams,wKeyNo,wNewKeyType) \
        phKeyStore_Sw_FormatKeyEntry((phKeyStore_Sw_DataParams_t *)pDataParams,wKeyNo,wNewKeyType)

#define phKeyStore_SetKUC(pDataParams, wKeyNo, wRefNoKUC) \
        phKeyStore_Sw_SetKUC((phKeyStore_Sw_DataParams_t *)pDataParams, wKeyNo, wRefNoKUC)

#define phKeyStore_GetKUC(pDataParams, wRefNoKUC, pdwLimit, pdwCurVal) \
        phKeyStore_Sw_GetKUC((phKeyStore_Sw_DataParams_t *)pDataParams, wRefNoKUC, pdwLimit, pdwCurVal)

#define phKeyStore_ChangeKUC(pDataParams, wRefNoKUC, dwLimit) \
        phKeyStore_Sw_ChangeKUC((phKeyStore_Sw_DataParams_t *)pDataParams, wRefNoKUC, dwLimit)

#define phKeyStore_SetConfig(pDataParams,wConfig,wValue) \
        phKeyStore_Sw_SetConfig((phKeyStore_Sw_DataParams_t *)pDataParams,wConfig,wValue)

#define phKeyStore_SetConfigStr(pDataParams,wConfig,pBuffer,wBufferLength) \
        phKeyStore_Sw_SetConfigStr((phKeyStore_Sw_DataParams_t *)pDataParams,wConfig,pBuffer,wBufferLength)

#define phKeyStore_GetConfig(pDataParams,wConfig,pValue) \
        phKeyStore_Sw_GetConfig((phKeyStore_Sw_DataParams_t *)pDataParams,wConfig,pValue)

#define phKeyStore_GetConfigStr(pDataParams,wConfig,ppBuffer,pBufferLength) \
        phKeyStore_Sw_GetConfigStr((phKeyStore_Sw_DataParams_t *)pDataParams,wConfig,ppBuffer,pBufferLength)

#define phKeyStore_SetKey(pDataParams, wKeyNo, wKeyVersion, wKeyType, pNewKey, wNewKeyVersion) \
        phKeyStore_Sw_SetKey((phKeyStore_Sw_DataParams_t *)pDataParams, wKeyNo, wKeyVersion, wKeyType, pNewKey, wNewKeyVersion)

#define phKeyStore_SetKeyAtPos(pDataParams, wKeyNo, wPos, wKeyType, pNewKey, wNewKeyVersion) \
        phKeyStore_Sw_SetKeyAtPos((phKeyStore_Sw_DataParams_t *)pDataParams, wKeyNo, wPos, wKeyType, pNewKey, wNewKeyVersion)

#define phKeyStore_SetFullKeyEntry(pDataParams, wNoOfKeys, wKeyNo, wNewRefNoKUC, wNewKeyType, pNewKeys, pNewKeyVersionList) \
        phKeyStore_Sw_SetFullKeyEntry((phKeyStore_Sw_DataParams_t *)pDataParams, wNoOfKeys, wKeyNo, wNewRefNoKUC, wNewKeyType, pNewKeys, pNewKeyVersionList)

#define phKeyStore_GetKeyEntry(pDataParams, wKeyNo, wKeyVersionBufSize, wKeyVersion, wKeyVersionLength, pKeyType) \
        phKeyStore_Sw_GetKeyEntry((phKeyStore_Sw_DataParams_t *)pDataParams, wKeyNo, wKeyVersionBufSize, wKeyVersion, wKeyVersionLength, pKeyType)

#define  phKeyStore_GetKey(pDataParams, wKeyNo, wKeyVersion, bKeyBufSize, pKey, pKeyType) \
         phKeyStore_Sw_GetKey((phKeyStore_Sw_DataParams_t *)pDataParams, wKeyNo, wKeyVersion, bKeyBufSize, pKey, pKeyType)
#endif /* NXPBUILD__PH_KEYSTORE_SW */

#else /* NXPRDLIB_REM_GEN_INTFS */

/**
 * \brief Format a key entry to a new KeyType.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_FormatKeyEntry(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] KeyEntry number to be Formatted. */
        uint16_t wNewKeyType                                                    /**< [In] New Key type of the KeyEntry (predefined type of KeyType).
                                                                                 *           - \ref phKeyStore_Sym_Defines_KeyType "Symmetric KeyTypes"
                                                                                 *           \cond NXPBUILD__PH_KEYSTORE_ASYM
                                                                                 *           - \ref phKeyStore_ASym_Defines_KeyType "ASymmetric KeyTypes"
                                                                                 *           \endcond
                                                                                 */
    );

/**
 * \brief Change the KUC of a key entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetKUC(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] KeyEntry number. */
        uint16_t wRefNoKUC                                                      /**< [In] Reference Number of the key usage counter used together with that key.*/
    );

/**
 * \brief Obtain a key usage counter entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_GetKUC(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wRefNoKUC,                                                     /**< [In] Number of the key usage counter to be looked at (00h to 0Fh) */
        uint32_t * pdwLimit,                                                    /**< [Out] Currently Set Limit in the KUC */
        uint32_t * pdwCurVal                                                    /**< [Out] Currently set value in the KUC */
    );

/**
 * \brief Change a key usage counter entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_ChangeKUC(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wRefNoKUC,                                                     /**< [In] Number of key entry. */
        uint32_t dwLimit                                                        /**< [In] Limit of the Key Usage Counter. */
    );

/**
 * \brief Set configuration parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetConfig(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier */
        uint16_t wValue                                                         /**< [In] Configuration Value */
    );

/**
 * \brief Set configuration parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetConfigStr(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier. */
        uint8_t *pBuffer,                                                       /**< [In] Buffer containing the configuration string. */
        uint16_t wBufferLength                                                  /**< [In] Length of configuration string. */
    );

/**
 * \brief Get configuration parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_GetConfig(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier */
        uint16_t * pValue                                                       /**< [Out] Configuration Value */
    );

/**
 * \brief Get configuration parameter.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_GetConfigStr(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wConfig,                                                       /**< [In] Configuration Identifier */
        uint8_t ** ppBuffer,                                                    /**< [Out] Pointer to the buffer containing the configuration string. */
        uint16_t * pBufferLength                                                /**< [Out] Amount of valid bytes in the configuration string buffer. */
    );

/**
 * \defgroup phKeyStore_Sym Symmetric
 * \brief Interfaces for Symmetric keys of KeyStore component.
 * @{
 */

/**
 * \brief Change a symmetric key entry at a given version.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetKey(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] Key number of the key to be loaded. Should be the Key index to
                                                                                 *        set the key to DataParams \b pKeyEntries buffer.
                                                                                 */
        uint16_t wKeyVersion,                                                   /**< [In] Key version of the key to be loaded. */
        uint16_t wKeyType,                                                      /**< [In] New Key type of the KeyEntry (predefined type of KeyType).
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES128
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES192
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES256
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_2K3DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_3K3DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_MIFARE
                                                                                 */
        uint8_t * pNewKey,                                                      /**< [In] Pointer to the key itself. */
        uint16_t wNewKeyVersion                                                 /**< [In] New Key version of the key to be updated. */
    );

/**
 * \brief Change a symmetric key entry at the specified position.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetKeyAtPos(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] Key number of the key to be loaded. Should be the Key index to
                                                                                 *        set the key to DataParams \b pKeyEntries member.
                                                                                 */
        uint16_t wPos,                                                          /**< [In] Key position to be updated.
                                                                                 *          - Should be the Key position to set the key to DataParams \b pKeyEntries buffer.
                                                                                 *          \cond NXPBUILD__PH_KEYSTORE_PN76XX
                                                                                 *          - Should be the following when used for PN76XX hardware.
                                                                                 *              - The Actual Symmetric Fixed Key Index (10h - 1Ah) of the hardware KeyStore.
                                                                                 *              - Will be Ignored below mentioned Keytypes.
                                                                                 *                  - \ref PH_KEYSTORE_KEY_TYPE_2K3DES "TripleDES - Two Key"
                                                                                 *                  - \ref PH_KEYSTORE_KEY_TYPE_3K3DES "TripleDES - Three Key"
                                                                                 *                  - \ref PH_KEYSTORE_KEY_TYPE_MIFARE "CRYPTO-1 (MIFARE) Key"
                                                                                 *          \endcond
                                                                                 */
        uint16_t wKeyType,                                                      /**< [In] Key type of the key to be loaded.*/
        uint8_t * pNewKey,                                                      /**< [In] Pointer to the key itself. */
        uint16_t wNewKeyVersion                                                 /**< [In] New Key version of the key to be updated. */
    );

/**
 * \brief Change a full symmetric key entry.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_SetFullKeyEntry(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wNoOfKeys,                                                     /**< [In] Number of keys in pNewKeys. */
        uint16_t wKeyNo,                                                        /**< [In] Key number of the key to be loaded. */
        uint16_t wNewRefNoKUC,                                                  /**< [In] Number of the key usage counter used together with that key. */
        uint16_t wNewKeyType,                                                   /**< [In] Key type of the key (if the current keyType of KeyEntry is different, error). */
        uint8_t * pNewKeys,                                                     /**< [In] Array of Keys to load. */
        uint16_t * pNewKeyVersionList                                           /**< [In] KeyVersionList of the key to be loaded. */
    );

/**
 * \brief Get a symmetric key entry information block.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_GetKeyEntry(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] Key number of the key entry of interest. */
        uint16_t wKeyVersionBufSize,                                            /**< [In] Buffer Size of wKeyVersion in Bytes. */
        uint16_t * wKeyVersion,                                                 /**< [Out] Array for version information. */
        uint16_t * wKeyVersionLength,                                           /**< [Out] Length of valid data in wKeyVersion. */
        uint16_t * pKeyType                                                     /**< [Out] Type of the key. */
    );

/**
 * \brief Get a symmetric key.
 *
 * \return Status code
 * \retval #PH_ERR_SUCCESS Operation successful.
 * \retval Other Depending on implementation and underlying component.
 */
phStatus_t phKeyStore_GetKey(
        void * pDataParams,                                                     /**< [In] Pointer to this layer's parameter structure. */
        uint16_t wKeyNo,                                                        /**< [In] Key number of the key to be retrieved. */
        uint16_t wKeyVersion,                                                   /**< [In] Key version of the key to be retrieved. */
        uint8_t bKeyBufSize,                                                    /**< [In] Size of the key buffer. */
        uint8_t * pKey,                                                         /**< [Out] Pointer to the key itself. */
        uint16_t * pKeyType                                                     /**< [Out] Type of the key. */
    );

/**
 * end of group phKeyStore_Sym
 * @}
 */


#endif /* NXPRDLIB_REM_GEN_INTFS */

/**
 * \defgroup phKeyStore_Utility Utility
 * \brief Interfaces for utility interfaces for KeyStore component.
 * @{
 */
/**
 * \brief Gets the size of Symmetric key.
 *
 * \retval Symmetric Key Size.
 */
uint8_t phKeyStore_GetKeySize(
        uint16_t wKeyType                                                       /**< [In] Key type of the KeyEntry (predefined type of KeyType).
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES128
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES192
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_AES256
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_2K3DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_3K3DES
                                                                                 *          - #PH_KEYSTORE_KEY_TYPE_MIFARE
                                                                                 */
    );

/**
 * end of group phKeyStore_Utility
 * @}
 */

/**
 * end of group phKeyStore
 * @}
 */
#endif /* NXPBUILD__PH_KEYSTORE */

#ifdef __cplusplus
} /* Extern C */
#endif

#endif /* PHKEYSTORE_H */
