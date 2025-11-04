/*
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*----------------------------------------------------------------------------*/
/* Copyright 2021-2023NXP                                                    */
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
 * Alternate implementation of mbedtls AES functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_AESALT_H_
#define PN76_AESALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/** @addtogroup PN76SYSSYMMETRICAES
 *
 * @brief System Service AES API's
 *
 * This module briefs about the implementation of various AES Algorithms.
 *
 * \section PN76SYSSYMMETRICAES_NOTE Note regarding the use of the AES keys stored in hardware keystore
	If the AES keys stored in hardware keystore to be used for encryption/decryption, only
	\ref SKM_KEY_TYPE_APP_MASTER or \ref SKM_KEY_TYPE_APP_FIXED must be used.
	
	If \ref SKM_KEY_TYPE_APP_MASTER is used, then a encryption/decryption key is derived from this key 
	with the derivation message stored in EEPROM configuration \ref PN76_SKM_EncrDecrDerMsg.
	
	If \ref SKM_KEY_TYPE_APP_FIXED is used, then the key itself is a encryption/decryption key.
	
	\note Further if the key to be used from hardware keystore, that key must be provisioned.
	
 *
 * @{
 *
 */

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/
/**
 * @brief MBEDTLS modes
 */
#define MBEDTLS_AES_ENCRYPT     1 /**< AES encryption       */
#define MBEDTLS_AES_DECRYPT     0 /**< AES decryption       */

/**
 * @brief MBEDTLS GCM modes
 */
#define MBEDTLS_GCM_ENCRYPT     1 /**< GCM encryption       */
#define MBEDTLS_GCM_DECRYPT     0 /**< GCM decryption       */


/**
 * @brief MBEDTLS error codes
 */
#define MBEDTLS_ERR_AES_INVALID_KEY_LENGTH                -0x0020  /**< Invalid key length. */
#define MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH              -0x0022  /**< Invalid data input length. */
#define MBEDTLS_ERR_AES_BAD_INPUT_DATA                    -0x0021  /**< Invalid input data. */
#define MBEDTLS_ERR_AES_HW_ACCEL_FAILED                   -0x0025  /**< AES hardware accelerator failed. */
#define MBEDTLS_ERR_CCM_BAD_INPUT                         -0x000D  /**< Bad input parameters to the function. */
#define MBEDTLS_ERR_CCM_AUTH_FAILED                       -0x000F /**< Authenticated decryption failed. */
#define MBEDTLS_ERR_CCM_HW_ACCEL_FAILED                   -0x0011 /**< CCM hardware accelerator failed. */
#define MBEDTLS_ERR_GCM_AUTH_FAILED                       -0x0012  /**< Authenticated decryption failed. */
/* MBEDTLS_ERR_GCM_HW_ACCEL_FAILED is deprecated and should not be used. */
#define MBEDTLS_ERR_GCM_HW_ACCEL_FAILED                   -0x0013  /**< GCM hardware accelerator failed. */
#define MBEDTLS_ERR_GCM_BAD_INPUT                         -0x0014  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_EAX_BAD_INPUT                         -0x0050  /**< Bad input parameters to the function. */
#define MBEDTLS_ERR_EAX_AUTH_FAILED                       -0x0051 /**< Authenticated decryption failed. */
#define MBEDTLS_ERR_EAX_HW_ACCEL_FAILED                   -0x0052 /**< EAX hardware accelerator failed. */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*!
 * @brief The AES context-type definition.
 */
typedef struct mbedtls_aes_context
{
    uint8_t key_index; /**< The index of the secure key store from which the key is to be loaded */
    uint8_t sec_options; /**< Security options RFU*/
}
mbedtls_aes_context;

/*!
 * @brief    The CCM context-type definition. The CCM context is passed
 *           to the APIs called.
 */
typedef struct mbedtls_ccm_context
{
   uint8_t key_index; /**< The index of the secure key store from which the key is to be loaded */
   uint8_t sec_options;/**< Security options RFU*/
}
mbedtls_ccm_context;

/*!
 * @brief          The GCM context structure.
 */
typedef struct mbedtls_gcm_context
{
   uint8_t key_index; /**< The index of the secure key store from which the key is to be loaded */
   uint8_t sec_options;/**< Security options RFU*/
}
mbedtls_gcm_context;

/*!
 * @brief The EAX context-type definition.
 */
typedef struct mbedtls_eax_context
{
    uint8_t key_index; /**< The index of the secure key store from which the key is to be loaded */
    uint8_t sec_options; /**< Security options RFU*/
}
mbedtls_eax_context;


/**
 * @brief Internal structure for the AES CBC mode operations.
 *
 */
typedef struct mbedtls_aes_crypt_cbc_params
{
   mbedtls_aes_context *ctx; /**< The AES context to use for encryption or decryption.It must be initialized and bound to a key. */
   int32_t mode; /**< The AES operation: #MBEDTLS_AES_ENCRYPT or #MBEDTLS_AES_DECRYPT. */
   size_t length; /**< The length of the input data in Bytes. This must be a multiple of the block size (\c 16 Bytes). */
   uint8_t *iv; /**< Initialization vector (updated after use). It must be a readable and writeable buffer of \c 16 Bytes. */
   const uint8_t *input; /**< The buffer holding the input data. It must be readable and of size \p length Bytes. */
   uint8_t *output; /**< The buffer holding the output data. It must be writeable and of size \p length Bytes. */
}mbedtls_aes_crypt_cbc_params_t;

/**
 * @brief Internal structure for the AES CCM mode operations.
 *
 */
typedef struct mbedtls_aes_crypt_ccm_params
{
   mbedtls_ccm_context *ctx; /**< The AES context to use for encryption or decryption.It must be initialized and bound to a key. */
   size_t length; /**< The length of the input data in Bytes. */
   const uint8_t *iv; /**< The initialization vector (nonce). This must be a readable buffer of at least \p iv_len Bytes. */
   size_t iv_len; /**< The length of the nonce in Bytes: 7, 8, 9, 10, 11, 12, or 13. The length L of the message length field is 15 - \p iv_len. */
   const uint8_t *add; /**< The additional data field. If \p add_len is greater than zero, \p add must be a readable buffer of at least that length. */
   size_t add_len; /**< The length of additional data in Bytes. This must be less than `2^16 - 2^8`. */
   const uint8_t *input; /**< The buffer holding the input data. If \p length is greater than zero, \p input must be a readable buffer of at least that length. */
   uint8_t *output; /**< The buffer holding the output data. If \p length is greater than zero, \p output must be a writable buffer of at least that length. */
   uint8_t *tag; /**< The buffer holding the authentication field. This must be a readable buffer of at least \p tag_len Bytes. */
   size_t tag_len; /**< The length of the authentication field to generate in Bytes: 4, 6, 8, 10, 12, 14 or 16. */
   uint8_t bMode;  /**< Mode = MBEDTLS_AES_ENCRYPT/MBEDTLS_AES_DECRYPT */
}mbedtls_aes_crypt_ccm_params_t;

/**
 * @brief Internal structure for the AES CTR mode operations.
 *
 */
typedef struct mbedtls_aes_crypt_ctr_params
{
   mbedtls_aes_context *ctx; /**< The AES context to use for encryption or decryption.It must be initialized and bound to a key. */
   size_t length; /**< The length of the input data. */
   size_t *nc_off; /**< The offset in the current \p stream_block, for
                   * resuming within the current cipher stream. The
                   * offset pointer should be 0 at the start of a stream.
                   * It must point to a valid \c size_t. */
   uint8_t *nonce_counter; /**< The 128-bit nonce and counter. It must be a readable-writeable buffer of \c 16 Bytes. */
   uint8_t *stream_block; /**< The saved stream block for resuming. This is overwritten by the function.
                                 * It must be a readable-writeable buffer of \c 16 Bytes. */
   const uint8_t *input; /**< The buffer holding the input data. It must be readable and of size \p length Bytes. */
   uint8_t *output; /**< The buffer holding the output data. It must be writeable and of size \p length Bytes. */
}mbedtls_aes_crypt_ctr_params_t;

/**
 * @brief Internal structure for the AES GCM encrypt mode operations.
 *
 */
typedef struct mbedtls_aes_crypt_gcm_params
{
   mbedtls_gcm_context *ctx; /**< The GCM context. This must be initialized. */
   int32_t mode; /**<  The operation to perform:
             * - #MBEDTLS_GCM_ENCRYPT to perform authenticated encryption.
             *   The ciphertext is written to \p output and the
             *   authentication tag is written to \p tag.
             * - #MBEDTLS_GCM_DECRYPT to perform decryption.
             *   The plaintext is written to \p output and the
             *   authentication tag is written to \p tag.
             *   Note that this mode is not recommended, because it does
             *   not verify the authenticity of the data. For this reason,
             *   you should use mbedtls_gcm_auth_decrypt() instead of
             *   calling this function in decryption mode. */
   size_t length; /**< The length of the input data, which is equal to the length
                   * of the output data. */
   const uint8_t *iv; /**< The initialization vector. This must be a readable buffer of at least \p iv_len Bytes. */
   size_t iv_len; /**< The length of the IV. */
   const uint8_t *add; /**< The buffer holding the additional data. This must be of at
                               * least that size in Bytes. */
   size_t add_len; /**< The length of the additional data. */
   const uint8_t *input; /**< The buffer holding the input data. If \p length is greater
                               * than zero, this must be a readable buffer of at least that
                               * size in Bytes. */
   uint8_t *output; /**< The buffer for holding the output data. If \p length is greater
                            * than zero, this must be a writable buffer of at least that
                            * size in Bytes. */
   size_t tag_len; /**< The length of the tag to generate. */
   uint8_t *tag; /**< The buffer for holding the tag. This must be a readable
                         * buffer of at least \p tag_len Bytes. */
}mbedtls_aes_crypt_gcm_params_t;

/**
 * @brief Internal structure for the AES GCM decrypt mode operations.
 *
 */
typedef struct mbedtls_aes_decrypt_gcm_params
{
   mbedtls_gcm_context *ctx; /**< The GCM context. This must be initialized. */
   size_t length; /**< The length of the ciphertext to decrypt, which is also
                   * the length of the decrypted plaintext. */
   const uint8_t *iv; /**< The initialization vector. This must be a readable buffer
                            * of at least \p iv_len Bytes. */
   size_t iv_len; /**< The length of the IV. */
   const uint8_t *add; /**< The buffer holding the additional data. This must be of at
                               * least that size in Bytes. */
   size_t add_len; /**< The length of the additional data. */
   uint8_t *tag; /**< The buffer holding the tag to verify. This must be a
                      * readable buffer of at least \p tag_len Bytes. */
   size_t tag_len; /**< The length of the tag to verify. */
   const uint8_t *input; /**< The buffer holding the ciphertext. If \p length is greater
                               * than zero, this must be a readable buffer of at least that size. */
   uint8_t *output; /**< The buffer for holding the decrypted plaintext. If \p length
                            * is greater than zero, this must be a writable buffer of at least that size. */
}mbedtls_aes_decrypt_gcm_params_t;


/**
 * @brief Internal structure for the AES EAX mode operations.
 *
 */
typedef struct mbedtls_aes_crypt_eax_params
{
   const uint8_t   *input;
   uint16_t   length;
   const uint8_t   *nonce;
   uint16_t   nonce_len;
   const uint8_t   *header;
   uint16_t   header_len;
   uint16_t   nBlocks;       /**< This is number of blocks processed at once*/
   uint8_t   *output;
   uint8_t   *tag;
   uint8_t    tag_len;
   uint8_t    bMode;         /**< Mode = MBEDTLS_AES_ENCRYPT/MBEDTLS_AES_DECRYPT */
}mbedtls_aes_crypt_eax_params_t;


/**
 * @brief     Supported cipher types.
 *
 */
typedef enum {
    MBEDTLS_CIPHER_ID_NONE = 0,  /**< Placeholder to mark the end of cipher ID lists. */
    MBEDTLS_CIPHER_ID_AES       /**< The AES cipher. */
} mbedtls_cipher_id_t;


/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*!
 * @brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 *                 If this is \c NULL, this function does nothing.
 *                 Otherwise, the context must have been at least initialized.
 */
void mbedtls_aes_free_stz( mbedtls_aes_context *ctx );

/*!
 * @brief          This function sets the encryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The encryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 *                 NULL if key stored in hardware key store is to be used
 * \param keybits  The size of data passed in bits. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 
 * \note           If key stored in hardware key store to be used, the parameter \b key must be NULL.
 *                 \n The value in \ref mbedtls_aes_context.key_index must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 
 
 */
int32_t mbedtls_aes_setkey_stz( mbedtls_aes_context *ctx, const uint8_t *key,
                    uint32_t keybits );

/*!
 * @brief          This function performs an AES single-block encryption or
 *                 decryption operation.
 *
 *                 It performs the operation defined in the \p mode parameter
 *                 (encrypt or decrypt), on the input data buffer defined in
 *                 the \p input parameter.
 *
 *                 mbedtls_aes_init(), and either \ref mbedtls_aes_setkey_enc() or
 *                 \ref mbedtls_aes_setkey_dec() must be called before the first
 *                 call to this API with the same context.
 *
 * \param ctx      The AES context to use for encryption or decryption.
 *                 It must be initialized and bound to a key.
 * \param mode     The AES operation: #MBEDTLS_AES_ENCRYPT or
 *                 #MBEDTLS_AES_DECRYPT.
 * \param input    The buffer holding the input data.
 *                 It must be readable and at least \c 16 Bytes long.
 * \param output   The buffer where the output data will be written.
 *                 It must be writeable and at least \c 16 Bytes long.

 * \return         \c 0 on success.
 
 * \note           The value in \ref mbedtls_aes_context.key_index must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
 				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_aes_crypt_ecb_stz( mbedtls_aes_context *ctx,
                    int32_t mode,
                    const uint8_t input[16],
                    uint8_t output[16] );


/*!
 * @brief  This function performs an AES-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed. \ref mbedtls_aes_init(), and either
 *         \ref mbedtls_aes_setkey_enc() or \ref mbedtls_aes_setkey_dec() must be called
 *         before the first call to this API with the same context.
 *
 * \note   This function operates on full blocks, that is, the input size
 *         must be a multiple of the AES block size of \c 16 Bytes.
 *
 * \note   Upon exit, the content of the IV is updated so that you can
 *         call the same function again on the next
 *         block(s) of data and get the same result as if it was
 *         encrypted in one call. This allows a "streaming" usage.
 *         If you need to retain the contents of the IV, you should
 *         either save it manually or use the cipher module instead.
 *
 *
 * \param mbedtls_aes_crypt_cbc_params  The structure holding the input and output params
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH
 *                 on failure.
 * \note           The value in \b mbedtls_aes_crypt_cbc_params_t.ctx->key_index must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_aes_crypt_cbc_stz(mbedtls_aes_crypt_cbc_params_t* mbedtls_aes_crypt_cbc_params) ;

/*!
 * @brief      This function performs an AES-CTR encryption or decryption
 *             operation.
 *
 *             This function performs the operation defined in the \p mode
 *             parameter (encrypt/decrypt), on the input data buffer
 *             defined in the \p input parameter.
 *
 *             Due to the nature of CTR, you must use the same key schedule
 *             for both encryption and decryption operations. Therefore, you
 *             must use the context initialized with \ref mbedtls_aes_setkey_enc()
 *             for both #MBEDTLS_AES_ENCRYPT and #MBEDTLS_AES_DECRYPT.
 *
 * \warning    You must never reuse a nonce value with the same key. Doing so
 *             would void the encryption for the two messages encrypted with
 *             the same nonce and key.
 *
 * \param mbedtls_aes_crypt_ctr_params  The structure holding the input and output params
 *
 * \return                 \c 0 on success.
  * \note      The value in \ref mbedtls_aes_crypt_ctr_params_t.mbedtls_aes_context.key_index must contain the key index.
               \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_aes_crypt_ctr_stz( mbedtls_aes_crypt_ctr_params_t *mbedtls_aes_crypt_ctr_params);

/*!
 * @brief   This function releases and clears the specified CCM context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The CCM context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void mbedtls_ccm_free_stz( mbedtls_ccm_context *ctx );

/*!
 * @brief           This function initializes the CCM context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The CCM context to initialize. This must be an initialized
 *                  context.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 *                  NULL if key stored in hardware key store is used
 * \param keybits   The key size in bits. This must be acceptable by the cipher.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 * \note      If key stored in hardware key store to be used, the parameter \b key must be NULL.
              \n The value in \ref mbedtls_ccm_context.key_index must contain the key index.
              \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_ccm_setkey_stz( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const uint8_t *key,
                        uint32_t keybits );


/*!
 * @brief           This function encrypts a buffer using CCM.
 *
 * \note            The tag is written to a separate buffer. To concatenate
 *                  the \p tag with the \p output, as done in <em>RFC-3610:
 *                  Counter with CBC-MAC (CCM)</em>, use
 *                  \p tag = \p output + \p length, and make sure that the
 *                  output buffer is at least \p length + \p tag_len wide.
 *
 * \param mbedtls_aes_crypt_ccm_params  The structure holding the input and output params
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 * \note      The value in \ref mbedtls_aes_crypt_ccm_params_t.ctx.key_index must contain the key index.
              \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_ccm_encrypt_decrypt_and_tag_stz(mbedtls_aes_crypt_ccm_params_t *mbedtls_aes_crypt_ccm_params );

/*!
 * @brief           This function clears a GCM context
 *
 * \param ctx       The GCM context to clear. If this is \c NULL, the call has
 *                  no effect. Otherwise, this must be initialized.
 */
void mbedtls_gcm_free_stz( mbedtls_gcm_context *ctx );

/**
 * \brief           This function associates a GCM context with a
 *                  cipher algorithm and a key.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key. This must be a readable buffer of at
 *                  least \p keybits bits.
 *                  NULL if key stored in hardware key store is used
 * \param keybits   The key size in bits. Valid options are:
 *                  <ul><li>128 bits</li>
 *                  <li>256 bits</li></ul>
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 * \note           If key stored in hardware key store to be used, the parameter \b key must be NULL.
 *                 \n The value in \ref mbedtls_gcm_context.key_index must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_gcm_setkey_stz( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const uint8_t *key,
                        uint32_t keybits );


/**
 * \brief           This function performs GCM encryption or decryption of a buffer.
 *
 * \note            For encryption, the output buffer can be the same as the
 *                  input buffer. For decryption, the output buffer cannot be
 *                  the same as input buffer. If the buffers overlap, the output
 *                  buffer must trail at least 8 Bytes behind the input buffer.
 *
 * \warning         When this function performs a decryption, it outputs the
 *                  authentication tag and does not verify that the data is
 *                  authentic. You should use this function to perform encryption
 *                  only. For decryption, use \ref mbedtls_gcm_auth_decrypt() instead.
 *
 * \param mbedtls_aes_crypt_gcm_params  The structure holding the input and output params
 *
 * \return          \c 0 if the encryption or decryption was performed
 *                  successfully. Note that in #MBEDTLS_GCM_DECRYPT mode,
 *                  this does not indicate that the data is authentic.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the encryption
 *                  or decryption failed.
 */
int32_t mbedtls_gcm_crypt_and_tag_stz(mbedtls_aes_crypt_gcm_params_t* mbedtls_aes_crypt_gcm_params);

/**
 * \brief           This function performs a GCM authenticated decryption of a
 *                  buffer.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 *
 * \param mbedtls_aes_decrypt_gcm_params  The structure holding the input and output params
 * \return          \c 0 if successful and authenticated.
 * \return          #MBEDTLS_ERR_GCM_AUTH_FAILED if the tag does not match.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the decryption
 *                  failed.
 */
int32_t mbedtls_gcm_auth_decrypt_stz(mbedtls_aes_decrypt_gcm_params_t* mbedtls_aes_decrypt_gcm_params);
/*!
 * @brief   This function releases and clears the specified eax context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The eax context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void mbedtls_eax_free_stz( mbedtls_eax_context *ctx );

/**
 * \brief           This function associates a EAX context with a
 *                  cipher algorithm and a key.
 *
 * \param ctx       The EAX context. This must be initialized.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key. This must be a readable buffer of at
 *                  least \p keybits bits.
 *                  NULL if key stored in hardware key store is used
 * \param keybits   The key size in bits. Valid options are:
 *                  <ul><li>128 bits</li>
 *                  <li>256 bits</li></ul>
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 * \note           If key stored in hardware key store to be used, the parameter \b key must be NULL.
 *                 \n The value in \ref mbedtls_eax_context.key_index must contain the key index.
                   \n The hardware key index \b 0, \b 2-3 cannot be used. The key must have been provisioned before using \ref PN76SYSHALSKM APIs.
				   \n please refer to \ref PN76SYSSYMMETRICAES_NOTE
 */
int32_t mbedtls_eax_setkey_stz(mbedtls_eax_context *ctx,
                       mbedtls_cipher_id_t cipher,
                       const uint8_t *key,
                       uint32_t keybits);

/*!
 * @brief           This function encrypts a buffer using EAX.
 *
 * \note            The tag is written to a separate buffer. To concatenate
 *                  the \p tag with the \p output, as done in <em>RFC-3610:
 *                  Counter with CBC-MAC (EAX)</em>, use
 *                  \p tag = \p output + \p length, and make sure that the
 *                  output buffer is at least \p length + \p tag_len wide.
 *                  In case of an invalid tag provided for the decrypt operation
 *                  the module returns MBEDTLS_ERR_EAX_HW_ACCEL_FAILED instead of
 *                  MBEDTLS_ERR_EAX_AUTH_FAILED one could expect
 * \param mbedtls_aes_crypt_eax_params  The structure holding the input and output params
 *
 * \return          \c 0 on success.
 * \return          A EAX or cipher-specific error code on failure.
 */
int32_t mbedtls_eax_encrypt_decrypt_and_tag_stz(mbedtls_aes_crypt_eax_params_t *mbedtls_aes_crypt_eax_params );


#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_AESALT_H_ */
