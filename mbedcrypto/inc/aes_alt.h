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
/* Copyright 2022 NXP                                                         */
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
 * Alternate implementation of mbedtls functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2020-11-04 $
 *
 * History:
 *
 */

#ifndef _AES_ALT_H
#define _AES_ALT_H

/** @addtogroup mbedcrypto_symm_wrap
 *
 * @brief Implementation of mbedtls functions using HW Crypto blocks of PN76 NFC Controller
 *
 * This module briefs all the prototypes of mbedtls functions that uses HW Crypto blocks of PN76 NFC Controller.
 *
 * @{
 *
 */


/*****************************************************************************
 * System Includes
 ****************************************************************************/


/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#ifdef __cplusplus
extern "C" {
#endif

#include "PN76_Crypto.h"
#include "PN76_aesalt.h"
#include "PN76_Desalt.h"
#include "PN76_Shaalt.h"
#include "PN76_CryptoHelper.h"

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/


/*****************************************************************************
 * Public functions declaration
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/
/*!
 * @brief          This function initializes crypto modules
 *
 *                 It must be the first API called before using
 *                 crypto.
 *
 *
 */
int32_t phmbedcrypto_Init( void );


/*!
 * @brief          This function de-initializes crypto modules
 *
 *                 This API must be called only if no crypto operations
 *                 are being done.
 *
 *
 *
 */
void phmbedcrypto_DeInit( void );


/*!
 * @brief          This function initializes the specified AES context.
 *
 *                 It must be the first API called before using
 *                 the context.
 * \note           Only 1 AES context is supported at any time. Use mbedtls_aes_free/
 *                 mbedtls_ccm_free before initializing the next context.
 * \param ctx      The AES context to initialize. This must not be \c NULL.
 */
void mbedtls_aes_init( mbedtls_aes_context *ctx );


/*!
 * @brief          This function releases and clears the specified AES context.
 *
 * \param ctx      The AES context to clear.
 *                 If this is \c NULL, this function does nothing.
 *                 Otherwise, the context must have been at least initialized.
 */
void mbedtls_aes_free( mbedtls_aes_context *ctx );

/*!
 * @brief          This function sets the encryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The encryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 *                 NULL if key stored in SKT is used
 * \param keybits  The size of data passed in bits. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 * \return         #MBEDTLS_ERR_AES_BAD_INPUT_DATA on failure
 */
int mbedtls_aes_setkey_enc( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/*!
 * @brief          This function sets the decryption key.
 *
 * \param ctx      The AES context to which the key should be bound.
 *                 It must be initialized.
 * \param key      The decryption key.
 *                 This must be a readable buffer of size \p keybits bits.
 *                 NULL if key stored in SKT is used
 * \param keybits  The size of data passed. Valid options are:
 *                 <ul><li>128 bits</li>
 *                 <li>256 bits</li></ul>
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_KEY_LENGTH on failure.
 * \return         #MBEDTLS_ERR_AES_BAD_INPUT_DATA on failure
 */
int mbedtls_aes_setkey_dec( mbedtls_aes_context *ctx, const unsigned char *key,
                    unsigned int keybits );

/*!
 * @brief          This function performs an AES single-block encryption or
 *                 decryption operation.
 *
 *                 It performs the operation defined in the \p mode parameter
 *                 (encrypt or decrypt), on the input data buffer defined in
 *                 the \p input parameter.
 *
 *                 mbedtls_aes_init(), and either mbedtls_aes_setkey_enc() or
 *                 mbedtls_aes_setkey_dec() must be called before the first
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
 */
int mbedtls_aes_crypt_ecb( mbedtls_aes_context *ctx,
                    int mode,
                    const unsigned char input[16],
                    unsigned char output[16] );


/*!
 * @brief  This function performs an AES-CBC encryption or decryption operation
 *         on full blocks.
 *
 *         It performs the operation defined in the \p mode
 *         parameter (encrypt/decrypt), on the input data buffer defined in
 *         the \p input parameter.
 *
 *         It can be called as many times as needed, until all the input
 *         data is processed. mbedtls_aes_init(), and either
 *         mbedtls_aes_setkey_enc() or mbedtls_aes_setkey_dec() must be called
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
 * \param ctx      The AES context to use for encryption or decryption.
 *                 It must be initialized and bound to a key.
 * \param mode     The AES operation: #MBEDTLS_AES_ENCRYPT or
 *                 #MBEDTLS_AES_DECRYPT.
 * \param length   The length of the input data in Bytes. This must be a
 *                 multiple of the block size (\c 16 Bytes).
 * \param iv       Initialization vector (updated after use).
 *                 It must be a readable and writeable buffer of \c 16 Bytes.
 * \param input    The buffer holding the input data.
 *                 It must be readable and of size \p length Bytes.
 * \param output   The buffer holding the output data.
 *                 It must be writeable and of size \p length Bytes.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_AES_INVALID_INPUT_LENGTH
 *                 on failure.
 */
int mbedtls_aes_crypt_cbc( mbedtls_aes_context *ctx,
                    int mode,
                    size_t length,
                    unsigned char iv[16],
                    const unsigned char *input,
                    unsigned char *output );

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
 *             must use the context initialized with mbedtls_aes_setkey_enc()
 *             for both #MBEDTLS_AES_ENCRYPT and #MBEDTLS_AES_DECRYPT.
 *
 * \warning    You must never reuse a nonce value with the same key. Doing so
 *             would void the encryption for the two messages encrypted with
 *             the same nonce and key.
 *
 * \param ctx              The AES context to use for encryption or decryption.
 *                         It must be initialized and bound to a key.
 * \param length           The length of the input data.
 * \param nc_off           Not used. Set to NULL
 * \param nonce_counter    The 128-bit nonce and counter.
 *                         It must be a readable-writeable buffer of \c 16 Bytes.
 * \param stream_block     Not used. Set to NULL
 * \param input            The buffer holding the input data.
 *                         It must be readable and of size \p length Bytes.
 * \param output           The buffer holding the output data.
 *                         It must be writeable and of size \p length Bytes.
 *
 * \return                 \c 0 on success.
 */
int mbedtls_aes_crypt_ctr( mbedtls_aes_context *ctx,
                       size_t length,
                       size_t *nc_off,
                       unsigned char nonce_counter[16],
                       unsigned char stream_block[16],
                       const unsigned char *input,
                       unsigned char *output );

/*!
 * @brief           This function initializes the specified CCM context,
 *                  to make references valid, and prepare the context
 *                  for mbedtls_ccm_setkey() or mbedtls_ccm_free().
 *
 * \note           Only 1 AES context is supported at any time. Use mbedtls_aes_free/
 *                 mbedtls_ccm_free before initializing the next context.
 *
 * \param ctx       The CCM context to initialize. This must not be \c NULL.
 */
void mbedtls_ccm_init( mbedtls_ccm_context *ctx );

/*!
 * @brief   This function releases and clears the specified CCM context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The CCM context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void mbedtls_ccm_free( mbedtls_ccm_context *ctx );

/*!
 * @brief           This function initializes the CCM context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The CCM context to initialize. This must be an initialized
 *                  context.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 *                  NULL if key stored in SKT is used
 * \param keybits   The key size in bits. This must be acceptable by the cipher.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_setkey( mbedtls_ccm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/*!
 * @brief           This function encrypts a buffer using CCM.
 *
 * \note            The tag is written to a separate buffer. To concatenate
 *                  the \p tag with the \p output, as done in <em>RFC-3610:
 *                  Counter with CBC-MAC (CCM)</em>, use
 *                  \p tag = \p output + \p length, and make sure that the
 *                  output buffer is at least \p length + \p tag_len wide.
 *
 * \param ctx       The CCM context to use for encryption. This must be
 *                  initialized and bound to a key.
 * \param length    The length of the input data in Bytes.
 * \param iv        The initialization vector (nonce). This must be a readable
 *                  buffer of at least \p iv_len Bytes.
 * \param iv_len    The length of the nonce in Bytes: 7, 8, 9, 10, 11, 12,
 *                  or 13. The length L of the message length field is
 *                  15 - \p iv_len.
 * \param add       The additional data field. If \p add_len is greater than
 *                  zero, \p add must be a readable buffer of at least that
 *                  length.
 * \param add_len   The length of additional data in Bytes.
 *                  This must be less than `2^16 - 2^8`.
 * \param input     The buffer holding the input data. If \p length is greater
 *                  than zero, \p input must be a readable buffer of at least
 *                  that length.
 * \param output    The buffer holding the output data. If \p length is greater
 *                  than zero, \p output must be a writable buffer of at least
 *                  that length.
 * \param tag       The buffer holding the authentication field. This must be a
 *                  readable buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the authentication field to generate in Bytes:
 *                  4, 6, 8, 10, 12, 14 or 16.
 *
 * \return          \c 0 on success.
 * \return          A CCM or cipher-specific error code on failure.
 */
int mbedtls_ccm_encrypt_and_tag( mbedtls_ccm_context *ctx, size_t length,
                         const unsigned char *iv, size_t iv_len,
                         const unsigned char *add, size_t add_len,
                         const unsigned char *input, unsigned char *output,
                         unsigned char *tag, size_t tag_len );



/*!
 * @brief           This function performs a CCM authenticated decryption of a
 *                  buffer.
 *
 * \param ctx       The CCM context to use for decryption. This must be
 *                  initialized and bound to a key.
 * \param length    The length of the input data in Bytes.
 * \param iv        The initialization vector (nonce). This must be a readable
 *                  buffer of at least \p iv_len Bytes.
 * \param iv_len    The length of the nonce in Bytes: 7, 8, 9, 10, 11, 12,
 *                  or 13. The length L of the message length field is
 *                  15 - \p iv_len.
 * \param add       The additional data field. This must be a readable buffer
 *                  of at least that \p add_len Bytes..
 * \param add_len   The length of additional data in Bytes.
 *                  This must be less than 2^16 - 2^8.
 * \param input     The buffer holding the input data. If \p length is greater
 *                  than zero, \p input must be a readable buffer of at least
 *                  that length.
 * \param output    The buffer holding the output data. If \p length is greater
 *                  than zero, \p output must be a writable buffer of at least
 *                  that length.
 * \param tag       The buffer holding the authentication field. This must be a
 *                  readable buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the authentication field to generate in Bytes:
 *                  4, 6, 8, 10, 12, 14 or 16.
 *
 * \return          \c 0 on success. This indicates that the message is authentic.
 * \return          #MBEDTLS_ERR_CCM_AUTH_FAILED if the tag does not match.
 * \return          A cipher-specific error code on calculation failure.
 */
int mbedtls_ccm_auth_decrypt( mbedtls_ccm_context *ctx, size_t length,
                      const unsigned char *iv, size_t iv_len,
                      const unsigned char *add, size_t add_len,
                      const unsigned char *input, unsigned char *output,
                      const unsigned char *tag, size_t tag_len );

/*!
 * @brief           This function initializes the specified GCM context,
 *                  to make references valid, and prepares the context
 *                  for mbedtls_gcm_setkey() or mbedtls_gcm_free().
 *
 *                  The function does not bind the GCM context to a particular
 *                  cipher, nor set the key. For this purpose, use
 *                  mbedtls_gcm_setkey().
 * \note           Only 1 AES context is supported at any time. Use mbedtls_aes_free/
 *                 mbedtls_ccm_free before initializing the next context.
 * \param ctx       The GCM context to initialize. This must not be \c NULL.
 */
void mbedtls_gcm_init( mbedtls_gcm_context *ctx );

/**
 * \brief           This function clears a GCM context
 *
 * \param ctx       The GCM context to clear. If this is \c NULL, the call has
 *                  no effect. Otherwise, this must be initialized.
 */
void mbedtls_gcm_free( mbedtls_gcm_context *ctx );

/*!
 * @brief           This function associates a GCM context with a
 *                  cipher algorithm and a key.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key. This must be a readable buffer of at
 *                  least \p keybits bits.
 *                  NULL if key stored in SKT is used
 * \param keybits   The key size in bits. Valid options are:
 *                  <ul><li>128 bits</li>
 *                  <li>256 bits</li></ul>
 *
 * \return          \c 0 on success.
 * \return          A cipher-specific error code on failure.
 */
int mbedtls_gcm_setkey( mbedtls_gcm_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/*!
 * @brief           This function performs GCM encryption or decryption of a buffer.
 *
 * \note            For encryption, the output buffer can be the same as the
 *                  input buffer. For decryption, the output buffer cannot be
 *                  the same as input buffer. If the buffers overlap, the output
 *                  buffer must trail at least 8 Bytes behind the input buffer.
 *
 * \warning         When this function performs a decryption, it outputs the
 *                  authentication tag and does not verify that the data is
 *                  authentic. You should use this function to perform encryption
 *                  only. For decryption, use mbedtls_gcm_auth_decrypt() instead.
 *
 * \param ctx       The GCM context to use for encryption or decryption. This
 *                  must be initialized.
 * \param mode      The operation to perform:
 *                  - #MBEDTLS_GCM_ENCRYPT to perform authenticated encryption.
 *                    The ciphertext is written to \p output and the
 *                    authentication tag is written to \p tag.
 * \param length    The length of the input data, which is equal to the length
 *                  of the output data.
 * \param iv        The initialization vector. This must be a readable buffer of
 *                  at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data. This must be of at
 *                  least that size in Bytes.
 * \param add_len   The length of the additional data.
 * \param input     The buffer holding the input data. If \p length is greater
 *                  than zero, this must be a readable buffer of at least that
 *                  size in Bytes.
 * \param output    The buffer for holding the output data. If \p length is greater
 *                  than zero, this must be a writable buffer of at least that
 *                  size in Bytes.
 * \param tag_len   The length of the tag to generate.
 * \param tag       The buffer for holding the tag. This must be a readable
 *                  buffer of at least \p tag_len Bytes. Tag lengths supported
 *                  12-16 bytes
 *
 * \return          \c 0 if the encryption or decryption was performed
 *                  successfully. Note that in #MBEDTLS_GCM_DECRYPT mode,
 *                  this does not indicate that the data is authentic.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the encryption
 *                  or decryption failed.
 */
int mbedtls_gcm_crypt_and_tag( mbedtls_gcm_context *ctx,
                       int mode,
                       size_t length,
                       const unsigned char *iv,
                       size_t iv_len,
                       const unsigned char *add,
                       size_t add_len,
                       const unsigned char *input,
                       unsigned char *output,
                       size_t tag_len,
                       unsigned char *tag );


/*!
 * @brief           This function performs a GCM authenticated decryption of a
 *                  buffer.
 *
 * \note            For decryption, the output buffer cannot be the same as
 *                  input buffer. If the buffers overlap, the output buffer
 *                  must trail at least 8 Bytes behind the input buffer.
 *
 * \param ctx       The GCM context. This must be initialized.
 * \param length    The length of the ciphertext to decrypt, which is also
 *                  the length of the decrypted plaintext.
 * \param iv        The initialization vector. This must be a readable buffer
 *                  of at least \p iv_len Bytes.
 * \param iv_len    The length of the IV.
 * \param add       The buffer holding the additional data. This must be of at
 *                  least that size in Bytes.
 * \param add_len   The length of the additional data.
 * \param tag       The buffer holding the tag to verify. This must be a
 *                  readable buffer of at least \p tag_len Bytes.
 * \param tag_len   The length of the tag to verify.
 *                  Tag lengths supported 12-16 bytes
 * \param input     The buffer holding the ciphertext. If \p length is greater
 *                  than zero, this must be a readable buffer of at least that
 *                  size.
 * \param output    The buffer for holding the decrypted plaintext. If \p length
 *                  is greater than zero, this must be a writable buffer of at
 *                  least that size.
 *
 * \return          \c 0 if successful and authenticated.
 * \return          #MBEDTLS_ERR_GCM_AUTH_FAILED if the tag does not match.
 * \return          #MBEDTLS_ERR_GCM_BAD_INPUT if the lengths or pointers are
 *                  not valid or a cipher-specific error code if the decryption
 *                  failed.
 */
int mbedtls_gcm_auth_decrypt( mbedtls_gcm_context *ctx,
                      size_t length,
                      const unsigned char *iv,
                      size_t iv_len,
                      const unsigned char *add,
                      size_t add_len,
                      const unsigned char *tag,
                      size_t tag_len,
                      const unsigned char *input,
                      unsigned char *output );

/*!
 * @brief           This function initializes the specified EAX context,
 *                  to make references valid, and prepare the context
 *                  for mbedtls_eax_setkey() or mbedtls_eax_free().
 *
 * \note           Only 1 AES context is supported at any time. Use mbedtls_aes_free/
 *                 mbedtls_eax_free before initializing the next context.
 *
 * \param ctx       The EAX context to initialize. This must not be \c NULL.
 */
void mbedtls_eax_init( mbedtls_eax_context *ctx );

/*!
 * @brief   This function releases and clears the specified EAX context
 *          and underlying cipher sub-context.
 *
 * \param ctx       The EAX context to clear. If this is \c NULL, the function
 *                  has no effect. Otherwise, this must be initialized.
 */
void mbedtls_eax_free( mbedtls_eax_context *ctx );

/*!
 * @brief           This function initializes the EAX context set in the
 *                  \p ctx parameter and sets the encryption key.
 *
 * \param ctx       The EAX context to initialize. This must be an initialized
 *                  context.
 * \param cipher    The 128-bit block cipher to use.
 * \param key       The encryption key.
 *                  NULL if key stored in SKT is used
 * \param keybits   The key size in bits. This must be acceptable by the cipher.
 *
 * \return          \c 0 on success.
 * \return          A EAX or cipher-specific error code on failure.
 */
int mbedtls_eax_setkey( mbedtls_eax_context *ctx,
                        mbedtls_cipher_id_t cipher,
                        const unsigned char *key,
                        unsigned int keybits );

/*!
 * @brief              This function encrypts a buffer using EAX.
 *
 * \note               The tag is written to a separate buffer. To concatenate
 *                     the \p tag with the \p output, as done in <em>RFC-3610:
 *                     Counter with CBC-MAC (EAX)</em>, use
 *                     \p tag = \p output + \p length, and make sure that the
 *                     output buffer is at least \p length + \p tag_len wide.
 *
 * \param ctx          The EAX context to use for decryption. This must be
 *                     initialized and bound to a key.
 * \param nBlocks      This is number of blocks processed at once.
 * \param input        The buffer holding the input data. If \p length is greater
 *                     than zero, \p input must be a readable buffer of at least
 *                     that length.
 * \param length       The length of the input data, which is equal to the length
 *                     of the output data.
 * \param nonce        The initialization vector (nonce). This must be a readable
 *                     buffer of at least \p iv_len Bytes.
 * \param nonce_len    The length of the nonce in Bytes.
 * \param header        The initialization vector (nonce). This must be a readable
 *                     buffer of at least \p iv_len Bytes.
 * \param header_len    The length of the header in Bytes.
 * \param tag          The buffer holding the authentication field. This must be a
 *                     writable buffer of at least \p tag_len Bytes.
 * \param tag_len      The length of the authentication field to generate in Bytes.
 * \param output       The buffer holding the output data. If \p length is greater
 *                     than zero, \p output must be a writable buffer of at least
 *                     that length.
 *
 * \return             \c 0 on success.
 * \return             A EAX or cipher-specific error code on failure.
 */
int mbedtls_eax_encrypt_and_tag(mbedtls_eax_context *ctx, size_t nBlocks,
                         const unsigned char *input, size_t length,
                         const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *header, size_t header_len,
                         unsigned char *tag, size_t tag_len,
                         unsigned char *output);



/*!
 * @brief           This function performs a EAX authenticated decryption of a
 *                  buffer.
 *
 * \param ctx          The EAX context to use for decryption. This must be
 *                     initialized and bound to a key.
 * \param nBlocks      This is number of blocks processed at once.
 * \param input        The buffer holding the input data. If \p length is greater
 *                     than zero, \p input must be a readable buffer of at least
 *                     that length.
 * \param length       The length of the input data, which is equal to the length
 *                     of the output data.
 * \param nonce        The initialization vector (nonce). This must be a readable
 *                     buffer of at least \p iv_len Bytes.
 * \param nonce_len    The length of the nonce in Bytes.
 * \param header        The initialization vector (nonce). This must be a readable
 *                     buffer of at least \p iv_len Bytes.
 * \param header_len    The length of the header in Bytes.
 * \param tag          The buffer holding the authentication field. This must be a
 *                     readable buffer of at least \p tag_len Bytes.
 * \param tag_len      The length of the authentication field to generate in Bytes.
 * \param output       The buffer holding the output data. If \p length is greater
 *                     than zero, \p output must be a writable buffer of at least
 *                     that length.
 *
 * \return          \c 0 on success. This indicates that the message is authentic.
 * \return          #MBEDTLS_ERR_EAX_AUTH_FAILED if the tag does not match.
 * \return          A cipher-specific error code on calculation failure.
 */
int mbedtls_eax_auth_decrypt(mbedtls_eax_context *ctx, size_t nBlocks,
            const unsigned char *input, size_t length,
            const unsigned char *nonce, size_t nonce_len,
            const unsigned char *header, size_t header_len,
            const unsigned char *tag, size_t tag_len,
            unsigned char *output);


#ifdef __cplusplus
}
#endif
/** @} */
#endif /* _AES_ALT_H */
