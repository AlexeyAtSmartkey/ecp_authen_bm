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
 * Alternate implementation of mbedtls SHA and secure SHA functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef _SHA_ALT_H_
#define _SHA_ALT_H_

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"
/*****************************************************************************
 * Component Includes
 ****************************************************************************/
#include "PN76_Shaalt.h"

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/

/*****************************************************************************
 * Public functions definitions
 ****************************************************************************/

/*!
 * @brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.
 *
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */

int mbedtls_SecureSha256_starts_ret(void);

/*!
 * @brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha256_update_ret( const uint8_t *input, size_t ilen );

/*!
 * @brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 *
 * \param output   The SHA-224 or SHA-256 checksum result.
 *                 This must be a writable buffer of length \c 32 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha256_finish_ret( unsigned char output[32]);

/*!
 * @brief          This function calculates the SHA-256
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   SHA-256 checksum result. This must
 *                 be a writable buffer of length \c at least 32 Bytes.
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha256(const uint8_t *input, size_t ilen,unsigned char output[32]);

/*!
 * @brief          This function starts a SHA-384 or SHA-512 checksum
 *                 calculation.
 *
 * \param is384    This determines which function to use. This must be
 *                 either \c 0 for SHA-512, or \c 1 for SHA-384.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha512_starts_ret( uint8_t is384 );

/*!
 * @brief          This function feeds an input buffer into an ongoing
 *                 SHA-512 checksum calculation.
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha512_update_ret( const uint8_t *input, size_t ilen );

/*!
 * @brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer.
 *
 * \param output   The SHA-384 or SHA-512 checksum result.
 *                 This must be a writable buffer of length of at least \c 32 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha512_finish_ret( unsigned char output[64]);

/*!
 * @brief          This function calculates the SHA-512
 *                 checksum of a buffer.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The SHA-512 result is calculated as
 *                 output = SHA-512(input buffer).
 *
 * \param input    The buffer holding the input data. This must be
 *                 a readable buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-512 checksum result.
 *                 This must be a writable buffer of length of at least \c 64 Bytes.
 * \param is384    Determines which function to use. Only supported
 *                 \c 0 for SHA-512
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int mbedtls_SecureSha512(const uint8_t *input, size_t ilen, unsigned char output[64], uint8_t is384);

/*!
 * @brief           This function initializes a message-digest context
 *
 *                  This function should always be called first.
 *
 \param ctx         The MD context to initialize. This must not be \c NULL.*
 */
void mbedtls_md_init( mbedtls_md_context_t *ctx );

/*!
 * @brief           This function clears the internal structure of \p ctx
 *
 *                  Calling this function if you have previously
 *                  called mbedtls_md_init() and nothing else is optional.
 *                  You must not call this function if you have not called
 *                  mbedtls_md_init().
 *
 \param ctx         The MD context to free. This must not be \c NULL.*
 */
void mbedtls_md_free( mbedtls_md_context_t *ctx );

/*!
 * @brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after mbedtls_md_init(),then call
 *                  mbedtls_md_hmac_update() to provide the input data, and
 *                  mbedtls_md_hmac_finish() to get the HMAC value.
 *
 * \param ctx       The message digest context
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int mbedtls_md_hmac_starts( mbedtls_md_context_t *ctx, const unsigned char *key,
                    size_t keylen );


/*!
 * @brief           This function feeds an input buffer into an ongoing HMAC
 *                  computation.
 *
 *                  Call mbedtls_md_hmac_starts() or mbedtls_md_hmac_reset()
 *                  before calling this function.
 *                  You may call this function multiple times to pass the
 *                  input piecewise.
 *                  Afterwards, call mbedtls_md_hmac_finish().
 *
 * \param ctx       The message digest context
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int mbedtls_md_hmac_update( mbedtls_md_context_t *ctx, const unsigned char *input,
                    size_t ilen );


/*!
 * @brief           This function finishes the HMAC operation, and writes
 *                  the result to the output buffer.
 *
 *                  Call this function after mbedtls_md_hmac_starts() and
 *                  mbedtls_md_hmac_update() to get the HMAC value. Afterwards
 *                  you may either call mbedtls_md_free() to clear the context,
 *                  or call mbedtls_md_hmac_reset() to reuse the context with
 *                  the same HMAC key.
 *
 * \param ctx       The message digest context
 * \param output    The generic HMAC checksum result.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int mbedtls_md_hmac_finish( mbedtls_md_context_t *ctx, unsigned char *output);


/*!
 * @brief          This function calculates the full generic HMAC
 *                 on the input buffer with the provided key.
 *
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *
 *                 The HMAC result is calculated as
 *                 output = generic HMAC(hmac key, input buffer).
 *
 * \param md_info  The information structure of the message-digest algorithm
 *                 to use.
 * \param key      The HMAC secret key.
 * \param keylen   The length of the HMAC secret key in Bytes.
 * \param input    The buffer holding the input data.
 * \param ilen     The length of the input data.
 * \param output   The generic HMAC result.
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 *                 #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int mbedtls_md_hmac( const mbedtls_md_info_t *md_info, const unsigned char *key, size_t keylen,
                const unsigned char *input, size_t ilen,
                unsigned char *output );

/*!
 * @brief  Take the input keying material \p ikm and extract from it a
 *          fixed-length pseudorandom key \p prk.
 *
 *  \warning    This function should only be used if the security of it has been
 *              studied and established in that particular context (eg. TLS 1.3
 *              key schedule). For standard HKDF security guarantees use
 *              \c mbedtls_hkdf instead.
 *
 *  \param       md        A hash function; md.size denotes the length of the
 *                         hash function output in bytes.
 *  \param       salt      An optional salt value (a non-secret random value);
 *                         if the salt is not provided, a string of all zeros
 *                         of md.size length is used as the salt.
 *  \param       salt_len  The length in bytes of the optional \p salt.
 *  \param       ikm       The input keying material.
 *  \param       ikm_len   The length in bytes of \p ikm.
 *  \param[out]  prk       A pseudorandom key of at least md.size bytes.
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int mbedtls_hkdf_extract( const mbedtls_md_info_t *md,
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk );

/*!
 * @brief  Expand the supplied \p prk into several additional pseudorandom
 *          keys, which is the output of the HKDF.
 *
 *  \warning    This function should only be used if the security of it has been
 *              studied and established in that particular context (eg. TLS 1.3
 *              key schedule). For standard HKDF security guarantees use
 *              \c mbedtls_hkdf instead.
 *
 *  \param  md        A hash function; md.size denotes the length of the hash
 *                    function output in bytes.
 *  \param  prk       A pseudorandom key of at least md.size bytes. \p prk is
 *                    usually the output from the HKDF extract step.
 *  \param  prk_len   The length in bytes of \p prk.
 *  \param  info      An optional context and application specific information
 *                    string. This can be a zero-length string.
 *  \param  info_len  The length of \p info in bytes.
 *  \param  okm       The output keying material of \p okm_len bytes.
 *  \param  okm_len   The length of the output keying material in bytes. This
 *                    must be less than or equal to 255 * md.size bytes.
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int mbedtls_hkdf_expand( const mbedtls_md_info_t *md, const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len );

/*!
 *  @brief  This is the HMAC-based Extract-and-Expand Key Derivation Function
 *          (HKDF).
 *
 *  \param  md        A hash function; md.size denotes the length of the hash
 *                    function output in bytes.
 *  \param  salt      An optional salt value (a non-secret random value);
 *                    if the salt is not provided, a string of all zeros of
 *                    md.size length is used as the salt.
 *  \param  salt_len  The length in bytes of the optional \p salt.
 *  \param  ikm       The input keying material.
 *  \param  ikm_len   The length in bytes of \p ikm.
 *  \param  info      An optional context and application specific information
 *                    string. This can be a zero-length string.
 *  \param  info_len  The length of \p info in bytes.
 *  \param  okm       The output keying material of \p okm_len bytes.
 *  \param  okm_len   The length of the output keying material in bytes. This
 *                    must be less than or equal to 255 * md.size bytes.
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int mbedtls_hkdf( const mbedtls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len );
#ifdef __cplusplus
}
#endif

#endif /* _SHA_ALT_H_ */
