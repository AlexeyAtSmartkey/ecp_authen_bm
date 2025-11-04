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
 * Alternate implementation of mbedtls SHA and secure SHA functions using HW Crypto blocks
 * $Author: NXP $
 * $Revision: $
 * $Date: 2021-02-24 $
 *
 * History:
 *
 */

#ifndef PN76_SHAALT_H_
#define PN76_SHAALT_H_
/** @addtogroup PN76SYSSYMMETRICSHA
 *
 * @brief System Service SHA API's
 *
 * This module briefs about the implementation of various SHA Algorithms.
 *
 * This module implements PN76SYSSYMMETRICSHA interface in the ROM code
 *
 * @{
 *
 */

/*****************************************************************************
 * System Includes
 ****************************************************************************/
#include "string.h"
#include "ph_Datatypes.h"

/*****************************************************************************
 * Component Includes
 ****************************************************************************/

#ifdef __cplusplus
extern "C" {
#endif

/*****************************************************************************
 * Macros
 ****************************************************************************/

#define MBEDTLS_ERR_SHA256_HW_ACCEL_FAILED                -0x0037  /**< SHA-256 hardware accelerator failed */
#define MBEDTLS_ERR_SHA256_BAD_INPUT_DATA                 -0x0074  /**< SHA-256 input data was malformed. */

#define MBEDTLS_ERR_SHA512_HW_ACCEL_FAILED                -0x0039  /**< SHA-512 hardware accelerator failed */
#define MBEDTLS_ERR_SHA512_BAD_INPUT_DATA                 -0x0075  /**< SHA-512 input data was malformed. */

#define MBEDTLS_ERR_MD_BAD_INPUT_DATA                     -0x5100  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_MD_HW_ACCEL_FAILED                    -0x5280  /**< MD hardware accelerator failed. */

#define MBEDTLS_ERR_HKDF_BAD_INPUT_DATA                   -0x5F80  /**< Bad input parameters to function. */

/*****************************************************************************
 * Public types/enumerations/variables
 ****************************************************************************/
/*!
 * @brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
typedef struct mbedtls_sha256_context
{
    int32_t is224;                  /**< Determines which function to use:
                                     0: Use SHA-256, or 1: Use SHA-224. */
}
mbedtls_sha256_context;

/*!
 * @brief          The SHA-512 context structure.
 *
 *                 The structure is used both for SHA-512 and for SHA-384
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
typedef struct mbedtls_sha512_context
{
    int32_t is384;                  /**< Determines which function to use:
                                     0: Use SHA-512, or 1: Use SHA-384. */
}
mbedtls_sha512_context;

/*!
 * @brief         The generic message-digest context.
 */
typedef struct mbedtls_md_context_t
{
   uint8_t keyindex;  /**< RFU */
} mbedtls_md_context_t;

/**
 * Opaque struct defined in md_internal.h.
 */
typedef struct mbedtls_md_info_t mbedtls_md_info_t;


/**
 * @brief Internal structure for the hmac operations
 *
 */
typedef struct mbedtls_md_hmac_params
{
   const uint8_t *key; /**< The HMAC secret key. */
   size_t keylen; /**< The length of the HMAC secret key in Bytes. */
   const uint8_t *input; /**< The buffer holding the input data. */
   size_t ilen; /**< The length of the input data. */
   uint8_t *output; /**< The generic HMAC result. */
}mbedtls_md_hmac_params_t;

/**
 * @brief The internal structure for complete HKDF operations
 *
 */
typedef struct mbedtls_hkdf_params
{
   const uint8_t *salt; /**< An optional salt value (a non-secret random value);
                               * if the salt is not provided, a string of all zeros of
                               * md.size length is used as the salt. */
   size_t salt_len; /**< The length in bytes of the optional \p salt. */
   const uint8_t *ikm; /**< The input keying material. */
   size_t ikm_len; /**< The length in bytes of \p ikm. */
   const uint8_t *info; /**< An optional context and application specific information
                               * string. This can be a null string with zero length. */
   size_t info_len; /**< The length of \p info in bytes. */
   uint8_t *okm; /**< The output keying material of \p okm_len bytes. */
   size_t okm_len; /**< The length of the output keying material in bytes. This
                      * must be less than or equal to 255 * md.size bytes. */
}mbedtls_hkdf_params_t;

/**
 * @brief The internal structure for extract HKDF operations
 *
 */
typedef struct mbedtls_hkdf_extract_params
{
   const uint8_t *salt; /**< An optional salt value (a non-secret random value);
                               * if the salt is not provided, a string of all zeros of
                               * md.size length is used as the salt. */
   size_t salt_len; /**< The length in bytes of the optional \p salt. */
   const uint8_t *ikm; /**< The input keying material. */
   size_t ikm_len; /**< The length in bytes of \p ikm. */
   uint8_t *prk; /**< A pseudorandom key of at least md.size bytes */
}mbedtls_hkdf_extract_params_t;

/**
 * @brief The internal structure for expand HKDF operations
 *
 */
typedef struct mbedtls_hkdf_expand_params
{
   const uint8_t *prk; /**< A pseudorandom key of at least md.size bytes \p prk is
                             * usually the output from the HKDF extract step. */
   size_t prk_len; /**< The length in bytes of \p prk. */
   const uint8_t *info; /**< An optional context and application specific information
                               * string. This can be a zero-length string. */
   size_t info_len; /**< The length of \p info in bytes. */
   uint8_t *okm; /**< The output keying material of \p okm_len bytes. */
   size_t okm_len; /**< The length of the output keying material in bytes. This
                   * must be less than or equal to 255 * md.size bytes. */
}mbedtls_hkdf_expand_params_t;

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

int32_t mbedtls_SecureSha256_starts_ret_stz(void);

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
int32_t mbedtls_SecureSha256_update_ret_stz( const uint8_t *input, size_t ilen );

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
int32_t mbedtls_SecureSha256_finish_ret_stz( uint8_t *output );

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
int32_t mbedtls_SecureSha256_stz(const uint8_t *input, size_t ilen, uint8_t *output);

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
int32_t mbedtls_SecureSha512_starts_ret_stz( uint8_t is384 );

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
int32_t mbedtls_SecureSha512_update_ret_stz( const uint8_t *input, size_t ilen );

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
int32_t mbedtls_SecureSha512_finish_ret_stz( uint8_t * output );

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
int32_t mbedtls_SecureSha512_stz(const uint8_t *input, size_t ilen, uint8_t *output, uint8_t is384);


/*!
 * @brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.
 *
 * \param is224    This determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */

int32_t mbedtls_sha256_starts_ret_stz( int32_t is224 );

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
int32_t mbedtls_sha256_update_ret_stz( const uint8_t *input,
                               size_t ilen );

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
int32_t mbedtls_sha256_finish_ret_stz( uint8_t output[32] );

/*!
 * @brief          This function calculates the SHA-224 or SHA-256
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
 * \param output   The SHA-224 or SHA-256 checksum result. This must
 *                 be a writable buffer of length \c 32 Bytes.
 * \param is224    Determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int32_t mbedtls_sha256_ret_stz( const uint8_t *input,
                        size_t ilen,
                        uint8_t output[32],
                        int32_t is224 );

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

int32_t mbedtls_sha512_starts_ret_stz( int32_t is384 );

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
int32_t mbedtls_sha512_update_ret_stz( const uint8_t *input,
                               size_t ilen );

/*!
 * @brief          This function finishes the SHA-512 operation, and writes
 *                 the result to the output buffer.
 *
 * \param output   The SHA-384 or SHA-512 checksum result.
 *                 This must be a writable buffer of length \c 64 Bytes.
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int32_t mbedtls_sha512_finish_ret_stz( uint8_t output[64] );

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
 *                 This must be a writable buffer of length \c 64 Bytes.
 * \param is384    Determines which function to use. Only supported
 *                 \c 0 for SHA-512
 *
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int32_t mbedtls_sha512_ret_stz( const uint8_t *input,
                        size_t ilen,
                        uint8_t output[64],
                        int32_t is384 );

/*!
 * @brief           This function sets the HMAC key and prepares to
 *                  authenticate a new message.
 *
 *                  Call this function after mbedtls_md_init(),then call
 *                  mbedtls_md_hmac_update() to provide the input data, and
 *                  mbedtls_md_hmac_finish() to get the HMAC value.
 *
 * \param key       The HMAC secret key.
 * \param keylen    The length of the HMAC key in Bytes.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int32_t mbedtls_md_hmac_starts_stz( const uint8_t *key,
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
 * \param input     The buffer holding the input data.
 * \param ilen      The length of the input data.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int32_t mbedtls_md_hmac_update_stz( const uint8_t *input,
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
 * \param output    The generic HMAC checksum result.
 *
 * \return          \c 0 on success.
 * \return          #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                  failure.
 *                  #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int32_t mbedtls_md_hmac_finish_stz( uint8_t *output);


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
 * \param         mbedtls_md_hmac_params The structure holding the input and output params
 *
 * \return         \c 0 on success.
 * \return         #MBEDTLS_ERR_MD_BAD_INPUT_DATA on parameter-verification
 *                 failure.
 *                 #MBEDTLS_ERR_MD_HW_ACCEL_FAILED on failure
 */
int32_t mbedtls_md_hmac_stz(mbedtls_md_hmac_params_t *mbedtls_md_hmac_params );

/*!
 * @brief  Take the input keying material \p ikm and extract from it a
 *          fixed-length pseudorandom key \p prk.
 *
 *  \warning    This function should only be used if the security of it has been
 *              studied and established in that particular context (eg. TLS 1.3
 *              key schedule). For standard HKDF security guarantees use
 *              \c mbedtls_hkdf instead.
 *
 *  \param      mbedtls_hkdf_extract_params The structure holding the input and output params
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int32_t mbedtls_hkdf_extract_stz(mbedtls_hkdf_extract_params_t *mbedtls_hkdf_extract_params);


/*!
 * @brief  Expand the supplied \p prk into several additional pseudorandom
 *          keys, which is the output of the HKDF.
 *
 *  \warning    This function should only be used if the security of it has been
 *              studied and established in that particular context (eg. TLS 1.3
 *              key schedule). For standard HKDF security guarantees use
 *              \c mbedtls_hkdf instead.
 *\param      mbedtls_hkdf_expand_params The structure holding the input and output params
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int32_t mbedtls_hkdf_expand_stz(mbedtls_hkdf_expand_params_t *mbedtls_hkdf_expand_params);

/**
 *  \brief  This is the HMAC-based Extract-and-Expand Key Derivation Function
 *          (HKDF).
 *
 * \param   mbedtls_hkdf_params The structure holding the input and output params
 *
 *  \return 0 on success.
 *  \return #MBEDTLS_ERR_HKDF_BAD_INPUT_DATA when the parameters are invalid.
 *  \return An MBEDTLS_ERR_MD_* error for errors returned from the underlying
 *          MD layer.
 */
int32_t mbedtls_hkdf_stz( mbedtls_hkdf_params_t *mbedtls_hkdf_params);

#ifdef __cplusplus
}
#endif
/** @} */

#endif /* PN76_SHAALT_H_ */
