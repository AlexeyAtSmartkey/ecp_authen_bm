#include <time.h>
#include <stdlib.h>

#include "PN76_Shaalt.h"  // Secure SHA256 hashing
#include "PN76_Eccalt.h"  // ECC operations API PN7642
#include "PN76_SKM.h"
#include "PN76_SHAALT.h"  // SHA256 и HMAC
#include "PN76_AESALT.h"  // AES-CTR
#include "ecc_alt.h"
#include "sha256_alt.h"
#include "crypto_helper.h"
#include "memory_buffer_alloc.h"

#include "phApp_Init.h"
#include "phacDiscLoop.h"
#include "fsl_debug_console.h"


#ifndef NDEF_EX_HELPER_H_INC
#define NDEF_EX_HELPER_H_INC

#define NDEF_HEADER_SIZE 5
#define ECC_PUBLIC_KEY_SIZE 64  // SECP256R1 public key size (X+Y)

// ----- Flags -----
#define NDEF_FLAG_MB         0x80
#define NDEF_FLAG_ME         0x40
#define NDEF_FLAG_CF         0x20
#define NDEF_FLAG_SR         0x10
#define NDEF_FLAG_IL         0x08

// ----- TNF (Type Name Format) -----
#define NDEF_TNF_EMPTY       0x00
#define NDEF_TNF_WELL_KNOWN  0x01
#define NDEF_TNF_MIME_MEDIA  0x02
#define NDEF_TNF_ABSOLUTE_URI 0x03
#define NDEF_TNF_EXTERNAL    0x04
#define NDEF_TNF_UNKNOWN     0x05
#define NDEF_TNF_UNCHANGED   0x06
#define NDEF_TNF_RESERVED    0x07

// ----- Default Values or Combinations (Optional, for convenience) -----
#define NDEF_HEADER_BEGIN_MASK  (NDEF_FLAG_MB | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL)
#define NDEF_HEADER_MIDDLE_MASK (NDEF_FLAG_SR | NDEF_TNF_EXTERNAL)
#define NDEF_HEADER_END_MASK    (NDEF_FLAG_ME | NDEF_FLAG_SR | NDEF_TNF_EXTERNAL)


/*******************************************************************************
**   Macros
*******************************************************************************/
#define NDEF_BYTE0(mb_flag, me_flag, cf_flag, sr_flag, il_flag, tnf) \
    (uint8_t) ( \
      ((mb_flag) ? NDEF_FLAG_MB : 0) | \
      ((me_flag) ? NDEF_FLAG_ME : 0) | \
      ((cf_flag) ? NDEF_FLAG_CF : 0) | \
      ((sr_flag) ? NDEF_FLAG_SR : 0) | \
      ((il_flag) ? NDEF_FLAG_IL : 0) | \
      ((tnf) & 0x07) \
    )

#define NDEF_HEADER(buffer, offset, header_byte0, type_str) ({ \
    (buffer)[(offset)++] = (header_byte0); \
    (buffer)[(offset)++] = 0x03; \
    uint8_t *length_ptr = &(buffer)[(offset)]; \
    (offset)++; \
    if (type_str != NULL) { \
        (buffer)[(offset)++] = (uint8_t)((type_str)[0]); \
        (buffer)[(offset)++] = (uint8_t)((type_str)[1]); \
        (buffer)[(offset)++] = (uint8_t)((type_str)[2]); \
    } \
    length_ptr; \
})

#define NDEF_HEADER1(buffer, offset, header_byte0, type_str) ({ \
    (buffer)[(offset)++] = (header_byte0); \
    (buffer)[(offset)++] = 0x01; \
    uint8_t *length_ptr = &(buffer)[(offset)]; \
    (offset)++; \
    if (type_str != NULL) { \
        (buffer)[(offset)++] = (uint8_t)((type_str)[0]); \
    } \
    length_ptr; \
})

#define NDEF_HEADER2(buffer, offset, header_byte0, type_str) ({ \
    (buffer)[(offset)++] = (header_byte0); \
    (buffer)[(offset)++] = 0x02; \
    uint8_t *length_ptr = &(buffer)[(offset)]; \
    (offset)++; \
    if (type_str != NULL) { \
        (buffer)[(offset)++] = (uint8_t)((type_str)[0]); \
        (buffer)[(offset)++] = (uint8_t)((type_str)[1]); \
    } \
    length_ptr; \
})

#define NDEF_PUT_TO_BUF(buffer, offset, value) \
		memcpy(buffer + offset, value, sizeof(value)); \
		offset += sizeof(value);

#define NDEF_PUT_BYTE(buffer, offset, value) \
		buffer[offset++] = value;

#define CHECK_STATUS_AND_RETURN(wStatus, condition, message) \
    if ((wStatus & (condition)) != PH_ERR_SUCCESS) { \
        DEBUG_PRINTF(message, wStatus); \
        return wStatus; \
    }

#define DEBUG_PRINT_ARR(msg, pArr, arrLen) \
		DEBUG_PRINTF(msg); \
		for (int i = 0; i < arrLen; i++) {DEBUG_PRINTF("%02X", pArr[i]);} \
		DEBUG_PRINTF("\n");

#define TOSTRING(x) STRINGIFY(x)

#define MBEDTLS_MPI_INIT_SINGLE(x) mbedtls_mpi_init(x)

#define MBEDTLS_MPI_INIT(...) \
    do { \
        void* args[] = { __VA_ARGS__ }; \
        for (int i = 0; i < sizeof(args)/sizeof(args[0]); ++i) { \
            MBEDTLS_MPI_INIT_SINGLE((mbedtls_mpi*)args[i]); \
        } \
    } while (0);

#define MBEDTLS_MPI_FREE_SINGLE(x) mbedtls_mpi_free(x)

#define MBEDTLS_MPI_FREE(...) \
    do { \
        void* args[] = { __VA_ARGS__ }; \
        for (int i = 0; i < sizeof(args)/sizeof(args[0]); ++i) { \
            MBEDTLS_MPI_FREE_SINGLE((mbedtls_mpi*)args[i]); \
        } \
    } while (0);

/*******************************************************************************
**   Static Defines
*******************************************************************************/
//static uint8_t bufferapp[1024];

// (e) Build nested "sig" record (Signature)
//     Data-to-sign = terminal_nonce      (32) ||
//                    mobile device nonce (32) ||
//                    collector_id        ( 4) ||
//                    compressed_key      (33)
#define SIGNED_SESSION_DATA_LEN ( \
		sizeof(((SmartTapSessionData *)0)->terminal_nonce) + \
		sizeof(((SmartTapSessionData *)0)->mobile_nonce) + \
		sizeof(((SmartTapSessionData *)0)->collector_id) + \
		sizeof(((SmartTapSessionData *)0)->terminal_compressed_public_key) \
	)


typedef struct {
	uint8_t cid[4];
	uint8_t ver[4];
	uint8_t key[32];
} LongTermPrivateKey;


// =================================================
//
//                 Test data
//
// =================================================
LongTermPrivateKey* GetTestPrivateKeys(void);
void GenerateRandomBytes(uint8_t *buf, size_t len);
void GenerateSessionID(uint8_t *sessionID);
void GenerateTerminalNonce(uint8_t *termNonce);


#endif
