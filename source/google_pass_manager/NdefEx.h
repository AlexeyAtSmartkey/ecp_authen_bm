#include "NdefEx_helper.h"

#ifndef NDEF_EX_H_INC
#define NDEF_EX_H_INC

typedef struct {
    uint8_t session_id[8];             			// Session ID for Smart Tap secure session
    uint8_t sequence_number;           			// Sequence number for session tracking
    uint8_t status_byte;               			// Status of negotiation/session (0x01 = OK)
    uint8_t authentication_byte;       			// Authentication flag (0x01 for live auth)
    uint8_t terminal_private_key[32]; 			// Ephemeral private key for terminal
    uint8_t terminal_public_key_x[32]; 			// X component of ephemeral terminal public key
    uint8_t terminal_public_key_y[32]; 			// Y component of ephemeral terminal public key
    uint8_t merchant_long_term_private_key[32]; // Lohng-term merchant private key
    uint8_t merchant_long_term_key_version[4]; 	// Long-term merchant key version
	uint8_t mobile_compressed_public_key[33]; 	// Mobile's ephemeral public key (compressed)
	uint8_t skip_second_select;					// Allow skipping second select
//  This vvvvvvvvvvv block must be defined as it is as soon it is used as signing data
	uint8_t der_signature_len;
	uint8_t der_signature[73];
    uint8_t terminal_nonce[32];        			// Terminal-generated nonce
    uint8_t mobile_nonce[32];          			// Mobile device nonce
    uint8_t collector_id[4];           			// Collector ID (e.g., Google Wallet test ID: {0x01, 0x33, 0xEE, 0x80})
    uint8_t terminal_compressed_public_key[33]; // Terminal's ephemeral public key (compressed)
// ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
} SmartTapSessionData;


PN76_Status_t APP_InitMbedCrypto(void);
PN76_Status_t APP_DeInitMbedCrypto(void);
void InitSmartTapSession(SmartTapSessionData *sessionData, int privateKeyVersion);
int GenerateEphemeralTerminalKey(SmartTapSessionData *sessionData);
int ECP_Compress(uint8_t *X, uint8_t *Y, uint8_t *compressed_key);
phStatus_t GenerateSharedSecret(SmartTapSessionData *sessionData);
phStatus_t DecryptGetDataResponse(SmartTapSessionData *sessionData, uint8_t *payload, size_t payload_len, uint8_t *decrypted_data, size_t *decrypted_len);
int ECC_SignData(SmartTapSessionData *sessionData, uint8_t *signature);
int DER_EncodeSignature(const uint8_t *raw_sig, uint8_t *der_sig);
int SignSessionData(SmartTapSessionData *sessionData, uint8_t *buffer);
void ConstructNegotiateNDEF(SmartTapSessionData *sessionData, uint8_t *ndef_buffer, uint8_t *ndef_length);
void ConstructGetDataNDEF(SmartTapSessionData *sessionData, uint8_t *ndef_buffer, uint8_t *ndef_length);


#endif
