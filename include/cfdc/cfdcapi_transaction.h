// Copyright 2019 CryptoGarage
/**
 * @file cfdcapi_transaction.h
 *
 * @brief cfd-capiで利用するTransaction作成のAPI定義
 *
 * C言語のAPIを提供する.
 */
#ifndef CFD_INCLUDE_CFDC_CFDCAPI_TRANSACTION_H_
#define CFD_INCLUDE_CFDC_CFDCAPI_TRANSACTION_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif  // 0
#endif  // __cplusplus

#include "cfdc/cfdcapi_address.h"
#include "cfdc/cfdcapi_common.h"

// FIXME elementsを先に作る

/*
CFDC_API int CfdInitializeMultisigSign(
    void* handle, int address_type, const Script& witness_script,
    const Script redeem_script, void** multisign_handle);
CFDC_API int CfdAddMultisigSignData(
    void* handle, void* multisign_handle, const uint8_t* signature,
    uint32_t signature_size, const char* related_pubkey);
CFDC_API int CfdAddMultisigSignDataToDer(
    void* handle, void* multisign_handle, const uint8_t* signature,
    uint32_t signature_size, uint8_t sighashType, bool sighash_anyone_can_pay,
    const char* related_pubkey);
CFDC_API int CfdFreeMultisigSignHandle(void* handle, void* multisign_handle);
CFDC_API int CfdFinalizeMultisigSign(
    void* handle, void* multisign_handle,  // BTC
    const char* tx_hex_string, const Txid& txid, uint32_t vout,
    bool is_witness, char** tx_string);
*/

#if 0
/*
CFDC_API int CfdAddTxSign(void* handle, const char* tx_hex_string,
    const char* txid, uint32_t vout, bool is_witness,
    const uint8_t* data, uint32_t data_size,
    char** tx_string);

CFDC_API int CfdAddTxDerSign(void* handle, const char* tx_hex_string,
    const char* txid, uint32_t vout, bool is_witness,
    const uint8_t* data, uint32_t data_size,
    uint8_t sighashType, bool sighash_anyone_can_pay,
    char** tx_string);


CFDC_API int CfdCreateSighash(void* handle, const char* tx_hex_string,
    int address_type, const char* pubkey, const char* redeem_script,
    int64_t value_satoshi,
    uint8_t** sighash, uint32_t* sighash_size);

- AddTxIn
- AddWitnessStack
- AddTxOut
- GetTxHex
- FreeTx
- GetTxInfo
  - version, locktime, 他
- GetTxIn
- GetTxInCount
- GetTxOut
- GetTxOutCount
- GetWitnessStack
- GetWitnessStackCount

      - Tx
        * CreateRawTransaction
          - InitTx
          - AddTxIn
          - AddWitnessStack
          - AddTxOut
          - GetTxHex
          - FreeTx
          - GetTxInfo
            - version, locktime, 他
          - GetTxIn
          - GetTxInCount
          - GetTxOut
          - GetTxOutCount
          - GetWitnessStack
          - GetWitnessStackCount
        * CreateSignatureHash
          - CreateSignatureHash
        * CalcurateEcSignature
          - CalcurateEcSignature
        * AddSign
          - AddSign
        * AddMultisigSign
          - InitializeMultisigSign
          - AddMultisigSign
          - FinalizeMultisigSign
        * get系
*/
#endif

#ifdef __cplusplus
#if 0
{
#endif  // 0
}
#endif  // __cplusplus

#endif  // CFD_INCLUDE_CFDC_CFDCAPI_TRANSACTION_H_