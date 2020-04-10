// Copyright 2019 CryptoGarage
/**
 * @file cfdcapi_key.h
 *
 * @brief cfd-capiで利用する鍵関連のAPI定義
 */
#ifndef CFD_INCLUDE_CFDC_CFDCAPI_KEY_H_
#define CFD_INCLUDE_CFDC_CFDCAPI_KEY_H_

#ifdef __cplusplus
extern "C" {
#if 0
}
#endif  // 0
#endif  // __cplusplus

#include <stddef.h>
#include <stdint.h>

#include "cfdc/cfdcapi_common.h"

/**
 * @brief extkey type.
 */
enum CfdExtKeyType {
  kCfdExtPrivkey = 0,  //!< extended privkey
  kCfdExtPubkey        //!< extended pubkey
};

/**
 * @brief calcurate ec signature.
 * @param[in] handle        cfd handle.
 * @param[in] sighash       sighash.
 * @param[in] privkey       privkey hex.
 * @param[in] wif           privkey wif.
 * @param[in] network_type  privkey wif network type.
 * @param[in] has_grind_r   grind_r flag.
 * @param[out] signature    signature.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCalculateEcSignature(
    void* handle, const char* sighash, const char* privkey, const char* wif,
    int network_type, bool has_grind_r, char** signature);

/**
 * @brief encode ec signature by der encoding.
 * @param[in] handle                  cfd handle.
 * @param[in] signature               compact signature string.
 * @param[in] sighash_type            sign sighash type.
 * @param[in] sighash_anyone_can_pay  flag of signing only the current input.
 * @param[out] der_signature  signature encoded by der encoding.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdEncodeSignatureByDer(
    void* handle, const char* signature, int sighash_type,
    bool sighash_anyone_can_pay, char** der_signature);

/**
 * @brief decode ec signature from der encoding.
 * @param[in] handle                   cfd handle.
 * @param[in] der_signature            signature encoded by der encoding.
 * @param[out] signature               compact signature string.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] sighash_type            sign sighash type.
 * @param[out] sighash_anyone_can_pay  flag of signing only the current input.
 * @return CfdErrorCode
 */
CFDC_API int CfdDecodeSignatureFromDer(
    void* handle, const char* der_signature, char** signature,
    int* sighash_type, bool* sighash_anyone_can_pay);

/**
 * @brief convert ec signature to low-s form
 * @param[in] handle                  cfd handle.
 * @param[in] signature               to convert ec signature
 * @param[out] normalized_signature   normalized signature
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdNormalizeSignature(
    void* handle, const char* signature, char** normalized_signature);

/**
 * @brief create key pair.
 * @param[in] handle          cfd handle.
 * @param[in] is_compressed   pubkey compressed.
 * @param[in] network_type    privkey wif network type.
 * @param[out] pubkey         pubkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] privkey        privkey hex.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] wif            privkey wif.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateKeyPair(
    void* handle, bool is_compressed, int network_type, char** pubkey,
    char** privkey, char** wif);

/**
 * @brief get privkey from WIF.
 * @param[in] handle          cfd handle.
 * @param[in] wif             privkey wif.
 * @param[in] network_type    privkey wif network type.
 * @param[out] privkey        privkey hex.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetPrivkeyFromWif(
    void* handle, const char* wif, int network_type, char** privkey);

/**
 * @brief get privkey WIF from hex.
 * @param[in] handle         cfd handle.
 * @param[in] privkey        privkey hex.
 * @param[in] network_type   privkey wif network type.
 * @param[in] is_compressed  compress flag.
 * @param[out] wif           privkey wif.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetPrivkeyWif(
    void* handle, const char* privkey, int network_type, bool is_compressed,
    char** wif);

/**
 * @brief parse privkey WIF information.
 * @param[in] handle          cfd handle.
 * @param[in] wif             privkey wif.
 * @param[out] privkey        privkey hex.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] network_type   network type.
 * @param[out] is_compressed  compress flag.
 * @return CfdErrorCode
 */
CFDC_API int CfdParsePrivkeyWif(
    void* handle, const char* wif, char** privkey, int* network_type,
    bool* is_compressed);

/**
 * @brief get pubkey from privkey.
 * @param[in] handle          cfd handle.
 * @param[in] privkey         privkey hex. (or wif)
 * @param[in] wif             privkey wif. (or privkey)
 * @param[in] is_compressed   pubkey compressed.
 * @param[out] pubkey         pubkey hex.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetPubkeyFromPrivkey(
    void* handle, const char* privkey, const char* wif, bool is_compressed,
    char** pubkey);

/**
 * @brief create extkey from seed.
 * @param[in] handle          cfd handle.
 * @param[in] seed_hex        seed data(hex).
 * @param[in] network_type    network type.
 * @param[in] key_type        extkey type.
 * @param[out] extkey         extkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateExtkeyFromSeed(
    void* handle, const char* seed_hex, int network_type, int key_type,
    char** extkey);

/**
 * @brief create extkey from direct info.
 * @param[in] handle          cfd handle.
 * @param[in] network_type    network type.
 * @param[in] key_type        extkey type.
 * @param[in] parent_key      parent key. (If there is no fingerprint)
 * @param[in] fingerprint     fingerprint.
 * @param[in] key             public or private key.
 * @param[in] chain_code      chain code.
 * @param[in] depth           depth.
 * @param[in] child_number    child key number.
 * @param[out] extkey         extkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateExtkey(
    void* handle, int network_type, int key_type, const char* parent_key,
    const char* fingerprint, const char* key, const char* chain_code,
    unsigned char depth, uint32_t child_number, char** extkey);

/**
 * @brief derive extkey from number.
 * @param[in] handle          cfd handle.
 * @param[in] extkey          parent extkey.
 * @param[in] child_number    child key number.
 * @param[in] hardened        hardened flag.
 * @param[in] network_type    network type.
 * @param[in] key_type        extkey type.
 * @param[out] child_extkey   child extkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateExtkeyFromParent(
    void* handle, const char* extkey, uint32_t child_number, bool hardened,
    int network_type, int key_type, char** child_extkey);

/**
 * @brief derive extkey from path.
 * @param[in] handle          cfd handle.
 * @param[in] extkey          parent extkey.
 * @param[in] path            create key path.(ex: 0/0h/0'/0)
 * @param[in] network_type    network type.
 * @param[in] key_type        extkey type.
 * @param[out] child_extkey   child extkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateExtkeyFromParentPath(
    void* handle, const char* extkey, const char* path, int network_type,
    int key_type, char** child_extkey);

/**
 * @brief create extpubkey from extprivkey.
 * @param[in] handle          cfd handle.
 * @param[in] extkey          ext privkey.
 * @param[in] network_type    network type.
 * @param[out] ext_pubkey     ext pubkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdCreateExtPubkey(
    void* handle, const char* extkey, int network_type, char** ext_pubkey);
/**
 * @brief get privkey from extprivkey.
 * @param[in] handle          cfd handle.
 * @param[in] extkey          ext privkey.
 * @param[in] network_type    network type.
 * @param[out] privkey        privkey hex.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] wif            privkey wif.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetPrivkeyFromExtkey(
    void* handle, const char* extkey, int network_type, char** privkey,
    char** wif);

/**
 * @brief get pubkey from extkey.
 * @param[in] handle          cfd handle.
 * @param[in] extkey          extkey.
 * @param[in] network_type    network type.
 * @param[out] pubkey         pubkey.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetPubkeyFromExtkey(
    void* handle, const char* extkey, int network_type, char** pubkey);

/**
 * @brief get parent key path data.
 * @param[in] handle             handle pointer.
 * @param[in] parent_extkey      parent ext key string.
 * @param[in] path               child path.
 * @param[in] child_key_type     child key type. (see CfdDescriptorKeyType)
 * @param[out] key_path_data     key path data.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] child_key         child ext key string.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetParentExtkeyPathData(
    void* handle, const char* parent_extkey, const char* path,
    int child_key_type, char** key_path_data, char** child_key);

/**
 * @brief get extkey information.
 * @param[in] handle             handle pointer.
 * @param[in] extkey             ext key string.
 * @param[out] version           version.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] fingerprint       parent fingerprint.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] chain_code        chain code.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] depth             depth.
 * @param[out] child_number      child number.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetExtkeyInformation(
    void* handle, const char* extkey, char** version, char** fingerprint,
    char** chain_code, uint32_t* depth, uint32_t* child_number);

/**
 * @brief initialize getting mnemonic word list.
 * @param[in] handle            cfd handle.
 * @param[in] language          language. (default: en)
 * @param[out] mnemonic_handle  get mnemonic word handle.
 *   Call 'CfdFreeMnemonicWordList' after you are finished using it.
 * @param[out] max_index        mnemonic word list num.
 * @return CfdErrorCode
 */
CFDC_API int CfdInitializeMnemonicWordList(
    void* handle, const char* language, void** mnemonic_handle,
    uint32_t* max_index);

/**
 * @brief get mnemonic word.
 * @param[in] handle            cfd handle.
 * @param[in] mnemonic_handle   get mnemonic word handle.
 * @param[in] index             index.
 * @param[out] mnemonic_word    mnemonic word.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdGetMnemonicWord(
    void* handle, void* mnemonic_handle, uint32_t index, char** mnemonic_word);

/**
 * @brief free getting mnemonic word list.
 * @param[in] handle            cfd handle.
 * @param[in] mnemonic_handle   get mnemonic word handle.
 * @return CfdErrorCode
 */
CFDC_API int CfdFreeMnemonicWordList(void* handle, void* mnemonic_handle);

/**
 * @brief convert mnemonic to seed.
 * @param[in] handle                 cfd handle.
 * @param[in] mnemonic               mnemonic.
 * @param[in] passphrase             passphrase.
 * @param[in] strict_check           strict check flag.
 * @param[in] language               language. (default: en)
 * @param[in] use_ideographic_space  use ideographic space.
 * @param[out] seed                  seed.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @param[out] entropy               mnemonic word entropy.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdConvertMnemonicToSeed(
    void* handle, const char* mnemonic, const char* passphrase,
    bool strict_check, const char* language, bool use_ideographic_space,
    char** seed, char** entropy);

/**
 * @brief convert entropy to mnemonic.
 * @param[in] handle          cfd handle.
 * @param[in] entropy         mnemonic word entropy.
 * @param[in] language        language. (default: en)
 * @param[out] mnemonic       mnemonic.
 *   If 'CfdFreeStringBuffer' is implemented,
 *   Call 'CfdFreeStringBuffer' after you are finished using it.
 * @return CfdErrorCode
 */
CFDC_API int CfdConvertEntropyToMnemonic(
    void* handle, const char* entropy, const char* language, char** mnemonic);

#ifdef __cplusplus
#if 0
{
#endif  // 0
}
#endif  // __cplusplus

#endif  // CFD_INCLUDE_CFDC_CFDCAPI_KEY_H_
