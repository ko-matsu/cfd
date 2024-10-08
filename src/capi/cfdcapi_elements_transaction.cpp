// Copyright 2019 CryptoGarage
/**
 * @file cfdcapi_elements_transaction.cpp
 *
 * @brief Implementation file of the ConfidentialTransaction process
 *  used by cfd-capi.
 */
#ifndef CFD_DISABLE_CAPI
#ifndef CFD_DISABLE_ELEMENTS
#include "cfdc/cfdcapi_elements_transaction.h"

#include <exception>
#include <map>
#include <string>
#include <vector>

#include "capi/cfdc_internal.h"
#include "cfd/cfd_common.h"
#include "cfd/cfd_elements_address.h"
#include "cfd/cfd_elements_transaction.h"
#include "cfd/cfd_transaction_common.h"
#include "cfd/cfdapi_elements_transaction.h"
#include "cfd/cfdapi_key.h"
#include "cfdc/cfdcapi_common.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_elements_address.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_util.h"

using cfd::ConfidentialKeyBlindParameter;
using cfd::ConfidentialTransactionContext;
using cfd::ConfidentialTransactionController;
using cfd::ElementsAddressFactory;
using cfd::SignParameter;
using cfd::UtxoData;
using cfd::api::ElementsTransactionApi;
using cfd::api::ElementsUtxoAndOption;
using cfd::api::IssuanceOutput;
using cfd::api::KeyApi;
using cfd::api::TxInBlindParameters;
using cfd::api::TxInReissuanceParameters;
using cfd::api::TxOutBlindKeys;
using cfd::core::Address;
using cfd::core::AddressType;
using cfd::core::Amount;
using cfd::core::BlindData;
using cfd::core::BlindFactor;
using cfd::core::BlindParameter;
using cfd::core::BlockHash;
using cfd::core::ByteData;
using cfd::core::ByteData256;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::ConfidentialAssetId;
using cfd::core::ConfidentialNonce;
using cfd::core::ConfidentialTransaction;
using cfd::core::ConfidentialTxIn;
using cfd::core::ConfidentialTxInReference;
using cfd::core::ConfidentialTxOut;
using cfd::core::ConfidentialTxOutReference;
using cfd::core::ConfidentialValue;
using cfd::core::Descriptor;
using cfd::core::ElementsConfidentialAddress;
using cfd::core::HashType;
using cfd::core::IssuanceBlindingKeyPair;
using cfd::core::NetType;
using cfd::core::OutPoint;
using cfd::core::Privkey;
using cfd::core::Pubkey;
using cfd::core::Script;
using cfd::core::ScriptUtil;
using cfd::core::SigHashAlgorithm;
using cfd::core::SigHashType;
using cfd::core::Txid;
using cfd::core::UnblindParameter;
using cfd::core::WitnessVersion;

using cfd::core::logger::info;
using cfd::core::logger::warn;

// =============================================================================
// internal c-api
// =============================================================================
namespace cfd {
namespace capi {

//! prefix: Blind Transaction Data
constexpr const char* const kPrefixBlindTxData = "BlindTxData";

/**
 * @brief cfd-capi Blind Transaction Data構造体.
 * @details 最大情報量が多すぎるため、flat structにはしない。
 */
struct CfdCapiBlindTxData {
  char prefix[kPrefixLength];  //!< buffer prefix
  //! txin list
  std::vector<TxInBlindParameters>* txin_blind_keys;
  //! txout list
  std::vector<TxOutBlindKeys>* txout_blind_keys;
  int64_t minimum_range_value;  //!< min range value. (default:1)
  int exponent;                 //!< exponent. (default:0)
  int minimum_bits;             //!< min bits. (default:36(old),52(new))
  bool has_collect_blinder;     //!< collect blinder (default: false)
  //! blinder list
  std::vector<BlindData>* blinder_list;
};

/**
 * @brief convert to issuance output parameter.
 * @param[in] address           address
 * @param[in] locking_script    locking script
 * @return issuance output parameter
 */
static cfd::IssuanceOutputParameter ConvertToIssuanceParameter(
    const char* address, const char* locking_script) {
  cfd::IssuanceOutputParameter data;
  data.is_remove_nonce = false;
  if (!IsEmptyString(address)) {
    auto prefix_list = cfd::core::GetElementsAddressFormatList();
    Address addr;
    if (ElementsConfidentialAddress::IsConfidentialAddress(
            address, prefix_list)) {
      data.confidential_address =
          ElementsConfidentialAddress(address, prefix_list);
    } else {
      data.address = Address(address, prefix_list);
    }
  } else {
    data.direct_locking_script = Script(locking_script);
  }
  return data;
}

}  // namespace capi
}  // namespace cfd

// =============================================================================
// extern c-api
// =============================================================================
using cfd::capi::AllocBuffer;
using cfd::capi::CfdCapiBlindTxData;
using cfd::capi::CfdCapiMultisigSignData;
using cfd::capi::CfdCapiTransactionData;
using cfd::capi::CheckBuffer;
using cfd::capi::CheckEmptyString;
using cfd::capi::ConvertAddressType;
using cfd::capi::ConvertHashToAddressType;
using cfd::capi::ConvertNetType;
using cfd::capi::ConvertToIssuanceParameter;
using cfd::capi::CreateString;
using cfd::capi::FreeBuffer;
using cfd::capi::FreeBufferOnError;
using cfd::capi::IsElementsNetType;
using cfd::capi::IsEmptyString;
using cfd::capi::kEmpty32Bytes;
using cfd::capi::kMultisigMaxKeyNum;
using cfd::capi::kPrefixBlindTxData;
using cfd::capi::kPrefixMultisigSignData;
using cfd::capi::kPrefixTransactionData;
using cfd::capi::kPubkeyHexSize;
using cfd::capi::SetLastError;
using cfd::capi::SetLastFatalError;

// API
extern "C" {

int CfdSetGenesisBlockHashGlobal(
    void* handle, const char* genesis_block_hash) {
  try {
    cfd::Initialize();
    if (IsEmptyString(genesis_block_hash)) {
      warn(CFD_LOG_SOURCE, "genesis_block_hash is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. genesis_block_hash is null or empty.");
    }

    BlockHash block_hash(genesis_block_hash);
    ConfidentialTransactionContext::SetDefaultGenesisBlockHash(block_hash);
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdInitializeConfidentialTx(
    void* handle, uint32_t version, uint32_t locktime, char** tx_string) {
  try {
    cfd::Initialize();
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }

    ConfidentialTransactionController ctxc(version, locktime);
    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxIn(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    uint32_t sequence, char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    ctxc.AddTxIn(Txid(txid), vout, sequence);
    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxOut(
    void* handle, const char* tx_hex_string, const char* asset_string,
    int64_t value_satoshi, const char* value_commitment, const char* address,
    const char* direct_locking_script, const char* nonce, char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }
    if (IsEmptyString(asset_string)) {
      warn(CFD_LOG_SOURCE, "asset is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null or empty.");
    }

    ConfidentialTransactionContext ctxc(tx_hex_string);

    Amount amount;
    if (IsEmptyString(value_commitment)) {
      amount = Amount::CreateBySatoshiAmount(value_satoshi);
    } else {
      ConfidentialValue value = ConfidentialValue(value_commitment);
      // unconfidential only
      if (!value.HasBlinding()) amount = value.GetAmount();
    }

    // add TxOut
    ElementsAddressFactory address_factory;
    ConfidentialAssetId asset_obj(asset_string);
    ConfidentialNonce nonce_obj;
    if (!IsEmptyString(nonce)) {
      nonce_obj = ConfidentialNonce(nonce);
    }
    if (!IsEmptyString(address)) {
      // const std::string addr(address);
      if (ElementsConfidentialAddress::IsConfidentialAddress(address)) {
        ElementsConfidentialAddress confidential_addr(address);
        ctxc.AddTxOut(confidential_addr, amount, asset_obj, false);
      } else {
        Address addr = address_factory.GetAddress(address);
        ctxc.AddTxOut(amount, asset_obj, addr.GetLockingScript(), nonce_obj);
      }
    } else if (!IsEmptyString(direct_locking_script)) {
      Script script(direct_locking_script);
      ctxc.AddTxOut(amount, asset_obj, script, nonce_obj);
    } else if (amount > 0) {
      // fee
      ctxc.UpdateFeeAmount(amount, asset_obj);
    }

    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdUpdateConfidentialTxOut(
    void* handle, const char* tx_hex_string, uint32_t index,
    const char* asset_string, int64_t value_satoshi,
    const char* value_commitment, const char* address,
    const char* direct_locking_script, const char* nonce, char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }
    if (IsEmptyString(asset_string)) {
      warn(CFD_LOG_SOURCE, "asset is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null or empty.");
    }

    ConfidentialTransactionContext ctx(tx_hex_string);
    if (ctx.HasBlinding()) {
      warn(CFD_LOG_SOURCE, "tx is already blinded.");
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Failed to blinded. this function can use unblind tx only.");
    }

    ConfidentialValue value;
    if (IsEmptyString(value_commitment)) {
      value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_satoshi));
    } else {
      ConfidentialValue temp_value = ConfidentialValue(value_commitment);
      // unconfidential only
      if (!temp_value.HasBlinding()) value = temp_value;
    }

    // add TxOut
    ElementsAddressFactory address_factory;
    ConfidentialAssetId asset_obj(asset_string);
    ConfidentialNonce nonce_obj;
    if (!IsEmptyString(nonce)) {
      nonce_obj = ConfidentialNonce(std::string(nonce));
    }
    Script locking_script;
    if (!IsEmptyString(address)) {
      const std::string addr(address);
      if (ElementsConfidentialAddress::IsConfidentialAddress(addr)) {
        ElementsConfidentialAddress confidential_addr(addr);
        locking_script = confidential_addr.GetLockingScript();
      } else {
        Address unconfidential_addr = address_factory.GetAddress(addr);
        locking_script = unconfidential_addr.GetLockingScript();
      }
    } else if (!IsEmptyString(direct_locking_script)) {
      locking_script = Script(std::string(direct_locking_script));
    }

    ctx.SetTxOutCommitment(
        index, asset_obj, value, nonce_obj, ByteData(), ByteData());
    *tx_string = CreateString(ctx.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInfo(
    void* handle, const char* tx_hex_string, char** txid, char** wtxid,
    char** wit_hash, uint32_t* size, uint32_t* vsize, uint32_t* weight,
    uint32_t* version, uint32_t* locktime) {
  int error_code = CfdErrorCode::kCfdUnknownError;
  char* work_txid = nullptr;
  char* work_wtxid = nullptr;
  char* work_wit_hash = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();

    if (txid != nullptr) {
      work_txid = CreateString(tx.GetTxid().GetHex());
    }
    if (wtxid != nullptr) {
      work_wtxid = CreateString(Txid(tx.GetWitnessHash()).GetHex());
    }
    if (wit_hash != nullptr) {
      work_wit_hash = CreateString(Txid(tx.GetWitnessOnlyHash()).GetHex());
    }
    if (size != nullptr) {
      *size = tx.GetTotalSize();
    }
    if (vsize != nullptr) {
      *vsize = tx.GetVsize();
    }
    if (weight != nullptr) {
      *weight = tx.GetWeight();
    }
    if (version != nullptr) {
      *version = tx.GetVersion();
    }
    if (locktime != nullptr) {
      *locktime = tx.GetLockTime();
    }

    if (work_txid != nullptr) *txid = work_txid;
    if (work_wtxid != nullptr) *wtxid = work_wtxid;
    if (work_wit_hash != nullptr) *wit_hash = work_wit_hash;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    error_code = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  FreeBufferOnError(&work_txid, &work_wtxid, &work_wit_hash);
  return error_code;
}

int CfdGetConfidentialTxIn(
    void* handle, const char* tx_hex_string, uint32_t index, char** txid,
    uint32_t* vout, uint32_t* sequence, char** script_sig) {
  char* work_txid = nullptr;
  char* work_script_sig = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();
    const ConfidentialTxInReference ref = tx.GetTxIn(index);

    if (txid != nullptr) {
      work_txid = CreateString(ref.GetTxid().GetHex());
    }
    if (vout != nullptr) {
      *vout = ref.GetVout();
    }
    if (sequence != nullptr) {
      *sequence = ref.GetSequence();
    }
    if (script_sig != nullptr) {
      work_script_sig = CreateString(ref.GetUnlockingScript().GetHex());
    }

    if (work_txid != nullptr) *txid = work_txid;
    if (work_script_sig != nullptr) *script_sig = work_script_sig;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(&work_txid, &work_script_sig);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(&work_txid, &work_script_sig);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(&work_txid, &work_script_sig);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInWitness(
    void* handle, const char* tx_hex_string, uint32_t txin_index,
    uint32_t stack_index, char** stack_data) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (stack_data == nullptr) {
      warn(CFD_LOG_SOURCE, "stack data is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. stack data is null.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();
    const ConfidentialTxInReference ref = tx.GetTxIn(txin_index);

    const std::vector<ByteData> witness_stack =
        ref.GetScriptWitness().GetWitness();
    if (witness_stack.size() <= stack_index) {
      warn(CFD_LOG_SOURCE, "stackIndex is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. stackIndex out of witness stack.");
    }
    *stack_data = CreateString(witness_stack[stack_index].GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInPeginWitness(
    void* handle, const char* tx_hex_string, uint32_t txin_index,
    uint32_t stack_index, char** stack_data) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (stack_data == nullptr) {
      warn(CFD_LOG_SOURCE, "stack data is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. stack data is null.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);
    const ConfidentialTxInReference ref = tx.GetTxIn(txin_index);

    const std::vector<ByteData> witness_stack =
        ref.GetPeginWitness().GetWitness();
    if (witness_stack.size() <= stack_index) {
      warn(CFD_LOG_SOURCE, "stackIndex is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. stackIndex out of pegin witness.");
    }
    *stack_data = CreateString(witness_stack[stack_index].GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetTxInIssuanceInfo(
    void* handle, const char* tx_hex_string, uint32_t index, char** entropy,
    char** nonce, int64_t* asset_amount, char** asset_value,
    int64_t* token_amount, char** token_value, char** asset_rangeproof,
    char** token_rangeproof) {
  char* work_entropy = nullptr;
  char* work_nonce = nullptr;
  char* work_asset_value = nullptr;
  char* work_token_value = nullptr;
  char* work_asset_rangeproof = nullptr;
  char* work_token_rangeproof = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();
    const ConfidentialTxInReference ref = tx.GetTxIn(index);

    if (entropy != nullptr) {
      work_entropy = CreateString(BlindFactor(ref.GetAssetEntropy()).GetHex());
    }
    if (nonce != nullptr) {
      work_nonce = CreateString(BlindFactor(ref.GetBlindingNonce()).GetHex());
    }
    const ConfidentialValue& asset_obj = ref.GetIssuanceAmount();
    const ConfidentialValue& token_obj = ref.GetInflationKeys();
    if ((asset_amount != nullptr) && (!asset_obj.HasBlinding())) {
      *asset_amount = (asset_obj.HasBlinding())
                          ? 0
                          : asset_obj.GetAmount().GetSatoshiValue();
    }
    if (asset_value != nullptr) {
      work_asset_value = CreateString(asset_obj.GetHex());
    }
    if ((token_amount != nullptr) && (!token_obj.HasBlinding())) {
      *token_amount = (token_obj.HasBlinding())
                          ? 0
                          : token_obj.GetAmount().GetSatoshiValue();
    }
    if (token_value != nullptr) {
      work_token_value = CreateString(token_obj.GetHex());
    }
    if (asset_rangeproof != nullptr) {
      work_asset_rangeproof =
          CreateString(ref.GetIssuanceAmountRangeproof().GetHex());
    }
    if (token_rangeproof != nullptr) {
      work_token_rangeproof =
          CreateString(ref.GetInflationKeysRangeproof().GetHex());
    }

    if (work_entropy != nullptr) *entropy = work_entropy;
    if (work_nonce != nullptr) *nonce = work_nonce;
    if (work_asset_value != nullptr) *asset_value = work_asset_value;
    if (work_token_value != nullptr) *token_value = work_token_value;
    if (work_asset_rangeproof != nullptr)
      *asset_rangeproof = work_asset_rangeproof;
    if (work_token_rangeproof != nullptr)
      *token_rangeproof = work_token_rangeproof;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxOut(
    void* handle, const char* tx_hex_string, uint32_t index,
    char** asset_string, int64_t* value_satoshi, char** value_commitment,
    char** nonce, char** locking_script, char** surjection_proof,
    char** rangeproof) {
  char* work_asset_string = nullptr;
  char* work_value_commitment = nullptr;
  char* work_nonce = nullptr;
  char* work_locking_script = nullptr;
  char* work_surjection_proof = nullptr;
  char* work_rangeproof = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();
    const ConfidentialTxOutReference ref = tx.GetTxOut(index);

    if (asset_string != nullptr) {
      work_asset_string = CreateString(ref.GetAsset().GetHex());
    }
    ConfidentialValue value = ref.GetConfidentialValue();
    if ((value_satoshi != nullptr) && (!value.HasBlinding())) {
      *value_satoshi = value.GetAmount().GetSatoshiValue();
    }
    if (value_commitment != nullptr) {
      work_value_commitment = CreateString(value.GetHex());
    }
    if (nonce != nullptr) {
      work_nonce = CreateString(ref.GetNonce().GetHex());
    }
    if (locking_script != nullptr) {
      work_locking_script = CreateString(ref.GetLockingScript().GetHex());
    }
    if (surjection_proof != nullptr) {
      work_surjection_proof = CreateString(ref.GetSurjectionProof().GetHex());
    }
    if (rangeproof != nullptr) {
      work_rangeproof = CreateString(ref.GetRangeProof().GetHex());
    }

    if (work_asset_string != nullptr) *asset_string = work_asset_string;
    if (work_value_commitment != nullptr)
      *value_commitment = work_value_commitment;
    if (work_nonce != nullptr) *nonce = work_nonce;
    if (work_locking_script != nullptr) *locking_script = work_locking_script;
    if (work_surjection_proof != nullptr)
      *surjection_proof = work_surjection_proof;
    if (work_rangeproof != nullptr) *rangeproof = work_rangeproof;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInCount(
    void* handle, const char* tx_hex_string, uint32_t* count) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    const ConfidentialTransaction& tx = ctxc.GetTransaction();

    if (count != nullptr) {
      *count = tx.GetTxInCount();
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInWitnessCount(
    void* handle, const char* tx_hex_string, uint32_t txin_index,
    uint32_t* count) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);
    const ConfidentialTxInReference ref = tx.GetTxIn(txin_index);

    if (count != nullptr) {
      *count = ref.GetScriptWitnessStackNum();
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInPeginWitnessCount(
    void* handle, const char* tx_hex_string, uint32_t txin_index,
    uint32_t* count) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);
    const ConfidentialTxInReference ref = tx.GetTxIn(txin_index);
    if (count != nullptr) {
      *count = ref.GetPeginWitnessStackNum();
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxOutCount(
    void* handle, const char* tx_hex_string, uint32_t* count) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);

    if (count != nullptr) {
      *count = tx.GetTxOutCount();
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxInIndex(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    uint32_t* index) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);
    OutPoint outpoint(Txid(txid), vout);
    if (index != nullptr) {
      *index = tx.GetTxInIndex(outpoint);
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxOutIndex(
    void* handle, const char* tx_hex_string, const char* address,
    const char* direct_locking_script, uint32_t* index) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionContext tx(tx_hex_string);
    bool is_find = false;

    if (!IsEmptyString(direct_locking_script)) {
      is_find = tx.IsFindTxOut(Script(direct_locking_script), index);
    } else if (!IsEmptyString(address)) {
      ElementsAddressFactory address_factory;
      std::string addr_str(address);
      Address addr;
      if (ElementsConfidentialAddress::IsConfidentialAddress(addr_str)) {
        addr = address_factory.GetConfidentialAddress(addr_str)
                   .GetUnblindedAddress();
      } else {
        addr = address_factory.GetAddress(addr_str);
      }
      is_find = tx.IsFindTxOut(addr, index);
    } else {
      // fee
      is_find = tx.IsFindFeeTxOut(index);
    }
    if (!is_find) {
      warn(CFD_LOG_SOURCE, "target not found.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. search target is not found.");
    }

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdSetRawReissueAsset(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    int64_t asset_amount, const char* blinding_nonce, const char* entropy,
    const char* address, const char* direct_locking_script,
    char** asset_string, char** tx_string) {
  char* work_asset_string = nullptr;
  char* work_tx_string = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. output tx is null.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (IsEmptyString(blinding_nonce)) {
      warn(CFD_LOG_SOURCE, "blinding nonce is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blinding nonce is null or empty.");
    }
    if (IsEmptyString(entropy)) {
      warn(CFD_LOG_SOURCE, "entropy is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. entropy is null or empty.");
    }

    ConfidentialTxOut asset_txout;
    Amount amount = Amount::CreateBySatoshiAmount(asset_amount);
    ElementsAddressFactory address_factory;
    if (!IsEmptyString(address)) {
      std::string addr(address);
      if (ElementsConfidentialAddress::IsConfidentialAddress(addr)) {
        ElementsConfidentialAddress confidential_addr(addr);
        asset_txout = ConfidentialTxOut(
            confidential_addr, ConfidentialAssetId(), amount);
      } else {
        Address unblind_addr = address_factory.GetAddress(addr);
        asset_txout =
            ConfidentialTxOut(unblind_addr, ConfidentialAssetId(), amount);
      }
    } else if (!IsEmptyString(direct_locking_script)) {
      Script script(direct_locking_script);
      asset_txout = ConfidentialTxOut(
          script, ConfidentialAssetId(), ConfidentialValue(amount));
    }

    TxInReissuanceParameters params;
    params.txid = Txid(std::string(txid));
    params.vout = vout;
    params.amount = amount;
    params.asset_txout = asset_txout;
    params.blind_factor = BlindFactor(std::string(blinding_nonce));
    params.entropy = BlindFactor(std::string(entropy));

    ElementsTransactionApi api;
    std::vector<IssuanceOutput> outputs;
    std::vector<TxInReissuanceParameters> issuances{params};
    ConfidentialTransactionController ctxc =
        api.SetRawReissueAsset(tx_hex_string, issuances, &outputs);

    if (!outputs.empty() && (asset_string != nullptr)) {
      work_asset_string = CreateString(outputs[0].output.asset.GetHex());
    }
    work_tx_string = CreateString(ctxc.GetHex());

    if (work_asset_string != nullptr) *asset_string = work_asset_string;
    *tx_string = work_tx_string;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(&work_asset_string, &work_tx_string);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(&work_asset_string, &work_tx_string);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(&work_asset_string, &work_tx_string);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetIssuanceBlindingKey(
    void* handle, const char* master_blinding_key, const char* txid,
    uint32_t vout, char** blinding_key) {
  try {
    cfd::Initialize();
    if (IsEmptyString(master_blinding_key)) {
      warn(CFD_LOG_SOURCE, "master blinding key is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. master blinding key is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (blinding_key == nullptr) {
      warn(CFD_LOG_SOURCE, "blinding key is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blinding key is null.");
    }

    ElementsTransactionApi api;
    Privkey privkey = api.GetIssuanceBlindingKey(
        Privkey(std::string(master_blinding_key)), Txid(txid),
        static_cast<int32_t>(vout));

    *blinding_key = CreateString(privkey.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetDefaultBlindingKey(
    void* handle, const char* master_blinding_key, const char* locking_script,
    char** blinding_key) {
  try {
    cfd::Initialize();
    if (IsEmptyString(master_blinding_key)) {
      warn(CFD_LOG_SOURCE, "master blinding key is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. master blinding key is null or empty.");
    }
    if (IsEmptyString(locking_script)) {
      warn(CFD_LOG_SOURCE, "locking script is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. locking script is null or empty.");
    }
    if (blinding_key == nullptr) {
      warn(CFD_LOG_SOURCE, "blinding key is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blinding key is null.");
    }

    Privkey privkey = ElementsConfidentialAddress::GetBlindingKey(
        Privkey(std::string(master_blinding_key)),
        Script(std::string(locking_script)));
    *blinding_key = CreateString(privkey.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdInitializeBlindTx(void* handle, void** blind_handle) {
  CfdCapiBlindTxData* buffer = nullptr;
  try {
    cfd::Initialize();
    if (blind_handle == nullptr) {
      warn(CFD_LOG_SOURCE, "blind handle is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blind handle is null.");
    }

    buffer = static_cast<CfdCapiBlindTxData*>(
        AllocBuffer(kPrefixBlindTxData, sizeof(CfdCapiBlindTxData)));
    buffer->txin_blind_keys = new std::vector<TxInBlindParameters>();
    buffer->txout_blind_keys = new std::vector<TxOutBlindKeys>();
    buffer->blinder_list = new std::vector<BlindData>();
    buffer->minimum_range_value = 1;                 // = 1,
    buffer->exponent = 0;                            // = 0
    buffer->minimum_bits = cfd::capi::kMinimumBits;  // = 36(old)
    buffer->has_collect_blinder = false;

    *blind_handle = buffer;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    if (buffer != nullptr) CfdFreeBlindHandle(handle, buffer);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    if (buffer != nullptr) CfdFreeBlindHandle(handle, buffer);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    if (buffer != nullptr) CfdFreeBlindHandle(handle, buffer);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddBlindTxInData(
    void* handle, void* blind_handle, const char* txid, uint32_t vout,
    const char* asset_string, const char* asset_blind_factor,
    const char* value_blind_factor, int64_t value_satoshi,
    const char* asset_key, const char* token_key) {
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    if (buffer->txin_blind_keys == nullptr) {
      warn(CFD_LOG_SOURCE, "buffer state is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. buffer state is illegal.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (IsEmptyString(asset_string)) {
      warn(CFD_LOG_SOURCE, "asset is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null or empty.");
    }

    TxInBlindParameters params;
    params.txid = Txid(txid);
    params.vout = vout;
    params.blind_param.asset = ConfidentialAssetId(asset_string);
    params.blind_param.value =
        ConfidentialValue(Amount::CreateBySatoshiAmount(value_satoshi));
    if (IsEmptyString(asset_blind_factor)) {
      params.blind_param.abf = BlindFactor(kEmpty32Bytes);
    } else {
      params.blind_param.abf = BlindFactor(asset_blind_factor);
    }
    if (IsEmptyString(value_blind_factor)) {
      params.blind_param.vbf = BlindFactor(kEmpty32Bytes);
    } else {
      params.blind_param.vbf = BlindFactor(value_blind_factor);
    }

    params.is_issuance = false;
    if (!IsEmptyString(asset_key)) {
      params.is_issuance = true;
      params.issuance_key.asset_key = Privkey(asset_key);
    }
    if (!IsEmptyString(token_key)) {
      params.is_issuance = true;
      params.issuance_key.token_key = Privkey(token_key);
    }

    buffer->txin_blind_keys->push_back(params);
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddBlindTxOutData(
    void* handle, void* blind_handle, uint32_t index,
    const char* confidential_key) {
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    if (buffer->txout_blind_keys == nullptr) {
      warn(CFD_LOG_SOURCE, "buffer state is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. buffer state is illegal.");
    }
    if (confidential_key == nullptr) {
      warn(CFD_LOG_SOURCE, "confidential key is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. confidential key is null.");
    }

    TxOutBlindKeys params;
    params.index = index;
    params.confidential_key = Pubkey(confidential_key);

    buffer->txout_blind_keys->push_back(params);
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddBlindTxOutByAddress(
    void* handle, void* blind_handle, const char* confidential_address) {
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    if (buffer->txout_blind_keys == nullptr) {
      warn(CFD_LOG_SOURCE, "buffer state is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. buffer state is illegal.");
    }
    if (confidential_address == nullptr) {
      warn(CFD_LOG_SOURCE, "confidential address is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. confidential address is null.");
    }

    TxOutBlindKeys params;
    params.confidential_address = std::string(confidential_address);
    buffer->txout_blind_keys->push_back(params);
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdSetBlindTxOption(
    void* handle, void* blind_handle, int key, int64_t value) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    switch (key) {
      case CfdBlindOption::kCfdBlindOptionMinimumRangeValue:
        buffer->minimum_range_value = value;
        break;
      case CfdBlindOption::kCfdBlindOptionExponent:
        buffer->exponent = static_cast<int>(value);
        break;
      case CfdBlindOption::kCfdBlindOptionMinimumBits:
        if (value >= 0) buffer->minimum_bits = static_cast<int>(value);
        break;
      case CfdBlindOption::kCfdBlindOptionCollectBlinder:
        if (value != 0) buffer->has_collect_blinder = true;
        break;
      default:
        warn(CFD_LOG_SOURCE, "illegal option key. [{}]", key);
        throw CfdException(
            CfdError::kCfdOutOfRangeError, "Failed to blind option key.");
    }

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdFinalizeBlindTx(
    void* handle, void* blind_handle, const char* tx_hex_string,
    char** tx_string) {
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. output tx is null.");
    }

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    if ((buffer->txin_blind_keys == nullptr) ||
        (buffer->txout_blind_keys == nullptr) ||
        (buffer->blinder_list == nullptr)) {
      warn(CFD_LOG_SOURCE, "buffer state is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. buffer state is illegal.");
    }
    if (buffer->txin_blind_keys->empty()) {
      warn(CFD_LOG_SOURCE, "txin blind data is empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txin blind data is empty.");
    }

    std::map<OutPoint, BlindParameter> utxo_info_map;
    std::map<OutPoint, IssuanceBlindingKeyPair> issuance_key_map;
    std::vector<ElementsConfidentialAddress> confidential_key_list;

    ConfidentialTransactionContext ctxc(tx_hex_string);

    for (const auto& txin_data : *buffer->txin_blind_keys) {
      OutPoint outpoint(txin_data.txid, txin_data.vout);
      utxo_info_map.emplace(outpoint, txin_data.blind_param);
      if (txin_data.is_issuance) {
        issuance_key_map.emplace(outpoint, txin_data.issuance_key);
      }
    }

    std::vector<ConfidentialKeyBlindParameter> direct_key_list;
    ElementsAddressFactory address_factory;
    for (const auto& data : *buffer->txout_blind_keys) {
      if (data.confidential_key.IsValid()) {
        Address addr =
            ctxc.GetTxOutAddress(data.index, NetType::kLiquidV1, true);
        if (addr.GetAddress().empty()) {
          // set direct confidential key
          ConfidentialKeyBlindParameter param = {
              data.index, data.confidential_key};
          direct_key_list.emplace_back(param);
        } else {
          confidential_key_list.emplace_back(addr, data.confidential_key);
        }
      } else if (!data.confidential_address.empty()) {
        confidential_key_list.push_back(
            address_factory.GetConfidentialAddress(data.confidential_address));
      }
    }

    std::vector<BlindData>* blinder_list_ptr = nullptr;
    if (buffer->has_collect_blinder) {
      blinder_list_ptr = buffer->blinder_list;
    }
    ctxc.BlindTransactionWithDirectKey(
        utxo_info_map, issuance_key_map, confidential_key_list,
        direct_key_list, buffer->minimum_range_value, buffer->exponent,
        buffer->minimum_bits, blinder_list_ptr);
    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetBlindTxBlindData(
    void* handle, void* blind_handle, uint32_t index, uint32_t* vout,
    char** asset, int64_t* value_satoshi, char** asset_blind_factor,
    char** value_blind_factor, char** issuance_txid, uint32_t* issuance_vout,
    bool* is_issuance_asset, bool* is_issuance_token) {
  int result = CfdErrorCode::kCfdUnknownError;
  char* work_asset = nullptr;
  char* work_asset_blind_factor = nullptr;
  char* work_value_blind_factor = nullptr;
  char* work_txid = nullptr;
  try {
    cfd::Initialize();
    CheckBuffer(blind_handle, kPrefixBlindTxData);

    CfdCapiBlindTxData* buffer =
        static_cast<CfdCapiBlindTxData*>(blind_handle);
    if (buffer->blinder_list == nullptr) {
      warn(CFD_LOG_SOURCE, "buffer state is illegal.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. buffer state is illegal.");
    }
    if (!buffer->has_collect_blinder) {
      warn(CFD_LOG_SOURCE, "unused collect blinder.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to collect state. unused collect blinder.");
    }
    if (index >= buffer->blinder_list->size()) {
      warn(CFD_LOG_SOURCE, "index out of range.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "Failed to parameter. index out of range.");
    }

    auto& data = (*buffer->blinder_list)[index];
    if (vout != nullptr) *vout = data.vout;
    if (asset != nullptr) {
      work_asset = CreateString(data.asset.GetHex());
    }
    if (value_satoshi != nullptr) {
      *value_satoshi = data.value.GetAmount().GetSatoshiValue();
    }
    if (asset_blind_factor != nullptr) {
      work_asset_blind_factor = CreateString(data.abf.GetHex());
    }
    if (value_blind_factor != nullptr) {
      work_value_blind_factor = CreateString(data.vbf.GetHex());
    }
    if ((issuance_txid != nullptr) && (issuance_vout != nullptr)) {
      *issuance_vout = data.issuance_outpoint.GetVout();
      work_txid = CreateString(data.issuance_outpoint.GetTxid().GetHex());
    }
    if (is_issuance_asset != nullptr) *is_issuance_asset = data.is_issuance;
    if (is_issuance_token != nullptr) {
      *is_issuance_token = data.is_issuance_token;
    }

    if (work_asset != nullptr) *asset = work_asset;
    if (work_asset_blind_factor != nullptr)
      *asset_blind_factor = work_asset_blind_factor;
    if (work_value_blind_factor != nullptr)
      *value_blind_factor = work_value_blind_factor;
    if (work_txid != nullptr) *issuance_txid = work_txid;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  FreeBufferOnError(&work_asset, &work_asset_blind_factor);
  FreeBufferOnError(&work_value_blind_factor, &work_txid);
  return result;
}

int CfdFreeBlindHandle(void* handle, void* blind_handle) {
  try {
    cfd::Initialize();
    if (blind_handle != nullptr) {
      CfdCapiBlindTxData* blind_tx_struct =
          static_cast<CfdCapiBlindTxData*>(blind_handle);
      if (blind_tx_struct->txin_blind_keys != nullptr) {
        delete blind_tx_struct->txin_blind_keys;
        blind_tx_struct->txin_blind_keys = nullptr;
      }
      if (blind_tx_struct->txout_blind_keys != nullptr) {
        delete blind_tx_struct->txout_blind_keys;
        blind_tx_struct->txout_blind_keys = nullptr;
      }
      if (blind_tx_struct->blinder_list != nullptr) {
        delete blind_tx_struct->blinder_list;
        blind_tx_struct->blinder_list = nullptr;
      }
    }
    FreeBuffer(blind_handle, kPrefixBlindTxData, sizeof(CfdCapiBlindTxData));
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxSign(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    bool is_witness, const char* sign_data_hex, bool clear_stack,
    char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }

    // if using witness, enable empty data.
    if ((is_witness && (sign_data_hex == nullptr)) ||
        (!is_witness && IsEmptyString(sign_data_hex))) {
      warn(CFD_LOG_SOURCE, "sign data is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. sign data is null or empty.");
    }

    std::vector<SignParameter> sign_list;
    sign_list.emplace_back(std::string(sign_data_hex));

    ElementsTransactionApi api;
    ConfidentialTransactionController ctxc = api.AddSign(
        std::string(tx_hex_string), Txid(std::string(txid)), vout, sign_list,
        is_witness, clear_stack);
    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxDerSign(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    bool is_witness, const char* signature, int sighash_type,
    bool sighash_anyone_can_pay, bool clear_stack, char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(signature)) {
      warn(CFD_LOG_SOURCE, "pubkey is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. pubkey is null or empty.");
    }

    // encode to der
    SigHashType sighashtype = SigHashType::Create(
        static_cast<uint8_t>(sighash_type), sighash_anyone_can_pay);
    ByteData signature_bytes = ByteData(std::string(signature));
    SignParameter param(signature_bytes, true, sighashtype);
    ByteData signature_der = param.ConvertToSignature();

    return CfdAddConfidentialTxSign(
        handle, tx_hex_string, txid, vout, is_witness,
        signature_der.GetHex().c_str(), clear_stack, tx_string);
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdFinalizeElementsMultisigSign(
    void* handle, void* multisign_handle, const char* tx_hex_string,
    const char* txid, uint32_t vout, int hash_type, const char* witness_script,
    const char* redeem_script, bool clear_stack, char** tx_string) {
  try {
    cfd::Initialize();
    CheckBuffer(multisign_handle, kPrefixMultisigSignData);
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }

    Script witness_script_obj;
    Script redeem_script_obj;
    AddressType addr_type = ConvertHashToAddressType(hash_type);
    switch (addr_type) {
      case AddressType::kP2shAddress:
        if (IsEmptyString(redeem_script)) {
          warn(CFD_LOG_SOURCE, "redeemScript is null or empty.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to parameter. redeemScript is null or empty.");
        }
        redeem_script_obj = Script(std::string(redeem_script));
        break;
      case AddressType::kP2wshAddress:
        // fall-through
      case AddressType::kP2shP2wshAddress:
        if (IsEmptyString(witness_script)) {
          warn(CFD_LOG_SOURCE, "witnessScript is null or empty.");
          throw CfdException(
              CfdError::kCfdIllegalArgumentError,
              "Failed to parameter. witnessScript is null or empty.");
        }
        witness_script_obj = Script(std::string(witness_script));
        break;
      default:
        warn(CFD_LOG_SOURCE, "pkh is not target.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to parameter. hash type cannot used pkh target.");
    }

    if (addr_type == AddressType::kP2shP2wshAddress) {
      if (IsEmptyString(redeem_script)) {
        redeem_script_obj =
            ScriptUtil::CreateP2shLockingScript(witness_script_obj);
      } else {
        redeem_script_obj = Script(std::string(redeem_script));
      }
    }

    CfdCapiMultisigSignData* data =
        static_cast<CfdCapiMultisigSignData*>(multisign_handle);
    if (data->current_index == 0) {
      warn(CFD_LOG_SOURCE, "The signature has empty.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError, "The signature has empty.");
    }
    if (data->current_index > kMultisigMaxKeyNum) {
      warn(
          CFD_LOG_SOURCE,
          "The number of signature has reached the upper limit.");
      throw CfdException(
          CfdError::kCfdOutOfRangeError,
          "The number of signature has reached the upper limit.");
    }

    std::vector<SignParameter> sign_list;
    for (uint32_t index = 0; index < data->current_index; ++index) {
      SignParameter param(ByteData(std::string(data->signatures[index])));
      std::string pubkey(data->pubkeys[index]);
      if (Pubkey::IsValid(ByteData(pubkey))) {
        param.SetRelatedPubkey(Pubkey(pubkey));
      }
      sign_list.push_back(param);
    }

    ElementsTransactionApi api;
    ConfidentialTransactionController ctxc = api.AddMultisigSign(
        std::string(tx_hex_string), Txid(std::string(txid)), vout, sign_list,
        addr_type, witness_script_obj, redeem_script_obj, clear_stack);
    *tx_string = CreateString(ctxc.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxSignWithPrivkeySimple(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    int hash_type, const char* pubkey, const char* privkey,
    int64_t value_satoshi, const char* value_commitment, int sighash_type,
    bool sighash_anyone_can_pay, bool has_grind_r, char** tx_string) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (IsEmptyString(pubkey)) {
      warn(CFD_LOG_SOURCE, "pubkey is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. pubkey is null or empty.");
    }
    if (IsEmptyString(privkey)) {
      warn(CFD_LOG_SOURCE, "privkey is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. privkey is null or empty.");
    }
    if (tx_string == nullptr) {
      warn(CFD_LOG_SOURCE, "tx output is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx output is null.");
    }

    AddressType addr_type = ConvertHashToAddressType(hash_type);
    ConfidentialValue value;
    if (IsEmptyString(value_commitment)) {
      value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_satoshi));
    } else {
      value = ConfidentialValue(value_commitment);
    }

    Privkey privkey_obj;
    std::string privkey_str(privkey);
    if (privkey_str.length() == 64) {
      privkey_obj = Privkey(privkey_str);
    } else {
      KeyApi keyapi;
      privkey_obj = keyapi.GetPrivkeyFromWif(privkey_str);
    }

    OutPoint outpoint(Txid(txid), vout);
    ConfidentialTransactionContext tx(tx_hex_string);
    SigHashType sighashtype = SigHashType::Create(
        static_cast<uint8_t>(sighash_type), sighash_anyone_can_pay);
    tx.SignWithPrivkeySimple(
        outpoint, Pubkey(pubkey), privkey_obj, sighashtype, value, addr_type,
        has_grind_r);

    *tx_string = CreateString(tx.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdCreateConfidentialSighash(
    void* handle, const char* tx_hex_string, const char* txid, uint32_t vout,
    int hash_type, const char* pubkey, const char* redeem_script,
    int64_t value_satoshi, const char* value_commitment, int sighash_type,
    bool sighash_anyone_can_pay, char** sighash) {
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    if (sighash == nullptr) {
      warn(CFD_LOG_SOURCE, "sighash is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. sighash is null.");
    }

    AddressType addr_type = ConvertHashToAddressType(hash_type);
    HashType core_hash_type;
    switch (addr_type) {
      case AddressType::kP2shAddress:
        core_hash_type = HashType::kP2sh;
        break;
      case AddressType::kP2wshAddress:
        // fall-through
      case AddressType::kP2shP2wshAddress:
        core_hash_type = HashType::kP2wsh;
        break;
      case AddressType::kP2pkhAddress:
        core_hash_type = HashType::kP2pkh;
        break;
      case AddressType::kP2wpkhAddress:
        // fall-through
      case AddressType::kP2shP2wpkhAddress:
        core_hash_type = HashType::kP2wpkh;
        break;
      default:
        warn(CFD_LOG_SOURCE, "hashtype is illegal.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to parameter. hashtype is illegal.");
    }

    ByteData key_data;
    if ((core_hash_type == HashType::kP2sh) ||
        (core_hash_type == HashType::kP2wsh)) {
      if (IsEmptyString(redeem_script)) {
        warn(CFD_LOG_SOURCE, "redeem script is null or empty.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to parameter. redeem script is null or empty.");
      }
      Script redeem_script_obj = Script(redeem_script);
      key_data = redeem_script_obj.GetData();
    } else {
      if (IsEmptyString(pubkey)) {
        warn(CFD_LOG_SOURCE, "pubkey is null or empty.");
        throw CfdException(
            CfdError::kCfdIllegalArgumentError,
            "Failed to parameter. pubkey is null or empty.");
      }
      Pubkey pubkey_obj = Pubkey(pubkey);
      key_data = pubkey_obj.GetData();
    }

    ConfidentialValue value;
    if (IsEmptyString(value_commitment)) {
      value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_satoshi));
    } else {
      value = ConfidentialValue(value_commitment);
    }

    ElementsTransactionApi api;
    SigHashType sighashtype = SigHashType::Create(
        static_cast<uint8_t>(sighash_type), sighash_anyone_can_pay);
    std::string sighash_bytes = api.CreateSignatureHash(
        std::string(tx_hex_string), Txid(std::string(txid)), vout, key_data,
        value, core_hash_type, sighashtype);
    *sighash = CreateString(sighash_bytes);
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdUnblindTxOut(
    void* handle, const char* tx_hex_string, uint32_t tx_out_index,
    const char* blinding_key, char** asset, int64_t* value,
    char** asset_blind_factor, char** value_blind_factor) {
  char* work_asset = nullptr;
  char* work_asset_blind_factor = nullptr;
  char* work_value_blind_factor = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(blinding_key)) {
      warn(CFD_LOG_SOURCE, "blinding key is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blinding key is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    UnblindParameter unblind_data =
        ctxc.UnblindTxOut(tx_out_index, Privkey(blinding_key));

    if (!unblind_data.asset.IsEmpty()) {
      if (asset != nullptr) {
        work_asset = CreateString(unblind_data.asset.GetHex());
      }
      if (value != nullptr) {
        *value = unblind_data.value.GetAmount().GetSatoshiValue();
      }
      if (asset_blind_factor != nullptr) {
        work_asset_blind_factor = CreateString(unblind_data.abf.GetHex());
      }
      if (value_blind_factor != nullptr) {
        work_value_blind_factor = CreateString(unblind_data.vbf.GetHex());
      }
    }

    if (work_asset != nullptr) *asset = work_asset;
    if (work_asset_blind_factor != nullptr)
      *asset_blind_factor = work_asset_blind_factor;
    if (work_value_blind_factor != nullptr)
      *value_blind_factor = work_value_blind_factor;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_value_blind_factor);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_value_blind_factor);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_value_blind_factor);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdUnblindIssuance(
    void* handle, const char* tx_hex_string, uint32_t tx_in_index,
    const char* asset_blinding_key, const char* token_blinding_key,
    char** asset, int64_t* asset_value, char** asset_blind_factor,
    char** asset_value_blind_factor, char** token, int64_t* token_value,
    char** token_blind_factor, char** token_value_blind_factor) {
  char* work_asset = nullptr;
  char* work_asset_blind_factor = nullptr;
  char* work_asset_value_blind_factor = nullptr;
  char* work_token = nullptr;
  char* work_token_blind_factor = nullptr;
  char* work_token_value_blind_factor = nullptr;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex_string)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex_string);
    Privkey asset_key;
    Privkey token_key;
    if (!IsEmptyString(asset_blinding_key)) {
      asset_key = Privkey(asset_blinding_key);
    }
    if (!IsEmptyString(token_blinding_key)) {
      token_key = Privkey(token_blinding_key);
    }

    std::vector<UnblindParameter> unblind_datas =
        ctxc.UnblindIssuance(tx_in_index, asset_key, token_key);

    UnblindParameter unblind_asset;
    UnblindParameter unblind_token;
    if (unblind_datas.size() == 2) {  // 2固定
      unblind_asset = unblind_datas[0];
      unblind_token = unblind_datas[1];
    }

    if (!unblind_asset.asset.IsEmpty()) {
      if (asset != nullptr) {
        work_asset = CreateString(unblind_asset.asset.GetHex());
      }
      if (asset_value != nullptr) {
        *asset_value = unblind_asset.value.GetAmount().GetSatoshiValue();
      }
      if (asset_blind_factor != nullptr) {
        work_asset_blind_factor = CreateString(unblind_asset.abf.GetHex());
      }
      if (asset_value_blind_factor != nullptr) {
        work_asset_value_blind_factor =
            CreateString(unblind_asset.vbf.GetHex());
      }
    }
    if (!unblind_token.asset.IsEmpty()) {
      if (token != nullptr) {
        work_token = CreateString(unblind_token.asset.GetHex());
      }
      if (token_value != nullptr) {
        *token_value = unblind_token.value.GetAmount().GetSatoshiValue();
      }
      if (token_blind_factor != nullptr) {
        work_token_blind_factor = CreateString(unblind_token.abf.GetHex());
      }
      if (token_value_blind_factor != nullptr) {
        work_token_value_blind_factor =
            CreateString(unblind_token.vbf.GetHex());
      }
    }

    if (work_asset != nullptr) *asset = work_asset;
    if (work_asset_blind_factor != nullptr)
      *asset_blind_factor = work_asset_blind_factor;
    if (work_asset_value_blind_factor != nullptr)
      *asset_value_blind_factor = work_asset_value_blind_factor;
    if (work_token != nullptr) *token = work_token;
    if (work_token_blind_factor != nullptr)
      *token_blind_factor = work_token_blind_factor;
    if (work_token_value_blind_factor != nullptr)
      *token_value_blind_factor = work_token_value_blind_factor;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_asset_value_blind_factor,
        &work_token, &work_token_blind_factor, &work_token_value_blind_factor);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_asset_value_blind_factor,
        &work_token, &work_token_blind_factor, &work_token_value_blind_factor);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_asset, &work_asset_blind_factor, &work_asset_value_blind_factor,
        &work_token, &work_token_blind_factor, &work_token_value_blind_factor);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

CFDC_API int CfdVerifyConfidentialTxSignature(
    void* handle, const char* tx_hex, const char* signature,
    const char* pubkey, const char* script, const char* txid, uint32_t vout,
    int sighash_type, bool sighash_anyone_can_pay, int64_t value_satoshi,
    const char* value_commitment, int witness_version) {
  bool work_result = false;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(signature)) {
      warn(CFD_LOG_SOURCE, "signature is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. signature is null or empty.");
    }
    if (IsEmptyString(pubkey)) {
      warn(CFD_LOG_SOURCE, "pubkey is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. pubkey is null or empty.");
    }

    ConfidentialTransactionController ctxc(tx_hex);
    ByteData signature_obj(signature);
    Txid txid_obj(txid);
    SigHashType sighash_type_obj = SigHashType::Create(
        static_cast<uint8_t>(sighash_type), sighash_anyone_can_pay);
    ConfidentialValue value;
    if (!IsEmptyString(value_commitment)) {
      value = ConfidentialValue(value_commitment);
    } else {
      value = ConfidentialValue(Amount::CreateBySatoshiAmount(value_satoshi));
    }

    if (!IsEmptyString(script)) {
      work_result = ctxc.VerifyInputSignature(
          signature_obj, Pubkey(pubkey), txid_obj, vout, Script(script),
          sighash_type_obj, value,
          static_cast<WitnessVersion>(witness_version));
    } else if (!IsEmptyString(pubkey)) {
      work_result = ctxc.VerifyInputSignature(
          signature_obj, Pubkey(pubkey), txid_obj, vout, sighash_type_obj,
          value, static_cast<WitnessVersion>(witness_version));
    }

    if (!work_result) {
      return CfdErrorCode::kCfdSignVerificationError;
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

CFDC_API int CfdVerifyConfidentialTxSign(
    void* handle, const char* tx_hex, const char* txid, uint32_t vout,
    const char* address, int address_type, const char* direct_locking_script,
    int64_t value_satoshi, const char* value_commitment) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    if (IsEmptyString(tx_hex)) {
      warn(CFD_LOG_SOURCE, "tx is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. tx is null or empty.");
    }
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }
    ConfidentialTransactionContext ctxc(tx_hex);
    OutPoint outpoint(Txid(txid), vout);
    ctxc.GetTxInIndex(outpoint);
    AddressType addr_type = ConvertAddressType(address_type);

    UtxoData utxo;
    utxo.block_height = 0;
    utxo.binary_data = nullptr;
    utxo.descriptor = "";
    utxo.txid = outpoint.GetTxid();
    utxo.vout = outpoint.GetVout();
    utxo.address_type = AddressType::kP2shAddress;

    ElementsAddressFactory address_factory;
    if (!IsEmptyString(address)) {
      std::string addr(address);
      if (ElementsConfidentialAddress::IsConfidentialAddress(addr)) {
        ElementsConfidentialAddress confidential_addr(addr);
        utxo.address = confidential_addr.GetUnblindedAddress();
      } else {
        utxo.address = address_factory.GetAddress(addr);
      }
      utxo.locking_script = utxo.address.GetLockingScript();
      utxo.address_type = addr_type;
    } else if (!IsEmptyString(direct_locking_script)) {
      utxo.locking_script = Script(direct_locking_script);
    }

    if (!IsEmptyString(value_commitment)) {
      utxo.value_commitment = ConfidentialValue(value_commitment);
    } else {
      utxo.amount = Amount::CreateBySatoshiAmount(value_satoshi);
    }

    std::vector<UtxoData> utxos = {utxo};
    ctxc.CollectInputUtxo(utxos);

    result = CfdErrorCode::kCfdSignVerificationError;
    ctxc.Verify(outpoint);

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    if (result != CfdErrorCode::kCfdSignVerificationError) {
      result = SetLastError(handle, except);
    } else {
      SetLastError(handle, except);  // collect error message
    }
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdGetConfidentialValueHex(
    void* handle, int64_t value_satoshi, bool ignore_version_info,
    char** value_hex) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    if (value_hex == nullptr) {
      warn(CFD_LOG_SOURCE, "value_hex is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. value_hex is null.");
    }
    Amount amount(value_satoshi);
    ConfidentialValue value(amount);
    std::string hex_str = value.GetHex();

    if (ignore_version_info) {  // erase first 1byte (2 char)
      hex_str = hex_str.substr(2);
    }
    *value_hex = CreateString(hex_str);

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdGetAssetCommitment(
    void* handle, const char* asset, const char* asset_blind_factor,
    char** asset_commitment) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    if (asset_commitment == nullptr) {
      warn(CFD_LOG_SOURCE, "asset commitment is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset commitment is null.");
    }
    if (IsEmptyString(asset)) {
      warn(CFD_LOG_SOURCE, "asset is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null or empty.");
    }
    if (IsEmptyString(asset_blind_factor)) {
      warn(CFD_LOG_SOURCE, "asset blind vactor is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset blind vactor is null or empty.");
    }
    ConfidentialAssetId asset_obj(asset);
    BlindFactor abf(asset_blind_factor);
    ConfidentialAssetId commitment =
        ConfidentialAssetId::GetCommitment(asset_obj, abf);
    *asset_commitment = CreateString(commitment.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdGetValueCommitment(
    void* handle, int64_t value_satoshi, const char* asset_commitment,
    const char* value_blind_factor, char** value_commitment) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    if (value_commitment == nullptr) {
      warn(CFD_LOG_SOURCE, "value commitment is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. value commitment is null.");
    }
    if (IsEmptyString(asset_commitment)) {
      warn(CFD_LOG_SOURCE, "asset commitment is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset commitment is null or empty.");
    }
    if (IsEmptyString(value_blind_factor)) {
      warn(CFD_LOG_SOURCE, "value blind vactor is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. value blind vactor is null or empty.");
    }
    Amount amount(value_satoshi);
    ConfidentialAssetId asset(asset_commitment);
    BlindFactor vbf(value_blind_factor);
    ConfidentialValue commitment =
        ConfidentialValue::GetCommitment(amount, asset, vbf);
    *value_commitment = CreateString(commitment.GetHex());

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdGetConfidentialTxInfoByHandle(
    void* handle, void* tx_data_handle, char** txid, char** wtxid,
    char** wit_hash, uint32_t* size, uint32_t* vsize, uint32_t* weight,
    uint32_t* version, uint32_t* locktime) {
  int error_code = CfdErrorCode::kCfdUnknownError;
  char* work_txid = nullptr;
  char* work_wtxid = nullptr;
  char* work_wit_hash = nullptr;
  try {
    cfd::Initialize();
    CheckBuffer(tx_data_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(tx_data_handle);
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    if (txid != nullptr) {
      work_txid = CreateString(tx->GetTxid().GetHex());
    }
    if (wtxid != nullptr) {
      work_wtxid = CreateString(Txid(tx->GetWitnessHash()).GetHex());
    }
    if (wit_hash != nullptr) {
      work_wit_hash = CreateString(Txid(tx->GetWitnessOnlyHash()).GetHex());
    }
    if (size != nullptr) {
      *size = tx->GetTotalSize();
    }
    if (vsize != nullptr) {
      *vsize = tx->GetVsize();
    }
    if (weight != nullptr) {
      *weight = tx->GetWeight();
    }
    if (version != nullptr) {
      *version = tx->GetVersion();
    }
    if (locktime != nullptr) {
      *locktime = tx->GetLockTime();
    }

    if (work_txid != nullptr) *txid = work_txid;
    if (work_wtxid != nullptr) *wtxid = work_wtxid;
    if (work_wit_hash != nullptr) *wit_hash = work_wit_hash;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    error_code = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  FreeBufferOnError(&work_txid, &work_wtxid, &work_wit_hash);
  return error_code;
}

int CfdHasPegoutConfidentialTxOut(
    void* handle, void* tx_data_handle, uint32_t index) {
  int ret = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(tx_data_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(tx_data_handle);
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    if (!tx->HasPegoutTxOut(index)) return CfdErrorCode::kCfdNotFoundError;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    ret = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return ret;
}

int CfdGetPegoutMainchainAddress(
    void* handle, void* tx_data_handle, uint32_t index, int mainchain_network,
    char** mainchain_address) {
  int ret = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(tx_data_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(tx_data_handle);
    if (mainchain_address == nullptr) {
      warn(CFD_LOG_SOURCE, "mainchain_address is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_address is null.");
    }
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }
    auto mainchain_net_type = ConvertNetType(mainchain_network, &is_bitcoin);
    if (!is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_network is not bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    auto addr = tx->GetTxOutPegoutAddress(index, mainchain_net_type);
    *mainchain_address = CreateString(addr.GetAddress());
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    ret = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return ret;
}

int CfdGetTxInIssuanceInfoByHandle(
    void* handle, void* tx_data_handle, uint32_t index, char** entropy,
    char** nonce, int64_t* asset_amount, char** asset_value,
    int64_t* token_amount, char** token_value, char** asset_rangeproof,
    char** token_rangeproof) {
  char* work_entropy = nullptr;
  char* work_nonce = nullptr;
  char* work_asset_value = nullptr;
  char* work_token_value = nullptr;
  char* work_asset_rangeproof = nullptr;
  char* work_token_rangeproof = nullptr;
  try {
    cfd::Initialize();
    CheckBuffer(tx_data_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(tx_data_handle);
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    const ConfidentialTxInReference ref = tx->GetTxIn(index);

    if (entropy != nullptr) {
      work_entropy = CreateString(BlindFactor(ref.GetAssetEntropy()).GetHex());
    }
    if (nonce != nullptr) {
      work_nonce = CreateString(BlindFactor(ref.GetBlindingNonce()).GetHex());
    }
    const ConfidentialValue& asset_obj = ref.GetIssuanceAmount();
    const ConfidentialValue& token_obj = ref.GetInflationKeys();
    if ((asset_amount != nullptr) && (!asset_obj.HasBlinding())) {
      *asset_amount = (asset_obj.HasBlinding())
                          ? 0
                          : asset_obj.GetAmount().GetSatoshiValue();
    }
    if (asset_value != nullptr) {
      work_asset_value = CreateString(asset_obj.GetHex());
    }
    if ((token_amount != nullptr) && (!token_obj.HasBlinding())) {
      *token_amount = (token_obj.HasBlinding())
                          ? 0
                          : token_obj.GetAmount().GetSatoshiValue();
    }
    if (token_value != nullptr) {
      work_token_value = CreateString(token_obj.GetHex());
    }
    if (asset_rangeproof != nullptr) {
      work_asset_rangeproof =
          CreateString(ref.GetIssuanceAmountRangeproof().GetHex());
    }
    if (token_rangeproof != nullptr) {
      work_token_rangeproof =
          CreateString(ref.GetInflationKeysRangeproof().GetHex());
    }

    if (work_entropy != nullptr) *entropy = work_entropy;
    if (work_nonce != nullptr) *nonce = work_nonce;
    if (work_asset_value != nullptr) *asset_value = work_asset_value;
    if (work_token_value != nullptr) *token_value = work_token_value;
    if (work_asset_rangeproof != nullptr)
      *asset_rangeproof = work_asset_rangeproof;
    if (work_token_rangeproof != nullptr)
      *token_rangeproof = work_token_rangeproof;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_entropy, &work_nonce, &work_asset_value, &work_token_value,
        &work_asset_rangeproof, &work_token_rangeproof);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdGetConfidentialTxOutSimpleByHandle(
    void* handle, void* tx_data_handle, uint32_t index, char** asset_string,
    int64_t* value_satoshi, char** value_commitment, char** nonce,
    char** locking_script) {
  return CfdGetConfidentialTxOutByHandle(
      handle, tx_data_handle, index, asset_string, value_satoshi,
      value_commitment, nonce, locking_script, nullptr, nullptr);
}

int CfdGetConfidentialTxOutByHandle(
    void* handle, void* tx_data_handle, uint32_t index, char** asset_string,
    int64_t* value_satoshi, char** value_commitment, char** nonce,
    char** locking_script, char** surjection_proof, char** rangeproof) {
  char* work_asset_string = nullptr;
  char* work_value_commitment = nullptr;
  char* work_nonce = nullptr;
  char* work_locking_script = nullptr;
  char* work_surjection_proof = nullptr;
  char* work_rangeproof = nullptr;
  try {
    cfd::Initialize();
    CheckBuffer(tx_data_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(tx_data_handle);
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    const ConfidentialTxOutReference ref = tx->GetTxOut(index);

    if (asset_string != nullptr) {
      work_asset_string = CreateString(ref.GetAsset().GetHex());
    }
    ConfidentialValue value = ref.GetConfidentialValue();
    if ((value_satoshi != nullptr) && (!value.HasBlinding())) {
      *value_satoshi = value.GetAmount().GetSatoshiValue();
    }
    if (value_commitment != nullptr) {
      work_value_commitment = CreateString(value.GetHex());
    }
    if (nonce != nullptr) {
      work_nonce = CreateString(ref.GetNonce().GetHex());
    }
    if (locking_script != nullptr) {
      work_locking_script = CreateString(ref.GetLockingScript().GetHex());
    }
    if (surjection_proof != nullptr) {
      work_surjection_proof = CreateString(ref.GetSurjectionProof().GetHex());
    }
    if (rangeproof != nullptr) {
      work_rangeproof = CreateString(ref.GetRangeProof().GetHex());
    }

    if (work_asset_string != nullptr) *asset_string = work_asset_string;
    if (work_value_commitment != nullptr)
      *value_commitment = work_value_commitment;
    if (work_nonce != nullptr) *nonce = work_nonce;
    if (work_locking_script != nullptr) *locking_script = work_locking_script;
    if (work_surjection_proof != nullptr)
      *surjection_proof = work_surjection_proof;
    if (work_rangeproof != nullptr) *rangeproof = work_rangeproof;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    FreeBufferOnError(
        &work_asset_string, &work_value_commitment, &work_nonce,
        &work_locking_script, &work_surjection_proof, &work_rangeproof);
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdSetConfidentialTxUtxoDataByHandle(
    void* handle, void* create_handle, const char* txid, uint32_t vout,
    int64_t amount, const char* commitment, const char* descriptor,
    const char* address, const char* asset, const char* asset_commitment,
    const char* asset_blinder, const char* amount_blinder,
    const char* scriptsig_template, bool can_insert) {
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if (IsEmptyString(txid)) {
      warn(CFD_LOG_SOURCE, "txid is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null or empty.");
    }

    bool is_bitcoin = false;
    NetType network = ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. this api support is elements only.");
    } else if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    }

    UtxoData utxo;
    utxo.address_type = AddressType::kP2shAddress;
    utxo.binary_data = nullptr;
    utxo.vout = vout;
    utxo.txid = Txid(txid);
    OutPoint outpoint(utxo.txid, utxo.vout);
    utxo.amount = Amount(amount);
    if (!IsEmptyString(scriptsig_template)) {
      utxo.scriptsig_template = Script(scriptsig_template);
    }
    if (!IsEmptyString(descriptor)) {
      utxo.descriptor = std::string(descriptor);
    }

    ElementsAddressFactory factory(network);
    if (!IsEmptyString(asset)) {
      utxo.asset = ConfidentialAssetId(asset);
    }
    if (!IsEmptyString(asset_commitment)) {
      utxo.asset_commitment = ConfidentialAssetId(asset_commitment);
    }
    if (!IsEmptyString(commitment)) {
      utxo.value_commitment = ConfidentialValue(commitment);
    }
    if (!IsEmptyString(address)) {
      if (ElementsConfidentialAddress::IsConfidentialAddress(address)) {
        ElementsConfidentialAddress confidential_addr(address);
        utxo.confidential_address = confidential_addr;
        utxo.address = confidential_addr.GetUnblindedAddress();
      } else {
        utxo.address = factory.GetAddress(address);
      }
      utxo.address_type = utxo.address.GetAddressType();
    } else if (!IsEmptyString(descriptor)) {
      Descriptor desc = Descriptor::ParseElements(utxo.descriptor);
      auto ref = desc.GetReference();
      auto addr = ref.GenerateAddress(NetType::kLiquidV1);
      utxo.address_type = addr.GetAddressType();
    }
    if (!IsEmptyString(asset_blinder)) {
      utxo.asset_blind_factor = BlindFactor(asset_blinder);
    }
    if (!IsEmptyString(amount_blinder)) {
      utxo.asset_blind_factor = BlindFactor(amount_blinder);
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    if (can_insert && !tx->IsFindTxIn(outpoint)) {
      tx->AddInput(utxo);
    } else {
      tx->CollectInputUtxo({utxo});
    }

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdSetConfidentialTxGenesisBlockHashByHandle(
    void* handle, void* create_handle, const char* genesis_block_hash) {
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if (IsEmptyString(genesis_block_hash)) {
      warn(CFD_LOG_SOURCE, "genesis_block_hash is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. genesis_block_hash is null or empty.");
    }

    BlockHash block_hash(genesis_block_hash);

    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. this api support is elements only.");
    } else if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    tx->SetGenesisBlockHash(block_hash);

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdAddConfidentialTxOutput(
    void* handle, void* create_handle, int64_t value_satoshi,
    const char* address, const char* direct_locking_script,
    const char* asset_string, const char* nonce) {
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }
    Amount amount = Amount(value_satoshi);

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    if (IsEmptyString(asset_string)) {
      warn(CFD_LOG_SOURCE, "asset is null or empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null or empty.");
    }
    ConfidentialAssetId asset = ConfidentialAssetId(asset_string);
    ConfidentialNonce nonce_obj;
    if (!IsEmptyString(nonce)) {
      nonce_obj = ConfidentialNonce(std::string(nonce));
    }

    if (!IsEmptyString(address)) {
      ElementsAddressFactory address_factory;
      if (ElementsConfidentialAddress::IsConfidentialAddress(address)) {
        ElementsConfidentialAddress confidential_addr(address);
        tx->AddTxOut(confidential_addr, amount, asset, false);
      } else {
        Address addr = address_factory.GetAddress(address);
        tx->AddTxOut(amount, asset, addr.GetLockingScript(), nonce_obj);
      }
    } else if (!IsEmptyString(direct_locking_script)) {
      tx->AddTxOut(amount, asset, Script(direct_locking_script), nonce_obj);
    } else {
      tx->UpdateFeeAmount(amount, asset);
    }

    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    return SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
    return CfdErrorCode::kCfdUnknownError;
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
    return CfdErrorCode::kCfdUnknownError;
  }
}

int CfdSetIssueAsset(
    void* handle, void* create_handle, const char* txid, uint32_t vout,
    const char* contract_hash, int64_t asset_amount, const char* asset_address,
    const char* asset_locking_script, int64_t token_amount,
    const char* token_address, const char* token_locking_script,
    bool is_blind_asset, char** entropy, char** asset_string,
    char** token_string) {
  int result = CfdErrorCode::kCfdUnknownError;
  char* work_entropy = nullptr;
  char* work_asset = nullptr;
  char* work_token = nullptr;
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if (entropy == nullptr) {
      warn(CFD_LOG_SOURCE, "entropy is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. entropy is null.");
    }
    if (txid == nullptr) {
      warn(CFD_LOG_SOURCE, "txid is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null.");
    }
    if (asset_string == nullptr) {
      warn(CFD_LOG_SOURCE, "asset_string is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset_string is null.");
    }
    if ((token_amount > 0) && (token_string == nullptr)) {
      warn(CFD_LOG_SOURCE, "token_string is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. token_string is null.");
    }
    if ((asset_address == nullptr) && (asset_locking_script == nullptr)) {
      warn(CFD_LOG_SOURCE, "asset address and script is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset address and script is null.");
    }
    if ((token_amount > 0) && (token_address == nullptr) &&
        (token_locking_script == nullptr)) {
      warn(CFD_LOG_SOURCE, "token address and script is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. token address and script is null.");
    }
    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    OutPoint outpoint(Txid(txid), vout);
    cfd::IssuanceOutputParameter issuance_data =
        ConvertToIssuanceParameter(asset_address, asset_locking_script);
    issuance_data.amount = Amount(asset_amount);
    cfd::IssuanceOutputParameter token_data;
    if (token_amount > 0) {
      token_data =
          ConvertToIssuanceParameter(token_address, token_locking_script);
      token_data.amount = Amount(token_amount);
    }
    ByteData256 contract_hash_obj;
    if (!IsEmptyString(contract_hash)) {
      contract_hash_obj = ByteData256(contract_hash);
    }

    auto data = tx->SetAssetIssuance(
        outpoint, issuance_data.amount, issuance_data, token_data.amount,
        token_data, is_blind_asset, contract_hash_obj);

    work_entropy = CreateString(data.entropy.GetHex());
    work_asset = CreateString(data.asset.GetHex());
    if (token_string != nullptr) {
      work_token = CreateString(data.token.GetHex());
    }

    *entropy = work_entropy;
    *asset_string = work_asset;
    if (token_string != nullptr) *token_string = work_token;
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  FreeBufferOnError(&work_entropy, &work_asset, &work_token);
  return result;
}

int CfdSetReissueAsset(
    void* handle, void* create_handle, const char* txid, uint32_t vout,
    int64_t asset_amount, const char* blinding_nonce, const char* entropy,
    const char* address, const char* direct_locking_script,
    char** asset_string) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if ((address == nullptr) && (direct_locking_script == nullptr)) {
      warn(CFD_LOG_SOURCE, "asset address and script is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset address and script is null.");
    }
    if (txid == nullptr) {
      warn(CFD_LOG_SOURCE, "txid is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null.");
    }
    if (blinding_nonce == nullptr) {
      warn(CFD_LOG_SOURCE, "blinding_nonce is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. blinding_nonce is null.");
    }
    if (entropy == nullptr) {
      warn(CFD_LOG_SOURCE, "entropy is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. entropy is null.");
    }

    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    OutPoint outpoint(Txid(txid), vout);
    cfd::IssuanceOutputParameter issuance_data =
        ConvertToIssuanceParameter(address, direct_locking_script);
    issuance_data.amount = Amount(asset_amount);

    auto data = tx->SetAssetReissuance(
        outpoint, issuance_data.amount, issuance_data,
        BlindFactor(blinding_nonce), BlindFactor(entropy));

    if (asset_string != nullptr) {
      *asset_string = CreateString(data.asset.GetHex());
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdAddTxPeginInput(
    void* handle, void* create_handle, const char* txid, uint32_t vout,
    int64_t amount, const char* asset,
    const char* mainchain_genesis_block_hash, const char* claim_script,
    const char* mainchain_tx_hex, const char* txout_proof) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if (txid == nullptr) {
      warn(CFD_LOG_SOURCE, "txid is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txid is null.");
    }
    if (asset == nullptr) {
      warn(CFD_LOG_SOURCE, "asset is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null.");
    }
    if (mainchain_genesis_block_hash == nullptr) {
      warn(CFD_LOG_SOURCE, "mainchain_genesis_block_hash is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_genesis_block_hash is null.");
    }
    if (claim_script == nullptr) {
      warn(CFD_LOG_SOURCE, "claim_script is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. claim_script is null.");
    }
    if (mainchain_tx_hex == nullptr) {
      warn(CFD_LOG_SOURCE, "mainchain_tx_hex is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_tx_hex is null.");
    }
    if (txout_proof == nullptr) {
      warn(CFD_LOG_SOURCE, "txout_proof is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. txout_proof is null.");
    }

    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    OutPoint outpoint(Txid(txid), vout);
    tx->AddPeginTxIn(
        outpoint, Amount(amount), ConfidentialAssetId(asset),
        BlockHash(mainchain_genesis_block_hash), Script(claim_script),
        ByteData(mainchain_tx_hex), ByteData(txout_proof));
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdAddTxPegoutOutput(
    void* handle, void* create_handle, const char* asset, int64_t amount,
    int mainchain_network_type, int elements_network_type,
    const char* mainchain_genesis_block_hash, const char* online_pubkey,
    const char* master_online_key, const char* mainchain_output_descriptor,
    uint32_t bip32_counter, const char* whitelist, char** mainchain_address) {
  int result = CfdErrorCode::kCfdUnknownError;
  try {
    cfd::Initialize();
    CheckBuffer(create_handle, kPrefixTransactionData);
    CfdCapiTransactionData* tx_data =
        static_cast<CfdCapiTransactionData*>(create_handle);
    if (asset == nullptr) {
      warn(CFD_LOG_SOURCE, "asset is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. asset is null.");
    }
    if (mainchain_genesis_block_hash == nullptr) {
      warn(CFD_LOG_SOURCE, "mainchain_genesis_block_hash is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_genesis_block_hash is null.");
    }
    if (online_pubkey == nullptr) {
      warn(CFD_LOG_SOURCE, "online_pubkey is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. online_pubkey is null.");
    }
    if (master_online_key == nullptr) {
      warn(CFD_LOG_SOURCE, "master_online_key is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. master_online_key is null.");
    }
    if (mainchain_output_descriptor == nullptr) {
      warn(CFD_LOG_SOURCE, "mainchain_output_descriptor is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. mainchain_output_descriptor is null.");
    }
    if (whitelist == nullptr) {
      warn(CFD_LOG_SOURCE, "whitelist is null.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Failed to parameter. whitelist is null.");
    }

    bool is_bitcoin = false;
    ConvertNetType(tx_data->net_type, &is_bitcoin);
    if (tx_data->tx_obj == nullptr) {
      throw CfdException(
          CfdError::kCfdIllegalStateError, "Invalid handle state. tx is null");
    } else if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalStateError,
          "Invalid handle state. tx is bitcoin.");
    }

    auto mainchain_net_type =
        ConvertNetType(mainchain_network_type, &is_bitcoin);
    if (!is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid mainchain network type.");
    }
    auto elements_net_type =
        ConvertNetType(elements_network_type, &is_bitcoin);
    if (is_bitcoin) {
      throw CfdException(
          CfdError::kCfdIllegalArgumentError, "Invalid network type.");
    }
    Privkey master_online_privkey;
    if (Privkey::HasWif(master_online_key)) {
      master_online_privkey = Privkey::FromWif(master_online_key);
    } else {
      master_online_privkey = Privkey(master_online_key);
    }

    ConfidentialTransactionContext* tx =
        static_cast<ConfidentialTransactionContext*>(tx_data->tx_obj);
    Address btc_derive_address;
    tx->AddPegoutTxOut(
        Amount(amount), ConfidentialAssetId(asset),
        BlockHash(mainchain_genesis_block_hash), Address(), mainchain_net_type,
        Pubkey(online_pubkey), master_online_privkey,
        mainchain_output_descriptor, bip32_counter, ByteData(whitelist),
        elements_net_type, &btc_derive_address);

    if (mainchain_address != nullptr) {
      *mainchain_address = CreateString(btc_derive_address.GetAddress());
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  return result;
}

int CfdUnblindTxOutData(
    void* handle, const char* blinding_key, const char* locking_script,
    const char* asset_commitment, const char* value_commitment,
    const char* commitment_nonce, const char* rangeproof, char** asset,
    int64_t* amount, char** asset_blind_factor, char** value_blind_factor) {
  int result = CfdErrorCode::kCfdUnknownError;
  char* work_asset = nullptr;
  char* work_asset_blinder = nullptr;
  char* work_value_blinder = nullptr;
  try {
    cfd::Initialize();
    CheckEmptyString(locking_script, "locking_script", CFD_LOG_SOURCE);
    CheckEmptyString(asset_commitment, "asset", CFD_LOG_SOURCE);
    CheckEmptyString(value_commitment, "value_commitment", CFD_LOG_SOURCE);
    CheckEmptyString(commitment_nonce, "commitment_nonce", CFD_LOG_SOURCE);
    CheckEmptyString(rangeproof, "rangeproof", CFD_LOG_SOURCE);
    CheckEmptyString(blinding_key, "blinding_key", CFD_LOG_SOURCE);

    Script locking_script_obj(locking_script);
    ConfidentialAssetId asset_obj(asset_commitment);
    ConfidentialValue value(value_commitment);
    ConfidentialNonce nonce(commitment_nonce);
    ByteData rangeproof_obj(rangeproof);
    Privkey blinding_key_obj = Privkey::HasWif(blinding_key)
                                   ? Privkey::FromWif(blinding_key)
                                   : Privkey(blinding_key);
    ConfidentialTxOut txout(
        locking_script_obj, asset_obj, value, nonce, ByteData(),
        rangeproof_obj);
    auto unblind_data = txout.Unblind(blinding_key_obj);

    if (asset != nullptr) {
      work_asset = CreateString(unblind_data.asset.GetHex());
    }
    if (asset_blind_factor != nullptr) {
      work_asset_blinder = CreateString(unblind_data.abf.GetHex());
    }
    if (value_blind_factor != nullptr) {
      work_value_blinder = CreateString(unblind_data.vbf.GetHex());
    }
    if (amount != nullptr) {
      *amount = unblind_data.value.GetAmount().GetSatoshiValue();
    }

    if (asset != nullptr) *asset = work_asset;
    if (asset_blind_factor != nullptr) {
      *asset_blind_factor = work_asset_blinder;
    }
    if (value_blind_factor != nullptr) {
      *value_blind_factor = work_value_blinder;
    }
    return CfdErrorCode::kCfdSuccess;
  } catch (const CfdException& except) {
    result = SetLastError(handle, except);
  } catch (const std::exception& std_except) {
    SetLastFatalError(handle, std_except.what());
  } catch (...) {
    SetLastFatalError(handle, "unknown error.");
  }
  FreeBufferOnError(&work_asset, &work_asset_blinder, &work_value_blinder);
  return result;
}

};  // extern "C"

#endif  // CFD_DISABLE_ELEMENTS
#endif  // CFD_DISABLE_CAPI
