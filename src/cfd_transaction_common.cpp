// Copyright 2019 CryptoGarage
/**
 * @file cfd_transaction.cpp
 *
 * @brief implementation of common classes related to transaction operation
 */
#include "cfd/cfd_transaction_common.h"

#include <algorithm>
#include <string>
#include <vector>

#include "cfd/cfd_common.h"
#include "cfd/cfd_utxo.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_coin.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_elements_transaction.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_transaction.h"

namespace cfd {

using cfd::core::AbstractTransaction;
using cfd::core::Address;
using cfd::core::AddressFormatData;
using cfd::core::AddressType;
using cfd::core::Amount;
using cfd::core::ByteData;
using cfd::core::CfdError;
using cfd::core::CfdException;
using cfd::core::CryptoUtil;
using cfd::core::Descriptor;
using cfd::core::DescriptorScriptReference;
using cfd::core::DescriptorScriptType;
using cfd::core::HashType;
using cfd::core::NetType;
using cfd::core::Pubkey;
using cfd::core::SchnorrSignature;
using cfd::core::Script;
using cfd::core::ScriptBuilder;
using cfd::core::ScriptOperator;
using cfd::core::ScriptUtil;
using cfd::core::SigHashType;
using cfd::core::SignatureUtil;
using cfd::core::Txid;
using cfd::core::TxIn;
using cfd::core::logger::warn;

#ifndef CFD_DISABLE_ELEMENTS
using cfd::core::ConfidentialTxIn;
#endif  // CFD_DISABLE_ELEMENTS

// -----------------------------------------------------------------------------
// Define
// -----------------------------------------------------------------------------
/// sequence number (enable locktime)
constexpr uint32_t kSequenceEnableLockTimeMax = 0xfffffffeU;
/// sequence number (disable locktime)
constexpr uint32_t kSequenceDisableLockTime = 0xffffffffU;

// -----------------------------------------------------------------------------
// UtxoData
// -----------------------------------------------------------------------------
UtxoData::UtxoData() {
  // do nothing
}

#ifndef CFD_DISABLE_ELEMENTS
UtxoData::UtxoData(
    uint64_t block_height, const BlockHash& block_hash, const Txid& txid,
    uint32_t vout, const Script& locking_script, const Script& redeem_script,
    const Address& address, const std::string& descriptor,
    const Amount& amount, AddressType address_type, void* binary_data,
    const ConfidentialAssetId& asset,
    const ElementsConfidentialAddress& confidential_address,
    const BlindFactor& asset_blind_factor,
    const BlindFactor& amount_blind_factor,
    const ConfidentialValue& value_commitment,
    const ConfidentialAssetId& asset_commitment,
    const Script& scriptsig_template)
    : block_height(block_height),
      block_hash(block_hash),
      txid(txid),
      vout(vout),
      locking_script(locking_script),
      redeem_script(redeem_script),
      address(address),
      descriptor(descriptor),
      amount(amount),
      address_type(address_type),
      binary_data(binary_data),
      asset(asset),
      confidential_address(confidential_address),
      asset_blind_factor(asset_blind_factor),
      amount_blind_factor(amount_blind_factor),
      value_commitment(value_commitment),
      asset_commitment(asset_commitment),
      scriptsig_template(scriptsig_template) {
  // do nothing
}
#else
UtxoData::UtxoData(
    uint64_t block_height, const BlockHash& block_hash, const Txid& txid,
    uint32_t vout, const Script& locking_script, const Script& redeem_script,
    const Address& address, const std::string& descriptor,
    const Amount& amount, AddressType address_type, void* binary_data,
    const Script& scriptsig_template)
    : block_height(block_height),
      block_hash(block_hash),
      txid(txid),
      vout(vout),
      locking_script(locking_script),
      redeem_script(redeem_script),
      address(address),
      descriptor(descriptor),
      amount(amount),
      address_type(address_type),
      binary_data(binary_data),
      scriptsig_template(scriptsig_template) {
  // do nothing
}
#endif  // CFD_DISABLE_ELEMENTS

UtxoData::UtxoData(const UtxoData& object) {
  block_height = object.block_height;
  block_hash = object.block_hash;
  txid = object.txid;
  vout = object.vout;
  locking_script = object.locking_script;
  redeem_script = object.redeem_script;
  address = object.address;
  descriptor = object.descriptor;
  amount = object.amount;
  address_type = object.address_type;
  binary_data = object.binary_data;
#ifndef CFD_DISABLE_ELEMENTS
  asset = object.asset;
  confidential_address = object.confidential_address;
  asset_blind_factor = object.asset_blind_factor;
  amount_blind_factor = object.amount_blind_factor;
  value_commitment = object.value_commitment;
  asset_commitment = object.asset_commitment;
#endif  // CFD_DISABLE_ELEMENTS
  scriptsig_template = object.scriptsig_template;
}

UtxoData& UtxoData::operator=(const UtxoData& object) & {
  if (this != &object) {
    block_height = object.block_height;
    block_hash = object.block_hash;
    txid = object.txid;
    vout = object.vout;
    locking_script = object.locking_script;
    redeem_script = object.redeem_script;
    address = object.address;
    descriptor = object.descriptor;
    amount = object.amount;
    address_type = object.address_type;
    binary_data = object.binary_data;
#ifndef CFD_DISABLE_ELEMENTS
    asset = object.asset;
    confidential_address = object.confidential_address;
    asset_blind_factor = object.asset_blind_factor;
    amount_blind_factor = object.amount_blind_factor;
    value_commitment = object.value_commitment;
    asset_commitment = object.asset_commitment;
#endif  // CFD_DISABLE_ELEMENTS
    scriptsig_template = object.scriptsig_template;
  }
  return *this;
}

// -----------------------------------------------------------------------------
// UtxoUtil
// -----------------------------------------------------------------------------
std::vector<Utxo> UtxoUtil::ConvertToUtxo(const std::vector<UtxoData>& utxos) {
  std::vector<Utxo> result;
  result.resize(utxos.size());
  std::vector<Utxo>::iterator ite = result.begin();
  for (const auto& utxo_data : utxos) {
    ConvertToUtxo(utxo_data, &(*ite));
    ++ite;
  }
  return result;
}

void UtxoUtil::ConvertToUtxo(
    const UtxoData& utxo_data, Utxo* utxo, UtxoData* dest) {
  if (utxo != nullptr) {
    UtxoData output(utxo_data);
    memset(utxo, 0, sizeof(Utxo));
    utxo->block_height = utxo_data.block_height;
    utxo->vout = utxo_data.vout;
    utxo->binary_data = utxo_data.binary_data;
    utxo->amount = utxo_data.amount.GetSatoshiValue();

    ByteData block_hash = utxo_data.block_hash.GetData();
    if (!block_hash.Empty()) {
      memcpy(
          utxo->block_hash, block_hash.GetBytes().data(),
          sizeof(utxo->block_hash));
    }
    ByteData txid = utxo_data.txid.GetData();
    if (!txid.Empty()) {
      memcpy(utxo->txid, txid.GetBytes().data(), sizeof(utxo->txid));
    }

    // convert from descriptor
    std::vector<uint8_t> locking_script_bytes;
    if (!utxo_data.descriptor.empty()) {
      NetType net_type = NetType::kMainnet;
      std::vector<AddressFormatData> addr_prefixes =
          cfd::core::GetBitcoinAddressFormatList();
#ifndef CFD_DISABLE_ELEMENTS
      if (!utxo_data.asset.IsEmpty()) {
        std::vector<AddressFormatData> elements_prefixes =
            cfd::core::GetElementsAddressFormatList();
        addr_prefixes = elements_prefixes;
        net_type = NetType::kLiquidV1;
      }
#endif  // CFD_DISABLE_ELEMENTS
      if (!utxo_data.address.GetAddress().empty()) {
        addr_prefixes.clear();
        addr_prefixes.push_back(utxo_data.address.GetAddressFormatData());
        net_type = utxo_data.address.GetNetType();
      }

      Descriptor desc =
          Descriptor::Parse(utxo_data.descriptor, &addr_prefixes, net_type);
      if (desc.GetNeedArgumentNum() == 0) {
        std::vector<DescriptorScriptReference> ref_list =
            desc.GetReferenceAll();
        DescriptorScriptReference& script_ref = ref_list[0];
        output.locking_script = script_ref.GetLockingScript();
        locking_script_bytes = output.locking_script.GetData().GetBytes();
        if ((script_ref.GetScriptType() !=
             DescriptorScriptType::kDescriptorScriptRaw) ||
            script_ref.HasAddress()) {
          output.address_type = script_ref.GetAddressType();
          output.address = script_ref.GenerateAddress(net_type);
          if (ref_list[ref_list.size() - 1].HasRedeemScript()) {
            output.redeem_script =
                ref_list[ref_list.size() - 1].GetRedeemScript();
          }
        }
        utxo->address_type = static_cast<uint16_t>(output.address_type);
      }
    }

    if (!locking_script_bytes.empty()) {
      // do nothing
    } else if (!output.address.GetAddress().empty()) {
      output.locking_script = output.address.GetLockingScript();
      locking_script_bytes = output.locking_script.GetData().GetBytes();
      AddressType addr_type = output.address.GetAddressType();
      if ((addr_type == AddressType::kP2shAddress) &&
          ((output.address_type == AddressType::kP2shP2wshAddress) ||
           (output.address_type == AddressType::kP2shP2wpkhAddress))) {
        // direct set. output.address_type;
      } else {
        output.address_type = addr_type;
      }
      utxo->address_type = static_cast<uint16_t>(output.address_type);
    } else if (!utxo_data.locking_script.IsEmpty()) {
      locking_script_bytes = utxo_data.locking_script.GetData().GetBytes();
      if (utxo_data.locking_script.IsP2wpkhScript()) {
        utxo->address_type = AddressType::kP2wpkhAddress;
      } else if (utxo_data.locking_script.IsP2wshScript()) {
        utxo->address_type = AddressType::kP2wshAddress;
      } else if (utxo_data.locking_script.IsP2pkhScript()) {
        utxo->address_type = AddressType::kP2pkhAddress;
      } else if (utxo_data.locking_script.IsTaprootScript()) {
        utxo->address_type = AddressType::kTaprootAddress;
      } else if (
          utxo_data.locking_script.IsWitnessProgram() &&
          (utxo_data.locking_script.GetElementList()[0].GetNumber() != 0)) {
        utxo->address_type = AddressType::kWitnessUnknown;
      } else {  // TODO(k-matsuzawa): unbknown type is convert to p2sh
        utxo->address_type = AddressType::kP2shAddress;
      }
      output.address_type = static_cast<AddressType>(utxo->address_type);
    }

    if (!locking_script_bytes.empty()) {
      utxo->script_length = static_cast<uint16_t>(locking_script_bytes.size());
      if (utxo->script_length < sizeof(utxo->locking_script)) {
        memcpy(
            utxo->locking_script, locking_script_bytes.data(),
            utxo->script_length);
      }
    }

    uint32_t wit_size = 0;
    uint32_t txin_size = 0;
    const Script* scriptsig_template = nullptr;
    if (!output.scriptsig_template.IsEmpty()) {
      scriptsig_template = &output.scriptsig_template;
    }

#ifndef CFD_DISABLE_ELEMENTS
    if (!utxo_data.asset.IsEmpty()) {
      std::vector<uint8_t> asset = utxo_data.asset.GetData().GetBytes();
      memcpy(utxo->asset, asset.data(), sizeof(utxo->asset));
      utxo->blinded = utxo_data.asset.HasBlinding();

      ConfidentialTxIn::EstimateTxInSize(
          output.address_type, output.redeem_script, 0, Script(), false, false,
          &wit_size, &txin_size, false, scriptsig_template);
      txin_size -= static_cast<uint32_t>(TxIn::kMinimumTxInSize);
      utxo->witness_size_max = static_cast<uint16_t>(wit_size);
      utxo->uscript_size_max = static_cast<uint16_t>(txin_size);
    }
#endif  // CFD_DISABLE_ELEMENTS

    if ((wit_size == 0) && (txin_size == 0)) {
      wit_size = 0;
      txin_size = 0;
      TxIn::EstimateTxInSize(
          output.address_type, output.redeem_script, &wit_size, &txin_size,
          scriptsig_template);
      txin_size -= static_cast<uint32_t>(TxIn::kMinimumTxInSize);
      utxo->witness_size_max = static_cast<uint16_t>(wit_size);
      utxo->uscript_size_max = static_cast<uint16_t>(txin_size);
    }

    if (dest != nullptr) {
      *dest = output;
    }
  }
}

// -----------------------------------------------------------------------------
// SignParameter
// -----------------------------------------------------------------------------

SignParameter::SignParameter()
    : data_(),
      data_type_(SignDataType::kBinary),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(
    const std::string& text_message, bool der_encode,
    const SigHashType sighash_type)
    : data_(),
      data_type_(SignDataType::kBinary),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  if (ScriptOperator::IsValid(text_message)) {
    data_type_ = SignDataType::kOpCode;
    op_code_ = ScriptOperator::Get(text_message);
    std::vector<uint8_t> list(1);
    list[0] = static_cast<uint8_t>(op_code_.GetDataType());
    data_ = ByteData(list);
  } else {
    data_ = ByteData(text_message);
    der_encode_ = der_encode;
    sighash_type_ = sighash_type;
    if (der_encode) data_type_ = SignDataType::kSign;
  }
}

SignParameter::SignParameter(
    const ByteData& data, bool der_encode, const SigHashType sighash_type)
    : data_(data),
      data_type_(SignDataType::kSign),
      related_pubkey_(),
      der_encode_(der_encode),
      sighash_type_(sighash_type),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(const ByteData& data)
    : data_(data),
      data_type_(SignDataType::kBinary),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(const Pubkey& pubkey)
    : data_(pubkey.GetData()),
      data_type_(SignDataType::kPubkey),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(const Script& redeem_script)
    : data_(redeem_script.GetData()),
      data_type_(SignDataType::kRedeemScript),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(const ScriptOperator& op_code)
    : data_(),
      data_type_(SignDataType::kOpCode),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(op_code) {
  std::vector<uint8_t> list(1);
  list[0] = static_cast<uint8_t>(op_code_.GetDataType());
  data_ = ByteData(list);
}

SignParameter::SignParameter(const SchnorrSignature& schnorr_signature)
    : data_(schnorr_signature.GetData(true)),
      data_type_(SignDataType::kBinary),
      related_pubkey_(),
      der_encode_(false),
      sighash_type_(),
      op_code_(ScriptOperator::OP_INVALIDOPCODE) {
  // do nothing
}

SignParameter::SignParameter(const SignParameter& sign_parameter) {
  data_ = sign_parameter.GetData();
  data_type_ = sign_parameter.GetDataType();
  related_pubkey_ = sign_parameter.GetRelatedPubkey();
  der_encode_ = sign_parameter.IsDerEncode();
  sighash_type_ = sign_parameter.GetSigHashType();
  op_code_ = sign_parameter.GetOpCode();
}

SignParameter& SignParameter::operator=(const SignParameter& sign_parameter) {
  if (this != &sign_parameter) {
    data_ = sign_parameter.GetData();
    data_type_ = sign_parameter.GetDataType();
    related_pubkey_ = sign_parameter.GetRelatedPubkey();
    der_encode_ = sign_parameter.IsDerEncode();
    sighash_type_ = sign_parameter.GetSigHashType();
    op_code_ = sign_parameter.GetOpCode();
  }
  return *this;
}

void SignParameter::SetRelatedPubkey(const Pubkey& pubkey) {
  if (pubkey.IsValid()) {
    related_pubkey_ = pubkey;
  }
}

ScriptOperator SignParameter::GetOpCode() const { return op_code_; }

bool SignParameter::IsOpCode() const {
  return data_type_ == SignDataType::kOpCode;
}

ByteData SignParameter::GetData() const { return data_; }

SignDataType SignParameter::GetDataType() const { return data_type_; }

Pubkey SignParameter::GetRelatedPubkey() const { return related_pubkey_; }

bool SignParameter::IsDerEncode() const { return der_encode_; }

SigHashType SignParameter::GetSigHashType() const { return sighash_type_; }

ByteData SignParameter::ConvertToSignature() const {
  ByteData byte_data;
  if (der_encode_) {
    if (data_.Empty()) {
      warn(CFD_LOG_SOURCE, "Failed to ConvertToSignature. sign hex empty.");
      throw CfdException(
          CfdError::kCfdIllegalArgumentError,
          "Invalid hex string. empty sign data.");
    }
    byte_data =
        CryptoUtil::ConvertSignatureToDer(data_.GetHex(), sighash_type_);
  } else {
    byte_data = data_;
  }
  return byte_data;
}

// -----------------------------------------------------------------------------
// TransactionController
// -----------------------------------------------------------------------------
AbstractTransactionController::AbstractTransactionController()
    : tx_address_(nullptr) {
  // do nothing
}

std::string AbstractTransactionController::GetHex() const {
  return tx_address_->GetHex();
}

uint32_t AbstractTransactionController::GetLockTimeDisabledSequence() {
  return kSequenceDisableLockTime;
}

uint32_t AbstractTransactionController::GetDefaultSequence() const {
  if (tx_address_->GetLockTime() == 0) {
    return kSequenceDisableLockTime;
  } else {
    return kSequenceEnableLockTimeMax;
  }
}
}  // namespace cfd
