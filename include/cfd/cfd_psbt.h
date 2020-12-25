// Copyright 2020 CryptoGarage
/**
 * @file cfd_psbt.h
 *
 * @brief This file is defines Partially Signed Bitcoin Transaction.
 */
#ifndef CFD_INCLUDE_CFD_CFD_PSBT_H_
#define CFD_INCLUDE_CFD_CFD_PSBT_H_

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

#include "cfd/cfd_common.h"
#include "cfd/cfd_transaction_common.h"
#include "cfd/cfd_transaction.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_descriptor.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_hdwallet.h"
#include "cfdcore/cfdcore_transaction_common.h"
#include "cfdcore/cfdcore_psbt.h"

namespace cfd {

using cfd::core::Descriptor;
using cfd::core::OutPoint;
using cfd::core::Transaction;
using cfd::core::KeyData;

/**
 * @brief The class of Partially Signed Bitcoin Transaction.
 */
class CFD_CORE_EXPORT Psbt : cfd::core::Psbt {
 public:
  /**
   * @brief constructor.
   *
   * for List.
   */
  Psbt();
  /**
   * @brief constructor
   * @param[in] version       tx version
   * @param[in] lock_time     lock time
   */
  explicit Psbt(uint32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] version       tx version
   * @param[in] lock_time     lock time
   */
  explicit Psbt(uint32_t psbt_version, uint32_t version, uint32_t lock_time);
  /**
   * @brief constructor
   * @param[in] base64    base64 string.
   */
  explicit Psbt(const std::string& base64);
  /**
   * @brief constructor
   * @param[in] byte_data   byte data
   */
  explicit Psbt(const ByteData& byte_data);
  /**
   * @brief constructor
   * @param[in] transaction   Transaction object.
   */
  explicit Psbt(const Transaction& transaction);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] transaction   Transaction object.
   */
  explicit Psbt(uint32_t psbt_version, const Transaction& transaction);
  /**
   * @brief constructor
   * @param[in] psbt_version  psbt version
   * @param[in] context       Transaction object.
   */
  explicit Psbt(uint32_t psbt_version, const TransactionContext& context);
  /**
   * @brief constructor
   * @param[in] psbt   Psbt object.
   */
  explicit Psbt(const Psbt& psbt);
  /**
   * @brief destructor
   */
  virtual ~Psbt() {}

  TransactionContext GetTransactionContext() const;

  uint32_t GetInputCount() const;
  uint32_t GetOutputCount() const;

  void AddTxIn(const OutPoint& outpoint);
  void AddTxIn(const OutPoint& outpoint, uint32_t sequence);

  void AddTxInData(const UtxoData& utxo);
  void AddTxInData(const UtxoData& utxo, uint32_t sequence);

  bool IsFindTxIn(const OutPoint& outpoint) const;
  uint32_t GetTxInIndex(const OutPoint& outpoint) const;

  void SetUtxoData(const UtxoData& utxo, const Transaction& transaction);
  void SetWitnessUtxoData(const UtxoData& utxo);
  /**
   * @brief collect utxo and cache into utxo_map_.
   * @param[in] utxos   utxo list.
   */
  void CollectInputUtxo(const std::vector<UtxoData>& utxos);

  void AddTxOut(const Amount& amount, const Address& address);
  void AddTxOutData(const Amount& amount, const Address& address,
      const KeyData& key_data);
  void AddTxOutData(const Amount& amount, const Address& address,
      const std::vector<KeyData>& key_list);

  /**
   * @brief set ignore verify target.
   * @param[in] outpoint    utxo target.
   */
  void IgnoreVerify(const OutPoint& outpoint);
  /**
   * @brief verify tx sign (signature).
   */
  void Verify();
  /**
   * @brief verify tx sign (signature) on outpoint.
   * @param[in] outpoint    utxo target.
   */
  void Verify(const OutPoint& outpoint);

  // FIXME fund
  Address FundTransaction(const Descriptor& change_address,
      const std::vector<UtxoData>& utxos,
      double effective_fee_rate = 20.0,
      Amount* estimate_fee = nullptr,
      const UtxoFilter* filter = nullptr,
      const CoinSelectionOption* option_params = nullptr);
};

}  // namespace cfd

#endif  // CFD_INCLUDE_CFD_CFD_PSBT_H_
