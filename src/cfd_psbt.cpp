// Copyright 2019 CryptoGarage
/**
 * @file cfd_fee.cpp
 *
 * @brief This file is implements Partially Signed Bitcoin Transaction.
 */

#include <algorithm>
#include <string>
#include <vector>

#include "cfd/cfd_psbt.h"
#include "cfdcore/cfdcore_psbt.h"
#include "cfdcore/cfdcore_amount.h"
#include "cfdcore/cfdcore_transaction.h"
#include "cfdcore/cfdcore_transaction_common.h"

namespace cfd {

using cfd::core::AbstractTransaction;
using cfd::core::Amount;
using cfd::core::TxIn;

#if 0
/*
- cfd-coreで実装する機能
  - パラメータ個別でのAdd/Edit/Remove
    -> Edit/Removeは申し送り。
- cfdで実装する機能
  - OutPoint指定での登録
  - UTXO一括登録, 更新（utxoupdatepsbt）
    -> full txだと無理。TxOut分のみに制限すべき。
  - FundRawTransaction
    - reserved address情報はdescriptorで渡してもらうことにする。
      - addressTypeが必要なため
  - TX情報を直接設定するAPI（ただしOutput側のKey一覧は未設定）
    -> 意図不明
  - decodepsbt, analyzepsbt
  - 署名関連
    -> key指定でのsignだが、libwallycoreのAPIで十分なので現状必要ないかも、、
    -> 他に必要なものがあれば追加する。
  - その他、bitcoin-cli相当の動作（converttopsbt、createpsbt）

- usecase
  - Creator
    - 初期TXを作成する。（Inputは空）
  - Updater
    - Inputを追加する。（各自にPSBTを送付して追加してもらう）
    - その後、Fund相当の処理を行う。
    - Base TXはここでFIXする。
  - Signer
    - Signを追加する。（各自にPSBTを送付して追加してもらう）
  - Combiner
    - Signerが署名したTXを結合する。
  - Input Finalizer
    - InputのFinalize処理
      - ここ、APIにした方が良いかもしれない。★
  - Transaction Extractor
    - export


{ "rawtransactions",    "decodepsbt",     &decodepsbt,       {"psbt"} },
{ "rawtransactions",    "analyzepsbt",    &analyzepsbt,      {"psbt"} },
{ "rawtransactions",    "createpsbt",     &createpsbt,       {"inputs","outputs","locktime","replaceable"} },
{ "rawtransactions",    "converttopsbt",  &converttopsbt,    {"hexstring","permitsigdata","iswitness"} },
{ "rawtransactions",    "joinpsbts",      &joinpsbts,        {"txs"} },
{ "rawtransactions",    "utxoupdatepsbt", &utxoupdatepsbt,   {"psbt"} },
{ "rawtransactions",    "combinepsbt",    &combinepsbt,      {"txs"} },
{ "rawtransactions",    "finalizepsbt",   &finalizepsbt,     {"psbt", "extract"} },

{ "wallet",           "walletcreatefundedpsbt", &walletcreatefundedpsbt,  {"inputs","outputs","locktime","options","bip32derivs","solving_data"} }, Creator and Updater
{ "wallet",           "walletprocesspsbt",      &walletprocesspsbt,       {"psbt","sign","sighashtype","bip32derivs"} },
{ "wallet",           "walletfillpsbtdata",     &walletfillpsbtdata,      {"psbt","bip32derivs"} },
{ "wallet",           "walletsignpsbt",         &walletsignpsbt,          {"psbt","sighashtype","imbalance_ok"} },

walletfillpsbtdata: bip32情報を付与してキーの追加？

*/
#endif


// -----------------------------------------------------------------------------
// File constants
// -----------------------------------------------------------------------------
//! KB size
static constexpr const uint64_t kKiloByteSize = 1000;

// -----------------------------------------------------------------------------
// Psbt
// -----------------------------------------------------------------------------


}  // namespace cfd
