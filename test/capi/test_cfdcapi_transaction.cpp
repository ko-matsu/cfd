#include "gtest/gtest.h"

#include <stdexcept>
#include <string>
#include <vector>

#include "capi/cfdc_internal.h"
#include "cfd/cfd_transaction_common.h"
#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_elements_transaction.h"
#include "cfdc/cfdcapi_key.h"
#include "cfdc/cfdcapi_transaction.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_script.h"

using cfd::Utxo;
using cfd::core::ByteData;
using cfd::core::ByteData256;

extern std::vector<Utxo> CfdGetElementsUtxoListByC(bool use_asset);

/**
 * @brief testing class.
 */
class cfdcapi_transaction : public ::testing::Test {
 protected:
  virtual void SetUp() { }
  virtual void TearDown() { }
};

TEST(cfdcapi_transaction, CreateRawTransaction) {
  static const char* exp_tx = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

  void* handle = nullptr;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  void* create_handle = nullptr;
  ret = CfdInitializeTransaction(
      handle, kCfdNetworkMainnet, 1, 17, nullptr, &create_handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == create_handle));

  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionInput(
        handle, create_handle, "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff", 0,
        4294967278);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionInput(
        handle, create_handle, "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef", 1,
        0xffffffff);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionOutput(
        handle, create_handle, 112340000, "1Cu32FVupVCgHkMMRJdYJugxwo2Aprgk7H",
        nullptr, nullptr);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionOutput(
        handle, create_handle, 223450000, "16TZ8J6Q5iZKBWizWzFAYnrsaox5Z5aBRV",
        nullptr, nullptr);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  if (ret == kCfdSuccess) {
    char* tx = nullptr;
    ret = CfdFinalizeTransaction(handle, create_handle, &tx);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(exp_tx, tx);
      CfdFreeStringBuffer(tx);
    }
  }

  ret = CfdFreeTransactionHandle(handle, create_handle);
  EXPECT_EQ(kCfdSuccess, ret);

  ret = CfdGetLastErrorCode(handle);
  if (ret != kCfdSuccess) {
    char* str_buffer = NULL;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("", str_buffer);
    CfdFreeStringBuffer(str_buffer);
    str_buffer = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_transaction, GetTransaction) {
  static const char* exp_tx = "0100000000010136641869ca081e70f394c6948e8af409e18b619df2ed74aa106c1ca29787b96e0100000023220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54ffffffff0200e9a435000000001976a914389ffce9cd9ae88dcc0631e88a821ffdbe9bfe2688acc0832f05000000001976a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac080047304402206ac44d672dac41f9b00e28f4df20c52eeb087207e8d758d76d92c6fab3b73e2b0220367750dbbe19290069cba53d096f44530e4f98acaa594810388cf7409a1870ce01473044022068c7946a43232757cbdf9176f009a928e1cd9a1a8c212f15c1e11ac9f2925d9002205b75f937ff2f9f3c1246e547e54f62e027f64eefa2695578cc6432cdabce271502473044022059ebf56d98010a932cf8ecfec54c48e6139ed6adb0728c09cbe1e4fa0915302e022007cd986c8fa870ff5d2b3a89139c9fe7e499259875357e20fcbb15571c76795403483045022100fbefd94bd0a488d50b79102b5dad4ab6ced30c4069f1eaa69a4b5a763414067e02203156c6a5c9cf88f91265f5a942e96213afae16d83321c8b31bb342142a14d16381483045022100a5263ea0553ba89221984bd7f0b13613db16e7a70c549a86de0cc0444141a407022005c360ef0ae5a5d4f9f2f87a56c1546cc8268cab08c73501d6b3be2e1e1a8a08824730440220525406a1482936d5a21888260dc165497a90a15669636d8edca6b9fe490d309c022032af0c646a34a44d1f4576bf6a4a74b67940f8faa84c7df9abe12a01a11e2b4783cf56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae00000000";

  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* txid = nullptr;
  char* wtxid = nullptr;
  uint32_t size = 0;
  uint32_t vsize = 0;
  uint32_t weight = 0;
  uint32_t version = 0;
  uint32_t locktime = 0;
  ret = CfdGetTxInfo(
      handle, kCfdNetworkMainnet, exp_tx, &txid, &wtxid, &size, &vsize,
      &weight, &version, &locktime);
  EXPECT_EQ(kCfdSuccess, ret);

  char* txin_txid = nullptr;
  char* script_sig = nullptr;
  uint32_t vout = 0;
  uint32_t sequence = 0;
  ret = CfdGetTxIn(
      handle, kCfdNetworkMainnet, exp_tx, 0,
      &txin_txid, &vout, &sequence, &script_sig);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436", txin_txid);
    EXPECT_EQ(1, vout);
    EXPECT_EQ(4294967295, sequence);
    EXPECT_STREQ("220020a16b5755f7f6f96dbd65f5f0d6ab9418b89af4b1f14a1bb8a09062c35f0dcb54", script_sig);
    CfdFreeStringBuffer(txin_txid);
    CfdFreeStringBuffer(script_sig);
  }

  char* stack_data = nullptr;
  ret = CfdGetTxInWitness(
      handle, kCfdNetworkMainnet, exp_tx, 0, 7, &stack_data);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("56210307b8ae49ac90a048e9b53357a2354b3334e9c8bee813ecb98e99a7e07e8c3ba32103b28f0c28bfab54554ae8c658ac5c3e0ce6e79ad336331f78c428dd43eea8449b21034b8113d703413d57761b8b9781957b8c0ac1dfe69f492580ca4195f50376ba4a21033400f6afecb833092a9a21cfdf1ed1376e58c5d1f47de74683123987e967a8f42103a6d48b1131e94ba04d9737d61acdaa1322008af9602b3b14862c07a1789aac162102d8b661b0b3302ee2f162b09e07a55ad5dfbe673a9f01d9f0c19617681024306b56ae", stack_data);
    CfdFreeStringBuffer(stack_data);
  }

  int64_t value_satoshi = 0;
  char* locking_script = nullptr;
  ret = CfdGetTxOut(
      handle, kCfdNetworkMainnet, exp_tx, 1,
      &value_satoshi, &locking_script);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_EQ(87000000, value_satoshi);
    EXPECT_STREQ("76a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac", locking_script);
    CfdFreeStringBuffer(locking_script);
  }

  uint32_t count = 0;
  ret = CfdGetTxInCount(
      handle, kCfdNetworkMainnet, exp_tx, &count);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(1, count);

  ret = CfdGetTxInWitnessCount(
      handle, kCfdNetworkMainnet, exp_tx, 0, &count);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(8, count);

  ret = CfdGetTxOutCount(
      handle, kCfdNetworkMainnet, exp_tx, &count);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(2, count);

  uint32_t index = 0;
  ret = CfdGetTxInIndex(
      handle, kCfdNetworkMainnet, exp_tx,
      "6eb98797a21c6c10aa74edf29d618be109f48a8e94c694f3701e08ca69186436", 1, &index);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(0, index);

  ret = CfdGetTxOutIndex(
      handle, kCfdNetworkMainnet, exp_tx, "16AQVuBMt818u2HBcbxztAZTT2VTDKupPS", "", &index);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(0, index);

  ret = CfdGetTxOutIndex(
      handle, kCfdNetworkMainnet, exp_tx, "", "76a9147480a33f950689af511e6e84c138dbbd3c3ee41588ac", &index);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(1, index);

  ret = CfdGetLastErrorCode(handle);
  if (ret != kCfdSuccess) {
    char* str_buffer = NULL;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("", str_buffer);
    CfdFreeStringBuffer(str_buffer);
    str_buffer = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_transaction, CfdAddSignWithPrivkeySimple) {
  static const char* tx_hex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
  static const char* exp_tx_hex = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a010000001716001473a4fc7f4c3cd762c86986f61abb7274d3914bf5ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402205c933cb3e81a1cb298e62e237169714bbc3a73c071d5c95d4b8e96b658913d8a022034075443df871165b5c998ead5e728d269182edde68b8b23a9c52a91d69293d0012102715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad11000000";

  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* tx_string = nullptr;
  ret = CfdAddSignWithPrivkeySimple(
      handle, kCfdNetworkMainnet, tx_hex,
      "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef", 1,
      kCfdP2shP2wpkh, "02715ed9a5f16153c5216a6751b7d84eba32076f0b607550a58b209077ab7c30ad",
      "cRVLMWHogUo51WECRykTbeLNbm5c57iEpSegjdxco3oef6o5dbFi",
      112340000, kCfdSigHashAll, false, true, &tx_string);
  EXPECT_EQ(kCfdSuccess, ret);

  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp_tx_hex, tx_string);
    CfdFreeStringBuffer(tx_string);
  }

  ret = CfdGetLastErrorCode(handle);
  if (ret != kCfdSuccess) {
    char* str_buffer = NULL;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("", str_buffer);
    CfdFreeStringBuffer(str_buffer);
    str_buffer = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_transaction, CfdCreateSighash) {
  static const char* tx_hex = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";

  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* sighash = nullptr;
  ret = CfdCreateSighash(
      handle, kCfdNetworkMainnet, tx_hex, "8ac60eb9575db5b2d987e29f301b5b819ea83a5c6579d282d189cc04b8e151ef",
      1, kCfdP2wpkh, "025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee6357", "",
      600000000, kCfdSigHashAll, false, &sighash);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670", sighash);
    CfdFreeStringBuffer(sighash);
  }

  ret = CfdGetLastErrorCode(handle);
  if (ret != kCfdSuccess) {
    char* str_buffer = NULL;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("", str_buffer);
    CfdFreeStringBuffer(str_buffer);
    str_buffer = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}


// FundRawTransaction(BTC) =====================================================

TEST(cfdcapi_transaction, FundRawTransaction_BTC1) {
  constexpr const char* kDescriptor = "sh(wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1))#4z2vy08x";
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  auto convert_to_byte = [](const uint8_t* byte_array, size_t size) -> std::string {
    std::vector<uint8_t> bytes(size);
    memcpy(bytes.data(), byte_array, bytes.size());
    std::vector<uint8_t> reverse_buffer(bytes.crbegin(), bytes.crend());
    return ByteData(reverse_buffer).GetHex();
  };

  void* fund_handle = nullptr;
  std::vector<Utxo> utxos = CfdGetElementsUtxoListByC(true);
  double effective_fee_rate = 10.0;
  double long_term_fee_rate = 10.0;
  double dust_fee_rate = -1;
  int64_t knapsack_min_change = -1;

  void* create_handle = nullptr;
  ret = CfdInitializeTransaction(
      handle, kCfdNetworkMainnet, 1, 17, nullptr, &create_handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == create_handle));

  char* tx = nullptr;
  int64_t amount = 112340000;
  const char* txid1 = "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff";
  uint32_t vout1 = 0;
  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionInput(handle, create_handle, txid1, vout1, 0xfffffffe);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdAddTransactionOutput(
        handle, create_handle, amount, "bc1qcevcszwsnmd2ew857n2mnwq7gsf62ujrutrfch",
        nullptr, nullptr);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdFinalizeTransaction(handle, create_handle, &tx);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("0100000001fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff01202cb20600000000160014c6598809d09edaacb8f4f4d5b9b81e4413a5724311000000", tx);
    ret = CfdFreeTransactionHandle(handle, create_handle);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  uint32_t target_asset_count = 1;
  if (ret == kCfdSuccess) {
    ret = CfdInitializeFundRawTx(
        handle, kCfdNetworkMainnet, target_asset_count, nullptr, &fund_handle);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_NE(nullptr, fund_handle);
  }

  if (ret == kCfdSuccess) {
    for (const auto& utxo : utxos) {
      std::string txid = convert_to_byte(utxo.txid, sizeof(utxo.txid));
      ret = CfdAddUtxoForFundRawTx(
          handle, fund_handle,
          Txid(txid).GetHex().c_str(), utxo.vout,
          utxo.amount,
          kDescriptor,
          "");
      EXPECT_EQ(kCfdSuccess, ret);
    }

    ret = CfdAddTxInForFundRawTx(handle, fund_handle,
        "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff", 0,
        amount,  kDescriptor, "", false, false, false, 0, "");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddTargetAmountForFundRawTx(handle, fund_handle, 0, 65976100,
        "", "bc1qdnf34k9c255nfa9anjx0sj5ne0t6f80p72wpce");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxIsBlind,
        0, 0, true);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxDustFeeRate,
        0, dust_fee_rate, false);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxLongTermFeeRate,
        0, long_term_fee_rate, false);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxKnapsackMinChange,
        knapsack_min_change, 0, false);
    EXPECT_EQ(kCfdSuccess, ret);

    int64_t tx_fee_amount = 0;
    uint32_t append_txout_count = 0;
    char* output_tx_hex = nullptr;
    ret = CfdFinalizeFundRawTx(handle, fund_handle, tx,
        effective_fee_rate, &tx_fee_amount, &append_txout_count,
        &output_tx_hex);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_EQ(3420, tx_fee_amount);
    EXPECT_EQ(1, append_txout_count);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("0100000003fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff0ad4a335556c64c3e2599c3a4c3ddff5b28f616fa55cf2323d2ae642eef74a8f0000000000feffffff010b0000000000000000000000000000000000000000000000000000000000000000000000feffffff02202cb20600000000160014c6598809d09edaacb8f4f4d5b9b81e4413a5724388bcee03000000001600146cd31ad8b8552934f4bd9c8cf84a93cbd7a49de111000000", output_tx_hex);
    }

    char* address = nullptr;
    ret = CfdGetAppendTxOutFundRawTx(handle, fund_handle, 0, &address);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("bc1qdnf34k9c255nfa9anjx0sj5ne0t6f80p72wpce", address);
  }
  ret = CfdFreeFundRawTxHandle(handle, fund_handle);
  EXPECT_EQ(kCfdSuccess, ret);

  CfdFreeStringBuffer(tx);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

// FundRawTransaction(multi Asset) =====================================================

#ifndef CFD_DISABLE_ELEMENTS
static constexpr const char* exp_dummytx_asset_ca = "aa00000000000000000000000000000000000000000000000000000000000000";
static constexpr const char* exp_dummytx_asset_cb = "bb00000000000000000000000000000000000000000000000000000000000000";
static constexpr const char* exp_dummytx_asset_cc = "cc00000000000000000000000000000000000000000000000000000000000000";

// reserved address key
// {    // ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e, bc1qdnf34k9c255nfa9anjx0sj5ne0t6f80p72wpce
//   pubkey: '0367ebd58ffca93a4f4a2a9c3cc24009101f39449e0993ca08b05fdbfb6e32a01b',
//   privkey: 'cTmuwbL1JXexLBLUoQd2nVo3mggkgkJ1RSRYj7cbiUsa5CYeQCkr'
// }, { // ex1q3tlca6nma70vvrf46up5ktjguxqwj0zamt7ktn
//   pubkey: '0202acaad1eee2b86a44687825e535d61a67f9276db720165fc296cdb1f6f92b9a',
//   privkey: 'cNaupUdFeVnWoWvqP9tStbpLKdTtUe2zgAm7L6vFxQVhk2JwgzRQ'
// }, { // ex1q0xdg60c3y5dk5m05hg2k52xavjkedx53t3k40m
//   pubkey: '02ba35856676b525fead8de496d15ed080bd8442cc2672f5cac81be1fd29e92fba',
//   privkey: 'cP12ycK4NMfT1Nur6HcQMvbiihMYquESYv5nE7jvHXpwK57Mj9Ey'
// }

// addr: ex1qcevcszwsnmd2ew857n2mnwq7gsf62ujrkz734h, bc1qcevcszwsnmd2ew857n2mnwq7gsf62ujrutrfch
// pubkey: '03ac6b4b32eb27ec1c13c6180dce6b0016e46a070bdac96b4d76f5da16ab66ae8f',
// privkey: 'cSzUivMfRpXotHt27jTKpP6uJyxmQFbkMkQnvMPSq4gBdySxFvAR'

TEST(cfdcapi_transaction, FundRawTransaction_Asset1) {
  constexpr const char* kDescriptor = "sh(wpkh([ef735203/0'/0'/7']022c2409fbf657ba25d97bb3dab5426d20677b774d4fc7bd3bfac27ff96ada3dd1))#4z2vy08x";
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  auto convert_to_byte = [](const uint8_t* byte_array, size_t size) -> std::string {
    if (size == 32) {
      std::vector<uint8_t> bytes(size);
      memcpy(bytes.data(), byte_array, bytes.size());
      std::vector<uint8_t> reverse_buffer(bytes.crbegin(), bytes.crend());
      return ByteData(reverse_buffer).GetHex();
    } else {
      std::vector<uint8_t> bytes(32);
      memcpy(bytes.data(), byte_array + 1, bytes.size());
      std::vector<uint8_t> reverse_buffer(bytes.crbegin(), bytes.crend());
      return ByteData(reverse_buffer).GetHex();
    }
  };

  void* fund_handle = nullptr;
  std::vector<Utxo> utxos = CfdGetElementsUtxoListByC(true);
  double effective_fee_rate = -1;
  double long_term_fee_rate = -1;
  double dust_fee_rate = -1;
  int64_t knapsack_min_change = -1;

  void* create_handle = nullptr;
  ret = CfdInitializeTransaction(
      handle, kCfdNetworkLiquidv1, 1, 17, nullptr, &create_handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == create_handle));

  char* tx = nullptr;
  int64_t amount = 112340000;
  const char* txid1 = "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff";
  uint32_t vout1 = 0;
  if (ret == kCfdSuccess) {
    ret = CfdAddTransactionInput(handle, create_handle, txid1, vout1, 0xfffffffe);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdAddTransactionOutput(
        handle, create_handle, amount, "ex1qcevcszwsnmd2ew857n2mnwq7gsf62ujrkz734h",
        nullptr, exp_dummytx_asset_ca);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdFinalizeTransaction(handle, create_handle, &tx);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("010000000001fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff010100000000000000000000000000000000000000000000000000000000000000aa010000000006b22c2000160014c6598809d09edaacb8f4f4d5b9b81e4413a5724311000000", tx);
    ret = CfdFreeTransactionHandle(handle, create_handle);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  uint32_t target_asset_count = 3;
  if (ret == kCfdSuccess) {
    ret = CfdInitializeFundRawTx(
        handle, kCfdNetworkLiquidv1, target_asset_count,
        exp_dummytx_asset_ca, &fund_handle);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_NE(nullptr, fund_handle);
  }

  if (ret == kCfdSuccess) {
    for (const auto& utxo : utxos) {
      std::string txid = convert_to_byte(utxo.txid, sizeof(utxo.txid));
      ret = CfdAddUtxoForFundRawTx(
          handle, fund_handle,
          Txid(txid).GetHex().c_str(), utxo.vout,
          utxo.amount,
          kDescriptor,
          convert_to_byte(utxo.asset, sizeof(utxo.asset)).c_str());
      EXPECT_EQ(kCfdSuccess, ret);
    }

    ret = CfdAddTxInForFundRawTx(handle, fund_handle,
        "9f96ade4b41d5433f4eda31e1738ec2b36f6e7d1420d94a6af99801a88f7f7ff", 0,
        amount,  kDescriptor, exp_dummytx_asset_ca,
        false, false, false, 0, "");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddTargetAmountForFundRawTx(handle, fund_handle, 0, 115800000,
        exp_dummytx_asset_ca, "ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e");
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdAddTargetAmountForFundRawTx(handle, fund_handle, 1, 347180040,
        exp_dummytx_asset_cb, "ex1q3tlca6nma70vvrf46up5ktjguxqwj0zamt7ktn");
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdAddTargetAmountForFundRawTx(handle, fund_handle, 2, 37654100,
        exp_dummytx_asset_cc, "ex1q0xdg60c3y5dk5m05hg2k52xavjkedx53t3k40m");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxIsBlind,
        0, 0, true);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxDustFeeRate,
        0, dust_fee_rate, false);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxLongTermFeeRate,
        0, long_term_fee_rate, false);
    EXPECT_EQ(kCfdSuccess, ret);
    ret = CfdSetOptionFundRawTx(handle, fund_handle, kCfdFundTxKnapsackMinChange,
        knapsack_min_change, 0, false);
    EXPECT_EQ(kCfdSuccess, ret);

    int64_t tx_fee_amount = 0;
    uint32_t append_txout_count = 0;
    char* output_tx_hex = nullptr;
    ret = CfdFinalizeFundRawTx(handle, fund_handle, tx,
        effective_fee_rate, &tx_fee_amount, &append_txout_count,
        &output_tx_hex);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_EQ(67540, tx_fee_amount);
    EXPECT_EQ(3, append_txout_count);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("010000000006fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000feffffff0a9a33750a810cd384ca5d93b09513f1eb5d93c669091b29eef710d2391ff7300000000000feffffff0ad4a335556c64c3e2599c3a4c3ddff5b28f616fa55cf2323d2ae642eef74a8f0000000000feffffff030b0000000000000000000000000000000000000000000000000000000000000000000000feffffff020b0000000000000000000000000000000000000000000000000000000000000000000000feffffff010c0000000000000000000000000000000000000000000000000000000000000000000000feffffff050100000000000000000000000000000000000000000000000000000000000000aa010000000006b22c2000160014c6598809d09edaacb8f4f4d5b9b81e4413a572430100000000000000000000000000000000000000000000000000000000000000aa0100000000000107d400000100000000000000000000000000000000000000000000000000000000000000bb010000000014b18c12001600148aff8eea7bef9ec60d35d7034b2e48e180e93c5d0100000000000000000000000000000000000000000000000000000000000000cc0100000000023e8eb800160014799a8d3f11251b6a6df4ba156a28dd64ad969a910100000000000000000000000000000000000000000000000000000000000000aa010000000006fb1bd8001600146cd31ad8b8552934f4bd9c8cf84a93cbd7a49de111000000", output_tx_hex);
    }

    for (uint32_t index = 0; index < append_txout_count; ++index) {
      char* address = nullptr;
      ret = CfdGetAppendTxOutFundRawTx(handle, fund_handle, index, &address);
      EXPECT_EQ(kCfdSuccess, ret);
      if (ret == kCfdSuccess) {
        if (index == 0) {
          EXPECT_STREQ("ex1q3tlca6nma70vvrf46up5ktjguxqwj0zamt7ktn", address);
        } else if (index == 1) {
          EXPECT_STREQ("ex1q0xdg60c3y5dk5m05hg2k52xavjkedx53t3k40m", address);
        } else if (index == 2) {
          EXPECT_STREQ("ex1qdnf34k9c255nfa9anjx0sj5ne0t6f80p5rne4e", address);
        }
      }
      CfdFreeStringBuffer(address);
    }
  }
  ret = CfdFreeFundRawTxHandle(handle, fund_handle);
  EXPECT_EQ(kCfdSuccess, ret);

  CfdFreeStringBuffer(tx);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}
#endif  // CFD_DISABLE_ELEMENTS
