#include "gtest/gtest.h"

#include <stdexcept>
#include <string>

#include "cfd/cfd_common.h"
#include "cfdc/cfdcapi_common.h"
#include "capi/cfdc_internal.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_hdwallet.h"

/**
 * @brief testing class.
 */
class cfdcapi_common : public ::testing::Test {
 protected:
  virtual void SetUp() { }
  virtual void TearDown() { }
};

TEST(cfdcapi_common, CfdGetSupportedFunction) {
  uint64_t functions = 0;
  int ret = CfdGetSupportedFunction(&functions);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(1,  functions & 0x01);

  ret = CfdGetSupportedFunction(NULL);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);
}

TEST(cfdcapi_common, CfdCreateHandle) {
  int ret = CfdCreateHandle(NULL);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  void* handle = NULL;
  ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  ret = CfdFreeHandle(NULL);
  EXPECT_EQ(kCfdSuccess, ret);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdCreateSimpleHandle) {
  int ret = CfdCreateSimpleHandle(NULL);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  void* handle = NULL;
  ret = CfdCreateSimpleHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdCloneHandle) {
  cfd::Initialize();
  int ret = CfdCloneHandle(NULL, NULL);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  void* handle = NULL;
  ret = CfdCloneHandle(NULL, &handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  void* handle2 = NULL;
  ret = CfdCloneHandle(handle, &handle2);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle2));

  ret = CfdCopyErrorState(handle, handle2);
  EXPECT_EQ(kCfdSuccess, ret);

  ret = CfdFreeHandle(handle2);
  EXPECT_EQ(kCfdSuccess, ret);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdFreeBuffer) {
  int ret = CfdFreeBuffer(NULL);
  EXPECT_EQ(kCfdSuccess, ret);

  void* buffer = malloc(1);
  ret = CfdFreeBuffer(buffer);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdFreeStringBuffer) {
  int ret = CfdFreeStringBuffer(NULL);
  EXPECT_EQ(kCfdSuccess, ret);

  char* buffer = static_cast<char*>(malloc(1));
  ret = CfdFreeStringBuffer(buffer);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdGetLastErrorCode) {
  int ret = CfdGetLastErrorCode(NULL);
  EXPECT_EQ(kCfdSuccess, ret);

  void* handle = NULL;
  ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  ret = CfdGetLastErrorCode(handle);
  EXPECT_EQ(kCfdSuccess, ret);

  cfd::capi::SetLastError(handle, kCfdOutOfRangeError, "dummy");
  ret = CfdGetLastErrorCode(handle);
  EXPECT_EQ(kCfdOutOfRangeError, ret);

  cfd::capi::SetLastFatalError(handle, "dummy");
  ret = CfdGetLastErrorCode(handle);
  EXPECT_EQ(kCfdUnknownError, ret);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdGetLastErrorMessage) {
  int ret = CfdGetLastErrorMessage(NULL, NULL);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  char* str_buffer = NULL;
  ret = CfdGetLastErrorMessage(NULL, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  void* handle = NULL;
  ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  ret = CfdGetLastErrorMessage(handle, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_STREQ("", str_buffer);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  cfd::capi::SetLastFatalError(handle, "dummy");
  ret = CfdGetLastErrorMessage(handle, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_STREQ("dummy", str_buffer);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  cfd::capi::SetLastError(handle,
    cfd::core::CfdException(cfd::core::CfdError::kCfdInternalError,
      "dummy_cfdexcept"));
  ret = CfdGetLastErrorMessage(handle, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  ret = CfdGetLastErrorCode(handle);
  EXPECT_EQ(kCfdInternalError, ret);
  EXPECT_STREQ("dummy_cfdexcept", str_buffer);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  cfd::capi::SetLastFatalError(handle, std::runtime_error("dummy_except"));
  ret = CfdGetLastErrorMessage(handle, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  ret = CfdGetLastErrorCode(handle);
  EXPECT_EQ(kCfdUnknownError, ret);
  EXPECT_STREQ("dummy_except", str_buffer);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdRequestExecuteJson_decodetx) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));
  char* respons_json = nullptr;

  // DecodeRawTransaction multiple input and output. (TxIn:2/TxOut:3)
  const char* request_json1 = "{\"hex\":\"02000000034cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20000000000ffffffff81ddd34c6c0c32544e3b89f5e24c6cd7afca62f2b5069281ac9fced6251191d20100000000ffffffff030200000000000000220020c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef406f400100000000220020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d215cd5b0700000000220020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a4200000000\"}";
  const char* exp_json1 = "{\"txid\":\"1fdeb34ff44d832a0064b57a4ec1d5ff4b6a64e2f65acafde071dff0dbd501ca\",\"hash\":\"1fdeb34ff44d832a0064b57a4ec1d5ff4b6a64e2f65acafde071dff0dbd501ca\",\"version\":2,\"size\":262,\"vsize\":262,\"weight\":1048,\"locktime\":0,\"vin\":[{\"txid\":\"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"d2911125d6ce9fac819206b5f262caafd76c4ce2f5893b4e54320c6c4cd3dd81\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"d2911125d6ce9fac819206b5f262caafd76c4ce2f5893b4e54320c6c4cd3dd81\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":2,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef\",\"hex\":\"0020c5ae4ff17cec055e964b573601328f3f879fa441e53ef88acdfd4d8e8df429ef\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"bc1qckhylutuasz4a9jt2umqzv5087relfzpu5l03zkdl4xcar0598hs4hsymp\"]}},{\"value\":21000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d2\",\"hex\":\"0020ea5a7208cddfbc20dd93e12bf29deb00b68c056382a502446c9c5b55490954d2\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"bc1qafd8yzxdm77zphvnuy4l980tqzmgcptrs2jsy3rvn3d42jgf2nfqc4zt4j\"]}},{\"value\":123456789,\"n\":2,\"scriptPubKey\":{\"asm\":\"0 f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42\",\"hex\":\"0020f39f6272ba6b57918eb047c5dc44fb475356b0f24c12fca39b19284e80008a42\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"bc1q7w0kyu46ddterr4sglzac38mgaf4dv8jfsf0egumry5yaqqq3fpqj93pax\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "DecodeRawTransaction", request_json1, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json1, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodeRawTransaction network (testnet)
  const char* request_json2 = "{\"hex\":\"02000000014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff0101000000000000002200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326200000000\",\"network\":\"testnet\"}";
  const char* exp_json2 = "{\"txid\":\"6655abb87632ba0730ff5c4e3280a063cc7984be43d89c8e19d766996ff3d307\",\"hash\":\"6655abb87632ba0730ff5c4e3280a063cc7984be43d89c8e19d766996ff3d307\",\"version\":2,\"size\":94,\"vsize\":94,\"weight\":376,\"locktime\":0,\"vin\":[{\"txid\":\"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":1,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262\",\"hex\":\"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "DecodeRawTransaction", request_json2, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json2, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodeRawTransaction network (regtest)
  const char* request_json3 = "{\"hex\":\"02000000014cdeada737db97af334f0fa4e87432d6068759eea65a3067d1f14a979e5a9dea0000000000ffffffff0101000000000000002200201863143c14c5166804bd19203356da136c985678cd4d27a1b8c632960490326200000000\",\"network\":\"regtest\"}";
  const char* exp_json3 = "{\"txid\":\"6655abb87632ba0730ff5c4e3280a063cc7984be43d89c8e19d766996ff3d307\",\"hash\":\"6655abb87632ba0730ff5c4e3280a063cc7984be43d89c8e19d766996ff3d307\",\"version\":2,\"size\":94,\"vsize\":94,\"weight\":376,\"locktime\":0,\"vin\":[{\"txid\":\"ea9d5a9e974af1d167305aa6ee598706d63274e8a40f4f33af97db37a7adde4c\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":1,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 1863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262\",\"hex\":\"00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"bcrt1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qzf4jry\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "DecodeRawTransaction", request_json3, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json3, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodeRawTransaction taproot send
  const char* request_json4 = "{\"hex\":\"02000000000101ffa8db90b81db256874ff7a98fb7202cdc0b91b5b02d7c3427c4190adc66981f0000000000ffffffff0118f50295000000002251201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb02473044022018b10265080f8c491c43595000461a19212239fea9ee4c6fd26498f358b1760d0220223c1389ac26a2ed5f77ad73240af2fa6eb30ef5d19520026c2f7b7e817592530121023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c4400000000\",\"network\":\"regtest\"}";
  const char* exp_json4 = "{\"txid\":\"2fea883042440d030ca5929814ead927075a8f52fef5f4720fa3cec2e475d916\",\"hash\":\"d95071dc758c623d7f2d91178f8b8ce1ee8272131ffedf510595fc4abe2960ad\",\"version\":2,\"size\":203,\"vsize\":122,\"weight\":485,\"locktime\":0,\"vin\":[{\"txid\":\"1f9866dc0a19c427347c2db0b5910bdc2c20b78fa9f74f8756b21db890dba8ff\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"txinwitness\":[\"3044022018b10265080f8c491c43595000461a19212239fea9ee4c6fd26498f358b1760d0220223c1389ac26a2ed5f77ad73240af2fa6eb30ef5d19520026c2f7b7e8175925301\",\"023179b32721d07deb06cade59f56dedefdc932e89fde56e998f7a0e93a3e30c44\"],\"sequence\":4294967295}],\"vout\":[{\"value\":2499999000,\"n\":0,\"scriptPubKey\":{\"asm\":\"1 1777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb\",\"hex\":\"51201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb\",\"reqSigs\":1,\"type\":\"witness_v1_taproot\",\"addresses\":[\"bcrt1pzamhq9jglfxaj0r5ahvatr8uc77u973s5tm04yytdltsey5r8nasmsdlvq\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "DecodeRawTransaction", request_json4, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json4, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodeRawTransaction tapscript
  const char* request_json5 = "{\"hex\":\"020000000001015b80a1af0e00c700bee9c8e4442bec933fcdc0c686dac2dc336caaaf186c5d190000000000ffffffff0130f1029500000000160014164e985d0fc92c927a66c0cbaf78e6ea389629d50341f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee90122201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac61c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d5400000000\",\"network\":\"regtest\"}";
  const char* exp_json5 = "{\"txid\":\"e4810312b04fcd7178f04153c08e9f065dbc3a2fcc27db77e76e4347d243f725\",\"hash\":\"dc8767a20b972967c1652436258500772fe93f5e0eae108fbb0a38c30e731c36\",\"version\":2,\"size\":284,\"vsize\":133,\"weight\":530,\"locktime\":0,\"vin\":[{\"txid\":\"195d6c18afaa6c33dcc2da86c6c0cd3f93ec2b44e4c8e9be00c7000eafa1805b\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"txinwitness\":[\"f5aa6b260f9df687786cd3813ba83b476e195041bccea800f2571212f4aae9848a538b6175a4f8ea291d38e351ea7f612a3d700dca63cd3aff05d315c5698ee901\",\"201777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfbac\",\"c01777701648fa4dd93c74edd9d58cfcc7bdc2fa30a2f6fa908b6fd70c92833cfb4d18084bb47027f47d428b2ed67e1ccace5520fdc36f308e272394e288d53b6ddc82121e4ff8d23745f3859e8939ecb0a38af63e6ddea2fff97a7fd61a1d2d54\"],\"sequence\":4294967295}],\"vout\":[{\"value\":2499998000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 164e985d0fc92c927a66c0cbaf78e6ea389629d5\",\"hex\":\"0014164e985d0fc92c927a66c0cbaf78e6ea389629d5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bcrt1qze8fshg0eykfy7nxcr96778xagufv2w429wx40\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "DecodeRawTransaction", request_json5, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json5, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdRequestExecuteJson_decodepsbt) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));
  char* respons_json = nullptr;

  // DecodePsbt multiple input and output.
  const char* request_json1 = "{\"psbt\":\"cHNidP8BAJoCAAAAAiZ//Xbq5rbBP/uGzquqJNQkhVICM8LDgF4K12RwlXjAAQAAAAD/////fSVGKkL/LLG6VAHliTJZ2zykvPXParlxXTUWPTHJ7MAAAAAAAP////8CAOH1BQAAAAAWABSzIr3c5jO4UaxzcKtFTws2egZU5QDh9QUAAAAAFgAUyrjFOm6PwCltHNORWjB9UcSRpVUAAAAAAAEA9gIAAAAAAQHxmT/o5xiVQu5FBiWOFwIBviknA80nWssJ7OFmcv2EiwAAAAAXFgAUrJ74CyevHJ2VwdtddhMZMivEL8X/////AggEECQBAAAAFgAUCd4qBDHLs0RPwiytnZoP0JY5chAA4fUFAAAAABepFFCfWYX06QoU+5Djkxb9tPOsl1MHhwJHMEQCIB4H33IcMyJBno820H7q5HlZdboNnRljDKPNPcDUlnFyAiAVQo574GtlZ1AVOQUL15GjgPALvdvFCX6pe6e+QBcRSgEhAkrvQ7HVrHulAUmY1jzqxYOVnR/cZuommc2E7q+CooMGAAAAAAEBIADh9QUAAAAAF6kUUJ9ZhfTpChT7kOOTFv2086yXUweHAQcXFgAUlixOCPM206+8NBXJ01muEEBHBSABCGsCRzBEAiApmGKmeptFTWzaX+40pS2Qib+gJERNiAMcNKmOKYvbygIgS0f89Qe4CVQQjgN1Zz/b3QhMX7uZT2yVFyDy6y9ruGYBIQJWUkhGCzwYbezxPbBvByT9ULR8w+SJwwB2yDY9UDjO/gABAL8CAAAAAcbS6jbi6AK1LdrGZdrL7S+DG1JjRZ4cpzT1yUXXUV5AAAAAAGpHMEQCIBG5bH0tDS6NyzcTjhisxGB1KWWt2cuHh99cNJ3w4q5mAiAuk68xtk9RZuVgWBlVXavsV755QwD62zcFLzHd3qmQXAEhA+PSRKOWfguHdl/ahsX/OIhfdJk5U7lYQ4iu8wsmr2rs/////wF4Uc0dAAAAABl2qRSNIEQ6kZaeO8oOJAzQ/+TcmMY94oisAAAAAAEHakcwRAIgZuyVbpZ4PNYSLJwHcyo66ZMbaava/x82LCjtX6lnKNMCIGoW1K5G/tSNPQSSc3YTvZtR/j4kU7REbkR8Zb8sln4QASEC2faIjyhaFaahiAoiAsKyMKQtd89i2mpIrKQZgmLNo8cAIgIDRzv8jHcMGyIKLnquS632wNfq8pAo1bKdNDgBK7KJ74EYKnBHYCwAAIAAAACAAAAAgAAAAAACAAAAACICA2R0r/JjPDUYZVOftStiudb7nk4jV2Yo4fCgp5k0WOBsGJ1rbYYsAACAAAAAgAAAAIAAAAAAAgAAAAA=\"}";
  const char* exp_json1 = "{\"tx\":{\"txid\":\"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5\",\"hash\":\"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5\",\"version\":2,\"size\":154,\"vsize\":154,\"weight\":616,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":100000000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 b322bddce633b851ac7370ab454f0b367a0654e5\",\"hex\":\"0014b322bddce633b851ac7370ab454f0b367a0654e5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"hex\":\"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p\"]}}]},\"unknown\":[],\"inputs\":[{\"non_witness_utxo\":{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"hash\":\"9cb67d0ba945c8da2342429e19b12e11852e3a032144ca908996ff46f05dd906\",\"version\":2,\"size\":246,\"vsize\":165,\"weight\":657,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1\",\"vout\":0,\"scriptSig\":{\"asm\":\"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\",\"hex\":\"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\"},\"txinwitness\":[\"304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01\",\"024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306\"],\"sequence\":4294967295}],\"vout\":[{\"value\":100000000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 b322bddce633b851ac7370ab454f0b367a0654e5\",\"hex\":\"0014b322bddce633b851ac7370ab454f0b367a0654e5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"hex\":\"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p\"]}},{\"value\":4899996680,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 09de2a0431cbb3444fc22cad9d9a0fd096397210\",\"hex\":\"001409de2a0431cbb3444fc22cad9d9a0fd096397210\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qp80z5pp3ewe5gn7z9jkemxs06ztrjusscl4mx0\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm\"]}}]},\"witness_utxo\":{\"amount\":100000000,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"type\":\"scripthash\",\"address\":\"393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm\"}},\"final_scriptsig\":{\"asm\":\"0014962c4e08f336d3afbc3415c9d359ae1040470520\",\"hex\":\"160014962c4e08f336d3afbc3415c9d359ae1040470520\"},\"final_scriptwitness\":[\"30440220299862a67a9b454d6cda5fee34a52d9089bfa024444d88031c34a98e298bdbca02204b47fcf507b80954108e0375673fdbdd084c5fbb994f6c951720f2eb2f6bb86601\",\"02565248460b3c186decf13db06f0724fd50b47cc3e489c30076c8363d5038cefe\"]},{\"non_witness_utxo\":{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"hash\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"version\":2,\"size\":191,\"vsize\":191,\"weight\":764,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1\",\"vout\":0,\"scriptSig\":{\"asm\":\"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\",\"hex\":\"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\"},\"txinwitness\":[\"304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01\",\"024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306\"],\"sequence\":4294967295},{\"txid\":\"405e51d745c9f534a71c9e4563521b832fedcbda65c6da2db502e8e236ead2c6\",\"vout\":0,\"scriptSig\":{\"asm\":\"3044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c01 03e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec\",\"hex\":\"473044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c012103e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec\"},\"sequence\":4294967295}],\"vout\":[{\"value\":100000000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 b322bddce633b851ac7370ab454f0b367a0654e5\",\"hex\":\"0014b322bddce633b851ac7370ab454f0b367a0654e5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qkv3tmh8xxwu9rtrnwz452nctxeaqv489dcscvw\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"hex\":\"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24f5qa8p\"]}},{\"value\":4899996680,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 09de2a0431cbb3444fc22cad9d9a0fd096397210\",\"hex\":\"001409de2a0431cbb3444fc22cad9d9a0fd096397210\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"bc1qp80z5pp3ewe5gn7z9jkemxs06ztrjusscl4mx0\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"393JshdyfRGe4Z4zvjvYYFPSUbrFvJy5tm\"]}},{\"value\":499995000,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 8d20443a91969e3bca0e240cd0ffe4dc98c63de2 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a9148d20443a91969e3bca0e240cd0ffe4dc98c63de288ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"1DsCvxydk2JqbEj1EqL6mXcEvStsKQvKbx\"]}}]},\"final_scriptsig\":{\"asm\":\"3044022066ec956e96783cd6122c9c07732a3ae9931b69abdaff1f362c28ed5fa96728d302206a16d4ae46fed48d3d0492737613bd9b51fe3e2453b4446e447c65bf2c967e1001 02d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7\",\"hex\":\"473044022066ec956e96783cd6122c9c07732a3ae9931b69abdaff1f362c28ed5fa96728d302206a16d4ae46fed48d3d0492737613bd9b51fe3e2453b4446e447c65bf2c967e10012102d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7\"}}],\"outputs\":[{\"bip32_derivs\":[{\"pubkey\":\"03473bfc8c770c1b220a2e7aae4badf6c0d7eaf29028d5b29d3438012bb289ef81\",\"master_fingerprint\":\"2a704760\",\"path\":\"44'/0'/0'/0/2\"}]},{\"bip32_derivs\":[{\"pubkey\":\"036474aff2633c351865539fb52b62b9d6fb9e4e23576628e1f0a0a7993458e06c\",\"master_fingerprint\":\"9d6b6d86\",\"path\":\"44'/0'/0'/0/2\"}]}],\"fee\":399995000}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json1, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json1, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt2 multiple input and output.
  const char* request_json2 = "{\"psbt\":\"cHNidP8BAF4CAAAAAWkv08JB0xYYGWvDa23k9riJEU5CDpvd+cu+Ux5aVE1UAAAAAAD/////ARBLzR0AAAAAIgAgPK0GGd5n5iR6dqECgTY1wFNFfGuk/eSsH/2BSNcOS8wAAAAAAAEBIAhYzR0AAAAAF6kUlF+1A5GnBjfB/8Wrf7ZTCMLyMXWHIgIDpRL19ZwOeQH8R47WNT7vdvRPnLLBhb+89/C5u3Zxa/NHMEQCICBjWTfgUXDYPcMhOts6bq5mcTAI5KvDi0kSxWgN7E8MAiAzwIpxowdXsIRj1TDsBY7XQBlo+zC+9j1FSXIaDkhbhAEiAgP01HNhTpVKxPVRjm98szB7T4R0PhN+1O7LX0+2Q8I7R0cwRAIgXSdKeIfePvrehKSjScTDb1ibVWI7ECe32m2sicF4VjQCIGoDr+u7tgifHjf6yPmZpAFRYciSAUT9UxEtoFgEzUPMAQEDBAEAAAABBCIAIJxNrLJeu4rai7sa3bhp3qTYFwzJUfHZaUshVOFYMnbJAQVHUiEDpRL19ZwOeQH8R47WNT7vdvRPnLLBhb+89/C5u3Zxa/MhA/TUc2FOlUrE9VGOb3yzMHtPhHQ+E37U7stfT7ZDwjtHUq4iBgOlEvX1nA55AfxHjtY1Pu929E+cssGFv7z38Lm7dnFr8xgqcEdgLAAAgAAAAIAAAACAAAAAAAsAAAAiBgP01HNhTpVKxPVRjm98szB7T4R0PhN+1O7LX0+2Q8I7Rxida22GLAAAgAAAAIAAAACAAAAAAAsAAAAAAQAiACA8rQYZ3mfmJHp2oQKBNjXAU0V8a6T95Kwf/YFI1w5LzAEBR1IhApBtOZ9tu+zImNS43j9JdHTIakHyzzbXH5XlygawdIZ7IQJiLHl07DLeda+jczsJpsM9DepRSyn6rM+wmRd09GIiQlKuIgICYix5dOwy3nWvo3M7CabDPQ3qUUsp+qzPsJkXdPRiIkIYnWtthiwAAIAAAACAAAAAgAAAAAAMAAAAIgICkG05n2277MiY1LjeP0l0dMhqQfLPNtcfleXKBrB0hnsYKnBHYCwAAIAAAACAAAAAgAAAAAAMAAAAAA==\",\"network\":\"testnet\"}";
  const char* exp_json2 = "{\"tx\":{\"txid\":\"4fca1d22793c84025ac994fe144b6840db376fcc50fe87ed98f60cd5717143df\",\"hash\":\"4fca1d22793c84025ac994fe144b6840db376fcc50fe87ed98f60cd5717143df\",\"version\":2,\"size\":94,\"vsize\":94,\"weight\":376,\"locktime\":0,\"vin\":[{\"txid\":\"544d545a1e53becbf9dd9b0e424e1189b8f6e46d6bc36b191816d341c2d32f69\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":499993360,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 3cad0619de67e6247a76a102813635c053457c6ba4fde4ac1ffd8148d70e4bcc\",\"hex\":\"00203cad0619de67e6247a76a102813635c053457c6ba4fde4ac1ffd8148d70e4bcc\",\"reqSigs\":1,\"type\":\"witness_v0_scripthash\",\"addresses\":[\"tb1q8jksvxw7vlnzg7nk5ypgzd34cpf52lrt5n77ftqllkq534cwf0xqjsj24p\"]}}]},\"unknown\":[],\"inputs\":[{\"witness_utxo\":{\"amount\":499996680,\"scriptPubKey\":{\"asm\":\"OP_HASH160 945fb50391a70637c1ffc5ab7fb65308c2f23175 OP_EQUAL\",\"hex\":\"a914945fb50391a70637c1ffc5ab7fb65308c2f2317587\",\"type\":\"scripthash\",\"address\":\"2N6mkeX6gvq65nySsWmQUqacjfnH9HV2ufY\"}},\"partial_signatures\":[{\"pubkey\":\"03a512f5f59c0e7901fc478ed6353eef76f44f9cb2c185bfbcf7f0b9bb76716bf3\",\"signature\":\"3044022020635937e05170d83dc3213adb3a6eae66713008e4abc38b4912c5680dec4f0c022033c08a71a30757b08463d530ec058ed7401968fb30bef63d4549721a0e485b8401\"},{\"pubkey\":\"03f4d473614e954ac4f5518e6f7cb3307b4f84743e137ed4eecb5f4fb643c23b47\",\"signature\":\"304402205d274a7887de3efade84a4a349c4c36f589b55623b1027b7da6dac89c178563402206a03afebbbb6089f1e37fac8f999a4015161c8920144fd53112da05804cd43cc01\"}],\"sighash\":\"ALL\",\"redeem_script\":{\"asm\":\"0 9c4dacb25ebb8ada8bbb1addb869dea4d8170cc951f1d9694b2154e1583276c9\",\"hex\":\"00209c4dacb25ebb8ada8bbb1addb869dea4d8170cc951f1d9694b2154e1583276c9\",\"type\":\"witness_v0_scripthash\"},\"witness_script\":{\"asm\":\"2 03a512f5f59c0e7901fc478ed6353eef76f44f9cb2c185bfbcf7f0b9bb76716bf3 03f4d473614e954ac4f5518e6f7cb3307b4f84743e137ed4eecb5f4fb643c23b47 2 OP_CHECKMULTISIG\",\"hex\":\"522103a512f5f59c0e7901fc478ed6353eef76f44f9cb2c185bfbcf7f0b9bb76716bf32103f4d473614e954ac4f5518e6f7cb3307b4f84743e137ed4eecb5f4fb643c23b4752ae\",\"type\":\"multisig\"},\"bip32_derivs\":[{\"pubkey\":\"03a512f5f59c0e7901fc478ed6353eef76f44f9cb2c185bfbcf7f0b9bb76716bf3\",\"master_fingerprint\":\"2a704760\",\"path\":\"44'/0'/0'/0/11\"},{\"pubkey\":\"03f4d473614e954ac4f5518e6f7cb3307b4f84743e137ed4eecb5f4fb643c23b47\",\"master_fingerprint\":\"9d6b6d86\",\"path\":\"44'/0'/0'/0/11\"}]}],\"outputs\":[{\"witness_script\":{\"asm\":\"2 02906d399f6dbbecc898d4b8de3f497474c86a41f2cf36d71f95e5ca06b074867b 02622c7974ec32de75afa3733b09a6c33d0dea514b29faaccfb0991774f4622242 2 OP_CHECKMULTISIG\",\"hex\":\"522102906d399f6dbbecc898d4b8de3f497474c86a41f2cf36d71f95e5ca06b074867b2102622c7974ec32de75afa3733b09a6c33d0dea514b29faaccfb0991774f462224252ae\",\"type\":\"\"},\"bip32_derivs\":[{\"pubkey\":\"02622c7974ec32de75afa3733b09a6c33d0dea514b29faaccfb0991774f4622242\",\"master_fingerprint\":\"9d6b6d86\",\"path\":\"44'/0'/0'/0/12\"},{\"pubkey\":\"02906d399f6dbbecc898d4b8de3f497474c86a41f2cf36d71f95e5ca06b074867b\",\"master_fingerprint\":\"2a704760\",\"path\":\"44'/0'/0'/0/12\"}]}],\"fee\":3320}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json2, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json2, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt3
  const char* request_json3 = "{\"psbt\":\"cHNidP8BAD8CAAAAAf//////////////////////////////////////////AAAAAAD/////AQAAAAAAAAAAA2oBAAAAAAAKDwECAwQFBgcICQ8BAgMEBQYHCAkKCwwNDg8ACg8BAgMEBQYHCAkPAQIDBAUGBwgJCgsMDQ4PAAoPAQIDBAUGBwgJDwECAwQFBgcICQoLDA0ODwA=\",\"network\":\"testnet\"}";
  const char* exp_json3 = "{\"tx\":{\"txid\":\"75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115\",\"hash\":\"75c5c9665a570569ad77dd1279e6fd4628a093c4dcbf8d41532614044c14c115\",\"version\":2,\"size\":63,\"vsize\":63,\"weight\":252,\"locktime\":0,\"vin\":[{\"txid\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":0,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_RETURN 0\",\"hex\":\"6a0100\",\"type\":\"nulldata\"}}]},\"unknown\":[{\"key\":\"0f010203040506070809\",\"value\":\"0102030405060708090a0b0c0d0e0f\"}],\"inputs\":[{\"unknown\":[{\"key\":\"0f010203040506070809\",\"value\":\"0102030405060708090a0b0c0d0e0f\"}]}],\"outputs\":[{\"unknown\":[{\"key\":\"0f010203040506070809\",\"value\":\"0102030405060708090a0b0c0d0e0f\"}]}]}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json3, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json3, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt4
  const char* request_json4 = "{\"psbt\":\"cHNidP8BAFUCAAAAASeaIyOl37UfxF8iD6WLD8E+HjNCeSqF1+Ns1jM7XLw5AAAAAAD/////AaBa6gsAAAAAGXapFP/pwAYQl8w7Y28ssEYPpPxCfStFiKwAAAAAAAEBIJVe6gsAAAAAF6kUY0UgD2jRieGtwN8cTRbqjxTA2+uHIgIDsTQcy6doO2r08SOM1ul+cWfVafrEfx5I1HVBhENVvUZGMEMCIAQktY7/qqaU4VWepck7v9SokGQiQFXN8HC2dxRpRC0HAh9cjrD+plFtYLisszrWTt5g6Hhb+zqpS5m9+GFR25qaAQEEIgAgdx/RitRZZm3Unz1WTj28QvTIR3TjYK2haBao7UiNVoEBBUdSIQOxNBzLp2g7avTxI4zW6X5xZ9Vp+sR/HkjUdUGEQ1W9RiED3lXR4drIBeP4pYwfv5uUwC89uq/hJ/78pJlfJvggg71SriIGA7E0HMunaDtq9PEjjNbpfnFn1Wn6xH8eSNR1QYRDVb1GELSmumcAAACAAAAAgAQAAIAiBgPeVdHh2sgF4/iljB+/m5TALz26r+En/vykmV8m+CCDvRC0prpnAAAAgAAAAIAFAACAAAA=\",\"network\":\"testnet\"}";
  const char* exp_json4 = "{\"tx\":{\"txid\":\"b4ca8f48572bf08354f8302adfbd9e5c2fc2a52731de5401a39aa048f68c9c21\",\"hash\":\"b4ca8f48572bf08354f8302adfbd9e5c2fc2a52731de5401a39aa048f68c9c21\",\"version\":2,\"size\":85,\"vsize\":85,\"weight\":340,\"locktime\":0,\"vin\":[{\"txid\":\"39bc5c3b33d66ce3d7852a7942331e3ec10f8ba50f225fc41fb5dfa523239a27\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":199908000,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 ffe9c0061097cc3b636f2cb0460fa4fc427d2b45 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a914ffe9c0061097cc3b636f2cb0460fa4fc427d2b4588ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"n4r6dDFCuGSZ1yQwxTJW3be3QFsoziJp3z\"]}}]},\"unknown\":[],\"inputs\":[{\"witness_utxo\":{\"amount\":199909013,\"scriptPubKey\":{\"asm\":\"OP_HASH160 6345200f68d189e1adc0df1c4d16ea8f14c0dbeb OP_EQUAL\",\"hex\":\"a9146345200f68d189e1adc0df1c4d16ea8f14c0dbeb87\",\"type\":\"scripthash\",\"address\":\"2N2J7hBS8e4eLE4sNVjJGF1eHuZoYdELe8g\"}},\"partial_signatures\":[{\"pubkey\":\"03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46\",\"signature\":\"304302200424b58effaaa694e1559ea5c93bbfd4a89064224055cdf070b6771469442d07021f5c8eb0fea6516d60b8acb33ad64ede60e8785bfb3aa94b99bdf86151db9a9a01\"}],\"redeem_script\":{\"asm\":\"0 771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681\",\"hex\":\"0020771fd18ad459666dd49f3d564e3dbc42f4c84774e360ada16816a8ed488d5681\",\"type\":\"witness_v0_scripthash\"},\"witness_script\":{\"asm\":\"2 03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46 03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd 2 OP_CHECKMULTISIG\",\"hex\":\"522103b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd462103de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd52ae\",\"type\":\"multisig\"},\"bip32_derivs\":[{\"pubkey\":\"03b1341ccba7683b6af4f1238cd6e97e7167d569fac47f1e48d47541844355bd46\",\"master_fingerprint\":\"b4a6ba67\",\"path\":\"0'/0'/4'\"},{\"pubkey\":\"03de55d1e1dac805e3f8a58c1fbf9b94c02f3dbaafe127fefca4995f26f82083bd\",\"master_fingerprint\":\"b4a6ba67\",\"path\":\"0'/0'/5'\"}]}],\"outputs\":[{}],\"fee\":1013}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json4, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json4, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt5
  const char* request_json5 = "{\"psbt\":\"cHNidP8BAJoCAAAAAiZ//Xbq5rbBP/uGzquqJNQkhVICM8LDgF4K12RwlXjAAQAAAAD/////fSVGKkL/LLG6VAHliTJZ2zykvPXParlxXTUWPTHJ7MAAAAAAAP////8CAOH1BQAAAAAWABSzIr3c5jO4UaxzcKtFTws2egZU5QDh9QUAAAAAFgAUyrjFOm6PwCltHNORWjB9UcSRpVUAAAAADfwDY2ZkAAZkdW1teTEEAQIDBA38A2NmZAAGZHVtbXkyAQAAAAAAAA==\",\"network\":\"testnet\"}";
  const char* exp_json5 = "{\"tx\":{\"txid\":\"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5\",\"hash\":\"f2bd9cccedc37e91a8b10e8034eefc49b901afa6220833097a31ed91772d81a5\",\"version\":2,\"size\":154,\"vsize\":154,\"weight\":616,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[{\"value\":100000000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 b322bddce633b851ac7370ab454f0b367a0654e5\",\"hex\":\"0014b322bddce633b851ac7370ab454f0b367a0654e5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qkv3tmh8xxwu9rtrnwz452nctxeaqv48987ttha\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"hex\":\"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24rjmwuj\"]}}]},\"unknown\":[{\"key\":\"fc03636664000664756d6d7931\",\"value\":\"01020304\"},{\"key\":\"fc03636664000664756d6d7932\",\"value\":\"00\"}],\"inputs\":[{},{}],\"outputs\":[{},{}]}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json5, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json5, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt6
  const char* request_json6 = "{\"psbt\":\"cHNidP8BAEgCAAAAAAIA4fUFAAAAABYAFLMivdzmM7hRrHNwq0VPCzZ6BlTlAOH1BQAAAAAWABTKuMU6bo/AKW0c05FaMH1RxJGlVQAAAAAAIgIDRzv8jHcMGyIKLnquS632wNfq8pAo1bKdNDgBK7KJ74EYKnBHYCwAAIAAAACAAAAAgAAAAAACAAAADfwDY2ZkAAZkdW1teTEEAQIDBA38A2NmZAAGZHVtbXkyAQAAIgIDZHSv8mM8NRhlU5+1K2K51vueTiNXZijh8KCnmTRY4GwYnWtthiwAAIAAAACAAAAAgAAAAAACAAAAAA==\",\"network\":\"testnet\"}";
  const char* exp_json6 = "{\"tx\":{\"txid\":\"772e587ed2406fa46800082714af39c6a0393eaab8b4c977aff22aa052dbdac0\",\"hash\":\"772e587ed2406fa46800082714af39c6a0393eaab8b4c977aff22aa052dbdac0\",\"version\":2,\"size\":72,\"vsize\":72,\"weight\":288,\"locktime\":0,\"vin\":[],\"vout\":[{\"value\":100000000,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 b322bddce633b851ac7370ab454f0b367a0654e5\",\"hex\":\"0014b322bddce633b851ac7370ab454f0b367a0654e5\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qkv3tmh8xxwu9rtrnwz452nctxeaqv48987ttha\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"0 cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"hex\":\"0014cab8c53a6e8fc0296d1cd3915a307d51c491a555\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qe2uv2wnw3lqzjmgu6wg45vra28zfrf24rjmwuj\"]}}]},\"unknown\":[],\"inputs\":[],\"outputs\":[{\"bip32_derivs\":[{\"pubkey\":\"03473bfc8c770c1b220a2e7aae4badf6c0d7eaf29028d5b29d3438012bb289ef81\",\"master_fingerprint\":\"2a704760\",\"path\":\"44'/0'/0'/0/2\"}],\"unknown\":[{\"key\":\"fc03636664000664756d6d7931\",\"value\":\"01020304\"},{\"key\":\"fc03636664000664756d6d7932\",\"value\":\"00\"}]},{\"bip32_derivs\":[{\"pubkey\":\"036474aff2633c351865539fb52b62b9d6fb9e4e23576628e1f0a0a7993458e06c\",\"master_fingerprint\":\"9d6b6d86\",\"path\":\"44'/0'/0'/0/2\"}]}]}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json6, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json6, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // DecodePsbt7
  const char* request_json7 = "{\"psbt\":\"cHNidP8BAFwCAAAAAiZ//Xbq5rbBP/uGzquqJNQkhVICM8LDgF4K12RwlXjAAQAAAAD/////fSVGKkL/LLG6VAHliTJZ2zykvPXParlxXTUWPTHJ7MAAAAAAAP////8AAAAAAAABAPYCAAAAAAEB8Zk/6OcYlULuRQYljhcCAb4pJwPNJ1rLCezhZnL9hIsAAAAAFxYAFKye+AsnrxydlcHbXXYTGTIrxC/F/////wIIBBAkAQAAABYAFAneKgQxy7NET8IsrZ2aD9CWOXIQAOH1BQAAAAAXqRRQn1mF9OkKFPuQ45MW/bTzrJdTB4cCRzBEAiAeB99yHDMiQZ6PNtB+6uR5WXW6DZ0ZYwyjzT3A1JZxcgIgFUKOe+BrZWdQFTkFC9eRo4DwC73bxQl+qXunvkAXEUoBIQJK70Ox1ax7pQFJmNY86sWDlZ0f3GbqJpnNhO6vgqKDBgAAAAABASAA4fUFAAAAABepFFCfWYX06QoU+5Djkxb9tPOsl1MHhwEDBAEAAAABBBYAFJYsTgjzNtOvvDQVydNZrhBARwUgIgYCVlJIRgs8GG3s8T2wbwck/VC0fMPkicMAdsg2PVA4zv4YKnBHYCwAAIAAAACAAAAAgAEAAAABAAAADfwDY2ZkAAZkdW1teTEEAQIDBA38A2NmZAAGZHVtbXkyAQAAAQC/AgAAAAHG0uo24ugCtS3axmXay+0vgxtSY0WeHKc09clF11FeQAAAAABqRzBEAiARuWx9LQ0ujcs3E44YrMRgdSllrdnLh4ffXDSd8OKuZgIgLpOvMbZPUWblYFgZVV2r7Fe+eUMA+ts3BS8x3d6pkFwBIQPj0kSjln4Lh3Zf2obF/ziIX3SZOVO5WEOIrvMLJq9q7P////8BeFHNHQAAAAAZdqkUjSBEOpGWnjvKDiQM0P/k3JjGPeKIrAAAAAAiBgLZ9oiPKFoVpqGICiICwrIwpC13z2LaakispBmCYs2jxxida22GLAAAgAAAAIAAAACAAAAAAAEAAAAA\",\"network\":\"testnet\"}";
  const char* exp_json7 = "{\"tx\":{\"txid\":\"6014abba7b6cef826488bdd44ce3269616cbfa37bf8e832d9e7703cf144ce646\",\"hash\":\"6014abba7b6cef826488bdd44ce3269616cbfa37bf8e832d9e7703cf144ce646\",\"version\":2,\"size\":92,\"vsize\":92,\"weight\":368,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295}],\"vout\":[]},\"unknown\":[],\"inputs\":[{\"non_witness_utxo\":{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"hash\":\"9cb67d0ba945c8da2342429e19b12e11852e3a032144ca908996ff46f05dd906\",\"version\":2,\"size\":246,\"vsize\":165,\"weight\":657,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1\",\"vout\":0,\"scriptSig\":{\"asm\":\"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\",\"hex\":\"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\"},\"txinwitness\":[\"304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01\",\"024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306\"],\"sequence\":4294967295}],\"vout\":[{\"value\":4899996680,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 09de2a0431cbb3444fc22cad9d9a0fd096397210\",\"hex\":\"001409de2a0431cbb3444fc22cad9d9a0fd096397210\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qp80z5pp3ewe5gn7z9jkemxs06ztrjussjewgau\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"2MzbWwSa1GsmzGLhYbsYRACNhgx4RjqGtTi\"]}}]},\"witness_utxo\":{\"amount\":100000000,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"type\":\"scripthash\",\"address\":\"2MzbWwSa1GsmzGLhYbsYRACNhgx4RjqGtTi\"}},\"sighash\":\"ALL\",\"redeem_script\":{\"asm\":\"0 962c4e08f336d3afbc3415c9d359ae1040470520\",\"hex\":\"0014962c4e08f336d3afbc3415c9d359ae1040470520\",\"type\":\"witness_v0_keyhash\"},\"bip32_derivs\":[{\"pubkey\":\"02565248460b3c186decf13db06f0724fd50b47cc3e489c30076c8363d5038cefe\",\"master_fingerprint\":\"2a704760\",\"path\":\"44'/0'/0'/1/1\"}],\"unknown\":[{\"key\":\"fc03636664000664756d6d7931\",\"value\":\"01020304\"},{\"key\":\"fc03636664000664756d6d7932\",\"value\":\"00\"}]},{\"non_witness_utxo\":{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"hash\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"version\":2,\"size\":191,\"vsize\":191,\"weight\":764,\"locktime\":0,\"vin\":[{\"txid\":\"c078957064d70a5e80c3c23302528524d424aaabce86fb3fc1b6e6ea76fd7f26\",\"vout\":1,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"c0ecc9313d16355d71b96acff5bca43cdb593289e50154bab12cff422a46257d\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"sequence\":4294967295},{\"txid\":\"8b84fd7266e1ec09cb5a27cd032729be0102178e250645ee429518e7e83f99f1\",\"vout\":0,\"scriptSig\":{\"asm\":\"0014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\",\"hex\":\"160014ac9ef80b27af1c9d95c1db5d761319322bc42fc5\"},\"txinwitness\":[\"304402201e07df721c3322419e8f36d07eeae4795975ba0d9d19630ca3cd3dc0d4967172022015428e7be06b6567501539050bd791a380f00bbddbc5097ea97ba7be4017114a01\",\"024aef43b1d5ac7ba5014998d63ceac583959d1fdc66ea2699cd84eeaf82a28306\"],\"sequence\":4294967295},{\"txid\":\"405e51d745c9f534a71c9e4563521b832fedcbda65c6da2db502e8e236ead2c6\",\"vout\":0,\"scriptSig\":{\"asm\":\"3044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c01 03e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec\",\"hex\":\"473044022011b96c7d2d0d2e8dcb37138e18acc460752965add9cb8787df5c349df0e2ae6602202e93af31b64f5166e5605819555dabec57be794300fadb37052f31dddea9905c012103e3d244a3967e0b87765fda86c5ff38885f74993953b9584388aef30b26af6aec\"},\"sequence\":4294967295}],\"vout\":[{\"value\":4899996680,\"n\":0,\"scriptPubKey\":{\"asm\":\"0 09de2a0431cbb3444fc22cad9d9a0fd096397210\",\"hex\":\"001409de2a0431cbb3444fc22cad9d9a0fd096397210\",\"reqSigs\":1,\"type\":\"witness_v0_keyhash\",\"addresses\":[\"tb1qp80z5pp3ewe5gn7z9jkemxs06ztrjussjewgau\"]}},{\"value\":100000000,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 509f5985f4e90a14fb90e39316fdb4f3ac975307 OP_EQUAL\",\"hex\":\"a914509f5985f4e90a14fb90e39316fdb4f3ac97530787\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"2MzbWwSa1GsmzGLhYbsYRACNhgx4RjqGtTi\"]}},{\"value\":499995000,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 8d20443a91969e3bca0e240cd0ffe4dc98c63de2 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a9148d20443a91969e3bca0e240cd0ffe4dc98c63de288ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"mtPAE24cZ3k6NMCcxQJUbSpZnSVaCu96Wj\"]}}]},\"bip32_derivs\":[{\"pubkey\":\"02d9f6888f285a15a6a1880a2202c2b230a42d77cf62da6a48aca4198262cda3c7\",\"master_fingerprint\":\"9d6b6d86\",\"path\":\"44'/0'/0'/0/1\"}]}],\"outputs\":[],\"fee\":599995000}";
  ret = CfdRequestExecuteJson(handle, "DecodePsbt", request_json7, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json7, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  if (ret != kCfdSuccess) {
    char* str_buffer = nullptr;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("dummy_except", str_buffer);
      CfdFreeStringBuffer(str_buffer);
      str_buffer = nullptr;
    }
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

#ifndef CFD_DISABLE_ELEMENTS
TEST(cfdcapi_common, CfdRequestExecuteJson_elementsdecodetx) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));
  char* respons_json = nullptr;

  // 'ElementsDecodeRawTransaction Unblind Transaction liquidv1',
  const char* request_json1 = "{\"hex\":\"0200000000019775b8f73a45d84ef27d746401da5027082814e1d1b2f217f2232508043cd3b00000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000036a01000125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000014543ae60d002b9db456c4a2738cecfa7438280152663382a20355ef86c8756dc5349127f5d0417a914c69be2ffd44c43a3ed02e522e87844788fb29545870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000005adc000000000000\",\"network\":\"liquidv1\"}";
  const char* exp_json1 = "{\"txid\":\"d74c1bc2cbcd35be5a237cb661de73e1349d36f993ffd51c708d7f06394cb6c1\",\"hash\":\"d74c1bc2cbcd35be5a237cb661de73e1349d36f993ffd51c708d7f06394cb6c1\",\"wtxid\":\"d74c1bc2cbcd35be5a237cb661de73e1349d36f993ffd51c708d7f06394cb6c1\",\"withash\":\"ab3393f4fb64685a4de07ac89c6903d6a0ba107c87fff33c9a981a7590bae48e\",\"version\":2,\"size\":242,\"vsize\":242,\"weight\":968,\"locktime\":0,\"vin\":[{\"txid\":\"b0d33c04082523f217f2b2d1e11428082750da0164747df24ed8453af7b87597\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"is_pegin\":false,\"sequence\":4294967293}],\"vout\":[{\"value\":0,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_RETURN 0\",\"hex\":\"6a0100\",\"type\":\"nulldata\"}},{\"value\":1396999872720,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"02b9db456c4a2738cecfa7438280152663382a20355ef86c8756dc5349127f5d04\",\"commitmentnonce_fully_valid\":true,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 c69be2ffd44c43a3ed02e522e87844788fb29545 OP_EQUAL\",\"hex\":\"a914c69be2ffd44c43a3ed02e522e87844788fb2954587\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"H1HfwR9HBddihh5qBfxEHpkwxQ2DeRsXvF\"]}},{\"value\":23260,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":2,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}}]}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json1, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json1, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // 'ElementsDecodeRawTransaction Blinded Transaction',
  const char* request_json2 = "{\"hex\":\"0200000001019775b8f73a45d84ef27d746401da5027082814e1d1b2f217f2232508043cd3b00000000000fdffffff030125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000036a01000af4bdb96b14428d1f588236b67333bbabb49af2fc301ebdc4044b41024cb7cb7c088a6e672499c71ee4656eb12393f5fd24b6b9d6ccd934975f9109655e2101554603b92f14171b7011bad74bd9f791d4f9aebc1a0733c2e965c129f7d040f14fdc2b17a914c69be2ffd44c43a3ed02e522e87844788fb29545870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000000005adc000000000000000000000000430100015469da8a1cacbeaf026fa27f925093ed7f250919af2cb4f468f262ae98ba3092ea982cce6dd110a135d5bdb3b3ea8938ca7163eee45598c4ffc21952c518a855fded0c6028000000000000000180670e8624153a715d4fe312050485d8e8e6c343e0e64fe2613c05f08f37e9ecff8cdceec5cd256765611dfba18db7cc6937efc7eba1add855bfb27860909affcf07f7655aca81b18f6e73b318c2c3917d9d44bca01102f8c90e66a8785c2d75fb097b06c23680dc48cfcc53c1746e360d6c8a16d333f4a50c9deafa6e26e2dcacb17b42bfe0827d273c1bce96eb2a0472beccdc3d7a0784244b2a1ba98d2db0e025cb1bd5e332e43c3c0f8a252bb8e8585d6f8b4f96831fae9c03b004c14c700c52d09bcaa807f86eec54d9cf714a45c23cc7f75bbf81f9d9cc74f70aafa884bec698020377dbb169dc9862c4eb544536de51f4ec77389ee06cc7a82753382a8f8ccf23c67db10fc3776d0cfa743445256369fcdeb1be9eb99353e7b14ea277ffd02738b5930d9f0b7421f8c80e8b0a05cdd8e0ab5445e2f520f1e6ed44be390dd73931927a61d216f8713ae142a9aa36eb2f75ead0d32847be0713f9425d39a11b4973934f5f2e3927606f2650cccb1fdaaca06b33f5156bedf4a4fc172dde044b5a1194a61fc04200712d5e66f62548a3baf2f9834b4479eff317feef21295932e15f9816cae63d6491693a0476a18cc524f8530930c93d975c2b8e014fc7111b66f8e58164b6ce482bea204a65325f812f21b985261027263b9227c12bf8f3394e3e305d3ec5cf9dadbd62a4f7b075826265e7015e7ddcc7939ed1f74c70aac8f93bd72926dfd13a740cdf076862ee9699fe366bf8a398d17d94fdc56ac333d44dd2fe7462398339f3076ec14752ca96743e8a7e24736aa8c85304c0893a0783c26264c61b4797a061ca8b70b3a830c3b9ed9d11a15f1d37a95a29674c81549f44e6577b03aca70657c9504dce23da6429ee7fb91f5a81a43ecb07796acd38dd6b4cbc3bc13be133978acfa5db88d7e20f41da3c4ca756fa3b9341b399fa5d8dde912983396ab47cba2872a882df375d9e9fca1720ce072c61b600f2f6e2819106c4265b9b774303d0d4147d0b70feefeb74fa1cab4e978e1c90fab4b76225887dad677a36033f8a485ca71664dea79dda24565c60d693f0a65408ccfde8d8b6ec79adf6f36670c7cb66eee89a4c608767a0c863d39dd58b19b1905d4d19c6d5afd5c925490ad3af3e7494d1f74f616288c9f3a76f1f5a9740d41f054c311ed1934d7ea647b2de6a84a28d2d2eb03ba757952d507689174f629dc7637333dee5c3473100d0c19de9fe25295a9861ae24c9c0808c53315b77a4ed970bfdd4391c178f33d3812f82fda4798ba7c467b4e959308ceb7ba811a3aef8eb5b0dba23d0305be86d3cc3c9425a19445b3dd16b2a3561d4ab554ac60836883f13c0d5dabb6d8864feb8984fb83be824646db0edb6fc52b4db0be3c62aaaebf92db76a3802cd9bbc66f35701b11f5b19355a257bf157face4012b59e1b491997fc841153a0597b5023ca4a565ed0b3104c614ce0ffd024e1a746457db3d91045a672c383f9f6ecfd117c4b1b6337a12c5a93969283705aaa47d2849d00a1f630346dba6877bd5946e931906658a76eb867f5c3c1279452fd4f93089d2d70827fae9ecf2b5a17d029cbb9dddd85cfdf8c9378608651120b7eb2ce3e3191c64e18a194092dfb528b236474f4f7e3d01b46c8bac93371d2e80f7d487aa549b2ee05167b9cde6ca122a31701a36825627e330de85825152c06464b67800a67ea86b2eb71a462657b70691ceaa991b18fbfa3002bfb921c4a396e89c7dbfb1cf44810ce74a96f3f408e43e7322da1d94ae79259b6384828debb1a6d57e6ce4fd2f45c70ab68808d8ac0e8d234df54c5f5fac2a1da53a1a84deea5ce63c7efad4c65bff8f29e93d98fbe687cf500045bd96417eea4c7a5869fb440793e612d917d3e93dd5742ba04e382a9792600b72295bcfb3b1c7102f6bd6e580d22fc68f7cbe042c44897c97b8ad7f6fff8b0127169889c6b0190fa873c2805c2c8a0c20087f6a67fc04648b403132f3120aed71da852f9b9ae39c4d51703d32b8f5828f8f31d639e8a2957d048395ee9817ee01df53fb231344db9fb1cdd7b548fbb468898ba9c770d7a69244383c7c30b74e11fec834efcc1ad9861afaaa566bd03da73161e73df27ed8e9fb21318f0f717fdc14ff4b9f4695b4da60a7d095f101083542e0b078bd851a44e6b7ab7f5b99ecff02700cd8ddafbcc4d947bea6cb5c00a42513d3adf30cb230cf425c07ab019af4e47167adf62e035012227deb2a36f874a11652dba40530ec5a10153f0d1fa90d47b1dccb455c0bc2fbb6e65a2482a024b9752090f6d75a2ceac037a7421aa368b11309f399cc27449cc181a8f7ca142a206fdde81a117bf7a7c9557af04ce97d5b3b901a63b4bb683d8a6dff902a2b514520ccfb53b1624441e151b970710a59db70dd3e6ccd98293cbb65712c6f1d4b6a334ed0d87e91322d35fe67a721aa353615f1d11a4189eec37f25df5f92e8d26f87511c30d5188c12749b38418c721525d2780f7199eab1248b3825794371a70737dd8acd890ea370e316863a2e53fa7bef650583e004e2427266ab04133ceeeb6bbd2c9632d34376df1a98969d6dbfc90809aa43adb84ca7775719d993c870c4df625a72c8acb7321065f6bc0d718e61111a163eed11020b1f848178530ddac58e3c70af31600dbdff7f5d0c4180d07d983dea42553d6413648016db0e0ccaff0891a3bdaaf21713860ace4efc4784378b028ac2a8b6bceacc1cfcb713b2bcae326a4edc6c2eb8b7bf9e9603f3fbfbf9fe92d2dc2fcc60aceebc29fb47e73ccdc3c43a2cdab11b0c4cadba4d0fb675f02e623595ec8f8e245b755f2177e5d8e059143ce7fdec51b7ae121b3ac253c5c0674ccca0eebf3e1dcf142ea0177322d5f96cb65a12061a23228c25d31afb1f0c4c7844a0e9a8103196a0deccc8ab7c926f514d650bb0ca7877c7f8d4ea3f4512ffcf8681fb30a97e1ae72a712d3707bb581f1343f5afc1f3275c242912a95d4ba4da5bc7bbf651b3dd90dcd09952a9142d3c9fed5a17ed4b5e87f90dd6c61bc8fb877ad7b1dd4074b2939611403b6dda4cd26cc923110e593e01f83337767271329e849d29737ee3f78d74327ba4c6a97fedf793aad5fab9846dfb4c4466686161bef801c50661daf71cf4becf0c2eaa0cf704ddd23be629d45efdfacffadcd38730f22befc8a17edf063ace85b233b3fed93d75867f57219a955849efcdc8e0c2f39c1f41cf9aa72e41880c129ec4d915f65b5c1a3a0f172db50666ef8cd00812410684feff3f3f37eac35afd493d8f4faf52cffbd02cdf482d3f9e1e3207b788f99cd8e6ae346bd33b678bc4f593ff3bb47ecdb64ce2ed4cc7691d45163aca9b69f2a29b6513154f87131f0ca1b2a1812f3455c62226b3692eec9ea2a01268e744bdd448757e4531e52a811a2eb6071de4a9ec96f51d6ebf0ad5dc97b426941cb58dfaa1e131115bb37ca2a8d5ab9f941ed7947b9dbccaff1992f0f29eec89900c418bbe2c76e485808ab9c4ab33e66f98d46980fb13a28c5d3ed81a239089757087458a2122d71227d1e9fd8262060e1d49199d82599154bc9ed8b954a7bf3a18722b43ae67786ea63e0c5a706d0be175fd9a18a1096d9806b273f02870ce6fc8f287ebdd70e3679f8d00d3394798199b949f177112c9c082a4b3254342dc03d89d9ebc808bbdd1fee33c14366d2da0e10aff20f5c8b6a5c2e9ec8265557f29695494b3ea73471af458a4b32ca44b7bba1e0e4993035d1a431a496d75bcc90c0fe68490746599bf4a0895510ae32055924222a95a46636c60f6942229ed45b3334f675d343c61cec3ab526e98e9cda2f632c93fb3a914e28c08308c260045da8e7b09a6c2796138fc1dc54a382389ebf3ee2f9f404f89886c72fb3c4d05bf99b28977c733e050126b65b78558f456895b27266bac77ac116275e9e227dabbc8a68070df0d81061b2773c8606bdee8975dd01b9aa57a660ceb52fc56bcecf2529568339e42e7565eb3b6ac95fd8ed800b8efb5e9970d3b5f5cca8cc57538d2eddfa1ebc4d052a0f1ac2eb69ac167b2e5ebc6bc2434cabcfdfa2bd9c6eeab40f1d004486c13a7418bce53fe71b19c77d8f83502e2a9099c46f3436d17e914215ec3e98cc8d3c00559c5455c60766714f19ff1a61dd426c719d7e7fa4f7cbb6b99834730a7457b39d777c23f4c6dde68ca0ee947a4130a7646825ec7e81c4e8ca3185a1838a17965d4a0100ea95e105f99983c3826cd179d46755704df0be25059c59690030311ebaef7a7d9c1a661c0963a4838e99f7bf3887619560327e9f4bef78c22b2306a9e7218dc3eed7edbaa8223e17a7c491d644c4b76778aca575a0cb9771507f2156b547ea1ba89454221162096da101a7f5b62bff79c5c7283c7c02a93a8e644a22881765aad66eac73f551ea5ce55bdcf50768a4d4c0baebd24f37baa7b70402d539ae4bc7fe3d35704858960e7c3cf3abfcb4b59f5c512b507d9168ed6ebaa758732df93b631fb3ce89c3816ad834941086acd580f0ff987bc9382c939717b21a1abd1b62e6eff11ab25c7b0e01d61a1de877e98a16d78ceb39f7f09f8fdc75f9551054f40b61a27d4057c3fe9cb53eba0f09b7a599294aea1a54b8f141733b7f50c05a479d6fbce51e4d74ac0f308d422d0000\",\"network\":\"regtest\"}";
  const char* exp_json2 = "{\"txid\":\"5a20e7f1b610da13bf7e05ebd24c333194fa60351768f8bd0d7d5b5cc3dbaf64\",\"hash\":\"2c7a0aca62e5284f7982bb01bfe7d2a03a4c51e4b4e952519f001d50b1e3c555\",\"wtxid\":\"2c7a0aca62e5284f7982bb01bfe7d2a03a4c51e4b4e952519f001d50b1e3c555\",\"withash\":\"e13f9b22379c550010ae85bb64fb95096264fc61667f841155ec21d65543dc84\",\"version\":2,\"size\":3654,\"vsize\":1113,\"weight\":4452,\"locktime\":0,\"vin\":[{\"txid\":\"b0d33c04082523f217f2b2d1e11428082750da0164747df24ed8453af7b87597\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"is_pegin\":false,\"sequence\":4294967293}],\"vout\":[{\"value\":0,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_RETURN 0\",\"hex\":\"6a0100\",\"type\":\"nulldata\"}},{\"value-minimum\":1,\"value-maximum\":2199023255552,\"ct-exponent\":0,\"ct-bits\":41,\"surjectionproof\":\"0100015469da8a1cacbeaf026fa27f925093ed7f250919af2cb4f468f262ae98ba3092ea982cce6dd110a135d5bdb3b3ea8938ca7163eee45598c4ffc21952c518a855\",\"valuecommitment\":\"088a6e672499c71ee4656eb12393f5fd24b6b9d6ccd934975f9109655e21015546\",\"assetcommitment\":\"0af4bdb96b14428d1f588236b67333bbabb49af2fc301ebdc4044b41024cb7cb7c\",\"commitmentnonce\":\"03b92f14171b7011bad74bd9f791d4f9aebc1a0733c2e965c129f7d040f14fdc2b\",\"commitmentnonce_fully_valid\":true,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_HASH160 c69be2ffd44c43a3ed02e522e87844788fb29545 OP_EQUAL\",\"hex\":\"a914c69be2ffd44c43a3ed02e522e87844788fb2954587\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XVTPPKsek8KG9J6x4mwhkLZGcZJBGeSGfP\"]}},{\"value\":23260,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":2,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}}]}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json2, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json2, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // 'ElementsDecodeRawTransaction Issuance(Unblind) Transaction',
  const char* request_json3 = "{\"hex\":\"0200000001016902d7cfeaed59a61432674060dbacf89aa50dc4fcb5980c55034ce75fed5eb40100008017160014bf7f6fbc324728d857801e7f3eff88cce289cf25ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000005f5e1000883321b72665e9844cdb8859a743583ac18623cf6b78e512fa291912320419104040125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000005f0f17c0017a91472a7834df62071c0bcae9e00b00cebef505b0cf6870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000027100000019ad6d207eae5433a78e0c13279d3b2eb1206110a61c0c7190c9b00213d9477b1010000000005f5e1000017a91417514a45caadd530f301c13faae6003c4ba1cfc887012cee71b33a252e6326a2450643ad13b05436112ad1e1fb284ed807da2eb81bba010000000005f5e1000017a914b721bfa4e90777607c95ad886362e4870ef6072c870000000000fd450b40239f26013d1f1952c24c7ca9878a6042683813daa766a6f6887578f1a2f7be418273a0b7e89aefdf3b9bf0cdc28f2e71444825e9978d34beb40e3bfb98497418c3a8386aa8a1f2dbace4ff72ea1e11c00b4b1474ecd934ac6098716d11d7fc83364f91908c12be70081186786503f85a9f7654f7a04e927c3df7bdbb9ffb2e8f7d2174ae0c18bb80adc1248bfcc65ef5b7599172b6428684a8f66fa73fc1f70b4f3f12e6644e27194b0fececc73d32ecab930d51555ec814ada14d1f5d76b2d3b03daf93d5b390314288dce055ee4207b4b2271af3f7351f8bed0de0796ed9c370fc78031b9c60937f786f5fd7f3d3bcd9e0adcc8aa7c0d3af6ccf733210222dacd7422f4ecb5540752862fbb710d83955069b5e91219256f3def7d6bbe7225be32a5e4a9161f7a317c1aa159c18ebc3e88527677e4b293db135732954bbe051681ac2eb96c9ef53f7055b483c4e9a88c5598037e233343986eb9a6ff98d611d8bb9bbb5445e784e781f8b3078bd795b8c24046cf95edea799286eb0faf952408ece194159c361509d2eb7dd0eb08f6e0cff96d6fff59fd9bde2825a510bb41a637c3dc961d268a84d7d3610eb5900a48b9d2808fdcf7570372372aa9f5d0af426d6340a8b422e18dfb9ff92439db30d548f727afd75555cdf28dd4a3f8ebafb680936c544bd2d8ab5c42be214e6e095678d7c5c6c4b56d8e1ac5025313466992eded93fcc365de54fcba323ce273afa9d6355747d8f03bd9ef16510a241f09a94c19eb3e315ee52049c4f2bbd3938e1922a6307711e2133ed442d94755cb4f9fff3b12c705bcfebba75c42afbf09f34cb2124c09462ee81805ee5c4d1f50145ebfb6761edac73cd3180d470c6afc11be09c4d82a95cb4a292ae548d911770a484e56f6caa7a8f411e61d3a11918a748c29953823839813c3fb6b7b5d7a19657fd015619dbfff91688a5510ad3a66d23b44f3182f2bcca1f0a85aa295f1b8bbce15dc8411a7b7ba01a20651924b052efdf3d686b232ba54520a38982cce05c748fe7138655c4273e6a2c2a1a615549635eb9bbd8e3df75c4fc406f4321b170dc29f18b6218ac79f9f9f83e9b126231679ee5863768b6873142017b3e4e17f18be79d988adfb5d4018481d3b07da9b65f95d114a69fda0702c881a0b61b3698daf0670ec79ab22e6862d4f2f369eef35255d6a58dc6d2e0751cbd4eb99cad1ae62aa92c0c80b971ba668bf6d089f79a3105fa2e7099942bace83b769594d9cad7725cc5b8c2cbf29c5be91b5f00e20763eacc1cc7dea5875731de50b13922ec00b3b8d31e5f26c19e937062e71b0fd65aec7ef49e174ffb76edaeb9e4db804e8a508a0dab33f6265de4384d726aa2ad52be1567b442d2e0ed0baef2d3250d8b60e72c3649aa165764b299c694b1cd27b80fbdf8fa25b64e18b6769099e3d3e4dbe952311bf75b92cb3d1fe2354387cd0b732a8e88a251662de9fb161c7742a0eede16c4335faec57b3c2933177f79b66cadc847fb8d5b01680c6ed80705d26a039f1af52675803ce97a8301ad319d3cb4b85ea4ea8220f8e6d2bf3547e3b6d9cc3c79db4a2be3af48c3ca0377f85e38c21807962a6137686f54710ea5baf71a345baec6737650fc26349bc967aa5cb4c046ec5286410c57753501e616684f99a31f5d883536952996335333fd23ed4c247239cb51e7ffb922c659f2939c8fa6f4934fdc99623bd3eaee99f4dcbc4d865b3b6b3f8286f0ec64e870a1f996eb5d69330928ed32de00921f68bed94f2e8d9dc05773b85f8c4cd1440d027e09cfa91d2b4a870f6ee089421de67da45b673b3c70e086ba378017a351e16098d2dda6f5728f8e4f6e1868ea055bc7788e9654bc03bbbcdb75e6c9005bfe861403d33e697c3c1d401b505f1ba7af879f02e2489114de9bd7a77304929c97b8a205ab92dca9ada5287f361133aff1cc4ddb49fe6af3f619cf7fb851a087beabb60916c64f574ffe95327ce3f60173b4a27e9ccbcf3654ec108198f5671e6c504347d9225e9d0e6298475d73c4521a1f8c8b54ecd5a2642ed1c35d348c035c49f851f98a55b756b6af511960c06fbf9ab51776339909727bf7cd7f899461b74313f75debaaa83b7bdded023672e6084b0848e26ff0bc4d2319d4f0eed92a365078c12b440963b7d92db90bf9ceb37ace8f558c446b5de704733d76d4ed88268f6c3685fc791dd46a05b74641d1a087f51eaac43e38de412926161e0e6cbf25b7c6e5971707d40d685b9d77bc58bc7a7e5ae22a07852b788729c32b22545a8fb5bc3d6d20df85df3ffa4bd7f6ab3812decf7362d0db8b60b4a2e9f62d80b46fd6c42138b7d2d5fd5d132f6a122ea88f110d7df5966a82a2fc6e1a9a1c56966c10466045bd395a0f5539b783029b02f3a261df32084b26f38712974fd76f7444fcd6fdafd66c74e43d84701b3280a26ba55e7e417ad8e512cf7ad568c25f37582f5de62539ac659437d525a0a6d547d404d22b4f4dac4dcae9579b6ca96a48db0b1abd489d4f89213cd4249ab042b6cde9776b0db7db098b3710286a83df75778350137972fb74624b242c509c9810f2d3302981c3dda1c1a9e676e52e1e72bfc9efbd0f84c7b48875e0a9f4387a8aaa0eec9ccce2c8db2b37a5b8826de88c2fb4fdf29947079a78f2661a3b92f25011ee6e0607d5db1d1a4d95661e678b689f4f44635d62df8aa82364bb2a879638f255c426d35b0ecd07a32a3a3fc94f6a489aa26448b61baedc1481de28661ddaedab0ee17f8a44b52f7c098c29e42785be645d885f2b8ff9ce666ad6a0a9ecc678075ba1d03306c1f80524fc699933adf76354c5f0d65ce827e54026706bd9b3825cbf85eb427f3e2305a224756eb46ad12109153181ad0e394ad12de3005c1767f2e1fa5e48b369f8455714df4181a8f8f6b6fb1bbc5653274ce648a54313e30583412a695e4eaeeefef038185bce2a1b2a90c3dd4d93e781e4ea1cc2afd4498880c118bcf104d1fb2c250e8263d15f1a82ce6248fe08aebe958c1245d5d82e58e6aba34aa70b384f051363d0f6eb6beae046461381351f18427c8bac041f0b682a02caa868e6f85409238e81d10de12fbe4b5f73941ed5416ccc3a52635978b15d0f90e63e0e25b2eac8a2d0acbcb7627abd13ade4080ca1d22d91661c64b35fc4cf158ae903c5a2bea91f61254878a8cd468025b947436c51d463b090b982f3f5a2af6127ca2c6e236a1d2e9848100bc96f6b2acd6cb7f9ec6c53eba286c26a8b657a3aa426440b1e7700b08e428729ebd5377a558dfcabc6ef8545ed161aa288fc25904b0b6f4306ad7ce51c65f4bfa0e31ee236b952026b8abfce9db79fcbfacc991163e4b8b9dda11fca65a7248997d3844a6bb6ffcc9a82b4d08f699ea527a14a9dc953dddeb2d9db33fbeb52955eb133c60eed85a20f4f764cd84e7955d46a73ab56baf5567efdd92ba6bd908a7a8fd067177170644e9e018ca9352aa641c787e07c78c137b62de0035d9b6ac8e0858ded0a24d9eb5a19d22dfb01fed8aeaa1512c6ed8e50b68332504bf7f58652dff5120b0fcda5dd7c6cbddd161f4ceec26675491fb9e17e6298f2b227f29b46155c9e55b600ad0a635921f0ec15e9b3b02d85fe1f00c05848d8478f97851aa67de15d48d9120fbef82abb1635c417245b2e330c4c79498b92eb471946d4fc2639a900f5b2e5f71d7890b1928d84da975a443d9098198ab5b10769462f6f307ac63d999a8cefa8bef60d4db39d3ae850e9751f1a4375554c54c41d1a1f48c96b0b4eb99935d21c7885b777012076efacd7fa7d69eb24640a37bb3a348faef5bb7462f2762397566a43fdf8df0fa1afbc6736bd46f75b19de822ff5b1b339b55a909b15d793499dd5432296a33efc186a5613842c47cefe1f1945dfbcf7e3deef292c5526391c624ab436adf674da17e8cfce18097b3083d170d0135dcb0fa0afe01c5e2f8e211032345288467258e7561389b6aee9271f645960d81073bcaf70ed72584406cc10d6411fe5f10a86be04f3e37a5f455b743da37130a49cd6347e861402a6536d04891302473044022036503a4f4c4a2e65483c0e762b561e6b267db0c498bfcf2e51a8cd8844015e88022031e9b44468cf9431f1fe74f60b755bb1e273ae462bc4024c097c01aeda7847bb012102ab849ed2b1e6f6c558d74e5c5d49d160c00afb6d7abd5b6c76024b3a85a6a5dd000000000000000000\",\"network\":\"regtest\"}";
  const char* exp_json3 = "{\"txid\":\"61d625e1b2f1d2ff42d6acb2e8f4e9743e74bdce448c0c233d3ba6460ff48289\",\"hash\":\"07eb5b884a3c9a7cca79ce2def3f9a72116bb1e05d2f635ed5af191629bdbc19\",\"wtxid\":\"07eb5b884a3c9a7cca79ce2def3f9a72116bb1e05d2f635ed5af191629bdbc19\",\"withash\":\"2d89cda5f7686fd76e9e618aeff1b9a75181e0ef1abd06a512ffb8863225784e\",\"version\":2,\"size\":3431,\"vsize\":1178,\"weight\":4709,\"locktime\":0,\"vin\":[{\"txid\":\"b45eed5fe74c03550c98b5fcc40da59af8acdb6040673214a659edeacfd70269\",\"vout\":1,\"scriptSig\":{\"asm\":\"0014bf7f6fbc324728d857801e7f3eff88cce289cf25\",\"hex\":\"160014bf7f6fbc324728d857801e7f3eff88cce289cf25\"},\"is_pegin\":false,\"sequence\":4294967295,\"txinwitness\":[\"3044022036503a4f4c4a2e65483c0e762b561e6b267db0c498bfcf2e51a8cd8844015e88022031e9b44468cf9431f1fe74f60b755bb1e273ae462bc4024c097c01aeda7847bb01\",\"02ab849ed2b1e6f6c558d74e5c5d49d160c00afb6d7abd5b6c76024b3a85a6a5dd\"],\"issuance\":{\"assetBlindingNonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"assetEntropy\":\"8c5bc0c2dc91f984b67f3de7947670994ad3892c5b371aee14e7f9bdce8c19d3\",\"contractHash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"isreissuance\":false,\"token\":\"7e81f4c3488cfd6fd0383b3a92bf27653a0ed27cf77a9681a375230f67be1dee\",\"asset\":\"b177943d21009b0c19c7c0610a110612ebb2d37932c1e0783a43e5ea07d2d69a\",\"assetamount\":100000000,\"tokenamountcommitment\":\"0883321b72665e9844cdb8859a743583ac18623cf6b78e512fa291912320419104\"}}],\"vout\":[{\"value\":99676540,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_HASH160 72a7834df62071c0bcae9e00b00cebef505b0cf6 OP_EQUAL\",\"hex\":\"a91472a7834df62071c0bcae9e00b00cebef505b0cf687\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XMoUZ1ntkntsvw3BHHYCfK56SaZn4SVaEk\"]}},{\"value\":10000,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":1,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}},{\"value\":100000000,\"asset\":\"b177943d21009b0c19c7c0610a110612ebb2d37932c1e0783a43e5ea07d2d69a\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":2,\"scriptPubKey\":{\"asm\":\"OP_HASH160 17514a45caadd530f301c13faae6003c4ba1cfc8 OP_EQUAL\",\"hex\":\"a91417514a45caadd530f301c13faae6003c4ba1cfc887\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XDUXmhD2Pd1GHDYEeZtr12r2mz1iAvgZmn\"]}},{\"value\":100000000,\"asset\":\"ba1bb82eda07d84e28fbe1d12a113654b013ad430645a226632e253ab371ee2c\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":3,\"scriptPubKey\":{\"asm\":\"OP_HASH160 b721bfa4e90777607c95ad886362e4870ef6072c OP_EQUAL\",\"hex\":\"a914b721bfa4e90777607c95ad886362e4870ef6072c87\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XU3Yw9KwUPSu8mi7pCrhEvCNeDN2eyvRbf\"]}}]}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json3, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json3, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

#if 1
  // 'ElementsDecodeRawTransaction Issuance(Blinded) Transaction',
  const char* request_json4_1 = "0200000001016902d7cfeaed59a61432674060dbacf89aa50dc4fcb5980c55034ce75fed5eb40100008017160014bf7f6fbc324728d857801e7f3eff88cce289cf25ffffffff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000092ef327afc62b0749826df12d34412566ec1743f75ee421b4e4440f0083bdff8c0883321b72665e9844cdb8859a743583ac18623cf6b78e512fa291912320419104040ae7be1f8a5aa41a98a0fd5ad39efdcc3f36a63adf5849836b08aa622ea65d25db0880596e89690a32299914da0a85fd57db46575663968243b3ba5b1ad15120c402034a6d652db056e0364a0eb997821d62266da79409d995f9d39d011ba0daa5998217a91472a7834df62071c0bcae9e00b00cebef505b0cf6870125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000271000000a364d73c6e121fdc4ea87a0228180a521be1e03c3b287435dbd06536ac6bf4770080e7d14989746f3c5d3cc4ea1c651731e9c375e71d487665a13ec8ba104b14f44025204161081bf96756531f5b8b00d85f3b831041be2b8bd108a48ffb44d9f014f17a91417514a45caadd530f301c13faae6003c4ba1cfc8870a9033c37f8d1151b8b87c003dd2b2ead5f85e3ca32340e9768a80ba5a840f9f4c0839ece197daa1568947778ed05f8d499e2ecdf326155a93a8052bbcb591356edc03395b4c5090e3fcbb0c5c2b258af7d078a9d4683d33d7905fceae7f0f7033511517a914b721bfa4e90777607c95ad886362e4870ef6072c8700000000fd450b4023677000a52b903bbd128b03b1e29e4d82ed0b43567843cc5ce1f4f979c7e631a1027d48f72a782f9870c1d5eba05b5e582de397255349313c54f5766f27262640c2f657d49a2faa9de02633ae9a627fa2a837a85252fa4f74b6a59f2bbc8b8bccb6094705ffe112c6b0437ea4a6877b53e53a6547c9aaa46e5a1f4fb8c1001d5f738f70d29551b6949bc4a2de85b842d6abf38aca5815c4ac5a6f5fab3a0df52ae5abf354cebf6f15f6dca2a855039ab6697199203bc7a1599990d424dd9bb6c9712af2a49c3abe609aa8d31a9e214fafeabe9393d9dc2dfd92b4f24b19a4fdbf376bb501936b9b875e822b7b117aa6c114c21761f4240162dfa6b98bc5f22c524ebb54130b0e7795663ef7f27ac1fa3daf65d85a8ac75dd98e7d35f14967c8a9a120e9715c8f2399cd41172478fbd1692c961153e16c677520269309687803f070d8e7c890b6f5f2ab79582a862f4ca4a49cede94d981f121643f4710835c1e30d560afb3df7b1020e1530eec31094e346cbe070b3b0e59478a962c3e6126969906c1b39a17667825a93c5882e63eb31e9003b5bfcea0c8a80ffa1ad1b0cca2b1d37382f6307937a6fe41f1a49599d508733b87524cc15ede76d3252aa571541fae83ef75e93639db72a6e54bf27fba09d1ecb8055c962475b996058e6ca85daa7a80d23a3903dd71b93d986ee6be8e27a14f4cfba3e2d953c065880fd715c739628618fb02cce6c4698a0ffe9e04aa116294e9c626e2e63cbb044991e3f29b7215a894cfe8ede4c5ab52ec47b6f64b3e69576798f65a4c3a3943b10cf07723af40bdd3ba6a382154605fe761a6ce0115c6a02e639ace3b44feb378262fb1c18ac2d70892195c6453159b9eef9aa86f8b300e0ef3408605229afba6cb985486d88b880f53f9019430b763d8fd3ade45424394e3a66e9c4d7752e63a1f295574e06bff6974fce8b8385fa597d9c731e972741e80dd4bf7bf6ab2fd0ec7d9aa1c9488b08572650967b373d08a75367ef47e348b5ba9ab90fab85095fae2b0daff44cf83883084dc8d0ef0adcdc95e74976218fbd7d7373fb0646786f76228efeea9a9e9e547e0b11f26b933cb41e5858932a5bcb992fa8b471a061a8379ca053573ff525c741eb0a51e7756820dcaaf7547afd71f30dc06495b6bf3310a9b4277743e9a17ffb5012d20d01365b7090d763c5511f9562437df7b7ede340004f15321cf0ec2994882f3e02114fe44f1805f58e0af310f22ab5a68907041f8f734b1f33e3e8753e365120bf2fb4f2a2a597d3cf2c8839462f35eff7ab62bbb0a4433876bffbf5532c2277ca48cd0a3eb4b773cefb46d0d539b177a694c85e02d70e99f14774faea2aefb65e639e8702ef2434ad66453c1a9f5b00760aa372cd432748b11ba1757b3071e6169cdac6beac4a160b55ea02d1d50159095e593e45683e0ca1bace4581a09b086cb74187de61ab1175c0d42a9601227be8422803d34789219b150a4de6a4432d28127195b8b46ef721f965aa0dfa5a939f85bb2fdb95efe882b877bcaa676ae964ef37d8dab7d5d6e2b6f4faf4f811366576a9d1c65c36c77a8daa6954f1395b1009c859044df8809f5dadcbf1dc16ec5955f0671cd3c499296bd494c6c0e1f0ab0012018e90bbf41d760c88940254258f92d6dfb6998b4afdc4c72487721f0e97ddcc3b28d941c7f2458d51916b9b2094e3c2913df3c227f8f957e5f595264b0da17469ba1e0794490cd5bb1b35cacb5c12152c8303ec038802ed334cef24a28e6aa38708dc72100879f721494a40659c41b63cd2c22d9a55b07aefc71a5532bc03564fad6767a41d9b52bbb1a323d280041e44eb87674ee964c9428e9ef96ba1dac685f8cb8fb950e34528fff02368be76cbddd9215ddd5e0635eae652a0ce642bfdf7777207644f1ba503b409faf68c48a9a31142af5396e4bca8e67cc183b30895a1893b2901e91b4e784dcb137b7d643ffadb6abfd8821ab1b4f6fbe20275d42ff44da02b32e00f238ba7b326f457f3ce70a2b784d4f165e594f0a27d21ef187376a1349401bc6d23ec2e356ce23e8e0be87f599d335e41c43985ece05f0dfe56d945aa5c3410d54a9cadfad6f29042bd37dcc069dfa27b2c7862a01b2535862d96cc80a0bbaebe1f673ae2daebfa133a3e1d7dc959fe062313ef9813f4341a5aec78c76a36d95dba906719ac50973cf7b2ba7037f489732bbc46b8da67f14a8e0ac225858c09f182c6c0b0540f9b69bd03a00c055016afec4c271cba5266255858c87516915e70db30ef8821f6336b184d8afee9c81ba51aabb5af9af9b473eceb9e2cd9076eeed17a5d423302008c63420d49e21147f48de7da5b69185e9733993a3504903a9df6c9e48f327ede7a9337c4e40c24739afe1e0b22377c62a98f2bf9968833af3f7208c7363e3702801c1145a1f1469875f0496a14ef401bf6b1f0aa75f77f031d30f415b514a73905bc7d3e2127ca88ad7969b08f021ec08fcfb3d7b23f1f22e42a5f77aef6319fd4eb4ff802bf0aa8b770789b94eee957636d23a303b07e5837cd9db6744eee86ca00a8ab63406203b10029ec27cf2551a05ebf7382d64aae1011c0ff6f4c98e3ca2162d7a7ac332d54908be1ff91b017b38786809c1a6007d2c6e4fee8b8162f2329ff2340c2302efb08fb8fadb5d84b6c2394988bdb69c08e51c2d7e003c97330bb651ed787584385a8cac09b16882c0a65fcf0c0812e9060a3b4ea443d583cbfefb0aad73d9d6b63eb75de3b5a7e04f26639ddd29e9047b6c0efae2a92b104157ec6164bc9c01249f073b5e42ee4618216f955ecbf0b7f8e4613159c1ff7009ba36571423557aa7807fdc4a07427ee3efbd67b645b3fadea1786acde3c73d65d3ea2743cb965fce112508f096fe44e6cf6d225b74e2f4a583bc8754f482eab453b7ba1472f75dc8892d2f0641cf5a84fa881890b2820c731fce87c6222d3e2014115ea567d0ec4945279bae6813403a46c77eb80eeefe958b765c849e4253fef2e8b474fab5b9df7ebf5ed8fff15063734e283a05e11638f38e6b0c375a989b3866a7122a1e9c2847dac65fce97b240c0bf0748a11aeaeae38d5a7527918c01357e06ff880ee491e96f3dbe75aa2b7513209dbd0b628dfcad3b9ad93d0146ef27515c1b50d43702b47c12b7bde5bd837fbcba97c814f616f7ae97053548afb0c75d1e6fee57bf6baccf9c894dc028c83beac85e1a99304cd76becdd3ac18b5995ea913211440665540dfb4d84706a49cd7159afd36d1d75cf2f2f317a5846d5a54be5d0c5a103a35ec2a370b4b81b11c61247e3178413c18dbf0532c28409b963a6230cb1290d0355d767f0c81a39662a65de72a002cb39e57950eadf93744a345cbf663e5e0d21495605178085091166782188839b462322e95a9f06275f9fdffc51fb7df79637ac388d9d28ce5fe590f99b16f7300756053ed3a3d990db0dc6f2549a3354cab2894b14aad86d2505ef574af0e12b2dd32418c2d5fc8106524b8b85e1953c4459ad7cd36e42202874b9854a0b366b809bbb4ee65757e3876877b552315cb1f0977e63b196b17b7709cdf937733f0330f19fcc192ac87d8b3f76494b38f9d7da166ce8f068a11a679ffb0f58857b4aa9d951f958db0e2001c62b0412de553cacf95ecea11a94b599188cc0fae8c0f404c4591072a08e015e235409716e048c05c208e651580606cf842110065b25064aa3829f916f1a770f5b7c07691612548df3b39dc76d1185879ee541bc2089f50c9bd116c0eb9bce88c55b3d99f5eb5344ec9b437e164b5c72dcd6daf765782dc45c48e572db8c551519e3f0ecb62761d80a7ce1fa319074c101710d4015af4017722d95dc2d468dfcccd8d9398a17152f054fa01730ced76faf3f12c1e5ae062682c74e823abfe59710391c8c7350f303f0c34fbb3bfbdd671f640b4a0eb483e64fcbf560f45b8d5bfe860bd6ce448229febdc3689a66761936283147495e4f7c75df412eb91bd66e81dfbc9f04852f10429b99f03429964c0b83d9d3b9a2597933be5786a00b06759bd95cbb0e52243d37194fd450b40239f26013d1f1952c24c7ca9878a6042683813daa766a6f6887578f1a2f7be418273a0b7e89aefdf3b9bf0cdc28f2e71444825e9978d34beb40e3bfb98497418c3a8386aa8a1f2dbace4ff72ea1e11c00b4b1474ecd934ac6098716d11d7fc83364f91908c12be70081186786503f85a9f7654f7a04e927c3df7bdbb9ffb2e8f7d2174ae0c18bb80adc1248bfcc65ef5b7599172b6428684a8f66fa73fc1f70b4f3f12e6644e27194b0fececc73d32ecab930d51555ec814ada14d1f5d76b2d3b03daf93d5b390314288dce055ee4207b4b2271af3f7351f8bed0de0796ed9c370fc78031b9c60937f786f5fd7f3d3bcd9e0adcc8aa7c0d3af6ccf733210222dacd7422f4ecb5540752862fbb710d83955069b5e91219256f3def7d6bbe7225be32a5e4a9161f7a317c1aa159c18ebc3e88527677e4b293db135732954bbe051681ac2eb96c9ef53f7055b483c4e9a88c5598037e233343986eb9a6ff98d611d8bb9bbb5445e784e781f8b3078bd795b8c24046cf95edea799286eb0faf952408ece194159c361509d2eb7dd0eb08f6e0cff96d6fff59fd9bde2825a510bb41a637c3dc961d268a84d7d3610eb5900a48b9d2808fdcf7570372372aa9f5d0af426d6340a8b422e18dfb9ff92439db30d548f727afd75555cdf28dd4a3f8ebafb680936c544bd2d8ab5c42be214e6e095678d7c5c6c4b56d8e1ac5025313466992eded93fcc365de54fcba323ce273afa9d6355747d8f03bd9ef16510a241f09a94c19eb3e315ee52049c4f2bbd3938e1922a6307711e2133ed442d94755cb4f9fff3b12c705bcfebba75c42afbf09f34cb2124c09462ee81805ee5c4d1f50145ebfb6761edac73cd3180d470c6afc11be09c4d82a95cb4a292ae548d911770a484e56f6caa7a8f411e61d3a11918a748c29953823839813c3fb6b7b5d7a19657fd015619dbfff91688a5510ad3a66d23b44f3182f2bcca1f0a85aa295f1b8bbce15dc8411a7b7ba01a20651924b052efdf3d686b232ba54520a38982cce05c748fe7138655c4273e6a2c2a1a615549635eb9bbd8e3df75c4fc406f4321b170dc29f18b6218ac79f9f9f83e9b126231679ee5863768b6873142017b3e4e17f18be79d988adfb5d4018481d3b07da9b65f95d114a69fda0702c881a0b61b3698daf0670ec79ab22e6862d4f2f369eef35255d6a58dc6d2e0751cbd4eb99cad1ae62aa92c0c80b971ba668bf6d089f79a3105fa2e7099942bace83b769594d9cad7725cc5b8c2cbf29c5be91b5f00e20763eacc1cc7dea5875731de50b13922ec00b3b8d31e5f26c19e937062e71b0fd65aec7ef49e174ffb76edaeb9e4db804e8a508a0dab33f6265de4384d726aa2ad52be1567b442d2e0ed0baef2d3250d8b60e72c3649aa165764b299c694b1cd27b80fbdf8fa25b64e18b6769099e3d3e4dbe952311bf75b92cb3d1fe2354387cd0b732a8e88a251662de9fb161c7742a0eede16c4335faec57b3c2933177f79b66cadc847fb8d5b01680c6ed80705d26a039f1af52675803ce97a8301ad319d3cb4b85ea4ea8220f8e6d2bf3547e3b6d9cc3c79db4a2be3af48c3ca0377f85e38c21807962a6137686f54710ea5baf71a345baec6737650fc26349bc967aa5cb4c046ec5286410c57753501e616684f99a31f5d883536952996335333fd23ed4c247239cb51e7ffb922c659f2939c8fa6f4934fdc99623bd3eaee99f4dcbc4d865b3b6b3f8286f0ec64e870a1f996eb5d69330928ed32de00921f68bed94f2e8d9dc05773b85f8c4cd1440d027e09cfa91d2b4a870f6ee089421de67da45b673b3c70e086ba378017a351e16098d2dda6f5728f8e4f6e1868ea055bc7788e9654bc03bbbcdb75e6c9005bfe861403d33e697c3c1d401b505f1ba7af879f02e2489114de9bd7a77304929c97b8a205ab92dca9ada5287f361133aff1cc4ddb49fe6af3f619cf7fb851a087beabb60916c64f574ffe95327ce3f60173b4a27e9ccbcf3654ec108198f5671e6c504347d9225e9d0e6298475d73c4521a1f8c8b54ecd5a2642ed1c35d348c035c49f851f98a55b756b6af511960c06fbf9ab51776339909727bf7cd7f899461b74313f75debaaa83b7bdded023672e6084b0848e26ff0bc4d2319d4f0eed92a365078c12b440963b7d92db90bf9ceb37ace8f558c446b5de704733d76d4ed88268f6c3685fc791dd46a05b74641d1a087f51eaac43e38de412926161e0e6cbf25b7c6e5971707d40d685b9d77bc58bc7a7e5ae22a07852b788729c32b22545a8fb5bc3d6d20df85df3ffa4bd7f6ab3812decf7362d0db8b60b4a2e9f62d80b46fd6c42138b7d2d5fd5d132f6a122ea88f110d7df5966a82a2fc6e1a9a1c56966c10466045bd395a0f5539b783029b02f3a261df32084b26f38712974fd76f7444fcd6fdafd66c74e43d84701b3280a26ba55e7e417ad8e512cf7ad568c25f37582f5de62539ac659437d525a0a6d547d404d22b4f4dac4dcae9579b6ca96a48db0b1abd489d4f89213cd4249ab042b6cde9776b0db7db098b3710286a83df75778350137972fb74624b242c509c9810f2d3302981c3dda1c1a9e676e52e1e72bfc9efbd0f84c7b48875e0a9f4387a8aaa0eec9ccce2c8db2b37a5b8826de88c2fb4fdf29947079a78f2661a3b92f25011ee6e0607d5db1d1a4d95661e678b689f4f44635d62df8aa82364bb2a879638f255c426d35b0ecd07a32a3a3fc94f6a489aa26448b61baedc1481de28661ddaedab0ee17f8a44b52f7c098c29e42785be645d885f2b8ff9ce666ad6a0a9ecc678075ba1d03306c1f80524fc699933adf76354c5f0d65ce827e54026706bd9b3825cbf85eb427f3e2305a224756eb46ad12109153181ad0e394ad12de3005c1767f2e1fa5e48b369f8455714df4181a8f8f6b6fb1bbc5653274ce648a54313e30583412a695e4eaeeefef038185bce2a1b2a90c3dd4d93e781e4ea1cc2afd4498880c118bcf104d1fb2c250e8263d15f1a82ce6248fe08aebe958c1245d5d82e58e6aba34aa70b384f051363d0f6eb6beae046461381351f18427c8bac041f0b682a02caa868e6f85409238e81d10de12fbe4b5f73941ed5416ccc3a52635978b15d0f90e63e0e25b2eac8a2d0acbcb7627abd13ade4080ca1d22d91661c64b35fc4cf158ae903c5a2bea91f61254878a8cd468025b947436c51d463b090b982f3f5a2af6127ca2c6e236a1d2e9848100bc96f6b2acd6cb7f9ec6c53eba286c26a8b657a3aa426440b1e7700b08e428729ebd5377a558dfcabc6ef8545ed161aa288fc25904b0b6f4306ad7ce51c65f4bfa0e31ee236b952026b8abfce9db79fcbfacc991163e4b8b9dda11fca65a7248997d3844a6bb6ffcc9a82b4d08f699ea527a14a9dc953dddeb2d9db33fbeb52955eb133c60eed85a20f4f764cd84e7955d46a73ab56baf5567efdd92ba6bd908a7a8fd067177170644e9e018ca9352aa641c787e07c78c137b62de0035d9b6ac8e0858ded0a24d9eb5a19d22dfb01fed8aeaa1512c6ed8e50b68332504bf7f58652dff5120b0fcda5dd7c6cbddd161f4ceec26675491fb9e17e6298f2b227f29b46155c9e55b600ad0a635921f0ec15e9b3b02d85fe1f00c05848d8478f97851aa67de15d48d9120fbef82abb1635c417245b2e330c4c79498b92eb471946d4fc2639a900f5b2e5f71d7890b1928d84da975a443d9098198ab5b10769462f6f307ac63d999a8cefa8bef60d4db39d3ae850e9751f1a4375554c54c41d1a1f48c96b0b4eb99935d21c7885b777012076efacd7fa7d69eb24640a37bb3a348faef5bb7462f2762397566a43fdf8df0fa1afbc6736bd46f75b19de822ff5b1b339b55a909b15d793499dd5432296a33efc186a5613842c47cefe1f1945dfbcf7e3deef292c5526391c624ab436adf674da17e8cfce18097b3083d170d0135dcb0fa0afe01c5e2f8e211032345288467258e7561389b6aee9271f645960d81073bcaf70ed72584406cc10d6411fe5f10a86be04f3e37a5f455b743da37130a49cd6347e861402a6536d04891302473044022036503a4f4c4a2e65483c0e762b561e6b267db0c498bfcf2e51a8cd8844015e88022031e9b44468cf9431f1fe74f60b755bb1e273ae462bc4024c097c01aeda7847bb012102ab849ed2b1e6f6c558d74e5c5d49d160c00afb6d7abd5b6c76024b3a85a6a5dd0083030007028daee23a0e51b165be98fc15150972f7f95a09ff050b9e95ba3c2f813293beb1e7fc051fa28f5a8a34cafc3d7e3b5086e3f256a70e1ddc6d9c6ef9c927d3a4e2b2b81f73f27137d0f77b72987d8d9771627abe02b47006b9eb95fe534ffa574798940f1ab429d1199fdacfff19ca08473685e70b10c7e643918d8c2924752dfd4d0b602300000000000000011cb6011e59d40a3b71d40f6080bc390592c5e07086dfb5d8008c41f35a9e51566fa565c66f41f3bfbb5afbbc67e6925b4310763f20f0315bccd30448c7fbdff7f2a467ae8081f7684d86e85ce77326a819d6e43a0b17701bc11e5b4a27e36b957348612f0dbc036358681031a1872e4c6993b9b8e1934d41b68e9123bfc788167fcfed34910378d1de93ec57b61183ea73643621bf9bff9291afa7b40851f4525c5721832d3f7d87c9f3674dd03f9a4e920978e6cb1d8388df138d15fd40cad1a506eb24a8ba41d49d93b61d4fc3afa9a0dfecca2dd882c0094154913c17b182abc5bd112eaed535ad9c210c51e9f82872214426bbfba664f71a887f2c643505bed39e31150c30722f8dcf070433472ffd67d965ac9df345f72ab5c513b155e0f0f52483c760ee5948d5801f481461e16f2d5f57fb52c0fd3a385ce4dbae07e0134729efe57c95bb89191d7fcd0dd4b59bab3c6d88425051dd92f32de5a7fccecc43847347a1cc73600b649ce4485591655bf5a59db89c8c128b792478dd10a0f3cefdfdfb5c2b9cd033cd9bcc2dc6e8155aecab3a35072b1231bf4e30178b963e0312f18e0dbc001ee8bf00f8e183c85cab7a263467af19dd2dbe1f4e96307c6d075c02c8c98a485078dba413558e0db49f5e678726bed1c841c2ceb8ffc8536c21cd152588f5497d5463e1982ebd6f85bfad3051313cfa57981510dba05674fcecc38d3b3a31c236edda9dacc4069ac931a48e9dd3df15ea0d2e72af07f4a1f535c626dc43bc742771a506aefbb6c24d1d713e88230aa67353d3d0762d0c246a11911aa1f41ea75440d2da9ef16391202c7fe9cc8c3b668907f23c131706e971c68403b923806b9f03615a9304531c8fd1fa070710713df0174f6fd95f9c8f368b1aa9d993d933f3d52eb9a01be330b9c631b496e20c72e0de91f2aff1e00a4a41c3fe0c82f6c6351e180b9911e21b3b86146ad7784bb06a378e216f931fef67515d991525b18fe9d04f9cff45559f846487694fab0d24333b0e583488709153a154df7399262dfcbe461609b7f21dffc99130f03ecbbdc6dd3417fce83791ee87464fab964f95500ef2b30e7cea2bbe6e3fdb193db3b203c99a232ac868372b81ac69c3f157bdd0173b999162000ba3e7b5ad4bee099867ed53d3efc714a82da98e608237fd0bb14daef5f65fae9196d8c09416256c8177d060935e4a52945879727d4accbf59fceed6f14ecaac73af2905e94d0922b9e799c9cf332ad5ec0016ec6e21bffde7a188b0a36718b3360a3c5af4f2c44470b0fa3fca45f1d5c95a3727a1573074ce1d73281d97f083b083ed5f6f0b4ce772b5acf9d29ccbddc863a6fd8d624ddb2cd15f86335ac77e7d898e4ce929e4000ba36b49f40f32da6d194dcb56961d94420d2a81c42d02aaccd70989c5906374600b632159dea91f8932449fe5669e8eb7d67456f66855d43da50edd9609ed1e9a76314d09437d118ee3cffbe2fbbca35541dd8091ca8884577706ca647006c4d0d28633567829f3c5bb11017d4339b59d67094b9890a88177cb796914f5dedccc4c668e723027ba987c3e2dd9a45769a5aa94c1643b2609ce8c22fcc223dc2e78bed6d30088747776641c17c0a289fe301db8c5c9c25b9cc2146c5db0e0c999244fa08a816ddf73f96bd685687ec78199bb1bc1e614d1e864c2d140251388b8904e4fb7f3c84a080ae53c120666f58f20e9d966e5c17cc93cc581b76559d5b3695a18318aa98c9e4509e4fe310e05cc8cbe999c70a937eede33cc2cf642b53be72cfb0f4eef91ddbe5b5311fa38200c796ca1dd68b416ab3628a9853b78d43f6316a122a141ede09869dc39f9fda053c643008b753711872b196d845711882be2349883b06b331584e029a8eac92bbb639c1ae9c1572b5bacfffcab6a21d4cfa28cddcf1d310fe5254b8217a20e6deb6b3c";
  const char* request_json4_2 = "462d4de34999d4c17023e69d9497a81145c4e361788778f3ecc9fcc98a839c2bb6654b55316085948c55f2ce173886b065c3ac051e113ef0195e8c1aebd9e708621727e5b264024058721a30b8d035c44e23b1e0d3d9577e37f2707df30fa71bba820475146133b1008669dcaf62784026b49c4d0283973f512feecdd619f4143fb08c2b6ba4313937afb85a7e2bb3115430b79a62b8cb8a76a02c56623e28b2c94c1a1562fa5905c81a8f72af0051f33b4b99dfbe19eab47a24f2b0580d49a0e766bff356dfbfdd8e08e9ba24b48c7d84a7695a8d59fa2a683b417b7b844b2ca09466701ddc488df87fe97372a87957e9d6d8b1d693f1771f411b30c4bb60c33b8721bd53f0d74435c2ae2048be64dfad5d5a3de566e52b6334e34ca613fc187aa873c69b5bbe964566ab03e3047c92a8df13b2fc9dd5ca75fc1530c20a61ad739a6adb6d8c792f0001d0adb3a8065123fa3b41bbc7e52f7fd46196b5b7f50cddb461a892813b404bb6800805f1c647642e3e6faa9fb238c058fbd42bf7ba75d52b2fdc5184d0c2495a3512c636336900f26c6912bda1fb519f8107ca4017b07a7199f287fac6057acbf45f6cb315b6252bc469c589204ef2354ad586888c0e2781dce6fba6619dc37d506a62c6a93fa25ef4255842cb4af74fcc2be7db2fa991521467772f105336f76645b0eb7be20cf9b37244623bf93d0ffa9d1381978d4582fedee14c0d26dbac978c0098260ee25c07b59bf9970ae6eba0003c7defad6383822c83481ca876fc758e0ed8926cfeb6745dbd6d1f93ba05d6f7f5d70c308bfee6f2e2304528c10e9a15d51915f9d3e6c4516c15565f867667df3d77385b5cdeb47f78f7ca7d71199e281a52a1adfcfb511a74f9164bc78ee5d962458926a76fbf4ae8b8db6038fb902883646cbc263fec145d44f0aab3d96969e3332a6973ed303b916abd0178aca760890811b56b18b8803600dd54c23bd0ecce71691a3d7eec24aab9dfac3c47a2cd9601212f94ddc3f96b697eb240cb12de6ccd7dfee1542676da9d6cff66d09c7ee4b558c4e72dfc6a41bcc6a336b7d20de6d354b894b3a74df83352bc1fd657680420e5981a8a3f54e2ce839e98edaaf959c01e87187556aa3958a81743791b6b4c9b3669de92fcdc80b7416faac2a5f9cf2aaa8d25787e1051ffcef11899a50b596bcb799c454290f2763772fee06db9e7293f3df5ba90053017788c15fde945ec60ce87493083264ec8af8f595b3b610e75233011989179f10ea0180bf7ef40412c3c285ae45fe2b19a03366f6f1e346ad617fa9569cafb66a6fa08804d86893e07c3674a49c0426dba1d7e8c56b032245389b91e156645e14fa5997d12c8feb67966b48e45f0b8786ea3fe3541b92ef1492076eb8ee0be0d95a1138e3826674b56b06d317036934249c07ca2620063f1f39059f4a254b3c9c384e9be7d560ce52c39a6e61848bb0fd2ddaf1d9093c7a25d461cb348b4c7d6be5b428a2b703329ea735d10f710a253dfc20cd8e948aa034f2e0b73e47d8e9a957dc5c93a9eaafc3065f93b9076500cd9c057eb4d5ae0444175b15523b6dbd64ee5390b20b0c74db33de03ab60692e066a10e9f10b4db592c2628229dda16ca9f4a79197447392e317a0ec08d267b703625ffe07bf90cabd1976faa1a89aa8b8afc3984dd02454364c1f99d6be9b7df28e03db1fd6140ab7f64777845b0b701134d5184b304c7819e8d500fb846378c7c08b34c25881f664f4bdd56211207fd7607396d0d5a0dff2699b8bf94b30660943ad2615adbb73eab4feadd7807c45db6f4513fd5fbc4fcc054e72099eb5746ff55e472430ff48e22df642886b9f095aebbcb1aa1a9d3106eea8f23f2aab32a598c8d9cafead4bd1599c7da4f1353c5bc41c0a0100493413a7e8427ae5efdbde19496d5bde3881f0adcc16cafd4374a1a22b83ac119a4cb8834c49bd1b6235c87c95243ea8629b08d82645ad1594fd188a07e03d3988bcca00c0b2bd6d526172dbfb21b51a8b408b7059c5b58ffe39e8e8494711a40876bce375fc01fad457de52c2d4467411e38a2c17d0ac3b78906efe2caf5696344c8fb3a8fdd4ad0e65384435a42960000830300077c4ead37561142ead7e8edeb59d2ed16c73828160dc7791fc4884b8031a61602aa5357a7001552652f554ebcf1c8b787500c9ac1e4d5f92aedd99f9b5c3b436ad3315123677372b6e3f080c5aa82b70350ae7976d203f7bc33de1e9429de8f4ec53d16b98779d4b10a437d9d44a66e14e6c1fbefdee87b88bddd428b8231f449fd4d0b602300000000000000016aa500ef0290b474589300ac5bb39f6632f8249c57256ca87309da9c18f745ec2f4fba32d3c0954940d8f00aa6e7ba51e388ccf9a853a9bd9a9de665c679209274b86ff64902b25bf8f34817f983ae92636044bbda21a5c6913e94636d8b5d2ffd8c07c6f4124692dc46bfef54381b76a5566108c554a2688db21aec4e5642bbf97b00c5d05251e74eea4e1f96a9c07c896556dc518f4f61069e001ce372e1448384359998fb12a8c656cf492a5bb598037b0a2aba001e7f94c4db09dd0a0d604c87ab1b1aaca23c4aee9fca3d6a195d887b00bb652dfd02af707eaab2385d86ae97d5067c1eec087ba705f6a4a1bdac83b7c78dcd135b2b4b72dbb367b7ad4c46f0cd8e2a0213d163ef46928584f5f26793a9930f898e364b7af18f4470e86ff4e01a39375682d45138e3eb636551ea675f749bf8a2b23676b4e13c85fef80e06830825b39300203241be31cfbc5c714590e01853c350a91dfdd96acf0f8b94e01ebd6ec487106dab6e69f558b3c6534aef85e7587384e939d666dd2018e0fcec38b6d65528ff4211129f275eb0f228b71eb0cfb2010508f3dab390e66b4a9c6992288470e777a3bf47b0f9f337f8630b4548c3777088f8797497a003324f440cd419e2c5c192e3ab8dafcbe4335c832a950b12cfa211fb7e46760846a120960a562c5df449ced2cb7cc92501fc9a771acee337f1cd3645867177e0b15f1178e0fb697442d308ce600a467866ca9a8aa33135481819189287ecff489b477af7337ae475c8cc3eb6dddb42f00b4fef384d4040c2fa7dfe902410b075afd05e87f6ae76744b581985c33d99364f56f29fb898142f6671b68d779908f6b3c8de1e096375e54384d10d69641989c70cdd44f08ddddde43b8e0da38d1e418d371a5f5851c716de8aa4d48418055dc3deedfa0a94aee55c7b253c47417b3c7397fa8b6004173f19f481629e4b762818eaf0cd89f4fd098e2ceb89227349f030189a5e01ee47b86a952f4a50597a94881f0ba8d4d41d646ad1e55c696c1d2e2d6fb8dc35d27a9c4e58445fb8347300881a5fd3bb7b39a3110e7de09764dd6f43602a1685ca3412cfb87b72cb75eed61dd46095621d30d7a0a17e246a5562790c47dccc1040a2aa5037572f29fd5811708841a13adfd21e603931cb5c1c86f5701426f708132daa25065ed5c82bfcfc623e796807980626c3e62017fc46f9fdcae3f4988e29ffc92a56db9324c07dd06b43556dd2fbf552b3240032f966cdf7227cd9e0557d4b577583a8dc2b87b490f65bb375532858062552a2587e0a6decad9377723a68478f1c4ce89c820967bec05e565e2af9e073f7992634da1818ab27b3927d0bf6fbf3dffd476a9f60e2a48955ad271b4dbe1364a87b3bbdffdeb28a79bfb089041ee85d5758fbf2e33e95ed34e31ad83031c78c9711a12d25a7e180fabeb5bf71d6bbfe092cb55559391fbe0886f9880cf38e0aae451992d73ab0707ca14130bbd4009b84944d4a31f721aa821288c0cb515d776817927877bb9ae919389879b24b122692eda38283955d7e7e23798fc0140a64a6118fec05175960aade3211442127d66f3537d774d552819dcda4ac0a543e8ed5c2963dedbd6e523b0e07ed86e451c172dea331f25a2b69a0f4eca6e9af0766290b3243916e6cb14cd642815b82ab1a3c4ed3e8e0e6f0ea81b4339df432535c198802c014b39ced12d205a425402469ecb65377ae8ecf6e07d06a432eb085e49d0842b2b4130482bdbd80750adcde3b7ecfe0a038f443735bd3fd9faf860958b70c140aafc91bdb267528293fad46db2cf529a0313f76993e63daf4c30c8b7514c54bfeae128e45e4d07485758e8ad130e2021f4569ef085ad771e0eb39696694e4234c871fd8026b9140ea8c8b7afa75c165384ce1eca47b8619095e749905cb8755fec7f5d0cfff187fc3fe4cfb2f355fc7399c905d82a5f8fde8a351e896ac05c1e17bb1c8f18a9e715f46d64fc13ee46c623a40bdaf230d466f6ee051f5698b67aafb8eb5803021c720fc2b6270317c4ef72208d95be0eaa108ba00b94b852fd3c72550bb816c9aad9f19b9d94f06954907207edb5703d5f542c5a5a5b49547e424517d2c5f2971a712f463662ed0e1b842b8c3524420df54885e6fde39c0dddc700992ec7b3caca01d9b584086e0e1bd3c49bb196f35bf50bf422ab1f7e6137ab30c21dd9ffb12d1f357bf3799bffa0ff10e40191c1f46fe272a06aaa7e6c113ac5b12cbf81f5484e1320ad8a0fa9b353a9be9fcee4a15d7040367f3fa1956c453e124c564836921e5c2009e8d270fdae2a75679ef38363bdafb7518f9bc199f565eea2375f479c79d800bfd19ae4a6e871e8d36c265bbfd67e4c7e1be91db81dde7ddd80b6e979dad6058164085d09280c846470b3dd04337bd6c571b6e3a009140b2ee7eb426db59d400d502e8eae1789e3d501d300d40e0c2a1537f34e84f7ec466b7816494068e806ea04120dacc28c30ebee2155574655f045ef5c143f05787ffc8d3a38955fc8d1e98128bac1524af08c3f843371b7861341f9e601764efc890c1e16ff8d86b96ddde4e6de03b1d1508057597b76ef276a5533accbb9f36ef618b508a5a022e2e28bce9fc4633ca11c512a7eaee6dd3abd49c982d9ace67798ad2f56cef370da796c61f02c89dfbae87e8fe095cbc4355cc18127f0bcdf97bd9d36e2503d562d5cae29106eb2936b28f293c93972678537dbeb47b9ddd7335d9de68a09fe4db30b111c9bfce0543f990fd9eab5efbb54be32a9958c4d1c4df5678b6445304988baafce19abc43964b1fc215e76ac03d737883a722523ea43b6de6d13fc45637064186f32d7797be95fdecce91b0b93d5e68b2420d3d477296af0e328aa031d6258c14365bd8061b1d1b82a86e9c6f298689b83736ad29bfb6436f6561dc5953f5377545c47033c1e91b4caea84beb1777315d00326edd5e3cdd346be3dcad3013507c5aee3214ee9eb7ee2322e95866cba3f6d64eefc1e1026adc4ad117182a450ce0eaf19b51457bb0e7638aeb26ff39cfbb33a27d4bd8b0ed715d8431816eac381a86d2856c834d7b5c68849156377aea5e96e6189a2ef459fb746713f2c5c43199d3b9481576929b3f4a87a210063ac45be2cd47154b1dbcaae6d021f356c6156f527e74e01beebe4e36d4e340917f21ca8a0314468df0292009898b6e5650c8f7397d75ce9a41344b6b23698055da8187ab7260bb2d660dbaf24eee20b70bc62db90e3dac7eaed30bb5e1d9ce8b9c638c08c8b032ccd569c71ec0c3e4a4135c4e5d0b1cd0f75c8909e3718a3728048a39dc7bcf6d638dc1d4bb2041f2fef90c680d294273b52c59b8ac70c4b54e691b2e772e409d71ff5a513de477f68e161863ba3b3ac2eff04952b9383799141251a094daafad2544631907e31b1bd50bfc9b4c09d1b86ca13ff23bc3e185ae6990baca356d36a6e3645c85568fe1f8bafbf31409bbcee0a601f5cf9e45148863bc36238e48538715419981b8d09400f71eba893ebbb8ef99c888147d739201d5afb21de99e77f76928a55d32c3a2c98a377ca1dc02432fd45a63d8637fae1b658fded2e96f91e458e6273b7ffd3593de87c9bfaba60347e610924bcd90f44c488f1fb0e6962d2530294c354ffdb4f56b6f568285e676e7fcd30d7482934f1645dabaf276e3340f0be1b3b0329fc53f64b6240e036e10a54af437b4c453c8fe20b5c972ab09f63924a6263d2fd464a2cdb2a5404536a4eee536c4b4ef9c5a18f7156b6fca427a09a8229a170d4063353105e8b9a1014c998ee65405fbac8b20463fc2a55aaf025ae962f5e5140f7157259619ace3aef2b11f4ed654055f4fd3b9a8829e86b8e4f8454563b843db50ba6d7e7e127152642a93fd358e8e6a0402f639fc7b3f70c3b5de2130b81c1655db80501ab9cfb7c0a34ad67cbfe87abecc24433ed90956583db8a7b1178c5fd689df39a0faed32578cd67fa59e958451dcea04a2e2e7f6c7f9109c3fb31037228a51825f02275fbe34a7c92af7e8ddf0de890b1a3290158d0e50a7ed4d672aba2e5a80830300079d7342edc8e4f367c464c673082612688fa916f3d71496950e595ff7c2ff54c04478a8cc525c6d9137c9c05a38253793b3bb1c78b1a8d7f4d08cb8bfeca7f60a266157782ec8b03327c180ebd90d1def2f7ffe88d4ccd008ef3f78c3e32fa33cce6ba6531ec884059d611d7f1366f113ccd90f2f3603f691531c4b4fe90aa930fd4d0b60230000000000000001639f0085e8000b3aefa7f690e47785875d9c8e3f6b18b022ede2c86338401206e88bcde9eaa7524a7663cb52cd50f2f81a00c852d1073e5489be1688183a3309a22b9c1ab0c8dfe1c3b754ad8d0a261ce2296c56eba270902a6e60abdd21dce7486a211e76cca1812b2e9347f95e1dbeaae4d56eda8264e4c8b24802e73e43f17e9ad45f0e3156384659da11b2ec87b523df35e1079e3399ab0ff33e04d0008ac8c019d2eb678b2e219680120a1e9c0b01017f12ce88597abe4bb9719ae9fb3dfd06f03f010cb540b022353f209ca8046e76d506cdfa7c99f01a05ff233a139bc34c45575c193da15ca683a5fe8e77fadafbaf6e5bf07100e426b1e142e42f9fd8f4e5344d052311d85ba0eef2f2df69e74f478487a25b894b017c47b421a917020fc9013c458aefd2b7bfd6d5f5e94a3403a82d90e3634e28a5c1610dd038f0b60ed9f237d7dbc41cb5d4c580b9f3e8997e04c29c57a52851d1ceb45f38fcedd08d219cfa165e1e74d96a39109d1cddc29183bc8c5c9ed7678e42408d8c72ffbb217534d28833e84277a1a6943721bf8629279050fc1a9aea75a730191906b0c05691b7d8dd9f87763d5df7606e9992742487e28e67f58765b8fa0ef4034bf7f8653934604c5650851f6bb10b2b379146ed6e83d1e020d4b2d7f670c16727f5bd091619cbd90ddf0669bc6ea01a3770fddb8f7f218a518defb531e110fcb5d28599c6816bfd7e261b32f7792a08f5ee6a4f308f95092ae55a3a1bd96872a5b06f9bd198e449c8cb5fe6d88211d512ff9d491a8fbd3d6aafaedebcf6d2c9d945c566347380342d48ac26afad49c0eadb3dbaecc1dd61ee13ba42059b40367fbeed476460f9686ce92089c734e648df3bc13a6bf58c6e062f244575bee5821c42b17b68c9bd3c1f74012cbbb8f702530fc1facafd092458dfaa760781f2761943266fb7eed5318d3dc48a6384e2ecab5290244b8b09f14147f734839fc352da11f0b38d619353e948485b4fd9112a1e13e09c6b3316a89280e803d1e3ec0787b8d16c8ff24a9267ee9ac73e8471b43ee01e4b848b608393ff8a3d6a352d8b5b56858b13ae07a83121046873b0adc50379464f0ae8b02f297282920222bb2b56fb0be1d2bbf44d2de42b8d0200f1add66d07ee672ab821dd1b274bf3b645d2b06e1043d5ef44237188278a76cce834729f9d66cc5ba8859735063d4c2f0bdfc569a2c90c0aea8a5c00f5c3df13a8cbae947b2acc5357209e3adc34c04cef2c11ad9f869289a31478c23a4737468d4bee26e5b45cca9d6a454fce837c75c3834082d657480df08143da06395a0180aa73d5a8f6c217aac5ca22b9b1a7a3e64c5a54e8807c41d6f0049728f8a86ce51be606f1da6dd777241e8474515ce6529ff755c7c7d7fa0054d1d4c3492dcac5da8dcb1150d7379734601c3d8d28863bc3d50cf64699dabd264dfe036f7200b348bb1cecb55ef0916b0c17373ff1205e2fa7bbcfee219fe27e4000c613b804dfff10963e48b0b27d9a5c7a6897ee86c4c77cd417ac1ca98415e647feae14115cacb9862a6693bb2c3b31b026b73950308bfb986b8e5f7e860d027df6c9fce9d7c39fc23cac49e4c8d3e07ad2b67a7e965a2b7acec4f771b8b46cd49a7971f6588958ad576afcf34420bfc7bf2827fb130f0d0ae3804f0768fac870cda7cb902638f4fd782f3161537b9e33b9845812ab2a8a0b1abd5daa7aaa218c32520f82a31e9ce6f645642a7309bfaac28a945ddda6fef5484412bbfd07a87f813c5c4ee344cddd81de0b7bfcd1d8e7c2762ad6f415d61dd51e7abe6b17f8138abbb743f5c3029d2b793a14391758a002456bfed2cd68a47822bd16ff7473a82440f4308bccdeacee047f1a429ec7ea8c0a237b35c737d8ed4526f726040ff8fa84d4439095061686500ff9559f16469fd1a66de17c9b8481d0b3db6a9811045b5e5757fcf9e128f03449e6018ee11e6c5a41a9cceeecd1ab9d8a81b34db02aec7f4831804dc1bd0b13d0cf62f2134dff3755ac741e9d789a6f38469fcd00967104e31a1aeceeaf49d63909623b7160fdc4bafcbe1536bf6f43e17b6ffee3dcc864a8c1ef7b437ed39fe2e54253c26d236da82837937042f36f68ef7bf0970cbeac3689a2ff2b2acc57f6d76d634173ba4a636b9723c5ee3852ac4f153e752b0aa17ee71d1365e45b1177f77647a02b1d6f92e386899c64ca1de46d0b34a8fbe1ac3ad8ee75c3dafeb3374f13253eb2a5fb7649a0e9ee3af265301043f22658529437c59e3216e8999ee1298597c26b06360e86b36a28d6fd07b6f837e610530e78c51e413d949c1b8bf687900d51b82fc4d386ec3a9c73aa6276954ac8d7f7273b5a945f7f59cd6ade841d5d68f7743e95ce1a5e351f46bf09b5fcd08409e315888478bd3c4788611185dc81c867ac679f006adc4b060c4a9b17d0af66068ca9a75dcc898ab3655d1a90c9fb92ad54823a7c4c15baa601ca6fc89811b1c619dc61a2a574ce9d45dac75af2600dd042f0679b54effc4c3796b59741ca0765d6d3edd62c1eca4dcc969cf4231273814b8beee07b0664983fe8b9c31b8efaeeefe04b03d7ed608c69cd4b0ef53556bc273f9dc7cd99421c2bca9b8e8a337dcc0aff7a8bb73a29ba2fc77f31476e42b08274c0f37a149a85cff9a49adc3d889812d60c7b8620a929aded40c6a3a0823e23904838de49cecae28088da02c3eb15a020d418f79c5f021484362accefe0dd992969bf4f378a7a512bfef8aee10adbcf3a5d91564a1ef4e0c3161ff2c75ec42a88635b1846ee36fde89744b3182b63794a7a19694605b16f8c5b048015bd9728f46ba9987637f0e8e9a68cac418a35fa9beb6a4e17c30dbed9f6b2453b3384dd2e008ed54e661e2181946b2d7a0bcee5bd9c447465e397fe7fc3373a9e8e0ff735f1eed5130f3c0211701223214e26559f05fd638fec803fa8658cac11fc5fba6ce4710e5281fd2df7f7179774744ed22ffde7d9b966343d34f927a85d885755a6d2676e76a7556401af667654b27481522c9509f76ecc474909c16cf90dff9c40f800461b616e8d1eda757a719a6afd9b54c3e2f8008118e7df8de8b384122a22e0479e24545305b640cd4421f45731fb31809624e123102866b2f93dbfb72e0a80e944ba1bd09af52e4cdf3e49c7e2d8b99a701b8616ec9d89735e928f61de7405da07707eadf4aa82fd5331dbe82c54e99aa502b71dfa578dd9c7b84ce06f80721c349c822654ea5e5ce62bddef81c0844ea2b33eedb1ae564f5144e7abebb2ff914325f251d9eb83ab88194769094c950f205bbc6018c4e9c608d43874abc6b6e36c75e309ecbb0bcc7a904d0d05726a4bbecfb9b3da6518cb2b40bb5f18888812f1f0c3158ae634298c3376f010c1e0bad7dd242328e7660105c633a1e6e5b0aedc4a3630d40b4c55a12ca2cad0c4fbe4be8f93af7575f2cf104a5f7d2d5996af90c7c643dfd8fa36b4fe497096c5eea26e16ff6364b364fc78bfd86726c56717ccbfaaeeba44e6e8527b92d73d9a132c507c13c73bb93335dec31a09d4d74d652c340ffd80860572a48f1735334b3672fc5ad30a6a05e1411cadc442bc8aa79ec48f1c6a7b64c4fb1d519df7819b1e753856baa70d806da054b4cee7369320621405b0a9613cf3d6448210b6388b696e36cd7603b9c57256d22578c88d4ceb07f580c195bcf93791ba3ef41f8b2821f49589c5db205563f87c27331b1b759f1120fd2bc2d035a471e2cdf49cabe20fa55b9343e3a6548d2b552d3c70d02bb596abebe23022d33acf94f03c38cdc4e00b9c59bdbacc92daaf8c14497d84cc6339cf46768e4133c7db68427df2b6bff030854b650f180261f0011b90ce0749ae32d485f978141a5f247b13a34e78f77365fba462db7ac7cf08b9866110c92f4df64779fbd42c12dd56506098a092be6507d53239f25547585c66c2871b77b8181f00c4d0dff8d98ddccc39e74038800516cf707aca21c1bdb1c0586b986911a519ce33cf0e2b75276d65b447c2c3c7fb00a13f9915d22616cf6d812dc98744d536f8dc9d9c650e5b82";
  const char* request_json4_format = "{\"hex\":\"%s%s\",\"network\":\"regtest\"}";
  const char* exp_json4 = "{\"txid\":\"1afaf39a618c90915ecd8c5ff7f8f6699dcf6d87012ed80a1a611d969b9fe8a8\",\"hash\":\"a1d828745c18c4e34efe38962a6ba6d6c109abdcc591f41020e4bcc060747668\",\"wtxid\":\"a1d828745c18c4e34efe38962a6ba6d6c109abdcc591f41020e4bcc060747668\",\"withash\":\"97dc71ad61bcdba12d5a34bbfd6dd76aaec29af79d46c46bb2b16c7e705dcd0e\",\"version\":2,\"size\":15588,\"vsize\":4361,\"weight\":17442,\"locktime\":0,\"vin\":[{\"txid\":\"b45eed5fe74c03550c98b5fcc40da59af8acdb6040673214a659edeacfd70269\",\"vout\":1,\"scriptSig\":{\"asm\":\"0014bf7f6fbc324728d857801e7f3eff88cce289cf25\",\"hex\":\"160014bf7f6fbc324728d857801e7f3eff88cce289cf25\"},\"is_pegin\":false,\"sequence\":4294967295,\"txinwitness\":[\"3044022036503a4f4c4a2e65483c0e762b561e6b267db0c498bfcf2e51a8cd8844015e88022031e9b44468cf9431f1fe74f60b755bb1e273ae462bc4024c097c01aeda7847bb01\",\"02ab849ed2b1e6f6c558d74e5c5d49d160c00afb6d7abd5b6c76024b3a85a6a5dd\"],\"issuance\":{\"assetBlindingNonce\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"assetEntropy\":\"8c5bc0c2dc91f984b67f3de7947670994ad3892c5b371aee14e7f9bdce8c19d3\",\"contractHash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"isreissuance\":false,\"token\":\"ba1bb82eda07d84e28fbe1d12a113654b013ad430645a226632e253ab371ee2c\",\"asset\":\"b177943d21009b0c19c7c0610a110612ebb2d37932c1e0783a43e5ea07d2d69a\",\"assetamountcommitment\":\"092ef327afc62b0749826df12d34412566ec1743f75ee421b4e4440f0083bdff8c\",\"tokenamountcommitment\":\"0883321b72665e9844cdb8859a743583ac18623cf6b78e512fa291912320419104\"}}],\"vout\":[{\"value-minimum\":1,\"value-maximum\":68719476736,\"ct-exponent\":0,\"ct-bits\":36,\"surjectionproof\":\"030007028daee23a0e51b165be98fc15150972f7f95a09ff050b9e95ba3c2f813293beb1e7fc051fa28f5a8a34cafc3d7e3b5086e3f256a70e1ddc6d9c6ef9c927d3a4e2b2b81f73f27137d0f77b72987d8d9771627abe02b47006b9eb95fe534ffa574798940f1ab429d1199fdacfff19ca08473685e70b10c7e643918d8c2924752d\",\"valuecommitment\":\"0880596e89690a32299914da0a85fd57db46575663968243b3ba5b1ad15120c402\",\"assetcommitment\":\"0ae7be1f8a5aa41a98a0fd5ad39efdcc3f36a63adf5849836b08aa622ea65d25db\",\"commitmentnonce\":\"034a6d652db056e0364a0eb997821d62266da79409d995f9d39d011ba0daa59982\",\"commitmentnonce_fully_valid\":true,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_HASH160 72a7834df62071c0bcae9e00b00cebef505b0cf6 OP_EQUAL\",\"hex\":\"a91472a7834df62071c0bcae9e00b00cebef505b0cf687\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XMoUZ1ntkntsvw3BHHYCfK56SaZn4SVaEk\"]}},{\"value\":10000,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":1,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}},{\"value-minimum\":1,\"value-maximum\":68719476736,\"ct-exponent\":0,\"ct-bits\":36,\"surjectionproof\":\"0300077c4ead37561142ead7e8edeb59d2ed16c73828160dc7791fc4884b8031a61602aa5357a7001552652f554ebcf1c8b787500c9ac1e4d5f92aedd99f9b5c3b436ad3315123677372b6e3f080c5aa82b70350ae7976d203f7bc33de1e9429de8f4ec53d16b98779d4b10a437d9d44a66e14e6c1fbefdee87b88bddd428b8231f449\",\"valuecommitment\":\"080e7d14989746f3c5d3cc4ea1c651731e9c375e71d487665a13ec8ba104b14f44\",\"assetcommitment\":\"0a364d73c6e121fdc4ea87a0228180a521be1e03c3b287435dbd06536ac6bf4770\",\"commitmentnonce\":\"025204161081bf96756531f5b8b00d85f3b831041be2b8bd108a48ffb44d9f014f\",\"commitmentnonce_fully_valid\":true,\"n\":2,\"scriptPubKey\":{\"asm\":\"OP_HASH160 17514a45caadd530f301c13faae6003c4ba1cfc8 OP_EQUAL\",\"hex\":\"a91417514a45caadd530f301c13faae6003c4ba1cfc887\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XDUXmhD2Pd1GHDYEeZtr12r2mz1iAvgZmn\"]}},{\"value-minimum\":1,\"value-maximum\":68719476736,\"ct-exponent\":0,\"ct-bits\":36,\"surjectionproof\":\"0300079d7342edc8e4f367c464c673082612688fa916f3d71496950e595ff7c2ff54c04478a8cc525c6d9137c9c05a38253793b3bb1c78b1a8d7f4d08cb8bfeca7f60a266157782ec8b03327c180ebd90d1def2f7ffe88d4ccd008ef3f78c3e32fa33cce6ba6531ec884059d611d7f1366f113ccd90f2f3603f691531c4b4fe90aa930\",\"valuecommitment\":\"0839ece197daa1568947778ed05f8d499e2ecdf326155a93a8052bbcb591356edc\",\"assetcommitment\":\"0a9033c37f8d1151b8b87c003dd2b2ead5f85e3ca32340e9768a80ba5a840f9f4c\",\"commitmentnonce\":\"03395b4c5090e3fcbb0c5c2b258af7d078a9d4683d33d7905fceae7f0f70335115\",\"commitmentnonce_fully_valid\":true,\"n\":3,\"scriptPubKey\":{\"asm\":\"OP_HASH160 b721bfa4e90777607c95ad886362e4870ef6072c OP_EQUAL\",\"hex\":\"a914b721bfa4e90777607c95ad886362e4870ef6072c87\",\"reqSigs\":1,\"type\":\"scripthash\",\"addresses\":[\"XU3Yw9KwUPSu8mi7pCrhEvCNeDN2eyvRbf\"]}}]}";
  char* request_json4 = static_cast<char*>(malloc(50000));
  if (request_json4 != nullptr) {
    snprintf(request_json4, 50000, request_json4_format, request_json4_1, request_json4_2);
    ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json4, &respons_json);
    EXPECT_EQ(kCfdSuccess, ret);
    if (respons_json != nullptr) {
      EXPECT_STREQ(exp_json4, respons_json);
      CfdFreeStringBuffer(respons_json);
    }
    respons_json = NULL;
    free(request_json4);
  }

#endif

  // 'ElementsDecodeRawTransaction Peg-in Transaction',
  const char* request_json5 = "{\"hex\":\"020000000101109d857925ebfb477c6e6e70069814f279e4a6d871af9165631df4e5982e22710000004000ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a010000000077358c30001976a914552a03dea30398d12253bc348d7a953097c00ab888ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a0100000000000007d0000000000000000002473044022078176d9e18878b104d01842a37f08dfb91d0e4d524fb1d414e1c164e4c1ed4e602202d18a9e8de65394c6ad07bfbe222800e7ad1374f99bd12cf04f8b24278ead21c012102e2de73578862dd68719a14a58875760c1c895b4d9bdd38ed28d8f4eef816249c060800943577000000002025b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a2006226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f16001482d28f5ef4a48ce456c58d27302443a91e7f1413fd030202000000031f2e6a4d988c25d56107d6417936572cc32f7e31ab741378ec67b7f0e01dc23c000000006a47304402200b801b1af2f55795f536eb8d9d67615ceed50181f30f9f4cf8907d4c2b6a6cbd02207998d94135f457682cd17d8bdf1b02daecbd1e71aed930e4fac184ceec390927012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffff814418da01d2521f972c5fc06a4d6f5c7aa0822572cd3e7332ccb25da68c4882000000006a473044022026ad74d9b7423fae91ed67c6512f129307df3cdd053aa820b49390a05075cda70220262f8c8c5b22308fa2684e7b42235fc8be2fe689e8bacc27c0fbcb4c2c0e3bb7012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffffce47f1793f0f6685e52ff5e34cca7f3781840d8bab89aba68cef8570c3073c80000000006a47304402207e25d95ce4727ffec558586f69f41b00360b069122eb8c8ccd132b6cbfcd0df5022039c0e9aadd00c5a83a502beb82dc200018a8ae42e4bf00fe09ad83fa9b975c70012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffff02009435770000000017a91472c44f957fc011d97e3406667dca5b1c930c40268714aedc010000000017a9149ebd22cf651def59eed1cbc5fc74bcdb9d7e1e8887e803000097000000204e28f541a3b2400720e1b7034c037e98e4806deb13f93927bf325eea3bcd5436a701767035de031ba3471b589ea214b54f0baa26d1118d2fb13a679f7b4b472e71128b5dffff7f2000000000020000000237f9a1552febc7194d5fac93e52a10dde4009ff485fbcc172b22d621b58c2d69109d857925ebfb477c6e6e70069814f279e4a6d871af9165631df4e5982e2271010500000000\",\"network\":\"regtest\"}";
  const char* exp_json5 = "{\"txid\":\"891e3a2496a7f9a79adcc5bd17a8a9cec873b8d30c433c2547f7c4d71a52b72d\",\"hash\":\"0469c54924873a582f5a81dd35e44e2513b146db8678b2a10e6b6619a97d4745\",\"wtxid\":\"0469c54924873a582f5a81dd35e44e2513b146db8678b2a10e6b6619a97d4745\",\"withash\":\"129bcf5c8b38a1cea1971314bf046d740333d89afd4d5a52c14f6b72a93f13c9\",\"version\":2,\"size\":1047,\"vsize\":386,\"weight\":1542,\"locktime\":0,\"vin\":[{\"txid\":\"71222e98e5f41d636591af71d8a6e479f2149806706e6e7c47fbeb2579859d10\",\"vout\":0,\"scriptSig\":{\"asm\":\"\",\"hex\":\"\"},\"is_pegin\":true,\"sequence\":4294967295,\"txinwitness\":[\"3044022078176d9e18878b104d01842a37f08dfb91d0e4d524fb1d414e1c164e4c1ed4e602202d18a9e8de65394c6ad07bfbe222800e7ad1374f99bd12cf04f8b24278ead21c01\",\"02e2de73578862dd68719a14a58875760c1c895b4d9bdd38ed28d8f4eef816249c\"],\"pegin_witness\":[\"0094357700000000\",\"25b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a\",\"06226e46111a0b59caaf126043eb5bbf28c34f3a5e332a1fc7b2b73cf188910f\",\"001482d28f5ef4a48ce456c58d27302443a91e7f1413\",\"02000000031f2e6a4d988c25d56107d6417936572cc32f7e31ab741378ec67b7f0e01dc23c000000006a47304402200b801b1af2f55795f536eb8d9d67615ceed50181f30f9f4cf8907d4c2b6a6cbd02207998d94135f457682cd17d8bdf1b02daecbd1e71aed930e4fac184ceec390927012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffff814418da01d2521f972c5fc06a4d6f5c7aa0822572cd3e7332ccb25da68c4882000000006a473044022026ad74d9b7423fae91ed67c6512f129307df3cdd053aa820b49390a05075cda70220262f8c8c5b22308fa2684e7b42235fc8be2fe689e8bacc27c0fbcb4c2c0e3bb7012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffffce47f1793f0f6685e52ff5e34cca7f3781840d8bab89aba68cef8570c3073c80000000006a47304402207e25d95ce4727ffec558586f69f41b00360b069122eb8c8ccd132b6cbfcd0df5022039c0e9aadd00c5a83a502beb82dc200018a8ae42e4bf00fe09ad83fa9b975c70012102157ef1d64a94052ef3df4862e32f5aa922cc96d83ffc74bc640b0f6dedcf344ffeffffff02009435770000000017a91472c44f957fc011d97e3406667dca5b1c930c40268714aedc010000000017a9149ebd22cf651def59eed1cbc5fc74bcdb9d7e1e8887e8030000\",\"000000204e28f541a3b2400720e1b7034c037e98e4806deb13f93927bf325eea3bcd5436a701767035de031ba3471b589ea214b54f0baa26d1118d2fb13a679f7b4b472e71128b5dffff7f2000000000020000000237f9a1552febc7194d5fac93e52a10dde4009ff485fbcc172b22d621b58c2d69109d857925ebfb477c6e6e70069814f279e4a6d871af9165631df4e5982e22710105\"]}],\"vout\":[{\"value\":1999998000,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 552a03dea30398d12253bc348d7a953097c00ab8 OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a914552a03dea30398d12253bc348d7a953097c00ab888ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"2dhC4A5w9p4vvaP1cQgBWL3QyRaFRhVAZGk\"]}},{\"value\":2000,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":1,\"scriptPubKey\":{\"asm\":\"\",\"hex\":\"\",\"type\":\"fee\"}}]}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json5, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json5, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;

  // 'ElementsDecodeRawTransaction Peg-out(Unblind) Transaction',
  const char* request_json6 = "{\"hex\":\"0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b2010101ffffffff020125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000b1b2001976a914370b9f298b2e2a9d8751bcf1a78787148fd5372d88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9edd591f3570cdb19344a1cca79de32d6e0e8b15dac7764dd47d3b30824c7d753ef000000ff0000012010000000000000000000000000000000000000000000000000000000000000000000000000\",\"network\":\"regtest\",\"mainchainNetwork\":\"regtest\"}";
  const char* exp_json6 = "{\"txid\":\"c020c2aa43e815f9ce01f6b2d2b55a824b77a1131a0fed93374e41780f4f9e81\",\"hash\":\"c681532901606b224fc9d557fa575ab28e411ff8003acfc50c79c63362c3308b\",\"wtxid\":\"c681532901606b224fc9d557fa575ab28e411ff8003acfc50c79c63362c3308b\",\"withash\":\"f150819cebd18e742bd70158fbf154dc6ca75b445141c87e8492bf48b758e628\",\"version\":2,\"size\":249,\"vsize\":219,\"weight\":873,\"locktime\":4278190080,\"vin\":[{\"coinbase\":\"02b2010101\",\"sequence\":4294967295,\"txinwitness\":[\"1000000000000000000000000000000000000000000000000000000000000000\"]}],\"vout\":[{\"value\":45490,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":0,\"scriptPubKey\":{\"asm\":\"OP_DUP OP_HASH160 370b9f298b2e2a9d8751bcf1a78787148fd5372d OP_EQUALVERIFY OP_CHECKSIG\",\"hex\":\"76a914370b9f298b2e2a9d8751bcf1a78787148fd5372d88ac\",\"reqSigs\":1,\"type\":\"pubkeyhash\",\"addresses\":[\"2deSoUZWZf2PzSnckYHUiNsaE3V8WKwkEzC\"]}},{\"value\":0,\"asset\":\"5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225\",\"commitmentnonce\":\"\",\"commitmentnonce_fully_valid\":false,\"n\":1,\"scriptPubKey\":{\"asm\":\"OP_RETURN aa21a9edd591f3570cdb19344a1cca79de32d6e0e8b15dac7764dd47d3b30824c7d753ef\",\"hex\":\"6a24aa21a9edd591f3570cdb19344a1cca79de32d6e0e8b15dac7764dd47d3b30824c7d753ef\",\"type\":\"nulldata\"}}]}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json6, &respons_json);
  EXPECT_EQ(kCfdSuccess, ret);
  if (respons_json != nullptr) {
    EXPECT_STREQ(exp_json6, respons_json);
    CfdFreeStringBuffer(respons_json);
  }
  respons_json = NULL;


  char* str_buffer = NULL;
  const char* request_json_e1 = "{\"hex\":\"0200000001010000000000000000000000000000000000000000000000000000000000000000ffffffff0502b2010101ffffffff020125b251070e29ca6c95a01000000000000b1b2001976a914370b9f298b2e2a9d8751bcf1a78787148fd5372d88ac0125b251070e29ca19043cf33ccd7324e2ddab03ecc4ae0b5e77c4fc0e5cf6c95a01000000000000000000266a24aa21a9edd591f3570cdb19344a1cca79de32d6e0e8b15dac7764dd47d3b30824c7d753ef000000ff0000012010000000000000000000000000000000000000000000000000000000000000000000000000\",\"network\":\"regtest\",\"mainchainNetwork\":\"regtest\"}";
  ret = CfdRequestExecuteJson(handle, "ElementsDecodeRawTransaction", request_json_e1, &respons_json);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);
  ret = CfdGetLastErrorMessage(handle, &str_buffer);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_STREQ("transaction data invalid.", str_buffer);
  CfdFreeStringBuffer(str_buffer);
  str_buffer = NULL;

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}
#endif  // CFD_DISABLE_ELEMENTS

TEST(cfdcapi_common, CfdSerializeByteData) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;

  ret = CfdSerializeByteData(handle, "0123456789ab", &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("060123456789ab", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdSerializeByteData(handle, "", &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("00", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  const char* target = "111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd";
  const char* exp = "fd0401111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd111111111111111111112222222222222222222233333333333333333333444444444444444444445555555555555555555566666666666666666666777777777777777777778888888888888888888899999999999999999999aaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbccccccccccccccccccccdddddddddddddddddddd";
  ret = CfdSerializeByteData(handle, target, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdSerializeByteData(handle, "", nullptr);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  ret = CfdSerializeByteData(handle, nullptr, &output);
  EXPECT_EQ(kCfdIllegalArgumentError, ret);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdEncryptDecryptAES) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* target_data = "74657374207465737420746573742074657374";
  const char* exp_aes = "752fe203af4a4d427997e5d2c8b246530e0546b66d2982a49e333e77295dccea";
  ret = CfdEncryptAES(handle,
      "616975656F616975656F616975656F616975656F616975656F616975656F6169",
      "",
      target_data,
      &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp_aes, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdDecryptAES(handle,
      "616975656F616975656F616975656F616975656F616975656F616975656F6169",
      "",
      exp_aes,
      &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("7465737420746573742074657374207465737400000000000000000000000000", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdEncryptDecryptAES_CBC) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* target_data = "74657374207465737420746573742074657374";
  const char* exp_aes = "2ef199bb7d160f94fc17fa5f01b220c630d6b19a5973f4b313868c921fc10d22";
  ret = CfdEncryptAES(handle,
      "616975656F616975656F616975656F616975656F616975656F616975656F6169",
      "33343536373839303132333435363738",
      target_data,
      &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp_aes, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdDecryptAES(handle,
      "616975656F616975656F616975656F616975656F616975656F616975656F6169",
      "33343536373839303132333435363738",
      exp_aes,
      &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(target_data, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdEncodeDecodeBase64) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* target_data = "54686520717569636b2062726f776e20666f78206a756d7073206f766572203133206c617a7920646f67732e";
  const char* exp = "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIDEzIGxhenkgZG9ncy4=";
  ret = CfdEncodeBase64(handle, target_data, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdDecodeBase64(handle, exp, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(target_data, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdEncodeDecodeBase58) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* target_data = "0488b21e051431616f00000000e6ba4088246b104837c62bd01fd8ba1cf2931ad1a5376c2360a1f112f2cfc63c02acf89ab4e3daa79bceef2ebecee2af92712e6bf5e4b0d10c74bbecc27ac13da8";
  const char* exp = "9XpNiCWvYUYz78YLbbNYoBMUef5GNJooCQ9i2nf9AH95Njpp4AbuEcmL5iVAwxa6LdR6FyRPeGFEmkFDr3KPGww6peFFtqtabW75Ush4TR";
  ret = CfdEncodeBase58(handle, target_data, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdDecodeBase58(handle, exp, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(target_data, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdEncodeDecodeBase58Check) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* target_data = "0488b21e051431616f00000000e6ba4088246b104837c62bd01fd8ba1cf2931ad1a5376c2360a1f112f2cfc63c02acf89ab4e3daa79bceef2ebecee2af92712e6bf5e4b0d10c74bbecc27ac13da8";
  const char* exp = "xpub6FZeZ5vwcYiT6r7ZYKJhyUqBxMBvzSmb6SpPQCsSenGPrVjKk5SGW4JJpc7cKERN8w9KnJZcMgJA4B2cHnpGq5TahYrDvZSBY2EMLKPRMTT";
  ret = CfdEncodeBase58(handle, target_data, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdDecodeBase58(handle, exp, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(target_data, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdHashMessageByHex) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* message_hex = "001412012222880A";

  ret = CfdRipemd160(handle, message_hex, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("5f4e6799b6d87fbf4cee7820b8a168b13225dbc8", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdSha256(handle, message_hex, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("7c90e7f25d3c26b098d43ae18cfc67e2d6c200f8acf8b16737c3ec6143e8ba8b", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdHash160(handle, message_hex, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("1097f123808affe262cc5b7cb6acfa84a7a61bb6", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdHash256(handle, message_hex, false, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("c6a3953d698f9ed23812c40bcf7aba724d66fbd9f771ffed8f5d6d2b4b267bcf", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CfdHashMessageByText) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  const char* message = "The quick brown fox jumps over the lazy dog";

  ret = CfdRipemd160(handle, message, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("37f332f68db77bd9d7edd4969571ad671cf9dd3b", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdSha256(handle, message, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdHash160(handle, message, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("0e3397b4abc7a382b3ea2365883c3c7ca5f07600", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdHash256(handle, message, true, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("6d37795021e544d82b41850edf7aabab9a0ebe274e54a519840c4666f35b3937", output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_common, CustomPrefixTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* custom_json = "{\"addressJsonDatas\":[{"
      "\"nettype\":\"testnet\",\"p2pkh\":\"71\","
      "\"p2sh\":\"83\",\"bech32\":\"btn\""
    "},{"
      "\"nettype\":\"regtest\",\"p2pkh\":\"95\","
      "\"p2sh\":\"a2\",\"bech32\":\"brt\""
    "}],"
    "\"keyJsonDatas\":[{"
      "\"IsMainnet\":\"\",\"wif\":\"40\","
      "\"bip32xpub\":\"0473e78d\",\"bip32xprv\":\"0473e354\""
    "},{"
      "\"wif\":\"60\","
      "\"bip32xpub\":\"0420bd3a\",\"bip32xprv\":\"0420b900\""
    "}]}";
  char* resp = nullptr;
  ret = CfdRequestExecuteJson(handle, "SetCustomPrefix", custom_json, &resp);
  EXPECT_EQ(kCfdSuccess, ret);
  if (resp != nullptr) CfdFreeStringBuffer(resp);

  try {
    using cfd::core::Pubkey;
    using cfd::core::Script;
    using cfd::core::Address;
    using cfd::core::ScriptUtil;
    using cfd::core::WitnessVersion;
    using cfd::core::HDWallet;
    using cfd::core::ExtPubkey;
    using cfd::core::ExtPrivkey;

    auto btc_list = cfd::core::GetBitcoinAddressFormatList();
    for (const auto& item : btc_list) {
      NetType nettype = item.GetNetType();
      if (nettype == NetType::kMainnet) {
        EXPECT_EQ("00", item.GetString(cfd::core::kPrefixP2pkh));
        EXPECT_EQ("05", item.GetString(cfd::core::kPrefixP2sh));
        EXPECT_EQ("bc", item.GetString(cfd::core::kPrefixBech32Hrp));
      } else if (nettype == NetType::kTestnet) {
        EXPECT_EQ("71", item.GetString(cfd::core::kPrefixP2pkh));
        EXPECT_EQ("83", item.GetString(cfd::core::kPrefixP2sh));
        EXPECT_EQ("btn", item.GetString(cfd::core::kPrefixBech32Hrp));
      } else if (nettype == NetType::kRegtest) {
        EXPECT_EQ("95", item.GetString(cfd::core::kPrefixP2pkh));
        EXPECT_EQ("a2", item.GetString(cfd::core::kPrefixP2sh));
        EXPECT_EQ("brt", item.GetString(cfd::core::kPrefixBech32Hrp));
      } else {
        EXPECT_EQ("Invalid nettype.", item.GetString(cfd::core::kNettype));
      }
    }

    // address check
    Pubkey pk(
      "02d21c625759280111907a06df050cccbc875b11a50bdafa71dae5d1e8695ba82e");
    Script p2pkh_script = ScriptUtil::CreateP2pkhLockingScript(pk);
    Address p2pkh = Address(NetType::kTestnet, pk, btc_list);
    Address p2sh = Address(NetType::kTestnet, p2pkh_script, btc_list);
    Address p2wpkh = Address(
      NetType::kTestnet, WitnessVersion::kVersion0, pk, btc_list);
    EXPECT_EQ("niAnB9k5NMVpeysW3VAzSMyw3rTHkWbrhs",
      p2pkh.GetAddress());
    EXPECT_EQ("uoruZ8Km3BeRgDHPnjHHPpBAC75ADUhQzt",
      p2sh.GetAddress());
    EXPECT_EQ("btn1qn98wsxje7xk68axrn979fuzqrd04880s8dr45z",
      p2wpkh.GetAddress());

    p2pkh = Address(NetType::kRegtest, pk, btc_list);
    p2sh = Address(NetType::kRegtest, p2pkh_script, btc_list);
    p2wpkh = Address(
      NetType::kRegtest, WitnessVersion::kVersion0, pk, btc_list);
    EXPECT_EQ("23CLVd4USvrBN6atcvbATtsnFi1jFJzBMWG",
      p2pkh.GetAddress());
    EXPECT_EQ("28HLc5VZh3n1b2ec5YjcARhcYhk4Q9x2yz8",
      p2sh.GetAddress());
    EXPECT_EQ("brt1qn98wsxje7xk68axrn979fuzqrd04880s345gz2",
      p2wpkh.GetAddress());

    Address reg_p2pkh = Address("23CLVd4USvrBN6atcvbATtsnFi1jFJzBMWG");
    EXPECT_EQ("23CLVd4USvrBN6atcvbATtsnFi1jFJzBMWG",
      reg_p2pkh.GetAddress());
    EXPECT_EQ(NetType::kRegtest, reg_p2pkh.GetNetType());
    Address reg_p2wpkh = Address("brt1qn98wsxje7xk68axrn979fuzqrd04880s345gz2");
    EXPECT_EQ("brt1qn98wsxje7xk68axrn979fuzqrd04880s345gz2",
      reg_p2wpkh.GetAddress());
    EXPECT_EQ(NetType::kRegtest, reg_p2wpkh.GetNetType());

    auto fmt_list = cfd::core::GetKeyFormatList();
    for (const auto& item : fmt_list) {
      if (item.IsMainnet()) {
        EXPECT_EQ("40", item.GetString(cfd::core::kWifPrefix));
        EXPECT_EQ("0473e78d", item.GetString(cfd::core::kBip32Xpub));
        EXPECT_EQ("0473e354", item.GetString(cfd::core::kBip32Xprv));
      } else {
        EXPECT_EQ("60", item.GetString(cfd::core::kWifPrefix));
        EXPECT_EQ("0420bd3a", item.GetString(cfd::core::kBip32Xpub));
        EXPECT_EQ("0420b900", item.GetString(cfd::core::kBip32Xprv));
      }
    }

    ByteData seed(
      "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04");
    HDWallet wallet(seed);
    auto extpriv0m = wallet.GeneratePrivkey(NetType::kMainnet);
    auto extpriv0t = wallet.GeneratePrivkey(NetType::kTestnet);
    auto extpub0m = extpriv0m.GetExtPubkey();
    auto extpub0t = extpriv0t.GetExtPubkey();
    EXPECT_EQ(
      "wprvikzVDokm6P1KtKfqXgTJv8XpWZcukZYCFsmaRemcFvKZakza93Zwuo15JHekgFrn6ZZai45KS6AitFzNGo2sTf17aiPR86dWi9Tq82Qgo1r",
      extpriv0m.ToString());
    EXPECT_EQ(
      "wpubWgH9tQnJckSFRpnyr5rjEzmB3bmxQ9nzR21zjuYXxKb8VsQ6bjNrpu2Aph61HVbgR9UFxZuRKe5FMHkZncoGNGUF1zjL8eyQSoacUbLMX4F",
      extpub0m.ToString());
    EXPECT_EQ(
      "sprv8Erh3X3hFeKuoD653knTvhJHkiKLxbhym6yyMYfKJ9kPXc3AnztLtmAyv29tc6yQn95qGE6e6TmYRokeKRMdyBXuyXTihmcpwoqJJPtTyAy",
      extpriv0t.ToString());
    EXPECT_EQ(
      "spub4Tr3T2ab61tD1hAY9nKUHqF2Jk9qN4Rq8Kua9w4vrVHNQQNKLYCbSZVTmHWGjUHEXBze8DprMkvK8ATi6tdKxBBjwmLdjVtuMKo4yLfkDWR",
      extpub0t.ToString());

    // parse extkey
    ExtPrivkey parse_sk1m(
      "wprvikzVDokm6P1KtKfqXgTJv8XpWZcukZYCFsmaRemcFvKZakza93Zwuo15JHekgFrn6ZZai45KS6AitFzNGo2sTf17aiPR86dWi9Tq82Qgo1r");
    ExtPubkey parse_pk1t(
      "spub4Tr3T2ab61tD1hAY9nKUHqF2Jk9qN4Rq8Kua9w4vrVHNQQNKLYCbSZVTmHWGjUHEXBze8DprMkvK8ATi6tdKxBBjwmLdjVtuMKo4yLfkDWR");
    EXPECT_EQ(extpriv0m.ToString(), parse_sk1m.ToString());
    EXPECT_EQ(extpub0t.ToString(), parse_pk1t.ToString());

    try {
      // unsupported prefix
      ExtPubkey parse_xpub0t(
        "tpubD6NzVbkrYhZ4XyJymmEgYC3uVhyj4YtPFX6yRTbW6RvfRC7Ag3sVhKSz7MNzFWW5MJ7aVBKXCAX7En296EYdpo43M4a4LaeaHuhhgHToSJF");
    } catch (const CfdException& except1) {
      EXPECT_STREQ("unsupported extkey version.", except1.what());
    }
  } catch (const CfdException& except) {
    EXPECT_STREQ("", except.what());
  } catch (...) {
    EXPECT_EQ("", "Throw exception.");
  }

  resp = nullptr;
  ret = CfdRequestExecuteJson(handle, "ClearCustomPrefix", "", &resp);
  EXPECT_EQ(kCfdSuccess, ret);
  if (resp != nullptr) CfdFreeStringBuffer(resp);

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

// last test.
/* comment out.
TEST(cfdcapi_common, CfdFinalize) {
  int ret = CfdInitialize();
  EXPECT_EQ(kCfdSuccess, ret);
  ret = CfdFinalize(false);
  EXPECT_EQ(kCfdSuccess, ret);
}
*/
