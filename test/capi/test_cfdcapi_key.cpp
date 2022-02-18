#include "gtest/gtest.h"

#include <stdexcept>
#include <string>

#include "cfdc/cfdcapi_common.h"
#include "cfdc/cfdcapi_key.h"
#include "cfdc/cfdcapi_address.h"
#include "capi/cfdc_internal.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_util.h"

using cfd::core::HashUtil;
using cfd::core::StringUtil;
using cfd::core::Privkey;
using cfd::core::CryptoUtil;
using cfd::core::SigHashType;

/**
 * @brief testing class.
 */
class cfdcapi_key : public ::testing::Test {
 protected:
  virtual void SetUp() { }
  virtual void TearDown() { }
};

TEST(cfdcapi_key, CfdCalculateEcSignature) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static constexpr const char* kSighash = "9b169f5af064cc2a0dac08d8be3c9e8bc3d3e1a3f3e2a44f0c3e4ecf23d56cf2";
  static constexpr const char* kPrivkey = "cU4KjNUT7GjHm7CkjRjG46SzLrXHXoH3ekXmqa2jTCFPMkQ64sw1";
  static constexpr const char* kExtSignature = "0bc7f08a2a8a5446e7483db1b46184ba3cc79d78a3452a72c5bc712cc7efb51f58af044d646c1fd4f755d49db26faa203937bc66c569047a7d3d3da531826060";
  static constexpr const int kNetwork = kCfdNetworkRegtest;

  char* signature = nullptr;
  ret = CfdCalculateEcSignature(handle, kSighash, nullptr, kPrivkey,
    kNetwork, true, &signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(kExtSignature, signature);
    CfdFreeStringBuffer(signature);
    signature = NULL;
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

TEST(cfdcapi_key, CfdEncodeSignatureByDer) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static constexpr const char* kSignature = "47ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
  static constexpr const char* kDerSignature = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01";

  char* der_signature = nullptr;
  ret = CfdEncodeSignatureByDer(handle, kSignature, kCfdSigHashAll, false, &der_signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(kDerSignature, der_signature);
    CfdFreeStringBuffer(der_signature);
    der_signature = NULL;
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

TEST(cfdcapi_key, CfdDecodeSignatureFromDer) {
  static constexpr const char* kSignature = "47ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb";
  static constexpr const char* kDerSignature = "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01";

  void* handle = nullptr;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((nullptr == handle));

  char* signature = nullptr;
  int sighash = 0;
  bool is_anyone_can_pay = false;
  ret = CfdDecodeSignatureFromDer(handle, kDerSignature, &signature,
      &sighash, &is_anyone_can_pay);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(kSignature, signature);
    EXPECT_EQ(kCfdSigHashAll, sighash);
    EXPECT_FALSE(is_anyone_can_pay);
    CfdFreeStringBuffer(signature);
    signature = nullptr;
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

TEST(cfdcapi_key, CfdNormalizeSignatureTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  // FIXME(fujita-cg): replace test data
  // this test data comes from https://www.pebblewind.com/entry/2018/04/27/232427
  if (ret == kCfdSuccess) {
    const char* signature = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5f67f6cf81a19873091aa7c9578fa2e96490e9bfc78ae7e9798004e8252c06287";
    char* normalized;
    ret = CfdNormalizeSignature(handle, signature, &normalized);
    EXPECT_EQ(kCfdSuccess, ret);
    const char* expect = "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee509809307e5e678cf6e55836a8705d16871a040ea369a21a427d2100a7d75deba";
    EXPECT_STREQ(normalized, expect);
    if (ret == kCfdSuccess) {
      CfdFreeStringBuffer(normalized);
      normalized = NULL;
    }
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

TEST(cfdcapi_key, PrivkeyAndPubkeyTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static constexpr const int kNetwork = kCfdNetworkRegtest;

  bool is_compressed = false;
  int network_type = kCfdNetworkRegtest;
  char* pubkey = nullptr;
  char* pubkey2 = nullptr;
  char* privkey = nullptr;
  char* privkey2 = nullptr;
  char* wif = nullptr;
  char* wif2 = nullptr;
  ret = CfdCreateKeyPair(handle, true, kNetwork, &pubkey, &privkey, &wif);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_EQ(66, strlen(pubkey));
    EXPECT_EQ(64, strlen(privkey));
    EXPECT_EQ(52, strlen(wif));

    ret = CfdGetPrivkeyFromWif(handle, wif, kNetwork, &privkey2);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(privkey, privkey2);
      CfdFreeStringBuffer(privkey2);
    }

    ret = CfdGetPubkeyFromPrivkey(handle, privkey, nullptr, true, &pubkey2);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(pubkey, pubkey2);
      CfdFreeStringBuffer(pubkey2);
    }

    CfdFreeStringBuffer(pubkey);
    CfdFreeStringBuffer(privkey);
    CfdFreeStringBuffer(wif);
  }

  ret = CfdCreateKeyPair(handle, false, kNetwork, &pubkey, &privkey, &wif);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_EQ(130, strlen(pubkey));
    EXPECT_EQ(64, strlen(privkey));
    EXPECT_EQ(51, strlen(wif));

    ret = CfdGetPrivkeyFromWif(handle, wif, kNetwork, &privkey2);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(privkey, privkey2);
      CfdFreeStringBuffer(privkey2);
    }

    ret = CfdParsePrivkeyWif(
        handle, wif, &privkey2, &network_type, &is_compressed);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_EQ(network_type, kCfdNetworkTestnet);
      EXPECT_FALSE(is_compressed);
      EXPECT_STREQ(privkey, privkey2);
      CfdFreeStringBuffer(privkey2);
    }

    ret = CfdGetPrivkeyWif(handle, privkey, kNetwork, false, &wif2);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(wif, wif2);
      CfdFreeStringBuffer(wif2);
    }

    void* handle2 = NULL;
    ret = CfdCreateHandle(&handle2);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_FALSE((NULL == handle2));

    ret = CfdGetPrivkeyWif(handle2, privkey, kCfdNetworkElementsRegtest,
        false, &wif2);
    EXPECT_EQ(kCfdIllegalArgumentError, ret);
    if (ret == kCfdIllegalArgumentError) {
      char* err_msg = NULL;
      ret = CfdGetLastErrorMessage(handle2, &err_msg);
      EXPECT_EQ(kCfdSuccess, ret);
#ifndef CFD_DISABLE_ELEMENTS
      EXPECT_STREQ("Failed to parameter. privkey's network_type is invalid.",
          err_msg);
#else  // CFD_DISABLE_ELEMENTS
      EXPECT_STREQ("Illegal network type.", err_msg);
#endif  // CFD_DISABLE_ELEMENTS
      CfdFreeStringBuffer(err_msg);
      err_msg = NULL;
    }
    ret = CfdFreeHandle(handle2);
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdGetPubkeyFromPrivkey(handle, privkey, nullptr, false, &pubkey2);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(pubkey, pubkey2);
      CfdFreeStringBuffer(pubkey2);
    }

    CfdFreeStringBuffer(pubkey);
    CfdFreeStringBuffer(privkey);
    CfdFreeStringBuffer(wif);
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

TEST(cfdcapi_key, CompressUncompressTest) {
  const char* key_uncompressed = "076468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73";
  const char* ext_key_uncompressed = "046468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955400e1a8f159b5dcea116049d09eb756b80d52aeaabb195b343cf713f62f01a73";
  const char* ext_key_compressed = "036468efc14b8512007bb720d6e7d4217a6686095a79b57e50dd48355110422955";

  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;

  ret = CfdCompressPubkey(handle, key_uncompressed, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(ext_key_compressed, output);
    CfdFreeStringBuffer(output);
    output = nullptr;
  }

  ret = CfdUncompressPubkey(handle, ext_key_compressed, &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(ext_key_uncompressed, output);
    CfdFreeStringBuffer(output);
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

TEST(cfdcapi_key, GetPubkeyFingerprint) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  ret = CfdGetPubkeyFingerprint(handle,
        "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9", &output);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("7df5646a", output);
    CfdFreeStringBuffer(output);
  }

  ret = CfdGetLastErrorCode(handle);
  if (ret != kCfdSuccess) {
    char* str_buffer = NULL;
    ret = CfdGetLastErrorMessage(handle, &str_buffer);
    EXPECT_EQ(kCfdSuccess, ret);
    EXPECT_STREQ("7df5646a", str_buffer);
    CfdFreeStringBuffer(str_buffer);
    str_buffer = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_key, CombinePubkeysTest1) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  void* combine_handle = nullptr;
  ret = CfdInitializeCombinePubkey(handle, &combine_handle);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    ret = CfdAddCombinePubkey(handle, combine_handle,
        "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddCombinePubkey(handle, combine_handle,
        "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdFinalizeCombinePubkey(handle, combine_handle, &output);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049", output);
      CfdFreeStringBuffer(output);
    }

    ret = CfdFreeCombinePubkeyHandle(handle, combine_handle);
    EXPECT_EQ(kCfdSuccess, ret);
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

TEST(cfdcapi_key, CombinePubkeysTest2) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* output = nullptr;
  void* combine_handle = nullptr;
  ret = CfdInitializeCombinePubkey(handle, &combine_handle);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    ret = CfdAddCombinePubkey(handle, combine_handle,
        "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddCombinePubkey(handle, combine_handle,
        "0261e37f277f02a977b4f11eb5055abab4990bbf8dee701119d88df382fcc1fafe");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddCombinePubkey(handle, combine_handle,
        "022a66efd1ea9b1ad3acfcc62a5ce8c756fa6fc3917fce3d4952a8701244ed1049");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdAddCombinePubkey(handle, combine_handle,
        "026356a05be3fcf52a57e133b7fb1cdb52a1bf14ef43f7d053e79b2ac98d5c2dd3");
    EXPECT_EQ(kCfdSuccess, ret);

    ret = CfdFinalizeCombinePubkey(handle, combine_handle, &output);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("03a5ba2faabc8966bb1b1525f5ecbd0205b357a70d8a26446224c92fffeb1ac8ca", output);
      CfdFreeStringBuffer(output);
    }

    ret = CfdFreeCombinePubkeyHandle(handle, combine_handle);
    EXPECT_EQ(kCfdSuccess, ret);
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

TEST(cfdcapi_key, PubkeyTweakConversionTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* pubkey = "03662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9";
  const char* tweak = "98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e";

  // test for adding tweak
  {
    char* tweak_added = nullptr;
    ret = CfdPubkeyTweakAdd(handle, pubkey, tweak, &tweak_added);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(tweak_added, "02b05cf99a2f556177a38f5108445472316e87eb4f5b243d79d7e5829d3d53babc");
      CfdFreeStringBuffer(tweak_added);
    }
  }

  // test for multiplying tweak
  {
    char* tweak_mul = nullptr;

    ret = CfdPubkeyTweakMul(handle, pubkey, tweak, &tweak_mul);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(tweak_mul, "0305d10e760a529d0523e98892d2deff59b91593a0d670bd82271cfa627c9e7e18");
      CfdFreeStringBuffer(tweak_mul);
    }
  }

  {
    char* negate = nullptr;

    ret = CfdNegatePubkey(handle, pubkey, &negate);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(negate, "02662a01c232918c9deb3b330272483c3e4ec0c6b5da86df59252835afeb4ab5f9");
      CfdFreeStringBuffer(negate);
    }
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

TEST(cfdcapi_key, PrivkeyTweakConversionTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* privkey = "036b13c5a0dd9935fe175b2b9ff86585c231e734b2148149d788a941f1f4f566";
  const char* tweak = "98430d10471cf697e2661e31ceb8720750b59a85374290e175799ba5dd06508e";

  // test for adding tweak
  {
    char* priv_tweak_added = nullptr;
    ret = CfdPrivkeyTweakAdd(handle, privkey, tweak, &priv_tweak_added);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(priv_tweak_added, "9bae20d5e7fa8fcde07d795d6eb0d78d12e781b9e957122b4d0244e7cefb45f4");
      CfdFreeStringBuffer(priv_tweak_added);
    }
  }

  // test for multiplying tweak
  {
    char* priv_tweak_mul = nullptr;

    ret = CfdPrivkeyTweakMul(handle, privkey, tweak, &priv_tweak_mul);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(priv_tweak_mul, "aa71b12accba23b49761a7521e661f07a7e5742ac48cf708b8f9497b3a72a957");
      CfdFreeStringBuffer(priv_tweak_mul);
    }
  }

  {
    char* negate = nullptr;

    ret = CfdNegatePrivkey(handle, privkey, &negate);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(negate, "fc94ec3a5f2266ca01e8a4d460079a78f87cf5b1fd341ef1e849b54ade414bdb");
      CfdFreeStringBuffer(negate);
    }
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


TEST(cfdcapi_key, ExtkeyTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static constexpr const char* kSeed = "0e09fbdd00e575b654d480ae979f24da45ef4dee645c7dc2e3b30b2e093d38dda0202357754cc856f8920b8e31dd02e9d34f6a2b20dc825c6ba90f90009085e1";
  static constexpr const int kNetwork = kCfdNetworkMainnet;

  char* pubkey = nullptr;
  char* privkey = nullptr;
  char* wif = nullptr;
  char* extprivkey1 = nullptr;
  char* extprivkey2 = nullptr;
  char* extprivkey3 = nullptr;
  char* extprivkey4 = nullptr;
  char* extpubkey1 = nullptr;
  char* key_path_data = nullptr;
  ret = CfdCreateExtkeyFromSeed(
      handle, kSeed, kNetwork, kCfdExtPrivkey, &extprivkey1);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("xprv9s21ZrQH143K38XAstQ4D3hCGbgydJgNff6CcwmkrWTBxksb2G4CsqAywJCKbTdywfCpmpJyxqf77iKK1ju1J982iP2PriifaNZLMbyPQCx", extprivkey1);

    ret = CfdCreateExtkeyFromParent(handle, extprivkey1, 44, true,
        kNetwork, kCfdExtPrivkey, &extprivkey2);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("xprv9tviYANkXM1CY831VtMFKFn6LP6aMHf1kvtCZyTL9YbyMwTR2BSmJaEoqw59BZdQhLSx9ZxyKsRUeCetxA2xZ34eupBqZUsifnWyLJJ16j3", extprivkey2);

    ret = CfdCreateExtPubkey(handle, extprivkey2, kNetwork,
        &extpubkey1);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("xpub67v4wfueMiZVkc7UbutFgPiptQw4kkNs89ooNMrwht8xEjnZZim1rNZHhEdrLejB99fiBdnWNNAB8hmUK7tCo5Ua6UtHzwVLj2Bzpch7vB2", extpubkey1);

    ret = CfdCreateExtkeyFromParentPath(handle, extprivkey2, "0h/0h/2",
        kNetwork, kCfdExtPrivkey, &extprivkey3);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("xprvA1YYKkMiZaDHRY4dmXjcP3js7ATJQAwt9gozTvi69etziyBAAENQN4w7sS3uBaF7rgXvP3sUtKFju7p3PosjNkRDuqqSFfxTjjEhgx6ejVZ", extprivkey3);

    ret = CfdGetPrivkeyFromExtkey(handle, extprivkey3,
        kNetwork, &privkey, &wif);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("597da1afc4218445ba9428c1c790a30fd21d5c4a932fa580b99dda7ec0887472", privkey);
    EXPECT_STREQ("KzDfmSzt1XqZh5m4sQPBqhpiTGncQ2xvXuWnKGMqR9gVHGSbVJP2", wif);

    ret = CfdGetPubkeyFromExtkey(handle, extprivkey3,
        kNetwork, &pubkey);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("031d7463018f867de51a27db866f869ceaf52abab71827a6051bab8a0fd020f4c1", pubkey);

    ret = CfdGetParentExtkeyPathData(
        handle, extprivkey2, "0h/0h/2", kCfdExtPrivkey, &key_path_data, &extprivkey4);
    EXPECT_EQ(kCfdSuccess, ret);
  }
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("[03af54a0/0h/0h/2]", key_path_data);
    EXPECT_STREQ(extprivkey3, extprivkey4);

    char* version = nullptr;
    char* fingerprint = nullptr;
    char* chain_code = nullptr;
    uint32_t depth = 0;
    uint32_t child_number = 0;
    ret = CfdGetExtkeyInformation(handle, extprivkey3, &version,
        &fingerprint, &chain_code, &depth, &child_number);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("0488ade4", version);
      EXPECT_STREQ("8806118d", fingerprint);
      EXPECT_STREQ("a3d58c40ac9c588529edb6cf9576241a6c2c919843bd97c3c26b35538d91a292", chain_code);
      EXPECT_EQ(4, depth);
      EXPECT_EQ(2, child_number);

      int net_type = 0;
      int key_type = 0;
      ret = CfdGetExtkeyInfo(handle, extprivkey3, nullptr, nullptr, nullptr,
          &depth, &child_number, &key_type, &net_type);
      EXPECT_EQ(kCfdSuccess, ret);
      EXPECT_EQ(kCfdExtPrivkey, key_type);
      EXPECT_EQ(kCfdNetworkMainnet, net_type);

      char* get_extkey = nullptr;
      ret = CfdCreateExtkey(handle, kNetwork, kCfdExtPrivkey, nullptr,
          fingerprint, privkey, chain_code,
          static_cast<unsigned char>(depth), child_number, &get_extkey);
      EXPECT_EQ(kCfdSuccess, ret);
      if (ret == kCfdSuccess) {
        EXPECT_STREQ(extprivkey3, get_extkey);
        CfdFreeStringBuffer(get_extkey);
        get_extkey = nullptr;
      }

      ret = CfdCreateExtkey(handle, kNetwork, kCfdExtPubkey, nullptr,
          fingerprint, pubkey, chain_code,
          static_cast<unsigned char>(depth), child_number, &get_extkey);
      EXPECT_EQ(kCfdSuccess, ret);
      if (ret == kCfdSuccess) {
        EXPECT_STREQ("xpub6EXtjFtcPwmae296sZGckBgbfCHnodfjWujbGK7hhzRybmWJhmgeusFbiiZyG1iSeiBcQ7diPeUC9vtP9wLS44bWpqH4kuQQD5N4gA3LaFE", get_extkey);
        CfdFreeStringBuffer(get_extkey);
        get_extkey = nullptr;
      }

      CfdFreeStringBuffer(version);
      CfdFreeStringBuffer(fingerprint);
      CfdFreeStringBuffer(chain_code);
    }
  }

  CfdFreeStringBuffer(extprivkey1);
  CfdFreeStringBuffer(extprivkey2);
  CfdFreeStringBuffer(extprivkey3);
  CfdFreeStringBuffer(extprivkey4);
  CfdFreeStringBuffer(key_path_data);
  CfdFreeStringBuffer(extpubkey1);
  CfdFreeStringBuffer(privkey);
  CfdFreeStringBuffer(wif);
  CfdFreeStringBuffer(pubkey);

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

TEST(cfdcapi_key, ExtkeyPatternTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* kSeed = "0e09fbdd00e575b654d480ae979f24da45ef4dee645c7dc2e3b30b2e093d38dda0202357754cc856f8920b8e31dd02e9d34f6a2b20dc825c6ba90f90009085e1";
  const char* kPubkey = "03516369486c27b7d1d6ee0acea16b9e551afd7509e3d845be5031a8313b3ffd5c";
  const char* kPrivkey = "0ff13951c5e144fe83130bca6011df2b0bc3ca7c039dfbc8d7b2cdf612b570a4";
  const char* kWifMainnet = "Kwkhb3aAjaQHGuB22TWBy9C95qdVjmzWaVi4ALreyQ3J21ijnbiN";
  const char* kWifTestnet = "cN7h3xa2Ae6YSLeHQsKKLThCi4vuQE6CeXrXGmKAUWhJGkpKc6dS";
  uint32_t derive_num = 44;
  const char* kDerivePath = "44";

  struct ExtkeyPatternTestData {
    std::string name;
    int bip32_format_type;
    int network_type;
    const char* extprivkey;
    const char* extpubkey;
    const char* derive_extprivkey;
    const char* derive_extpubkey;
    const char* pub_version;
  };
  static const ExtkeyPatternTestData kTestDataList[] = {
    {
      "bip32:mainnet",
      kCfdBip32FormatTypeNormal,
      kCfdNetworkMainnet,
      "xprv9s21ZrQH143K38XAstQ4D3hCGbgydJgNff6CcwmkrWTBxksb2G4CsqAywJCKbTdywfCpmpJyxqf77iKK1ju1J982iP2PriifaNZLMbyPQCx",
      "xpub661MyMwAqRbcFcbdyuw4aBdvpdXU2mQE2t1oRLBNQqzAqZCjZoNTRdVTnbfewkSqeo4p4VoBCT2ndY9s9zoxQzYtxH73AXP5BiKp4jbS4it",
      "xprv9tviYANcBgUENaVpFFU3WE75UECUQANDenzYG1jeEoJtxuoBwFea7L6GY5dweDgGhRYgMh33GCcJgzYCzHcU2uY1HF1sueqmAtNR7AFQ2pD",
      "xpub67v4wfuW242Xb4aHMH13sN3p2G2xod6521v94Q9Fo8qsqi8LUnxpf8QkPNhVccmDZG3PRS5PNgAXXifbxcgy6gS1vLiRM9k2fLnvKnFA6zq",
      "0488b21e",
    },
    {
      "bip32:testnet",
      kCfdBip32FormatTypeNormal,
      kCfdNetworkTestnet,
      "tprv8ZgxMBicQKsPdwkhYTFZNhKBaj7BrpiP1D1KVNCDLUwfkMcg1dPxPaYRrUMybq2JK6jbmuvk8CEuaZs48xEx7CPdF2EhX5SiVUJkoGmdvt3",
      "tpubD6NzVbkrYhZ4XQnVS6v9n6yJ9kd829uHaWc6mtEWkkk4aqsSe2DYa5AJ2dkSUFQ5Shbig5K3jYrqKieUYrfCJS1C1srLr43JmfvDphF7jQE",
      "tprv8bbfKVgwaxJJyPjLupKYfsj4nMcgdgQDzLuf8SA6imoNkWYGvczKd5TiTFobeb4b4s5TMneoRZC79r5x7VxQqxobotEBa1Zp5z7qYrTVvH8",
      "tpubD8HhTujBjKyyrrm8oTz95HPBMP8co1b8ZeWSQxCQ93bmazo3Z1ouoa5adQnH97iTMAaJ31bFumzaDuADMUYCz7tJywTj2gQGFJPL5sMss9U",
      "043587cf",
    },
    {
      "bip49:mainnet",
      kCfdBip32FormatTypeBip49,
      kCfdNetworkMainnet,
      "yprvABrGsX5C9jantRiHiFBgR8nhSZqRZvfsamcRQLfeEWq51rgpGvDmVtq7xW9ubNHuMJKdXHuYRW1ezzvsjSK26NodaiipSdY9r6cyk9JgjW8",
      "ypub6QqdH2c5z7966unkpGignGjRzbfuyPPiwzY2Cj5FnrN3tf1xpTY23h9boodEwf6m4SBcoyPjf7PLWpmRshDyDEEVpcoTkSCZTSPTTFvmihB",
      "yprvADkyqq3XLN1iDsgw5cFfiKCaeCLvLnMiZuWm3QdXcogn21cRBup8jPkQZHbXe8LC74fV7AdbirxraH9mhz2Uq9Dc9aiJVZfFScS4Vh2ekLD",
      "ypub6SkLFLaRAja1SMmQBdng5T9KCEBQkF5Zw8SMqo39B9DktowZjT8PHC4tQaf5cXR8xuACAufwqLX5R1HAgK6ytv7cngQqw4ZWw4rZiMFPTAP",
      "049d7cb2",
    },
    {
      "bip49:testnet",
      kCfdBip32FormatTypeBip49,
      kCfdNetworkTestnet,
      "uprv8tXDerPXZ1QsVEwpNp3BanQgkhFdoShsvKXYGm66iVKYoTRuGHZX1eCZsgKZbjgDijrQXPXJarbTTrUcreexuS5E7Mw86zGCmCNQBtELiFA",
      "upub57Wa4MvRPNyAhj2HUqaBwvMRJj68CuRjHYT959ViGprXgFm3opsmZSX3iyntx2V5RsiPp51VpTy8ygKAzuZv2HW6MG1mQnvcNY8su1hHuHT",
      "uprv8vRvdAMrjdqnpgvTkB7AsxpZxKm8aJPiuTRsuq3z6nBFocMWBH9tF97rUTmBeViWUWCG7GFMtDYf38hWqCNReCVCgDvc9vPJMiBUwMPssP3",
      "upub59RH2ftka1Q63AzvrCeBF6mJWMbcym7aGgMUiDTbf7iEgQgeipU8nwSLKkpjctoTLLgyB1Hhzh6ssrpuoXSvhyPDKKd9bRHZrAbzA4iQjZG",
      "044a5262",
    },
    {
      "bip84:mainnet",
      kCfdBip32FormatTypeBip84,
      kCfdNetworkMainnet,
      "zprvAWgYBBk7JR8GjiuQYbyJdDtCcXysWYfNVt8eBjZXcXCx4xW3XaPL7xVFyi7VbGwpkwSSGmW6tANCtHYST8j2tcVET4RF2YMe7pgd8n9uMRM",
      "zpub6jftahH18ngZxCysedWJzMpwAZpMv1PDs74Ez7y9ArjvwkqC57hafkojq1apwZkgU5JRZSzJ7mjtQ7NzbPdz1Tv6gxVtLM23jAT6qqM33qr",
      "zprvAYbF9ViSV3ZC5At3uy3HvQJ5pAVNHQMDV22ypoXQzp4f57ReSZyhMTQYaVZ7e2z7WhnHreEABXKQTZmLRgSVdNuD1vQj5UUjiLVhtDXvrDy",
      "zpub6mabZ1FLKR7VHexX1zaJHYEpNCKrgs54rExadBw2Z9bdwuknz7HwuFj2RncfcS54NYGzvPGWHzsdJHtjQ1Wzh9oDf27GWyP1CnvD6ykhvRn",
      "04b24746",
    },
    {
      "bip84:testnet",
      kCfdBip32FormatTypeBip84,
      kCfdNetworkTestnet,
      "vprv9DMUxX4ShgxMLY8wDAponsWBvfQ5k4hNqS3m49yz6VhRrZF8Wwj5dhrhttH9beL98NyDGs7s3Wx1M96BaM4yhfkpyhdYgu5h2vS3aQMofWX",
      "vpub5SLqN2bLY4WeZ2DQKCMpA1SvUhEa9XRECeyMrYPbeqEQjMaH4V3LBWBBkBkUww8zqWqCZYc4H8KgrxvjibyvpXBhDbiBzhk6eGCXHX9VwmM",
      "vprv9FGBvq2mtKPGfz7aaXto63v58HuaWvPDpZx6hDwsUnZ8riAjRwKSsCmzVfimeQNRt9K4rjqvLsuCvRK5YtnSSSAoYZd2jqCndSF8KzQrCPY",
      "vpub5UFYLLZfigwZtUC3gZRoTBrogKk4vP75BnshVcMV3867jWVsyUdhR16ULxnKcoTNjyomvUtGTMTRm9SUXDrwWD4pBfKaBL747tfdYf5ZH7N",
      "045f1cf6",
    },
  };

  size_t size = sizeof(kTestDataList) / sizeof(ExtkeyPatternTestData);
  for (size_t index = 0; index < size; ++index) {
    SCOPED_TRACE("test_" + kTestDataList[index].name);

    char* extprivkey = nullptr;
    char* extpubkey = nullptr;
    char* derive_extprivkey = nullptr;
    char* derive_extpubkey = nullptr;
    char* privkey = nullptr;
    char* wif = nullptr;
    char* pubkey = nullptr;
    char* path = nullptr;
    ret = CfdCreateExtkeyByFormatFromSeed(handle, kSeed,
        kTestDataList[index].network_type, kCfdExtPrivkey,
        kTestDataList[index].bip32_format_type, &extprivkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].extprivkey, extprivkey);
      CfdFreeStringBuffer(extprivkey);
    }

    ret = CfdCreateExtPubkey(handle, kTestDataList[index].extprivkey,
        kTestDataList[index].network_type, &extpubkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].extpubkey, extpubkey);
      CfdFreeStringBuffer(extpubkey);
    }

    ret = CfdCreateExtkeyFromParent(handle, kTestDataList[index].extprivkey,
        derive_num, false, kTestDataList[index].network_type,
        kCfdExtPrivkey, &derive_extprivkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].derive_extprivkey, derive_extprivkey);
      CfdFreeStringBuffer(derive_extprivkey);
    }

    ret = CfdCreateExtkeyFromParentPath(handle, kTestDataList[index].extpubkey,
        kDerivePath, kTestDataList[index].network_type,
        kCfdExtPubkey, &derive_extpubkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].derive_extpubkey, derive_extpubkey);
      CfdFreeStringBuffer(derive_extpubkey);
    }

    derive_extprivkey = nullptr;
    ret = CfdCreateExtkeyByFormat(handle, kTestDataList[index].network_type,
        kCfdExtPrivkey, "", "00000000", kPrivkey,
        "6ba6fe01878a68bd0691da3b0485ff90781b4ba8731dca2364f73bca4cb994b4",
        0, 0, kTestDataList[index].bip32_format_type, &extprivkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].extprivkey, extprivkey);
      CfdFreeStringBuffer(extprivkey);
    }

    ret = CfdGetPrivkeyFromExtkey(handle, kTestDataList[index].extprivkey,
        kTestDataList[index].network_type, &privkey, &wif);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kPrivkey, privkey);
      if (kTestDataList[index].network_type == kCfdNetworkMainnet) {
        EXPECT_STREQ(kWifMainnet, wif);
      } else {
        EXPECT_STREQ(kWifTestnet, wif);
      }
      CfdFreeStringBuffer(privkey);
      CfdFreeStringBuffer(wif);
    }

    ret = CfdGetPubkeyFromExtkey(handle, kTestDataList[index].extpubkey,
        kTestDataList[index].network_type, &pubkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kPubkey, pubkey);
      CfdFreeStringBuffer(pubkey);
    }

    ret = CfdGetParentExtkeyPathData(handle, kTestDataList[index].extprivkey,
        kDerivePath, kCfdExtPrivkey, &path, &derive_extprivkey);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("[00000000/44]", path);
      EXPECT_STREQ(kTestDataList[index].derive_extprivkey, derive_extprivkey);
      CfdFreeStringBuffer(path);
      CfdFreeStringBuffer(derive_extprivkey);
    }

    uint32_t depth = 0;
    uint32_t child_number = 0;
    char* version = nullptr;
    char* finger_print = nullptr;
    char* chain_code = nullptr;
    ret = CfdGetExtkeyInformation(handle, kTestDataList[index].derive_extpubkey,
        &version, &finger_print, &chain_code, &depth, &child_number);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(kTestDataList[index].pub_version, version);
      EXPECT_STREQ("03af54a0", finger_print);
      EXPECT_STREQ("60e694e8121800da6cd00a6943420d4b1de78b8071cd265a2345f92eb02f265a", chain_code);
      EXPECT_EQ(1, depth);
      EXPECT_EQ(44, child_number);
      CfdFreeStringBuffer(version);
      CfdFreeStringBuffer(finger_print);
      CfdFreeStringBuffer(chain_code);
    }
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_key, MnemonicTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  char* mnemonic_word = nullptr;
  char* mnemonic = nullptr;
  void* mnemonic_handle = nullptr;
  uint32_t max_index = 0;
  ret = CfdInitializeMnemonicWordList(handle, "en", &mnemonic_handle, &max_index);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_EQ(2048, max_index);
  if (ret == kCfdSuccess) {
    ret = CfdGetMnemonicWord(handle, mnemonic_handle, 3, &mnemonic_word);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ("about", mnemonic_word);
      CfdFreeStringBuffer(mnemonic_word);
      mnemonic_word = nullptr;
    }

    ret = CfdFreeMnemonicWordList(handle, mnemonic_handle);
    EXPECT_EQ(kCfdSuccess, ret);
  }

  char* mnemonic_words = nullptr;
  ret = CfdGetMnemonicWords(handle, "en", &mnemonic_words);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    auto words = StringUtil::Split(mnemonic_words, " ");
    EXPECT_EQ("about", words[3]);
    EXPECT_EQ(2048, words.size());
  }

  char* seed = nullptr;
  char* entropy = nullptr;
  const char* test_mnemonic = "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave";
  const char* exp_entropy = "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3";
  ret = CfdConvertMnemonicToSeed(handle, test_mnemonic, "TREZOR", true, "en", false, &seed, &entropy);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d", seed);
    EXPECT_STREQ(exp_entropy, entropy);
    CfdFreeStringBuffer(seed);
    CfdFreeStringBuffer(entropy);
  }

  ret = CfdConvertMnemonicToSeed(handle, test_mnemonic, "abcde", true, "en", false, &seed, &entropy);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ("fd3bb1e11eb0e3e59e8ba4d6eefca06446c504123f73096142766ad4803e19e777091973655b5cd3e951d72fda51be48f9ae231bab59d3a37f547ffc73dc00b5", seed);
    EXPECT_STREQ(exp_entropy, entropy);
    CfdFreeStringBuffer(seed);
    CfdFreeStringBuffer(entropy);
  }

  ret = CfdConvertEntropyToMnemonic(handle, exp_entropy, "en", &mnemonic);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(test_mnemonic, mnemonic);
    CfdFreeStringBuffer(mnemonic);
    mnemonic = nullptr;
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

TEST(cfdcapi_key, MessageSignTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* exp_sig_b64 = "H9Dk+Y13ybD+hH7okYJemWs0N9cIJ23Zn5T+lDFo+ZO3G9QSb6Qla2TATXFji29uip6vKsi8TJRZQHbCTu85/74=";
  const char* exp_sig_hex = "1fd0e4f98d77c9b0fe847ee891825e996b3437d708276dd99f94fe943168f993b71bd4126fa4256b64c04d71638b6f6e8a9eaf2ac8bc4c94594076c24eef39ffbe";
  const char* privkey_wif = "cUUuHBXPzhaFnny2gCBzZZzYtFyps9B1sDJbtJMC8ssjUhNMq9xk";
  const char* privkey_hex = "cde0d924f9ffaa23951d86160329630261e68eaa62b8b389735b42238618c50e";
  const char* pubkey = "0278bfaa4e045cc450ce9397136ac9bac1914147d85945dd9c8c3b2edc0108249d";
  const char* pubkey2 = "0378bfaa4e045cc450ce9397136ac9bac1914147d85945dd9c8c3b2edc0108249d";
  const char* msg = "This is just a test message";
  char* signature = NULL;
  char* recovered_pubkey = NULL;

  ret = CfdSignMessage(handle, privkey_wif, msg, NULL, true,
      &signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp_sig_b64, signature);
    CfdFreeStringBuffer(signature);
    signature = NULL;
  }

  ret = CfdVerifyMessage(handle, exp_sig_b64, pubkey, msg, NULL,
      &recovered_pubkey);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(pubkey, recovered_pubkey);
    CfdFreeStringBuffer(recovered_pubkey);
    recovered_pubkey = NULL;
  }

  ret = CfdSignMessage(handle, privkey_hex, msg, NULL, false,
      &signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(exp_sig_hex, signature);
    CfdFreeStringBuffer(signature);
    signature = NULL;
  }

  ret = CfdVerifyMessage(handle, exp_sig_hex, pubkey, msg, NULL,
      &recovered_pubkey);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(pubkey, recovered_pubkey);
    CfdFreeStringBuffer(recovered_pubkey);
    recovered_pubkey = NULL;
  }

  // verify error
  ret = CfdVerifyMessage(handle, exp_sig_hex, pubkey, "This is just a test message2", NULL,
      &recovered_pubkey);
  EXPECT_EQ(kCfdSignVerificationError, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STRNE(pubkey, recovered_pubkey);
    CfdFreeStringBuffer(recovered_pubkey);
    recovered_pubkey = NULL;
  }

  ret = CfdVerifyMessage(handle, exp_sig_hex, pubkey2, msg, NULL,
      &recovered_pubkey);
  EXPECT_EQ(kCfdSignVerificationError, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(pubkey, recovered_pubkey);
    CfdFreeStringBuffer(recovered_pubkey);
    recovered_pubkey = NULL;
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}

TEST(cfdcapi_key, EcdsaAdaptorSignatureTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  const char* msg =
      "024bdd11f2144e825db05759bdd9041367a420fad14b665fd08af5b42056e5e2";
  const char* adaptor =
      "038d48057fc4ce150482114d43201b333bf3706f3cd527e8767ceb4b443ab5d349";
  const char* sk =
      "90ac0d5dc0a1a9ab352afb02005a5cc6c4df0da61d8149d729ff50db9b5a5215";
  const char* pubkey =
      "03490cec9a53cd8f2f664aea61922f26ee920c42d2489778bb7c9d9ece44d149a7";
  const char* adaptor_sig_str =
      "02717ff3bb1c1ab09782f1f9ac0ea9f07006717efe0771d1ab7fc856bf6bb802c2"
      "03164e2639cff6ad8943244d4f31533b0f168f026242905c0a761681b2eaf7329b"
      "de184ef11c5a9d89a871422ae92f42b0ae09c975d34450cb0c77eeeaa6988115"
      "2fb87fca8d09454743b5d77abb60aea5263e93eecfbf933a9efd6e48b5b7946f"
      "d8021bf858141f1c3854d24778baf27e642d288e07851b3e83c33a64ab10ee85";

  const ByteData raw_sig(
      "717ff3bb1c1ab09782f1f9ac0ea9f07006717efe0771d1ab7fc856bf6bb802c2"
      "60d6deb1bc09038b4eb8244a645beed1387890b58b83f0674102b21561456f20");
  const char* secret =
      "475697a71a74ff3f2a8f150534e9b67d4b0b6561fab86fcaa51f8c9d6c9db8c6";

  char* adaptor_signature = NULL;
  ret = CfdEncryptEcdsaAdaptor(handle, msg, sk, adaptor,
      &adaptor_signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(adaptor_sig_str, adaptor_signature);
    CfdFreeStringBuffer(adaptor_signature);
  }

  ret = CfdVerifyEcdsaAdaptor(
      handle, adaptor_sig_str, msg, pubkey, adaptor);
  EXPECT_EQ(kCfdSuccess, ret);

  SigHashType sig_hash;
  char* signature = NULL;
  ret = CfdDecryptEcdsaAdaptor(handle, adaptor_sig_str, secret, &signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(raw_sig.GetHex().c_str(), signature);
    CfdFreeStringBuffer(signature);
  }

  char* adaptor_secret = NULL;
  ret = CfdRecoverEcdsaAdaptor(
      handle, adaptor_sig_str, raw_sig.GetHex().c_str(), adaptor, &adaptor_secret);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(secret, adaptor_secret);
    CfdFreeStringBuffer(adaptor_secret);
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


TEST(cfdcapi_key, SchnorrTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static const char* msg =
      "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614";
  static const char* sk =
      "688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef";
  static const char* pubkey =
      "b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390";
  static const char* aux_rand =
      "02cce08e913f22a36c5648d6405a2c7c50106e7aa2f1649e381c7f09d16b80ab";
  static const char* nonce =
      "8c8ca771d3c25eb38de7401818eeda281ac5446f5c1396148f8d9d67592440fe";
  static const char* schnorr_nonce =
      "f14d7e54ff58c5d019ce9986be4a0e8b7d643bd08ef2cdf1099e1a457865b547";
  static const char* signature =
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee"
      "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";

  char* schnorr_signature;
  ret = CfdSignSchnorr(handle, msg, sk, aux_rand, &schnorr_signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(signature, schnorr_signature);
    CfdFreeStringBuffer(schnorr_signature);
    schnorr_signature = NULL;
  }

  static const char* expected_sig =
      "5da618c1936ec728e5ccff29207f1680dcf4146370bdcfab0039951b91e3637a958e91"
      "d68537d1f6f19687cec1fd5db1d83da56ef3ade1f3c611babd7d08af42";
  ret = CfdSignSchnorrWithNonce(handle, msg, sk, nonce, &schnorr_signature);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(expected_sig, schnorr_signature);
    CfdFreeStringBuffer(schnorr_signature);
    schnorr_signature = NULL;
  }

  static const char* expected_sig_point =
      "03735acf82eef9da1540efb07a68251d5476dabb11ac77054924eccbb4121885e8";
  char* sigpoint = NULL;
  ret = CfdComputeSchnorrSigPoint(handle, msg, schnorr_nonce, pubkey, &sigpoint);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(expected_sig_point, sigpoint);
    CfdFreeStringBuffer(sigpoint);
  }

  ret = CfdVerifySchnorr(handle, signature, msg, pubkey);
  EXPECT_EQ(kCfdSuccess, ret);

  const char* expected_nonce =
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee";
  const char* expected_privkey =
      "5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8";
  char* sigs_nonce = NULL;
  char* sigs_key = NULL;
  ret = CfdSplitSchnorrSignature(handle, signature, &sigs_nonce, &sigs_key);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_STREQ(expected_nonce, sigs_nonce);
    EXPECT_STREQ(expected_privkey, sigs_key);
    CfdFreeStringBuffer(sigs_nonce);
    CfdFreeStringBuffer(sigs_key);
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

TEST(cfdcapi_key, SchnorrKeyTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  static const char* tweak =
      "e48441762fb75010b2aa31a512b62b4148aa3fb08eb0765d76b252559064a614";
  static const char* sk =
      "688c77bc2d5aaff5491cf309d4753b732135470d05b7b2cd21add0744fe97bef";
  static const char* pk =
      "03b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390";
  static const char* exp_pubkey =
      "b33cc9edc096d0a83416964bd3c6247b8fecd256e4efa7870d2c854bdeb33390";
  // static const bool exp_parity = true;
  static const char* exp_tweaked_pk =
      "1fc8e882e34cc7942a15f39ffaebcbdf58a19239bcb17b7f5aa88e0eb808f906";
  static const bool exp_tweaked_parity = true;
  static const char* exp_tweaked_sk =
      "7bf7c9ba025ca01b698d3e9b3e40efce2774f8a388f8c390550481e1407b2a25";

  char* temp_schnorr_pubkey = nullptr;
  bool parity = false;
  ret = CfdGetSchnorrPubkeyFromPrivkey(handle, sk, &temp_schnorr_pubkey, &parity);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_TRUE(parity);
    EXPECT_STREQ(exp_pubkey, temp_schnorr_pubkey);
    CfdFreeStringBuffer(temp_schnorr_pubkey);
    temp_schnorr_pubkey = nullptr;
  }

  ret = CfdGetSchnorrPubkeyFromPubkey(handle, pk, &temp_schnorr_pubkey, &parity);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_TRUE(parity);
    EXPECT_STREQ(exp_pubkey, temp_schnorr_pubkey);
    CfdFreeStringBuffer(temp_schnorr_pubkey);
    temp_schnorr_pubkey = nullptr;
  }

  // check tweak

  char* tweaked_pk = nullptr;
  ret = CfdSchnorrPubkeyTweakAdd(handle, exp_pubkey, tweak, &tweaked_pk, &parity);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_TRUE(parity);
    EXPECT_STREQ(exp_tweaked_pk, tweaked_pk);
    CfdFreeStringBuffer(tweaked_pk);
    tweaked_pk = NULL;
  }

  char* tweaked_sk = nullptr;
  ret = CfdSchnorrKeyPairTweakAdd(handle, sk, tweak,
      &tweaked_pk, &parity, &tweaked_sk);
  EXPECT_EQ(kCfdSuccess, ret);
  if (ret == kCfdSuccess) {
    EXPECT_TRUE(parity);
    EXPECT_STREQ(exp_tweaked_pk, tweaked_pk);
    EXPECT_STREQ(exp_tweaked_sk, tweaked_sk);
    CfdFreeStringBuffer(tweaked_pk);
    CfdFreeStringBuffer(tweaked_sk);
    tweaked_pk = NULL;
    tweaked_sk = NULL;
  }

  ret = CfdCheckTweakAddFromSchnorrPubkey(handle, exp_tweaked_pk,
      exp_tweaked_parity, exp_pubkey, tweak);
  EXPECT_EQ(kCfdSuccess, ret);

  ret = CfdCheckTweakAddFromSchnorrPubkey(handle, exp_tweaked_pk,
      !exp_tweaked_parity, exp_pubkey, tweak);
  EXPECT_EQ(kCfdSignVerificationError, ret);

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

TEST(cfdcapi_key, SchnorrSignatureTest) {
  void* handle = NULL;
  int ret = CfdCreateHandle(&handle);
  EXPECT_EQ(kCfdSuccess, ret);
  EXPECT_FALSE((NULL == handle));

  struct CfdSchnorrSignatureTestData {
    const char* signature;
    const char* sighash_signature;
    int sighash_type;
    bool anyone_can_pay;
  };
  const struct CfdSchnorrSignatureTestData exp_datas[] = {
    {  // sighash all
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce801",
      kCfdSigHashAll,
      false
    },
    {  // sighash default
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      kCfdSigHashDefault,
      false
    },
    {  // sighash none
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce802",
      kCfdSigHashNone,
      false
    },
    {  // sighash single
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce803",
      kCfdSigHashSingle,
      false
    },
    {  // sighash single + anyone can pay
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce8",
      "6470fd1303dda4fda717b9837153c24a6eab377183fc438f939e0ed2b620e9ee5077c4a8b8dca28963d772a94f5f0ddf598e1c47c137f91933274c7c3edadce883",
      kCfdSigHashSingle,
      true
    },
  };
  size_t list_size = sizeof(exp_datas) / sizeof(struct CfdSchnorrSignatureTestData);

  for (size_t idx = 0; idx < list_size; ++idx) {
    char* sig = nullptr;
    int sighash_type = 0;
    bool anyone_can_pay = false;
    ret = CfdAddSighashTypeInSchnorrSignature(
        handle, exp_datas[idx].signature, exp_datas[idx].sighash_type,
        exp_datas[idx].anyone_can_pay, &sig);
    EXPECT_EQ(kCfdSuccess, ret);
    if (ret == kCfdSuccess) {
      EXPECT_STREQ(exp_datas[idx].sighash_signature, sig);
      CfdFreeStringBuffer(sig);
      sig = nullptr;

      ret = CfdGetSighashTypeFromSchnorrSignature(
          handle, exp_datas[idx].sighash_signature, &sighash_type, &anyone_can_pay);
      EXPECT_EQ(kCfdSuccess, ret);
      if (ret == kCfdSuccess) {
        EXPECT_EQ(exp_datas[idx].sighash_type, sighash_type & 0x1f);
        EXPECT_EQ(exp_datas[idx].anyone_can_pay, anyone_can_pay);
      }
    }

    if (ret != kCfdSuccess) {
      char* message = nullptr;
      ret = CfdGetLastErrorMessage(handle, &message);
      if (ret == kCfdSuccess) {
        EXPECT_STREQ("", message);
        CfdFreeStringBuffer(message);
      }
    }
  }

  ret = CfdFreeHandle(handle);
  EXPECT_EQ(kCfdSuccess, ret);
}
