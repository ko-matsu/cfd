// Copyright 2021 CryptoGarage
/**
 * @file cfd_json_utility.cpp
 *
 * @brief Implementation files for common classes used by cfd-api.
 */
#include <string>
#include <vector>

#include "cfd/cfd_common.h"
#include "jsonapi/autogen/cfd_api_json_autogen.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_exception.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_logger.h"
#include "cfdcore/cfdcore_util.h"
#include "cfd_json_utility.h"

namespace cfd {
namespace api {
namespace json {

using cfd::core::ByteData;
using cfd::core::CfdError;
using cfd::core::CfdException;

void JsonUtilApi::SetCustomPrefix(
    SetCustomPrefixRequest* request, VoidFunctionResponse* response) {
  using cfd::core::kPrefixBlindP2pkh;
  using cfd::core::kPrefixBlindP2sh;
  using cfd::core::kPrefixBlindBech32Hrp;
  using cfd::core::kBip49Ypub;
  using cfd::core::kBip49Yprv;
  using cfd::core::kBip84Zpub;
  using cfd::core::kBip84Zprv;
  using cfd::core::AddressFormatData;
  using cfd::core::KeyFormatData;
  if (request == nullptr) {
    throw CfdException(
        CfdError::kCfdIllegalArgumentError, "request is null.");
  }

  std::string addr_custom_json;
  for (const auto& json_data : request->GetAddressJsonDatas()) {
    auto data = json_data.ConvertToStruct();
    json::AddressPrefixCustomizeData addr_obj;
    addr_obj.ConvertFromStruct(data);
    if (data.blinded.empty()) addr_obj.SetIgnoreItem(kPrefixBlindP2pkh);
    if (data.blinded_p2sh.empty()) addr_obj.SetIgnoreItem(kPrefixBlindP2sh);
    if (data.blech32.empty()) addr_obj.SetIgnoreItem(kPrefixBlindBech32Hrp);
    if (!addr_custom_json.empty()) addr_custom_json += ",";
    addr_custom_json += addr_obj.Serialize();
  }
  if (!addr_custom_json.empty()) {
    addr_custom_json = "[" + addr_custom_json + "]";
    auto list = AddressFormatData::ConvertListFromJson(addr_custom_json);
    cfd::core::SetCustomAddressFormatList(list);
  }

  std::string key_custom_json;
  for (const auto& json_data : request->GetKeyJsonDatas()) {
    auto data = json_data.ConvertToStruct();
    json::KeyPrefixCustomizeData key_obj;
    key_obj.ConvertFromStruct(data);
    if (data.bip49ypub.empty()) key_obj.SetIgnoreItem(kBip49Ypub);
    if (data.bip49yprv.empty()) key_obj.SetIgnoreItem(kBip49Yprv);
    if (data.bip84zpub.empty()) key_obj.SetIgnoreItem(kBip84Zpub);
    if (data.bip84zprv.empty()) key_obj.SetIgnoreItem(kBip84Zprv);
    if (!key_custom_json.empty()) key_custom_json += ",";
    key_custom_json += key_obj.Serialize();
  }
  if (!key_custom_json.empty()) {
    key_custom_json = "[" + key_custom_json + "]";
    auto list = KeyFormatData::ConvertListFromJson(key_custom_json);
    cfd::core::SetCustomKeyFormatList(list);
  }

  if (response != nullptr) {
    response->SetSuccess(true);
  }
}

void JsonUtilApi::ClearCustomPrefix(VoidFunctionResponse* response) {
  cfd::core::ClearCustomAddressFormatList();
  cfd::core::ClearCustomKeyFormatList();

  if (response != nullptr) {
    response->SetSuccess(true);
  }
}

}  // namespace json
}  // namespace api
}  // namespace cfd
