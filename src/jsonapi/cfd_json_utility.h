// Copyright 2021 CryptoGarage
/**
 * @file cfd_json_utility.h
 *
 * @brief cfd-json-api utility
 */
#ifndef CFD_SRC_JSONAPI_CFD_JSON_UTILITY_H_
#define CFD_SRC_JSONAPI_CFD_JSON_UTILITY_H_

#include <string>

#include "cfd/cfd_common.h"
#include "jsonapi/cfd_struct.h"

/**
 * @brief cfdapi namespace
 */
namespace cfd {
namespace api {
namespace json {

/**
 * @brief Json utility API
 */
class JsonUtilApi {
 public:
  /**
   * @brief Set custom prefix setting.
   * @param[in] request     request struct from json
   * @param[out] response   response struct from json
   */
  static void SetCustomPrefix(
      SetCustomPrefixRequest* request,
      VoidFunctionResponse* response);
  /**
   * @brief Clear custom prefix setting.
   * @param[out] response   response struct from json
   */
  static void ClearCustomPrefix(VoidFunctionResponse* response);

 private:
  JsonUtilApi();
};

}  // namespace json
}  // namespace api
}  // namespace cfd

#endif  // CFD_SRC_JSONAPI_CFD_JSON_UTILITY_H_
