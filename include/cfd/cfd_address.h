// Copyright 2019 CryptoGarage
/**
 * @file cfd_address.h
 *
 * @brief Related class definition for Address operation
 */
#ifndef CFD_INCLUDE_CFD_CFD_ADDRESS_H_
#define CFD_INCLUDE_CFD_CFD_ADDRESS_H_

#include <string>
#include <vector>

#include "cfd/cfd_common.h"
#include "cfdcore/cfdcore_address.h"
#include "cfdcore/cfdcore_bytedata.h"
#include "cfdcore/cfdcore_key.h"
#include "cfdcore/cfdcore_schnorrsig.h"
#include "cfdcore/cfdcore_script.h"
#include "cfdcore/cfdcore_taproot.h"

namespace cfd {

using cfd::core::Address;
using cfd::core::AddressFormatData;
using cfd::core::AddressType;
using cfd::core::ByteData;
using cfd::core::ByteData160;
using cfd::core::ByteData256;
using cfd::core::NetType;
using cfd::core::Pubkey;
using cfd::core::SchnorrPubkey;
using cfd::core::Script;
using cfd::core::TaprootScriptTree;
using cfd::core::WitnessVersion;

/**
 * @brief Factory class that generates Address
 */
class CFD_EXPORT AddressFactory {
 public:
  /**
   * @brief Constructor.
   */
  AddressFactory();

  /**
   * @brief Constructor.
   * @param[in] type      network type
   */
  explicit AddressFactory(NetType type);

  /**
   * @brief Constructor.
   * @param[in] type      network type
   * @param[in] wit_ver   witness version
   */
  explicit AddressFactory(NetType type, WitnessVersion wit_ver);

  /**
   * @brief Constructor.
   * @param[in] type          network type
   * @param[in] wit_ver       witness version
   * @param[in] prefix_list   address prefix list
   */
  explicit AddressFactory(
      NetType type, WitnessVersion wit_ver,
      const std::vector<AddressFormatData>& prefix_list);

  /**
   * @brief Constructor.
   * @param[in] type          network type
   * @param[in] prefix_list   address prefix list
   */
  explicit AddressFactory(
      NetType type, const std::vector<AddressFormatData>& prefix_list);

  /**
   * @brief Destructor.
   */
  virtual ~AddressFactory() {
    // do nothing
  }

  /**
   * @brief Create an address
   * @param[in] address_string  address string
   * @return address
   */
  Address GetAddress(const std::string& address_string) const;

  /**
   * @brief Create an address from locking script
   * @param[in] locking_script  locking script
   * @return address
   */
  Address GetAddressByLockingScript(const Script& locking_script) const;

  /**
   * @brief Create an address from hash data
   * @param[in] address_type  address type
   * @param[in] hash          hash data
   * @return address
   */
  Address GetAddressByHash(
      AddressType address_type, const ByteData& hash) const;
  /**
   * @brief Create an address from hash data
   * @param[in] address_type  address type
   * @param[in] hash          hash data
   * @return address
   */
  Address GetAddressByHash(
      AddressType address_type, const ByteData160& hash) const;

  /**
   * @brief Create a segwit native address from hash data.
   * @param[in] hash  hash data
   * @return address
   */
  Address GetSegwitAddressByHash(const ByteData& hash) const;

  /**
   * @brief Create a segwit native address from hash data.
   * @param[in] hash        hash data
   * @param[in] version     witness version
   * @return address
   */
  Address GetSegwitAddressByHash(
      const ByteData& hash, WitnessVersion version) const;

  /**
   * @brief Create a P2PKH address.
   * @param[in] pubkey  Pubkey
   * @return address
   */
  Address CreateP2pkhAddress(const Pubkey& pubkey) const;

  /**
   * @brief Create a P2SH address.
   * @param[in] script  Redeem script
   * @return address
   */
  Address CreateP2shAddress(const Script& script) const;

  /**
   * @brief Create a P2WPKH address.
   * @param[in] pubkey      Pubkey
   * @return address
   */
  Address CreateP2wpkhAddress(const Pubkey& pubkey) const;

  /**
   * @brief Create a P2WSH address.
   * @param[in] script      Redeem script
   * @return address
   */
  Address CreateP2wshAddress(const Script& script) const;

  /**
   * @brief Create a P2WSH Multisig (n of m) address.
   * @param[in] require_num     signature require num(n)
   * @param[in] pubkeys         Pubkey list(m)
   * @return address
   */
  Address CreateP2wshMultisigAddress(
      uint32_t require_num, const std::vector<Pubkey>& pubkeys) const;

  /**
   * @brief Create taproot address by schnorr pubkey.
   * @param[in] pubkey      schnorr pubkey
   * @return Address by taproot
   */
  Address CreateTaprootAddress(const SchnorrPubkey& pubkey) const;

  /**
   * @brief Create taproot address by tapscript.
   * @param[in] tree                merkle tree
   * @param[in] internal_pubkey     internal schnorr pubkey
   * @return Address by taproot
   */
  Address CreateTaprootAddress(
      const TaprootScriptTree& tree,
      const SchnorrPubkey& internal_pubkey) const;

  /**
   * @brief Create taproot address by hash.
   * @param[in] hash      hash
   * @return Address by taproot
   */
  Address CreateTaprootAddress(const ByteData256& hash) const;

  /**
   * @brief check address's network type is valid.
   * @param[in] address address which is checked network type
   * @param[in] net_type check network type (ref: cfd::core::NetType)
   * @return true: much net_type, false: unmatch
   */
  bool CheckAddressNetType(const Address& address, NetType net_type) const;

 protected:
  NetType type_;                                //!< network type
  WitnessVersion wit_ver_;                      //!< witness version
  std::vector<AddressFormatData> prefix_list_;  //!< address prefix list
};

}  // namespace cfd

#endif  // CFD_INCLUDE_CFD_CFD_ADDRESS_H_
