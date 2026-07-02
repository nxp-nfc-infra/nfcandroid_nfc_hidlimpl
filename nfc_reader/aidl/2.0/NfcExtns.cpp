/******************************************************************************
 *
 *  Copyright 2025,2026 NXP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/
#include "NfcExtns.h"

#include "phNfcStatus.h"
#include "phNxpConfig.h"
#include "phNxpNciHal_extOperations.h"

namespace aidl {
namespace android {
namespace hardware {
namespace nfc {

void NfcExtns::getConfig(NfcConfig& config) {
  unsigned long num = 0;
  std::array<uint8_t, NXP_MAX_CONFIG_STRING_LEN> buffer;
  buffer.fill(0);
  int64_t retlen = 0;
  config = {};


  if (GetNxpNumValue(NAME_NFA_POLL_BAIL_OUT_MODE, &num, sizeof(num))) {
    config.nfaPollBailOutMode = static_cast<bool>(num);
  }
  if (GetNxpNumValue(NAME_ISO_DEP_MAX_TRANSCEIVE, &num, sizeof(num))) {
    config.maxIsoDepTransceiveLength = static_cast<uint32_t>(num);
  }
  if (GetNxpNumValue(NAME_DEFAULT_OFFHOST_ROUTE, &num, sizeof(num))) {
    config.defaultOffHostRoute = static_cast<uint8_t>(num);
  }
  if (GetNxpNumValue(NAME_DEFAULT_NFCF_ROUTE, &num, sizeof(num))) {
    config.defaultOffHostRouteFelica = static_cast<uint8_t>(num);
  }
  if (GetNxpNumValue(NAME_DEFAULT_SYS_CODE_ROUTE, &num, sizeof(num))) {
    config.defaultSystemCodeRoute = static_cast<uint8_t>(num);
  }
  if (GetNxpNumValue(NAME_DEFAULT_SYS_CODE_PWR_STATE, &num, sizeof(num))) {
    config.defaultSystemCodePowerState =
        phNxpNciHal_updateAutonomousPwrState(static_cast<uint8_t>(num));
  }
  if (GetNxpNumValue(NAME_DEFAULT_ROUTE, &num, sizeof(num))) {
    config.defaultRoute = static_cast<uint8_t>(num);
  }
  if (GetNxpNumValue(NAME_OFF_HOST_ESE_PIPE_ID, &num, sizeof(num))) {
    config.offHostESEPipeId = static_cast<uint8_t>(num);
  }
  if (GetNxpNumValue(NAME_T4T_NFCEE_ENABLE, &num, sizeof(num))) {
    config.t4tNfceeEnable = static_cast<bool>(num & 0x01);
  }
  if (GetNxpByteArrayValue(NAME_OFF_HOST_SIM_PIPE_IDS, reinterpret_cast<char*>(buffer.data()),
                           buffer.size(), &retlen)) {
    config.offHostSimPipeIds.resize(retlen);
    for (int64_t i = 0; i < retlen; i++) config.offHostSimPipeIds[i] = buffer[i];
  }
  if (GetNxpNumValue(NAME_DEFAULT_ISODEP_ROUTE, &num, sizeof(num))) {
    config.defaultIsoDepRoute = static_cast<uint8_t>(num);
  }
  if (GetNxpByteArrayValue(NAME_OFFHOST_ROUTE_UICC, reinterpret_cast<char*>(buffer.data()),
                           buffer.size(), &retlen)) {
    config.offHostRouteUicc.resize(retlen);
    for (int64_t i = 0; i < retlen; i++) config.offHostRouteUicc[i] = buffer[i];
  }

  if (GetNxpByteArrayValue(NAME_OFFHOST_ROUTE_ESE, reinterpret_cast<char*>(buffer.data()),
                           buffer.size(), &retlen)) {
    config.offHostRouteEse.resize(retlen);
    for (int64_t i = 0; i < retlen; i++) config.offHostRouteEse[i] = buffer[i];
  }
  if ((GetNxpByteArrayValue(NAME_NFA_PROPRIETARY_CFG, reinterpret_cast<char*>(buffer.data()),
                            buffer.size(), &retlen)) &&
      (retlen == 10)) {
    config.nfaProprietaryCfg.protocol18092Active = static_cast<uint8_t>(buffer[0]);
    config.nfaProprietaryCfg.protocolBPrime = static_cast<uint8_t>(buffer[1]);
    config.nfaProprietaryCfg.protocolDual = static_cast<uint8_t>(buffer[2]);
    config.nfaProprietaryCfg.protocol15693 = static_cast<uint8_t>(buffer[3]);
    config.nfaProprietaryCfg.protocolKovio = static_cast<uint8_t>(buffer[4]);
    config.nfaProprietaryCfg.protocolMifare = static_cast<uint8_t>(buffer[5]);
    config.nfaProprietaryCfg.discoveryPollKovio = static_cast<uint8_t>(buffer[6]);
    config.nfaProprietaryCfg.discoveryPollBPrime = static_cast<uint8_t>(buffer[7]);
    config.nfaProprietaryCfg.discoveryListenBPrime = static_cast<uint8_t>(buffer[8]);
    config.nfaProprietaryCfg.protocolChineseId = static_cast<uint8_t>(buffer[9]);
  } else {
    memset(&config.nfaProprietaryCfg, 0xFF, sizeof(ProtocolDiscoveryConfig));
  }
  if ((GetNxpNumValue(NAME_PRESENCE_CHECK_ALGORITHM, &num, sizeof(num))) &&
      (num <= 2)) {
    config.presenceCheckAlgorithm = static_cast<PresenceCheckAlgorithm>(num);
  }
}

}  // namespace nfc
}  // namespace hardware
}  // namespace android
}  // namespace aidl
