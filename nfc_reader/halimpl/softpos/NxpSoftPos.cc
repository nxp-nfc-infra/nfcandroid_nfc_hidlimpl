/*
 *
 *  The original Work has been changed by NXP.
 *
 *  Copyright 2026 NXP
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
 */

#include "NxpSoftPos.h"
#include <phNxpConfig.h>
#include <cstring>
#include <phNxpLog.h>
#include <stdlib.h>
#include <string.h>
#include <phNxpNciHal.h>
#include <phTmlNfc.h>
#include <phNxpNciHal_ext.h>
#include "phNxpNciHal_IoctlOperations.h"
#include <phNfcNciConstants.h>

std::unique_ptr<NxpSoftPos> NxpSoftPos::instance = nullptr;

NxpSoftPos::NxpSoftPos() {}

NxpSoftPos::~NxpSoftPos() {}

NxpSoftPos *NxpSoftPos::getInstance() {
  if (!instance) {
    instance = std::unique_ptr<NxpSoftPos>(new NxpSoftPos());
  }
  return instance.get();
}

bool NxpSoftPos::switchEmvcoMode(uint8_t techConfig) {
  NXPLOG_NCIHAL_D("%s Enter ", __func__);
  std::vector<uint8_t> cmd = buildSoftPosRfDiscoveryCmd(techConfig);
  phNxpNciHal_setSoftPosModeRfDiscCmd(cmd);
  std::vector<uint8_t> rf_disc_cmd = {0x21,0x03};

  if (mIsEmvcoMode) {
    NXPLOG_NCIHAL_D("%s Already in EMVCO Mode", __func__);
    return true;
  }
  if (!performNciCoreReset()) {
    NXPLOG_NCIHAL_D("%s Failed to perform nci core reset", __func__);
    return false;
  }
  if (NFCSTATUS_SUCCESS != phTmlNfc_IoCtl(phTmlNfc_e_ResetDevice)) {
    NXPLOG_NCIHAL_W("%s failed to perform ven toggle", __func__);
  }
  if (NFCSTATUS_SUCCESS != phTmlNfc_IoCtl(phTmlNfc_e_ModeSwitchOn)) {
    NXPLOG_NCIHAL_E("%s Failed to toggle gpio", __func__);
    return false;
  }

  if (NFCSTATUS_SUCCESS != phTmlNfc_IoCtl(phTmlNfc_e_RedLedOff)) {
    NXPLOG_NCIHAL_W("%s failed to switch red light", __func__);
  }
  if (NFCSTATUS_SUCCESS != phTmlNfc_IoCtl(phTmlNfc_e_GreenLedOn)) {
    NXPLOG_NCIHAL_W("%s failed to switch green light", __func__);
  }
  if (phNxpNciHal_nfcc_core_reset_init(true) != NFCSTATUS_SUCCESS) {
    NXPLOG_NCIHAL_E("%s Failed to perform nci core reset", __func__);
  }
  if (!setRequiredConfig()) {
    NXPLOG_NCIHAL_E("%s Failed to set the required config", __func__);
  }
  if (!performPropAct()) {
    NXPLOG_NCIHAL_W("%s Failed to perform prop act command", __func__);
  }
  mIsEmvcoMode = true;
  return true;
}

bool NxpSoftPos::switchNciMode() {
  phNxpNciHal_setSoftPosModeRfDiscCmd({});
  if (!mIsEmvcoMode) {
    NXPLOG_NCIHAL_D("%s Already in NCI Mode", __func__);
    return true;
  }
  // Update the flag Nfc disable/enable will switch mode to NFC
  mIsEmvcoMode = false;
  return true;
}

bool NxpSoftPos::performPropAct() {
  uint8_t cmd[] = {0x2F, 0x02, 0x00};
  if (phNxpNciHal_send_ext_cmd(sizeof(cmd), cmd)
      == NFCSTATUS_SUCCESS) {
    return true;
  }
  return false;
}

bool NxpSoftPos::performNciCoreReset() {
  uint8_t cmd_reset_nci[] = {0x20, 0x00, 0x01, 0x00};
  uint8_t retry = 0;

  do { /*This is NXP_EXTNS code for retry*/
    if (phNxpNciHal_send_ext_cmd(sizeof(cmd_reset_nci), cmd_reset_nci)
        == NFCSTATUS_SUCCESS) {
      return true;
    } else {
      NXPLOG_NCIHAL_E("NCI_CORE_RESET: Failed, perform retry after delay");
      retry++;
      if (retry > 3) {
        NXPLOG_NCIHAL_E(
            "Maximum retries performed, shall restart HAL to recover");
      }
    }
  } while(retry < 3);
  return false;
}

bool NxpSoftPos::setRequiredConfig() {
  uint8_t cmd[] = {0x20, 0x02, 0x05, 0x01,0xA0, 0x44, 0x01, 0x02};
  if (phNxpNciHal_send_ext_cmd(sizeof(cmd), cmd)
      == NFCSTATUS_SUCCESS) {
    return true;
  }
  return false;
}

std::vector<uint8_t> NxpSoftPos::buildSoftPosRfDiscoveryCmd(uint8_t techConfig) {
    std::vector<uint8_t> cmd;
    cmd.push_back(NCI_RF_DISC_COMMD_GID);
    cmd.push_back(NCI_RF_DISC_COMMAND_OID);
    cmd.push_back(0x00);
    uint8_t total_tech = 0;
    cmd.push_back(0x00);
    if (techConfig & TECH_MASK_A) {
        cmd.push_back(TECH_NFC_A_POLL);
        cmd.push_back(DISCOVERY_FREQ);
        total_tech++;
    }
    if (techConfig & TECH_MASK_B) {
        cmd.push_back(TECH_NFC_B_POLL);
        cmd.push_back(DISCOVERY_FREQ);
        total_tech++;
    }
    if (techConfig & TECH_MASK_F) {
        cmd.push_back(TECH_NFC_F_POLL);
        cmd.push_back(DISCOVERY_FREQ);
        total_tech++;
    }
    cmd[NCI_MSG_LEN_INDEX] = static_cast<uint8_t>(1 + (total_tech * 2));
    /* number of tech value set */
    cmd[NCI_MSG_LEN_INDEX + 1] = total_tech;
    return cmd;
}

bool NxpSoftPos::isEMVCOMode() {
  return mIsEmvcoMode;
}
