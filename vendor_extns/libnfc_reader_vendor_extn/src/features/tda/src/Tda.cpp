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

#include "Tda.h"
#include "NciStateMonitor.h"
#include "NfcExtensionApi.h"
#include "NfcExtensionController.h"
#include "NfcExtensionWriter.h"
#include "PlatformAbstractionLayer.h"
#include <phNxpConfig.h>
#include <cstring>
#include <phNxpLog.h>
#include <stdlib.h>
#include <string.h>
#include <tda_api.h>

std::unique_ptr<Tda> Tda::instance = nullptr;

Tda::Tda() {}

Tda::~Tda() {}

Tda *Tda::getInstance() {
  if (!instance) {
    instance = std::unique_ptr<Tda>(new Tda());
  }
  return instance.get();
}

static void switchToDefaultHandler() {
  NfcExtensionController::getInstance()->switchEventHandler(
      HandlerType::DEFAULT);
}

NFCSTATUS Tda::discover(tda_control_t *tda_data) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  if (ct_get_tda_state() == INIT_STATE) {
    if (ct_init_ext() != NFCSTATUS_SUCCESS) {
      NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s TDA CT init Failed  ", __func__);
      return NFCSTATUS_FAILED;
    }
    unsigned long num = 0;
    if (GetNxpNumValue(NAME_NXP_CT_MAX_WTX_WAIT_TIME, &num, sizeof(num)) > 0) {
      set_max_wtx_timeout_value(num);
    } else {
      NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s NXP_CT_MAX_WTX_WAIT_TIME not found", __func__);
    }
  }
  if (ct_discover_tda(tda_data) != NFCSTATUS_SUCCESS) {
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Discover TDA Failed  ", __func__);
    return NFCSTATUS_FAILED;
  }
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::open(uint8_t tdaId, uint8_t standBy, uint8_t &cid) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  int8_t cid_val = 0;

  if (ct_open((int8_t)tdaId, (int8_t)standBy, &cid_val) != NFCSTATUS_SUCCESS) {
    return NFCSTATUS_FAILED;
  }
  cid = (uint8_t)cid_val;
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::transceive(std::vector<uint8_t> command,
                          std::vector<uint8_t> &response) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  tda_data tda_cmd;
  tda_data tda_res;
  tda_cmd.len = command.size();
  tda_cmd.p_data = command.data();
  if (ct_transceive(&tda_cmd, &tda_res) != NFCSTATUS_SUCCESS) {
    return NFCSTATUS_FAILED;
  }
  response.resize(tda_res.len);
  std::copy(tda_res.p_data, tda_res.p_data + tda_res.len, response.begin());
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::close(uint8_t tdaId, uint8_t standBy) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  NFCSTATUS status = NFCSTATUS_FAILED;
  if (NFCSTATUS_SUCCESS == ct_close((int8_t) tdaId, (int8_t) standBy)) {
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  }
  if (ct_de_init_ext() != NFCSTATUS_SUCCESS) {
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s TDA CT deinit Failed  ", __func__);
  }
  return status;
}

system_state_t Tda::getTdaState() {
  return ct_get_tda_state();
}

NFCSTATUS Tda::processResponseNtf(uint16_t dataLen, uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  if (process_tda_rsp_ntf(pData, dataLen) == NFCSTATUS_SUCCESS) {
    return NFCSTATUS_EXTN_FEATURE_SUCCESS;
  }
  return NFCSTATUS_EXTN_FEATURE_FAILURE;
}
