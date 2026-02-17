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
#include <cstring>
#include <phNxpLog.h>
#include <stdlib.h>
#include <string.h>

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
  // return ct_discover_tda(tda_data);
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::open(uint8_t tdaId, uint8_t standBy, uint8_t &cid) {
  // return ct_open(tdaId, standBy, cid);
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::transceive(std::vector<uint8_t> command,
                          std::vector<uint8_t> &response) {
  tda_data tda_cmd;
  tda_data tda_res;
  tda_cmd.len = command.size();
  tda_cmd.p_data = command.data();
  // ct_transceive(tda_cmd, tda_res);
  response.resize(tda_res.len);
  std::copy(tda_res.p_data, tda_res.p_data + tda_res.len, response.begin());
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::close(uint8_t tdaId, uint8_t standBy) {
  // return ct_close(tdaId, standBy);
  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

NFCSTATUS Tda::processResponseNtf(uint16_t dataLen, uint8_t *pData) {
  /*if (process_tda_rsp_ntf(pData, dataLen) == EMVCO_STATUS_SUCCESS) {
    return NFCSTATUS_EXTN_FEATURE_SUCCESS;
  }*/
  return NFCSTATUS_EXTN_FEATURE_FAILURE;
}
