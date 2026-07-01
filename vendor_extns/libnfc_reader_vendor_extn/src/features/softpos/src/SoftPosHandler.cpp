/**
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
 **/

#include "SoftPosHandler.h"
#include "NfcExtensionConstants.h"
#include "NfcExtensionController.h"
#include "NfcExtensionWriter.h"
#include "PlatformAbstractionLayer.h"
#include <phNxpLog.h>

NxpSoftPos* SoftPosHandler::mSoftPosMngr = nullptr;

SoftPosHandler::SoftPosHandler() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter", __func__);
  mSoftPosMngr = NxpSoftPos::getInstance();
}

SoftPosHandler::~SoftPosHandler() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter", __func__);
  mSoftPosMngr->finalize();
}

void SoftPosHandler::onFeatureStart() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "SoftPosHandler::%s Enter", __func__);
  NfcExtensionWriter::getInstance()->requestHalControl();
}

void SoftPosHandler::onFeatureEnd() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "SoftPosHandler::%s Enter", __func__);
  NfcExtensionWriter::getInstance()->releaseHalControl();
}

NFCSTATUS SoftPosHandler::handleVendorNciMessage(uint16_t dataLen,
                                             const uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "SoftPosHandler::%s Enter dataLen:%d",
                 __func__, dataLen);

  HandlerType currentHandleType;
  NFCSTATUS status = NFCSTATUS_EXTN_FEATURE_FAILURE;
  std::vector<uint8_t> response;
  int offset = NCI_PAYLOAD_LEN_INDEX;
  int payload_len = pData[offset++];

  if ((dataLen < NCI_HEADER_LEN) || (payload_len > (dataLen - NCI_HEADER_LEN))) {
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN,
                   "SoftPosHandler::%s Received corrupted payload ", __func__);
    return status;
  }

  const uint8_t subGidOid = pData[offset++];
  const uint8_t subGid = subGidOid >> 4;
  if (subGid != SOFTPOS_SUB_GID) {
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "SoftPosHandler::%s Not SoftPos GID ",
                   __func__);
    return status;
  }
  currentHandleType =
      NfcExtensionController::getInstance()->getEventHandlerType();
  if (currentHandleType != HandlerType::SOFTPOS) {
    NfcExtensionController::getInstance()->switchEventHandler(HandlerType::SOFTPOS);
  }
  response.push_back(NCI_PROP_RSP_VAL);
  response.push_back(NCI_READER_PROP_OID_VAL);

  switch (subGidOid) {
  case SWITCH_MODE_EMVCO: {
      response.push_back(0x02);
      response.push_back(SWITCH_MODE_EMVCO);
      uint8_t techConfig = pData[offset++];
      if (mSoftPosMngr->switchEmvcoMode(techConfig)) {
        response.push_back(RESPONSE_STATUS_OK);
      } else {
        response.push_back(RESPONSE_STATUS_FAILED);
      }
  } break;
  case SWITCH_MODE_NORMAL: {
      response.push_back(0x02);
      response.push_back(SWITCH_MODE_NORMAL);
      if (mSoftPosMngr->switchNciMode()) {
        response.push_back(RESPONSE_STATUS_OK);
      } else {
        response.push_back(RESPONSE_STATUS_FAILED);
      }
  } break;
  case GET_MODE: {
      response.push_back(0x03);
      response.push_back(GET_MODE);
      response.push_back(RESPONSE_STATUS_OK);
      response.push_back(mSoftPosMngr->isEMVCOMode());
  } break;
  default: {
      NfcExtensionController::getInstance()->switchEventHandler(
         HandlerType::DEFAULT);
      return NFCSTATUS_EXTN_FEATURE_FAILURE;
  }
  }
  PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
      response.size(), response.data());
  status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  NfcExtensionController::getInstance()->switchEventHandler(
      HandlerType::DEFAULT);
  return status;
}

NFCSTATUS SoftPosHandler::handleVendorNciRspNtf(uint16_t dataLen, uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN,
                 "SoftPosHandler::%s "
                 "Enter dataLen:%d",
                 __func__, dataLen);

  return NFCSTATUS_EXTN_FEATURE_SUCCESS;
}

void SoftPosHandler::onWriteComplete(uint8_t status) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter status:%d", __func__,
                 status);
  NfcExtensionWriter::getInstance()->onWriteComplete(status);
}

void SoftPosHandler::onWriteRspTimeout() {
  NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  const HandlerType currentHandleType =
      NfcExtensionController::getInstance()->getEventHandlerType();
  if (currentHandleType == HandlerType::SOFTPOS) {
    NfcExtensionController::getInstance()->switchEventHandler(
        HandlerType::DEFAULT);
  }
}

NFCSTATUS SoftPosHandler::processExtnWrite(uint16_t *dataLen, uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  return NFCSTATUS_EXTN_FEATURE_FAILURE;
}
