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

#include "TdaHandler.h"
#include "NfcExtensionConstants.h"
#include "NfcExtensionController.h"
#include "NfcExtensionWriter.h"
#include "PlatformAbstractionLayer.h"
#include "Tda.h"
#include <phNxpLog.h>

Tda *mTdaMngr = Tda::getInstance();

TdaHandler::TdaHandler() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter", __func__);
}

TdaHandler::~TdaHandler() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter", __func__);
  mTdaMngr->finalize();
}

void TdaHandler::onFeatureStart() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "TdaHandler::%s Enter", __func__);
}

void TdaHandler::onFeatureEnd() {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "TdaHandler::%s Enter", __func__);
  NfcExtensionWriter::getInstance()->releaseHalControl();
}

NFCSTATUS TdaHandler::handleVendorNciMessage(uint16_t dataLen,
                                             const uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "TdaHandler::%s Enter dataLen:%d",
                 __func__, dataLen);

  HandlerType currentHandleType;
  NFCSTATUS status = NFCSTATUS_EXTN_FEATURE_FAILURE;
  std::vector<uint8_t> response;
  int offset = NCI_PAYLOAD_LEN_INDEX;
  int payload_len = pData[offset++];

  if ((payload_len + NCI_HEADER_LEN) > dataLen) {
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN,
                   "TdaHandler::%s Received corrupted payload ", __func__);
    return status;
  }

  const uint8_t subGidOid = pData[offset++];
  const uint8_t subGid = subGidOid >> 4;
  if (subGid != TDA_SUB_GID) {
    NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "TdaHandler::%s Not TDA GID ",
                   __func__);
    return status;
  }
  currentHandleType =
      NfcExtensionController::getInstance()->getEventHandlerType();
  if (currentHandleType != HandlerType::TDA) {
    NfcExtensionController::getInstance()->switchEventHandler(HandlerType::TDA);
  }

  switch (subGidOid) {
  case DISCOVER_TDA_GID_OID: {
    tda_control_t tda_control;
    response.push_back(NCI_PROP_RSP_VAL);
    response.push_back(NCI_READER_PROP_OID_VAL);
    response.push_back(0x00); // Length to be modify after calculation
    response.push_back(DISCOVER_TDA_GID_OID);
    if (mTdaMngr->discover(&tda_control) == NFCSTATUS_EXTN_FEATURE_SUCCESS) {
      response.push_back(RESPONSE_STATUS_OK);
      response.push_back(tda_control.num_tda_supported);
      for (int i = 0; i < tda_control.num_tda_supported; i++) {
        if ((tda_control.p_tda + i) != nullptr) {
          response.push_back((tda_control.p_tda + i)->id);
          response.push_back((tda_control.p_tda + i)->status);
          response.push_back((tda_control.p_tda + i)->number_of_protocols);
          if ((tda_control.p_tda + i)->number_of_protocols > 0) {
            for (int j = 0; j < (tda_control.p_tda + i)->number_of_protocols;
                 j++) {
              uint8_t protocolVal =
                  (*((uint8_t *)((tda_control.p_tda + i)->protocols_t) + j));
              response.push_back(protocolVal);
            }
          }
          uint8_t numberOfCardInfo =
              (tda_control.p_tda + i)->number_of_card_info;
          response.push_back(numberOfCardInfo);
          if (numberOfCardInfo > 0) {
            for (int k = 0; k < numberOfCardInfo; k++) {
              response.push_back((tda_control.p_tda + i)->card_tlv_info->type);
              uint8_t cardtlvlength =
                  ((tda_control.p_tda + i)->card_tlv_info->length);
              response.push_back(cardtlvlength);
              if (cardtlvlength > 0) {
                for (int l = 0; l < cardtlvlength; l++) {
                  uint8_t *value = ((uint8_t *)((tda_control.p_tda + i)
                                                    ->card_tlv_info->value) +
                                    l);
                  response.push_back(*value);
                }
              }
            }
          }
        }
      }
      response[NCI_PAYLOAD_LEN_INDEX] =
          (uint8_t)(response.size() - NCI_HEADER_LEN);
    } else {
      response[NCI_PAYLOAD_LEN_INDEX] = 2;
      response.push_back(RESPONSE_STATUS_FAILED);
    }
    PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
        response.size(), response.data());
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  } break;
  case OPEN_TDA_GID_OID: {
    uint8_t tdaId = pData[offset++];
    uint8_t standBy = pData[offset++];
    uint8_t cid;
    response.push_back(NCI_PROP_RSP_VAL);
    response.push_back(NCI_READER_PROP_OID_VAL);
    if (mTdaMngr->open(tdaId, standBy, cid) == NFCSTATUS_EXTN_FEATURE_SUCCESS) {
      response.push_back(0x03);
      response.push_back(OPEN_TDA_GID_OID);
      response.push_back(RESPONSE_STATUS_OK);
      response.push_back(cid);
    } else {
      response.push_back(0x02);
      response.push_back(OPEN_TDA_GID_OID);
      response.push_back(RESPONSE_STATUS_FAILED);
    }
    PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
        response.size(), response.data());
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  } break;
  case TRANSCIVE_TDA_GID_OID: {
    uint8_t command_len = pData[offset++];
    std::vector<uint8_t> cmd(pData + offset, pData + offset + command_len);
    std::vector<uint8_t> transResponse;
    response.push_back(NCI_PROP_RSP_VAL);
    response.push_back(NCI_READER_PROP_OID_VAL);
    if (mTdaMngr->transceive(cmd, transResponse) ==
        NFCSTATUS_EXTN_FEATURE_SUCCESS) {
      response.push_back(transResponse.size() + 2);
      response.push_back(TRANSCIVE_TDA_GID_OID);
      response.push_back(RESPONSE_STATUS_OK);
      response.insert(response.end(), transResponse.begin(),
                      transResponse.end());
    } else {
      response.push_back(0x02);
      response.push_back(TRANSCIVE_TDA_GID_OID);
      response.push_back(RESPONSE_STATUS_FAILED);
    }
    PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
        response.size(), response.data());
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  } break;
  case CLOSE_TDA_GID_OID: {
    uint8_t tdaId = pData[offset++];
    uint8_t standBy = pData[offset++];
    response.push_back(NCI_PROP_RSP_VAL);
    response.push_back(NCI_READER_PROP_OID_VAL);
    response.push_back(0x02);
    response.push_back(CLOSE_TDA_GID_OID);
    if (mTdaMngr->close(tdaId, standBy) == NFCSTATUS_EXTN_FEATURE_SUCCESS) {
      response.push_back(RESPONSE_STATUS_OK);
    } else {
      response.push_back(RESPONSE_STATUS_FAILED);
    }
    PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
        response.size(), response.data());
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  } break;
  case GET_TDA_STATE_GID_OID: {
    response.push_back(NCI_PROP_RSP_VAL);
    response.push_back(NCI_READER_PROP_OID_VAL);
    system_state_t tdaState = mTdaMngr->getTdaState();
    response.push_back(0x03);
    response.push_back(GET_TDA_STATE_GID_OID);
    response.push_back(RESPONSE_STATUS_OK);
    switch (tdaState) {
      case INIT_STATE:
        response.push_back(0x00);
        break;
      case DISCOVERED_STATE:
        response.push_back(0x01);
        break;
      case MODE_SET_ENABLED_STATE:
        response.push_back(0x02);
        break;
      case CORE_CONN_CREATED_STATE:
        response.push_back(0x03);
        break;
      case CORE_CONN_CLOSED_STATE:
        response.push_back(0x04);
        break;
      case LAST_STATE:
      default:
        response[NCI_PAYLOAD_LEN_INDEX] = 2;
        response.push_back(RESPONSE_STATUS_FAILED);
        break;
    }
    PlatformAbstractionLayer::getInstance()->palSendNfcDataCallback(
        response.size(), response.data());
    status = NFCSTATUS_EXTN_FEATURE_SUCCESS;
  } break;
  }
  NfcExtensionController::getInstance()->switchEventHandler(
      HandlerType::DEFAULT);
  return status;
}

NFCSTATUS TdaHandler::handleVendorNciRspNtf(uint16_t dataLen, uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN,
                 "TdaHandler::%s "
                 "Enter dataLen:%d",
                 __func__, dataLen);

  return mTdaMngr->processResponseNtf(dataLen, pData);
}

void TdaHandler::onWriteComplete(uint8_t status) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter status:%d", __func__,
                 status);
  NfcExtensionWriter::getInstance()->onWriteComplete(status);
}

void TdaHandler::onWriteRspTimeout() {
  NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  const HandlerType currentHandleType =
      NfcExtensionController::getInstance()->getEventHandlerType();
  if (currentHandleType == HandlerType::TDA) {
    NfcExtensionController::getInstance()->switchEventHandler(
        HandlerType::DEFAULT);
  }
}

NFCSTATUS TdaHandler::processExtnWrite(uint16_t *dataLen, uint8_t *pData) {
  NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, "%s Enter ", __func__);
  return NFCSTATUS_EXTN_FEATURE_FAILURE;
}
