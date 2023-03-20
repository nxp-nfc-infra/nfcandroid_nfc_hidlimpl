/******************************************************************************
 *
 *  Copyright 2015-2018,2020-2023 NXP
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
#define LOG_TAG "NxpHal"
#include "NxpNfcCapability.h"
#include <phNxpLog.h>

capability *capability::instance = NULL;
tNFC_chipType capability::chipType = pn7220;
tNfc_featureList nfcFL;

capability::capability() {}

capability *capability::getInstance() {
  if (NULL == instance) {
    instance = new capability();
  }
  return instance;
}

tNFC_chipType capability::processChipType(uint8_t *msg, uint16_t msg_len) {
  if ((msg != NULL) && (msg_len != 0)) {
    if (msg[0] == 0x60 && msg[1] == 0x00) {
      if (msg[msg_len - 3] == 0x03 && msg[msg_len - 2] == 0x00)
        chipType = pn7220;
    } else if (msg[0] == 0x00) {
      if (msg[offsetFwRomCodeVersion] == 0x03)
        chipType = pn7220;
    } else if (offsetHwVersion < msg_len) {
      ALOGD("%s HwVersion : 0x%02x", __func__, msg[msg_len - 4]);
      switch (msg[msg_len - 4]) {
      case 0x53:
        chipType = pn7220;
        break;
      default:
        chipType = pn7220;
      }
    } else {
      ALOGD("%s Wrong msg_len. Setting Default ChiptType pn7220", __func__);
      chipType = pn7220;
    }
  }
  ALOGD("%s Product : %s", __func__, product[chipType]);
  return chipType;
}

uint32_t capability::getFWVersionInfo(uint8_t *msg, uint16_t msg_len) {
  uint32_t versionInfo = 0;
  if ((msg != NULL) && (msg_len != 0)) {
    if (msg[0] == 0x00) {
      versionInfo = msg[offsetFwRomCodeVersion] << 16;
      versionInfo |= msg[offsetFwMajorVersion] << 8;
      versionInfo |= msg[offsetFwMinorVersion];
    }
  }
  return versionInfo;
}
