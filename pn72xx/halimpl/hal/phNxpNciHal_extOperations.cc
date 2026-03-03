/*
 * Copyright 2019-2021,2023-2024,2026 NXP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "phNxpNciHal_extOperations.h"
#include "phNfcCommon.h"
#include "phNfcNciConstants.h"
#include "phNxpNciHal_IoctlOperations.h"
#include <phNxpLog.h>
#include <phTmlNfc.h>

#define NCI_HEADER_SIZE 3
#define NCI_SE_CMD_LEN 4
nxp_nfc_config_ext_t config_ext;
extern phNxpNciHal_Control_t nxpncihal_ctrl;
extern phTmlNfc_Context_t *gpphTmlNfc_Context;
static std::vector<uint8_t> uicc1HciParams(0);
static std::vector<uint8_t> uicc2HciParams(0);
static std::vector<uint8_t> uiccHciCeParams(0);

/******************************************************************************
 * Function         phNxpNciHal_updateAutonomousPwrState
 *
 * Description      This function can be used to update autonomous pwr state.
 *                  num: value to check  switch off bit is set or not.
 *
 * Returns          uint8_t
 *
 ******************************************************************************/
uint8_t phNxpNciHal_updateAutonomousPwrState(uint8_t num) {
  if ((config_ext.autonomous_mode == true) &&
      ((num & SWITCH_OFF_MASK) == SWITCH_OFF_MASK)) {
    num = (num | AUTONOMOUS_SCREEN_OFF_LOCK_MASK);
  }
  return num;
}
/*******************************************************************************
**
** Function         phNxpNciHal_hndlVndSpecificAndroidCmd()
**
** Description      This handles the vendor specific command
**
** Returns          It returns number of bytes received.
*******************************************************************************/
int phNxpNciHal_hndlVndSpecificAndroidCmd(uint16_t data_len,
                                          const uint8_t *p_data) {
  if (data_len >= 4 &&
      p_data[NCI_MSG_INDEX_FOR_FEATURE] == NCI_ANDROID_GET_CAPABILITY) {
    // 2F 0C 01 00 => GetCapability Command length is 4 Bytes
    return handleGetCapability(data_len, p_data);
  } else {
    return -1;
  }
}
/*******************************************************************************
**
** Function         phNxpNciHal_vendorSpecificCallback()
**
** Params           oid, opcode, data
**
** Description      This function sends response to Vendor Specific commands
**
*******************************************************************************/
void phNxpNciHal_vendorSpecificCallback(int oid, int opcode,
                                        std::vector<uint8_t> data) {
  static phLibNfc_Message_t msg;
  nxpncihal_ctrl.vendor_msg[0] =
      static_cast<uint8_t>(NCI_GID_PROP | NCI_MT_RSP);
  nxpncihal_ctrl.vendor_msg[1] = oid;
  nxpncihal_ctrl.vendor_msg[2] = 1 + static_cast<int>(data.size());
  nxpncihal_ctrl.vendor_msg[3] = opcode;
  if (static_cast<int>(data.size()) > 0) {
    memcpy(&nxpncihal_ctrl.vendor_msg[4], data.data(),
           data.size() * sizeof(uint8_t));
  }
  nxpncihal_ctrl.vendor_msg_len = 4 + static_cast<int>(data.size());
  msg.eMsgType = NCI_HAL_VENDOR_MSG;
  msg.pMsgData = NULL;
  msg.Size = 0;
  phNxpNciHal_print_packet("RECV", nxpncihal_ctrl.vendor_msg,
                           nxpncihal_ctrl.vendor_msg_len);
  phTmlNfc_DeferredCall(gpphTmlNfc_Context->dwCallbackThreadId, &msg);
}
/*******************************************************************************
 *
 * Function         handleGetCapability()
 *
 * Description      It frames the capability for the below features
 *                  1. Observe mode
 *                  2. Polling frame notification
 *                  3. Power saving mode
 *                  4. Auto transact polling loop filter
 *
 * Returns          It returns number of bytes received.
 *
 ******************************************************************************/
int handleGetCapability(uint16_t data_len, const uint8_t *p_data) {
  // 2F 0C 01 00 => GetCapability Command length is 4 Bytes
  if (data_len < 4) {
    return 0;
  }
  // First byte is status is ok
  // next 2 bytes is version for Android requirements
  std::vector<uint8_t> capability = {0x00, 0x00, 0x00};
  capability.push_back(5); // 5 capability event's
  // Observe mode
  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.id);
  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.len);
  capability.push_back(nfcFL.nfccCap.OBSERVE_MODE.val);
  // Polling frame notification
  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.id);
  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.len);
  capability.push_back(nfcFL.nfccCap.POLLING_FRAME_NOTIFICATION.val);
  // Power saving mode
  capability.push_back(nfcFL.nfccCap.POWER_SAVING.id);
  capability.push_back(nfcFL.nfccCap.POWER_SAVING.len);
  capability.push_back(nfcFL.nfccCap.POWER_SAVING.val);
  // Auto transact polling loop filter
  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.id);
  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.len);
  capability.push_back(nfcFL.nfccCap.AUTOTRANSACT_PLF.val);
  // No of exit frames supported
  capability.push_back(nfcFL.nfccCap.NO_OF_EXIT_FRAMES_PLF.id);
  capability.push_back(nfcFL.nfccCap.NO_OF_EXIT_FRAMES_PLF.len);
  capability.push_back(nfcFL.nfccCap.NO_OF_EXIT_FRAMES_PLF.val);
  phNxpNciHal_vendorSpecificCallback(p_data[NCI_OID_INDEX],
                                     p_data[NCI_MSG_INDEX_FOR_FEATURE],
                                     std::move(capability));
  return p_data[NCI_MSG_LEN_INDEX];
}