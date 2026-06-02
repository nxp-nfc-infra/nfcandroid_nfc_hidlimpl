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

#ifndef SOFTPOS_HANDLER_H
#define SOFTPOS_HANDLER_H

#include "IEventHandler.h"
#include <cstdint>
#include <vector>
#include "NxpSoftPos.h"

/** \addtogroup SOFTPOS_HANDLER_API_INTERFACE
 *  @brief  interface to perform the SoftPos feature functionality.
 *  @{
 */
class SoftPosHandler : public IEventHandler {
public:
  /**
   * @brief handles the vendor NCI message
   * @return returns NFCSTATUS_EXTN_FEATURE_SUCCESS, if it is vendor specific
   * feature and handled by extension library otherwise
   * NFCSTATUS_EXTN_FEATURE_FAILURE.
   *
   */
  NFCSTATUS handleVendorNciMessage(uint16_t dataLen, const uint8_t *pData);

  /**
   * @brief handles the vendor NCI response and notification
   * @return returns NFCSTATUS_EXTN_FEATURE_SUCCESS, if it is vendor specific
   * feature and handled by extension library otherwise
   * NFCSTATUS_EXTN_FEATURE_FAILURE.
   *
   */
  NFCSTATUS handleVendorNciRspNtf(uint16_t dataLen, uint8_t *pData) override;

  /**
   * @brief on Feature start, Current Handler have to be registered with
   * controller through switchEventHandler interface
   * @return void
   *
   */
  void onFeatureStart() override;

  /**
   * @brief on Feature End, Default Handler have to be registered with
   * controller through switchEventHandler interface
   * @return void
   *
   */
  void onFeatureEnd() override;

  SoftPosHandler();

  ~SoftPosHandler();
  /**
   * @brief handles the control granted callback, if concrete
   *        handler does not handle it
   * \note This function should be light weight and shall not
   * take much time to execute otherwise all other processing
   * will be blocked.
   * @return returns void
   *
   */
  void onWriteComplete(uint8_t status) override;

  /**
   * @brief indicates that write response time out for the
   *        NCI packet sent to controller
   *
   * @return void
   *
   */
  void onWriteRspTimeout() override;

  /**
   * @brief on receiving command and change specfic to SoftPos feature if required
   *
   * @param dataLen
   * @param pData
   * @return returns NFCSTATUS_EXTN_FEATURE_SUCCESS, if it is vendor specific
   * feature and handled by extension library otherwise
   * NFCSTATUS_EXTN_FEATURE_FAILURE.
   */
  NFCSTATUS processExtnWrite(uint16_t *dataLen, uint8_t *pData) override;

private:
  static NxpSoftPos* mSoftPosMngr;
  static constexpr uint8_t SOFTPOS_SUB_GID = 0x03;
  static constexpr uint8_t SWITCH_MODE_EMVCO = 0x31;
  static constexpr uint8_t SWITCH_MODE_NORMAL = 0x32;
  static constexpr uint8_t GET_MODE = 0x33;
};
/** @}*/
#endif // SOFTPOS_HANDLER_H
