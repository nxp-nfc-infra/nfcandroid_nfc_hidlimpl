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

#ifndef TDA_HANDLER_H
#define TDA_HANDLER_H

#include "IEventHandler.h"
#include <cstdint>
#include <vector>

/** \addtogroup TDA_HANDLER_API_INTERFACE
 *  @brief  interface to perform the TDA feature functionality.
 *  @{
 */
class TdaHandler : public IEventHandler {
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

  TdaHandler();

  ~TdaHandler();
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
   * @brief on receiving command and change specfic to TDA feature if required
   *
   * @param dataLen
   * @param pData
   * @return returns NFCSTATUS_EXTN_FEATURE_SUCCESS, if it is vendor specific
   * feature and handled by extension library otherwise
   * NFCSTATUS_EXTN_FEATURE_FAILURE.
   */
  NFCSTATUS processExtnWrite(uint16_t *dataLen, uint8_t *pData) override;

private:
  static constexpr uint8_t TDA_SUB_GID = 0x01;
  static constexpr uint8_t DISCOVER_TDA_GID_OID = 0x11;
  static constexpr uint8_t OPEN_TDA_GID_OID = 0x12;
  static constexpr uint8_t TRANSCIVE_TDA_GID_OID = 0x13;
  static constexpr uint8_t CLOSE_TDA_GID_OID = 0x14;
  static constexpr uint8_t GET_TDA_STATE_GID_OID = 0x15;
};
/** @}*/
#endif // TDA_HANDLER_H
