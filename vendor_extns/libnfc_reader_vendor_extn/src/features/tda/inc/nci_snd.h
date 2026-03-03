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

#ifndef NCI_SND_H_
#define NCI_SND_H_

/** \addtogroup NCI_SND_INTERFACE
 *  @brief  interface to form and send the NCI command to controller
 *  @{
 */

#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MS_NTF_TIMEOUT_IN_SEC 0x02
#define MAX_WTX_TIMEOUT_IN_SEC  0x02
static unsigned int max_wtx_time_out = MAX_WTX_TIMEOUT_IN_SEC; // By default, 2sec is WTX time out

/**
 *
 * @brief           This function is called to enable or disable NFCEE
 *                  Discovery.
 *
 * @return          NFC status:
 *                  NFC_STATUS_SUCCESS - command processed successfully
 *                  NFC_STATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfcee_discover();

/**
 *
 * @brief           This function is called to activate or de-activate an NFCEE
 *                  connected to the NFCC.
 *
 * @param[in]       nfcee_id - the NFCEE to activate or de-activate.
 *                  nfcee_mode - NFC_MODE_ACTIVATE to activate NFCEE,
 *                  NFC_MODE_DEACTIVATE to de-activate.
 *
 * @return          NFC status:
 *                  NFC_STATUS_SUCCESS - command processed successfully
 *                  NFC_STATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfcee_mode_set(uint8_t nfcee_id, uint8_t nfcee_mode);

/**
 *
 * @brief           compose and send CORE CONN_CREATE command to command queue
 *
 * @param[in]       conn_id - Connection ID
 *
 * @return          NFC status:
 *                  NFC_STATUS_SUCCESS - command processed successfully
 *                  NFC_STATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_core_conn_create(uint8_t conn_id);

/**
 *
 * @brief           compose and send CORE CONN_CLOSE command to command queue
 *
 * @param[in]       channel_num - logical connection ID
 *
 * @return          NFC status:
 *                  NFC_STATUS_SUCCESS - command processed successfully
 *                  NFC_STATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_core_conn_close(uint8_t channel_num);

/**
 *
 * @brief           Internal function to send raw APDU to controller
 *
 * @param[in]       p_data - data buffer pointer
 * @param[in]       data_len - data buffer length
 *
 * @return          NFC status:
 *                  NFC_STATUS_SUCCESS - command processed successfully
 *                  NFC_STATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfc_ct_data(uint8_t *p_data, uint16_t data_len);

/**
 *
 * @brief           sets the WTX time out value
 *
 * @param[in]       time_out_val WTX time out value in secs
 *
 * @return void
 *
 */
void set_max_wtx_timeout_val(uint8_t time_out_val);

#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* NCI_SND_H_ */
