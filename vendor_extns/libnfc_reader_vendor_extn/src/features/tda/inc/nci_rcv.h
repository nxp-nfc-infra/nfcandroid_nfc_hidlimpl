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

#ifndef NCI_RCV_H
#define NCI_RCV_H
/** \addtogroup NCI_RCV_INTERFACE
 *  @brief  interface to process the NCI response, notification and data packet
 *  @{
 */
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief process TDA discover response and handles the errors
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_tda_discover_rsp(uint8_t *p_rsp, uint16_t p_len);
/**
 * @brief process TDA core connection close response and updates the connection
 * ID
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_tda_core_conn_close_rsp(uint8_t *p_rsp, uint16_t p_len);
/**
 * @brief process TDA core connection  create response and updates the
 * connection ID
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_tda_core_conn_create_rsp(uint8_t *p_rsp, uint16_t p_len);
/**
 * @brief process the mode set respose and handle the errors
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_tda_mode_set_rsp(uint8_t *p_rsp);
/**
 * @brief process TDA discover response and updates the TDA info
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_tda_discover_ntf(uint8_t *p_ntf);
/**
 * @brief process CT data with reassembles and send to upper layer
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return void
 *
 */
void process_nfc_ct_data(uint8_t *p_ntf, uint16_t p_len);

/**
 * @brief process the nci packet related to CT
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS proc_tda_rsp_ntf(uint8_t *p_ntf, uint16_t p_len);

#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* NCI_RCV_H */
