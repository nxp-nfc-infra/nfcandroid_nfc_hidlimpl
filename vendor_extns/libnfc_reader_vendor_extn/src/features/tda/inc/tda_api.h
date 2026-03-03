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

#ifndef TDA_API_H_
#define TDA_API_H_
/** \addtogroup NFC_TDA_API_INTERFACE
 *  @brief  interface to perform the CT functionality.
 *  @{
 */
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief initialize CT and sends discovers the TDA connected
 *
 *
 * @return NFC_STATUS indicates success or failure
 *
 */
NFC_STATUS ct_init_ext(void);

/**
 * @brief De-initializes CT
 *
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_de_init_ext();
/**
 * @brief sends nfcee discover command to controller.
 *
 * @param[in] void
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_nfcee_discover();
/**
 * @brief discovers the smart card connected to TDA and returns the smart card
 * control.
 *
 * @param[in] void
 * @param[out] tda_control provides the deatils of the smartcards present over
 * TDA
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_discover_tda(tda_control_t *tda_control);
/**
 * @brief provides current tda state.
 * @return system_state_t indicates the current state of tda
 *
 */
system_state_t ct_get_tda_state();
/**
 * @brief opens the contactcard.
 *
 * @param[in] tda_id id of the contact card to be opened
 * @param[in]  standBy false, opens the communication with TDA freshely and mode
 * set enable command is sent to controller. standBy true, resumes the
 * communication from partial close and does not send mode set enable command to
 * controller
 *
 * @note       use standby false, if you are opening the TDA for first time.
 *             use standby true, if you are opening the TDA followed by partial
 * close of another TDA
 * @param[out] channel_num returns the conn_id id of the contact card
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_open(int8_t tda_id, bool in_standBy, int8_t *channel_num);
/**
 *
 * @brief           This function write the data to NFCC through physical
 *                  interface (e.g. I2C) using the PN7220 driver interface.
 *
 * @param[in]       cmd_apdu: Command to TDA
 * @param[out]      rsp_apdu: Command to TDA
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_transceive(tda_data *cmd_apdu, tda_data *rsp_apdu);
/**
 * @brief closes the contactcard.
 *
 * @param[in] tda_id id of the contact card to be closed
 * @param[in]  standBy true, closes the communication with TDA fully and allows
 * the system to go in standbymode standBy false, closes the communication
 * partially and does not allow the system to go in standbymode.
 *
 * @note       use standby false, If you are closing the current TDA to open
 * another TDA for communication then use false to get better performance use
 * standby true, If you are closing the current TDA to stop the communication
 * with it fully and allow system to enter standby mode
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_close(int8_t tda_id, bool in_standBy);

/**
 * @brief process the nci data/rsp/ntf packet related to CT
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return NFC_STATUS indicates success or failure
 * Refer NFC_STATUS.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS process_tda_rsp_ntf(uint8_t *p_ntf, uint16_t p_len);

/**
 * @brief process the nci packet and checks whether it is credit ntf received
 * for CT data packet
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is CT packet otherwise returns false
 *
 */
bool is_ct_data_credit_received(uint8_t *p_ntf, uint16_t p_len);

/**
 * @brief process the nci packet and checks whether NCI command initiated by CT
 * library
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is related to CT command otherwise returns false
 *
 */
bool is_ct_send_app_data(const uint8_t *p_ntf, uint16_t p_len, bool is_tda);

/**
 * @brief process the nci packet and checks whether NCI response is related to
 * NCI command initiated by CT library
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is related to CT command otherwise returns false
 *
 */
bool is_ct_data_rsp(uint8_t *p_ntf, uint16_t p_len);

/**
 * @brief process the nci packet and checks for core interface error
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is CT packet otherwise returns false
 *
 */
bool is_core_inf_err_ntf(uint8_t *p_ntf, uint16_t p_len);

/**
 *
 * @brief           sets the WTX time out value
 *
 * @param[in]       ime_out_val WTX time out value in secs
 *
 * @return void
 *
 */
void set_max_wtx_timeout_value(uint8_t time_out_val);

#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* TDA_API_H_ */
