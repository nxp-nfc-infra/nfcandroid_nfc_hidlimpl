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
#include "tda_api.h"
#include "fsm.h"
#include "nci_rcv.h"
#include "nci_snd.h"
#include "pal.h"
#include "tda.h"
#include "tda_nci_defs.h"

tda_control_t g_tda_ctrl;

/**
 * @brief initialize CT and sends discovers the TDA connected
 *
 * @return NFC_STATUS indicates success or failure
 *
 */
NFC_STATUS ct_init_ext(void) {
  OSAL_LOG_NFCHAL_D("%s", __func__);
  NFC_STATUS status = NFC_STATUS_SUCCESS;
  if (0 != sem_init(&g_tda_ctrl.discover_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for discover_lck, errno = 0x%02X",
                      errno);
  }

  if (0 != sem_init(&g_tda_ctrl.mode_set_en_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for mode_set_en_lck, errno = 0x%02X",
                      errno);
  }

  if (0 != sem_init(&g_tda_ctrl.open_ch_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for open_ch_lck, errno = 0x%02X",
                      errno);
  }
  if (0 != sem_init(&g_tda_ctrl.transceive_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for transceive_lck, errno = 0x%02X",
                      errno);
  }
  if (0 != sem_init(&g_tda_ctrl.mode_set_dis_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for mode_set_dis_lck, errno = 0x%02X",
                      errno);
  }

  if (0 != sem_init(&g_tda_ctrl.close_ch_lck, 0, 0)) {
    OSAL_LOG_NFCHAL_E("sem_init() Failed for close_ch_lck, errno = 0x%02X",
                      errno);
  }

  if (pthread_mutex_init(&g_tda_ctrl.snd_lck, NULL) != 0) {
    OSAL_LOG_NFCHAL_E("sem_init failed for snd_lck, errono = 0x%08x",
                      errno);
  }
  if (pthread_mutex_init(&g_tda_ctrl.api_lck, NULL) != 0) {
    OSAL_LOG_NFCHAL_E("sem_init failed for api_lck, errono = 0x%08x", errno);
  }
  if (pthread_mutex_init(&g_tda_ctrl.rcv_lck, NULL) != 0) {
    OSAL_LOG_NFCHAL_E("sem_init failed for rcv_lck, errono = 0x%08x", errno);
  }

  fp_event_handler_t fp_event_handler = handle_event(NFCEE_DISCOVER_EVENT);
  status = fp_event_handler(NULL);
  OSAL_LOG_NFCHAL_D("%s Returing %d", __func__, status);
  return status;
}

/**
 * @brief De-initializes CT
 *
 * @return NFC_STATUS indicates success or failure
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_de_init_ext(void) {
  OSAL_LOG_NFCHAL_D("%s", __func__);
  g_tda_ctrl.num_tda_supported = 0;
  g_tda_ctrl.curr_tda = 0;
  update_state(INIT_STATE);
  sem_destroy(&g_tda_ctrl.discover_lck);
  sem_destroy(&g_tda_ctrl.mode_set_en_lck);
  sem_destroy(&g_tda_ctrl.open_ch_lck);
  sem_destroy(&g_tda_ctrl.transceive_lck);
  sem_destroy(&g_tda_ctrl.mode_set_dis_lck);
  sem_destroy(&g_tda_ctrl.close_ch_lck);
  pthread_mutex_destroy(&g_tda_ctrl.snd_lck);
  pthread_mutex_destroy(&g_tda_ctrl.api_lck);
  pthread_mutex_destroy(&g_tda_ctrl.rcv_lck);
  return NFC_STATUS_SUCCESS;
}

/**
 * @brief discovers the smart card connected to TDA and returns the smart card
 * control.
 *
 * @param[in] void
 * @param[out] tda_control provides the deatils of the smartcards present over
 * TDA
 *
 * @return NFC_STATUS indicates success or failure
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_discover_tda(tda_control_t *tda_control) {
  pthread_mutex_lock(&g_tda_ctrl.api_lck);
  OSAL_LOG_NFCHAL_D("%s with api_lck", __func__);
  NFC_STATUS status = NFC_STATUS_SUCCESS;
  fp_event_handler_t fp_event_handler = handle_event(DISCOVER_TDA_EVENT);
  status = fp_event_handler(tda_control);
  pthread_mutex_unlock(&g_tda_ctrl.api_lck);
  return status;
}

/**
 * @brief provides current tda state.
 * @return system_state_t indicates the current state of tda
 *
 */
system_state_t ct_get_tda_state() {
  OSAL_LOG_NFCHAL_D("%s current_state:%d", __func__,
                      g_tda_ctrl.tda_state);
  return  g_tda_ctrl.tda_state;
}

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
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_open(int8_t tda_id, bool in_standBy, int8_t *channel_num) {
  pthread_mutex_lock(&g_tda_ctrl.api_lck);
  OSAL_LOG_NFCHAL_D("%s with api_lck tda_id:%02x, in_standBy:%d", __func__,
                    tda_id, in_standBy);
  g_tda_ctrl.tda_ch_pr.tda_id = tda_id;
  g_tda_ctrl.tda_ch_pr.channel_num = INVALID_NUM;
  NFC_STATUS status = NFC_STATUS_SUCCESS;
  fp_event_handler_t fp_event_handler;
  if (!in_standBy) {
    fp_event_handler = handle_event(OPEN_TDA_EVENT);
  } else {
    fp_event_handler = handle_event(CORE_CONN_CREATE_EVENT);
  }
  status = fp_event_handler(&g_tda_ctrl.tda_ch_pr);
  *channel_num = g_tda_ctrl.tda_ch_pr.channel_num;
  OSAL_LOG_NFCHAL_D("%s g_tda_ctrl.tda_ch_pr.channel_num: 0x%X,*channel_num: 0x%X", __func__,
                    g_tda_ctrl.tda_ch_pr.channel_num, *channel_num);
  pthread_mutex_unlock(&g_tda_ctrl.api_lck);
  return status;
}

/**
 *
 * @brief           This function write the data to NFCC through physical
 *                  interface (e.g. I2C) using the PN7220 driver interface.
 *
 * @param[in]       cmd_apdu: Command to TDA
 * @param[out]      rsp_apdu: Command to TDA
 *
 * @return NFC_STATUS indicates success or failure
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_transceive(tda_data *cmd_apdu, tda_data *rsp_apdu) {
  OSAL_LOG_NFCHAL_D("%s", __func__);
  g_tda_ctrl.trans_buf.cmd_apdu = cmd_apdu;
  g_tda_ctrl.trans_buf.rsp_apdu = rsp_apdu;
  NFC_STATUS status = NFC_STATUS_SUCCESS;
  fp_event_handler_t fp_event_handler = handle_event(TRANSCEIVE_EVENT);
  status = fp_event_handler(&g_tda_ctrl.trans_buf);
  return status;
}

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
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS ct_close(int8_t tda_id, bool in_standBy) {
  pthread_mutex_lock(&g_tda_ctrl.api_lck);
  OSAL_LOG_NFCHAL_D("%s with api_lck tda_id:%02x", __func__, tda_id);
  NFC_STATUS status = NFC_STATUS_SUCCESS;
  fp_event_handler_t fp_event_handler;
  if (in_standBy) {
    fp_event_handler = handle_event(CLOSE_TDA_EVENT);
  } else {
    fp_event_handler = handle_event(CORE_CONN_CLOSE_EVENT);
  }
  status = fp_event_handler(&tda_id);
  pthread_mutex_unlock(&g_tda_ctrl.api_lck);
  return status;
}

/**
 * @brief process the nci packet and checks for core interface error
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is CT packet otherwise returns false
 *
 */
bool is_core_inf_err_ntf(uint8_t *p_ntf, uint16_t p_len) {
  OSAL_LOG_NFCHAL_D("%s p_len:%d", __func__, p_len);
  int channel_num = get_tda_channel_num();
  OSAL_LOG_NFCHAL_D("%s channel_num:%02x,p_ntf:%02x \n", __func__, channel_num,
                    *p_ntf);
  if ((5 == p_len) &&
      (p_ntf[0] == NCI_MT_NTF_VAL &&
       p_ntf[1] == NCI_CORE_INTERFACE_ERROR_NTF_VAL &&
       p_ntf[2] == NCI_CORE_INTERFACE_ERROR_NTF_LEN_VAL &&
       p_ntf[3] == NFCEE_TRANSMISSION_ERROR && p_ntf[4] == channel_num)) {
    return true;
  } else {
    return false;
  }
}

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
bool is_ct_data_credit_received(uint8_t *p_ntf, uint16_t p_len) {
  if (is_core_inf_err_ntf(p_ntf, p_len)) {
    release_ct_lock(&g_tda_ctrl.transceive_lck);
  }
  OSAL_LOG_NFCHAL_D("%s p_len:%d", __func__, p_len);

  int channel_num = get_tda_channel_num();
  OSAL_LOG_NFCHAL_D("%s channel_num:%02x,p_ntf:%02x \n", __func__, channel_num,
                    *p_ntf);
  if ((6 == p_len) &&
      (p_ntf[0] == NCI_MT_NTF_VAL &&
       p_ntf[1] == NCI_CORE_CONN_CREDITS_NTF_VAL &&
       p_ntf[2] == NCI_CORE_CONN_CREDITS_NTF_LEN_VAL &&
       p_ntf[3] == NCI_CORE_CONN_CREDITS_NTF_NO_OF_ENTRY_VAL &&
       p_ntf[4] == channel_num &&
       p_ntf[5] == NCI_CORE_CONN_CREDITS_NTF_CONN_CREDITS_VAL)) {
    return true;
  } else {
    return false;
  }
}

/**
 * @brief process the nci data/rsp/ntf packet related to CT
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return NFC_STATUS indicates success or failure
 * Refer nfc_status.h file for more specific error code
 * incase of failure.
 *
 */
NFC_STATUS process_tda_rsp_ntf(uint8_t *p_ntf, uint16_t p_len) {
  pthread_mutex_lock(&g_tda_ctrl.rcv_lck);
  OSAL_LOG_NFCHAL_D("%s with  rcv_lck p_len:%d", __func__, p_len);
  NFC_STATUS status = proc_tda_rsp_ntf(p_ntf, p_len);
  pthread_mutex_unlock(&g_tda_ctrl.rcv_lck);
  return status;
}

/**
 * @brief process the nci packet and checks the response is related to the NCI
 * command initiated by CT library
 *
 * @param[in] p_ntf data buffer
 * @param[in] p_len data length
 *
 * @return true, if it is related to CT command otherwise returns false
 *
 */
bool is_ct_data_rsp(uint8_t *p_ntf, uint16_t p_len) {
  OSAL_LOG_NFCHAL_D("%s p_len:%d", __func__, p_len);
  int conn_id = get_tda_channel_num();
  LOG_NFCHAL_D("%s conn_id:%d, conn_id_mask:%02d", __func__, conn_id,
               *p_ntf & NCI_CONN_ID_MASK_VAL);
  if (conn_id != INVALID_NUM && ((*p_ntf & NCI_CONN_ID_MASK_VAL) == conn_id)) {
    return true;
  }

  int oid = (*(p_ntf + 1) & NCI_OID_MASK_VAL);
  int gid = (*(p_ntf + 1) & NCI_GID_MASK_VAL);
  LOG_NFCHAL_D("%s oid:%d, gid:%d", __func__, oid, gid);

  if ((((*p_ntf) & (NCI_MSG_TYPE_RSP_VAL << NCI_MT_SHIFT_VAL)) ||
       ((*p_ntf) & (NCI_MSG_TYPE_NTF_VAL << NCI_MT_SHIFT_VAL))) &&
      ((gid == NCI_GID_EE) &&
       ((oid == NCI_MSG_CORE_CONN_CREATE_VAL ||
         oid == NCI_MSG_CORE_CONN_CLOSE_VAL || oid == NCI_MSG_MODE_SET_VAL)))) {
    LOG_NFCHAL_E("CT NCI response");
    return true;
  }
  return false;
}

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
bool is_ct_send_app_data(const uint8_t *p_ntf, uint16_t p_len, bool is_tda) {
  OSAL_LOG_NFCHAL_D("%s p_len:%d, is_tda:%d", __func__, p_len, is_tda);
  int msg_type = p_ntf[0] & (NCI_MSG_TYPE_RSP_VAL << NCI_MT_SHIFT_VAL);
  int oid = p_ntf[1] & NCI_OID_MASK_VAL;
  int gid = p_ntf[1] & NCI_GID_MASK_VAL;
  int conn_id = get_tda_channel_num();
  LOG_NFCHAL_D("%s msg_type:%02x, id:%d, conn_id:%d, gid:%d", __func__,
               msg_type, oid, conn_id, gid);
  if ((msg_type == NCI_MSG_COMMAND_TYPE_VAL) &&
      (!(is_tda && ((gid == NCI_GID_EE) &&
                    (oid == NCI_MSG_CORE_CONN_CREATE_VAL ||
                     oid == NCI_MSG_CORE_CONN_CLOSE_VAL || oid == conn_id))))) {
    LOG_NFCHAL_E("NOT CT Command");
    return false;
  }
  return true;
}

/**
 *
 * @brief           sets the WTX time out value
 *
 * @param[in]       ime_out_val WTX time out value in secs
 *
 * @return void
 *
 */
void set_max_wtx_timeout_value(uint8_t time_out_val) {
  set_max_wtx_timeout_val(time_out_val);
}
