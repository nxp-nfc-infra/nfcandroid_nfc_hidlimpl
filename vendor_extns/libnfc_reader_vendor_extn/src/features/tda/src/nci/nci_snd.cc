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
#include "nci_snd.h"
#include "pal.h"
#include "tda.h"
#include "tda_nci_defs.h"

extern tda_control_t g_tda_ctrl;

static int wait_for_data_rsp(sem_t *lck);
static NFC_STATUS write_ct_data_internal(sem_t *lck, uint8_t *p_data,
                                         uint16_t data_len);
uint8_t *p_nci_data = NULL;

/**
 *
 * @brief           This function is called to enable or disable NFCEE
 *                  Discovery.
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfcee_discover() {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  uint8_t *pp, *p;
  int len = NCI_PKT_HDR_SIZE;
  uint8_t cmd_buf[len];
  p = cmd_buf;
  pp = p;

  NCI_MSG_BLD_HDR0(pp, NCI_MSG_TYPE_CMD, NCI_GID_EE);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_NFCEE_DISCOVER);
  UINT8_TO_STREAM(pp, NCI_PARAM_SIZE_DISCOVER_NFCEE);

  g_tda_ctrl.ret_status = NFCSTATUS_SUCCESS;
  if (NFC_STATUS_SUCCESS !=
      write_ct_data_internal(&(g_tda_ctrl.discover_lck), p, len)) {
    g_tda_ctrl.ret_status = NFCSTATUS_FAILED;
  }
  return g_tda_ctrl.ret_status;
}

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
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfcee_mode_set_impl(uint8_t tda_id, uint8_t nfcee_mode) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  uint8_t *pp, *p;
  int len = NCI_PKT_HDR_SIZE + NCI_CORE_PARAM_SIZE_NFCEE_MODE_SET;
  uint8_t cmd_buf[len];
  p = cmd_buf;
  pp = p;

  NCI_MSG_BLD_HDR0(pp, NCI_MSG_TYPE_CMD, NCI_GID_EE);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_NFCEE_MODE_SET);
  UINT8_TO_STREAM(pp, NCI_CORE_PARAM_SIZE_NFCEE_MODE_SET);
  UINT8_TO_STREAM(pp, tda_id);
  UINT8_TO_STREAM(pp, nfcee_mode);

  g_tda_ctrl.ret_status = NFCSTATUS_SUCCESS;
  // Since mode set have timeout callback, no need to update the error based on
  // write return value
  if (NCI_NFCEE_MD_ACTIVATE == nfcee_mode) {
    OSAL_LOG_NFCHAL_D("%s Mode set enabled Lock \n", __func__);
    if (NFC_STATUS_SUCCESS !=
        write_ct_data_internal(&g_tda_ctrl.mode_set_en_lck, p, len)) {
      OSAL_LOG_NFCHAL_E("%s write_ct_data_internal : failed \n", __func__);
      g_tda_ctrl.ret_status = NFC_STATUS_TRANSCEIVE_FAILED;
    }
  } else if (NCI_NFCEE_MD_DEACTIVATE == nfcee_mode) {
    OSAL_LOG_NFCHAL_D("%s Mode set enabled Lock \n", __func__);
    if (NFC_STATUS_SUCCESS !=
        write_ct_data_internal(&g_tda_ctrl.mode_set_dis_lck, p, len)) {
      OSAL_LOG_NFCHAL_E("%s write_ct_data_internal : failed \n", __func__);
      g_tda_ctrl.ret_status = NFC_STATUS_TRANSCEIVE_FAILED;
    }
  } else {
    OSAL_LOG_NFCHAL_D("%s ERROR UNKNOWN MODESET MODE \n", __func__);
  }
  return g_tda_ctrl.ret_status;
}

/**
 *
 * @brief           Helper function to add the TLV and sends core connection
 *create command
 *
 * @param[in]       dest_type - destination type
 * @param[in]       num_tlv - Number of TLV
 * @param[in]       tlv_size - TLV size
 * @param[in]       p_param_tlvs - TLV data
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_core_conn_create_internal(uint8_t dest_type, uint8_t num_tlv,
                                          uint8_t tlv_size,
                                          uint8_t *p_param_tlvs) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  uint8_t *pp, *p;
  int len = NCI_PKT_HDR_SIZE + NCI_CORE_PARAM_SIZE_CON_CREATE + tlv_size;
  uint8_t cmd_buf[len];
  p = cmd_buf;
  pp = p;

  NCI_MSG_BLD_HDR0(pp, NCI_MSG_TYPE_CMD, NCI_CORE_GID);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_CON_CREATE);
  UINT8_TO_STREAM(pp, NCI_CORE_PARAM_SIZE_CON_CREATE + tlv_size);
  UINT8_TO_STREAM(pp, dest_type);
  UINT8_TO_STREAM(pp, num_tlv);
  if (tlv_size) {
    BYTE_ARRAY_TO_STREAM(pp, p_param_tlvs, tlv_size);
  }

  g_tda_ctrl.ret_status = NFC_STATUS_SUCCESS;
  if (NFC_STATUS_SUCCESS !=
      write_ct_data_internal(&g_tda_ctrl.open_ch_lck, p, len)) {
    g_tda_ctrl.ret_status = NFC_STATUS_WRITE_FAILED;
  }
  return g_tda_ctrl.ret_status;
}

/**
 *
 * @brief           compose and send CORE CONN_CREATE command to command queue
 *
 * @param[in]       conn_id - Connection ID
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_core_conn_create(uint8_t tda_id) {
  uint8_t param_tlvs[4], *pp;
  uint8_t num_tlv = 1;
  int tlv_size = 4;
  pp = param_tlvs;
  UINT8_TO_STREAM(pp, NCI_CON_CREATE_TAG_NFCEE_VAL);
  UINT8_TO_STREAM(pp, 2);
  UINT8_TO_STREAM(pp, tda_id);
  UINT8_TO_STREAM(pp, NCI_NFCEE_INTERFACE_APDU);
  g_tda_ctrl.curr_tda = tda_id;
  return send_core_conn_create_internal(NCI_DEST_TYPE_NFCEE, num_tlv, tlv_size,
                                        param_tlvs);
}

/**
 *
 * @brief           compose and send CORE CONN_CLOSE command to command queue
 *
 * @param[in]       channel_num - logical connection ID
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_core_conn_close(uint8_t channel_num) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  uint8_t *pp, *p;
  int len = NCI_PKT_HDR_SIZE + NCI_CORE_PARAM_SIZE_CON_CLOSE;
  uint8_t cmd_buf[len];
  p = cmd_buf;
  pp = p;

  NCI_MSG_BLD_HDR0(pp, NCI_MSG_TYPE_CMD, NCI_CORE_GID);
  NCI_MSG_BLD_HDR1(pp, NCI_MSG_CORE_CON_CLOSE);
  UINT8_TO_STREAM(pp, NCI_CORE_PARAM_SIZE_CON_CLOSE);
  UINT8_TO_STREAM(pp, channel_num);
  g_tda_ctrl.ret_status = NFC_STATUS_SUCCESS;
  if (NFC_STATUS_SUCCESS !=
      write_ct_data_internal(&g_tda_ctrl.close_ch_lck, p, len)) {
    g_tda_ctrl.ret_status = NFC_STATUS_WRITE_FAILED;
  }
  return g_tda_ctrl.ret_status;
}

void mode_set_ntf_timeout(int sig) {
  OSAL_LOG_NFCHAL_D("%s, g_tda_ctrl.mode_set_ctrl.tda_id:%d, "
                      "g_tda_ctrl.mode_set_ctrl.mode:%d \n",
                      __func__, g_tda_ctrl.mode_set_ctrl.tda_id,
                      g_tda_ctrl.mode_set_ctrl.mode);
  alarm(0);
  g_tda_ctrl.ret_status = NFC_STATUS_NFCEE_MODE_SET_ENABLE_TIMEOUT;
  g_tda_ctrl.mode_set_ctrl.tda_id = INVALID_NUM;
  g_tda_ctrl.mode_set_ctrl.mode = INVALID_NUM;
}

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
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfcee_mode_set(uint8_t tda_id, uint8_t mode) {
  signal(SIGALRM, mode_set_ntf_timeout);
  alarm(MAX_MS_NTF_TIMEOUT_IN_SEC);
  g_tda_ctrl.mode_set_ctrl.tda_id = tda_id;
  g_tda_ctrl.mode_set_ctrl.mode = mode;
  OSAL_LOG_NFCHAL_D("%s send nfcee_mode_set enable for TDA:%d\n", __func__,
                    tda_id);
  return send_nfcee_mode_set_impl(tda_id, mode);
}

/**
 * @brief Forms the NCI packet by including NCI header and retruns the data
 *
 * @param[in] pbf_n_conn_id packet boundary and connection ID
 * @param[in] p_data data buffer
 * @param[in] data_len data length
 * @return NCI packet buffer
 *
 */
static uint8_t *get_nci_ct_loopback_data(uint8_t pbf_n_conn_id, uint8_t *p_data,
                                         int data_len) {
  p_nci_data = (uint8_t *) ct_osal_malloc((data_len + NCI_PKT_HDR_SIZE) * sizeof(uint8_t));
  OSAL_LOG_NFCHAL_D("%s get_nci_ct_loopback_data pbf_n_conn_id:%02x\n",
                      __func__, pbf_n_conn_id);
  *(p_nci_data + 0) = pbf_n_conn_id;
  *(p_nci_data + 1) = 0x00;
  *(p_nci_data + 2) = data_len;
  ct_osal_memcpy((p_nci_data + NCI_PKT_HDR_SIZE), p_data, data_len);
  return p_nci_data;
}

/**
 *
 * @brief           Internal function to send raw APDU to controller
 *
 * @param[in]       p_data - data buffer pointer
 * @param[in]       data_len - data buffer length
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
static NFC_STATUS write_ct_data_internal(sem_t *lck, uint8_t *p_data,
                                         uint16_t data_len) {
  pthread_mutex_lock(&g_tda_ctrl.snd_lck);
  if (ct_osal_write(p_data, data_len, true) != NFCSTATUS_SUCCESS) {
    g_tda_ctrl.ret_status = NFC_STATUS_TRANSCEIVE_FAILED;
    return NFC_STATUS_TRANSCEIVE_FAILED;
  }

  NFC_STATUS status = wait_for_data_rsp(lck);
  if (status != NFC_STATUS_SUCCESS) {
    int sem_val;
    ct_osal_sem_getvalue(lck, &sem_val);
    g_tda_ctrl.ret_status = status;
  }
  return status;
}

/**
 *
 * @brief           Internal function to form the NCI data packet and call the
 *internal write API
 *
 * @param[in]       pbf - packet boundary flag
 * @param[in]       p_data - data buffer pointer
 * @param[in]       data_len - data buffer length
 *
 * @return          void
 *
 **/
static void send_nfc_ct_data_impl(int pbf, uint8_t *p_data, int data_len) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  p_nci_data = get_nci_ct_loopback_data(pbf, p_data, data_len);
  if (NFC_STATUS_SUCCESS !=
      write_ct_data_internal(&g_tda_ctrl.transceive_lck, p_nci_data,
                             data_len + NCI_PKT_HDR_SIZE)) {
    OSAL_LOG_NFCHAL_D("%s write_ct_data_internal:failed \n", __func__);
  }
  if (p_nci_data != NULL) {
    free(p_nci_data);
    p_nci_data = NULL;
  }
}

/**
 *
 * @brief           handles the segmentation and sends to controller
 *
 * @param[in]       p_data - data buffer pointer
 * @param[in]       data_len - data buffer length
 *
 * @return          NFC status:
 *                  NFCSTATUS_SUCCESS - command processed successfully
 *                  NFCSTATUS_FAILED - failed to process the command
 *
 **/
NFC_STATUS send_nfc_ct_data(uint8_t *p_data, uint16_t data_len) {
  uint8_t rcvd_conn_id = NCI_CT_DATA_CONN_ID_MASK & (*p_data);
  int act_conn_id = get_tda_channel_num();
  OSAL_LOG_NFCHAL_D("%s sending segment packet *p_data:%02x, "
                      "rcvd_conn_id:%02x, act_conn_id:%02x\n",
                      __func__, *p_data, rcvd_conn_id, act_conn_id);
  if (rcvd_conn_id != act_conn_id) {
    return NFC_STATUS_TRANSCEIVE_FAILED;
  }

  g_tda_ctrl.ret_status = NFC_STATUS_SUCCESS;
  if (data_len > MAX_FRAGMENT_SIZE) {
    uint8_t pbf_n_conn_id = PBF_SEGMENT_MSG | (*p_data);
    p_data += NCI_PKT_HDR_SIZE;
    data_len -= NCI_PKT_HDR_SIZE;
    while (data_len > (MAX_FRAGMENT_SIZE - NCI_PKT_HDR_SIZE)) {
      CT_SET_CHAINED_CMD_DATA();
      OSAL_LOG_NFCHAL_D(
          "%s sending segment packet data_len:%02x, pbf_n_conn_id:%02x\n",
          __func__, data_len, pbf_n_conn_id);
      send_nfc_ct_data_impl(pbf_n_conn_id, p_data,
                            (MAX_FRAGMENT_SIZE - NCI_PKT_HDR_SIZE));
      data_len -= (MAX_FRAGMENT_SIZE - NCI_PKT_HDR_SIZE);
      p_data += (MAX_FRAGMENT_SIZE - NCI_PKT_HDR_SIZE);
    }
    if (data_len > 0) {
      pbf_n_conn_id = (PBF_COMPLETE_MSG | act_conn_id);
      OSAL_LOG_NFCHAL_D("%s pbf_n_conn_id:%d, data_len:%d\n", __func__,
                          pbf_n_conn_id, data_len);
      send_nfc_ct_data_impl(pbf_n_conn_id, p_data, data_len);
    }
  } else {
    if (write_ct_data_internal(&g_tda_ctrl.transceive_lck, p_data, data_len) !=
        NFC_STATUS_SUCCESS) {
      OSAL_LOG_NFCHAL_E("%s write_ct_data_internal failed ", __func__);
    }
  }
  return g_tda_ctrl.ret_status;
}

/******************************************************************************
 * Function         wait_for_data_rsp
 *
 * Description      This function is called to wait for the
 *                  response/notication/data for the request
 *                  sent to controller
 *
 * Returns          return 0 on success and -1 on fail.
 *
 ******************************************************************************/

int wait_for_data_rsp(sem_t *lck) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  NFCSTATUS status = NFC_STATUS_FAIL;
  int s;
  struct timespec ts;

  clock_gettime(CLOCK_MONOTONIC, &ts);
  ts.tv_sec += max_wtx_time_out;
  int sem_val;
  ct_osal_sem_getvalue(lck, &sem_val);
  OSAL_LOG_NFCHAL_D("%s sem_val:%d, max_wtx_time_out:%d \n", __func__,
                      sem_val, max_wtx_time_out);
  pthread_mutex_unlock(&g_tda_ctrl.snd_lck);
  while ((s = ct_osal_sem_timedwait_monotonic_np(lck, &ts)) == -1 &&
         errno == EINTR) {
    OSAL_LOG_NFCHAL_D("%s continue\n", __func__);
    continue; /* Restart if interrupted by handler */
  }
  OSAL_LOG_NFCHAL_D("%s time:%d\n", __func__, s);
  if (s != -1) {
    status = NFC_STATUS_SUCCESS;
  } else {
    if (errno == ETIMEDOUT) {
      status = NFC_STATUS_TRANSCEIVE_FAILED;
    }
  }

  return status;
}

/**
 *
 * @brief           sets the WTX time out value, only if it
 *                  is positive value
 *
 * @param[in]       ime_out_val WTX time out value in secs
 *
 * @return void
 *
 */
void set_max_wtx_timeout_val(uint8_t time_out_val) {
  if (time_out_val > 0) {
    max_wtx_time_out = time_out_val;
    OSAL_LOG_NFCHAL_E("%s max_wtx_time_out:%d\n", __func__, max_wtx_time_out);
  } else {
    OSAL_LOG_NFCHAL_E("%s Failed to update the MAX WTX timeout value as it "
                        "is negative. time_out_val:%d\n",
                        __func__, time_out_val);
  }
}
