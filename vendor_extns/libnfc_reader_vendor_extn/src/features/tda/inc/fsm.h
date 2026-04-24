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
#ifndef CT_TDA_FSM_H_
#define CT_TDA_FSM_H_

#include "pal.h"
/** \addtogroup TDA_FSM_API_INTERFACE
 *  @brief  has states, events and functions needed to handle FSM
 *  @{
 */

/**
 * @brief  updates the state of TDA
 *
 **/
void update_state(system_state_t state);

/**
 * @brief  handles the incoming event based on the current state
 *         and calls the respective event handler to process the
 *         event
 *
 **/
fp_event_handler_t handle_event(system_event_t sys_evt);

NFC_STATUS init_nfcee_discover(void *);
NFC_STATUS init_discover_tda(void *);
NFC_STATUS init_open_tda(void *);
NFC_STATUS init_core_conn_create(void *);
NFC_STATUS init_transceive(void *);
NFC_STATUS init_close_tda(void *);
NFC_STATUS init_core_conn_close(void *);
NFC_STATUS discovered_nfcee_discover(void *);
NFC_STATUS discovered_discover_tda(void *);
NFC_STATUS discovered_open_tda(void *);
NFC_STATUS discovered_core_conn_create(void *);
NFC_STATUS discovered_transceive(void *);
NFC_STATUS discovered_close_tda(void *);
NFC_STATUS discovered_core_conn_close(void *);
NFC_STATUS mode_set_enabled_nfcee_discover(void *);
NFC_STATUS mode_set_enabled_discover_tda(void *);
NFC_STATUS mode_set_enabled_open_tda(void *);
NFC_STATUS mode_set_enabled_core_conn_create(void *);
NFC_STATUS mode_set_enabled_transceive(void *);
NFC_STATUS mode_set_enabled_close_tda(void *);
NFC_STATUS mode_set_enabled_core_conn_close(void *);
NFC_STATUS core_conn_created_nfcee_discover(void *);
NFC_STATUS core_conn_created_discover_tda(void *);
NFC_STATUS core_conn_created_open_tda(void *);
NFC_STATUS core_conn_created_core_conn_create(void *);
NFC_STATUS core_conn_created_transceive(void *);
NFC_STATUS core_conn_created_close_tda(void *);
NFC_STATUS core_conn_created_core_conn_close(void *);
NFC_STATUS core_conn_closed_nfcee_discover(void *);
NFC_STATUS core_conn_closed_discover_tda(void *);
NFC_STATUS core_conn_closed_open_tda(void *);
NFC_STATUS core_conn_closed_core_conn_create(void *);
NFC_STATUS core_conn_closed_transceive(void *);
NFC_STATUS core_conn_closed_close_tda(void *);
NFC_STATUS core_conn_closed_core_conn_close(void *);
/** @}*/
#endif /* CT_TDA_FSM_H_ */
