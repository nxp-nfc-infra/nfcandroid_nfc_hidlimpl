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

#ifndef TDA_H
#define TDA_H
/** \addtogroup TDA_API_INTERFACE
 *  @brief  interface to perform the TDA structure update.
 *  @{
 */
#include "pal.h"

#ifdef __cplusplus
extern "C" {
#endif
#define INVALID_NUM -1
/**
 *
 * @brief           returns the channel number of the currently opened TDA
 *
 *
 * @return          returns valid channel number, if found or returns
 *(-1)INVALID_NUM
 *
 **/
uint8_t get_tda_channel_num();

/**
 *
 * @brief           releases the lock to send next data to controller.
 *
 *
 * @return          returns void
 *
 **/
void release_ct_lock(sem_t *lck);

/**
 *
 * @brief           removes the TDA information based on TDA received NCI NTF.
 * @param[in]       p_ntf data buffer received from NFCC
 * @param[in]       p_tda tda structure pointer to be removed/updated
 *
 * @return          returns void
 *
 **/
void remove_tda_info(uint8_t *p_ntf, tda_t *p_tda);

/**
 *
 * @brief           adds the TDA information for given TDA.
 * @param[in]       p_ntf data buffer received from NFCC
 * @param[in]       p_tda tda structure pointer to be added/updated
 *
 * @return          returns void
 *
 **/
void add_tda_info(uint8_t *p_ntf, tda_t *p_tda);

/**
 *
 * @brief           removes the TDA information for given TDA.
 * @param[in]       tda_id id of the TDA
 *
 * @return          returns void
 *
 **/
void remove_tda_info_of_tda(uint8_t tda_id);
#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* TDA_H */
