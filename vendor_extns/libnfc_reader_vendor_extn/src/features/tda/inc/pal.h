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

#ifndef PAL_H_
#define PAL_H_
/** \addtogroup PAL_API
 *  @brief  interface to perform the project/profile(NFC) specific
 * operations
 *  @{
 */
#include <tda_utils.h>
#include <phNxpLog.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <nci_parser.h>
#include <nfc_status.h>
#include <nfc_common.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OSAL_LOG_NFCHAL_D(...) { NXPLOG_EXTNS_D(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__); };
#define OSAL_LOG_NFCHAL_W(...) { NXPLOG_EXTNS_W(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__); };
#define OSAL_LOG_NFCHAL_E(...) { NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__); };

#define LOG_NFCHAL_D(...) NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__)
#define LOG_NFCHAL_W(...) { NXPLOG_EXTNS_W(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__);};
#define LOG_NFCHAL_E(...) { NXPLOG_EXTNS_E(NXPLOG_ITEM_NXP_GEN_EXTN, __VA_ARGS__); };
/**
 *
 * @brief           This function write the data to NFCC through physical
 *                  interface (e.g. I2C) using the PN7220 driver interface.
 *
 * @param[in]       data_len length of the data to be written
 * @param[in]       p_data actual data to be written
 * @param[in]       is_tda specifies data received from CT or CL
 *
 * @return          uint16_t - returns the number of bytes written to controller
 *
 */
uint16_t ct_osal_write(uint8_t *p_data, uint16_t data_len, bool is_tda);

/**
 *
 * @brief initialize an unnamed semaphore
 *
 * @param[in] sem_t                          Semaphore.
 *
 * @return #0                on success
 * @return #EINVAL           value exceeds SEM_VALUE_MAX
 * @return #ENOSYS           pshared is nonzero, but the system does not support
 *                           process-shared semaphores
 *
 */
int ct_osal_sem_init(sem_t *sem, int pshared, unsigned int value);

/**
 *
 * @brief  Allocates some memoryAllocates some memory
 *
 * @param[in] dwSize   Size, in uint32_t, to be allocated
 *
 * @return            NON-NULL value:  The memory is successfully allocated ;
 *                    the return value is a pointer to the allocated memory
 * location NULL:The operation is not successful.
 *
 */
void *ct_osal_malloc(int dwSize);

/**
 * @brief                Copies the values stored in the source memory to the
 *                       values stored in the destination memory.
 *
 * @param[in] pDest     Pointer to the Destination Memory
 * @param[in] pSrc      Pointer to the Source Memory
 * @param[in] dwSize    Number of bytes to be copied.
 *
 * @return    void
 */
void ct_osal_memcpy(void *pDest, const void *pSrc, int size);

/**
 *
 * @brief get the value of a semaphore
 *
 * @param[in] sem_t          Semaphore.
 *
 * @return #0                on success
 * @return #EINVAL           sem is not a valid semaphore
 *
 */
int ct_osal_sem_getvalue(sem_t *sem, int *sval);

/**
 *
 * @brief unlock a semaphore
 *
 * @param[in] sem_t                          Semaphore.
 *
 * @return #0                on success
 * @return #EINVAL           sem is not a valid semaphore..
 * @return #EOVERFLOW        The maximum allowable value for a semaphore would
 *                           be exceeded
 */
int ct_osal_sem_post(sem_t *sem);

/**
 *
 * @brief lock a semaphore with monotonic timeout
 *
 * @param[in] sem_t                          Semaphore.
 *
 * @return #0             on success
 * @return #EAGAIN        The operation could not be performed
 *                        without blocking
 *
 * @return #EINTR         The call was interrupted by
 *                        a signal handler.
 * @return #EINVAL        sem is not a valid semaphore..
 * @return #EINVAL        The value of abs_timeout.tv_nsecs is
 *                        less than 0, or greater than or
 *                        equal to 1000 million
 * @return #ETIMEDOUT     The call timed out before the semaphore
 *                        could be locked.
 */
int ct_osal_sem_timedwait_monotonic_np(sem_t *__sem,
                                       const struct timespec *__ts)
    __INTRODUCED_IN(28);

#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* PAL_H_ */
