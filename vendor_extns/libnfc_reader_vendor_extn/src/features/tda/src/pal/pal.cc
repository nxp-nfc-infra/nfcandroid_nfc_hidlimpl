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

#include "pal.h"
#include <stdlib.h>
#include <string.h>
#include <semaphore.h>
#include <NfcExtensionWriter.h>

/**
 *
 * @brief           Writes the data to controller
 *
 * @param[in]       p_data - data buffer pointer
 * @param[in]       data_len - data buffer length
 *
 * @return          uint16_t - returns the number of bytes written to controller
 *
 **/
NFCSTATUS ct_osal_write(uint8_t *p_data, uint16_t data_len, bool is_tda) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  (void)is_tda;
  return NfcExtensionWriter::getInstance()->write(p_data, data_len);
}

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
void *ct_osal_malloc(int size) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  return malloc(size);
}

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
void ct_osal_memcpy(void *pDest, const void *pSrc, int size) {
  OSAL_LOG_NFCHAL_D("%s \n", __func__);
  memcpy(pDest, pSrc, size);
}

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
int ct_osal_sem_getvalue(sem_t *sem, int *sval) {
  OSAL_LOG_NFCHAL_D("%s\n", __func__);
  return sem_getvalue(sem, sval);
}

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
int ct_osal_sem_post(sem_t *sem) {
  OSAL_LOG_NFCHAL_D("%s\n", __func__);
  return sem_post(sem);
}

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
                                       const struct timespec *__ts) {
  OSAL_LOG_NFCHAL_D("%s\n", __func__);
  return sem_timedwait_monotonic_np(__sem, __ts);
}
