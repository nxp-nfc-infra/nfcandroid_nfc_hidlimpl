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

#include "IEventHandler.h"
#include <iostream>
#include <stdint.h>
#include <string>
#include <tda_utils.h>
#include <vector>

class Tda {

public:
  /**
   * @brief Get the singleton instance of Tda.
   * @return Tda* Pointer to the instance.
   */
  static Tda *getInstance();
  void Initialize();
  Tda(const Tda &) = delete;            /* Deleted copy constructor */
  Tda &operator=(const Tda &) = delete; /* Deleted assignment operator */

  NFCSTATUS discover(tda_control_t *tda_data);
  NFCSTATUS open(uint8_t tdaId, uint8_t standBy, uint8_t &cid);
  NFCSTATUS transceive(std::vector<uint8_t> command,
                       std::vector<uint8_t> &response);
  NFCSTATUS close(uint8_t tdaId, uint8_t standBy);
  system_state_t getTdaState();
  NFCSTATUS processResponseNtf(uint16_t dataLen, uint8_t *pData);
  /**
   * @brief Releases all the resources
   * @return None
   *
   */
  static inline void finalize() {
    if (instance != nullptr) {
      instance.reset();
    }
  }

private:
  static std::unique_ptr<Tda> instance;
  Tda();
  ~Tda();
  friend struct std::default_delete<Tda>;
};
