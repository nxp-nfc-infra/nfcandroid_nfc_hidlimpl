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

#include <iostream>
#include <stdint.h>
#include <string>
#include <vector>

class NxpSoftPos {

public:
  /**
   * @brief Get the singleton instance of NxpSoftPos.
   * @return NxpSoftPos* Pointer to the instance.
   */
  static NxpSoftPos *getInstance();
  void Initialize();
  NxpSoftPos(const NxpSoftPos &) = delete;            /* Deleted copy constructor */
  NxpSoftPos &operator=(const NxpSoftPos &) = delete; /* Deleted assignment operator */

  bool switchEmvcoMode();
  bool switchNciMode();
  bool isEMVCOMode();

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
  static std::unique_ptr<NxpSoftPos> instance;
  NxpSoftPos();
  ~NxpSoftPos();
  bool mIsEmvcoMode = false;
  friend struct std::default_delete<NxpSoftPos>;
  bool performNciCoreReset();
  bool performPropAct();
  bool setRequiredConfig();
};
