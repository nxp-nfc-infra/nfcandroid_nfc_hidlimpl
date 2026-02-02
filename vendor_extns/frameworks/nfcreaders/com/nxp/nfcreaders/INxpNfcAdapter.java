 /*
  * Copyright 2015-2021,2023,2025-2026 NXP
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
  * You may obtain a copy of the License at
  *
  *      http://www.apache.org/licenses/LICENSE-2.0
  *
  * Unless required by applicable law or agreed to in writing, software
  * distributed under the License is distributed on an "AS IS" BASIS,
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
package com.nxp.nfcreaders;

import com.nxp.nfcreaders.dynamicpower.DynamicPowerResult;
import com.nxp.nfcreaders.tda.NfcTDAInfo;
import com.nxp.nfcreaders.tda.TdaResult;

public interface INxpNfcAdapter
{
    DynamicPowerResult setDynamicPowerConfig(byte[] config);
    NfcTDAInfo[] discoverTDA(TdaResult tdaResult);
    byte openTDA(byte tdaID, boolean standBy, TdaResult tdaResult);
    void closeTDA(byte tdaID, boolean standBy, TdaResult tdaResult);
    byte[] transceive(byte[] in_cmd_data, TdaResult tdaResult);
}
