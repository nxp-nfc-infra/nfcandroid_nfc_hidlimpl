/*
 * Copyright 2026 NXP
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

/*
 * This file is auto-generated.  DO NOT MODIFY.
 */
package com.nxp.nfcreaders.tda;
import java.util.Arrays;
/**
 * @brief This provides the TLV information of the smart card connected over
 * TDA
 */
public class CardTLVInfo {
  public byte type = 0;
  public byte length = 0;
  public byte[] value;

  public CardTLVInfo() {}

  public CardTLVInfo(CardTLVInfo other) {
    this.type = other.type;
    this.length = other.length;
    this.value = Arrays.copyOf(other.value, other.value.length);
  }
}
