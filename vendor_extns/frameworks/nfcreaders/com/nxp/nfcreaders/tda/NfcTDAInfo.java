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

package com.nxp.nfcreaders.tda;
import java.util.Arrays;
/**
 * @brief This structure defines the propery of smart card connected over TDA
 */
public class NfcTDAInfo {
  public byte id = 0;
  public int status;
  public byte numberOfProtocols = 0;
  public int[] protocols;
  public byte numberOfCardInfo = 0;
  public CardTLVInfo[] cardTLVInfo;

  public NfcTDAInfo() {}

  public NfcTDAInfo(NfcTDAInfo other) {

    this.id = other.id;
    this.status = other.status;
    this.numberOfProtocols = other.numberOfProtocols;
    this.protocols = Arrays.copyOf(other.protocols, other.protocols.length);
    this.numberOfCardInfo = other.numberOfCardInfo;
    this.cardTLVInfo = new CardTLVInfo[other.cardTLVInfo.length];

    for (int i = 0; i < other.cardTLVInfo.length; i++) {
      this.cardTLVInfo[i] = new CardTLVInfo(other.cardTLVInfo[i]);
    }
  }
}
