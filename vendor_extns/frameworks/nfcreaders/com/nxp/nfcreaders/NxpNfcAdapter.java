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

package com.nxp.nfcreaders;

import android.annotation.RequiresPermission;

import android.nfc.NfcAdapter;
import com.nxp.nfcreaders.tda.NfcTDAInfo;
import com.nxp.nfcreaders.dynamicpower.DynamicPowerResult;
import com.nxp.nfcreaders.tda.TdaResult;
import com.nxp.nfcreaders.tda.TDAHandler;
import com.nxp.nfcreaders.utils.NxpNfcLogger;

public final class NxpNfcAdapter implements INxpNfcAdapter {
    private static final String TAG = "NXPNFC";

    private static NxpNfcAdapter sNxpNfcAdapter;
    private static TDAHandler sTDAHandler;

    private NxpNfcAdapter(NfcAdapter nfcAdapter) {
        sTDAHandler = new TDAHandler(nfcAdapter);
    }

    /**
     * Returns the NxpNfcAdapter for application context,
     * or throws if NFC is not available.
     * @hide
     */
    public static synchronized INxpNfcAdapter getNxpNfcAdapter(NfcAdapter adapter) {
        if (sNxpNfcAdapter == null) {
            if (adapter == null) {
                NxpNfcLogger.e(TAG, "nfcAdapter is null");
                throw new UnsupportedOperationException();
            }
            sNxpNfcAdapter = new NxpNfcAdapter(adapter);
        }
        return sNxpNfcAdapter;
    }
    /**
     * This API sets the new power configuration to controller dynamically by
     * following below sequence.
     * 1. Sends RF deactivate command
     * 2. Sets the new power configuration
     * 3. Sends RF discover command
     *
     * @param pwrConfig :    power configuration array with two bytes
     *                       First byte indicates the value length
     *                       Second byte indicates the actual value
     * @return DynamicPowerResult :-Returns SUCCESS, if power configuration set to
     *                       controller successfully.
     *                       Returns VALUE_ALREADY_EXISTS, if given power
     *                       configuration already exist in controller.
     *                       Returns FAILURE, if power configuration set to
     *                       controller fails. Returns null on remote exception.
     * <p>Requires {@link    android.Manifest.permission#NFC} permission.
     */
    @RequiresPermission(android.Manifest.permission.NFC)
    public DynamicPowerResult setDynamicPowerConfig(byte[] pwrConfig) {
       /* try {
            return sNxpService.setDynamicPowerConfig(pwrConfig);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }*/
//TODO : Yet to implement handler for this api
        return null;
    }

    @RequiresPermission(android.Manifest.permission.NFC)
    public NfcTDAInfo[] discoverTDA(TdaResult tdaResult) {
        try {
            return sTDAHandler.discoverTDA(tdaResult);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @RequiresPermission(android.Manifest.permission.NFC)
    public byte openTDA(byte tdaID, boolean standBy, TdaResult tdaResult) {
        byte inValidCid = 0x00;
        try {
            return sTDAHandler.openTDA(tdaID, standBy, tdaResult);
        } catch (Exception e) {
            e.printStackTrace();
            return inValidCid;
        }
    }

    @RequiresPermission(android.Manifest.permission.NFC)
    public byte[] transceive(byte[] in_cmd_data, TdaResult tdaResult) {
        try {
            return sTDAHandler.transceive(in_cmd_data, tdaResult);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @RequiresPermission(android.Manifest.permission.NFC)
    public void closeTDA(byte tdaID, boolean standBy, TdaResult tdaResult) {
        try {
            sTDAHandler.closeTDA(tdaID, standBy, tdaResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

}
