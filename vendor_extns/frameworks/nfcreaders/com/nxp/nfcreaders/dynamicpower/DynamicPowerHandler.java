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

package com.nxp.nfcreaders.dynamicpower;

import android.nfc.NfcAdapter;

import com.nxp.nfcreaders.INxpNfcNtfHandler;
import com.nxp.nfcreaders.INxpOEMCallbacks;
import com.nxp.nfcreaders.utils.NxpNfcConstants;
import com.nxp.nfcreaders.utils.NxpNfcLogger;
import com.nxp.nfcreaders.core.NfcOperations;
import com.nxp.nfcreaders.core.NxpNciPacketHandler;

import java.io.IOException;


/**
 * This class is responsible to control TDA features
 */
public class DynamicPowerHandler implements INxpNfcNtfHandler, INxpOEMCallbacks {

    private static final String TAG = "DynamicPowerHandler";
    private static final byte CONF_GID = 0x20;
    private static final byte SET_CONF_OID = 0x02;
    private static final byte GET_CONF_OID = 0x03;
    private final NfcOperations mNfcOperations;
    private final NxpNciPacketHandler mNxpNciPacketHandler;

    public DynamicPowerHandler(NfcAdapter nfcAdapter) {
        this.mNxpNciPacketHandler = NxpNciPacketHandler.getInstance(nfcAdapter);
        this.mNfcOperations = NfcOperations.getInstance(nfcAdapter);
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
     */
    public DynamicPowerResult setDynamicPowerConfig(byte[] pwrConfig) {
        NxpNfcLogger.d(TAG, "Entry setDynamicPowerConfig ");
        DynamicPowerResult result = new DynamicPowerResult(DynamicPowerResult.Result.FAILURE);

        if (pwrConfig == null || pwrConfig.length < 2) {
            NxpNfcLogger.e(TAG, "Invalid config value");
            return result;
        }

        if (!mNfcOperations.isEnabled()) {
            return result;
        }

        int responseOffset = 0;
        boolean enableDiscovery = false;
        try {
            byte[] getConfig = {0x01, (byte) 0xA1, (byte) 0xA4};
            mNxpNciPacketHandler.shouldCheckResponseSubGid(false);
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(CONF_GID,
                    GET_CONF_OID, getConfig);
            mNxpNciPacketHandler.shouldCheckResponseSubGid(true);
            if (vendorRsp != null && vendorRsp.length > 4
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                /* response should be status + len + 2 byte Tag + LV*/
                /* 400306   00 01 A1A4 01 00 */
                responseOffset++;
                if (vendorRsp[responseOffset++] == (byte)0xA1 &&
                        vendorRsp[responseOffset++] == (byte)0xA4) {
                    responseOffset++;
                    if (vendorRsp[responseOffset++] == pwrConfig[1]) {
                        NxpNfcLogger.d(TAG, "Same value as power config");
                        result.setResult(DynamicPowerResult.Result.VALUE_ALREADY_EXISTS);
                        return result;
                    }
                }
            } else {
                NxpNfcLogger.e(TAG, "Send Vendor Failed");
                return result;
            }
            mNfcOperations.registerNxpOemCallback(this);
            if (mNfcOperations.isDiscoveryStarted()) {
                mNfcOperations.startDiscovery(false);
                enableDiscovery = true;
            }
            /* check if discovery started */
           if (mNfcOperations.isDiscoveryStarted()) {
                NxpNfcLogger.e(TAG, "Not able to stop discovery");
                mNfcOperations.unregisterNxpOemCallback();
                return result;
            }
            byte[] setConfig = {0x01, (byte) 0xA1, (byte) 0xA4, pwrConfig[0], pwrConfig[1]};
            mNxpNciPacketHandler.shouldCheckResponseSubGid(false);
            vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(CONF_GID,
                    SET_CONF_OID, setConfig);
            mNxpNciPacketHandler.shouldCheckResponseSubGid(true);
            if (vendorRsp != null && vendorRsp.length > 0
                    && vendorRsp[0] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "SuccessFully updated the power config");
                result.setResult(DynamicPowerResult.Result.SUCCESS);
            } else {
                NxpNfcLogger.e(TAG, "Send Vendor Failed");
            }
            mNxpNciPacketHandler.unregisterNtfCallback(this);
            if (enableDiscovery) {
                mNfcOperations.startDiscovery(true);
            }
        } catch (Exception e) {
            NxpNfcLogger.d(TAG, "Exception in sendVendorNciMessage ");
        }
        return result;
    }

    @Override
    public void onVendorNciNotification(int gid, int oid, byte[] payload) {
        if (payload == null || payload.length < 2) {
            NxpNfcLogger.e(TAG, "Invalid payload");
            return;
        }
        NxpNfcLogger.d(TAG, "onVendorNciNotification GID: " +  gid + " OID: " + oid);
    }
}
