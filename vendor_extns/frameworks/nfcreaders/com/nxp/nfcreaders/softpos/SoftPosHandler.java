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

package com.nxp.nfcreaders.softpos;

import android.nfc.NfcAdapter;

import android.content.Context;
import com.nxp.nfcreaders.INxpNfcNtfHandler;
import com.nxp.nfcreaders.INxpOEMCallbacks;
import com.nxp.nfcreaders.utils.NxpNfcConstants;
import com.nxp.nfcreaders.utils.NxpNfcLogger;
import com.nxp.nfcreaders.core.NfcOperations;
import com.nxp.nfcreaders.core.NxpNciPacketHandler;

import java.io.IOException;


/**
 * This class is responsible to control Softpos features
 */
public class SoftPosHandler implements INxpNfcNtfHandler, INxpOEMCallbacks {

    private static final String TAG = "SoftPosHandler";

    public static final byte NFC_SOFTPOS_SWITCH_EMVCO = (byte) 0x31;
    public static final byte NFC_SOFTPOS_SWITCH_NFC = (byte) 0x32;
    public static final byte NFC_SOFTPOS_GET_MODE = (byte) 0x33;

    private final NfcOperations mNfcOperations;
    private NfcAdapter mNfcAdapter;
    private final NxpNciPacketHandler mNxpNciPacketHandler;
    private static final int SOFTPOS_STATUS_SUCCESS = 0x00;
    private static final int SOFTPOS_STATUS_FAILED = 0x01;
    private static final int SOFTPOS_STATUS_NFC_OFF = 0x02;
    private static final int SOFTPOS_STATUS_NFC_NOT_AVAIABLE = 0x03;
    private static final int SOFTPOS_STATUS_ALREADY_IN_REQUESTED_MODE = 0x04;
    private static final int SOFTPOS_STATUS_INVALID_PARAM = 0x05;
    private static final int SOFTPOS_STATUS_UNKNOWN = 0xFF;
    private static final byte NFC_MODE = 0x00;
    private static final byte EMVCO_MODE = 0x01;

    public SoftPosHandler(NfcAdapter nfcAdapter) {
        this.mNxpNciPacketHandler = NxpNciPacketHandler.getInstance(nfcAdapter);
        this.mNfcOperations = NfcOperations.getInstance(nfcAdapter);
        this.mNfcAdapter = nfcAdapter;
    }

    @Override
    public boolean onDisableRequested() {
        NxpNfcLogger.d(TAG, "onDisableRequested: ");
        if (mNfcOperations != null) {
            mNfcOperations.unregisterNxpOemCallback();
        }
        return true;
    }

    @Override
    public void onEnableFinished(int status){
        NxpNfcLogger.d(TAG, "onEnableFinished: ");
    }

    @Override
    public void onBootFinished(int status) {
        NxpNfcLogger.d(TAG, "onBootFinished: ");
    }

    @Override
    public void onVendorNciNotification(int gid, int oid, byte[] payload) {
        if (payload == null || payload.length < 2) {
            NxpNfcLogger.e(TAG, "Invalid payload");
            return;
        }
        NxpNfcLogger.d(TAG, "onVendorNciNotification GID: " +  gid + " OID: " + oid);
    }

    /**
     * This API switches the softpos mode discovery and default discovery
     * by enabling and disabling the softpos feature.
     *
     * @param config :       technology configuration required to
     *                       be enable in softpos mode discovery
     * @param mode :         to enable disable the softpos mode
     *                       true will indicate the request to enable softpos
     *                       false will indicate the request to disable softpos
     *                       and start default nfc discovery
     * @param context :      application context
     * @return int :         0x00 : For successful execution of api
     *                       0x01 : If switching from softpos to default
     *                              or default to softpos fails.
     *                       0x02 : If NFC is off.
     *                       0x03 : If NFC service not available.
     *                       0x04 : If already in requested mode softpos off/on.
     *                       0x05 : if input params are invalid like: context is null.
     *                       0xFF : any unkonwn error or exceptions like IO Exception;
     */
    public int enableSoftPOSMode (byte config, boolean mode, Context context) {

        NxpNfcLogger.d(TAG, "enableSoftPOSMode Enter: Config: " + config + " Mode: " + mode);
        if (mNfcOperations == null) {
            NxpNfcLogger.e(TAG, "NFC not avaiable ");
            return  SOFTPOS_STATUS_NFC_NOT_AVAIABLE;
        }
        if (!mNfcOperations.isEnabled()) {
            NxpNfcLogger.e(TAG, "NFC not enabled please enable the NFC before calling api");
            return SOFTPOS_STATUS_NFC_OFF;
        }
        if (context == null || config > 0x07 || config < 0x01) {
            return SOFTPOS_STATUS_INVALID_PARAM;
        }
        if (mode == isEmvcoMode()) {
            NxpNfcLogger.i(TAG, "Already in requested Mode: ");
            return SOFTPOS_STATUS_ALREADY_IN_REQUESTED_MODE;
        }
        int status = SOFTPOS_STATUS_SUCCESS;
        if (mode) {
            mNfcOperations.registerNxpOemCallback(this);
            boolean isDiscoverStopped = false;
            if (mNfcOperations.isDiscoveryStarted()) {
                mNfcOperations.startDiscovery(false);
                isDiscoverStopped = true;

            }
            if (switchEmvcoMode(config)) {
                mNfcOperations.setDiscoveryTech(config, NfcAdapter.FLAG_LISTEN_DISABLE);
            } else if (isDiscoverStopped) {
                mNfcOperations.startDiscovery(true);
                status = SOFTPOS_STATUS_FAILED;
            }
            isDiscoverStopped = false;
        } else {
            //  reset NFC
            if (!switchNFCMode()) {
                NxpNfcLogger.e(TAG, "failed to reset the flag");
                status = SOFTPOS_STATUS_FAILED;
            }
            if (mNfcOperations != null) {
                mNfcOperations.unregisterNxpOemCallback();
            }
            if (!mNfcOperations.disableNfc(context) || ! mNfcOperations.enableNfc()) {
                NxpNfcLogger.e(TAG, "failed to switch to NFC Mode");
                status = SOFTPOS_STATUS_FAILED;
            }
        }
        return status;
    }

    private boolean isEmvcoMode() {
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_SOFTPOS_GET_MODE};
            byte mode = NFC_MODE;
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_SOFTPOS_GET_MODE
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset) {
                    mode = vendorRsp[responseOffset++];
                }
                if (mode == EMVCO_MODE) {
                    return true;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean switchEmvcoMode(byte techConfig) {
        if (mNxpNciPacketHandler == null) {
            return false;
        }
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_SOFTPOS_SWITCH_EMVCO, techConfig};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_SOFTPOS_SWITCH_EMVCO
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "switch emvco : Success ");
                return true;
            } else {
                NxpNfcLogger.e(TAG, "switch emvco: Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    private boolean switchNFCMode() {
        if (mNxpNciPacketHandler == null) {
            return false;
        }
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_SOFTPOS_SWITCH_NFC};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_SOFTPOS_SWITCH_NFC
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "reset emvco flag : Success ");
                return true;
            } else {
                NxpNfcLogger.e(TAG, "reset emvco flag : Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}
