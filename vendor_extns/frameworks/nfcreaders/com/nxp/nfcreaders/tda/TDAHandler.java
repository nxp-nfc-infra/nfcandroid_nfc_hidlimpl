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

package com.nxp.nfcreaders.tda;

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
public class TDAHandler implements INxpNfcNtfHandler, INxpOEMCallbacks {

    private static final String TAG = "TDAHandler";

    public static final byte NFC_TDA_DISCOVER_SUB_GID_OID = (byte) 0x11;
    public static final byte NFC_TDA_OPEN_SUB_GID_OID = (byte) 0x12;
    public static final byte NFC_TDA_TRANSACT_SUB_GID_OID = (byte) 0x13;
    public static final byte NFC_TDA_CLOSE_SUB_GID_OID = (byte) 0x14;
    public static final byte NFC_TDA_WTX_SUB_GID_OID = (byte) 0x15;

    private final NfcOperations mNfcOperations;
    private final NxpNciPacketHandler mNxpNciPacketHandler;

    private static final int STATUS_SUCCESS = 0x00;
    private static final int STATUS_FAILED = 0x01;

    public TDAHandler(NfcAdapter nfcAdapter) {
        this.mNxpNciPacketHandler = NxpNciPacketHandler.getInstance(nfcAdapter);
        this.mNfcOperations = NfcOperations.getInstance(nfcAdapter);
    }

    @Override
    public void onRfFieldDetected(boolean isActive) {
        NxpNfcLogger.d(TAG, "onRfFieldDetected: " + isActive);
    }

    @Override
    public boolean onDisableRequested() {
        NxpNfcLogger.d(TAG, "onDisableRequested: ");
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

    public NfcTDAInfo[] discoverTDA(TdaResult tdaResult) {
        NxpNfcLogger.d(TAG, "discoverTDA: ");
        if (mNxpNciPacketHandler == null) {
            return null;
        }
        int responseOffset = 0;
        try {
            byte[] preCmd = {NFC_TDA_DISCOVER_SUB_GID_OID};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NXP_NFC_PROP_OID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_DISCOVER_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length < responseOffset + 4 ) {
                    NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response");
                    return null;
                }
                int number_of_tda  = vendorRsp[responseOffset++];
                if (number_of_tda == 0) {
                    NxpNfcLogger.e(TAG, "discoverTDA: no TDA found");
                    return null;
                }
                NfcTDAInfo[] tdaInfo = new NfcTDAInfo[number_of_tda];
                for (int i = 0; i < number_of_tda; i++) {
                    if (vendorRsp.length < (responseOffset + 4)) {
                        NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response");
                        return null;
                    }
                    tdaInfo[i].id = vendorRsp[responseOffset++];
                    tdaInfo[i].status = vendorRsp[responseOffset++];
                    tdaInfo[i].numberOfProtocols = vendorRsp[responseOffset++];
                    tdaInfo[i].protocols = new int[tdaInfo[i].numberOfProtocols];
                    if (tdaInfo[i].numberOfProtocols > 0 &&
                            (vendorRsp.length < (responseOffset + tdaInfo[i].numberOfProtocols))) {
                        NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response for protocol details");
                        return null;
                    }
                    for (int protocolOffset = 0; protocolOffset < tdaInfo[i].numberOfProtocols; protocolOffset++) {
                        // extenstion module sends protocol as byte;
                        tdaInfo[i].protocols[protocolOffset] = vendorRsp[responseOffset++];
                    }
                    if (vendorRsp.length < responseOffset + 1) {
                        NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response");
                        return null;
                    }
                    tdaInfo[i].numberOfCardInfo = vendorRsp[responseOffset++];
                    tdaInfo[i].cardTLVInfo = new CardTLVInfo[tdaInfo[i].numberOfCardInfo];
                    for (int offset = 0; offset < tdaInfo[i].numberOfCardInfo; offset++) {
                        if (vendorRsp.length < (responseOffset + 2)) {
                            NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response for cardtlv");
                            return null;
                        }
                        tdaInfo[i].cardTLVInfo[offset].type = vendorRsp[responseOffset++];
                        tdaInfo[i].cardTLVInfo[offset].length = vendorRsp[responseOffset++];
                        tdaInfo[i].cardTLVInfo[offset].value = new byte[tdaInfo[i].cardTLVInfo[offset].length];
                        if (tdaInfo[i].cardTLVInfo[offset].length > 0 &&
                            (vendorRsp.length < (responseOffset + tdaInfo[i].cardTLVInfo[offset].length))) {
                            NxpNfcLogger.e(TAG, "discoverTDA: corrupted vendor response cardtlv value");
                            return null;
                        }
                        for (int dataOffset = 0; dataOffset < tdaInfo[i].cardTLVInfo[offset].length; dataOffset++) {
                            tdaInfo[i].cardTLVInfo[offset].value[dataOffset] = vendorRsp[responseOffset++];
                        }
                    }
                }
                return tdaInfo;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        NxpNfcLogger.d(TAG, "discoverTDA: Failed");
        return null;
    }

    public byte openTDA(byte tdaID, boolean standBy, TdaResult tdaResult) {
        if (mNxpNciPacketHandler == null) {
            return STATUS_FAILED;
        }
        byte cid = 0x00; // Invalid
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_TDA_OPEN_SUB_GID_OID, tdaID, (byte) (standBy ? 0x01 : 0x00)};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NXP_NFC_PROP_OID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_OPEN_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset + 1) {
                    cid = vendorRsp[responseOffset++];
                }
                NxpNfcLogger.d(TAG, "openTDA: Success CID : " + cid);
            } else {
                NxpNfcLogger.e(TAG, "openTDA: Failed");
            }
            return cid;
        } catch (Exception e) {
            e.printStackTrace();
            return cid;
        }
    }

    public byte[] transceive(byte[] cmd_data, TdaResult tdaResult) {
        try {
            int responseOffset = 0;
            byte[] preCmd = new byte[cmd_data.length + 2];
            int commandOffset = 0;
            preCmd[commandOffset++] = NFC_TDA_TRANSACT_SUB_GID_OID;
            preCmd[commandOffset++] = (byte) cmd_data.length;
            for (int cmdIndex = 0; cmdIndex < cmd_data.length; cmdIndex++) {
                preCmd[commandOffset++] = cmd_data[cmdIndex++];
            }
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NXP_NFC_PROP_OID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            byte[] response = null;
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_TRANSACT_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset + 1) {
                    response = new byte[vendorRsp[responseOffset++]];// 1 byte for response length
                    if (vendorRsp.length < responseOffset + response.length) {
                        NxpNfcLogger.e(TAG, "transceive: corrupted vendor nci data");
                        return null;
                    }
                    for (int i = 0; i < response.length; i++) {
                        response[i] = vendorRsp[responseOffset++];
                    }
                    NxpNfcLogger.d(TAG, "transceive: Success");
                }
            } else {
                NxpNfcLogger.e(TAG, "transceive: Failed");
            }
            return response;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public void closeTDA(byte tdaID, boolean standBy, TdaResult tdaResult) {
        try {
            byte[] preCmd = {NFC_TDA_CLOSE_SUB_GID_OID, tdaID, (byte) (standBy ? 0x01 : 0x00)};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NXP_NFC_PROP_OID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[0] == NFC_TDA_CLOSE_SUB_GID_OID
                    && vendorRsp[1] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "closeTDA: Success");
            } else {
                NxpNfcLogger.e(TAG, "closeTDA: Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
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
