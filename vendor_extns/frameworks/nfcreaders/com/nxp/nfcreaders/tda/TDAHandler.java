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
    public static final byte NFC_TDA_GET_STATE_SUB_GID_OID = (byte) 0x15;
    public static final byte NFC_TDA_TRANSACT_CHAIN_SUB_GID_OID = (byte) 0x16;

    private final NfcOperations mNfcOperations;
    private final NxpNciPacketHandler mNxpNciPacketHandler;

    private static final int MAX_TRANSCEIVE_LEN_SUPPORT = 251;
    private static final int STATUS_SUCCESS = 0x00;
    private static final int STATUS_FAILED = 0x01;
    private static final byte TDA_STATE_INIT = 0x00;
    private static final byte DISABLE_TDA = 0x00;
    private static final byte ENABLE_TDA = 0x01;
    private static final byte CONF_GID = 0x20;
    private static final byte SET_CONF_OID = 0x02;
    private static final byte GET_CONF_OID = 0x03;

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
        if (mNxpNciPacketHandler == null || mNfcOperations == null) {
            NxpNfcLogger.e(TAG, "discoverTDA: Invalid state");
            return null;
        }
        if (tdaResult == null) {
            NxpNfcLogger.e(TAG, "discoverTDA: tdaResult is null");
            return null;
        }
        int responseOffset = 0;
        boolean enableDiscovery = false;
        tdaResult.setStatus(TdaResult.RESULT_FAILURE);
        tdaResult.setError(TdaResult.RESULT_FAILURE);
        tdaResult.setException(TdaResult.RESULT_FAILURE);
        try {
            if (isDiscoveryStopRequiredForTDA()) {
                mNfcOperations.startDiscovery(false);
                enableDiscovery = true;
                if (getTDAConfig() == DISABLE_TDA) {
                    if (!setTDAConfig(ENABLE_TDA)) {
                        NxpNfcLogger.e(TAG, "discoverTDA: Failed to enable tda config");
                    }
                }
            }
            byte[] preCmd = {NFC_TDA_DISCOVER_SUB_GID_OID};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
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
                    tdaInfo[i] = new NfcTDAInfo();
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
                        tdaInfo[i].cardTLVInfo[offset] = new CardTLVInfo();
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
                tdaResult.setStatus(TdaResult.RESULT_SUCCESS);
                tdaResult.setError(TdaResult.RESULT_SUCCESS);
                tdaResult.setException(TdaResult.RESULT_SUCCESS);
                return tdaInfo;
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (enableDiscovery) {
                mNfcOperations.startDiscovery(true);
            }
        }
        NxpNfcLogger.d(TAG, "discoverTDA: Failed");
        return null;
    }

    public byte openTDA(byte tdaID, boolean standBy, TdaResult tdaResult) {
        NxpNfcLogger.d(TAG, "openTDA: ");
        byte cid = 0x00; // Invalid
        if (mNxpNciPacketHandler == null) {
            NxpNfcLogger.e(TAG, "openTDA: Invalid state");
            return cid;
        }
        if (tdaResult == null) {
            NxpNfcLogger.e(TAG, "openTDA: tdaResult is null");
            return cid;
        }
        tdaResult.setStatus(TdaResult.RESULT_FAILURE);
        tdaResult.setError(TdaResult.RESULT_FAILURE);
        tdaResult.setException(TdaResult.RESULT_FAILURE);
        if (mNxpNciPacketHandler == null) {
            return STATUS_FAILED;
        }
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_TDA_OPEN_SUB_GID_OID, tdaID, (byte) (standBy ? 0x01 : 0x00)};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_OPEN_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset) {
                    cid = vendorRsp[responseOffset++];
                }
                NxpNfcLogger.d(TAG, "openTDA: Success CID : " + cid);
                tdaResult.setStatus(TdaResult.RESULT_SUCCESS);
                tdaResult.setError(TdaResult.RESULT_SUCCESS);
                tdaResult.setException(TdaResult.RESULT_SUCCESS);
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
        NxpNfcLogger.d(TAG, "transceive: ");
        if (mNxpNciPacketHandler == null) {
            NxpNfcLogger.e(TAG, "transceive: Invalid state");
            return null;
        }
        if (tdaResult == null || cmd_data == null || cmd_data.length == 0) {
            NxpNfcLogger.e(TAG, "transceive: invalid params");
            return null;
        }
        try {
            tdaResult.setStatus(TdaResult.RESULT_FAILURE);
            tdaResult.setError(TdaResult.RESULT_FAILURE);
            tdaResult.setException(TdaResult.RESULT_FAILURE);
            int responseOffset = 0;
            byte[] preCmd;
            if (cmd_data.length <= MAX_TRANSCEIVE_LEN_SUPPORT) {
                preCmd = new byte[cmd_data.length + 1];
                preCmd[0] = NFC_TDA_TRANSACT_SUB_GID_OID;
                System.arraycopy(cmd_data, 0, preCmd, 1, cmd_data.length);
            } else {
                int offset = 0;
                while (offset < cmd_data.length) {
                    if (offset + MAX_TRANSCEIVE_LEN_SUPPORT > cmd_data.length) {
                        break;
                    }
                    byte[] chainedData = new byte[MAX_TRANSCEIVE_LEN_SUPPORT + 1];
                    chainedData[0] = NFC_TDA_TRANSACT_CHAIN_SUB_GID_OID;
                    System.arraycopy(cmd_data, offset, chainedData, 1, MAX_TRANSCEIVE_LEN_SUPPORT);
                    offset += MAX_TRANSCEIVE_LEN_SUPPORT;
                    byte[] resp = mNxpNciPacketHandler.sendVendorNciMessage(
                            NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, chainedData);
                    responseOffset = 0;
                    if (resp == null || resp.length < 2
                            || resp[responseOffset++] != NFC_TDA_TRANSACT_CHAIN_SUB_GID_OID
                            || resp[responseOffset++] != NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                        NxpNfcLogger.e(TAG, "transceive: Failed for chaining pkt");
                        return null;
                    }
                }
                preCmd = new byte[(cmd_data.length - offset) + 1];
                preCmd[0] = NFC_TDA_TRANSACT_SUB_GID_OID;
                System.arraycopy(cmd_data, offset, preCmd, 1, cmd_data.length - offset);
                responseOffset = 0;
            }
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            byte[] response = null;
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_TRANSACT_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset + 1) {
                    response = new byte[vendorRsp.length - responseOffset];
                    for (int i = 0; i < response.length; i++) {
                        response[i] = vendorRsp[responseOffset++];
                    }
                    NxpNfcLogger.d(TAG, "transceive: Success");
                    tdaResult.setStatus(TdaResult.RESULT_SUCCESS);
                    tdaResult.setError(TdaResult.RESULT_SUCCESS);
                    tdaResult.setException(TdaResult.RESULT_SUCCESS);
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
        NxpNfcLogger.d(TAG, "closeTDA: ");
        if (mNxpNciPacketHandler == null) {
            NxpNfcLogger.e(TAG, "closeTDA: Invalid state");
            return;
        }
        if (tdaResult == null) {
            NxpNfcLogger.e(TAG, "closeTDA: tdaResult is null");
            return;
        }
        try {
            tdaResult.setStatus(TdaResult.RESULT_FAILURE);
            tdaResult.setError(TdaResult.RESULT_FAILURE);
            tdaResult.setException(TdaResult.RESULT_FAILURE);
            byte[] preCmd = {NFC_TDA_CLOSE_SUB_GID_OID, tdaID, (byte) (standBy ? 0x01 : 0x00)};
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[0] == NFC_TDA_CLOSE_SUB_GID_OID
                    && vendorRsp[1] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "closeTDA: Success");
                tdaResult.setStatus(TdaResult.RESULT_SUCCESS);
                tdaResult.setError(TdaResult.RESULT_SUCCESS);
                tdaResult.setException(TdaResult.RESULT_SUCCESS);
            } else {
                NxpNfcLogger.e(TAG, "closeTDA: Failed");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (getTDAConfig() != DISABLE_TDA) {
            mNfcOperations.startDiscovery(false);
            if (!setTDAConfig(DISABLE_TDA)) {
                NxpNfcLogger.e(TAG, "closeTDA: Failed to enable tda config");
            }
            mNfcOperations.startDiscovery(true);
        }
        return;
    }

    private boolean isDiscoveryStopRequiredForTDA() {
        try {
            int responseOffset = 0;
            byte[] preCmd = {NFC_TDA_GET_STATE_SUB_GID_OID};
            byte tdaState = TDA_STATE_INIT;
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(
                    NxpNfcConstants.NFC_NCI_PROP_GID, NxpNfcConstants.NXP_NFC_PROP_OID, preCmd);
            if (vendorRsp != null && vendorRsp.length > 1
                    && vendorRsp[responseOffset++] == NFC_TDA_GET_STATE_SUB_GID_OID
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                if (vendorRsp.length > responseOffset) {
                    tdaState = vendorRsp[responseOffset++];
                }
                if (tdaState != TDA_STATE_INIT) {
                    return false;
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return true;
    }

    private boolean setTDAConfig(byte value) {
        try {
            byte[] setConfig = {0x01, (byte) 0xA1, (byte) 0xE6, 0x01, value};
            int responseOffset = 0;
            mNxpNciPacketHandler.shouldCheckResponseSubGid(false);
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(CONF_GID,
                    SET_CONF_OID, setConfig);
            mNxpNciPacketHandler.shouldCheckResponseSubGid(true);
            if (vendorRsp != null && vendorRsp.length > 0
                    && vendorRsp[0] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                NxpNfcLogger.d(TAG, "SuccessFully updated the tda config to " + value);
                return true;
            } else {
                NxpNfcLogger.e(TAG, "Failed to update TDA config");
            }
        } catch (Exception e) {
            NxpNfcLogger.e(TAG, "Exception while updating TDA config " + e);
        }
        return false;
    }

    private byte getTDAConfig() {
        try {
            int responseOffset = 0;
            byte[] getConfig = {0x01, (byte) 0xA1, (byte) 0xE6};
            mNxpNciPacketHandler.shouldCheckResponseSubGid(false);
            byte[] vendorRsp = mNxpNciPacketHandler.sendVendorNciMessage(CONF_GID,
                    GET_CONF_OID, getConfig);
            mNxpNciPacketHandler.shouldCheckResponseSubGid(true);
            if (vendorRsp != null && vendorRsp.length > 4
                    && vendorRsp[responseOffset++] == NfcAdapter.SEND_VENDOR_NCI_STATUS_SUCCESS) {
                responseOffset++;
                if (vendorRsp[responseOffset++] == (byte)0xA1 &&
                        vendorRsp[responseOffset++] == (byte)0xE6) {
                    responseOffset++;
                    NxpNfcLogger.d(TAG, "Get TDA Config Success");
                    return vendorRsp[responseOffset++];
                }
            } else {
                NxpNfcLogger.e(TAG, "Send Vendor Failed");
            }
        } catch (Exception e) {
            NxpNfcLogger.e(TAG, "Exception while updating TDA config " + e);
        }
        return -1;
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
