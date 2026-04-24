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
#ifndef TDA_NCI_DEFS_H_
#define TDA_NCI_DEFS_H_

/** \addtogroup TDA_NCI_DEF_INTERFACE
 *  @brief  This file contains the definition from NCI specification
 *  @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#define NCI_MSG_TYPE_CMD 1
#define NCI_GID_EE 0x02
#define NCI_MSG_NFCEE_DISCOVER 0
#define NCI_MSG_NFCEE_MODE_SET 1
#define NCI_MSG_CORE_CON_CLOSE 5
#define NCI_PARAM_SIZE_DISCOVER_NFCEE 0
#define NCI_PKT_HDR_SIZE 3
#define NCI_CORE_PARAM_SIZE_NFCEE_MODE_SET 0x02
#define NCI_CORE_PARAM_SIZE_CON_CREATE 0x02
#define NCI_CORE_PARAM_SIZE_CON_CLOSE 0x01
#define NCI_CORE_GID 0x00
#define NCI_MSG_CORE_CON_CREATE 4
#define NCI_CON_CREATE_TAG_NFCEE_VAL 0x01
#define NCI_NFCEE_INTERFACE_APDU 0x00
#define NCI_DEST_TYPE_NFCC 1   /* NFCC - loopback */
#define NCI_DEST_TYPE_REMOTE 2 /* Remote NFC Endpoint */
#define NCI_DEST_TYPE_NFCEE 3  /* NFCEE */
#define MAX_FRAGMENT_SIZE 256
#define PBF_COMPLETE_MSG 0x00
#define PBF_SEGMENT_MSG 0x10
#define BYTE_ARRAY_TO_STREAM(p, a, len)                                        \
  {                                                                            \
    int ijk;                                                                   \
    for (ijk = 0; ijk < (len); ijk++)                                          \
      *(p)++ = (uint8_t)(a)[ijk];                                              \
  }
#define STATUS_SEMANTIC_ERROR 0x06
#define MSG_CORE_NFCEE_DISCOVER_RSP_NTF_VAL 0
#define MSG_CORE_NFCEE_MODESET_RSP_NTF 1
#define MSG_CORE_CREDIT_DATA_NTF 3
#define MSG_CORE_NFCEE_DISCOVER_RSP_LEN 5
#define MSG_CORE_INTERFACE_ERROR_NTF 0x08
#define MSG_CORE_PROPRIETARY_RSP 2
#define MSG_RF_DISCOVER_RSP 3
#define RF_DEACTIVATE_NTF 6
#define NCI_NFCEE_INTERFACE_HCI_ACCESS 0x01
#define NCI_NFCEE_INTERFACE_T3T 0x02
#define NCI_NFCEE_INTERFACE_TRANSPARENT 0x03
#define NCI_NFCEE_INTERFACE_PROPRIETARY 0x80
/* Deactivate the connected NFCEE */
#define NCI_NFCEE_MD_DEACTIVATE 0x00
/* Activate the connected NFCEE */
#define NCI_NFCEE_MD_ACTIVATE 0x01
#define CT_TDA_ID 0x20
#define WAIT_FOR_MODE_SET_NTF 0x01
#define NCI_MSG_NFCEE_DISCOVER 0
/* parse byte1 of NCI Cmd/Ntf */
#define NCI_MSG_PRS_HDR_BYTE1(p, oid)                                          \
  (oid) = (*(p)&NCI_OID_MASK);                                                 \
  (p)++;

/* parse byte0 of NCI packet */
#define NCI_MSG_PRS_HDR_BYTE0(p, mt, pbf, gid)                                 \
  mt = (*(p)&NCI_MT_MASK) >> NCI_MT_SHIFT;                                     \
  (pbf) = (*(p)&NCI_PBF_MASK) >> NCI_PBF_SHIFT;                                \
  (gid) = *(p)++ & NCI_GID_MASK;

#define NCI_MSG_COMMAND_TYPE_VAL 0x20

#define NCI_MSG_TYPE_DATA_VAL 0
#define NCI_MSG_TYPE_CMD_VAL 1 /* (NCI_MSG_TYPE_CMD << NCI_MT_SHIFT) = 0x20 */
#define NCI_MSG_TYPE_RSP_VAL 2 /* (NCI_MSG_TYPE_RSP << NCI_MT_SHIFT) = 0x40 */
#define NCI_MSG_TYPE_NTF_VAL 3 /* (NCI_MSG_TYPE_NTF << NCI_MT_SHIFT) = 0x60 */

#define NCI_MT_SHIFT_VAL 5
#define NCI_OID_MASK_VAL 0x3F
#define NCI_CONN_ID_MASK_VAL 0x0F
#define NCI_MSG_MODE_SET_VAL 1

/* GID: Group Identifier (byte 0) */
#define NCI_GID_MASK_VAL 0x0F
#define NCI_GID_CORE_VAL 0x00      /* 0000b NCI Core group */
#define NCI_GID_RF_MANAGE_VAL 0x01 /* 0001b RF Management group */
#define NCI_GID_EE_MANAGE_VAL 0x02 /* 0010b NFCEE Management group */
#define NCI_GID_PROP_VAL 0x0F      /* 1111b Proprietary */

#define NCI_MSG_CORE_CONN_CREATE_VAL 4
#define NCI_MSG_CORE_CONN_CLOSE_VAL 5

#define NCI_FRAG_MAX_DATA_LEN 1024

#define NFCEE_INTERFACE_ACTIVATION_FAILED 0xc0
#define NFCEE_TRANSMISSION_ERROR 0xc1
#define NFCEE_PROTOCOL_ERROR 0xc2
#define NFCEE_TIMEOUT_ERROR 0xc3

#define NCI_MT_NTF_VAL 0x60
#define NCI_CORE_CONN_CREDITS_NTF_VAL 0x06
#define NCI_CORE_CONN_CREDITS_NTF_LEN_VAL 0x03
#define NCI_CORE_CONN_CREDITS_NTF_NO_OF_ENTRY_VAL 0x01
#define NCI_CORE_CONN_CREDITS_NTF_CONN_ID_VAL 0x00
#define NCI_CORE_CONN_CREDITS_NTF_CONN_CREDITS_VAL 0x01

#define NCI_CORE_INTERFACE_ERROR_NTF_VAL 0x08
#define NCI_CORE_INTERFACE_ERROR_NTF_LEN_VAL 0x02
#define NCI_CT_DATA_CONN_ID_MASK 0x0F

#ifdef __cplusplus
}
#endif /*  C++ Compilation guard */
/** @}*/
#endif /* _PHNXPNICHAL_EXT_H_ */
