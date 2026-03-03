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

#ifndef _NCI_PARSER_H_
#define _NCI_PARSER_H_

/* OID: Opcode Identifier (byte 1) */
#define NCI_OID_MASK 0x3F
#define NCI_OID_SHIFT 0


  /* builds byte0 of NCI Command and Notification packet */
#define NCI_MSG_BLD_HDR0(p, mt, gid)                                           \
  *(p)++ = (uint8_t)(((mt) << NCI_MT_SHIFT) | (gid));

/* builds byte1 of NCI Command and Notification packet */
#define NCI_MSG_BLD_HDR1(p, oid) *(p)++ = (uint8_t)(((oid) << NCI_OID_SHIFT));

#define UINT8_TO_STREAM(p, u8)                                                 \
  { *(p)++ = (uint8_t)(u8); }

#define ARRAY_TO_STREAM(p, a, len)                                             \
  {                                                                            \
    int ijk;                                                                   \
    for (ijk = 0; ijk < (len); ijk++)                                          \
      *(p)++ = (uint8_t)(a)[ijk];                                              \
  }
#define STREAM_TO_ARRAY(a, p, len)                                             \
  {                                                                            \
    int ijk;                                                                   \
    for (ijk = 0; ijk < (len); ijk++)                                          \
      ((uint8_t *)(a))[ijk] = *(p)++;                                          \
  }


#define NCI_MT_MASK 0xE0
#define NCI_MT_SHIFT 5

/* PBF: Packet Boundary Flag (byte 0) */
#define NCI_PBF_MASK 0x10
#define NCI_PBF_SHIFT 4

/* GID: Group Identifier (byte 0) */
#define NCI_GID_MASK 0x0F
#define NCI_GID_CORE 0x00      /* 0000b NCI Core group */
#define NCI_GID_RF_MANAGE 0x01 /* 0001b RF Management group */
#define NCI_GID_EE_MANAGE 0x02 /* 0010b NFCEE Management group */
#define NCI_GID_PROP 0x0F      /* 1111b Proprietary */
/* 0111b - 1110b RFU */

/* OID: Opcode Identifier (byte 1) */
#define NCI_OID_MASK 0x3F

#define NCI_BYTE_0_MASK 0x0F
#define NCI_BYTE_1_MASK 0x1F
#define NCI_BYTE_2_MASK 0x2F
#define NCI_BYTE_3_MASK 0x3F

#define NCI_MSG_CMD_ABS_VAL 0x20

#define NCI_MSG_TYPE_DATA 0
#define NCI_MSG_TYPE_CMD 1 /* (NCI_MSG_TYPE_CMD << NCI_MT_SHIFT) = 0x20 */
#define NCI_MSG_TYPE_RSP 2 /* (NCI_MSG_TYPE_RSP << NCI_MT_SHIFT) = 0x40 */
#define NCI_MSG_TYPE_NTF 3 /* (NCI_MSG_TYPE_NTF << NCI_MT_SHIFT) = 0x60 */

/* parse byte0 of NCI packet */
#define NCI_MSG_PRS_HDR0(p, mt, pbf, gid)                                      \
  mt = (*(p)&NCI_MT_MASK) >> NCI_MT_SHIFT;                                     \
  (pbf) = (*(p)&NCI_PBF_MASK) >> NCI_PBF_SHIFT;                                \
  (gid) = *(p)++ & NCI_GID_MASK;

/* parse byte1 of NCI Cmd/Ntf */
#define NCI_MSG_PRS_HDR1(p, oid)                                               \
  (oid) = (*(p)&NCI_OID_MASK);                                                 \
  (p)++;

#define NCI_MSG_PRS_BYTE(p, oid)                                               \
  (oid) = (*(p)&NCI_OID_MASK);                                                 \
  (p)++;

#define MSG_CORE_PROPRIETARY_RSP 2
#define MSG_RF_DISCOVER_RSP 3
#define RF_DEACTIVATE_NTF 6
#define NCI_MSG_CORE_CONN_CREATE 4
#define NCI_MSG_CORE_CONN_CLOSE 5
#define NCI_MSG_MODE_SET 1
#define MSG_CORE_PROPRIETARY_STANDBY_RSP 8
#endif /* _NCI_PARSER_H_ */
