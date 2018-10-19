/*
* Copyright 2018-present Open Networking Foundation
*
* Contributed and sponsored by Deutsche Telekom AG.
* Originally developed as part of the D-Nets 6 P4 Service Edge project
* in collaboration with Technische Universitaet Darmstadt.
* Authors: Jeremias Blendin, Leonhard Nobach
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* For details see the file LICENSE in the top project directory.
*/


#define ROUTE_CAPACITY 256
#define NEXT_HOP_CAPACITY 256
#define ACL_CAPACITY 128

#define VLAN_SERVICE_VID 7

#define MPLS_TUNNEL 9000
#define MPLS_IPV4  16384
#define MPLS_IPV6  16385
#define MPLS_IP    16386

#define NEXT_HOP_CP 255

#define FALSE 0
#define TRUE 1

#define IN_CLASSIFY_TABLE_SIZE 64

#define PROCESSOR_NONE 0
#define PROCESSOR_SR_FWD 1
#define PROCESSOR_SR_TERM 2
#define PROCESSOR_BNG 3
#define PROCESSOR_WHOLESALE 4

#define NET_PROTO_UNDEFINED 0
#define NET_PROTO_IP 1
#define NET_PROTO_SR 2 // Segment Routing
#define NET_PROTO_CP 3 // Control Plane

#define PKT_LEN_OPERATOR_NOCHANGE 0
#define PKT_LEN_OPERATOR_INC 0
#define PKT_LEN_OPERATOR_DEC 0

#define CPU_ERROR_NONE         0
#define CPU_ERROR_PKT_TOO_BIG  1
#define HANDLING_TYPE_ERROR 1
#define HANDLING_TYPE_CP_PRC_US 2
#define HANDLING_TYPE_PRC_DS_CP 3

//#define CPU_MIRROR_SESSION_ID 250
#define CPU_MIRROR_SESSION_ID 100

#define CPU_PORT 64

#define SR_SERVICE_TYPE_NONE              0
#define SR_SERVICE_TYPE_IP                1
#define SR_SERVICE_TYPE_SUBSCRIBER_TUNNEL 2

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_PPPOED 0x8863
#define ETHERTYPE_PPPOES 0x8864
#define ETHERTYPE_MPLS 0x8847
#define ETHERTYPE_CPUHEADER 0xeeee

#define PPPOE_PROTOCOL_IPV4 0x0021
#define PPPOE_PROTOCOL_IPV6 0x0057

