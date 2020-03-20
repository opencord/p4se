/*
* Copyright 2019-present Open Networking Foundation
*
* Contributed and sponsored by Deutsche Telekom AG.
* Originally developed as part of the D-Nets 6 P4 Service Edge project
* in collaboration with Technische Universitaet Darmstadt.
* Authors: Leonhard Nobach, Jeremias Blendin, Ralf Kundel
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

struct ingress_md_t {
    bit<2>  usds;
    bit<1>  cp;
    bit<32> line_id;
    bit<8>  subsc_id;
    bit<16> ctr_bucket;
    bit<32> meter_result;
}


header bng_cp_t {
    bit<16> stamp;
    bit<32> fwd_port; //storing bng ingress port for messages to Control Plane
    bit<48> eth_dstAddr;
    bit<48> eth_srcAddr;
    bit<16> eth_etherType;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header mpls_t {
    bit<20> label;
    bit<3>  tc;
    bit<1>  s;
    bit<8>  ttl;
}

header pppoe_t {
    bit<4>  version;
    bit<4>  typeID;
    bit<8>  code;
    bit<16> sessionID;
    bit<16> totalLength;
    bit<16> protocol; //See http://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml
                        //User-plane: IPv4:  0x0021, IPv6: 0x0057, 
                        ////Control-plane: LCP: 0xc021, IPv6CP: 0x8057, IPCP: 
}

header vlan_t {
    bit<16> vlanID;
    bit<16> etherType;
}
#define PPPOE_PROTOCOL_IP4 16w0x0021
#define PPPOE_PROTOCOL_IP6 16w0x0057

#define ETHERTYPE_IPV4 16w0x0800
#define ETHERTYPE_VLAN 16w0x8100
#define ETHERTYPE_PPPOED 16w0x8863
#define ETHERTYPE_PPPOES 16w0x8864
#define ETHERTYPE_MPLS 16w0x8847
#define ETHERTYPE_CP 16w0x8765	//A (remote) CP packet that must be forwarded on a specific port.
