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

/*************************************************************************
 ***********************  M E T A D A T A  *******************************
 *************************************************************************/

header_type serviceedge_md_t {
    fields {
        processor_ingress : 4;
        processor_egress : 4;
        //processor_state : 4;
        processor_add_header_len : 8;
        in_net_proto : 4;
        fwd_net_proto : 4;
        out_net_proto : 4;
        pad_1 : 4;

        next_hop_id : 8;
        pad_2 : 8;
        // Number of bytes left for increasing the packet size. If this
        // value is 0 the packet must be redirected to the control plane.
        mtu_check : 16 (saturating);
        // MTU of the next hop. The next hop MTU is used
        // because inside of the CORD POD the MTU is expected to be large
        // enough to host any kind of forwarded packet. Therefore, the bottleneck
        // MTU is the MTU of the link of the next hop and not our interfaces MTU.
        mtu_out : 16;
        // Overall length of the packet as it will be send out the port.
        pkt_len_out : 16;
        // Expected length of the packet after adding the headers length added in the egress
        // to the packet as processed in the traffic manager.
        pkt_len_out_decr : 16;
    }
}

header_type cpu_md_t {
    fields {
        in_classifier : 8;
        handling_type : 8;
        reason_code : 8;
        pad_1 : 16;
        expected_value : 32;
        actual_value : 32;
        meter_id: 16;
        packet_color: 2;
        pad_2 : 6;
    }
}

header_type sr_md_t {
    fields {
        // MPLS service label for this traffic
        mpls_service_label : 20;
        bos_tc    : 3;
        bos_s     : 1;
        bos_ttl   : 8;

        // MPLS next hop node label for this traffic
        mpls_next_node_label : 20;
        non_bos_tc    : 3;
        non_bos_s     : 1;
        non_bos_ttl   : 8;

        // Topmost MPLS label
        mpls_top_label : 20;
        top_tc    : 3;
        top_s     : 1;
        top_ttl   : 8;

        // Number of MPLS labels extracted
        // Use only after checking that the packet source of serviceedge_md
        // is PACKET_SOURCE_TRANSPORT_SR
        in_stack_depth : 3;
        in_bos_parsed  : 1;

        in_service_tag_type : 4;

        enabled : 1;
        pad_0   : 7;

        in_classifier : 8;
    }
}

header_type mcast_md_t {
    fields {
        is_multicast : 1;
        pad_0 : 7;
        in_classifier : 8;
    }
}

header_type qos_md_t {
    fields {
        pad_0 : 5;
        phb   : 3;
    }
}

header_type l2_md_t {
    fields {
        in_ok : 1;
        pad_0 : 7;
        in_classifier : 8;
    }
}

header_type ip_md_t {
    fields {
        in_classifier_dst : 8;
        in_classifier_src : 8;
        in_ipv4_classifier_dst : 8;
        in_ipv4_classifier_src : 8;
        in_ipv6_classifier_dst : 8;
        in_ipv6_classifier_src : 8;
        vrf : 8;
    }
}


/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

header_type cpu_header_t {
    fields {
        handling_type: 8;
        reason: 8;
        pcr_bng_access_node_id: 8;
        pcr_bng_access_node_mpls_label : 20;
        padding: 4;
        pcr_bng_session_id: 16;
        etherType: 16;
    }
}

header_type ethernet_t {
    fields {
        dstAddr : 48;
        srcAddr : 48;
        etherType : 16;
    }
}

header_type mpls_t {
    fields {
        label : 20;
        tc : 3;
        s : 1;
        ttl : 8;
    }
}

header_type vlan_t {
    fields {
        pcp : 3;
        dei : 1;
        vlanID: 12;
        etherType: 16;
    }
}

header_type ipv4_t {
    fields {
#ifndef SELECT_MOVING_OFFSET
        version : 4;
#endif
        ihl : 4;
        phb : 3;
        dscp : 3;
        ecn : 2;
        totalLen : 16;
        identification : 16;
        flags : 3;
        fragOffset : 13;
        ttl : 8;
        protocol : 8;
        hdrChecksum : 16;
        srcAddr : 32;
        dstAddr: 32;
    }
}

header_type ipv6_t {
    fields {
#ifndef SELECT_MOVING_OFFSET
        version : 4;
#endif
        phb : 3;
        dscp : 3;
        ecn : 2;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}

//@pragma header_ordering ethernet ipv4 ipv4_option_security ipv4_option_NOP ipv4_option_timestamp ipv4_option_EOL

/*************************************************************************
 ***************  C A L C U L A T E D  F I E L D S ***********************
 *************************************************************************/


field_list ipv4_field_list {
    ipv4.version;
    ipv4.ihl;
    ipv4.phb;
    ipv4.dscp;
    ipv4.ecn;
    ipv4.totalLen;
    ipv4.identification;
    ipv4.flags;
    ipv4.fragOffset;
    ipv4.ttl;
    ipv4.protocol;
    ipv4.srcAddr;
    ipv4.dstAddr;
}

field_list_calculation ipv4_chksum_calc {
    input {
        ipv4_field_list;
    }
    algorithm : csum16;
    output_width: 16;
}

calculated_field ipv4.hdrChecksum {
    verify ipv4_chksum_calc;
    update ipv4_chksum_calc;
}

field_list error_fields {
    cpu_md.handling_type;
    cpu_md.reason_code;
    cpu_md.expected_value;
    cpu_md.actual_value;
    cpu_md.meter_id;
    serviceedge_md.in_net_proto;
    serviceedge_md.fwd_net_proto;
    serviceedge_md.out_net_proto;
    serviceedge_md.processor_ingress;
    serviceedge_md.processor_egress;
    serviceedge_md.next_hop_id;
    pcr_bng_md.access_node_id;
    pcr_bng_md.session_id;
}

/*************************************************************************
 ***********************  P A R S E R  ***********************************
 *************************************************************************/

metadata serviceedge_md_t serviceedge_md;
metadata cpu_md_t cpu_md;
metadata sr_md_t sr_md;
metadata mcast_md_t mcast_md;
metadata qos_md_t qos_md;
metadata l2_md_t l2_md;

metadata ip_md_t ip_md;

header cpu_header_t cpu_header;

header ethernet_t ethernet_outer;
header mpls_t mpls[7];
header mpls_t mpls_bos;

header ethernet_t ethernet_inner;

header vlan_t vlan_subsc;
header vlan_t vlan_service;

header ipv4_t ipv4;
header ipv6_t ipv6;

#define MPLS_BOS current(23, 1)
@pragma parser_value_set_size 2
parser_value_set mpls_service_subscriber_tunnel;
@pragma parser_value_set_size 2
parser_value_set mpls_service_ip;

parser start {
    set_metadata(sr_md.bos_s, 1);
    set_metadata(sr_md.non_bos_s, 0);
    return parse_ethernet_outer;
}

parser parse_ethernet_outer {
    extract(ethernet_outer);
    return select(latest.etherType) {
        ETHERTYPE_MPLS : parse_mpls;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        ETHERTYPE_CPUHEADER : parse_cpu_header;
        default: ingress;
    }
}

parser parse_cpu_header {
    extract(cpu_header);
    return select(latest.etherType) {
        ETHERTYPE_MPLS : parse_mpls;
        ETHERTYPE_IPV4 : parse_ipv4;
        ETHERTYPE_IPV6 : parse_ipv6;
        ETHERTYPE_VLAN : parse_vlan_subsc;
        default: ingress;
    }
}

parser parse_mpls {
    return select(MPLS_BOS) {
        0: parse_mpls_non_bos;
        1: parse_mpls_bos;
    }
}

parser parse_mpls_non_bos {
    extract(mpls[next]);
    return parse_mpls;
}

parser parse_mpls_bos {
    extract(mpls_bos);
    return select (latest.label) {
        mpls_service_subscriber_tunnel : parse_mpls_service_subscriber_tunnel;
        mpls_service_ip : parse_mpls_service_ip;
        default : ingress;
    }
}

parser parse_mpls_service_subscriber_tunnel {
    set_metadata(sr_md.in_service_tag_type, SR_SERVICE_TYPE_SUBSCRIBER_TUNNEL);
    return parse_ethernet_inner;
}

parser parse_mpls_service_ip {
    set_metadata(sr_md.in_service_tag_type, SR_SERVICE_TYPE_IP);
    return parse_ip;
}

parser parse_ethernet_inner {
    extract(ethernet_inner);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan_subsc;
        //TODO: check which double-tagging ethtype format must be used.
        //      alternatively allow both tags or use PVST
        default: ingress;
    }
}

parser parse_vlan_subsc {
    extract(vlan_subsc);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan_service;
        //In this case we have no service field
        ETHERTYPE_PPPOED : parse_pppoed;
        ETHERTYPE_PPPOES : parse_pppoes;
        default: ingress;
    }
}

parser parse_vlan_service {
    extract(vlan_service);
    return select(latest.etherType) {
        ETHERTYPE_PPPOED : parse_pppoed;
        ETHERTYPE_PPPOES : parse_pppoes;
        default: ingress;
    }
}

parser parse_pppoed {
    extract(pppoe);
    set_metadata(pppoe_md.ppp_proto, PPPOE_PROTO_DISCOVERY);
    return ingress;
}

parser parse_pppoes {
    extract(pppoe);
    extract(pppoes_protocol);
    set_metadata(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);
    return select(latest.protocol) {
        PPPOE_PROTOCOL_IPV4: parse_ipv4;
        PPPOE_PROTOCOL_IPV6: parse_ipv6;
        default: ingress;
    }
}

parser parse_ip {
    //We cannot get the IP version from the ethertype or MPLS label. Thus, get it 
    //from the IP packet's first 4 bytes.
    return select(current(0, 4)) {
        4 : parse_ipv4;
        6 : parse_ipv6;
        default : ingress;
    }
}

parser parse_ipv4 {
    extract(ipv4);
    return select(ipv4.ihl) {
        default : ingress;
    }
}

parser parse_ipv6 {
    extract(ipv6);
    return ingress;
}


