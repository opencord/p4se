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
 **************************** D E F I N E S ******************************
 *************************************************************************/

#define PCR_BNG_DIRECTION_UNDEF 0
#define PCR_BNG_DIRECTION_DS 1
#define PCR_BNG_DIRECTION_US 2

#define IPV6_ADDR_TYPE_LL_64 0
#define IPV6_ADDR_TYPE_GU_64 1
#define IPV6_ADDR_TYPE_GU_56 2
#define IPV4_ADDR_TYPE_GU_32 3

#define LINE_CAPACITY 4096
#define LINE_CAPACITY_BITS 14
#define SUBSC_CAPACITY 4096
#define SUBSC_CAPACITY_x2 8192
#define SUBSC_CAPACITY_x3 12288
#define SUBSC_CAPACITY_x4 16384
#define SUBSC_CAPACITY_BITS 14

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/


/*
 * Metadata for the BNG processor
 */
header_type pcr_bng_md_t {
    fields {
        // Store src or dst address for direction-agnostic matching
        address_ipv6 : 128;
        pad_1 : 7;
        session_established : 1;
        address_ipv4 : 32;

        session_id : 16; // set either by bng address matcher or by the bng processor

        access_node_id : 8;
        access_node_tunnel_mpls_label : 20;
        pad_2 : 4;

        subscr_cpe_pppoe_session : 16;

        //traffic_type : 2;
        direction : 2;
        // IPv6 prefix matcher space compression
        ipv6_prefix_id : 2;
        // Address type: see IPV6_ADDR_TYPE_*
        address_type : 2;
        pad_3 : 2;

        us_access_node_id : 8;    // US: set in line match table
        us_vlan_id : 8;           // US: set in line match table
        us_line_session_id : 16;  // US: set in line match table
        us_line_session_id_check : 16;  // US: set in line match table

        // Check bits
        address_match_ok : 1;
        mtu_check_ok : 1;
        us_cpe_match_ok : 1;
        us_line_match_ok : 1;

        ds_packet_color : 2;

        pad_4 : 2;
    }
}

header_type pcr_bng_vlan_md_t {
    fields {
        vlan_outer_pcp : 3;
        vlan_outer_dei : 1;
        vlan_outer_id : 12;
        vlan_outer_etherType : 16;

        vlan_inner_pcp  : 3;
        vlan_inner_dei : 1;
        vlan_inner_id : 12;
        vlan_inner_etherType : 16;
    }
}

metadata pcr_bng_md_t pcr_bng_md;

metadata pcr_bng_vlan_md_t pcr_bng_vlan_md;

metadata pppoe_md_t pppoe_md;

/*************************************************************************
 ********************** T A B L E S & A C T I O N S **********************
 *************************************************************************/

// === Classifier actions for this processor

action a_in_select_processor_bng() {
    modify_field(serviceedge_md.processor_ingress, PROCESSOR_BNG);
    modify_field(serviceedge_md.processor_egress, PROCESSOR_BNG);
}


action a_in_select_processor_bng_ds_ipv4(vrf) {
    a_in_select_processor_bng();
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_DS);
    remove_header(mpls_bos);
    remove_header(mpls[0]);

    modify_field(ethernet_outer.etherType, ETHERTYPE_IPV4);
    modify_field(ethernet_inner.etherType, ETHERTYPE_IPV4);

    modify_field(pcr_bng_md.address_type, IPV4_ADDR_TYPE_GU_32);
    modify_field(pcr_bng_md.address_ipv4, ipv4.dstAddr);

    add(pppoe_md.totalLength, ipv4.totalLen, 2);
    modify_field(pppoe_md.protocol, 0x0021);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);
    modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOES);

    modify_field(ip_md.vrf, vrf);
}

action a_in_select_processor_bng_ds_ipv6(address_type, prefix_id, vrf) {
    a_in_select_processor_bng();
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_DS);
    remove_header(mpls_bos);
    remove_header(mpls[0]);

    modify_field(ethernet_outer.etherType, ETHERTYPE_IPV6);
    modify_field(ethernet_inner.etherType, ETHERTYPE_IPV6);

    modify_field(pcr_bng_md.address_type, address_type);
    modify_field(pcr_bng_md.ipv6_prefix_id, prefix_id);
    modify_field(pcr_bng_md.address_ipv6, ipv6.dstAddr);

    add(pppoe_md.totalLength, ipv6.payloadLen, 42);
    modify_field(pppoe_md.protocol, 0x0057);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);
    modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOES);

    modify_field(ip_md.vrf, vrf);
}

action a_in_select_processor_bng_us_ipv4(vrf) {
    a_in_select_processor_bng();
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_US);
    remove_header(mpls_bos);
    remove_header(mpls[0]);

    modify_field(ethernet_outer.etherType, ETHERTYPE_IPV4);
    modify_field(ethernet_inner.etherType, ETHERTYPE_IPV4);

    modify_field(pcr_bng_md.address_type, IPV4_ADDR_TYPE_GU_32);
    modify_field(pcr_bng_md.address_ipv4, ipv4.srcAddr);

    modify_field(pppoe_md.protocol, pppoes_protocol.protocol);
    modify_field(pppoe_md.totalLength, pppoe.totalLength);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);

    modify_field(ip_md.vrf, vrf);
}

action a_in_select_processor_bng_us_ipv6(address_type, prefix_id, vrf) {
    a_in_select_processor_bng();
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_US);
    remove_header(mpls_bos);
    remove_header(mpls[0]);

    modify_field(ethernet_outer.etherType, ETHERTYPE_IPV6);
    modify_field(ethernet_inner.etherType, ETHERTYPE_IPV6);

    modify_field(pcr_bng_md.address_type, address_type);
    modify_field(pcr_bng_md.ipv6_prefix_id, prefix_id);
    modify_field(pcr_bng_md.address_ipv6, ipv6.srcAddr);

    modify_field(pppoe_md.protocol, pppoes_protocol.protocol);
    modify_field(pppoe_md.totalLength, pppoe.totalLength);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);

    modify_field(ip_md.vrf, vrf);
}

action a_in_select_processor_bng_us_pppoed() {
    a_in_select_processor_bng();
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_US);

    modify_field(pppoe_md.totalLength, pppoe.totalLength);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_DISCOVERY);
}

action a_in_select_processor_bng_ds_pppoed() {
    modify_field(serviceedge_md.processor_egress, PROCESSOR_BNG);
    modify_field(serviceedge_md.in_net_proto, NET_PROTO_CP);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_CP);
    modify_field(pcr_bng_md.access_node_id, cpu_header.pcr_bng_access_node_id);
    modify_field(pcr_bng_md.session_id, cpu_header.pcr_bng_session_id);
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_DS);

    modify_field(pppoe_md.totalLength, pppoe.totalLength);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_DISCOVERY);
    modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOED);

    remove_header(cpu_header);
    modify_field(ethernet_outer.etherType, ETHERTYPE_VLAN);
    modify_field(ethernet_inner.etherType, ETHERTYPE_VLAN);
}

action a_in_select_processor_bng_ds_ipv6_fromcp(address_type, prefix_id, vrf) {
    a_in_select_processor_bng();
    modify_field(serviceedge_md.in_net_proto, NET_PROTO_CP);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_IP);
    modify_field(pcr_bng_md.access_node_id, cpu_header.pcr_bng_access_node_id);
    modify_field(pcr_bng_md.session_id, cpu_header.pcr_bng_session_id);
    modify_field(pcr_bng_md.direction, PCR_BNG_DIRECTION_DS);
    modify_field(pcr_bng_md.address_type, address_type);
    modify_field(pcr_bng_md.ipv6_prefix_id, prefix_id);
    modify_field(pcr_bng_md.address_ipv6, ipv6.dstAddr);

    remove_header(cpu_header);
    modify_field(ethernet_outer.etherType, ETHERTYPE_IPV6);
    modify_field(ethernet_inner.etherType, ETHERTYPE_IPV6);

    add(pppoe_md.totalLength, ipv6.payloadLen, 42);
    modify_field(pppoe_md.protocol, 0x0057);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);
    modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOES);

    modify_field(ip_md.vrf, vrf);
}

/**************************************
 * Upstream (Subscriber -> Core or Subscriber -> Subscriber)
 *************************************/


// ===== t_pcr_bng_us_line_map

table t_pcr_bng_us_line_map {
    reads {
        sr_md.mpls_service_label : exact;
        vlan_subsc.vlanID : exact;
    }
    actions {
        a_pcr_bng_us_line_map_pass;
        a_pcr_bng_us_line_map_fail;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_us_line_map_pass(session_id, access_node_id, mru) {
    modify_field(pcr_bng_md.us_access_node_id, access_node_id);
    modify_field(pcr_bng_md.us_line_session_id, session_id);
    modify_field(pcr_bng_md.us_line_match_ok, TRUE);

    subtract(pcr_bng_md.us_line_session_id_check, session_id, pcr_bng_md.session_id);

    subtract(pppoe_md.mru_check, mru, pppoe_md.totalLength);
}
action a_pcr_bng_us_line_map_fail() {
    modify_field(pcr_bng_md.us_line_match_ok, FALSE);
}

// ===== t_pcr_bng_us_antispoof_mac

table t_pcr_bng_us_antispoof_mac {
    reads {
        pcr_bng_md.us_line_session_id : exact;
        ethernet_inner.srcAddr : exact;
    }
    actions {
        a_pcr_bng_us_antispoof_mac_pass;
        a_pcr_bng_us_antispoof_mac_fail;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_us_antispoof_mac_pass() {
    modify_field(pcr_bng_md.us_cpe_match_ok, TRUE);
}
action a_pcr_bng_us_antispoof_mac_fail() {
    modify_field(pcr_bng_md.us_cpe_match_ok, FALSE);
}

// ===== t_pcr_bng_mtu_init/check
/*
TODO: MRU/MTU check for the tunnel should be done in
the processor.
table t_pcr_bng_mru_check_failed {
    actions {
        a_pcr_bng_mtu_too_big;
    }
}

action a_pcr_bng_mtu_too_big() {
    ingress_pkt_too_big();
}
*/
// ===== t_pcr_bng_us_verify 

table t_pcr_bng_us_verify {
    /*
     * Packets matched by this table have been checked for equality of 
     * pcr_bng_md.in_line_session_id and session_id, and was as 
     * pcr_bng_md.in_line_session_id_ok == 1
     */
    reads {
        pcr_bng_md.address_type : ternary;
        pcr_bng_md.address_match_ok : ternary;
        pcr_bng_md.us_cpe_match_ok : ternary;
        pcr_bng_md.us_line_match_ok : ternary;
        ethernet_inner.dstAddr : ternary;
        vlan_service.vlanID : ternary;
        vlan_service.etherType : ternary;
        pppoe_md.mru_check : ternary;
        pppoe_md.protocol : ternary;
        pppoe_md.ppp_proto : ternary;
    }
    actions {
        _drop;
        a_pcr_bng_accept_us_session;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

table t_pcr_bng_verify {
    reads {
        pcr_bng_md.direction : ternary;
        pcr_bng_md.address_type : ternary;
        pcr_bng_md.address_match_ok : ternary;
        pcr_bng_md.us_cpe_match_ok : ternary;
        pcr_bng_md.us_line_match_ok : ternary;
        ethernet_inner.dstAddr : ternary;
        vlan_service.vlanID : ternary;
        vlan_service.etherType : ternary;
        pppoe_md.mru_check : ternary;
        pppoe_md.protocol : ternary;
        pppoe_md.ppp_proto : ternary;
    }
    actions {
        _drop;
        a_pcr_bng_accept_us_no_session;
        a_pcr_bng_accept_ds;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_pcr_bng_accept() {
    modify_field(cpu_md.meter_id, pcr_bng_md.session_id);
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_SESSION);
}

action a_pcr_bng_accept_us() {
    remove_header(vlan_subsc);
    remove_header(vlan_service);
    copy_header(ethernet_outer, ethernet_inner);
    remove_header(ethernet_inner);
    remove_header(pppoe);
    remove_header(pppoes_protocol);
}

action a_pcr_bng_accept_us_session() {
    a_pcr_bng_accept_us();
    modify_field(pcr_bng_md.session_established, TRUE);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_IP);
    modify_field(cpu_md.meter_id, pcr_bng_md.session_id);
}

action a_pcr_bng_accept_us_no_session() {
    modify_field(pppoe_md.ppp_proto, PPPOE_PROTO_DISCOVERY);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_CP);
    modify_field(pcr_bng_md.access_node_id, pcr_bng_md.us_access_node_id);
    modify_field(pcr_bng_md.session_id, pcr_bng_md.us_line_session_id);
    modify_field(cpu_md.handling_type, HANDLING_TYPE_PRC_DS_CP);
    modify_field(cpu_md.meter_id, pcr_bng_md.us_line_session_id);
}

action a_pcr_bng_accept_ds() {
    a_pcr_bng_accept();
    modify_field(pcr_bng_md.session_established, TRUE);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_IP);
}

// ===== direction-agnostic classification of IPs to Subscriber sessions

table t_pcr_bng_subsc_match_ipv4 {
    reads {
        pcr_bng_md.address_ipv4 : exact;
    }
    action_profile : ap_pcr_bng_set_subscriber_id;
    size : SUBSC_CAPACITY;
}

// ===== t_ds_subsc_match_ipv6

table t_pcr_bng_subsc_match_ipv6_net64_ll {
    reads {
        pcr_bng_md.address_ipv6 mask 0x0000000000000000ffffffffffffffff: exact;
    }
    action_profile : ap_pcr_bng_set_subscriber_id;
    size : SUBSC_CAPACITY;
}

table t_pcr_bng_subsc_match_ipv6_net64 {
    reads {
        pcr_bng_md.ipv6_prefix_id : exact;
        pcr_bng_md.address_ipv6 mask 0x0000000000003fff0000000000000000 : exact;
    }
    action_profile : ap_pcr_bng_set_subscriber_id;
    size : SUBSC_CAPACITY;
}

table t_pcr_bng_subsc_match_ipv6_net56 {
    reads {
        pcr_bng_md.ipv6_prefix_id : exact;
        pcr_bng_md.address_ipv6 mask 0x00000000003fff000000000000000000: exact;
    }
    action_profile : ap_pcr_bng_set_subscriber_id;
    size : SUBSC_CAPACITY;
}

// ==== Tag subscriber traffic


action_profile ap_pcr_bng_set_subscriber_id {
    actions {
        a_pcr_bng_no_match;
        a_pcr_bng_set_subscriber_id;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_no_match() {
    modify_field(pcr_bng_md.address_match_ok, FALSE);
}

action a_pcr_bng_set_subscriber_data(session_id,
                                   access_node_id,
                                   access_node_tunnel_mpls_label,
                                   subscr_cpe_pppoe_session) {
    modify_field(pcr_bng_md.session_id, session_id);
    modify_field(pcr_bng_md.access_node_id, access_node_id);
    modify_field(pcr_bng_md.access_node_tunnel_mpls_label, access_node_tunnel_mpls_label);
    modify_field(pcr_bng_md.subscr_cpe_pppoe_session, subscr_cpe_pppoe_session);
}

action a_pcr_bng_set_subscriber_id(session_id,
                                   access_node_id,
                                   access_node_tunnel_mpls_label,
                                   subscr_cpe_pppoe_session,
                                   mru) {
    a_pcr_bng_set_subscriber_data(session_id,
                                  access_node_id,
                                  access_node_tunnel_mpls_label,
                                  subscr_cpe_pppoe_session);

    modify_field(pcr_bng_md.address_match_ok, TRUE);
    /*
     * set mru to mru+1, if mru_check is 0, the packet is considered too large
    */
    subtract(pppoe_md.mru_check, mru, pppoe_md.totalLength);
}

// ==== Forwarding Actions

action a_pcr_bng_forward_tocp_us() {
    modify_field(serviceedge_md.next_hop_id, NEXT_HOP_CP);
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_CP);

    modify_field(sr_md.mpls_service_label, pcr_bng_md.access_node_tunnel_mpls_label);
    modify_field(cpu_md.handling_type, HANDLING_TYPE_PRC_DS_CP);
}

action a_pcr_bng_forward_fromcp_ds() {
    modify_field(serviceedge_md.next_hop_id, cpu_header.pcr_bng_access_node_id);
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(sr_md.mpls_service_label, cpu_header.pcr_bng_access_node_mpls_label);
}

action a_pcr_bng_forward_nexthop_sr_bng_ds() {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(sr_md.mpls_service_label, pcr_bng_md.access_node_tunnel_mpls_label);
    modify_field(serviceedge_md.next_hop_id, pcr_bng_md.access_node_id);
}

action a_pcr_bng_forward_ipv4_nexthop_sr_bng_ds() {
    a_pcr_bng_forward_nexthop_sr_bng_ds();
    add_to_field(ipv4.ttl, -1);
}

action a_pcr_bng_forward_ipv6_nexthop_sr_bng_ds() {
    a_pcr_bng_forward_nexthop_sr_bng_ds();
    add_to_field(ipv6.hopLimit, -1);
}


// ==== Tag multicast traffic

table t_pcr_bng_mcast_egress {
    reads {
        ig_intr_md_for_tm.mcast_grp_a : exact;
        eg_intr_md.egress_port : exact;
        eg_intr_md.egress_rid : exact;
    }
    action_profile : ap_pcr_bng_mcast_set_subscriber_id;
    size : SUBSC_CAPACITY_x2;
}


action_profile ap_pcr_bng_mcast_set_subscriber_id {
    actions {
        _drop;
        a_pcr_bng_mcast_set_subscriber_id;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_mcast_set_subscriber_id(session_id,
                                         access_node_id,
                                         access_node_tunnel_mpls_label,
                                         subscr_cpe_pppoe_session) {
    a_pcr_bng_set_subscriber_data(session_id,
                                  access_node_id,
                                  access_node_tunnel_mpls_label,
                                  subscr_cpe_pppoe_session);
    modify_field(serviceedge_md.next_hop_id, access_node_id);
    modify_field(sr_md.mpls_service_label, access_node_tunnel_mpls_label);
}

// ==== Add transport headers for downstream traffic

table t_pcr_bng_ds_set_session {
    reads {
        pcr_bng_md.session_id : exact;
    }
    actions {
        _drop;
        a_pcr_bng_ds_set_session;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_ds_set_session(subscr_cpe_mac, subscr_vid) {
    add_header(ethernet_inner);
    modify_field(ethernet_inner.dstAddr, subscr_cpe_mac);
    modify_field(ethernet_inner.etherType, ETHERTYPE_VLAN);

    modify_field(pcr_bng_vlan_md.vlan_outer_id, subscr_vid);
    modify_field(pcr_bng_vlan_md.vlan_outer_etherType, ETHERTYPE_VLAN);

    modify_field(pcr_bng_vlan_md.vlan_inner_id, VLAN_SERVICE_VID);
    //modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOED);
}

table t_pcr_bng_ds_pushstack_vlan {
    actions {
        a_pcr_bng_ds_pushstack_vlan;
    }
}

action a_pcr_bng_ds_pushstack_vlan() {
    add_header(vlan_subsc);
    modify_field(vlan_subsc.vlanID,     pcr_bng_vlan_md.vlan_outer_id);
    modify_field(vlan_subsc.pcp,        pcr_bng_vlan_md.vlan_outer_pcp);
    modify_field(vlan_subsc.dei,        pcr_bng_vlan_md.vlan_outer_dei);
    modify_field(vlan_subsc.etherType,  pcr_bng_vlan_md.vlan_outer_etherType);

    add_header(vlan_service);
    modify_field(vlan_service.vlanID,   pcr_bng_vlan_md.vlan_inner_id);
    modify_field(vlan_service.pcp,      pcr_bng_vlan_md.vlan_inner_pcp);
    modify_field(vlan_service.dei,      pcr_bng_vlan_md.vlan_inner_dei);
    modify_field(vlan_service.etherType,pcr_bng_vlan_md.vlan_inner_etherType);
}

table t_pcr_bng_ds_pushstack_session_pppoes {
    actions {
        a_pcr_bng_ds_pushstack_session_pppoes;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_ds_pushstack_session_pppoes() {
    //modify_field(vlan_service.etherType, ETHERTYPE_PPPOES);
    //modify_field(pcr_bng_vlan_md.vlan_inner_etherType, ETHERTYPE_PPPOES);

    add_header(pppoe);
    modify_field(pppoe.version, 1);
    modify_field(pppoe.typeID, 1);
    modify_field(pppoe.code, 0); // PPPoE Session Data
    modify_field(pppoe.totalLength, pppoe_md.totalLength);
    modify_field(pppoe.sessionID, pcr_bng_md.subscr_cpe_pppoe_session);
    add_header(pppoes_protocol);
    modify_field(pppoes_protocol.protocol, pppoe_md.protocol);
}

table t_pcr_bng_ds_pushstack_nosession {
    actions {
        a_pcr_bng_ds_pushstack_nosession;
    }
    size : SUBSC_CAPACITY;
}

action a_pcr_bng_ds_pushstack_nosession() {
    copy_header(ethernet_inner, ethernet_outer);
}

// ===== t_pcr_bng_ds_srcmac

table t_pcr_bng_ds_srcmac {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions {
        _drop;
        a_pcr_bng_ds_srcmac;
    }
    size : 128;
}

action a_pcr_bng_ds_srcmac(inner_src_mac) {
    modify_field(ethernet_inner.srcAddr, inner_src_mac);
}


// ===== t_ds_meters / counters

meter mtr_ds_subsc {
    type : bytes;
    direct : t_pcr_bng_ds_meter;
    result : pcr_bng_md.ds_packet_color;
}

table t_pcr_bng_ds_meter {
    reads {
        pcr_bng_md.session_id : exact;
    }
    actions {
        _nop;
    }
    size : SUBSC_CAPACITY;
}

counter ctr_subsc {
    type : bytes;
    direct : t_pcr_bng_ds_meter;
}

table t_pcr_bng_counter {
    reads {
        pcr_bng_md.session_id : exact;
    }
    actions {
        _nop;
    }
    size : SUBSC_CAPACITY;
}

/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control ingress_processor_bng {
    /*
     * MTU checks are specific to PPP and therefore should be part of this
     * processor. Per-subscriber PPP MRUs are theoretically possible, but
     * not supported in this version. For details refer to RFC 4638.
     */
    if (pcr_bng_md.address_type == IPV4_ADDR_TYPE_GU_32) {
        apply(t_pcr_bng_subsc_match_ipv4);
    } else if (pcr_bng_md.address_type == IPV6_ADDR_TYPE_LL_64) {
        apply(t_pcr_bng_subsc_match_ipv6_net64_ll);
    } else if (pcr_bng_md.address_type == IPV6_ADDR_TYPE_GU_64) {
        apply(t_pcr_bng_subsc_match_ipv6_net64);
    } else if (pcr_bng_md.address_type == IPV6_ADDR_TYPE_GU_56) {
        apply(t_pcr_bng_subsc_match_ipv6_net56);
    }

    if (pcr_bng_md.direction == PCR_BNG_DIRECTION_US) {
        apply(t_pcr_bng_us_line_map);      // set pcr_bng_md.in_line_* values
        if (pcr_bng_md.subscr_cpe_pppoe_session == pppoe.sessionID) {
            apply(t_pcr_bng_us_antispoof_mac); // set pcr_bng_md.in_mac_* values
        }
    }

    /*
    if (pppoe_md.mru_check == 0) {
        apply(t_pcr_bng_mru_check_failed);
    }
    */
    /*
     * Put all information together. Enable parallelization for the tables
     * before this point.
     */
    if (pcr_bng_md.address_match_ok == TRUE and
        pcr_bng_md.us_line_match_ok == TRUE and
        pcr_bng_md.us_line_session_id == pcr_bng_md.session_id) {
        apply(t_pcr_bng_us_verify);
    } else {
        /* Handle DS traffic and US traffic that has no valid session_id. */
        apply(t_pcr_bng_verify);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control egress_processor_bng {
    if (pcr_bng_md.direction == PCR_BNG_DIRECTION_DS) {
        if (mcast_md.is_multicast==TRUE) {
            apply(t_pcr_bng_mcast_egress);
        }
        apply(t_pcr_bng_ds_meter);
    }
    apply(t_pcr_bng_counter);
    if (serviceedge_md.out_net_proto == NET_PROTO_SR) {
        if (pcr_bng_md.direction == PCR_BNG_DIRECTION_DS) {
            if (pcr_bng_md.session_established == TRUE) {
                apply(t_pcr_bng_ds_set_session);
                apply(t_pcr_bng_ds_pushstack_vlan);
                if (pppoe_md.ppp_proto == PPPOE_PROTO_SESSION) {
                    apply(t_pcr_bng_ds_pushstack_session_pppoes);
                }
            } else {
                apply(t_pcr_bng_ds_pushstack_nosession);
            }
            apply(t_pcr_bng_ds_srcmac);
        }
    }
}

