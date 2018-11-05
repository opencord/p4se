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

#include "constants.p4"
#include "pppoe.p4"
#include "headers.p4"
#include "acl.p4"
#include "processor_bng.p4"
#include <tofino/intrinsic_metadata.p4>
#include <tofino/constants.p4>

/*************************************************************************
 **************************** D E F I N E S ******************************
 *************************************************************************/

action _nop() { }

action _drop() { drop(); }

/*************************************************************************
 **************  I N G R E S S   T A B L E S & A C T I O N S *************
 *************************************************************************/

// ============= General Tables

action a_in_analyze_sr_none() {
    modify_field(sr_md.in_stack_depth, 0);
}

action a_in_analyze_base(in_bos_parsed) {
    modify_field(sr_md.in_bos_parsed, in_bos_parsed);
    modify_field(serviceedge_md.in_net_proto, NET_PROTO_SR);
}

table t_in_classify_sr {
    reads {
        mpls_bos.valid : ternary;
        mpls[0].valid : ternary;
        mpls[1].valid : ternary;
        mpls[2].valid : ternary;
        mpls[3].valid : ternary;
        mpls[4].valid : ternary;
        mpls[5].valid : ternary;
        mpls[6].valid : ternary;
        mpls_bos.label : ternary;
        mpls[0].label : ternary;
        mpls[1].label : ternary;
        sr_md.in_service_tag_type : ternary;
    }
    actions {
        _nop;
        a_in_analyze_sr_none;
        a_in_classify_sr_cls;
        a_in_classify_sr_cls_remove_mpls0;
        a_in_analyze_sr_set_stack_depth_bos_1;
        a_in_analyze_sr_set_stack_depth_bos_2;
        a_in_analyze_sr_set_stack_depth_bos_3;
        a_in_analyze_sr_set_stack_depth_bos_4;
        a_in_analyze_sr_set_stack_depth_bos_5;
        a_in_analyze_sr_set_stack_depth_bos_6;
        a_in_analyze_sr_set_stack_depth_bos_7;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_sr_cls_remove_mpls0(in_classifier) {
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.in_stack_depth, 2);
    modify_field(sr_md.mpls_top_label, mpls[0].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    remove_header(mpls[0]);
    remove_header(mpls_bos);
}

action a_in_classify_sr_cls(in_classifier) {
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.in_stack_depth, 1);
    modify_field(sr_md.mpls_top_label, mpls_bos.label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    remove_header(mpls_bos);
}

action a_in_analyze_sr_set_stack_depth_bos_1(in_classifier) {
    modify_field(sr_md.in_stack_depth, 1);
    modify_field(sr_md.mpls_top_label, mpls_bos.label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_2(in_classifier) {
    modify_field(sr_md.in_stack_depth, 2);
    modify_field(sr_md.mpls_top_label, mpls[0].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_3(in_classifier) {
    modify_field(sr_md.in_stack_depth, 3);
    modify_field(sr_md.mpls_top_label, mpls[1].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_4(in_classifier) {
    modify_field(sr_md.in_stack_depth, 4);
    modify_field(sr_md.mpls_top_label, mpls[2].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_5(in_classifier) {
    modify_field(sr_md.in_stack_depth, 5);
    modify_field(sr_md.mpls_top_label, mpls[3].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_6(in_classifier) {
    modify_field(sr_md.in_stack_depth, 6);
    modify_field(sr_md.mpls_top_label, mpls[4].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}
action a_in_analyze_sr_set_stack_depth_bos_7(in_classifier) {
    modify_field(sr_md.in_stack_depth, 7);
    modify_field(sr_md.mpls_top_label, mpls[5].label);
    modify_field(sr_md.mpls_service_label, mpls_bos.label);
    modify_field(sr_md.in_classifier, in_classifier);
    modify_field(sr_md.bos_tc, mpls_bos.tc);
    modify_field(sr_md.bos_ttl, mpls_bos.ttl);
    a_in_analyze_base(1);
}

table t_in_classify_l2 {
    reads {
        ig_intr_md.ingress_port : ternary;
        ethernet_outer.srcAddr : ternary;
        ethernet_outer.dstAddr : ternary;
    }
    actions {
        _nop;
        a_in_classify_l2_cls;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_l2_cls(in_classifier) {
    modify_field(l2_md.in_classifier, in_classifier);
}

table t_in_classify_cp {
    reads {
        cpu_header.valid : ternary;
        cpu_header.handling_type : ternary;
        cpu_header.reason : ternary;
    }
    actions {
        _nop;
        a_in_classify_cp_cls;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_cp_cls(in_classifier) {
    modify_field(cpu_md.in_classifier, in_classifier);
}

table t_in_classify_ipv4_dst {
    reads {
        ipv4.dstAddr : ternary;
    }
    actions {
        _nop;
        a_in_classify_ip_cls_ip_dst;
        a_in_classify_ipv4_cls_ipv4_dst;
        a_in_classify_ipv4_cls_ip_ipv4_dst;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_ip_cls_ip_dst(in_ip_classifier) {
    modify_field(ip_md.in_classifier_dst, in_ip_classifier);
}
action a_in_classify_ipv4_cls_ipv4_dst(in_ipv4_classifier) {
    modify_field(ip_md.in_ipv4_classifier_dst, in_ipv4_classifier);
}
action a_in_classify_ipv4_cls_ip_ipv4_dst(in_ip_classifier, in_ipv4_classifier) {
    modify_field(ip_md.in_classifier_dst, in_ip_classifier);
    modify_field(ip_md.in_ipv4_classifier_dst, in_ipv4_classifier);
}

table t_in_classify_ipv4_src {
    reads {
        ipv4.srcAddr : ternary;
    }
    actions {
        _nop;
        a_in_classify_ip_cls_ip_src;
        a_in_classify_ipv4_cls_ipv4_src;
        a_in_classify_ipv4_cls_ip_ipv4_src;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_ip_cls_ip_src(in_ip_classifier) {
    modify_field(ip_md.in_classifier_src, in_ip_classifier);
}
action a_in_classify_ipv4_cls_ipv4_src(in_ipv4_classifier) {
    modify_field(ip_md.in_ipv4_classifier_src, in_ipv4_classifier);
}
action a_in_classify_ipv4_cls_ip_ipv4_src(in_ip_classifier, in_ipv4_classifier) {
    modify_field(ip_md.in_classifier_src, in_ip_classifier);
    modify_field(ip_md.in_ipv4_classifier_src, in_ipv4_classifier);
}

table t_in_classify_ipv6_dst {
    reads {
        ipv6.dstAddr mask 0xffffffffffffffff0000000000000000: ternary;
    }
    actions {
        _nop;
        a_in_classify_ip_cls_ip_dst;
        a_in_classify_ipv6_cls_ipv6_dst;
        a_in_classify_ipv6_cls_ip_ipv6_dst;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_ipv6_cls_ipv6_dst(in_ipv6_classifier) {
    modify_field(ip_md.in_ipv6_classifier_dst, in_ipv6_classifier);
}
action a_in_classify_ipv6_cls_ip_ipv6_dst(in_ip_classifier, in_ipv6_classifier) {
    modify_field(ip_md.in_classifier_dst, in_ip_classifier);
    modify_field(ip_md.in_ipv6_classifier_dst, in_ipv6_classifier);
}

table t_in_classify_ipv6_src {
    reads {
        ipv6.srcAddr mask 0xffffffffffffffff0000000000000000 : ternary;
    }
    actions {
        _nop;
        a_in_classify_ip_cls_ip_src;
        a_in_classify_ipv6_cls_ipv6_src;
        a_in_classify_ipv6_cls_ip_ipv6_src;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

action a_in_classify_ipv6_cls_ipv6_src(in_ipv6_classifier) {
    modify_field(ip_md.in_ipv6_classifier_src, in_ipv6_classifier);
}
action a_in_classify_ipv6_cls_ip_ipv6_src(in_ip_classifier, in_ipv6_classifier) {
    modify_field(ip_md.in_classifier_src, in_ip_classifier);
    modify_field(ip_md.in_ipv6_classifier_src, in_ipv6_classifier);
}


table t_in_count_parser_errors {
    reads {
        ig_intr_md_from_parser_aux.ingress_parser_err : exact;
    }
    actions {
        _nop;
    }
    size : 16;
}

counter ctr_in_count_parser_errors {
    type : packets;
    direct : t_in_count_parser_errors;
}


table t_in_select_processor_fwd {
    reads {
        ig_intr_md.resubmit_flag : ternary;
        l2_md.in_classifier : ternary;
        cpu_md.in_classifier : ternary;
        sr_md.in_classifier : ternary;
        ip_md.in_classifier_dst : ternary;
        ip_md.in_classifier_src : ternary;
        ip_md.in_ipv4_classifier_dst : ternary;
        ip_md.in_ipv4_classifier_src : ternary;
        ip_md.in_ipv6_classifier_dst : ternary;
        ip_md.in_ipv6_classifier_src : ternary;
        ig_intr_md_from_parser_aux.ingress_parser_err : ternary;
    }
    actions {
        _nop;
        _drop;
        // PROCESSOR_BNG actions
        // actions are defined in processor_bng.p4
        a_in_select_processor_bng_ds_ipv4;
        a_in_select_processor_bng_ds_ipv6;
        a_in_select_processor_bng_us_ipv4;
        a_in_select_processor_bng_us_ipv6;
        a_in_select_processor_bng_us_pppoed;
        a_in_select_processor_bng_ds_pppoed;
        a_in_select_processor_bng_ds_ipv6_fromcp;
    }
    size : IN_CLASSIFY_TABLE_SIZE;
}

#ifdef DEBUG_COUNTERS

counter ctr_debug {
    type : packets;
    instance_count : 16;
}

#endif


/**************************************
 *
 * Ingress
 *
 *************************************/

// ===== t_acl_v4|6

table t_acl_ipv4 {
    reads {
        ip_md.vrf : ternary;
        ipv4.dstAddr : lpm;
        ipv4.srcAddr : ternary;
    }
    actions {
        _drop;
        _nop;
        /* TODO
        Set QoS fields
        */
        a_set_qos_ip;
        a_set_qos_se;
    }
    size : ACL_CAPACITY;
}

table t_acl_ipv6 {
    reads {
        ip_md.vrf : ternary;
        ipv6.dstAddr : lpm;
        ipv6.srcAddr : ternary;
    }
    actions {
        _drop;
        _nop;
        /* TODO
        Set QoS fields
        */
        a_set_qos_ip;
        a_set_qos_se;
    }
    size : ACL_CAPACITY;
}

action a_set_qos_for_tm(qid, packet_color) {
    modify_field(ig_intr_md_for_tm.qid, qid);
    modify_field(ig_intr_md_for_tm.packet_color, packet_color);
}

action a_set_qos_ip(phb, qid, packet_color) {
    a_set_qos_for_tm(qid, packet_color);
    modify_field(qos_md.phb, phb);
}

action a_set_qos_se(phb, qid, packet_color) {
    a_set_qos_for_tm(qid, packet_color);
    modify_field(qos_md.phb, phb);
    modify_field(sr_md.bos_tc, phb);
    modify_field(sr_md.non_bos_tc, phb);
    modify_field(pcr_bng_vlan_md.vlan_inner_pcp, phb);
    modify_field(pcr_bng_vlan_md.vlan_outer_pcp, phb);
}

table t_forward_cp {
    reads {
        pcr_bng_md.direction : ternary;
    }
    actions {
        a_pcr_bng_forward_tocp_us;
        a_pcr_bng_forward_fromcp_ds;
    }
    size : 2;
}

/**************************************
 * Downstream (Core -> Subscriber)
 *************************************/


// ===== t_forward_ipv4

table t_forward_ipv4 {
    reads {
        ip_md.vrf : exact;
        ipv4.dstAddr : lpm;
    }
    actions {
        _drop;
        a_forward_ipv4_to_cp;
        a_forward_ipv4_nexthop_sr;
        a_forward_ipv4_mcast_sr;
        a_pcr_bng_forward_ipv4_nexthop_sr_bng_ds;
    }

    size : 256;
}

action a_forward_ipv4_to_cp(mpls_service_label) {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_CP);
    modify_field(serviceedge_md.next_hop_id, NEXT_HOP_CP);
    modify_field(sr_md.mpls_service_label, mpls_service_label);
    add_to_field(ipv4.ttl, -1);
}

action a_forward_ipv4_nexthop_sr(next_hop_id, mpls_service_label) {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(serviceedge_md.next_hop_id, next_hop_id);
    modify_field(sr_md.mpls_service_label, mpls_service_label);
    add_to_field(ipv4.ttl, -1);
}

action a_forward_ipv4_mcast_sr() {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(mcast_md.is_multicast, 1);
    add_to_field(ipv4.ttl, -1);
}

// ===== t_forward_ipv6

table t_forward_ipv6 {
    reads {
        ip_md.vrf : exact;
        ipv6.dstAddr mask 0xffffffffffffffff0000000000000000: lpm;
    }
    actions {
        _drop;
        a_forward_ipv6_to_cp;
        a_forward_ipv6_nexthop_sr;
        a_forward_ipv6_mcast_sr;
        a_pcr_bng_forward_ipv6_nexthop_sr_bng_ds;
    }

    size : 256;
}

action a_forward_ipv6_to_cp() {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_CP);
    modify_field(serviceedge_md.next_hop_id, NEXT_HOP_CP);
    modify_field(cpu_md.handling_type, HANDLING_TYPE_PRC_DS_CP);
    add_to_field(ipv6.hopLimit, -1);
}

action a_forward_ipv6_nexthop_sr(next_hop_id, mpls_service_label) {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(serviceedge_md.next_hop_id, next_hop_id);
    modify_field(sr_md.mpls_service_label, mpls_service_label);
    add_to_field(ipv6.hopLimit, -1);
}

action a_forward_ipv6_mcast_sr(mpls_service_label) {
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_SR);
    modify_field(sr_md.mpls_service_label, mpls_service_label);
    add_to_field(ipv6.hopLimit, -1);
    modify_field(mcast_md.is_multicast, 1);
}

// ===== t_forward_to_sr_ttl

action a_forward_to_sr_mpls_ttl(ttl) {
    modify_field(sr_md.bos_ttl, ttl);
    modify_field(sr_md.non_bos_ttl, ttl);
}


table t_forward_to_sr_ttl_ipv4 {
    actions {
        a_forward_to_sr_ttl_ipv4;
    }
}

action a_forward_to_sr_ttl_ipv4() {
    a_forward_to_sr_mpls_ttl(ipv4.ttl);
}

table t_forward_to_sr_ttl_ipv6 {
    actions {
        a_forward_to_sr_ttl_ipv6;
    }
}

action a_forward_to_sr_ttl_ipv6() {
    a_forward_to_sr_mpls_ttl(ipv6.hopLimit);
}

table t_forward_to_sr_ttl_default {
    actions {
        a_forward_to_sr_ttl_default;
    }
}

action a_forward_to_sr_ttl_default(default_ttl) {
    a_forward_to_sr_mpls_ttl(default_ttl);
}

/**************************************
 * Multicast
 *************************************/

table t_mcast_ipv4 {
    reads {
        ipv4.srcAddr : exact;
        ipv4.dstAddr : exact;
    }
    actions {
        _nop;
        a_do_mcast;
    }
    size : 256;
}

table t_mcast_ipv6 {
    reads {
        ipv6.srcAddr : exact;
        ipv6.dstAddr : exact;
    }
    actions {
        _nop;
        a_do_mcast;
    }
    size : 256;
}

action a_do_mcast(group_id) {
    modify_field(ig_intr_md_for_tm.mcast_grp_a, group_id);
}

/*************************************************************************
 ********************** E G R E S S   T A B L E S ************************
 *************************************************************************/

table t_init_pkt_len_change {
    reads {
        serviceedge_md.in_net_proto : ternary;
        serviceedge_md.fwd_net_proto : ternary;
        serviceedge_md.out_net_proto : ternary;
        serviceedge_md.processor_ingress : ternary;
        serviceedge_md.processor_egress : ternary;
    }
    actions {
        a_init_pkt_len_nochange;
        a_init_pkt_len_increase;
        a_init_pkt_len_decrease;
    }
    size : 16;
}

action a_init_pkt_len_nochange() {
    modify_field(serviceedge_md.pkt_len_out, eg_intr_md.pkt_length);
}

action a_init_pkt_len_increase(diff) {
    add(serviceedge_md.pkt_len_out, diff, eg_intr_md.pkt_length);
}

action a_init_pkt_len_decrease(diff) {
    modify_field(serviceedge_md.pkt_len_out, eg_intr_md.pkt_length);
    modify_field(serviceedge_md.pkt_len_out_decr, diff);
}

table t_init_pkt_len_change_dec {
    actions {
        a_init_pkt_len_do_dec;
    }
}

action a_init_pkt_len_do_dec() {
    subtract_from_field(serviceedge_md.pkt_len_out, serviceedge_md.pkt_len_out_decr);
}

table t_init_mtu {
    reads {
        serviceedge_md.in_net_proto : ternary;
        serviceedge_md.fwd_net_proto : ternary;
        serviceedge_md.out_net_proto : ternary;
        mcast_md.is_multicast : ternary;
        eg_intr_md.egress_port : ternary;
        serviceedge_md.next_hop_id : ternary;
        serviceedge_md.processor_ingress : ternary;
        serviceedge_md.processor_egress : ternary;
    }
    actions {
        a_init_mtu;
    }
    size : 64;
}

action a_init_mtu(mtu) {
    // Set MTU to MTU+1 to ensure the mtu_check result is > if the
    // packet is valid.
    add_to_field(serviceedge_md.mtu_out, mtu);
}


table t_mtu_diff {
    actions {
        a_mtu_diff;
    }
}

action a_mtu_diff() {
    subtract(serviceedge_md.mtu_check,
             serviceedge_md.mtu_out,
             serviceedge_md.pkt_len_out);
}

// ===== t_srcdstmac

table t_srcdstmac {
    reads {
        eg_intr_md.egress_port : exact;
    }
    actions {
        _drop;
        _nop;
        a_srcdstmac;
    }
    size : 64;
}

action a_srcdstmac(src_mac, dst_mac) {
    modify_field(ethernet_outer.srcAddr, src_mac);
    modify_field(ethernet_outer.dstAddr, dst_mac);
#ifdef DEBUG_COUNTERS
    count(ctr_debug, 2);
#endif
}

// ===== t_next_hop

table t_next_hop {
    reads {
        serviceedge_md.next_hop_id : exact;
        serviceedge_md.out_net_proto : exact;
    }
    actions {
        _drop;
        a_next_hop_set_port;
    }
    size : 256;
}

action a_next_hop_set_port(out_port) {
    modify_field(ig_intr_md_for_tm.ucast_egress_port, out_port);
}

// ===== t_tocp_meter

meter mtr_tocp {
    type : packets;
    direct : t_tocp_meter;
    result : cpu_md.packet_color;
}

table t_tocp_meter {
    reads {
        cpu_md.meter_id : exact;
    }
    actions {
        _nop;
    }
    size : 33000;
}

// ===== t_tocp_header

table t_tocp_header {
    actions {
        a_tocp_header;
    }
}

action a_tocp_header() {
    add_header(cpu_header);
    modify_field(cpu_header.handling_type, cpu_md.handling_type);
    modify_field(cpu_header.reason, cpu_md.reason_code);
    modify_field(cpu_header.pcr_bng_access_node_id, pcr_bng_md.access_node_id);
    //modify_field(cpu_header.pcr_bng_access_node_mpls_label, pcr_bng_md.access_node_mpls_label);
    modify_field(cpu_header.pcr_bng_session_id, pcr_bng_md.session_id);
    modify_field(cpu_header.etherType, ethernet_outer.etherType);
    modify_field(ethernet_outer.etherType, ETHERTYPE_CPUHEADER);
}


// ===== t_next_hop_egress

table t_next_hop_egress {
    reads {
        serviceedge_md.next_hop_id : exact;
    }
    actions {
        _drop;
        a_next_hop_egress;
    }
    size : NEXT_HOP_CAPACITY;
}

action a_next_hop_egress(hop_nodelabel) {
    modify_field(sr_md.mpls_next_node_label, hop_nodelabel);
}

table t_next_hop_egress_postprocess {
    actions {
        a_next_hop_egress_postprocess;
    }
}

action a_next_hop_egress_postprocess() {
    modify_field(ethernet_outer.etherType, ETHERTYPE_MPLS);

    add_header(mpls_bos);
    modify_field(mpls_bos.label, sr_md.mpls_service_label);
    modify_field(mpls_bos.tc, sr_md.bos_tc);
    modify_field(mpls_bos.s, sr_md.bos_s);
    modify_field(mpls_bos.ttl, sr_md.bos_ttl);

    add_header(mpls[0]);
    modify_field(mpls[0].label, sr_md.mpls_next_node_label);
    modify_field(mpls[0].tc, sr_md.non_bos_tc);
    modify_field(mpls[0].s, sr_md.non_bos_s);
    modify_field(mpls[0].ttl, sr_md.non_bos_ttl);
}

/**************************************
 * Segment Routing Forwarding
 *************************************/

table t_sr_start {
    actions {
        _drop;
    }
}


/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/


control ingress {
#if DEBUG_UNROLL_MPLS_ANALYSIS
    apply(t_in_analyze_sr);
    if (sr_md.in_stack_depth > 0) {
        apply(t_in_classify_sr);
    }
#else
    apply(t_in_classify_sr);
#endif
    if (valid(ipv4)){
        apply(t_in_classify_ipv4_dst);
        apply(t_in_classify_ipv4_src);
    } else if (valid(ipv6)){
        apply(t_in_classify_ipv6_dst);
        apply(t_in_classify_ipv6_src);
    }
    apply(t_in_classify_l2);
    apply(t_in_classify_cp);
    apply(t_in_count_parser_errors);

    apply(t_in_select_processor_fwd);
    /*
     * At this point the in transport and the processing must be set.
     */

    // Classification and service processing selection until this point


    /************************** PROCESSORS ************************************/
    if (serviceedge_md.processor_ingress == PROCESSOR_BNG) {
        ingress_processor_bng();
        /*
         * serviceedge_md.fwd_net_proto is set in t_bng_subsc_match actions.
         */
    } else if (serviceedge_md.processor_ingress == PROCESSOR_SR_TERM) {
        // Terminate the SR transport here
    }

    /*************************** FWD ********************************/
    if (serviceedge_md.fwd_net_proto == NET_PROTO_SR) {
        // TODO: SR forwarding
        apply(t_sr_start);
    } else if (serviceedge_md.fwd_net_proto == NET_PROTO_IP) {
        // Select output port and next hop id

        if (valid(ipv4)) {
            apply(t_forward_ipv4);
            apply(t_acl_ipv4);
        } else if (valid(ipv6)) {
            apply(t_forward_ipv6);
            apply(t_acl_ipv6);
        }

        if (mcast_md.is_multicast==TRUE) {
            if (valid(ipv4)) {
                apply(t_mcast_ipv4);
            } else if (valid(ipv6)) {
                apply(t_mcast_ipv6);
            }
        } 
    } else if (serviceedge_md.fwd_net_proto == NET_PROTO_CP) {
        apply(t_forward_cp);
    }

    if (mcast_md.is_multicast==FALSE) {
        apply(t_next_hop);
    }

    // Add ECMP here if needed
    /*
     * At this point the out transport must be set or the packet must be 
     * dropped by the ACL.
     * IMPORTANT: Drop packets that are too large for PPPoE here.
     *            Dropping them after duplication is not efficient.
     */
    process_ingress_system_acl();
}

/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

control egress {
    if (eg_intr_md_from_parser_aux.clone_src == NOT_CLONED) {
        apply(t_init_pkt_len_change);
        apply(t_init_pkt_len_change_dec);

        if (serviceedge_md.out_net_proto == NET_PROTO_SR and
            serviceedge_md.fwd_net_proto != NET_PROTO_SR) {
            if (valid(ipv4)) {
                apply(t_forward_to_sr_ttl_ipv4);
            } else if (valid(ipv6)) {
                apply(t_forward_to_sr_ttl_ipv6);
            } else {
                apply(t_forward_to_sr_ttl_default);
            }
        }

        /******************* PROCESSORS **************************************/
        if (serviceedge_md.processor_egress == PROCESSOR_BNG) {
            egress_processor_bng();
        }

        apply(t_init_mtu);
        apply(t_mtu_diff);
    }

    /******************* OUT TRANSPORT **********************************/
    if (serviceedge_md.out_net_proto == NET_PROTO_SR) {
        apply(t_next_hop_egress);
        apply(t_next_hop_egress_postprocess);
        // Add ECMP handling if required
    } else if (serviceedge_md.out_net_proto == NET_PROTO_IP) {
        // Handle link local traffic here
    } else if (serviceedge_md.out_net_proto == NET_PROTO_CP) {
            // Add CP header as needed by the CP software
        apply(t_tocp_meter);
        apply(t_tocp_header);
    }
    apply(t_srcdstmac);

    /********************** MTU/ACL_CHECK *******************************/
    process_egress_system_acl();
}


