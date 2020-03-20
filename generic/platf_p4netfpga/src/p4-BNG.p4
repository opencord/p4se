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


#include <core.p4>
#include <sume_switch.p4>
#include "header_16.p4"


//#define ENABLE_COUNTERS  //counters are currently not supported
//#define ENABLE_DS_METERS  //meters are currently not supported by netfpga
//#define ENABLE_IPV6

#define TYPE_DS 0x0
#define TYPE_US 0x1
#define TYPE_INVALID 0x2

#define SUBSC_CAPACITY 4096
#define NET_CAPACITY 3*SUBSC_CAPACITY
#define ROUTE_CAPACITY 256

#define NUM_OF_CPS 64


struct metadata {
    ingress_md_t         ingress_md;
}

struct headers {
    bng_cp_t   bng_cp;
    ethernet_t ethernet_inner;
    ethernet_t ethernet_outer;
    ipv4_t     ipv4;
    ipv6_t     ipv6;
    mpls_t     mpls0;
    mpls_t     mpls1;
    pppoe_t    pppoe;
    vlan_t     vlan_service;
    vlan_t     vlan_subsc;
}
struct digest_data_t {
    bit<32> foobar; //not used
}
#define mpls_0_accesslabels 0x80001
// Parser Implementation
@Xilinx_MaxPacketRegion(16384)
parser TopParser(packet_in packet, //packet - b
                 out headers hdr, //hdr - p
                 out metadata meta, //meta - user_metadata
                 out digest_data_t digest_data,
                 inout sume_metadata_t sume_metadata) { //standard metatdata
    //value_set<bit<20>>(4) mpls_0_accesslabels; //currently not supported by P4NetFPGA compiler. workaround by hard coded in P4
    state parse_above_mpls {
        transition select(hdr.mpls0.label) {
            mpls_0_accesslabels: parse_ethernet_inner;
            //TODO: add further access labes here or replace by P4 parser value set, if supported by hardware
            default: parse_ip;
        }
    }
    state parse_bng_cp {
        packet.extract(hdr.bng_cp);
        transition accept;
    }
    state parse_ethernet_inner {
        packet.extract(hdr.ethernet_inner);
        transition select(hdr.ethernet_inner.etherType) {
            ETHERTYPE_VLAN: parse_vlan_subsc;
            default: accept;
        }
    }
    state parse_ethernet_outer {
        packet.extract(hdr.ethernet_outer);
        transition select(hdr.ethernet_outer.etherType) {
            ETHERTYPE_MPLS: parse_mpls0;
            ETHERTYPE_CP: parse_bng_cp;
            default: accept;
        }
    }
    state parse_ip {
        transition select((packet.lookahead<bit<4>>())[3:0]) {
            4w4: parse_ipv4;
            4w6: parse_ipv6;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition accept;
    }
    state parse_mpls0 {
        packet.extract(hdr.mpls0);
        transition select(hdr.mpls0.s) {
            1w1: accept;
            default: parse_mpls1;
        }
    }
    state parse_mpls1 {
        packet.extract(hdr.mpls1);
        transition select(hdr.mpls1.s) {
            1w1: parse_above_mpls;
            default: accept;
        }
    }
    state parse_pppoe {
        packet.extract(hdr.pppoe);
        transition select(hdr.pppoe.protocol) {
            PPPOE_PROTOCOL_IP4: parse_ip;
            PPPOE_PROTOCOL_IP6: parse_ip;
            default: accept;
        }
    }
    state parse_vlan_service {
        packet.extract(hdr.vlan_service);
        transition select(hdr.vlan_service.etherType) {
            ETHERTYPE_PPPOED: parse_pppoe;
            ETHERTYPE_PPPOES: parse_pppoe;
            default: accept;
        }
    }
    state parse_vlan_subsc {
        packet.extract(hdr.vlan_subsc);
        transition select(hdr.vlan_subsc.etherType) {
            ETHERTYPE_VLAN: parse_vlan_service;
            ETHERTYPE_PPPOED: parse_pppoe;
            ETHERTYPE_PPPOES: parse_pppoe;
            default: accept;
        }
    }
    state start {
        transition parse_ethernet_outer;
    }
}

// match-action pipeline
control TopPipe(inout headers hdr,
                inout metadata meta, 
                inout digest_data_t digest_data, 
                inout sume_metadata_t sume_metadata) {

   action a_bng_output() {
        hdr.ethernet_outer.dstAddr = hdr.bng_cp.eth_dstAddr;
        hdr.ethernet_outer.srcAddr = hdr.bng_cp.eth_srcAddr;
        hdr.ethernet_outer.etherType = hdr.bng_cp.eth_etherType;
        sume_metadata.dst_port = (bit<8>)hdr.bng_cp.fwd_port;
        meta.ingress_md.cp = 1w1;
        hdr.bng_cp.setInvalid();
    }
    action action_drop() {
        sume_metadata.drop = 1;
    }
    action a_bng_tocp(bit<48> ourOuterMAC, bit<48> remoteOuterMAC, bit<8> cpPhysicalPort) {
        hdr.bng_cp.setValid();
        hdr.bng_cp.eth_dstAddr = hdr.ethernet_outer.dstAddr;
        hdr.bng_cp.eth_srcAddr = hdr.ethernet_outer.srcAddr;
        hdr.bng_cp.eth_etherType = hdr.ethernet_outer.etherType;
        hdr.bng_cp.fwd_port = (bit<32>)sume_metadata.src_port;
        hdr.ethernet_outer.dstAddr = remoteOuterMAC;
        hdr.ethernet_outer.srcAddr = ourOuterMAC;
        hdr.ethernet_outer.etherType = ETHERTYPE_CP;
        sume_metadata.dst_port = cpPhysicalPort;
    }
    action a_cptap_cp() {
        meta.ingress_md.cp = 1w1;
    }
    action a_cptap_dp() {
    }
    action a_usds_handle_ds() {
        meta.ingress_md.usds = 2w0x0;
    }
    action a_usds_handle_us() {
        hdr.vlan_service.setValid();
        meta.ingress_md.usds = 2w0x1;
    }
    action mark_to_drop() {
        meta.ingress_md.usds = 2w0x2;
    }
    table t_bng_fromcp {
        actions = {
            a_bng_output;
            action_drop;
        }
        key = {
            hdr.ethernet_outer.dstAddr    : exact;
            hdr.ethernet_outer.srcAddr    : exact;
            sume_metadata.src_port        : exact;
        }
        size = NUM_OF_CPS;
    }
    table t_bng_tocp {
        actions = {
            a_bng_tocp;
        }
        key = {
            sume_metadata.src_port: exact;
        }
        size = NUM_OF_CPS;
    }
    table t_cptap_outer_ethernet {
        actions = {
            a_cptap_cp;
            a_cptap_dp;
        }
        key = {
            hdr.ethernet_outer.dstAddr  : exact;
            hdr.ethernet_outer.etherType: exact;
        }
        size = 64;
    }
    table t_usds {
        actions = {
            a_usds_handle_ds;
            a_usds_handle_us;
            mark_to_drop;
        }
        key = {
            hdr.ethernet_outer.dstAddr    : exact;
            sume_metadata.src_port        : exact;
            hdr.mpls0.label               : exact;
        }
        size = 256;
    }
///// from ingress downstream
    #ifdef ENABLE_COUNTERS
    counter(32w8192, CounterType.packets) ctr_ds_subsc;
    #endif

    #ifdef ENABLE_DS_METERS
    meter(32w8192, MeterType.bytes) mtr_ds_besteff;
    meter(32w8192, MeterType.bytes) mtr_ds_prio;
    action a_ds_acl_qos_prio() {
        mtr_ds_prio.execute_meter((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket, meta.ingress_md.meter_result);
        #ifdef ENABLE_COUNTERS
        ctr_ds_subsc.count((bit<32>)meta.ingress_md.ctr_bucket);
        #endif
    }
    action a_ds_acl_qos_besteff() {
        mtr_ds_besteff.execute_meter((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket, meta.ingress_md.meter_result);
        #ifdef ENABLE_COUNTERS
        ctr_ds_subsc.count((bit<32>)meta.ingress_md.ctr_bucket);
        #endif
    }
    table t_ds_acl_qos_v4 {
        actions = {
            a_ds_acl_qos_prio;
            a_ds_acl_qos_besteff;
            mark_to_drop;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv4.diffserv      : ternary;
            hdr.ipv4.srcAddr       : lpm;
        }
        size = 64;
    }
    table t_ds_acl_qos_v6 {
        actions = {
            a_ds_acl_qos_prio;
            a_ds_acl_qos_besteff;
            mark_to_drop;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv6.trafficClass  : ternary;
            hdr.ipv6.srcAddr       : ternary;
        }
        size = 64;
    }
    #endif


    action a_ds_route_tocp() {
        meta.ingress_md.cp = 1w1;
    }
    action a_ds_route_pushstack(bit<20> mpls0_label, bit<20> mpls1_label, bit<16> subsc_vid, bit<16> service_vid, bit<16> pppoe_session_id, bit<8> out_port, bit<48> inner_cpe_mac, bit<16> ctr_bucket) {
        hdr.mpls0.label = mpls0_label;
        hdr.mpls1.label = mpls1_label;
        hdr.ethernet_inner.setValid();
        hdr.ethernet_inner.dstAddr = inner_cpe_mac;
        hdr.ethernet_inner.etherType = ETHERTYPE_VLAN;
        hdr.vlan_subsc.setValid();
        hdr.vlan_subsc.vlanID = subsc_vid;
        hdr.vlan_subsc.etherType = ETHERTYPE_VLAN;
        hdr.vlan_service.setValid();
        hdr.vlan_service.vlanID = service_vid;
        hdr.vlan_service.etherType = ETHERTYPE_PPPOES;
        hdr.pppoe.setValid();
        hdr.pppoe.version = 4w1;
        hdr.pppoe.typeID = 4w1;
        hdr.pppoe.sessionID = pppoe_session_id;
        sume_metadata.dst_port = out_port;
        meta.ingress_md.ctr_bucket = ctr_bucket;
    }
    action a_ds_route_nextpm() {
    }
    table t_ds_routev4 {
        actions = {
            mark_to_drop;
            a_ds_route_pushstack;
            a_ds_route_tocp;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = SUBSC_CAPACITY;
    }
    #ifdef ENABLE_IPV6
    table t_ds_routev6_0 {
        actions = {
            a_ds_route_pushstack;
            a_ds_route_nextpm;
            a_ds_route_tocp;
        }
        key = {
            hdr.ipv6.dstAddr[127:64]: exact @name("ipv6.dstAddr") ;
        }
        size = NET_CAPACITY;
    }
    table t_ds_routev6_1 {
        actions = {
            a_ds_route_pushstack;
            a_ds_route_tocp;
            mark_to_drop;
        }
        key = {
            hdr.ipv6.dstAddr[127:72]: exact @name("ipv6.dstAddr") ;
        }
        size = NET_CAPACITY;
    }
    #endif

///From ingress upstream:
    #ifdef ENABLE_COUNTERS
    counter(32w8192, CounterType.packets) ctr_us_subsc;
    #endif
    action a_antispoof_ipv4v6_pass() {
        hdr.pppoe.setInvalid();
        hdr.vlan_subsc.setInvalid();
        hdr.ethernet_inner.setInvalid();
    }
    action a_antispoof_ipv4v6_nextpm() {}
    action a_antispoof_mac_pass(bit<8> subsc_id, bit<32> ctr_bucket) {
        meta.ingress_md.subsc_id = subsc_id;
        #ifdef ENABLE_COUNTERS
        ctr_us_subsc.count((bit<32>)ctr_bucket);
        #endif
    }
    action a_line_map_pass(bit<32> line_id) {
        meta.ingress_md.line_id = line_id;
    }
    action a_pppoe_cpdp_to_cp() {
        meta.ingress_md.cp = 1w1;
    }
    action a_pppoe_cpdp_pass_ip() {
    }
    action a_us_routev4v6_tocp() {
        meta.ingress_md.cp = 1w1;
    }
    action a_us_routev4v6(bit<8> out_port, bit<20> mpls0_label, bit<20> mpls1_label, bit<48> via_hwaddr) {
        hdr.vlan_service.setInvalid();
        sume_metadata.dst_port = out_port;
        hdr.mpls0.label = mpls0_label;
        hdr.mpls1.label = mpls1_label;
        hdr.ethernet_outer.dstAddr = via_hwaddr;
    }
    table t_antispoof_ipv4 {
        actions = {
            mark_to_drop;
            a_antispoof_ipv4v6_pass;
        }
        key = {
            hdr.ipv4.srcAddr        : exact;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = SUBSC_CAPACITY;
    }
    #ifdef ENABLE_IPV6
    table t_antispoof_ipv6_0 {
        actions = {
            a_antispoof_ipv4v6_pass;
            a_antispoof_ipv4v6_nextpm;
        }
        key = {
            hdr.ipv6.srcAddr[127:64]: exact @name("ipv6.srcAddr") ;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = NET_CAPACITY;
    }
    table t_antispoof_ipv6_1 {
        actions = {
            mark_to_drop;
            a_antispoof_ipv4v6_pass;
        }
        key = {
            hdr.ipv6.srcAddr[127:72]: exact @name("ipv6.srcAddr") ;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = NET_CAPACITY;
    }
    #endif


    table t_antispoof_mac {
        actions = {
            mark_to_drop;
            a_antispoof_mac_pass;
        }
        key = {
            meta.ingress_md.line_id   : exact;
            hdr.vlan_service.vlanID   : exact;
            hdr.ethernet_inner.srcAddr: exact;
            hdr.pppoe.sessionID       : exact;
        }
        size = SUBSC_CAPACITY;
    }
    table t_line_map {
        actions = {
            mark_to_drop;
            a_line_map_pass;
        }
        key = {
            sume_metadata.src_port        : exact;
            hdr.mpls0.label               : exact;
            hdr.mpls1.label               : exact;
            hdr.vlan_subsc.vlanID         : exact;
        }
        size = SUBSC_CAPACITY;
    }
    table t_pppoe_cpdp {
        actions = {
            mark_to_drop;
            a_pppoe_cpdp_to_cp;
            a_pppoe_cpdp_pass_ip;
        }
        key = {
            hdr.ethernet_inner.dstAddr: exact;
            hdr.vlan_service.etherType: exact;
            hdr.pppoe.protocol        : exact;
        }
        size = NUM_OF_CPS;
    }
    table t_us_routev4 {
        actions = {
            mark_to_drop;
            a_us_routev4v6;
            a_us_routev4v6_tocp;
        }
        key = {
            hdr.vlan_service.vlanID: exact; 
        }
        size = ROUTE_CAPACITY;
    }

    #ifdef ENABLE_IPV6
    table t_us_routev6 {
        actions = {
            mark_to_drop;
            a_us_routev4v6;
            a_us_routev4v6_tocp;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv6.dstAddr       : exact; // lpm - not supported in SDNet for tables with multiple inputs
        }
        size = ROUTE_CAPACITY;
    }
    #endif

////////////////////// from egress pipeline /////////////////////////////////
    action a_ds_pppoe_aftermath_v4() {
        hdr.pppoe.totalLength = hdr.ipv4.totalLen + 16w2;
        hdr.pppoe.protocol = 16w0x21;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    action a_ds_srcmac(bit<48> outer_src_mac, bit<48> outer_dst_mac, bit<48> inner_src_mac) {
        hdr.ethernet_outer.srcAddr = outer_src_mac;
        hdr.ethernet_outer.dstAddr = outer_dst_mac;
        hdr.ethernet_inner.srcAddr = inner_src_mac;
    }
    action no_op() {
    }
    action a_us_srcmac(bit<48> src_mac) {
        hdr.ethernet_outer.srcAddr = src_mac;
    }
    #ifdef ENABLE_IPV6
    action a_ds_pppoe_aftermath_v6() {
        hdr.pppoe.totalLength = hdr.ipv6.payloadLen + 16w42;
        hdr.pppoe.protocol = 16w0x57;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit + 8w255;
    }
    table t_ds_pppoe_aftermath_v6 {
        actions = {
            a_ds_pppoe_aftermath_v6;
        }
    }
    #endif
    table t_ds_srcmac {
        actions = {
            mark_to_drop;
            a_ds_srcmac;
        }
        key = {
            sume_metadata.dst_port       : exact;
            hdr.mpls0.label              : exact;
        }
        size = 256;
    }
    table t_us_srcmac {
        actions = {
            no_op;
            a_us_srcmac;
        }
        key = {
            sume_metadata.dst_port       : exact;
            hdr.mpls0.label              : exact;
        }
    }


/////////////////////////////////////////////////////////////////////////////
//////////////// Controll Flow Description starts here //////////////////////
/////////////////////////////////////////////////////////////////////////////
    apply {
        if (hdr.bng_cp.isValid()) {
            t_bng_fromcp.apply();
        }
        else {
            t_cptap_outer_ethernet.apply();
            if (meta.ingress_md.cp == 1w0) {
                t_usds.apply();
                if (meta.ingress_md.usds == 2w0x1 && hdr.pppoe.isValid()) {
			t_line_map.apply();
			t_pppoe_cpdp.apply();
			if (meta.ingress_md.cp == 1w0) {
			    t_antispoof_mac.apply();
			    if (hdr.ipv4.isValid()) {
				t_antispoof_ipv4.apply();
				if (meta.ingress_md.usds == 2w0x1) {
				    if (hdr.ipv4.ttl <= 8w1) {
				        a_us_routev4v6_tocp();
				    }
				    t_us_routev4.apply();
				}
			    }
			    #ifdef ENABLE_IPV6
			    else {
				if (hdr.ipv6.isValid()) {
				    switch (t_antispoof_ipv6_0.apply().action_run) {
				        a_antispoof_ipv4v6_nextpm: {
				            t_antispoof_ipv6_1.apply();
				        }
				    }

				    if (meta.ingress_md.usds == 2w0x1) {
				        if (hdr.ipv6.hopLimit <= 8w1) {
				            a_us_routev4v6_tocp();
				        }
				        t_us_routev6.apply();
				    }
				}
			    }
			    #endif
			}
                }
                else {
                    if (meta.ingress_md.usds == 2w0x0) {
			if (hdr.ipv4.isValid()) {
			    if (hdr.ipv4.ttl <= 8w1) {
				a_ds_route_tocp();
			    }
			    t_ds_routev4.apply();
			    #ifdef ENABLE_DS_METERS
			    if (meta.ingress_md.usds == 2w0x0) {
				t_ds_acl_qos_v4.apply();
			    }
			    #endif

			}
			#ifdef ENABLE_IPV6
			else {
			    if (hdr.ipv6.isValid()) {
				if (hdr.ipv6.hopLimit <= 8w1) {
				    a_ds_route_tocp();
				}
				switch (t_ds_routev6_0.apply().action_run) {
				    a_ds_route_nextpm: {
				        t_ds_routev6_1.apply();
				    }
				}
				#ifdef ENABLE_DS_METERS
				if (meta.ingress_md.usds == 2w0x0) {
				    t_ds_acl_qos_v6.apply();
				}
				#endif
			    }
			}
			#endif
                    }
                }
            }
            if (meta.ingress_md.cp == 1w1) {
                t_bng_tocp.apply();
            }
        }
        //P4_14 egress pipe starts here
        if (meta.ingress_md.cp == 1w0) {
            if (meta.ingress_md.usds == 2w0x1) {
                t_us_srcmac.apply();
            }
            if (meta.ingress_md.usds == 2w0x0) {
                if (hdr.ipv4.isValid()) {
                    a_ds_pppoe_aftermath_v4();
                }
                else {
                    #ifdef ENABLE_IPV6
                    t_ds_pppoe_aftermath_v6.apply();
                    #endif
                }
                t_ds_srcmac.apply();
            }
            else {
                mark_to_drop();
            }
        }
    }
}


// Deparser Implementation
@Xilinx_MaxPacketRegion(16384)
control TopDeparser(packet_out packet,
                    in headers hdr,
                    in metadata meta,
                    inout digest_data_t digest_data, 
                    inout sume_metadata_t sume_metadata) { 
    apply {
        packet.emit(hdr.ethernet_outer);
        packet.emit(hdr.bng_cp);
        packet.emit(hdr.mpls0);
        packet.emit(hdr.mpls1);
        packet.emit(hdr.ethernet_inner);
        packet.emit(hdr.vlan_subsc);
        packet.emit(hdr.vlan_service);
        packet.emit(hdr.pppoe);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv4);
    }
}


// Instantiate the SimpleSumeSwitch
SimpleSumeSwitch(TopParser(), TopPipe(), TopDeparser()) main;

