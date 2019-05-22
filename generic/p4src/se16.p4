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

// P4_16 implementation of se.p4

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_PPPOED 0x8863
#define ETHERTYPE_PPPOES 0x8864
#define ETHERTYPE_MPLS 0x8847

// A (remote) CP packet that must be forwarded on a specific port.
#define ETHERTYPE_CP 0x8765

#define PPPOE_PROTOCOL_IP4 0x0021
#define PPPOE_PROTOCOL_IP6 0x0057

#define TYPE_DS 2w0x0
#define TYPE_US 2w0x1
#define TYPE_INVALID 2w0x2

#define SUBSC_CAPACITY 8192
#define NET_CAPACITY 4*SUBSC_CAPACITY
#define ROUTE_CAPACITY 256

#include <core.p4>
#include <v1model.p4>

struct ingress_md_t {
    bit<2>  usds;
    bit<1>  cp;
    bit<32> line_id;
    bit<8>  subsc_id;
    bit<16> ctr_bucket;
    bit<32> meter_result;
}

struct intrinsic_metadata_t {
    bit<48> ingress_global_timestamp;
    bit<32> lf_field_list;
    bit<16> mcast_grp;
    bit<16> egress_rid;
}

header bng_cp_t {
    bit<16> stamp;
    bit<32> fwd_port;
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
    bit<16> protocol;
}

header vlan_t {
    bit<16> vlanID;
    bit<16> etherType;
}

struct metadata {
    ingress_md_t ingress_md;
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

parser ParserImpl(
    packet_in packet,
    out headers hdr,
    inout metadata meta,
    inout standard_metadata_t standard_metadata) {

    value_set<bit<20>>(4) mpls_0_accesslabels;

    state start {
        transition parse_ethernet_outer;
    }

    state parse_ethernet_outer {
        packet.extract(hdr.ethernet_outer);
        transition select(hdr.ethernet_outer.etherType) {
            ETHERTYPE_MPLS: parse_mpls0;
            ETHERTYPE_CP: parse_bng_cp;
            default: accept;
        }
    }

    state parse_bng_cp {
        packet.extract(hdr.bng_cp);
        transition accept;
    }

    state parse_mpls0 {
        packet.extract(hdr.mpls0);
        transition select(hdr.mpls0.s) { // BOS
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

    state parse_above_mpls {
        transition select(hdr.mpls0.label) {
            mpls_0_accesslabels: parse_ethernet_inner;
            default: parse_ip;
        }
    }


    state parse_ethernet_inner {
        packet.extract(hdr.ethernet_inner);
        transition select(hdr.ethernet_inner.etherType) {
            ETHERTYPE_VLAN: parse_vlan_subsc;
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

    state parse_vlan_service {
        packet.extract(hdr.vlan_service);
        transition select(hdr.vlan_service.etherType) {
            ETHERTYPE_PPPOED: parse_pppoe;
            ETHERTYPE_PPPOES: parse_pppoe;
            default: accept;
        }
    }

    state parse_pppoe {
        packet.extract(hdr.pppoe);
        transition select(hdr.pppoe.protocol) {
            PPPOE_PROTOCOL_IP4: parse_ipv4;
            PPPOE_PROTOCOL_IP6: parse_ipv6;
            default: accept;
        }
    }

    state parse_ip {
        // Look at the first 4 bits for the version number, assumming it's an
        // IPv4 or IPv6 header.
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
}

counter(SUBSC_CAPACITY, CounterType.packets) ctr_us_subsc;

control ingress_upstream(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _mark_drop() {
        meta.ingress_md.usds = TYPE_INVALID;
    }

    action a_antispoof_ipv4v6_pass() {
        hdr.pppoe.setInvalid();
        hdr.vlan_subsc.setInvalid();
        hdr.ethernet_inner.setInvalid();
    }

    action a_antispoof_ipv4v6_nextpm() {
    }

    action a_antispoof_mac_pass(bit<8> subsc_id, bit<32> ctr_bucket) {
        meta.ingress_md.subsc_id = subsc_id;
        ctr_us_subsc.count((bit<32>)ctr_bucket);
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

    action a_us_routev4v6(bit<9> out_port, bit<20> mpls0_label, bit<20> mpls1_label, bit<48> via_hwaddr) {
        hdr.vlan_service.setInvalid();
        standard_metadata.egress_spec = out_port;
        hdr.mpls0.label = mpls0_label;
        hdr.mpls1.label = mpls1_label;
        hdr.ethernet_outer.dstAddr = via_hwaddr;
    }

    table t_antispoof_ipv4 {
        actions = {
            _mark_drop;
            a_antispoof_ipv4v6_pass;
        }
        key = {
            hdr.ipv4.srcAddr        : exact;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = NET_CAPACITY;
    }

    table t_antispoof_ipv6_0 {
        actions = {
            a_antispoof_ipv4v6_pass;
            a_antispoof_ipv4v6_nextpm;
        }
        key = {
            hdr.ipv6.srcAddr[127:64]: exact;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = NET_CAPACITY;
    }

    table t_antispoof_ipv6_1 {
        actions = {
            _mark_drop;
            a_antispoof_ipv4v6_pass;
        }
        key = {
            hdr.ipv6.srcAddr[127:72]: exact;
            meta.ingress_md.line_id : exact;
            meta.ingress_md.subsc_id: exact;
        }
        size = NET_CAPACITY;
    }

    table t_antispoof_mac {
        actions = {
            _mark_drop;
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
            _mark_drop;
            a_line_map_pass;
        }
        key = {
            standard_metadata.ingress_port: exact;
            hdr.mpls0.label               : exact;
            hdr.mpls1.label               : exact;
            hdr.vlan_subsc.vlanID         : exact;
        }
        size = SUBSC_CAPACITY;
    }

    table t_pppoe_cpdp {
        actions = {
            _mark_drop;
            a_pppoe_cpdp_to_cp;
            a_pppoe_cpdp_pass_ip;
        }
        key = {
            hdr.ethernet_inner.dstAddr: exact;
            hdr.vlan_service.etherType: exact;
            hdr.pppoe.protocol        : exact;
        }
        size = 16;
    }

    table t_us_expiredv4 {
        actions = {
            a_us_routev4v6_tocp;
        }
        size = 1;
    }

    table t_us_expiredv6 {
        actions = {
            a_us_routev4v6_tocp;
        }
        size = 1;
    }

    table t_us_routev4 {
        actions = {
            _mark_drop;
            a_us_routev4v6;
            a_us_routev4v6_tocp;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv4.dstAddr       : lpm;
        }
        size = 256;
    }

    table t_us_routev6 {
        actions = {
            _mark_drop;
            a_us_routev4v6;
            a_us_routev4v6_tocp;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv6.dstAddr       : lpm;
        }
        size = 256;
    }
    apply {
        t_line_map.apply();
        t_pppoe_cpdp.apply();
        if (meta.ingress_md.cp == 1w0) {
            t_antispoof_mac.apply();
            if (hdr.ipv4.isValid()) {
                t_antispoof_ipv4.apply();
                if (meta.ingress_md.usds == TYPE_US) {
                    if (hdr.ipv4.ttl <= 8w1) {
                        t_us_expiredv4.apply();
                    }
                    t_us_routev4.apply();
                }
            }
            else {
                if (hdr.ipv6.isValid()) {
                    switch (t_antispoof_ipv6_0.apply().action_run) {
                        a_antispoof_ipv4v6_nextpm: {
                            t_antispoof_ipv6_1.apply();
                        }
                    }

                    if (meta.ingress_md.usds == TYPE_US) {
                        if (hdr.ipv6.hopLimit <= 8w1) {
                            t_us_expiredv6.apply();
                        }
                        t_us_routev6.apply();
                    }
                }
            }
        }
    }
}

counter(SUBSC_CAPACITY, CounterType.packets) ctr_ds_subsc;

meter(SUBSC_CAPACITY, MeterType.bytes) mtr_ds_besteff;

meter(SUBSC_CAPACITY, MeterType.bytes) mtr_ds_prio;

control ingress_downstream(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action a_ds_acl_qos_prio() {
        mtr_ds_prio.execute_meter((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket, meta.ingress_md.meter_result);
        ctr_ds_subsc.count((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket);
    }

    action a_ds_acl_qos_besteff() {
        mtr_ds_besteff.execute_meter((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket, meta.ingress_md.meter_result);
        ctr_ds_subsc.count((bit<32>)(bit<32>)meta.ingress_md.ctr_bucket);
    }

    action _mark_drop() {
        meta.ingress_md.usds = TYPE_INVALID;
    }

    action a_ds_route_tocp() {
        meta.ingress_md.cp = 1w1;
    }

    action a_ds_route_pushstack(
            bit<20> mpls0_label,
            bit<20> mpls1_label,
            bit<16> subsc_vid,
            bit<16> service_vid,
            bit<16> pppoe_session_id,
            bit<9> out_port,
            bit<48> inner_cpe_mac,
            bit<16> ctr_bucket) {

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
        standard_metadata.egress_spec = out_port;
        meta.ingress_md.ctr_bucket = ctr_bucket;
    }

    action a_ds_route_nextpm() {
    }

    table t_ds_acl_qos_v4 {
        actions = {
            a_ds_acl_qos_prio;
            a_ds_acl_qos_besteff;
            _mark_drop;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv4.diffserv      : ternary;
            hdr.ipv4.srcAddr       : lpm;
        }
        size = 32;
    }

    table t_ds_acl_qos_v6 {
        actions = {
            a_ds_acl_qos_prio;
            a_ds_acl_qos_besteff;
            _mark_drop;
        }
        key = {
            hdr.vlan_service.vlanID: exact;
            hdr.ipv6.trafficClass  : ternary;
            hdr.ipv6.srcAddr       : ternary;
        }
        size = 32;
    }

    table t_ds_expiredv4 {
        actions = {
            a_ds_route_tocp;
        }
        size = 1;
    }

    table t_ds_expiredv6 {
        actions = {
            a_ds_route_tocp;
        }
        size = 1;
    }

    table t_ds_routev4 {
        actions = {
            _mark_drop;
            a_ds_route_pushstack;
            a_ds_route_tocp;
        }
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        size = NET_CAPACITY;
    }

    table t_ds_routev6_0 {
        actions = {
            a_ds_route_pushstack;
            a_ds_route_nextpm;
            a_ds_route_tocp;
        }
        key = {
            hdr.ipv6.dstAddr[127:64]: exact;
        }
        size = NET_CAPACITY;
    }

    table t_ds_routev6_1 {
        actions = {
            a_ds_route_pushstack;
            a_ds_route_tocp;
            _mark_drop;
        }
        key = {
            hdr.ipv6.dstAddr[127:72]: exact;
        }
        size = NET_CAPACITY;
    }
    apply {
        if (hdr.ipv4.isValid()) {
            if (hdr.ipv4.ttl <= 8w1) {
                t_ds_expiredv4.apply();
            }
            t_ds_routev4.apply();
            if (meta.ingress_md.usds == 2w0x0) {
                t_ds_acl_qos_v4.apply();
            }
        }
        else {
            if (hdr.ipv6.isValid()) {
                if (hdr.ipv6.hopLimit <= 8w1) {
                    t_ds_expiredv6.apply();
                }
                switch (t_ds_routev6_0.apply().action_run) {
                    a_ds_route_nextpm: {
                        t_ds_routev6_1.apply();
                    }
                }

                if (meta.ingress_md.usds == 2w0x0) {
                    t_ds_acl_qos_v6.apply();
                }
            }
        }
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action a_bng_output() {
        hdr.ethernet_outer.dstAddr = hdr.bng_cp.eth_dstAddr;
        hdr.ethernet_outer.srcAddr = hdr.bng_cp.eth_srcAddr;
        hdr.ethernet_outer.etherType = hdr.bng_cp.eth_etherType;
        standard_metadata.egress_spec = (bit<9>)hdr.bng_cp.fwd_port;
        meta.ingress_md.cp = 1w1;
        hdr.bng_cp.setInvalid();
    }

    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action a_bng_tocp(bit<48> ourOuterMAC, bit<48> remoteOuterMAC, bit<9> cpPhysicalPort) {
        hdr.bng_cp.setValid();
        hdr.bng_cp.eth_dstAddr = hdr.ethernet_outer.dstAddr;
        hdr.bng_cp.eth_srcAddr = hdr.ethernet_outer.srcAddr;
        hdr.bng_cp.eth_etherType = hdr.ethernet_outer.etherType;
        hdr.bng_cp.fwd_port = (bit<32>)standard_metadata.ingress_port;
        hdr.ethernet_outer.dstAddr = remoteOuterMAC;
        hdr.ethernet_outer.srcAddr = ourOuterMAC;
        hdr.ethernet_outer.etherType = ETHERTYPE_CP;
        standard_metadata.egress_spec = cpPhysicalPort;
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
        meta.ingress_md.usds = TYPE_US;
    }

    action _mark_drop() {
        meta.ingress_md.usds = TYPE_INVALID;
    }

    table t_bng_fromcp {
        actions = {
            a_bng_output;
            _drop;
        }
        key = {
            hdr.ethernet_outer.dstAddr    : exact;
            hdr.ethernet_outer.srcAddr    : exact;
            standard_metadata.ingress_port: exact;
        }
        size = 16;
    }

    table t_bng_tocp {
        actions = {
            a_bng_tocp;
        }
        key = {
            standard_metadata.ingress_port: exact;
        }
        size = 16;
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
        size = 32;
    }

    table t_usds {
        actions = {
            a_usds_handle_ds;
            a_usds_handle_us;
            _mark_drop;
        }
        key = {
            hdr.ethernet_outer.dstAddr    : exact;
            standard_metadata.ingress_port: exact;
            hdr.mpls0.label               : exact;
        }
        size = ROUTE_CAPACITY;
    }

    ingress_upstream() ingress_upstream_0;
    ingress_downstream() ingress_downstream_0;

    apply {
        if (hdr.bng_cp.isValid()) {
            t_bng_fromcp.apply();
        }
        else {
            t_cptap_outer_ethernet.apply();
            if (meta.ingress_md.cp == 1w0) {
                t_usds.apply();
                if (meta.ingress_md.usds == TYPE_US && hdr.pppoe.isValid()) {
                    ingress_upstream_0.apply(hdr, meta, standard_metadata);
                }
                else {
                    if (meta.ingress_md.usds == TYPE_DS) {
                        ingress_downstream_0.apply(hdr, meta, standard_metadata);
                    }
                }
            }
            if (meta.ingress_md.cp == 1w1) {
                t_bng_tocp.apply();
            }
        }
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action _drop() {
        mark_to_drop(standard_metadata);
    }

    action a_ds_pppoe_aftermath_v4() {
        hdr.pppoe.totalLength = hdr.ipv4.totalLen + 16w2;
        hdr.pppoe.protocol = PPPOE_PROTOCOL_IP4;
        hdr.ipv4.ttl = hdr.ipv4.ttl + 8w255;
    }

    action a_ds_pppoe_aftermath_v6() {
        hdr.pppoe.totalLength = hdr.ipv6.payloadLen + 16w42;
        hdr.pppoe.protocol = PPPOE_PROTOCOL_IP6;
        hdr.ipv6.hopLimit = hdr.ipv6.hopLimit + 8w255;
    }

    action a_ds_srcmac(bit<48> outer_src_mac, bit<48> outer_dst_mac, bit<48> inner_src_mac) {
        hdr.ethernet_outer.srcAddr = outer_src_mac;
        hdr.ethernet_outer.dstAddr = outer_dst_mac;
        hdr.ethernet_inner.srcAddr = inner_src_mac;
    }

    action _nop() {
    }

    action a_us_srcmac(bit<48> src_mac) {
        hdr.ethernet_outer.srcAddr = src_mac;
    }

    table t_drop {
        actions = {
            _drop;
        }
    }

    table t_ds_pppoe_aftermath_v4 {
        actions = {
            a_ds_pppoe_aftermath_v4;
        }
    }

    table t_ds_pppoe_aftermath_v6 {
        actions = {
            a_ds_pppoe_aftermath_v6;
        }
    }

    table t_ds_srcmac {
        actions = {
            _drop;
            a_ds_srcmac;
        }
        key = {
            standard_metadata.egress_port: exact;
            hdr.mpls0.label              : exact;
        }
        size = 256;
    }

    table t_us_srcmac {
        actions = {
            _nop;
            a_us_srcmac;
        }
        key = {
            standard_metadata.egress_port: exact;
            hdr.mpls0.label              : exact;
        }
    }
    apply {
        if (meta.ingress_md.cp == 1w0) {
            if (meta.ingress_md.usds == TYPE_US) {
                t_us_srcmac.apply();
            }
            if (meta.ingress_md.usds == 2w0x0) {
                if (hdr.ipv4.isValid()) {
                    t_ds_pppoe_aftermath_v4.apply();
                }
                else {
                    t_ds_pppoe_aftermath_v6.apply();
                }
                t_ds_srcmac.apply();
            }
            else {
                t_drop.apply();
            }
        }
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
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

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
        verify_checksum(true, {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(true, {
                hdr.ipv4.version,
                hdr.ipv4.ihl,
                hdr.ipv4.diffserv,
                hdr.ipv4.totalLen,
                hdr.ipv4.identification,
                hdr.ipv4.flags,
                hdr.ipv4.fragOffset,
                hdr.ipv4.ttl,
                hdr.ipv4.protocol,
                hdr.ipv4.srcAddr,
                hdr.ipv4.dstAddr
            }, hdr.ipv4.hdrChecksum, HashAlgorithm.csum16);
    }
}

V1Switch(
    ParserImpl(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    DeparserImpl()
) main;

