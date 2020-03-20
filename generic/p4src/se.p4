/*
* Copyright 2018-present Open Networking Foundation
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


//#define DEBUG_COUNTERS
#define ENABLE_COUNTERS
#define ENABLE_DS_METERS
#define ENABLE_IPV6

#include "headers.p4"
#include "includes/intrinsic.p4"

#define TYPE_DS 0x0
#define TYPE_US 0x1
#define TYPE_INVALID 0x2

#define SUBSC_CAPACITY 8192
#define NET_CAPACITY 4*SUBSC_CAPACITY
#define ROUTE_CAPACITY 256

#define NUM_OF_CPS 16

header_type ingress_md_t {
    fields {
	usds : 2; 	//0 if Upstream, double-tag, 1 if Downstream, 2 if invalid (3 undefined).
	cp : 1; 	//0 if still in dataplane, 1 if destined for control plane or coming from control plane.
	line_id : 32;	//e.g. a DSL line on the DSLAM.
	subsc_id : 8;	//Subscriber of line (multiple authed subscribers per line possible).
	ctr_bucket : 16; //References counters and meters of the current subscriber.
        meter_result : 32;
    }
}

metadata ingress_md_t ingress_md;

action _nop() { }

#ifdef DEBUG_COUNTERS

counter ctr_debug {
 type : packets;
 instance_count : 16;
}

#endif


// ============= General Tables


// ===== t_bng_fromcp

table t_bng_fromcp {
 reads {
  ethernet_outer.dstAddr : exact;
  ethernet_outer.srcAddr : exact;
  standard_metadata.ingress_port : exact;

 }
 actions {
  a_bng_output;
  _drop;
 }

 max_size : NUM_OF_CPS;
}

action a_bng_output() {
 modify_field(ethernet_outer.dstAddr, bng_cp.eth_dstAddr);
 modify_field(ethernet_outer.srcAddr, bng_cp.eth_srcAddr);
 modify_field(ethernet_outer.etherType, bng_cp.eth_etherType);
 modify_field(standard_metadata.egress_spec, bng_cp.fwd_port);
 modify_field(ingress_md.cp, 1);
 remove_header(bng_cp);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 13);
#endif
}


// ============= CP Tapping

table t_cptap_outer_ethernet {
 reads {
  ethernet_outer.dstAddr : exact;
  ethernet_outer.etherType : exact;
 }
 actions {
  a_cptap_cp;
  a_cptap_dp;
 }
 max_size : 32;
}

action a_cptap_cp() {
 modify_field(ingress_md.cp, 1);
}

action a_cptap_dp() {
 //Nothing to do.
}

//This e.g. catches ARP. More tapping tables thinkable - depending on exact CP behavior.
//IP (e.g. v6 link-local) tapping is done in the routing tables.

// ===== t_usds


table t_usds {
 reads {
  ethernet_outer.dstAddr : exact;
  standard_metadata.ingress_port : exact;
  mpls0.label : exact;

 }
 actions {
  a_usds_handle_ds;
  a_usds_handle_us;
  _mark_drop;
 }

 max_size : 256;
}

action a_usds_handle_ds() {
 modify_field(ingress_md.usds, TYPE_DS);

#ifdef DEBUG_COUNTERS
 count(ctr_debug, 0);
#endif
}

action a_usds_handle_us() {
 add_header(vlan_service); 
	//SPEC says: "If the header instance was invalid, all its 
	//fields are initialized to 0. If the header instance is 
	//already valid, it is not changed."
 modify_field(ingress_md.usds, TYPE_US);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 1);
#endif
}




// ============= Upstream (Subscriber -> Core or Subscriber -> Subscriber)


// ===== t_subsc_map

table t_line_map {
 reads {
  standard_metadata.ingress_port : exact;
  mpls0.label : exact;
  mpls1.label : exact;
  vlan_subsc.vlanID : exact;
 }
 actions {
  _mark_drop;
  a_line_map_pass;
 }
 max_size : SUBSC_CAPACITY;
}

action a_line_map_pass(line_id) {
 modify_field(ingress_md.line_id, line_id);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 2);
#endif

}


// ===== t_pppoe_cpdp

table t_pppoe_cpdp {
 reads {
  ethernet_inner.dstAddr : exact;	//bcast and mcast. Different services have the same local address
  vlan_service.etherType : exact;
  pppoe.protocol : exact;
 }
 actions {
  _mark_drop;
  a_pppoe_cpdp_to_cp;
  a_pppoe_cpdp_pass_ip;
 }
 max_size : 16;
}

action a_pppoe_cpdp_to_cp() {
 modify_field(ingress_md.cp, 1);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 3);
#endif
}

action a_pppoe_cpdp_pass_ip(version) {
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 4);
#endif
}



// ===== t_antispoof_mac

table t_antispoof_mac {
 reads {
  ingress_md.line_id : exact;
  vlan_service.vlanID : exact;
  ethernet_inner.srcAddr : exact;
  pppoe.sessionID : exact;
 }
 actions {
  _mark_drop;
  a_antispoof_mac_pass;
 }
 max_size : SUBSC_CAPACITY;
}

action a_antispoof_mac_pass(subsc_id, ctr_bucket) {
 modify_field(ingress_md.subsc_id, subsc_id);
 count(ctr_us_subsc, ctr_bucket);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 5);
#endif
}

#ifdef ENABLE_COUNTERS

counter ctr_us_subsc {
 type : packets;
 instance_count : SUBSC_CAPACITY;
}

#endif



// ===== t_antispoof_ipv4

table t_antispoof_ipv4 {
 reads {
  ipv4.srcAddr : exact;
  ingress_md.line_id : exact;
  ingress_md.subsc_id : exact;
 }
 actions {
  _mark_drop;
  a_antispoof_ipv4v6_pass;
 }
 max_size : NET_CAPACITY;
}

action a_antispoof_ipv4v6_pass() {
 remove_header(pppoe);
 remove_header(vlan_subsc);
 remove_header(ethernet_inner);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 6);
#endif
}

action a_antispoof_ipv4v6_nextpm() {
 //No operation
}


#ifdef ENABLE_IPV6

// ===== t_antispoof_ipv6

table t_antispoof_ipv6_0 {
 reads {
  //ipv6.srcAddr_0_55 : exact;
  //ipv6.srcAddr_56_63 : exact;
  ipv6.srcAddr mask 0xffffffffffffffff0000000000000000: exact;
  ingress_md.line_id : exact;
  ingress_md.subsc_id : exact;
 }
 actions {
  a_antispoof_ipv4v6_pass;
  a_antispoof_ipv4v6_nextpm; //Default action: Go to next table (is shown in the control flow)
 }
 max_size : NET_CAPACITY;
}

table t_antispoof_ipv6_1 {
 reads {
  //ipv6.srcAddr_0_55 : exact;
  ipv6.srcAddr mask 0xffffffffffffff000000000000000000: exact;
  ingress_md.line_id : exact;
  ingress_md.subsc_id : exact;
 }
 actions {
  _mark_drop;  //Default action: Drop (as there is no next table).     
  a_antispoof_ipv4v6_pass;
 }
 max_size : NET_CAPACITY;
}

#endif


// ===== t_us_expiredv4

table t_us_expiredv4 {
 actions {
  a_us_routev4v6_tocp;
 }
 max_size : 1;
}

// ===== t_us_routev4

table t_us_routev4 {
 reads {
  vlan_service.vlanID : exact;
  ipv4.dstAddr : lpm;
 }
 actions {
  _mark_drop;
  a_us_routev4v6;
  a_us_routev4v6_tocp;
 }
 max_size : ROUTE_CAPACITY ;
}

action a_us_routev4v6(out_port, mpls0_label, mpls1_label, via_hwaddr) {
 remove_header(vlan_service);
 modify_field(standard_metadata.egress_spec, out_port);
 modify_field(mpls0.label, mpls0_label);
 modify_field(mpls1.label, mpls1_label);
 modify_field(ethernet_outer.dstAddr, via_hwaddr);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 7);
#endif
}

action a_us_routev4v6_tocp() {
 modify_field(ingress_md.cp, 1);
}

#ifdef ENABLE_IPV6

// ===== t_us_expiredv6

table t_us_expiredv6 {
 actions {
  a_us_routev4v6_tocp;
 }
 max_size : 1;
}

// ===== t_us_routev6

table t_us_routev6 {
 reads {
  vlan_service.vlanID : exact;
  ipv6.dstAddr : lpm;
 }
 actions {
  _mark_drop;
  a_us_routev4v6;
  a_us_routev4v6_tocp;
 }
 max_size : ROUTE_CAPACITY ;
}

#endif




// ===== t_bng_tocp

table t_bng_tocp {
 reads {
  standard_metadata.ingress_port : exact;
    //put here whatever you want to balance your load on.
 }
 actions {
  a_bng_tocp;
 }

 max_size : NUM_OF_CPS;
}

action a_bng_tocp(ourOuterMAC, remoteOuterMAC, cpPhysicalPort) {

#ifdef DEBUG_COUNTERS
 count(ctr_debug, 11);
#endif

 add_header(bng_cp);
 modify_field(bng_cp.eth_dstAddr, ethernet_outer.dstAddr);
 modify_field(bng_cp.eth_srcAddr, ethernet_outer.srcAddr);
 modify_field(bng_cp.eth_etherType, ethernet_outer.etherType);
 modify_field(bng_cp.fwd_port, standard_metadata.ingress_port);

 modify_field(ethernet_outer.dstAddr, remoteOuterMAC);
 modify_field(ethernet_outer.srcAddr, ourOuterMAC);
 modify_field(ethernet_outer.etherType, ETHERTYPE_CP);

 modify_field(standard_metadata.egress_spec, cpPhysicalPort);

}



// ======= Egress

// ===== t_us_srcmac

table t_us_srcmac {
 reads {
  standard_metadata.egress_port : exact;
  mpls0.label : exact;
 }
 actions {
  _nop;
  a_us_srcmac;
 }
}

action a_us_srcmac(src_mac) {
 modify_field(ethernet_outer.srcAddr, src_mac);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 8);
#endif
}

// ============= Downstream (Core -> Subscriber)

// ===== t_ds_expiredv4

table t_ds_expiredv4 {
 actions {
  a_ds_route_tocp; 
 }
 max_size : 1;
}

// ===== t_ds_routev4

table t_ds_routev4 {
 reads {
  ipv4.dstAddr : exact;
 }
 actions {
  _mark_drop;
  a_ds_route_pushstack;
  a_ds_route_tocp;
 }
 max_size : NET_CAPACITY;
}

action a_ds_route_pushstack(mpls0_label, mpls1_label, subsc_vid, service_vid, 
	pppoe_session_id, out_port, inner_cpe_mac, ctr_bucket) {

 modify_field(mpls0.label, mpls0_label);
 modify_field(mpls1.label, mpls1_label);
 add_header(ethernet_inner);
 modify_field(ethernet_inner.dstAddr, inner_cpe_mac);
 modify_field(ethernet_inner.etherType, ETHERTYPE_VLAN);
 add_header(vlan_subsc);
 modify_field(vlan_subsc.vlanID, subsc_vid);
 modify_field(vlan_subsc.etherType, ETHERTYPE_VLAN);
 add_header(vlan_service);
 modify_field(vlan_service.vlanID, service_vid);
 modify_field(vlan_service.etherType, ETHERTYPE_PPPOES); 
 add_header(pppoe);
 modify_field(pppoe.version, 1);
 modify_field(pppoe.typeID, 1);
 //Code can be empty.
 modify_field(pppoe.sessionID, pppoe_session_id);
 modify_field(standard_metadata.egress_spec, out_port);
 modify_field(ingress_md.ctr_bucket, ctr_bucket);

#ifdef DEBUG_COUNTERS
 count(ctr_debug, 9);
#endif

#ifndef ENABLE_COUNTERS
 // count here if no meters, otherwise counting in the meter actions.
 // count(ctr_ds_subsc, ingress_md.ctr_bucket);
#endif

}

action a_ds_route_nextpm() {
 //Nop
}

action a_ds_route_tocp() {
 modify_field(ingress_md.cp, 1);
}



#ifdef ENABLE_IPV6

// ===== t_ds_expiredv6

table t_ds_expiredv6 {
 actions {
  a_ds_route_tocp;
 }
 max_size : 1;
}

// ===== t_ds_routev6

table t_ds_routev6_0 {
 reads {
  //ipv6.dstAddr_0_55 : exact;
  //ipv6.dstAddr_56_63 : exact;
  ipv6.dstAddr mask 0xffffffffffffffff0000000000000000: exact;
 }
 actions {
  a_ds_route_pushstack;
  a_ds_route_nextpm;
  a_ds_route_tocp;
 }
 max_size : NET_CAPACITY;
}

table t_ds_routev6_1 {
 reads {
  //ipv6.dstAddr_0_55 : exact;
  ipv6.dstAddr mask 0xffffffffffffff000000000000000000: exact;
 }
 actions {
  a_ds_route_pushstack;
  a_ds_route_tocp;
  _mark_drop;
 }
 max_size : NET_CAPACITY;
}

#endif






#ifdef ENABLE_COUNTERS

counter ctr_ds_subsc {
 type : packets;
 instance_count : SUBSC_CAPACITY;
}

#endif


// ===== Various QoS/Meter specific things

#ifdef ENABLE_DS_METERS

meter mtr_ds_prio {
 type : bytes;
 result : ingress_md.meter_result;
 instance_count : SUBSC_CAPACITY;
}

meter mtr_ds_besteff {
 type : bytes;
 result : ingress_md.meter_result;
 instance_count : SUBSC_CAPACITY;
}

table t_ds_acl_qos_v4 {
 reads {
  vlan_service.vlanID : exact;
  ipv4.diffserv : ternary;
  ipv4.srcAddr : lpm;
 }
 actions {
  a_ds_acl_qos_prio;
  a_ds_acl_qos_besteff;
  _mark_drop;
 }
 max_size : 32;
}

table t_ds_acl_qos_v6 {
 reads {
  vlan_service.vlanID : exact;
  ipv6.trafficClass : ternary;
  ipv6.srcAddr : ternary;
 }
 actions {
  a_ds_acl_qos_prio;
  a_ds_acl_qos_besteff;
  _mark_drop;
 }
 max_size : 32;
}

action a_ds_acl_qos_prio() {
 execute_meter(mtr_ds_prio, ingress_md.ctr_bucket, ingress_md.meter_result);
#ifdef ENABLE_COUNTERS
 count(ctr_ds_subsc, ingress_md.ctr_bucket);
#endif
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 10);
#endif
}

action a_ds_acl_qos_besteff() {
 execute_meter(mtr_ds_besteff, ingress_md.ctr_bucket, ingress_md.meter_result);
#ifdef ENABLE_COUNTERS
 count(ctr_ds_subsc, ingress_md.ctr_bucket);
#endif
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 10);
#endif
}

#endif



// ======= Egress

// ===== t_ds_pppoe_aftermath_v4

table t_ds_pppoe_aftermath_v4 {
 actions {
  a_ds_pppoe_aftermath_v4;
 }
}

action a_ds_pppoe_aftermath_v4() {
 add(pppoe.totalLength, ipv4.totalLen, 2);
 modify_field(pppoe.protocol, 0x0021);
 add(ipv4.ttl, ipv4.ttl, -1);

#ifdef DEBUG_COUNTERS
 count(ctr_debug, 12);
#endif

}

#ifdef ENABLE_IPV6

// ===== t_ds_pppoe_aftermath_v6

table t_ds_pppoe_aftermath_v6 {
 actions {
  a_ds_pppoe_aftermath_v6;
 }
}

action a_ds_pppoe_aftermath_v6() {
 add(pppoe.totalLength, ipv6.payloadLen, 42);	//2 plus 40 bytes IPv6 header.
 modify_field(pppoe.protocol, 0x0057);
 add(ipv6.hopLimit, ipv6.hopLimit, -1);

#ifdef DEBUG_COUNTERS
 count(ctr_debug, 14);
#endif

}

#endif


// ===== t_ds_srcmac

table t_ds_srcmac {
 reads {
  standard_metadata.egress_port : exact;
  mpls0.label : exact;
  //Must set the same MAC addresses for every MPLS0 label (except the inner dst MAC)
 }
 actions {
  _drop;
  a_ds_srcmac;
 }
 max_size : 256;
}

action a_ds_srcmac(outer_src_mac, outer_dst_mac, inner_src_mac) {

 modify_field(ethernet_outer.srcAddr, outer_src_mac);
 modify_field(ethernet_outer.dstAddr, outer_dst_mac);
 modify_field(ethernet_inner.srcAddr, inner_src_mac);
}


table t_drop {
 actions {
  _drop;
 }
}

action _mark_drop() {
 modify_field(ingress_md.usds, TYPE_INVALID);
#ifdef DEBUG_COUNTERS
 count(ctr_debug, 15);
#endif
}

action _drop() {
 drop();
}

control ingress {
 if (valid(bng_cp)) {
  apply(t_bng_fromcp);
 } else {
  apply(t_cptap_outer_ethernet);
  if (ingress_md.cp == 0) {
   apply(t_usds);
   if (ingress_md.usds == TYPE_US and valid(pppoe)) {
    ingress_upstream();
   } else if (ingress_md.usds == TYPE_DS) {
    ingress_downstream();
   }
  }
  if (ingress_md.cp == 1) {
   apply(t_bng_tocp);
  }
 }
}

control ingress_upstream {
 apply(t_line_map);
 apply(t_pppoe_cpdp);
 if (ingress_md.cp == 0) {
  apply(t_antispoof_mac);
  if (valid(ipv4)) {
   apply(t_antispoof_ipv4);
   if (ingress_md.usds == TYPE_US) {
    if (ipv4.ttl <= 1) apply(t_us_expiredv4);
    apply(t_us_routev4);
   }
#ifdef ENABLE_IPV6
  } else if (valid(ipv6)) {
   apply(t_antispoof_ipv6_0) {
    a_antispoof_ipv4v6_nextpm {
     apply(t_antispoof_ipv6_1);
    }
   }
   if (ingress_md.usds == TYPE_US) {
    if (ipv6.hopLimit <= 1) apply(t_us_expiredv6);
    apply(t_us_routev6);
   }
#endif
  }
 }
}

control ingress_downstream {
 if (valid(ipv4)) {
  if (ipv4.ttl <= 1) {
   apply(t_ds_expiredv4);
  }
  apply(t_ds_routev4);
#ifdef ENABLE_DS_METERS
  if (ingress_md.usds == TYPE_DS) apply(t_ds_acl_qos_v4);
#endif
#ifdef ENABLE_IPV6
 } else if (valid(ipv6)) {
  if (ipv6.hopLimit <= 1) {
   apply(t_ds_expiredv6);
  }
  apply(t_ds_routev6_0) {
   a_ds_route_nextpm {
    apply(t_ds_routev6_1);
   }
  }
#ifdef ENABLE_DS_METERS
  if (ingress_md.usds == TYPE_DS) apply(t_ds_acl_qos_v6);
#endif
#endif
 }
}


control egress {
 if (ingress_md.cp == 0) {
  if (ingress_md.usds == TYPE_US) {
   apply(t_us_srcmac);
  } if (ingress_md.usds == TYPE_DS) {
   if (valid(ipv4)) apply(t_ds_pppoe_aftermath_v4);
#ifdef ENABLE_IPV6
   else apply(t_ds_pppoe_aftermath_v6);
#endif
   apply(t_ds_srcmac);
  } else {
   //TYPE_INVALID
   apply(t_drop);
  }
 }
}






















