/*
* Copyright 2018-present Open Networking Foundation and Barefoot Networks
* 
* This file is adapted from an original acl.p4 from Barefoot Networks.
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

/*****************************************************************************/
/* Egress System ACL                                                         */
/*****************************************************************************/

action ingress_redirect_to_cpu_with_reason(reason_code) {
    modify_field(cpu_md.reason_code, reason_code);
    modify_field(cpu_md.handling_type, HANDLING_TYPE_ERROR);
    modify_field(serviceedge_md.fwd_net_proto, NET_PROTO_CP);
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_CP);
}

/*
MRU/MTU check for the tunnel should be done in
the processor. The details have not been worked out yet.
action ingress_pkt_too_big() {
    ingress_redirect_to_cpu_with_reason(CPU_ERROR_PKT_TOO_BIG);
}
*/

action egress_copy_to_cpu(mirror_id) {
    clone_egress_pkt_to_egress(mirror_id, error_fields);
}

action egress_redirect_to_cpu(mirror_id) {
    egress_copy_to_cpu(mirror_id);
    drop();
}

action egress_copy_to_cpu_with_reason(mirror_id, reason_code) {
    modify_field(cpu_md.reason_code, reason_code);
    egress_copy_to_cpu(mirror_id);
}

action egress_redirect_to_cpu_with_reason(mirror_id, reason_code) {
    egress_copy_to_cpu_with_reason(mirror_id, reason_code);
    drop();
}


action egress_pkt_too_big(mirror_id) {
    modify_field(cpu_md.expected_value, serviceedge_md.mtu_out);
    modify_field(cpu_md.actual_value, serviceedge_md.pkt_len_out);
    modify_field(cpu_md.handling_type, HANDLING_TYPE_ERROR);
    modify_field(serviceedge_md.out_net_proto, NET_PROTO_CP);
    egress_copy_to_cpu_with_reason(mirror_id, CPU_ERROR_PKT_TOO_BIG);
    drop();
}


table ingress_system_acl {
    reads {
        serviceedge_md.in_net_proto : ternary;
        serviceedge_md.fwd_net_proto : ternary;
        serviceedge_md.out_net_proto : ternary;
        serviceedge_md.processor_ingress : ternary;
        serviceedge_md.processor_egress : ternary;
        serviceedge_md.next_hop_id : ternary;
        mcast_md.is_multicast : ternary;
        ipv4.valid : ternary;
        ipv4.ttl : ternary;
        ipv4.totalLen : ternary;
        ipv6.valid : ternary;
        ipv6.hopLimit : ternary;
        ipv6.payloadLen : ternary;
    }
    actions {
        _nop;
        _drop;
        ingress_redirect_to_cpu_with_reason;
    }
    size : 64;
}

control process_ingress_system_acl {
    apply(ingress_system_acl);
}

table egress_system_acl {
    reads {
        ig_intr_md_for_tm.packet_color : ternary;
        eg_intr_md.egress_port : ternary;
        eg_intr_md_from_parser_aux.clone_src : ternary;
        cpu_md.packet_color : ternary;
        pcr_bng_md.ds_packet_color : ternary;
        serviceedge_md.pkt_len_out : ternary;
        serviceedge_md.mtu_out : ternary;
        serviceedge_md.mtu_check : ternary;
        serviceedge_md.in_net_proto : ternary;
        serviceedge_md.fwd_net_proto : ternary;
        serviceedge_md.out_net_proto : ternary;
        serviceedge_md.next_hop_id : ternary;
    }
    actions {
        _nop;
        _drop;
        egress_pkt_too_big;
        egress_copy_to_cpu;
        egress_redirect_to_cpu;
        egress_copy_to_cpu_with_reason;
        egress_redirect_to_cpu_with_reason;
    }
    size : 64;
}

control process_egress_system_acl {
    apply(egress_system_acl);
}

