/*

Common network header definitions

Copyright 2013-present Barefoot Networks, Inc. and Open Networking Foundation

Added by author Leonhard Nobach:
	MPLS header
	VLAN header
	PPPoE header
	Graph

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

//Custom header to dispatch control plane (CP) packets over Ethernet.
header_type bng_cp_t {
    fields {
    stamp : 16;
    fwd_port: 32;       //Incoming packets -> their output port, 
                        //Outgoing packets -> their input port.
    eth_dstAddr: 48;    //Fields which are the "actual" encapsulated "Ethernet header".
    eth_srcAddr: 48;
    eth_etherType: 16;
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
        vlanID: 16;
	etherType: 16;
    }
}

header_type pppoe_t {
    fields {
	version : 4;   //Always 1
	typeID : 4;    //Always 1
	code : 8;
	sessionID : 16;
	totalLength : 16;
	protocol : 16; //See http://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml
                   //User-plane: IP:  0021, IPv6: 0057, 
                   //Control-plane: LCP: c021, IPv6CP: 8057, IPCP: 
    }
}

header_type ipv4_t {
    fields {
        version : 4;
        ihl : 4;
        diffserv : 8;	//a.k.a. ToS
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

#ifdef ENABLE_IPV6
header_type ipv6_t {
    fields {
        version : 4;
        trafficClass : 8;
        flowLabel : 20;
        payloadLen : 16;
        nextHdr : 8;
        hopLimit : 8;
        srcAddr : 128;
        dstAddr : 128;
    }
}
#endif

/* === */



field_list ipv4_checksum_list {
        ipv4.version;
        ipv4.ihl;
        ipv4.diffserv;
        ipv4.totalLen;
        ipv4.identification;
        ipv4.flags;
        ipv4.fragOffset;
        ipv4.ttl;
        ipv4.protocol;
        ipv4.srcAddr;
        ipv4.dstAddr;
}

field_list_calculation ipv4_checksum {
    input {
        ipv4_checksum_list;
    }
    algorithm : csum16;
    output_width : 16;
}

calculated_field ipv4.hdrChecksum  {
    verify ipv4_checksum;
    update ipv4_checksum;
}


/* === */

parser start {
    return parse_ethernet_outer;
}

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_PPPOED 0x8863
#define ETHERTYPE_PPPOES 0x8864
#define ETHERTYPE_MPLS 0x8847

#define ETHERTYPE_CP 0x8765	//A (remote) CP packet that must be forwarded on a specific port.

header ethernet_t ethernet_outer;

parser parse_ethernet_outer {
    extract(ethernet_outer);
    return select(latest.etherType) {
        ETHERTYPE_MPLS : parse_mpls0;
        ETHERTYPE_CP : parse_bng_cp;
        default: ingress;
    }
}

header bng_cp_t bng_cp;

parser parse_bng_cp {
    extract(bng_cp);
    return ingress;  
}

// We require a parser value set here, as we need to already know
// in the parser whether a label is an access or a core label, to
// be able to parse it correctly
parser_value_set mpls_0_accesslabels;

header mpls_t mpls0;

parser parse_mpls0 {
    extract(mpls0);
    return select(latest.s) {
	1 : ingress; // packets must have 2 labels.
	default : parse_mpls1;
    }
}

header mpls_t mpls1;

parser parse_mpls1 {
    extract(mpls1);
    return select(latest.s) {
	1 : parse_above_mpls;
	default : ingress; //packets must not have more than 2 labels.
    }
}

parser parse_above_mpls {
    return select(mpls0.label) {
	mpls_0_accesslabels : parse_ethernet_inner;
	default : parse_ip;
    }
}


header ethernet_t ethernet_inner;

parser parse_ethernet_inner {
    extract(ethernet_inner);
    return select(latest.etherType) {
	ETHERTYPE_VLAN : parse_vlan_subsc;	
        default: ingress;
    }
}

header vlan_t vlan_subsc;
header vlan_t vlan_service;

parser parse_vlan_subsc {
    extract(vlan_subsc);
    return select(latest.etherType) {
	ETHERTYPE_VLAN : parse_vlan_service;
	ETHERTYPE_PPPOED : parse_pppoe;
	ETHERTYPE_PPPOES : parse_pppoe; 	//In this case we have no service field -> supported!
        default: ingress;
    }
}

parser parse_vlan_service {
    extract(vlan_service);
    return select(latest.etherType) {
	ETHERTYPE_PPPOED : parse_pppoe;
	ETHERTYPE_PPPOES : parse_pppoe;
        default: ingress;
    }
}

#define PPPOE_PROTOCOL_IP4 0x0021
#define PPPOE_PROTOCOL_IP6 0x0057

header pppoe_t pppoe;

parser parse_pppoe {
    extract(pppoe);
    return select(latest.protocol) {
	PPPOE_PROTOCOL_IP4: parse_ip;	
    //Reference parse_ip even though we already know the version...
#ifdef ENABLE_IPV6
	PPPOE_PROTOCOL_IP6: parse_ip;
#endif
	default: ingress;
    }
}

parser parse_ip {
    //We cannot get the IP version from the ethertype or MPLS label. Thus, get it 
    //from the IP packet's first 4 bits.
    return select(current(0, 4)) {
        4 : parse_ipv4;
#ifdef ENABLE_IPV6
        6 : parse_ipv6;
#endif
	default : ingress;
    }
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}

#ifdef ENABLE_IPV6
header ipv6_t ipv6;

parser parse_ipv6 {
    extract(ipv6);
    return ingress;
}
#endif










