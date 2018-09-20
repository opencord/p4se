#!/usr/bin/python

# Copyright 2018-present Open Networking Foundation
#
# Contributed and sponsored by Deutsche Telekom AG.
# Originally developed as part of the D-Nets 6 P4 Service Edge project
# in collaboration with Technische Universitaet Darmstadt.
# Authors: Leonhard Nobach, Jeremias Blendin, Ralf Kundel
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For details see the file LICENSE in the top project directory.

# Requires python-ipaddr

import ipaddr
import binascii
import meterbuckets
import threading

ENABLE_IPV6 = True


METERBUCKET_SIZE = 512

METER_BWCLASSES = {
    "SNAIL": [500, 50, 50, 10],
    # [<prio>, <prio_burst>, <besteff>, <besteff_burst>] (Kbit/s)
    # Note: burst must be set to >0, otherwise no traffic will pass!
    "SPEED_50": [50000, 5000, 10000, 1000],
    "SPEED_100": [50000, 5000, 10000, 1000],

    # 10G god mode for Moongen testing
    "TENGIG": [10000000, 1000000, 10000000, 1000000]
}

# Important: A "labelport" here is the (physical port, MPLS0 label) tuple.


class RuntimeP4Manager:
    """Platform-independent runtime manager"""

    def __init__(self, platf):
        self.platf = platf
        self.accessPorts = {}
        self.corePorts = {}
        self.line_info = {}
        self.routesv4 = {}
        self.routesv6 = {}
        self.SUBSC_FACING_INNERMAC = "52:54:00:01:01:01"

        self.statelock = threading.Lock()

        self.mbuckets = meterbuckets.MeterBuckets(
            self, METERBUCKET_SIZE, 128)  # FIXME: set the limit better?

   
    def setDefaults(self):
        """ Sets the initial P4 runtime config. Must always be implemented. 
        Run at the very start to set initial rules"""

        self.platf.setTableDefaultRuleRaw("t_bng_fromcp", "_drop", [])
        self.platf.setTableDefaultRuleRaw(
            "t_cptap_outer_ethernet", "a_cptap_dp", [])

        self.platf.setTableDefaultRuleRaw("t_usds", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw("t_line_map", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw(
            "t_pppoe_cpdp", "a_pppoe_cpdp_to_cp", [])

        # self.platf_addTableRuleRaw("t_pppoe_cpdp", { "ethernet_inner.dstAddr" : vlan_service.etherType "0xffffffffffff", 0021,0
        self.platf.addTableRuleRaw("t_pppoe_cpdp", "V4_DP",
                                   [("ethernet_inner.dstAddr", self.SUBSC_FACING_INNERMAC), (
                                       "vlan_service.etherType", "0x8864"), ("pppoe.protocol", "0x0021")],
                                   "a_pppoe_cpdp_pass_ip", [])  # IPv4 to Dataplane
        self.platf.addTableRuleRaw("t_pppoe_cpdp", "V6_DP",
                                   [("ethernet_inner.dstAddr", self.SUBSC_FACING_INNERMAC), (
                                       "vlan_service.etherType", "0x8864"), ("pppoe.protocol", "0x0057")],
                                   "a_pppoe_cpdp_pass_ip", [])  # IPv6 to Dataplane

        self.platf.setTableDefaultRuleRaw("t_antispoof_mac", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw("t_antispoof_ipv4", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw(
            "t_us_expiredv4", "a_us_routev4v6_tocp", [])
        self.platf.setTableDefaultRuleRaw("t_us_routev4", "_mark_drop", [])
        if ENABLE_IPV6:
            self.platf.setTableDefaultRuleRaw(
                "t_antispoof_ipv6_0", "a_antispoof_ipv4v6_nextpm", [])
            self.platf.setTableDefaultRuleRaw(
                "t_antispoof_ipv6_1", "_mark_drop", [])
            self.platf.setTableDefaultRuleRaw(
                "t_us_expiredv6", "a_us_routev4v6_tocp", [])
            self.platf.setTableDefaultRuleRaw("t_us_routev6", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw("t_us_srcmac", "_nop", [])

        self.platf.setTableDefaultRuleRaw(
            "t_ds_expiredv4", "a_ds_route_tocp", [])
        self.platf.setTableDefaultRuleRaw("t_ds_routev4", "_mark_drop", [])
        self.platf.setTableDefaultRuleRaw(
            "t_ds_pppoe_aftermath_v4", "a_ds_pppoe_aftermath_v4", [])
        # could be "drop" for a stricter ACL.
        self.platf.setTableDefaultRuleRaw(
            "t_ds_acl_qos_v4", "a_ds_acl_qos_besteff", [])
        if ENABLE_IPV6:
            self.platf.setTableDefaultRuleRaw(
                "t_ds_expiredv6", "a_ds_route_tocp", [])
            self.platf.setTableDefaultRuleRaw(
                "t_ds_routev6_0", "a_ds_route_nextpm", [])
            self.platf.setTableDefaultRuleRaw(
                "t_ds_routev6_1", "_mark_drop", [])
            self.platf.setTableDefaultRuleRaw(
                "t_ds_pppoe_aftermath_v6", "a_ds_pppoe_aftermath_v6", [])
            # could be "drop" for a stricter ACL.
            self.platf.setTableDefaultRuleRaw(
                "t_ds_acl_qos_v6", "a_ds_acl_qos_besteff", [])

        self.platf.setTableDefaultRuleRaw("t_ds_srcmac", "_drop", [])

        self.platf.addParserValueSetEntry("mpls_0_accesslabels", "0x80000", mask="0x80000")

        self.connectCP("0x52540000d474", "0x52540001d474",
                       self.platf.getPort("ctrl"), "Default")





    def connectCP(self, ourOuterMAC, remoteOuterMAC, physicalPort, name):
        """Connects a control plane (CP, preparation to support multiple CP endpoints)"""

        # Default rule, but in the future we could use it for load balancing.
        self.platf.setTableDefaultRuleRaw("t_bng_tocp", "a_bng_tocp", [(
            "ourOuterMAC", ourOuterMAC), ("remoteOuterMAC", remoteOuterMAC), ("cpPhysicalPort", physicalPort)])

        # Match incoming from DP to send it out on appropriate CP port.
        self.platf.addTableRuleRaw("t_bng_fromcp", name,
                                   [("ethernet_outer.dstAddr", ourOuterMAC), ("ethernet_outer.srcAddr",
                                                                              remoteOuterMAC), ("standard_metadata.ingress_port", physicalPort)],
                                   "a_bng_output", [])




    def enableLabelPortAccess(self, port, mpls0_label, ourOuterMAC, peerOuterMAC):
        """Enables a physical port / MPLS0 label combination as an 
        access labelport (a labelport where an AN is connected to) 
        Whatever must be entered in ourOuterMAC, peerOuterMAC, mpls0_label 
        depends on the way MPLS is done in the network, the dataplane 
        just matches it (drops it if the fields in the packet are not 
        as expected). MPLS1 label will be set on a per-subscriber basis later."""

        # TODO: Consistency check!

        self.platf.addTableRuleRaw("t_usds", "AccessPort_" + str(port) + "_" + str(mpls0_label),
                                   [("ethernet_outer.dstAddr", ourOuterMAC), (
                                       "standard_metadata.ingress_port", port), ("mpls0.label", mpls0_label)],
                                   "a_usds_handle_us", [])  # Note that the outer src MAC is not checked for spoofing at the moment (trusted MPLS net assumed).

        self.platf.addTableRuleRaw("t_ds_srcmac", "AccessPort_" + str(port) + "_" + str(mpls0_label),
                                   [("standard_metadata.egress_port", port),
                                    ("mpls0.label", mpls0_label)],
                                   "a_ds_srcmac", [("outer_src_mac", ourOuterMAC), ("outer_dst_mac", peerOuterMAC), ("inner_src_mac", self.SUBSC_FACING_INNERMAC)])

        self.statelock.acquire()
        if not port in self.accessPorts:
            self.accessPorts[port] = {}
        self.accessPorts[port][mpls0_label] = {
            "our_mac": ourOuterMAC, "peer_mac": peerOuterMAC}
        self.statelock.release()




    def enableLabelPortCore(self, port, mpls0_label, ourMAC):
        """Enables a physical port / MPLS0 label combination as a core 
        labelport (a labelport where an uplink gateway is connected to) 
        Whatever must be entered in ourOuterMAC, peerOuterMAC, mpls0_label 
        depends on the way MPLS is done in the network, the dataplane just 
        matches it (drops it if the fields in the packet are not as expected). 
        The core peer's MAC (e.g. a core router as the "next hop") can 
        be set in the routing table later."""

        # TODO: Consistency check!

        self.platf.addTableRuleRaw("t_usds", "CorePort_" + str(port) + "_" + str(mpls0_label),
                                   [("ethernet_outer.dstAddr", ourMAC), (
                                       "standard_metadata.ingress_port", port), ("mpls0.label", mpls0_label)],
                                   "a_usds_handle_ds", [])  # Note that the src MAC is not checked for spoofing at the moment (trusted MPLS net assumed).

        self.platf.addTableRuleRaw("t_us_srcmac", "CorePort_" + str(port) + "_" + str(mpls0_label),
                                   [("standard_metadata.egress_port", port),
                                    ("mpls0.label", mpls0_label)],
                                   "a_us_srcmac", [("src_mac", ourMAC)])

        self.statelock.acquire()
        if not port in self.corePorts:
            self.corePorts[port] = {}
        self.corePorts[port][mpls0_label] = {"our_mac": ourMAC}
        self.statelock.release()





    def addSubscLine(self, port, mpls0_label, mpls1_label, subsc_vlan_id, line_id):
        """Registers a subscriber line. e.g. if a new customer premise is 
        connected to a DSLAM port. When a line is registered, the SE waits 
        for PPPoE authentication attempts of subscribers on it. Matches 
        the expected (port, mpls0_label, mpls1_label, subsc_vlan_id) 
        combination in this packet and assigns the specified line_id, 
        which is an arbitrary 32-bit unsigned integer number used to match
        the subscriber in the following pipeline."""

        # TODO: Consistency check!

        self.platf.addTableRuleRaw("t_line_map", "Line_" + str(line_id),
                                   [("standard_metadata.ingress_port", port), ("mpls0.label", mpls0_label), (
                                       "mpls1.label", mpls1_label), ("vlan_subsc.vlanID", subsc_vlan_id)],
                                   "a_line_map_pass", [("line_id", line_id)])

        self.statelock.acquire()
        self.line_info[line_id] = {"port": port, "mpls0_label": mpls0_label, "mpls1_label": mpls1_label, "subsc_vlan_id": subsc_vlan_id, "line_id": line_id,
                                   "sessions": {}}
        self.statelock.release()




    def addSubscSession(self, line_id, line_sub_id, service_id, cpe_mac, pppoe_sess_id, bwClass):
        """Establishes a new active session.
        Policing data is an array: [<rate1>, <rate1_burst>] (Kbit/s)"""

        # TODO: Consistency check!

        sessid = (line_id << 4) | line_sub_id
        ctr_bucket = self.mbuckets.addSub(sessid, bwClass)

        self.platf.addTableRuleRaw("t_antispoof_mac", "Sess_" + str(line_id) + "_" + str(line_sub_id),
                                   [("ingress_md.line_id", line_id),
                                    ("vlan_service.vlanID", service_id),
                                    ("ethernet_inner.srcAddr", cpe_mac),
                                    ("pppoe.sessionID", pppoe_sess_id)],
                                   "a_antispoof_mac_pass", [("subsc_id", line_sub_id), ("ctr_bucket", ctr_bucket)])

        self.statelock.acquire()

        self.line_info[line_id]["sessions"][line_sub_id] = {"cpe_mac": cpe_mac, "pppoe_sess_id": pppoe_sess_id, "ctr_bucket": ctr_bucket,
                                                            "service_id": service_id, "nets_v4": {}, "nets_v6": {}, "bwClass": bwClass}

        self.statelock.release()

    def delSubscSession(self, line_id, line_sub_id):

        sessid = (line_id << 4) | line_sub_id
        ctr_bucket = self.mbuckets.delSub(sessid)

        if not line_id in self.line_info:
            raise ValueError('Line ID not registered.')
        lineSessions = self.line_info[line_id]["sessions"]
        if not line_sub_id in lineSessions:
            raise ValueError('Line ID not registered.')
        session = lineSessions[line_sub_id]

        for net in session["nets_v4"]:
            self._delSubscNetV4(line_id, line_sub_id, net)
        for net in session["nets_v6"]:
            self._delSubscNetV6(line_id, line_sub_id, net)
        self.platf.delTableRuleRaw(
            "t_antispoof_mac", "Sess_" + str(line_id) + "_" + str(line_sub_id))

        self.statelock.acquire()
        del self.line_info[line_id]["sessions"][line_sub_id]
        self.statelock.release()

    def createMeterBucket(self, cls, i, size):

        policingData = METER_BWCLASSES[cls]

        self.platf.setMeterRates(
            "ds_prio_bkt_" + str(i), "mtr_ds_prio", i*size, size, policingData[0], policingData[1])
        self.platf.setMeterRates("ds_besteff_bkt_" + str(i), "mtr_ds_besteff",
                                 i*size, size, policingData[2], policingData[3])


    def addSubscNetV4(self, line_id, line_sub_id, netv4_cidr_str):
        """Add a v4 network to the authenticated subscriber's session."""

        # TODO: Consistency check!

        id_str = "Net4_" + str(line_id) + "_" + str(line_sub_id) + \
            "_" + netv4_cidr_str.replace("/", "_")
        
        # Upstream

        self.platf.addTableRuleRaw("t_antispoof_ipv4", id_str,
                                   [("ingress_md.line_id", line_id),
                                    ("ingress_md.subsc_id", line_sub_id),
                                       ("ipv4.srcAddr", netv4_cidr_str)],
                                   "a_antispoof_ipv4v6_pass", [])

        self.statelock.acquire()
        lineinfo = self.line_info[line_id]
        subscinfo = lineinfo["sessions"][line_sub_id]
        subscinfo["nets_v4"][netv4_cidr_str] = True
        self.statelock.release()

        # Downstream

        self.platf.addTableRuleRaw("t_ds_routev4", id_str,
                                   [("ipv4.dstAddr", netv4_cidr_str)],
                                   "a_ds_route_pushstack", [("mpls0_label", lineinfo["mpls0_label"]), ("mpls1_label", lineinfo["mpls1_label"]),
                                                            ("subsc_vid", lineinfo["subsc_vlan_id"]), (
                                                                "service_vid", subscinfo["service_id"]),
                                                            ("pppoe_session_id", subscinfo["pppoe_sess_id"]), (
                                       "out_port", lineinfo["port"]),
                                       ("inner_cpe_mac", subscinfo["cpe_mac"]), ("ctr_bucket", subscinfo["ctr_bucket"])])




    def delSubscNetV4(self, line_id, line_sub_id, netv4_cidr_str):
        """Delete a v4 network from the authenticated subscriber's session."""
        lineinfo = self.line_info[line_id]
        subscinfo = lineinfo["sessions"][line_sub_id]
        _delSubscNetV4(line_id, line_sub_id, netv4_cidr_str)

        self.statelock.acquire()
        del subscinfo["nets_v4"][netv4_cidr_str]
        self.statelock.release()




    def _delSubscNetV4(self, line_id, line_sub_id, netv4_cidr_str):
        id_str = "Net4_" + str(line_id) + "_" + str(line_sub_id) + \
            "_" + netv4_cidr_str.replace("/", "_")
        self.platf.delTableRuleRaw("t_antispoof_ipv4", id_str)
        self.platf.delTableRuleRaw("t_ds_routev4", id_str)





    def addSubscNetV6(self, line_id, line_sub_id, netv6_addr_cidr):
        """Add a v6 network to the authenticated subscriber's session."""

        # TODO: Consistency check!

        addr = ipaddr.IPv6Network(netv6_addr_cidr)

        netv6 = "0x" + binascii.hexlify(bytes(addr.packed))
        # FIXME: check for 0s above subnet?

        if addr.prefixlen == 64:
            table_id = 0
        elif addr.prefixlen == 56:
            table_id = 1
        else:
            raise ValueError('Can only assign /56 and /64 subnets.')

        # Populate upstream table

        match_params_us = [("ingress_md.line_id", line_id),
                           ("ingress_md.subsc_id", line_sub_id),
                           ("ipv6.srcAddr", netv6)]

        v6_addr_sanitized = netv6_addr_cidr.replace("/", "_").replace(":", "_")
        table_name = "t_antispoof_ipv6_" + str(table_id)
        rule_name = "Net6_" + str(table_id) + "_" + str(line_id) + \
            "_" + str(line_sub_id) + "_" + v6_addr_sanitized

        self.platf.addTableRuleRaw(
            table_name, rule_name, match_params_us, "a_antispoof_ipv4v6_pass", [])

        self.statelock.acquire()
        lineinfo = self.line_info[line_id]
        subscinfo = lineinfo["sessions"][line_sub_id]
        subscinfo["nets_v6"][netv6_addr_cidr] = True
        self.statelock.release()

        # Populate downstream table.

        match_params_ds = [("ipv6.dstAddr", netv6)]

        table_name = "t_ds_routev6_" + str(table_id)

        self.platf.addTableRuleRaw(table_name, rule_name, match_params_ds,
                                   "a_ds_route_pushstack", [("mpls0_label", lineinfo["mpls0_label"]), ("mpls1_label", lineinfo["mpls1_label"]),
                                                            ("subsc_vid", lineinfo["subsc_vlan_id"]), (
                                                                "service_vid", subscinfo["service_id"]),
                                                            ("pppoe_session_id", subscinfo["pppoe_sess_id"]), (
                                                                "out_port", lineinfo["port"]),
                                                            ("inner_cpe_mac", subscinfo["cpe_mac"]), ("ctr_bucket", subscinfo["ctr_bucket"])])






    def delSubscNetV6(self, line_id, line_sub_id, netv6_addr_cidr):
        """Delete a v6 network from the authenticated subscriber's session."""
        
        
        lineinfo = self.line_info[line_id]
        subscinfo = lineinfo["sessions"][line_sub_id]
        _delSubscNetV4(line_id, line_sub_id, netv6_addr_cidr)

        self.statelock.acquire()
        del subscinfo["nets_v6"][netv6_addr_cidr]
        self.statelock.release()




    def _delSubscNetV6(self, line_id, line_sub_id, netv6_addr_cidr):

        addr = ipaddr.IPv6Network(netv6_addr_cidr)

        if addr.prefixlen == 64:
            table_id = 0
        elif addr.prefixlen == 56:
            table_id = 1
        else:
            raise ValueError('Can only remove /56 and /64 subnets.')

        v6_addr_sanitized = netv6_addr_cidr.replace("/", "_").replace(":", "_")
        table_name = "t_antispoof_ipv6_" + str(table_id)
        rule_name = "Net6_" + str(table_id) + "_" + str(line_id) + \
            "_" + str(line_sub_id) + "_" + v6_addr_sanitized
        self.platf.delTableRuleRaw(table_name, rule_name)
        table_name = "t_ds_routev6_" + str(table_id)
        self.platf.delTableRuleRaw(table_name, rule_name)


    def addUpstreamRouteV4(self, service_id, netv4_cidr_str, coreOutPort, coreOutLabel0, coreOutLabel1, nextHopMac):
        """Add a general (non-subscriber-specific) upstream route.
        Must be HEX, no v6 address with CIDR-str at the moment"""

        # TODO: Consistency check!
        # Check if the respective labelport has been set as a core port.

        self.platf.addTableRuleRaw("t_us_routev4", "Rt4_" + str(netv4_cidr_str).replace("/", "_"),
                                   [("vlan_service.vlanID", service_id),
                                    ("ipv4.dstAddr", netv4_cidr_str)],
                                   "a_us_routev4v6", [("out_port", coreOutPort), ("mpls0_label", coreOutLabel0),
                                                      ("mpls1_label", coreOutLabel1), ("via_hwaddr", nextHopMac)])

        if not service_id in self.routesv4:
            self.routesv4[service_id] = {}
        self.routesv4[service_id][netv4_cidr_str] = {
            "coreOutPort": coreOutPort, "coreOutLabel0": coreOutLabel0, "coreOutLabel1": coreOutLabel1, "via_hwaddr": nextHopMac}






    def addUpstreamRouteV6(self, service_id, netv6_cidr_str, coreOutPort, coreOutLabel0, coreOutLabel1, nextHopMac):
        """Add a general (non-subscriber-specific) upstream route. Must 
        be HEX, no v6 address with CIDR-str at the moment"""

        # TODO: Consistency check! Check if the respective labelport has been set as a core port.

        addr = ipaddr.IPv6Network(netv6_cidr_str)

        prefix = addr.prefixlen
        netv6 = "0x" + binascii.hexlify(bytes(addr.packed))

        self.platf.addTableRuleRaw("t_us_routev6", "Rt6_all_" + str(service_id),
                                   [("vlan_service.vlanID", service_id),
                                    ("ipv6.dstAddr", netv6, prefix)],
                                   "a_us_routev4v6", [("out_port", coreOutPort), ("mpls0_label", coreOutLabel0),
                                                      ("mpls1_label", coreOutLabel1), ("via_hwaddr", nextHopMac)])

        if not service_id in self.routesv6:
            self.routesv6[service_id] = {}
        self.routesv6[service_id]["all"] = {
            "coreOutPort": coreOutPort, "coreOutLabel0": coreOutLabel0, "coreOutLabel1": coreOutLabel1, "via_hwaddr": nextHopMac}
