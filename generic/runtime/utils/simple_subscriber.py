
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

import time

from threading import Thread


class SimpleSubscriber:
    """Creates/removes a subscriber based on our defined IP/MAC testing pattern"""

    def __init__(self, caller, subid, bw_class="TENGIG", stats=None):
        self.stats = stats
        self.caller = caller
        self.subid = subid
        self.bw_class = bw_class

        self.line_id = self.subid
        self.line_mpls1_label = self.subid/16 + 1
        self.line_vlan_id = self.subid % 16

        self.subsc_id = 1
        self.service_id = 1
        #self.cpe_mac = "0x52540010" + "{0:0{1}x}".format(self.subid,4)
        pre_mac = "{0:0{1}x}".format(self.subid, 4)
        self.cpe_mac = "52:54:00:10:" + pre_mac[0:2] + ":" + pre_mac[2:4]
        self.pppoe_sess_id = self.subid

        octet3 = (self.subid+1)/256
        octet4 = (self.subid+1) % 256
        self.net4 = "100.69." + str(octet3) + "." + str(octet4)
        self.net6_t = "2a02:aaa1:0000:" + \
            "{0:0{1}x}".format(self.subid, 4) + "::/64"
        self.net6_s = "2a02:aaa2:00" + \
            "{0:0{1}x}".format(octet3, 2) + ":" + \
            "{0:0{1}x}".format(octet4, 2) + "00::/56"

    def createLine(self, accessPort, accessOuterLabel):

        self.accessPort = accessPort
        self.accessOuterLabel = accessOuterLabel

        startTime = time.time()
        # Subscriber Line
        line_id = self.subid
        self.caller.addSubscLine(accessPort, accessOuterLabel,
                                 self.line_mpls1_label, self.line_vlan_id, self.line_id)
        endTime = time.time()
        self.stats.add("createLineTime", self.subid, float(
            endTime-startTime)) if self.stats else None
        print "Created line for " + str(self.subid) + "."

    def setAuthed(self):
        startTime = time.time()
        # Authenticated subsc with networks
        self.caller.addSubscSession(
            self.line_id, self.subsc_id, self.service_id, self.cpe_mac, self.pppoe_sess_id, self.bw_class)
        self.caller.addSubscNetV4(self.line_id, self.subsc_id, self.net4)
        self.caller.addSubscNetV6(self.line_id, self.subsc_id, self.net6_t)
        self.caller.addSubscNetV6(self.line_id, self.subsc_id, self.net6_s)

        endTime = time.time()

        self.stats.add("authSubTime", self.subid, float(
            endTime-startTime)) if self.stats else None

        print "Authenticated subscriber " + str(self.subid) + "."

    def unsetAuthed(self):

        startTime = time.time()
        self.caller.delSubscSession(self.line_id, self.subsc_id)
        endTime = time.time()

        self.stats.add("unauthSubTime", self.subid, float(
            endTime-startTime)) if self.stats else None
