
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

from runtime.utils.simple_subscriber import *

DEFAULT_SERVICE_ID = 1

class SimpleTest:

    def __init__(self, caller, stats=None):
        self.caller = caller
        self.stats = stats




    def run(self):

        # == Port enabling

        # Access Port 1
        self.accessPort1 = self.caller.platf.getPort("access1")
        self.accessOuterLabel1 = 0x80001 #Note: accessInnerLabel1 defined by subscriber line definitions.
        self.accessOurOuterMAC1 = "52:54:00:00:01:01"
        self.accessPeerOuterMAC1 = "52:54:00:00:01:02"
        self.caller.enableLabelPortAccess(self.accessPort1, self.accessOuterLabel1, self.accessOurOuterMAC1, self.accessPeerOuterMAC1)

        # Core Port 1
        corePort1 = self.caller.platf.getPort("core1")
        coreOuterLabel1 = 0x00010
        coreInnerLabel1 = 200
        coreNextHopMac1 = "52:54:00:fe:00:01"
        self.caller.enableLabelPortCore(corePort1, coreOuterLabel1, "52:54:00:00:02:01")

        # Upstream Routes
        self.caller.addUpstreamRouteV4(DEFAULT_SERVICE_ID, "0.0.0.0/0", corePort1, coreOuterLabel1, coreInnerLabel1, coreNextHopMac1)
        self.caller.addUpstreamRouteV6(DEFAULT_SERVICE_ID, "2a02::/16", corePort1, coreOuterLabel1, coreInnerLabel1, coreNextHopMac1)
        self.caller.addUpstreamRouteV6(DEFAULT_SERVICE_ID, "2a03::/16", corePort1, coreOuterLabel1, coreInnerLabel1, coreNextHopMac1)




    def addManySubs(self, size):


        subs = []

        for i in range(0, size):
            subs.append(SimpleSubscriber(self.caller, i, "TENGIG", self.stats))

        for sub in subs:
            sub.createLine(self.accessPort1, self.accessOuterLabel1)

        for sub in subs:
            sub.setAuthed()
