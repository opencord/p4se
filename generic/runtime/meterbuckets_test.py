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

import time
import random
import meterbuckets


class MeterBucketsTest:

    def createMeterBucket(self, cls, id, size):
        print "T: Creating meter bucket: ", cls, id, size


if __name__ == '__main__':

    b = meterbuckets.MeterBuckets(MeterBucketsTest(), 32, 8)

    subs = {}

    while True:

        subint = random.randint(0, 100)

        sub = "Sub" + str(subint)
        cls = "Cls" + str(random.randint(0, 3))

        ret = b.addSub(sub, cls)
        print "T: Adding subscriber " + sub + " to " + \
            cls + ", returned " + str(ret) + "as offset."
        #print b.getForDump()
        subs[subint] = True

        # time.sleep(0.1)

        subint = random.randint(0, 100)

        if not subint in subs:
            continue

        sub = "Sub" + str(subint)
        cls = "Cls" + str(random.randint(0, 3))

        ret = b.delSub(sub)
        print "T: Deleting subscriber " + sub + " to " + \
            cls + ". returned " + str(ret) + "as offset."
        #print b.getForDump()
        del subs[subint]

        # time.sleep(0.1)
