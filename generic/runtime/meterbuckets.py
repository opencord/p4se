
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


class MeterBuckets:

    def __init__(self, caller, size, limit):
        self.caller = caller
        self.size = size
        self.limit = limit
        self.bucket2occupation = {}
        self.subscriber2bucket_occupation_class = {}
        self.cls2buckets = {}

    def getSub(self, sub):
        bkt, occupationNo, cls = self.subscriber2bucket_occupation_class[sub]
        return bkt*self.size+occupationNo

    def addSub(self, sub, cls):
        if sub in self.subscriber2bucket_occupation_class:
            bkt, occupationNo, cls = self.subscriber2bucket_occupation_class[sub]
            return bkt*self.size+occupationNo

        if cls in self.cls2buckets:
            for bkt in self.cls2buckets[cls]:
                position = self._addSubToBucket(sub, bkt, cls)
                if position >= 0:
                    return bkt*self.size+position
        bkt = self._makeBucket(cls)
        position = self._addSubToBucket(sub, bkt, cls)
        return bkt*self.size+position

    def delSub(self, sub):
        if not sub in self.subscriber2bucket_occupation_class:
            return None
        bucket, occupationNo, cls = self.subscriber2bucket_occupation_class[sub]
        del self.bucket2occupation[bucket][occupationNo]
        if not self.bucket2occupation[bucket]:
            # Delete bucket, as it is unused.
            del self.bucket2occupation[bucket]
            del self.cls2buckets[cls]
        del self.subscriber2bucket_occupation_class[sub]
        return bucket*self.size+occupationNo

    def _addSubToBucket(self, sub, bkt, cls):

        occupations = self.bucket2occupation[bkt]

        for i in range(0, self.size):
            if not i in occupations:
                self.bucket2occupation[bkt][i] = True
                self.subscriber2bucket_occupation_class[sub] = bkt, i, cls
                return i
        return -1

    def _makeBucket(self, cls):

        if not cls in self.cls2buckets:
            self.cls2buckets[cls] = {}

        for i in range(0, self.limit):
            if not i in self.bucket2occupation:
                self.bucket2occupation[i] = {}
                self.cls2buckets[cls][i] = True
                self.caller.createMeterBucket(cls, i, self.size)
                return i

        raise Exception("Meter bucket limit exceeded.")

    def getForDump(self):
        return self.bucket2occupation, self.subscriber2bucket_occupation_class, self.cls2buckets
