# Copyright 2019-present Open Networking Foundation
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

import time, threading

class SimpleStats:

  def __init__(self, statsfile, live=False):
    self._out = open(statsfile, 'w')
    self._lock = threading.Lock()
    self._live = live

  def add(self, eventName, identifier, eventValue):
    self._lock.acquire()
    self._out.write(str(time.time()) + "," + str(eventName) + "," + str(identifier) + "," + str(eventValue) + "\n")
    if self._live:
      self._out.flush()
    self._lock.release()

  def onEnd(self):
    self._out.close()



