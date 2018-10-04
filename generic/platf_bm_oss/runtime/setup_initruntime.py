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


"""This script just launches a control plane stub with the initial configuration.
Use it e.g. for testing."""

import sys
import os
basedir = os.path.dirname(os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))))
sys.path.append(basedir)

import runtime.thriftcli_runtime_mgr as thr_rt
import runtime.runtime_p4_manager as gen_cfg

platf = thr_rt.ThriftCLIRuntimeMgr(sys.argv[1])
mgr = gen_cfg.RuntimeP4Manager(platf)
mgr.setDefaults()
platf.commitInitial()
