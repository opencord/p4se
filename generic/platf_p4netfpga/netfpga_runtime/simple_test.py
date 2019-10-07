#!/usr/bin/python


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


### you might have to install the python dependency ipaddr first:
# pip install ipaddr --user


#### Config params:
DO_MOONGEN = True
DO_VERIFICATION = False
FOUR_PORT = False



import sys,os
basedir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(basedir)

basedir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
print(basedir)
sys.path.append(basedir)

print(basedir)

import p4netfpga_runtime as fpga_cfg
import runtime.runtime_p4_manager as gen_cfg
import tests.simple_test as simple_test
import runtime.simple_stats as sim

def do_one_run(runid=0, size=32):

  print "===== Doing run " + str(runid) + ", size=" + str(size) + ".========="

  stats = sim.SimpleStats(basedir + "/out/p4_netfpga_simple_test_sub" + str(size) + "_run" + str(runid) + ".csv")

  platf = fpga_cfg.P4NetfpgaRuntime(basedir + "/build/CliCommands_"+str(size)+".txt")
  mgr = gen_cfg.RuntimeP4Manager(platf)


  mgr.setDefaults()

  test = simple_test.SimpleTest(mgr, stats)

  test.run()

  test.addManySubs(size)

  platf.makeInitial()

  if DO_MOONGEN:
    print("no load generator api found")
    ####create your load generator config here, e.g. config file for a MoonGen lua script



do_one_run(128, size=32)
do_one_run(128, size=64)
do_one_run(128, size=128)
do_one_run(128, size=256)
do_one_run(128, size=512)
do_one_run(128, size=1024)
do_one_run(128, size=2048)
do_one_run(128, size=3500)
do_one_run(128, size=4000)
do_one_run(128, size=4096)

exit()












