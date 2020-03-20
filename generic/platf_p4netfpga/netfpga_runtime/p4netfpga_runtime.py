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


import os,json,time,subprocess,threading


MAX_ALLOWED_THREADS = 1
THREAD_TIMEOUT = 5 #seconds

class P4NetfpgaRuntime:

 def __init__(self, targetfile):
  self.targetfile = targetfile
  tables = {}
  self.allTables = ["t_usds", "t_us_srcmac", "t_ds_srcmac", "t_cptap_outer_ethernet", "t_bng_tocp", "t_bng_fromcp", "t_line_map", "t_pppoe_cpdp", "t_us_routev4", "t_ds_routev4", "t_antispoof_ipv4", "t_antispoof_mac"]
  self.cli_commands = []


 def makeInitial(self):
  with open(self.targetfile, 'w') as outfile:
   for line in self.cli_commands:
    outfile.write("%s\n" % line)





 def addTableRuleRaw(self, table, name, match, actionName, actionParams):
  if not any(table in s for s in self.allTables):
   return 0
  
  if table == "t_antispoof_mac":
   new_match = [{},{},{},{}]
   for match_entry in match:
    if match_entry[0] == "ingress_md.line_id":
     new_match[0] = ("line_id", match_entry[1])
    if match_entry[0] == "vlan_service.vlanID":
     new_match[1] = ("servicevlan", match_entry[1])
    if match_entry[0] == "ethernet_inner.srcAddr":
     new_match[2] = ("innerMac", match_entry[1])
    if match_entry[0] == "pppoe.sessionID":
     new_match[3] = ("pppoe-line", match_entry[1])
   match = new_match

  if table == "t_antispoof_ipv4":
   new_match = [{},{},{}]
   for match_entry in match:
    if match_entry[0] == "ipv4.srcAddr":
     new_match[0] = ("ipv4src", match_entry[1])
    if match_entry[0] == "ingress_md.line_id":
     new_match[1] = ("line_id", match_entry[1])
    if match_entry[0] == "ingress_md.subsc_id":
     new_match[2] = ("subsc_id", match_entry[1])
   match = new_match

  if actionName == "a_ds_route_pushstack":
   new_actionParams = [{},{},{},{},{},{},{},{}]
   for action_entry in actionParams:
    if action_entry[0] == "mpls0_label":
     new_actionParams[0] = ("mpls0", action_entry[1])
    if action_entry[0] == "mpls1_label":
     new_actionParams[1] = ("mpls1", action_entry[1])
    if action_entry[0] == "subsc_vid":
     new_actionParams[2] = ("subsc-vid", action_entry[1])
    if action_entry[0] == "service_vid":
     new_actionParams[3] = ("service-id", action_entry[1])
    if action_entry[0] == "pppoe_session_id":
     new_actionParams[4] = ("pppoe_id", action_entry[1])
    if action_entry[0] == "out_port":
     new_actionParams[5] = ("out_port", action_entry[1])
    if action_entry[0] == "inner_cpe_mac":
     new_actionParams[6] = ("inner_cpe_mac", action_entry[1])
    if action_entry[0] == "ctr_bucket":
     new_actionParams[7] = ("ctr_bucket", action_entry[1])
   actionParams=new_actionParams


  if table == "t_line_map":
   print(match)



  cmd = "table_cam_add_entry " + table + " " + actionName + " "
  for match_entry in match:
   if "/" in str(match_entry[1]):
    continue #dirty workaround as p4-netfpga does not support lpm
   cmd = cmd + str(match_entry[1]) + " "
  cmd = cmd + "=> "
  for action_entry in actionParams:
   cmd = cmd + str(action_entry[1]) + " "
  self.cli_commands.append(cmd)
  return 0


 def delTableRuleRaw(self, table, name):
  print("del Rule table currently not supported")



 def setTableDefaultRuleRaw(self, table, actionName, actionParams):
  if not any(table in s for s in self.allTables):
   return 0
  print("default rule: "+table +" " + actionName)
  return 0


 #ports of p4-NetFPGA are one-hot encoded: {DMA, NF3, DMA, NF2, DMA, NF1, DMA, NF0}

 def getPort(self, symbol):
  print("get Port")
  if symbol == "ctrl":
   return "2"
  if symbol == "access1":
   return "1"   #external
  if symbol == "core1":
   return "4"   #external
  if symbol == "access2":
   return "16"   #external
  if symbol == "core2":
   return "64"   #external
  raise ValueError("P4 port not defined!")




 def setMeterRates(self, name, meter_name, meter_index, meter_count, rate1, burst1):
   #currently not supported
   return 0



 def addParserValueSetEntry(self, name, value, mask=None):
  #parser value-set currently not supported
  return 0

  valSet = {"value_set": name, "entries":[]}
  self._addParserValSetEntryRaw(valSet, value, mask)
  self.cf["parser_value_sets"]["configs"].append(valSet)

 def onEnd(self):
  if MAX_ALLOWED_THREADS > 1: 
   print "Waiting for threads to exit..."
   time.sleep(THREAD_TIMEOUT)









