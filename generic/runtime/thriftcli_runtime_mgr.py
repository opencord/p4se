
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

import pexpect
from runtime import p4_userplane_exception

dump = True
debug = True
strict = True



class ThriftCLIRuntimeMgr:
    def __init__(self, thriftcli_cmd, prompt_command="RuntimeCmd:"):
        self.cliproc = pexpect.spawn(thriftcli_cmd)
        self.prompt_command = prompt_command
        self.cliproc.expect(self.prompt_command)



    def sendCmd(self, command):
        if dump or debug:
            print
            command
        self.cliproc.sendline(command)
        self.cliproc.expect(self.prompt_command)
        output = self.cliproc.before
        error = "Error" in output or "Invalid match key" in output
        
        if dump or debug:
            print "P4_RUNTIME_CLI: \n#\t" + output.replace("\n", "\n#\t")
        if error and strict:
            raise p4_userplane_exception.P4UserPlaneException("Thrift command returned error.", command, output)
        return error



    def commitInitial(self):
        pass
        # Not required



    def _getActionParams(self, tokens):
        if len(tokens) > 2:
            # we have a mask
            return str(tokens[1]) + "/" + str(tokens[2])
        else:
            # we have no mask
            return str(tokens[1])



    def addTableRuleRaw(self, table, name, match, actionName, actionParams, priority=0):
        match_str = ' '.join(self._getActionParams(value) for value in match)
        actionParams_str = ' '.join(str(value[1]) for value in actionParams)
        cmd = "table_add " + table + " " + actionName + " " + match_str + " => " + actionParams_str + " "
        if priority != 0:
            # A priority is required for ternary tables
            cmd += " " + str(priority)
        
        # cmd = "table_add " + table + " " + actionName + " " + match_str + ((" => " + actionParams_str) if len(actionParams) != 0 else "") + " 0"
        return self.sendCmd(cmd)



    def setTableDefaultRuleRaw(self, table, actionName, actionParams):
        actionParams_str = ' '.join(str(value[1]) for value in actionParams)
        cmd = "table_set_default " + table + " " + actionName + " " + actionParams_str
        return self.sendCmd(cmd)



    def setMeterRates(self, meter_name, meter_index, rate1, burst1, rate2, burst2):
        cmd = "meter_set_rates " + meter_name + " " + str(meter_index) + " " + str(rate1) + ":" + str(
            burst1) + " " + str(rate2) + ":" + str(burst2)
        return self.sendCmd(cmd)
        
        
        
    def addParserValueSetEntry(self, name, value, mask=None):
        print "Not implemented yet."
        return 0
        


    def getPort(self, symbol):
        """Maps the symbolic port (e.g. a label) to a P4-understandable one."""
        
        if symbol == "ctrl":
            return "0"
        if symbol == "access1":
            return "1"  #internal
        if symbol == "core1":
            return "2"  #internal
        if symbol == "access2":
            return "3"  #internal
        if symbol == "core2":
            return "4"  #internal
        raise ValueError("P4 port not defined!")




