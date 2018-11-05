-- Copyright 2018-present Open Networking Foundation
--
-- Contributed and sponsored by Deutsche Telekom AG.
-- Originally developed as part of the D-Nets 6 P4 Service Edge project
-- in collaboration with Technische Universitaet Darmstadt.
-- Author: Jeremias Blendin
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
-- http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.
--
-- For details see the file LICENSE in the top project directory.
--
-- se.p4 CPU header
--
-- declare our protocol
sep4cpu_proto = Proto("sep4cpuheader","se.p4 cpu header")
-- create a function to dissect it
function sep4cpu_proto.dissector(buffer,pinfo,tree)
	local HEADER_LEN = 10
    pinfo.cols.protocol = "SEP4CPUHEADER"
    local subtree = tree:add(sep4cpu_proto,buffer(),"se.p4 cpu header")
    subtree:add(buffer(0,1),"handling_type " .. buffer(0,1):uint())
    subtree:add(buffer(1,1),"reason " .. buffer(1,1):uint())
    subtree:add(buffer(2,1),"pcr_bng_access_node_id " .. buffer(2,1):uint())
    subtree:add(buffer(3,3),"pcr_bng_access_node_mpls_label " .. buffer(3,3):uint())
    subtree:add(buffer(6,2),"pcr_bng_session_id " .. buffer(6,2):uint())
    subtree:add(buffer(8,2),"ethertype " .. buffer(8,2):uint())
	if buffer:len() > HEADER_LEN then
        local next_diss = (DissectorTable.get("ethertype")):get_dissector(buffer(8,2):uint())
		next_diss:call(buffer(HEADER_LEN):tvb(), pinfo, tree)
    end
end
-- load the ethertype table
eth_table = DissectorTable.get("ethertype")
-- register our protocol to handle ethertype 0xeeee
eth_table:add(0xeeee,sep4cpu_proto)
