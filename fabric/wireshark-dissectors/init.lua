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
-- USER_DIR is initialized in ${GLOBAL_CONFIG_DIR}/init.lua
local basedir = ( USER_DIR or persconffile_path() )..'lua/'

-- load all Lua scripts in "~/.config/wireshark/lua/" (ascending ASCII order)
for f in Dir.open(basedir, ".lua") do
    dofile(basedir..f)
end

