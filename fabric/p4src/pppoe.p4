/*
* Copyright 2018-present Open Networking Foundation
*
* Contributed and sponsored by Deutsche Telekom AG.
* Originally developed as part of the D-Nets 6 P4 Service Edge project
* in collaboration with Technische Universitaet Darmstadt.
* Authors: Jeremias Blendin, Leonhard Nobach
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
* For details see the file LICENSE in the top project directory.
*/


#define PPPOE_PROTO_DISCOVERY 0
#define PPPOE_PROTO_SESSION 1


header_type pppoe_md_t {
    fields {
        ppp_proto : 1;
        pad_1: 7;
        protocol : 16; // PPP protocol field
        totalLength : 16; // PPP lengths field
        mru : 16; // PPP maximum receive unit (RFC 4638)
        mru_check : 16 (saturating);
    }
}

header_type pppoe_t {
    fields {
        version : 4;
        typeID : 4;
        code : 8;
        sessionID : 16;
        totalLength : 16;
    }
}

header_type pppoes_protocol_t {
    fields {
        protocol : 16;
        /*
         * See http://www.iana.org/assignments/ppp-numbers/ppp-numbers.xhtml
         * Dataplane: IP:  0021, IPv6: 0057,
         * Control plane: LCP: c021, IPv6CP: 8057
         */
    }
}

header pppoe_t pppoe;
header pppoes_protocol_t pppoes_protocol;
