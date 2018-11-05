
P4 CORD Service Edge
====================

This repository contains a P4 program that implements
a residential network access service data plane. The data plane has been
designed to support a typical large-scale residential broadband access 
network using PPPoE for subscriber access.

The repository contains the data plane only, no control plane is included at 
the moment. The current status of the program is described in the following 
status section.

Status
------

The generic part of the service edge should be understood as
a prototype to support the subscriber termination and has not been tested
in detail yet. The code does not include a control plane.
All tests have been conducted using the Barefoot SDE 8.0.0.19 and the Barefoot
Tofino simulator.

Open tasks

- Running tests on an Barefoot Tofino hardware switch
- Testing the data plane together with a control plane and physical residential
  gateway devices

Directory Layout
----------------

'''
./p4src
The P4 source code.

./wireshark-dissectors/
Wireshark dissector for the data plane to control plane communication protocol.
'''

Build Instructions
------------------

Requirements: Barefoot SDE 8.0.0.19

```
cd $SDE
./p4_build.sh <se.p4 dir>/p4src/se.p4
```

For details on testing and the Wireshark dissectors, please refer to
`README.md` in the respective folders.

