# Generic P4 service edge code.

## Platforms

- bmv2 (a.k.a. behavioral-model)

## Supports

User-plane functionality for:

- PPPoE termination
- Reverse-path filtering (MAC, IPv4/v6)
- Metering
- TR-101 double-VLAN termination
- 2-label MPLS termination (label behavior depends on control plane)
- Routing, ACLs

## Currently missing:

- Control plane,
- Fully-fledged fabric integration,
- MTU handling

## Build Instructions

- Refer to the specific `platf_*` directory on how to build for your platform. 
