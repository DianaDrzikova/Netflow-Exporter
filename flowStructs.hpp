#pragma once

#ifndef FLOWSTRUCTS_HPP
#define FLOWSTRUCTS_HPP

/** Flow record

srcIP        Source IP address
dstIP        Destination IP address
nexthop      IP address of next hop router
input        SNMP index of input interface
output       SNMP index of output interface
dPkts        Packets in the flow
dOctets      Total number of Layer 3 bytes in the packets of the flow
First        SysUptime at start of flow
Last         SysUptime at the time the last packet of the flow was received
srcPort      TCP/UDP source port number or equivalent
dstPort      TCP/UDP destination port number or equivalent
pad1         Unused (zero) byte
tcp_flags    Cumulative OR of TCP flags
prot         IP protocol type
ToS          IP type of service (ToS)
src_as       Autonomous system number of the source, either origin or peer
dst_as       Autonomous system number of the destination, either origin or peer
src_mask     Source address prefix mask bits
dst_mask     Destination address prefix mask bits
pad2         Unused (zero) bytes
*/
struct V5Flow{
    u_int32_t srcIP; 
    u_int32_t dstIP; 
    u_int32_t nexthop;
    u_int16_t input;
    u_int16_t output;
    u_int32_t dPkts;
    u_int32_t dOctets;
    u_int32_t First;
    u_int32_t Last;
    u_int16_t srcPort; 
    u_int16_t dstPort; 
    u_int8_t pad1 = 0;
    u_int8_t tcp_flags;
    u_int8_t prot;
    uint8_t ToS; 
    u_int16_t src_as;
    u_int16_t dst_as;
    u_int8_t src_mask;
    u_int8_t dst_mask;
    u_int16_t pad2 = 0;
};


/* Flow packet header
Bytes   Contents        Description
0-1     version         NetFlow export format version number
2-3     count           Number of flows exported in this flow frame (protocol data unit, or PDU)
4-7     SysUptime       Current time in milliseconds since the export device booted
8-11    unix_secs       Current seconds since 0000 UTC 1970
12-15   unix_nsecs      Residual nanoseconds since 0000 UTC 1970
16-19   flow_sequence   Sequence counter of total flows seen
20-23   reserved        Unused (zero) bytes
*/
struct b5header{
    uint16_t version;
    uint16_t count;
    uint32_t SysUptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence = 0;
    u_int8_t engine_type;
    u_int8_t engine_id;
    uint16_t sampling_interval;
};

/* Flow packet
header  header of flow packet
data    record of flow packet
*/
struct exported{
    struct b5header header;
    struct V5Flow data;
};


#endif

