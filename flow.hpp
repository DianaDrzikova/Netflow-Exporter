/*#########################################################################
# Diana Maxima Drzikova
# xdrzik01
# 30.09.2022
# FIT VUT
# flow.hpp
###########################################################################*/

#pragma once

#ifndef FLOW_HPP
#define FLOW_HPP

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string>
#include <cstring> 
#include <iostream>
#include <array>
using namespace std;

#define __FAVOR_BSD
#include <pcap.h>
#define __FAVOR_BSD
#include <arpa/inet.h>
#define __FAVOR_BSD
#include <netinet/ether.h>
#define __FAVOR_BSD
#include <netinet/tcp.h>
#define __FAVOR_BSD
#include <netinet/ip_icmp.h>
#define __FAVOR_BSD
#include <netinet/udp.h>
#define __FAVOR_BSD
#include <netdb.h>
#include <map>
#include <vector>
#include <err.h>
#include "flowStructs.hpp"

#define STARTING_POS 2
#define ACT_TIMER 60
#define SEC 10
#define COUNT 1024
#define IP "127.0.0.1"
#define PORT 2055
#define HOSTNAME "127.0.0.1:2055"
#define ETHER_SIZE 14
#define ETHERTYPE_IP 0x0800
#define MAX 10000
#define FILTER "tcp or udp or icmp"



static int num_of_flows;
static int num_of_packets;
map< vector<u_int32_t> , struct V5Flow> map_of_flows;
int c, position = STARTING_POS, flag = 0, port = PORT; 
unsigned int active_timer = ACT_TIMER, inactive_timer = SEC, flow_cache = COUNT;
string hostname = IP, ip = "";

unsigned long current_time = 0;
unsigned long current_time_sec = 0;
unsigned long current_time_usec = 0;
unsigned long export_beg = 0;
bool export_beg_bool = true;

/** @brief Export of flows
 *
 *  @param message flow record
 *  @return Void.
 */
void export_flow(struct V5Flow message);


/** @brief Extract source and destination port number when packet has TCP protocol.
 *
 *  @param packet pacekt = data from which port is extracted.
 *  @param size_ip size of internet protocol part of the packet (for setting pointer to the right place of packet)
 *  @param keys vector with u_int32_t values used as key for map
 *  @return Void.
 */
void tcp(const u_char *packet, u_int size_ip, vector<u_int32_t> *keys);


/** @brief Extract source and destination port number when packet has UDP protocol.
 *
 *  @param packet pacekt = data from which port is extracted.
 *  @param size_ip size of internet protocol part of the packet (for setting pointer to the right place of packet)
 *  @param keys vector with u_int32_t values used as key for map
 *  @return Void.
 */
void udp(const u_char *packet, u_int size_ip, vector<u_int32_t> *keys);


/** @brief Computing destination port with icmp type and code
 *
 *  @param packet pacekt = data from which port is extracted.
 *  @param size_ip size of IP header, used for shifting
 *  @param keys vector with u_int32_t values used as key for map
 *  @return Void.
 */
void icmp(const u_char *packet, u_int size_ip,  vector<u_int32_t> *keys);


/** @brief Group flows
 *
 *  @param packet pacekt = data from which port is extracted.
 *  @param keys vector with u_int32_t values used as key for map
 *  @return Void.
 */
void group_flows(const u_char *packet, vector<u_int32_t> *keys);


/** @brief Check time of current packet, export if active or inactive
 *
 *  @return Void.
 */
void check_time();


/** @brief pcap_loop() callback function
 *  
 *  @param args optional variables
 *  @param header header of packet
 *  @param packet all of the recieved data
 *  @return Void.
 */
void packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

#endif
