/*#########################################################################
# Diana Maxima Drzikova
# xdrzik01
# 30.09.2022
# FIT VUT
# flow.cpp
###########################################################################*/

#include "flow.hpp"

void empty(){
    if(!map_of_flows.empty()){
        for (auto it = map_of_flows.begin(); it != map_of_flows.end() ; ){
            export_flow(it->second);
            map_of_flows.erase(it++);
        }
    }   
}

void export_flow(struct V5Flow message){

    struct b5header header;

    num_of_flows++;

    // updating flow packet header
    header.version = htons((u_int16_t)5);
    header.count = htons(1);
    header.SysUptime = htonl(current_time - export_beg);
    header.unix_secs = htonl(current_time_sec);
    header.unix_nsecs = htonl(current_time_usec);
    header.flow_sequence = htonl(num_of_flows);
    header.engine_id = 0;
    header.engine_type = 0;
    header.sampling_interval = 0;

    // exported packet contians header and record
    struct exported exp_flow = {header, message};

    int sock;                        // socket descriptor
    int i;
    struct sockaddr_in server; // address structures of the server and the client
    struct hostent *servent;         // network host entry required by gethostbyname()
    char buffer[1024];     

    mempcpy(buffer, &exp_flow, sizeof(exp_flow));

    memset(&server,0,sizeof(server)); // erase the server structure
    server.sin_family = AF_INET;                   

    if ((servent = gethostbyname(hostname.c_str())) == NULL) // check the first parameter
        errx(1,"gethostbyname() failed\n");

    memcpy(&server.sin_addr,servent->h_addr,servent->h_length); 

    server.sin_port = htons(port);   

    if ((sock = socket(AF_INET , SOCK_DGRAM , 0)) == -1)   //create a client socket
      err(1,"socket() failed\n");
    

    if (connect(sock, (struct sockaddr *)&server, sizeof(server))  == -1)
      err(1, "connect() failed");

    i = send(sock,buffer,sizeof(exp_flow),0);     // send data to the server
    if (i == -1)                   // check if data was sent correctly
        err(1,"send() failed");
    else if (i != sizeof(exp_flow))
        err(1,"send(): buffer written partially");

    if (sizeof(exp_flow) == -1)
        err(1,"reading failed");
    close(sock);
}




void tcp(const u_char *packet, u_int size_ip, vector<u_int32_t> *keys, u_int32_t *fin_rst_flag){
    const struct tcphdr *tcp_header;
    tcp_header = (struct tcphdr *) (packet + ETHER_SIZE + size_ip);
    // adding value for crafting key
    keys->push_back( (u_int32_t) ntohs(tcp_header->th_sport));
    keys->push_back( (u_int32_t) ntohs(tcp_header->th_dport));

    // rst and fin flag for exporting tcp packet
    if(tcp_header->th_flags & TH_FIN || tcp_header->th_flags & TH_RST) *fin_rst_flag = 1;

}

void udp(const u_char *packet, u_int size_ip, vector<u_int32_t> *keys, u_int32_t *size_udp){
    const struct udphdr *udp_header;
    udp_header = (struct udphdr *) (packet + ETHER_SIZE + size_ip);
    *size_udp = 8; // header size for substraction of data added to full lengh t of one flow
    // adding value for crafting key
    keys->push_back( (u_int32_t) ntohs(udp_header->uh_sport));
    keys->push_back( (u_int32_t) ntohs(udp_header->uh_dport));
}

void icmp(const u_char *packet, u_int size_ip,  vector<u_int32_t> *keys, u_int32_t *size_icmp){
    const struct icmphdr *icmp_header;
    icmp_header = (struct icmphdr *) (packet + ETHER_SIZE + size_ip);
    *size_icmp = 8; // header size for substraction of data added to full lenght of one flow
    // adding value for crafting key
    keys->push_back( 0 );
    keys->push_back( (u_int32_t)  (icmp_header->type << 8) + icmp_header->code);
}

void check_time(){
    bool erase = false; 
    auto it = map_of_flows.begin();

    while(it != map_of_flows.end()){ // chcecking flow cache if there are any flow to be exported due to time(s) up
        if(((current_time - export_beg - ntohl(it->second.First)) >= active_timer*1000) ||
            (current_time - export_beg - ntohl(it->second.Last)) >= inactive_timer*1000){
            export_flow(it->second);
            erase = true;
        }

        if(erase){
            map_of_flows.erase(it++); //if flow has been exported, erase from flow cache
            erase = false;
        }else{
            ++it;
        }

    }
}


void group_flows(const u_char *packet, vector<u_int32_t> *keys){
    const struct ip *ip;
    ip = (struct ip *) (packet + ETHER_SIZE);
    u_int size_ip = (ip->ip_hl & 0x0f)*4, size_udp = 0, size_icmp = 0; //size of ip for skipping to get tcp, udp and icmp data

    // keys = vector of u_int32_t => IP src/dst, port src/dst, ToS
    keys->push_back(ntohl(ip->ip_src.s_addr));
    keys->push_back(ntohl(ip->ip_dst.s_addr));
    
    u_int32_t fin_rst_flag = 0;

    switch(ip->ip_p){ // checking protocol, usage for setting port parameters in key 
    case 6:
        tcp(packet, size_ip, keys, &fin_rst_flag);
        break;
    case 17:
        udp(packet, size_ip, keys, &size_udp);
        break;
    case 1:
        icmp(packet, size_ip, keys, &size_icmp);
        break;
    default:
        break;
    }
    
    keys->push_back((u_int32_t)ip->ip_tos);

    // check if there are any flows in flow cache to be exported
    check_time();

    auto it = map_of_flows.begin();
    auto oldest = map_of_flows.begin();

    if(!map_of_flows.count(*keys)){ // add new flow

        if(flow_cache == map_of_flows.size()){ // if flow cache is full export the oldest one
            while(it != map_of_flows.end()){ 
                if(ntohl(oldest->second.Last) > ntohl(it->second.Last)){ //oldest one = with smallest last time
                    oldest = it;
                }
                it++;
            }

            export_flow(oldest->second);
            map_of_flows.erase(oldest);
        }
        map_of_flows.insert({*keys, V5Flow()});
        map_of_flows[*keys].srcIP = ip->ip_src.s_addr;
        map_of_flows[*keys].dstIP = ip->ip_dst.s_addr;
        map_of_flows[*keys].nexthop = 0;
        map_of_flows[*keys].input = 0;
        map_of_flows[*keys].output = 0;
        map_of_flows[*keys].dPkts = htonl(1);
        map_of_flows[*keys].dOctets = htonl(ntohs(ip->ip_len) - size_ip - size_udp);
        map_of_flows[*keys].First = htonl(current_time - export_beg); 
        map_of_flows[*keys].Last = htonl(current_time - export_beg); 
        map_of_flows[*keys].srcPort = htons((*keys)[2]);
        map_of_flows[*keys].dstPort = htons((*keys)[3]);
        map_of_flows[*keys].tcp_flags = fin_rst_flag;
        map_of_flows[*keys].prot = ip->ip_p;
        map_of_flows[*keys].ToS = ip->ip_tos;
        map_of_flows[*keys].dst_as = 0;
        map_of_flows[*keys].src_as = 0;
        map_of_flows[*keys].src_mask = 0;
        map_of_flows[*keys].dst_mask = 0;
    }else{ // updating flow
        (map_of_flows[*keys].dPkts) += htonl(1);
        map_of_flows[*keys].dOctets += htonl(ntohs(ip->ip_len) - size_ip - size_udp);
        map_of_flows[*keys].Last = htonl(current_time - export_beg);
    }


    if(fin_rst_flag){ //exporting due to flag occur
        export_flow(map_of_flows[*keys]);
        map_of_flows.erase(*keys);
    }
}

void packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){

    const struct ether_header* ethernet;
    ethernet = (struct ether_header *) packet;

    (void)ethernet;

    vector<u_int32_t> keys;

    // updating current time
    current_time = header->ts.tv_sec*1000 + header->ts.tv_usec/1000;
    current_time_sec = header->ts.tv_sec;
    current_time_usec = header->ts.tv_usec*1000;

    if(export_beg_bool){ // boot time of exporter
        export_beg = current_time;
        export_beg_bool = false;
    }

    group_flows(packet, &keys);

}


int main(int argc, char *argv[]){

    FILE *file;
    char *endptr, filename[100];
    struct bpf_program fp;
    pcap_t *handle;
    bpf_u_int32 net;
    int index;
    

    while((c = getopt(argc, argv, "f:c:a:i:m:")) != -1){ // command line specifications
        switch (c){
        case 'f':
            strcpy(filename, argv[position]);
            flag = 1;
            break;
        case 'c':
            index = (string(argv[position])).find(":");
            hostname = string(argv[position]).substr(0, index);
            port = strtoull(string(argv[position]).substr(index + 1).c_str(), &endptr,10);
            break;
        case 'a':
            active_timer = strtoull(argv[position], &endptr, 10);
            break;
        case 'i':
            inactive_timer = strtoull(argv[position], &endptr, 10);
            break;
        case 'm':
            flow_cache = strtoull(argv[position], &endptr, 10);
            break;
        default:
            break;
        }
        position += 2;
    }

    if(flag){ //input data
        file = fopen(filename, "r");
        handle = pcap_fopen_offline(file, endptr);
    }else{
        handle = pcap_open_offline("-", endptr);
    }

    if (!handle){
        fprintf(stderr, "File error.\n");    
        return(2);
    }


    string filter = FILTER;

    // compiling filter
    if (pcap_compile(handle, &fp, filter.c_str(), 0, net) == -1) {
        fprintf(stderr, "Compiling filter error, filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return(2);
    }
    
    // setting filter
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Setting filter error, filter %s: %s\n", filter.c_str(), pcap_geterr(handle));
        return(2);
    }

    pcap_loop(handle, -1 ,packet, NULL);

    pcap_close(handle);


    empty();


    printf("Sum of exported flows: %u. Exported to %s:%d.\n", num_of_flows, hostname.c_str(), port);
    return 0;
}
