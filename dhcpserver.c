#include <arpa/inet.h>
#include <net/if.h>     // for struct ifreq
#include <sys/types.h>
#include <sys/socket.h> // for setsockopt()
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include "dhcp.h"

void print_timestamp()
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep); 
    printf("[%d-%d-%d %d:%d:%d] ", (1900+p->tm_year),(1+p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);   
}

char *get_timestamp()
{
    static char timestr[40];
    time_t t;
    struct tm *nowtime;

    time(&t);
    nowtime = localtime(&t);
    strftime(timestr,sizeof(timestr),"[%Y-%m-%d %H:%M:%S] ",nowtime);

    return timestr;
}


void string_trim(char *str)
{
    int len = strlen(str);
    if(str[len-1] == '\n')
    {
        len--;
        str[len] = 0;   
    }
}

void change_status(int line_num)
{
    FILE *fp;  
    char line[32];
    char txt[10][20];
    int read_count = 0;
    int write_count = 0;

    if((fp = fopen(IP_FILE, "r")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  
    while((fgets(line,1024,fp) != NULL))
    {
        strcpy(txt[read_count],line);
        read_count++;
    }
    fclose(fp);

    txt[line_num-1][0] = '0';

    if((fp = fopen(IP_FILE, "w")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  

    while(write_count < read_count)
    {
        fputs(txt[write_count], fp);
        write_count++;
    }   
    fclose(fp);
}

void change_status_one()
{
    FILE *fp;  
    char line[32];
    char txt[10][20];
    int read_count = 0;
    int write_count = 0;

    if((fp = fopen(IP_FILE, "r")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  
    while((fgets(line,1024,fp) != NULL))
    {
        strcpy(txt[read_count],line);
        read_count++;
    }
    fclose(fp);

    txt[0][0] = '1';

    if((fp = fopen(IP_FILE, "w")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  

    while(write_count < read_count)
    {
        fputs(txt[write_count], fp);
        write_count++;
    }   
    fclose(fp);
}


void get_valid_ip(char *ip)
{
    FILE *fp;  
    char line[32];
    int line_count = 0;
    if((fp = fopen(IP_FILE, "r")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  
    while((fgets(line,1024,fp) != NULL))
    {
        line_count++;
        if(line[0] == '1')
            break;
    }
    fclose(fp);
    strcpy(ip,&line[2]);
    string_trim(ip);
    change_status(line_count);
}

void get_final_ip(char *ip)
{
    FILE *fp;  
    char line[32];

    if((fp = fopen(IP_FILE, "r")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  
    while((fgets(line,1024,fp) != NULL))
    {
        ;
    }
    fclose(fp);
    strncpy(ip,&line[2], strlen(&line[2]));
    string_trim(ip);
}


void add_lease(char *ip, char *mac)
{
    FILE *fp;  
    char *time;
    if((fp = fopen(LEASE_FILE, "a+")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  
    time = get_timestamp();
    fwrite(time,strlen(time), 1, fp);
    fwrite("  ",2, 1, fp);
    fwrite(ip,strlen(ip), 1, fp);
    fwrite("  ",2, 1, fp);
    fwrite(mac,strlen(mac), 1, fp);
    fwrite("\n",1, 1, fp);
    fclose(fp);
}

void remove_lease()
{
    FILE *fp;  
    // char line[1024];
    // char txt[10][1024];
    // int read_count = 0;
    // int write_count = 0;

    if((fp = fopen(LEASE_FILE, "w")) == NULL)
    {
        printf("Error in file open. \n");
        exit(-1);
    }  

    // while(write_count < read_count-1)
    // {
    //     fputs(txt[write_count], fp);
    //     write_count++;
    // }   
    fclose(fp);    
}

int get_mac_address(unsigned char *mac)
{
    struct ifreq s;
    int fd;
    int flag;
    //unsigned char arp[6];

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        printf("Socket Error");  
        exit(1); 
    }
    strcpy(s.ifr_name, DEV);
    flag = ioctl(fd, SIOCGIFHWADDR, &s);
    close(fd);

    if (flag != 0)
        return -1;

    memcpy((void *)mac, s.ifr_hwaddr.sa_data, 6);
    return 0;
}

int get_ip_address(in_addr_t *ip)
{
    struct ifreq s;
    int fd;
    int flag;
    //unsigned char arp[6];

    if ((fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0)
    {
        printf("Socket Error");  
        exit(1); 
    }
    strcpy(s.ifr_name, DEV);
    flag = ioctl(fd, SIOCGIFADDR, &s);
    close(fd);

    if (flag != 0)
        return -1;

    memcpy((void *)ip, s.ifr_addr.sa_data, 6);
    return 0;
}

u_int8_t get_packet_type(packet received)
{
    return received.options[2];
}

int fill_dhcp_option(unsigned char *options, u_int8_t type, u_int8_t *data, u_int8_t length)
{
    options[0] = type;
    options[1] = length;
    memcpy(&options[2], data, length);
    // printf("length = %d \n",length);
    // printf("type = %d \n",type);
    return length + (sizeof(u_int8_t) * 2);
}

void fill_server_commen_field(packet *p)
{
    p->op = BOOTREPLY;
    p->htype = 1;
    p->hlen  = 6;
    /* student ID  2014213092 */
    p->xid   = 0x780E73E4;   
    p->magic_cookie = DHCP_MAGIC_COOKIE;
}

void fill_offer(packet *offer_packet, packet *discover_packet, u_int32_t lease_time, char *ip)
{
    int len = 0;

    u_int8_t message_data[] = {DHCPOFFER};
    
    in_addr_t submask_data = inet_addr("255.255.255.0");
    in_addr_t router_data  = inet_addr("192.168.0.1");
    in_addr_t domain_server_data = inet_addr("192.168.0.1");
    in_addr_t server_data  = inet_addr("192.168.0.1");
    
    u_int32_t time_data;
    u_int8_t end_data[] = {0};

    time_data = htonl(lease_time);
    memset(offer_packet, 0, sizeof(packet));
    fill_server_commen_field(offer_packet);

    offer_packet->xid    = discover_packet->xid;
    offer_packet->flags  = discover_packet->flags;
    memcpy((void *)offer_packet->chaddr, discover_packet->chaddr, 6);
    
    offer_packet->yiaddr.s_addr = inet_addr(ip);

    len += fill_dhcp_option(&offer_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&offer_packet->options[len], DHO_SUBNET_MASK, (u_int8_t *)&submask_data, sizeof(submask_data));
    len += fill_dhcp_option(&offer_packet->options[len], DHO_ROUTERS, (u_int8_t *)&router_data, sizeof(router_data));
    len += fill_dhcp_option(&offer_packet->options[len], DHO_DOMAIN_NAME_SERVERS, (u_int8_t *)&domain_server_data, sizeof(domain_server_data));
    len += fill_dhcp_option(&offer_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_data, sizeof(server_data));
    len += fill_dhcp_option(&offer_packet->options[len], DHO_DHCP_LEASE_TIME, (u_int8_t *)&time_data, sizeof(time_data));

    len += fill_dhcp_option(&offer_packet->options[len], DHO_END, (u_int8_t *)&end_data, sizeof(end_data));
}

void fill_broadcast_ack(packet *ack_packet, packet *received_packet, u_int32_t lease_time, char *ip)
{
    int len = 0;
    u_int32_t time_data;
    u_int32_t renewal_time_data;
    u_int32_t rebind_time_data;
    u_int32_t student = 0x780E73E4;
    u_int8_t message_data[] = {DHCPACK};
    u_int8_t end_data[] = {0};

    in_addr_t submask_data = inet_addr("255.255.255.0");
    in_addr_t router_data  = inet_addr("192.168.0.1");
    in_addr_t domain_server_data = inet_addr("192.168.0.1");
    in_addr_t server_data  = inet_addr("192.168.0.1");

    time_data = htonl(lease_time);
    renewal_time_data = time_data / 2;
    rebind_time_data  = (u_int32_t)(time_data * 7 / 8);

    memset(ack_packet, 0, sizeof(packet));
    fill_server_commen_field(ack_packet);

    ack_packet->xid    = received_packet->xid;
    ack_packet->flags  = received_packet->flags;
    memcpy((void *)ack_packet->chaddr, received_packet->chaddr, 6);
    
    ack_packet->yiaddr.s_addr = inet_addr(ip);

    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_SUBNET_MASK, (u_int8_t *)&submask_data, sizeof(submask_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_ROUTERS, (u_int8_t *)&router_data, sizeof(router_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DOMAIN_NAME_SERVERS, (u_int8_t *)&domain_server_data, sizeof(domain_server_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_data, sizeof(server_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_LEASE_TIME, (u_int8_t *)&time_data, sizeof(time_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_RENEWAL_TIME, (u_int8_t *)&renewal_time_data, sizeof(renewal_time_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_REBINDING_TIME, (u_int8_t *)&rebind_time_data, sizeof(rebind_time_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_VENDOR_CLASS_IDENTIFIER, (u_int8_t *)&student, sizeof(student));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_END, (u_int8_t *)&end_data, sizeof(end_data));
}

void fill_unicast_ack(packet *ack_packet, packet *received_packet, u_int32_t lease_time, char *ip)
{
    int len = 0;
    u_int32_t time_data;
    u_int8_t message_data[] = {DHCPACK};
    u_int8_t end_data[] = {0};

    in_addr_t submask_data = inet_addr("255.255.255.0");
    in_addr_t router_data  = inet_addr("192.168.0.1");
    in_addr_t domain_server_data = inet_addr("192.168.0.1");
    in_addr_t server_data  = inet_addr("192.168.0.1");

    time_data = htonl(lease_time);
    memset(ack_packet, 0, sizeof(packet));
    fill_server_commen_field(ack_packet);

    ack_packet->xid    = received_packet->xid;
    ack_packet->flags  = 0x0000;
    memcpy((void *)ack_packet->chaddr, received_packet->chaddr, 6);
    
    ack_packet->yiaddr.s_addr = inet_addr(ip);

    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_SUBNET_MASK, (u_int8_t *)&submask_data, sizeof(submask_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_ROUTERS, (u_int8_t *)&router_data, sizeof(router_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DOMAIN_NAME_SERVERS, (u_int8_t *)&domain_server_data, sizeof(domain_server_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_data, sizeof(server_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_LEASE_TIME, (u_int8_t *)&time_data, sizeof(time_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_END, (u_int8_t *)&end_data, sizeof(end_data));
}

void fill_nak(packet *ack_packet, packet *received_packet)
{
    int len = 0;
    u_int32_t time_data;
    u_int8_t message_data[] = {DHCPNAK};
    u_int8_t end_data[] = {0};

    in_addr_t server_data  = inet_addr("192.168.0.1");

    memset(ack_packet, 0, sizeof(packet));
    fill_server_commen_field(ack_packet);

    ack_packet->xid    = received_packet->xid;
    ack_packet->flags  = received_packet->flags;
    memcpy((void *)ack_packet->chaddr, received_packet->chaddr, 6);
    
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_data, sizeof(server_data));
    len += fill_dhcp_option(&ack_packet->options[len], DHO_END, (u_int8_t *)&end_data, sizeof(end_data));
}

int determine_request_ip(packet *p)
{   
    char final_ip[32] = {0};
    char *ip;

    int final_n = 0;
    int n = 0;

    get_final_ip((char *) final_ip);
    ip = inet_ntoa(*((struct in_addr *)&p->options[5]));

    final_n = strlen(final_ip);
    n = strlen(ip);

    // printf("final_ip is %s\n", final_ip);
    // printf("ip is %s\n", ip);
    // printf("final_ip is %c\n", final_ip[final_n-2]);
    // printf("ip is %c\n", ip[n-1]);

    // printf("final : %d", atoi(final_ip[final_n-2]));
    // printf("your  : %d", atoi(((char *)(*((u_int16_t *)&ip[n-2]))));
    // printf("your  : %d", atoi((char *)((u_int16_t *)&ip[n-2])));
    if ((u_int32_t)p->ciaddr.s_addr == 0)
    {
        return 1;
    }
    else
    {   
        if (ip[n-2] == '.')
        {
            if ( final_ip[final_n-2] >= ip[n-1])
            {
                return 0;
            }            
        }
    }
    return -1;
}   

void send_to(int socket, const void* buffer, int buffer_length, int flags, const struct sockaddr* dest_addr, socklen_t dest_len)
{
    int res;
    if ((res = sendto(socket, buffer, buffer_length, 0, dest_addr, dest_len)) < 0) {
        printf("sendto failed. \n");
        exit(1);
    }
    print_timestamp();
    printf("Sending packet to: %s(%d)\n",inet_ntoa(((struct sockaddr_in*)dest_addr)->sin_addr),ntohs(((struct sockaddr_in*)dest_addr)->sin_port));
}

void recv_from(int socket, void* buffer, int buffer_length, int flags, struct sockaddr* address, socklen_t* address_len)
{
    int res;
    if ((res = recvfrom(socket, buffer, buffer_length, flags, address, address_len)) < 0) {
        printf("recvfrom failed. \n");
        exit(1);
    }
    print_timestamp();
    printf("Recieve packet from: %s(%d)\n", inet_ntoa(((struct sockaddr_in*)address)->sin_addr), ntohs(((struct sockaddr_in*)address)->sin_port));
}

int main(int argc, char **argv) 
{
    int broadcast_sock; /* Socket descriptor */
    int unicast_sock;
    char *timestamp;
    struct ifreq netcard;
    struct sockaddr_in clntAddr;
    struct sockaddr_in servAddr;
    struct sockaddr_in uni_clntAddr;
    struct sockaddr_in uni_servAddr;

    struct sockaddr_in fromAddr;
    struct in_addr received_addr;
    packet send_packet, receive_packet;

    int res;
    int clntPort; /* client port */
    int servPort; /* server port */
    int i = 1;
    int lease_time;
    u_int8_t type;

    unsigned int fromSize;
    char ip[32] = {0};
    char *final_ip;

    if ((argc < 1) || (argc > 3)) /* Test for correct number of arguments */
    {
        printf("Usage: %s [lease_time]\n", argv[0]);
        exit(1);
    }

    if (argc == 2)
    {
        lease_time = atoi(argv[1]);
    }
    else
    {
        /* Default 30s */
        lease_time = 30;
    }

    clntPort = DHCP_CLIENT_PORT;
    servPort = DHCP_SERVER_PORT;

    /* Create a datagram/UDP socket */
    if ((broadcast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
    {
        printf("socket() failed.\n");
        exit(1);
    }

    strcpy(netcard.ifr_name, DEV);
    socklen_t len = sizeof(i);
    /* Allow socket to broadcast */
    setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &i, len);

    /* Set socket to interface DEV */
    if(setsockopt(broadcast_sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&netcard, sizeof(netcard)) < 0)
    {
        printf("bind socket to %s error\n", DEV);
    }

    /* Zero out structure */
    memset(&clntAddr, 0, sizeof(clntAddr));
    clntAddr.sin_family = AF_INET;
    clntAddr.sin_port   = htons(clntPort);
    clntAddr.sin_addr.s_addr = inet_addr("255.255.255.255");

    /* Construct the server address structure */
    /*Zero out structure*/
    memset(&servAddr, 0, sizeof(servAddr));
    /* Internet addr family */
    servAddr.sin_family = AF_INET; 
    /*Server IP address*/
    servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
    /* Server port */
    servAddr.sin_port = htons(servPort);

    if((bind(broadcast_sock, (struct sockaddr *)&servAddr, sizeof(servAddr))) < 0)
    {
        printf("bind() failed.\n");
        exit(1);
    }

    print_timestamp();printf("Waiting for packet.\n");

    while(1)
    {   

        fromSize = sizeof(fromAddr);
        /* Block until receive message from a client */
        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
        print_timestamp();
        printf("Handling client %s\n",inet_ntoa(fromAddr.sin_addr));
        type = get_packet_type(receive_packet);

        if(type == DHCPDISCOVER)
        {
            get_valid_ip(ip);
            fill_offer(&send_packet, &receive_packet, (u_int32_t)lease_time, (char *)ip);
            send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&clntAddr, sizeof(clntAddr));
            //recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
        }
        if(type == DHCPREQUEST)
        {   
            res = determine_request_ip(&receive_packet);
            // printf("%d  ip is %s\n", res, inet_ntoa(*((struct in_addr *)&receive_packet.options[5])));

            if ( res == 1)
            {
                fill_broadcast_ack(&send_packet, &receive_packet, (u_int32_t)lease_time, (char *)ip);
                send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&clntAddr, sizeof(clntAddr));
                add_lease(ip,"08:00:27:d3:fd:ae");
            }
            else if (res == 0)
            {
                close(broadcast_sock);
                /* Create a datagram/UDP socket */
                if ((unicast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    exit(1);
                }


                memset(&uni_clntAddr, 0, sizeof(uni_clntAddr));
                uni_clntAddr.sin_family = AF_INET;
                uni_clntAddr.sin_port   = htons(clntPort);
                uni_clntAddr.sin_addr.s_addr   = inet_addr(ip);

                memset(&uni_servAddr, 0, sizeof(uni_servAddr));
                uni_servAddr.sin_family = AF_INET; 
                uni_servAddr.sin_addr.s_addr = inet_addr("192.168.0.1");
                uni_servAddr.sin_port = htons(servPort);

                if((bind(unicast_sock, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    exit(1);
                }

                fill_unicast_ack(&send_packet, &receive_packet, (u_int32_t)lease_time, (char *)ip);
                // send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&clntAddr, sizeof(clntAddr));
                send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_clntAddr, sizeof(uni_clntAddr));
                add_lease(ip,"08:00:27:d3:fd:ae");

                close(unicast_sock);
                /* Create a datagram/UDP socket */
                if ((broadcast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    exit(1);
                }

                strcpy(netcard.ifr_name, DEV);
                socklen_t len = sizeof(i);
                /* Allow socket to broadcast */
                setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &i, len);

                /* Set socket to interface DEV */
                if(setsockopt(broadcast_sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&netcard, sizeof(netcard)) < 0)
                {
                    printf("bind socket to %s error\n", DEV);
                }

                /* Zero out structure */
                memset(&clntAddr, 0, sizeof(clntAddr));
                clntAddr.sin_family = AF_INET;
                clntAddr.sin_port   = htons(clntPort);
                clntAddr.sin_addr.s_addr = inet_addr("255.255.255.255");

                /* Construct the server address structure */
                /*Zero out structure*/
                memset(&servAddr, 0, sizeof(servAddr));
                /* Internet addr family */
                servAddr.sin_family = AF_INET; 
                /*Server IP address*/
                servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                /* Server port */
                servAddr.sin_port = htons(servPort);

                if((bind(broadcast_sock, (struct sockaddr *)&servAddr, sizeof(servAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    exit(1);
                }
            }
            else
            {
                close(broadcast_sock);
                /* Create a datagram/UDP socket */
                if ((unicast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    exit(1);
                }

                memset(&uni_clntAddr, 0, sizeof(uni_clntAddr));
                uni_clntAddr.sin_family = AF_INET;
                uni_clntAddr.sin_port   = htons(clntPort);
                uni_clntAddr.sin_addr.s_addr   = inet_addr(ip);

                memset(&uni_servAddr, 0, sizeof(uni_servAddr));
                uni_servAddr.sin_family = AF_INET; 
                uni_servAddr.sin_addr.s_addr = inet_addr("192.168.0.1");
                uni_servAddr.sin_port = htons(servPort);

                if((bind(unicast_sock, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    exit(1);
                }              
                
                fill_nak(&send_packet, &receive_packet);
                send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_clntAddr, sizeof(uni_clntAddr));

                close(unicast_sock);
                /* Create a datagram/UDP socket */
                if ((broadcast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    exit(1);
                }

                strcpy(netcard.ifr_name, DEV);
                socklen_t len = sizeof(i);
                /* Allow socket to broadcast */
                setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &i, len);

                /* Set socket to interface DEV */
                if(setsockopt(broadcast_sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&netcard, sizeof(netcard)) < 0)
                {
                    printf("bind socket to %s error\n", DEV);
                }

                /* Zero out structure */
                memset(&clntAddr, 0, sizeof(clntAddr));
                clntAddr.sin_family = AF_INET;
                clntAddr.sin_port   = htons(clntPort);
                clntAddr.sin_addr.s_addr = inet_addr("255.255.255.255");

                /* Construct the server address structure */
                /*Zero out structure*/
                memset(&servAddr, 0, sizeof(servAddr));
                /* Internet addr family */
                servAddr.sin_family = AF_INET; 
                /*Server IP address*/
                servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                /* Server port */
                servAddr.sin_port = htons(servPort);

                if((bind(broadcast_sock, (struct sockaddr *)&servAddr, sizeof(servAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    exit(1);
                }
            }
        }
        else if(type == DHCPRELEASE)
        {
            change_status_one();
            remove_lease();
        }
        else if(type == DHCPINFORM)
        {
            fill_broadcast_ack(&send_packet, &receive_packet, (u_int32_t)lease_time, (char *)ip);
            send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&clntAddr, sizeof(clntAddr));
        }
        printf("Waiting for packet.\n");
    }
}