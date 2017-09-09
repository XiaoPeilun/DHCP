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
#include <errno.h>
#include <fcntl.h>
#include "dhcp.h"

const int BUFFERSIZE=80;
char buffer[80];

void print_timestamp()
{
    time_t timep;
    struct tm *p;
    time(&timep);
    p = localtime(&timep); 
    printf("[%d-%d-%d %d:%d:%d] ", (1900+p->tm_year),(1+p->tm_mon), p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec);   
}

int get_mac_address(u_int8_t *mac)
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

int get_local_ip(char *ip)
{
    char *temp = NULL;
    int inet_sock;
    struct ifreq ifr;

    inet_sock = socket(AF_INET, SOCK_DGRAM, 0); 

    memset(ifr.ifr_name, 0, sizeof(ifr.ifr_name));
    memcpy(ifr.ifr_name, DEV, 4);

    if(0 != ioctl(inet_sock, SIOCGIFADDR, &ifr)) 
    {   
        perror("ioctl error");
        return -1;
    }

    temp = inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr);     
    memcpy(ip, temp, strlen(temp));

    close(inet_sock);
    return 0;
}

void set_ip(struct in_addr ipaddr)  
{  
    int sock_set_ip;       
    struct sockaddr_in sin_set_ip;       
    struct ifreq ifr_set_ip;       
  
    memset(&ifr_set_ip,0,sizeof(ifr_set_ip));       
    strcpy(ifr_set_ip.ifr_name, DEV);

    if((sock_set_ip = socket( AF_INET, SOCK_STREAM, 0 )) < 0)    
    {       
        printf("set_ip() socket error. \n");      
        exit(1);     
    }       
  
    memset(&sin_set_ip, 0, sizeof(sin_set_ip));       

    sin_set_ip.sin_family = AF_INET;       
    sin_set_ip.sin_addr = ipaddr;

    memcpy(&ifr_set_ip.ifr_addr, &sin_set_ip, sizeof(sin_set_ip));       
    
    if( ioctl( sock_set_ip, SIOCSIFADDR, &ifr_set_ip) < 0 )       
    {       
        printf( "set_ip() SIOCSIFADDR error. \n");       
        exit(1);       
    }       
    ifr_set_ip.ifr_flags |= IFF_UP |IFF_RUNNING;        
    if( ioctl( sock_set_ip, SIOCSIFFLAGS, &ifr_set_ip ) < 0 )       
    {       
         printf("set_ip() SIOCSIFFLAGS error. \n");       
         exit(1);      
    }       
    close(sock_set_ip);         
}  

int fill_dhcp_option(unsigned char *options, u_int8_t type, u_int8_t *data, u_int8_t length)
{
    options[0] = type;
    options[1] = length;
    memcpy(&options[2], data, length);

    return length + (sizeof(u_int8_t) * 2);
}

void fill_client_commen_field(packet *p)
{
    p->op = BOOTREQUEST;
    p->htype = 1;
    p->hlen  = 6;
    p->hops  = 0;
    p->xid   = 0x780E73E4;   // student ID  2014213092
    p->secs  = 0;
    get_mac_address(p->chaddr);

    p->magic_cookie = DHCP_MAGIC_COOKIE;
}

void fill_inform(packet *inform_packet)
{
    int len = 0;
    u_int8_t message_data[] = {DHCPINFORM}; 
    u_int8_t end_data = 0;
    u_int8_t parameter_req_list[] = {DHO_SUBNET_MASK, DHO_ROUTERS, DHO_DOMAIN_NAME_SERVERS, DHO_DHCP_LEASE_TIME,DHO_DHCP_RENEWAL_TIME,DHO_DHCP_REBINDING_TIME,DHO_VENDOR_CLASS_IDENTIFIER, DHO_DHCP_SERVER_IDENTIFIER};
    char ip[32] = {0};

    memset(inform_packet, 0, sizeof(packet));
    fill_client_commen_field(inform_packet);
    inform_packet->flags  = 0x0080;

    get_local_ip((char *)ip);
    //printf("%s  \n",ip);
    inform_packet->ciaddr.s_addr = inet_addr(ip);

    len += fill_dhcp_option(&inform_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&inform_packet->options[len], DHO_DHCP_PARAMETER_REQUEST_LIST, (u_int8_t *)&parameter_req_list, sizeof(parameter_req_list));
    len += fill_dhcp_option(&inform_packet->options[len], DHO_END, &end_data, sizeof(end_data));

}

void fill_discover(packet *discover_packet)
{   
    int len = 0;
    u_int8_t message_data[] = {DHCPDISCOVER};
    u_int8_t end_data = 0;   
    u_int8_t parameter_req_list[] = {DHO_SUBNET_MASK, DHO_ROUTERS, DHO_DOMAIN_NAME_SERVERS, DHO_DHCP_LEASE_TIME, DHO_DHCP_SERVER_IDENTIFIER};

    memset(discover_packet, 0, sizeof(packet));
    fill_client_commen_field(discover_packet);

    discover_packet->flags = 0x0080;

    len += fill_dhcp_option(&discover_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&discover_packet->options[len], DHO_DHCP_PARAMETER_REQUEST_LIST, (u_int8_t *)&parameter_req_list, sizeof(parameter_req_list));
    len += fill_dhcp_option(&discover_packet->options[len], DHO_END, &end_data, sizeof(end_data));
}

void fill_broadcast_request(packet *request_packet, packet *offer_packet)
{
    int len = 0;
    u_int32_t addr_data;
    u_int32_t server_addr_data;
    u_int8_t message_data[] = {DHCPREQUEST}; 
    u_int8_t end_data = 0;
    u_int8_t parameter_req_list[] = {DHO_SUBNET_MASK, DHO_ROUTERS, DHO_DOMAIN_NAME_SERVERS};
    
    server_addr_data = *((u_int32_t *)&offer_packet->options[23]);
    memset(request_packet, 0, sizeof(packet));
    fill_client_commen_field(request_packet);

    addr_data = (u_int32_t)offer_packet->yiaddr.s_addr; 

    request_packet->xid   = offer_packet->xid; 
    request_packet->flags = 0x0080;

    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_REQUESTED_IP, (u_int8_t *)&addr_data, sizeof(addr_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_addr_data, sizeof(server_addr_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_PARAMETER_REQUEST_LIST, (u_int8_t *)&parameter_req_list, sizeof(parameter_req_list));
    len += fill_dhcp_option(&request_packet->options[len], DHO_END, &end_data, sizeof(end_data));
}

void fill_unicast_request(packet *request_packet, packet *offer_packet, struct in_addr now_ip, struct in_addr wanted_addr)
{
    int len = 0;
    u_int32_t addr_data = 0;
    u_int32_t server_addr_data;
    u_int8_t message_data[] = {DHCPREQUEST}; 
    u_int8_t end_data = 0;
    u_int8_t parameter_req_list[] = {DHO_SUBNET_MASK, DHO_ROUTERS, DHO_DOMAIN_NAME_SERVERS};

    server_addr_data = *((u_int32_t *)&offer_packet->options[23]);
    memset(request_packet, 0, sizeof(packet));
    fill_client_commen_field(request_packet);

    request_packet->ciaddr = now_ip;
    // printf("%d\n", (u_int32_t)wanted_addr.s_addr);
    // printf("%s\n", inet_ntoa(wanted_addr));

    if((u_int32_t)wanted_addr.s_addr != 0)
        addr_data = wanted_addr.s_addr; 
    else
    {
        addr_data = offer_packet->yiaddr.s_addr;
    }

    request_packet->xid   = offer_packet->xid; 
    request_packet->flags = 0x0000;

    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_REQUESTED_IP, (u_int8_t *)&addr_data, sizeof(addr_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_addr_data, sizeof(server_addr_data));
    len += fill_dhcp_option(&request_packet->options[len], DHO_DHCP_PARAMETER_REQUEST_LIST, (u_int8_t *)&parameter_req_list, sizeof(parameter_req_list));
    len += fill_dhcp_option(&request_packet->options[len], DHO_END, &end_data, sizeof(end_data));
}

void fill_release(packet *release_packet)
{   
    int len = 0;
    u_int8_t message_data[] = {DHCPRELEASE};
    u_int8_t end_data = 0;
    char ip[32] = {0};
    in_addr_t server_addr_data =  inet_addr("192.168.0.1");

    memset(release_packet, 0, sizeof(packet));
    fill_client_commen_field(release_packet);

    if (get_local_ip((char *)ip) == -1)
        release_packet->ciaddr.s_addr = inet_addr("0.0.0.0");
    else
    {
        release_packet->ciaddr.s_addr = inet_addr(ip);
    }

    len += fill_dhcp_option(&release_packet->options[len], DHO_DHCP_MESSAGE_TYPE, (u_int8_t *)&message_data, sizeof(message_data));
    len += fill_dhcp_option(&release_packet->options[len], DHO_DHCP_SERVER_IDENTIFIER, (u_int8_t *)&server_addr_data, sizeof(server_addr_data));
    len += fill_dhcp_option(&release_packet->options[len], DHO_END, &end_data, sizeof(end_data));
}

void send_to(int socket, const void* buffer, int buffer_length, int flags, const struct sockaddr* dest_addr, socklen_t dest_len)
{
    int res;
    if ((res = sendto(socket, buffer, buffer_length, 0, dest_addr, dest_len)) < 0) {
        printf("%d : sendto failed. \n", res);
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

char *get_command(int *input_len)
{
    char lc_char;
    char *get_in;
    (*input_len) = 0; 

    lc_char = getchar();
    while(lc_char != '\n' && (*input_len) < BUFFERSIZE)
    {
            buffer[(*input_len) ++] = lc_char;
        lc_char = getchar();
    }

    if((*input_len) >= BUFFERSIZE) {
       printf("Your command too long ! Please renter your command !\n");
       (*input_len) = 0;     /* Reset */
       gets(buffer);
       strcpy(buffer,"");
       get_in=NULL;
           return NULL;
    }
    else  
        buffer[(*input_len)] = '\0'; 

    if((*input_len)==0)
        return NULL;

    get_in = (char *)malloc(sizeof(char) * ((*input_len) + 1));
    strcpy(get_in, buffer);
    strcpy(buffer,"");
    return get_in;
}

void interact_mode()
{
    int broadcast_sock; /* Socket descriptor */
    int unicast_sock;
    struct ifreq netcard;
    struct sockaddr_in clntAddr;
    struct sockaddr_in servAddr;
    struct sockaddr_in uni_clntAddr;
    struct sockaddr_in uni_servAddr;

    struct sockaddr_in fromAddr;
    struct in_addr wanted_addr; 
    struct in_addr received_addr;
    packet send_packet, receive_packet;
    int clntPort; /* client port */
    int servPort; /* server port */
    int i = 1;
    int lease_time;
    int res;
    unsigned int fromSize;
    struct timeval timeout;

    char *input = NULL;
    int command_len = 0;

    char ip[32] = {0};

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
    clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
    {
        printf("bind() failed.\n");
        exit(1);
    }

    /* Construct the server address structure */
    /*Zero out structure*/
    memset(&servAddr, 0, sizeof(servAddr));
    /* Internet addr family */
    servAddr.sin_family = AF_INET; 
    /*Server IP address*/
    servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
    /* Server port */
    servAddr.sin_port = htons(servPort);

    while(1)
    {   
        command_len = 0;
        printf(">>");
        if(input)
            free(input);
        input = get_command(&command_len);
        if(input)
        {
            if(strcmp(input, "release") == 0)
            {
                fill_release(&send_packet);
                send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
                received_addr.s_addr =  inet_addr("0.0.0.0");
                set_ip(received_addr);
            }
            else if(strcmp(input, "discover") == 0)
            {
                fill_discover(&send_packet);
                send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr)); 
                fromSize = sizeof(fromAddr);
                recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
            }
            else if(strcmp(input, "request") == 0)
            {
                fill_broadcast_request(&send_packet, &receive_packet);
                send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
                fromSize = sizeof(fromAddr);
                recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
                received_addr = receive_packet.yiaddr;      
                set_ip(received_addr);
                lease_time = htonl(*((int *)&receive_packet.options[29]));
            }
            else if(strcmp(input, "inform") == 0)
            {
                fill_inform(&send_packet);
                send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
            }
            else if(strcmp(input, "renew") == 0)
            {
                close(broadcast_sock);
                /* Zero out structure */

                    /* Create a datagram/UDP socket */
                if ((unicast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    exit(1);
                }

                memset(&uni_clntAddr, 0, sizeof(uni_clntAddr));
                uni_clntAddr.sin_family = AF_INET;
                uni_clntAddr.sin_port   = htons(clntPort);
                uni_clntAddr.sin_addr   = received_addr;

                memset(&uni_servAddr, 0, sizeof(uni_servAddr));
                uni_servAddr.sin_family = AF_INET; 
                uni_servAddr.sin_addr.s_addr = inet_addr("192.168.0.1");
                uni_servAddr.sin_port = htons(servPort);

                if((bind(unicast_sock, (struct sockaddr *)&uni_clntAddr, sizeof(uni_clntAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    break;
                }

                timeout.tv_usec = 0;
                timeout.tv_sec  = lease_time * 3 / 8;
                if((setsockopt(unicast_sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval))) < 0)
                {
                    printf("socket option  SO_RCVTIMEO not support\n");
                    break;
                }

                fill_unicast_request(&send_packet, &receive_packet, received_addr, wanted_addr);
                send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr));

                // return -1 if timeout
                res = recvfrom(unicast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

                // printf("\n%d\n",res);

                if(res==-1 && errno==EAGAIN)
                {
                    print_timestamp();
                    printf("t2 timeout!\n");

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
                    clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

                    if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
                    {
                        printf("bind() failed.\n");
                        exit(1);
                    }

                    /* Construct the server address structure */
                    /*Zero out structure*/
                    memset(&servAddr, 0, sizeof(servAddr));
                    /* Internet addr family */
                    servAddr.sin_family = AF_INET; 
                    /*Server IP address*/
                    servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
                    /* Server port */
                    servAddr.sin_port = htons(servPort);

                    fill_broadcast_request(&send_packet, &receive_packet);
                    send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));

                    sleep( lease_time/ 8 );
                    print_timestamp();
                    printf("Total timeout and no response, begin address acquisitic.\n");

                    fill_discover(&send_packet);
                    send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
                    
                    fromSize = sizeof(fromAddr);
                    recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);     
                }
                else
                {
                    print_timestamp();
                    printf("Recieve packet from: 192.168.0.1(67)\n");
                }

                close(unicast_sock);
                /* Create a datagram/UDP socket */
                if ((broadcast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
                {
                    printf("socket() failed.\n");
                    break;
                }

                strcpy(netcard.ifr_name, DEV);
                socklen_t len = sizeof(i);
                /* Allow socket to broadcast */
                setsockopt(broadcast_sock, SOL_SOCKET, SO_BROADCAST, &i, len);


                /* Set socket to interface DEV */
                if(setsockopt(broadcast_sock, SOL_SOCKET, SO_BINDTODEVICE, (char *)&netcard, sizeof(netcard)) < 0)
                {
                    printf("bind socket to %s error\n", DEV);
                    break;
                }

                /* Zero out structure */
                memset(&clntAddr, 0, sizeof(clntAddr));
                clntAddr.sin_family = AF_INET;
                clntAddr.sin_port   = htons(clntPort);
                clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

                if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
                {
                    printf("bind() failed.\n");
                    break;
                }

                /* Construct the server address structure */
                /*Zero out structure*/
                memset(&servAddr, 0, sizeof(servAddr));
                /* Internet addr family */
                servAddr.sin_family = AF_INET; 
                /*Server IP address*/
                servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
                /* Server port */
                servAddr.sin_port = htons(servPort);
            }
            else if(strcmp(input, "ip") == 0)
            {
                if (get_local_ip((char *)ip) == -1)
                    printf("IP: 0.0.0.0\n");
                else 
                {
                    printf("IP: %s\n",ip);                    
                }
            }
            else
            {
                printf("Bad command. \n");
            }
        }
    }
}

int main(int argc, char **argv) 
{   
    int broadcast_sock; /* Socket descriptor */
    int unicast_sock;
    struct ifreq netcard;
    struct sockaddr_in clntAddr;
    struct sockaddr_in servAddr;
    struct sockaddr_in uni_clntAddr;
    struct sockaddr_in uni_servAddr;

    struct sockaddr_in fromAddr;
    struct in_addr wanted_addr; 
    struct in_addr received_addr;
    packet send_packet, receive_packet;
    char *commond;
    int clntPort; /* client port */
    int servPort; /* server port */
    int i = 1;
    int lease_time;
    int res;
    unsigned int fromSize;
    struct timeval timeout;

    if ((argc < 2) || (argc > 4)) /* Test for correct number of arguments */
    {
        printf("Usage: %s <commond> [desired_address]\n", argv[0]);
        exit(1);
    }
    commond = argv[1];

    if (strcmp(commond, "--interact") == 0)
    {
        interact_mode();
    }

    if (argc == 3)
    {
        wanted_addr.s_addr = inet_addr(argv[2]);
    }
    else
    {
        wanted_addr.s_addr = 0;
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
    clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

    if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
    {
        printf("bind() failed.\n");
        exit(1);
    }

    /* Construct the server address structure */
    /*Zero out structure*/
    memset(&servAddr, 0, sizeof(servAddr));
    /* Internet addr family */
    servAddr.sin_family = AF_INET; 
    /*Server IP address*/
    servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
    /* Server port */
    servAddr.sin_port = htons(servPort);

    if (strcmp(commond, "--default") == 0)
    {
        fill_discover(&send_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
        
        fromSize = sizeof(fromAddr);
        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

        fill_broadcast_request(&send_packet, &receive_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));

        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
        /* successfully receive DHCPOFFER */
        /* Get the IP address given by the server */
        received_addr = receive_packet.yiaddr;      
        set_ip(received_addr);
        lease_time = htonl(*((int *)&receive_packet.options[29]));

        close(broadcast_sock);

        /* Create a datagram/UDP socket */
        if ((unicast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        {
            printf("socket() failed.\n");
            exit(1);
        }

        /* Zero out structure */
        memset(&uni_clntAddr, 0, sizeof(uni_clntAddr));
        uni_clntAddr.sin_family = AF_INET;
        uni_clntAddr.sin_port   = htons(clntPort);
        uni_clntAddr.sin_addr   = received_addr;

        memset(&uni_servAddr, 0, sizeof(uni_servAddr));
        uni_servAddr.sin_family = AF_INET; 
        uni_servAddr.sin_addr.s_addr = inet_addr("192.168.0.1");
        uni_servAddr.sin_port = htons(servPort);

        if((bind(unicast_sock, (struct sockaddr *)&uni_clntAddr, sizeof(uni_clntAddr))) < 0)
        {
            printf("bind() failed.\n");
            exit(1);
        }
        print_timestamp();
        printf("Total lease time : %d\n", lease_time);
        sleep(lease_time/2);

        print_timestamp();
        printf("t1 timeout!\n");

        timeout.tv_usec = 0;
        timeout.tv_sec  = lease_time * 3 / 8;
        if((setsockopt(unicast_sock,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(struct timeval))) < 0)
        {
            printf("socket option  SO_RCVTIMEO not support\n");
        }

        fill_unicast_request(&send_packet, &receive_packet, received_addr, wanted_addr);
        send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr));

        // return -1 if timeout
        res = recvfrom(unicast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

        // printf("\n%d\n",res);

        if(res==-1 && errno==EAGAIN)
        {
            print_timestamp();
            printf("t2 timeout!\n");

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
            clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

            if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
            {
                printf("bind() failed.\n");
                exit(1);
            }

            /* Construct the server address structure */
            /*Zero out structure*/
            memset(&servAddr, 0, sizeof(servAddr));
            /* Internet addr family */
            servAddr.sin_family = AF_INET; 
            /*Server IP address*/
            servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
            /* Server port */
            servAddr.sin_port = htons(servPort);

            fill_broadcast_request(&send_packet, &receive_packet);
            send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));

            sleep( lease_time/ 8 );
            print_timestamp();
            printf("Total timeout and no response, begin address acquisitic.\n");

            fill_discover(&send_packet);
            send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
            
            fromSize = sizeof(fromAddr);
            recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);     
        }
        else
        {
            print_timestamp();
            printf("Recieve packet from: 192.168.0.1(67)\n");
        }

        while(1)
        {
            lease_time = htonl(*((int *)&receive_packet.options[29]));
            print_timestamp();
            printf("Lease time : %d\n", lease_time);
            sleep(lease_time/2);

            fill_unicast_request(&send_packet, &receive_packet, received_addr, wanted_addr);
            send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr));
            fromSize = sizeof(fromAddr);
            recv_from(unicast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

        }
    }
    else if (strcmp(commond, "--release") == 0)
    {   
        fill_release(&send_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
        received_addr.s_addr =  inet_addr("0.0.0.0");
        set_ip(received_addr);
    }
    else if (strcmp(commond, "--renew") == 0)
    {

        fill_discover(&send_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
        
        fromSize = sizeof(fromAddr);
        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

        fill_broadcast_request(&send_packet, &receive_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));

        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
        /* successfully receive DHCPOFFER */
        /* Get the IP address given by the server */
        received_addr = receive_packet.yiaddr;      
        set_ip(received_addr);
        lease_time = htonl(*((int *)&receive_packet.options[29]));

        close(broadcast_sock);

        if ((unicast_sock = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
        {
            printf("socket() failed.\n");
            exit(1);
        }
        memset(&uni_clntAddr, 0, sizeof(uni_clntAddr));
        uni_clntAddr.sin_family = AF_INET;
        uni_clntAddr.sin_port   = htons(clntPort);
        uni_clntAddr.sin_addr   = received_addr;

        memset(&uni_servAddr, 0, sizeof(uni_servAddr));
        uni_servAddr.sin_family = AF_INET; 
        uni_servAddr.sin_addr.s_addr = inet_addr("192.168.0.1");
        uni_servAddr.sin_port = htons(servPort);

        if((bind(unicast_sock, (struct sockaddr *)&uni_clntAddr, sizeof(uni_clntAddr))) < 0)
        {
            printf("bind() failed.\n");
            exit(1);
        }
        print_timestamp();
        printf("Total lease time : %d\n", lease_time);
        sleep(lease_time/2);

        print_timestamp();
        printf("t1 timeout!\n");

        fill_unicast_request(&send_packet, &receive_packet, received_addr, wanted_addr); 
        send_to(unicast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&uni_servAddr, sizeof(uni_servAddr));
        recv_from(unicast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

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
        clntAddr.sin_addr.s_addr = htonl(INADDR_ANY);

        if((bind(broadcast_sock, (struct sockaddr *)&clntAddr, sizeof(clntAddr))) < 0)
        {
            printf("bind() failed.\n");
            exit(1);
        }

        /* Construct the server address structure */
        /*Zero out structure*/
        memset(&servAddr, 0, sizeof(servAddr));
        /* Internet addr family */
        servAddr.sin_family = AF_INET; 
        /*Server IP address*/
        servAddr.sin_addr.s_addr = inet_addr("255.255.255.255");
        /* Server port */
        servAddr.sin_port = htons(servPort); 
        
        sleep(3);
        fill_discover(&send_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
        
        fromSize = sizeof(fromAddr);
        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);

        fill_broadcast_request(&send_packet, &receive_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));

        recv_from(broadcast_sock, &receive_packet, sizeof(packet), 0, (struct sockaddr *)&fromAddr, &fromSize);
        /* successfully receive DHCPOFFER */
        /* Get the IP address given by the server */
        received_addr = receive_packet.yiaddr;      
        set_ip(received_addr);
        lease_time = htonl(*((int *)&receive_packet.options[29]));               
    }
    else if (strcmp(commond, "--inform") == 0)
    {
        fill_inform(&send_packet);
        send_to(broadcast_sock, &send_packet, sizeof(packet), 0, (struct sockaddr *)&servAddr, sizeof(servAddr));
    }
    else
    {
        printf("Bad Commond. \n");
        exit(1);
    }
}