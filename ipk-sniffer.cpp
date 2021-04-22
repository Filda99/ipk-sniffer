/*********************************************************************************************************************
 * Předmět:     Počítačové komunikace a sítě
 * Projekt:     Sniffer packetů
 * Datum:       4/2021
 * Vypracoval:  Filip Jahn
 * Login:       xjahnf00
 *
 * *******************************************************************************************************************
 * Zadání:
 * Navrhněte a implementujte síťový analyzátor v C/C++/C#,
 * který bude schopný na určitém síťovém rozhraním zachytávat a filtrovat pakety.
 *
 * *******************************************************************************************************************
 * Spuštění:
 * ./ipk-sniffer [-i rozhraní | --interface rozhraní] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
 * -> Složené závorky {} znamenají, že volba je nepovinná, oproti tomu [] znamená povinnou volbu.
 *      -i eth0 (právě jedno rozhraní, na kterém se bude poslouchat)
 *      -p 23 (bude filtrování paketů na daném rozhraní podle portu)
 *      -t nebo --tcp (bude zobrazovat pouze TCP pakety)
 *      -u nebo --udp (bude zobrazovat pouze UDP pakety)
 *      --icmp (bude zobrazovat pouze ICMPv4 a ICMPv6 pakety)
 *      --arp (bude zobrazovat pouze ARP rámce)
 *      -> Pokud nebudou konkrétní protokoly specifikovány, uvažují se k tisknutí všechny
 *      -n 10 (určuje počet paketů, které se mají zobrazit)
 *
 * *******************************************************************************************************************
 */

#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <iostream>
#include <arpa/inet.h>
#include<arpa/inet.h>           //inet_ntoa(), inet_ntop()
#include<net/ethernet.h>
#include <netinet/ether.h>
#include<netinet/ip_icmp.h>        //icmp hlavicka
#include<netinet/udp.h>            //udp hlavicka
#include<netinet/tcp.h>            //tcp hlavicka
#include<netinet/ip.h>            //ip hlavicka
#include<netinet/if_ether.h>    //ethernet hlavicka
#include<net/if_arp.h>          //arp hlavicka
#include<netinet/ip6.h>         //ipv6 hlavicka
#include<arpa/inet.h>           //inet_ntoa(), inet_ntop()
#include <math.h>               //ceil()

#define ETH_HEADER  14
#define IPV4_PROT   0
#define IPV6_PROT   1
#define IPV6_HDR    40

/***********************/
/** Globalni promenne **/
// Boolean hodnoty, ktere protokoly se maji zobrazovat
bool tcp = false;
bool udp = false;
bool arp = false;
bool icmp = false;

// Rozhranni, na kterem se posloucha
char* device;

// Port
char* port;

// Pocet paketu, kolik se jich ma zobrazit
// Defaultne 1
int num_of_packets = 1;
/***********************/

/**
 * Vypsani rozhranni, na kterych se da packety odchytavat.
 */
void printInterface()
{
    // Prevzato a upraveno z: http://embeddedguruji.blogspot.com/2014/01/pcapfindalldevs-example.html
    char error[PCAP_ERRBUF_SIZE];
    pcap_if_t *interfaces,*temp;
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1)
    {
        printf("[ERR]: Nenasel jsem zadna zarizeni.\n");
    }
    printf("Seznam veskerych rozhranni je nasledujici:\n");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("%d:  %s\n",i++,temp->name);
    }
    exit(1);
}

/**
 * Parsovani argumentu.
 * Argumenty mohou byt zadany nasledovne:
 * [-i rozhraní | --interface rozhraní] {-p ­­port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp]} {-n num}
 * @param argc Pocet argumentu
 * @param argv Pole zadanych argumentu
 */
void parseArguments(int argc, char **argv)
{
    bool checkInterface = false;

    static struct option longopts[] =
        {
                {"interface",   required_argument,  0,  'i'},
                {"tcp",         no_argument,        0,  't'},
                {"udp",         no_argument,        0,  'u'},
                {"arp",         no_argument,        0,  0},
                {"icmp",        no_argument,        0,  0},
                {0, 0, 0, 0}  // ukoncovaci prvek
        };

    int c;  // Prave nacteny argument
    int index = 0;  //  Index ve strukture longopts, vyuziva se, kdyz argument nema zkratku
    //  interface, port, num musi pozaduji zadane argumenty
    while((c = getopt_long(argc, argv, ":i:p:tun:", longopts, &index)) != -1){
        //printf("%c\n", c);
        switch (c)
        {
            // Pokud je zadan pouze samotny argument, napr: -i
            case ':':
                if (optopt == 'i'){
                    printInterface();
                }
                else{
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(1);
                }
            case 0:
                if (longopts[index].flag != 0)
                    break;
                if (strcmp(longopts[index].name, "arp") == 0)
                    arp = true;
                else if (strcmp(longopts[index].name, "icmp") == 0)
                    icmp = true;
                else{
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(1);
                }
                break;
            case 'i':
                if (optarg == NULL || (strcmp(optarg, "-p") == 0)){
                    fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                    exit(1);
                }
                else{
                    device = optarg;
                    checkInterface = true;
                    //printf("%s\n", device);
                }
                break;

            case 'p':
                if (atoi(optarg) < 0){
                    fprintf(stderr, "[ERR]: Parametru -p lze priradit pouze int.\n");
                    exit(1);
                }
                else{
                    //printf("here0\n");
                    port = optarg;
                }
                //printf("%s",port);
                break;

            case 't':
                tcp = true;
                break;

            case 'u':
                udp = true;
                break;

            case 'n':
                if ((num_of_packets = atoi(optarg)) == 0){
                    fprintf(stderr, "[ERR]: Parametru -n lze priradit pouze int.\n");
                    exit(1);
                }
                //printf("%i",num_of_packets);
                break;

            default:
                fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
                exit(1);
        }
    }
    if (!checkInterface){
        fprintf(stderr, "[ERR]: Zadal jste spatne argumenty.\n");
        exit(1);
    }

    if (!tcp && !udp && !arp && !icmp){
        tcp = true;
        udp = true;
        arp = true;
        icmp = true;
    }
    return;
}

/**
 * Naplni pole filter_exp retezcem.
 * Ve funkci pcap_compile(), kam retezec posilame, probehne zpracovani tohoto retezce
 * a tim se nam vrati spravna struktura.
 * @param str Retezec, ktery se ma naplnit
 */
std::string fillFilterStr(std::string str)
{
    bool atLeastOneIsIn = false;
    if (strcmp(port, "0") != 0){
        str.append("port ");
        str.append(port);
        str.append(" and ");
    }
    if(tcp || icmp || udp || arp)
        str.append(" (");
    if(tcp){
        str.append("tcp");
        atLeastOneIsIn = true;
    }
    if(udp){
        if (atLeastOneIsIn)
            str.append(" or ");
        str.append("udp");
        atLeastOneIsIn = true;
    }
    if(arp){
        if (atLeastOneIsIn)
            str.append(" or ");
        str.append("arp");
        atLeastOneIsIn = true;
    }
    if(icmp){
        if (atLeastOneIsIn)
            str.append(" or ");
        str.append("icmp or icmp6");
        atLeastOneIsIn = true;
    }
    if (atLeastOneIsIn)
        str.append(")");
    return str;
}

/**
 * Ziska momentalni cas a ve spravnem formatu vraci.
 * @return Retezec, ve kterem je ulozen cas zachyceni packetu
 */
std::string time_rfc3339()
{
    char cstr[80];
    timeval curTime;
    gettimeofday(&curTime, NULL);
    int milli = curTime.tv_usec / 1000;
    char buffer [60];
    strftime(buffer,59,"%FT%T", localtime(&curTime.tv_sec));
    // %03d - vypis tri cela cisla, jinak nic
    sprintf(cstr, "%s.%03d+02:00", buffer, milli);
    std::string s(cstr);
    return s;
}

/**
 * Vypsani prave casti vypisu v ascii podobe.
 * Pokud nejsou znaky tisknutelne, vypiseme misto nich tecku.
 * @param ascii_str Pole znaku, ktere se maji vypsat
 * @param charsToPrint Pocet znaku, kolik se jich ma vypsat
 */
void print_char_ascii(char ascii_str[17], int charsToPrint)
{
    printf("\t");
    for(int i = 0; i < charsToPrint; i++){
        if(i == 8)
            printf(" ");
        if (isprint(ascii_str[i]))
            printf("%c", ascii_str[i]);
        else
            printf(".");
    }
}

/**
 * Funkce pro vypis dat z packetu.
 * Prochazeni dat z packetu, kde kazdy znak vypisujeme v hexa podobe a ukladame
 * do pole ascii_str dany znak pro pozdejsi vypsani ve funkci print_char_ascii().
 * @param packet Prijaty packet, ktery se ma vypsat
 * @param length Delka packetu. Prochazime ho od zacatku do konce
 */
void print_packet_body( const u_char *packet, bpf_u_int32 length)
{
    char ascii_str[17] = "";
    int posInPckt;
    for (posInPckt = 0; posInPckt < length; posInPckt++){
        int lastPosInLine = (posInPckt % 16);
        // Vypis konec radku, ascii hodnoty
        if(lastPosInLine == 0 && posInPckt != 0){
            print_char_ascii(ascii_str, 16); // Vypis cely radek = 16 znaku
        }

        // Vypis zacatku radku
        if(lastPosInLine == 0){// End of line
            // Nechceme aby se nam oddelil prvni radek od vypisu dat
            if (posInPckt != 0)
                printf("\n");
            int line_number = posInPckt / 16;
            // New line
            printf("0x%03d0\t", line_number);
        }

        // Mezera uprostred
        if ((posInPckt % 8) == 0)
            printf(" ");

        // Vypis dat v hexa podobe
        printf("%02x ", packet[posInPckt]);
        ascii_str[lastPosInLine] = packet[posInPckt];

        //printf("\n");
    }

    // Pokud nebylo zarovnano a vse vypsano
    // tak zarovnej a vypis co zbylo v ascii_str
    int charsToPrint = posInPckt % 16;
    while((posInPckt % 16) != 0){
        // Zarovnani na konec
        printf("   ");
        posInPckt++;
    }
    // Vypsani ascii hodnot
    print_char_ascii(ascii_str, charsToPrint); // Vypis takovy pocet znaku, kolik je na poslednim radku

    printf("\n");
}

/**
 * Zpracovani a vypsani protokolu icmp pro ipv4.
 * Ze zacatku pretypovani packetu na ip strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 */
void icmp_v4(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(ICMPv4)");
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
    struct ip* iphdr_var = (struct ip*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    srcIpAddr.append(inet_ntoa(iphdr_var->ip_src));
    destIpAddr.append(inet_ntoa(iphdr_var->ip_dst));
    printf("\n%s %s > %s, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(),
           destIpAddr.c_str(), lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu icmp pro ipv6.
 * Ze zacatku pretypovani packetu na ip6 strukturu, ziskani ip adres, vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 */
void icmp_v6(const u_char *packetWoEther,  const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(ICMPv6)");
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/ip.h.html
    struct ip6_hdr* ip6hdr_var = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    printf("\n%s %s > %s, length %d bytes\n", currentTime.c_str(), srcIpAddr, destIpAddr, lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu udp pro ipv4.
 * Ze zacatku pretypovani packetu na ip strukturu, pote ziskani ip adres,
 * posunuti se v packetu o delku hlavicky, pretypovani na upd strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 * @param ipLen Delka hlavicky, o kterou se mame posunout pro ziskani portu
 */
void udp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen)
{
    printf("\n(UDPv4)");
    // IP source/dest
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    // Pretypovani zbytku packetu na ip hlavicku
    struct ip *iphdr_var = (struct ip *) packetWoEther;
    srcIpAddr.append(inet_ntoa(iphdr_var->ip_src));
    destIpAddr.append(inet_ntoa(iphdr_var->ip_dst));
    const u_char *transportProtocolHdr = packet + ETH_HEADER + ipLen;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct udphdr *udphdr_var = (struct udphdr *) transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(udphdr_var->uh_sport);
    uint16_t dstPort = ntohs(udphdr_var->uh_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(), srcPort,
           destIpAddr.c_str(), dstPort, lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu udp pro ipv6.
 * Ze zacatku pretypovani packetu na ip6 strukturu, pote ziskani ip adres,
 * posunuti se v packetu o delku hlavicky, pretypovani na upd strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 */
void udp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(UDPv6)");
    // IP source/dest
    struct ip6_hdr* ip6hdr_var = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    const u_char *transportProtocolHdr = packet + ETH_HEADER + IPV6_HDR;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct udphdr *udphdr_var = (struct udphdr *) transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(udphdr_var->uh_sport);
    uint16_t dstPort = ntohs(udphdr_var->uh_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr, srcPort,
           destIpAddr, dstPort, lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu tcp pro ipv4.
 * Ze zacatku pretypovani packetu na ip strukturu, pote ziskani ip adres,
 * posunuti se v packetu o delku hlavicky, pretypovani na tcp strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 * @param ipLen Delka hlavicky, o kterou se mame posunout pro ziskani portu
 */
void tcp_v4(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket,
              std::string currentTime, unsigned int ipLen)
{
    printf("\n(TCPv4)");
    // IP source/dest
    std::string srcIpAddr = "";
    std::string destIpAddr = "";
    // Pretypovani zbytku packetu na ip hlavicku
    struct ip* iphdr_var = (struct ip*)packetWoEther;
    srcIpAddr.append(inet_ntoa(iphdr_var->ip_src));
    destIpAddr.append(inet_ntoa(iphdr_var->ip_dst));
    const u_char *transportProtocolHdr = packet + ETH_HEADER + ipLen;

    // https://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/tcp.h.html
    struct tcphdr* tcphdr_var = (struct tcphdr*)transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(tcphdr_var->th_sport);
    uint16_t dstPort = ntohs(tcphdr_var->th_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr.c_str(), srcPort,
           destIpAddr.c_str(), dstPort, lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Zpracovani a vypsani protokolu tcp pro ipv6.
 * Ze zacatku pretypovani packetu na ip6 strukturu, pote ziskani ip adres,
 * posunuti se v packetu o delku hlavicky, pretypovani na tcp strukturu,
 * zjisteni portu a nasledne vypsani.
 * @param packetWoEther Packet bez ethernetove hlavicky
 * @param packet Obdrzeny packet
 * @param lengthOfPacket Delka packetu
 * @param currentTime Cas obdrzeni packetu
 */
void tcp_v6(const u_char *packetWoEther, const u_char *packet, bpf_u_int32 lengthOfPacket, std::string currentTime)
{
    printf("\n(TCPv6)");
    // IP source/dest
    struct ip6_hdr* ip6hdr_var = (struct ip6_hdr*)packetWoEther; //pretypovani na IP hlavicku, ze ktere ziskame adresy
    char srcIpAddr [INET6_ADDRSTRLEN];
    char destIpAddr [INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_src), srcIpAddr, INET6_ADDRSTRLEN);
    inet_ntop(AF_INET6, &(ip6hdr_var->ip6_dst), destIpAddr, INET6_ADDRSTRLEN);
    const u_char *transportProtocolHdr = packet + ETH_HEADER + IPV6_HDR;

    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/udp.h.html
    struct tcphdr* tcphdr_var = (struct tcphdr*)transportProtocolHdr; // udp struktura
    uint16_t srcPort = ntohs(tcphdr_var->th_sport);
    uint16_t dstPort = ntohs(tcphdr_var->th_dport);
    printf("\n%s %s : %d > %s : %d, length %d bytes\n", currentTime.c_str(), srcIpAddr, srcPort,
           destIpAddr, dstPort, lengthOfPacket);
    print_packet_body(packet, lengthOfPacket);
}

/**
 * Hlavni funkce, vola se vzdy pri prijeti packetu.
 * Zpracovani ethernetove hlavicky, zjisteni, ktery protokol se vyuziva a
 * nasledne volani funkce se zpracovanim daneho protokolu nad timto packetem.
 * @param args Argumenty, ktere nevyuzivam. MUSI zde byt.
 * @param header Vyuziti pro zjisteni delky celeho packetu
 * @param packet Odchyceny packet
 */
void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // https://unix.superglobalmegacorp.com/Net2/newsrc/netinet/if_ether.h.html
    struct ether_header *ipv_num = (struct ether_header*)packet;
    u_short type = ntohs(ipv_num->ether_type);
    // Aktualni cas prijeti packetu
    std::string currentTime = time_rfc3339();
    // Posunuti se v packetu o ethernetovou hlavicku
    const u_char *packet_ip = packet + ETH_HEADER;

    if(type == 0x0800){ //ipv4
        // Pretypovani zbytku packetu na ip hlavicku
        // https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
        struct iphdr *ip_header = (struct iphdr*)packet_ip;

        // Podle protokolu se bude zpracovavat budto ICMP, TCP nebo UDP
        switch (ip_header->protocol) {
            // ICMP
            case 1:
                icmp_v4(packet_ip, packet, header->len, currentTime);
                break;

            // TCP + UDP
            case 6:
            case 17:{ // V zavorkach kvuli deklarovani promenne
                // Promenliva delka hlavicky
                unsigned int ipLen = ip_header->ihl * 4;
                if(ip_header->protocol == 17)
                    udp_v4(packet_ip, packet, header->len, currentTime, ipLen);
                else
                    tcp_v4(packet_ip, packet, header->len, currentTime, ipLen);
                break;
            }

            default:
                break;
        }
    }
    else if (type == 0x86DD){ // IPV6
        // https://sites.uclouvain.be/SystInfo/usr/include/netinet/ip.h.html
        // Pretypovani zbytku packetu na ip hlavicku
        struct ip6_hdr *ip6Header = (struct ip6_hdr*)packet_ip;

        // Podle protokolu se bude zpracovavat budto ICMP, TCP nebo UDP
        switch (ip6Header->ip6_nxt) {
            // ICMPv6
            case 58:
                icmp_v6(packet_ip, packet, header->len, currentTime);
                break;

            // TCP
            case 6:
                tcp_v6(packet_ip, packet, header->len, currentTime);
                break;

            // UDP
            case 17:
                udp_v6(packet_ip, packet, header->len, currentTime);
                break;

            default:
                break;
        }
    }
    else if (type == 0x0806) {   // arp
        // https://unix.superglobalmegacorp.com/BSD4.4/newsrc/netinet/if_ether.h.html
        // Posunuti se v packetu o ethernetovou hlavicku
        const u_char *packet_arp = packet + ETH_HEADER;
        struct ether_arp *ether_arp = (struct ether_arp *) packet_arp;

        // Ziskani source IP a MAC adresy
        struct in_addr *srcIP = (struct in_addr *) ether_arp->arp_spa;
        char* srcMac = ether_ntoa((struct ether_addr*) &ether_arp->arp_sha);
        std::string printAddr = ""; // retezec pro vypis adres
        // Format vypisu v podobe: sourceIP (sourceMac) > destIP (destMac)
        printAddr.append(inet_ntoa(*srcIP));
        printAddr.append(" (");
        printAddr.append(srcMac);
        printAddr.append(") > ");

        // Ziskani dest IP a MAC adresy
        struct in_addr *dstIP = (struct in_addr *) ether_arp->arp_tpa;
        char *dstMac = ether_ntoa((struct ether_addr *) &ether_arp->arp_tha);
        // Dovypsani
        printAddr.append(inet_ntoa(*dstIP));
        printAddr.append(" (");
        printAddr.append(dstMac);
        printAddr.append(")");

        std::string option;
        if (ntohs(ether_arp->arp_op) == ARPOP_REQUEST)
            option = "requests";
        else if (ntohs(ether_arp->arp_op) == ARPOP_REPLY)
            option = "reply";

        printf("%s %s (%s), length %d bytes\n", currentTime.c_str(), printAddr.c_str(), option.c_str(), header->len);
        print_packet_body(packet, header->len);
    }
}

int main (int argc, char **argv)
{
    if (argc == 1){
        printInterface();
        exit(1);
    }
    // Parsovani argumentu
    parseArguments(argc, argv);

    pcap_t *handle;
    struct bpf_program fp;
    // Hodnota pro filtrovani
    std::string filter_exp = "";    // https://bit.ly/3giiyKP
    filter_exp = fillFilterStr(filter_exp);
    bpf_u_int32 net;
    // Error buffer, slouzi pro ukladani pripadnych erroru
    char errbuf[PCAP_ERRBUF_SIZE];

    // Otevreni zarizeni pro sledovani packetu
    handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", device, errbuf);
        return(2);
    }
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp.c_str(), pcap_geterr(handle));
        return(2);
    }
    pcap_loop(handle, num_of_packets, process_packet, NULL);

    pcap_freecode(&fp);
    pcap_close(handle);

    return(0);
}