/* keylogger.c */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

/* init function */
static int keylogger_init(void)
{
    printk(KERN_INFO "Keylogger is loaded!\n");
    return 0;
}

/* exit function */
static void keylogger_exit(void)
{
    printk(KERN_INFO "Keylogger is unloaded!\n");
}

module_init(keylogger_init);
module_exit(keylogger_exit);

MODULE_LICENSE ("GPL");
MODULE_AUTHOR ("Richard Wu");
MODULE_DESCRIPTION ("a keylogger rootkit module");
MODULE_VERSION("1.0");
