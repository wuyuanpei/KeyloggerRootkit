# KeyloggerRootkit
This project implements a Linux keylogger rootkit module that sends logs over network, hides its existence, hides specified processes/files, and starts automatically at boot time

- The keylogger will log all the ASCII characters, <kbd>ENTER</kbd> ``'\n'``, <kbd>BACKSPACE</kbd> ``'\b'``, <kbd>ESC</kbd> ``'\e'``, and <kbd>TAB</kbd> ``'\t'``. <kbd>SHIFT</kbd> with a key will change the corresponding character into upper case or a different symbol.
- All the keys stored will be put into a local buffer (char array) named ``key_buf``
- ``key_buf`` has a size preset by the attacker and when ``key_buf`` is full, a udp packet containing the whole buffer will be sent to the attacker.
- The ip address and udp port are preset by the attacker.
- The keylogger also implements a timer that periodically checks ``key_buf``. If ``key_buf`` is not empty, a udp packet containing its content will be sent to the attacker. The period of the timer is preset by the attacker.
- The module hooks ``sys_kill`` to receive signals from user space. 
- We use signal 64 to hide/show this module. Thus, one can hide this module by typing the command ``kill -64 1``. Check ``lsmod`` to verify that keylogger is gone.
- To hide any process ``pid``, one can type ``kill -63 pid``: e.g. to hide process ``bash`` with pid 2296, do ``kill -63 2296``. Check ``ps`` to see bash is gone.
- To hide a file, the module is preset to hide any files or directories starting with the name "realbad". This can be changed to the attacker's needs. The file hiding is automatic when keylogger is loaded.
- We also implement a script to automatically load the module every time the operating system boots. Run the script by typing ``sudo ./autoload.sh``. Then reboot ``shutdown -r now`` and ``lsmod | grep "keylogger"``
- The script ``remove-autoload.sh`` will disable automatic loading on boot.
