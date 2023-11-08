# Shellcode-injection-with-api-hashing
***
This x32 bit malware uses the *shellcode injection with thread hijacking technique*, the process is created in suspended mode, and using the thread context structure, the EIP register for the thread is changed, after which the thread is started.
The shellcode is obfuscated using xor and written to the program resources.
Api hashing is also used.

VT link: https://www.virustotal.com/gui/file/11762510b96c0f0bfa7e9fbcabc06df6db03126f5d5a7075199e181aba872c1c
