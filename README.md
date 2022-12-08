# ACPLoader

-------------------------------------\_~~__(··)_~~_/-------------------------------------------

This repository contains a couple of simple loader scripts.



- Technique -1 :
  - Loader uses Obfusicated NT Api calls and resolved using Syswhispers 2 concept.
  - stream[] containes the aes encrypted shellcode (CS / Metasploit) and key[] contains the encryption key. getthatdecrypted_sea is the AES decrption routine.Use Cyberchief to generate AES encrypted payload.
  - Use process hacker to see whats goin on.
  - Same concept can be used for remote process injection. Modify the code to get a handle on the process you want to inject to and pass it to hProc variable.
  
 
- Technique -2:
  - Same concept as above the only difference is the encrypted shellcode is passed as a .ico file rather than an string array.
  - Save the encrypted payload as .ico and include the .ico file as rcdata.

- Opsec:
  - Obfusicate and remove debug statements.
  - For better file opsec follow this highly recommended [SharpUp](https://redteamer.tips/basic-operational-security-when-dropping-to-disk/).


- Acknowledgments:
  - [SysWhispers2](https://github.com/jthuraisamy/SysWhispers2)
  - [Sektor7 Malware Development Cources](https://institute.sektor7.net/)
