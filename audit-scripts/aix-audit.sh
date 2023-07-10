echo "=== AIX > Informational > Hostname"===
hostname

echo "=== AIX > Informational > Kernel version"===
uname -a

echo "=== AIX > Informational > Network interfaces"===
ifconfig -a

echo "=== AIX > Environment > PCI cards accessible"===
lsdev -C

echo "=== AIX > Environment > USB peripherals accessible"===
lsdev -C

echo "=== AIX > Networking > ARP"===
arp -an

echo "=== AIX > Networking > Routing"===
netstat -rn

echo "=== AIX > Networking > Name services"===
cat /etc/netsvc.conf

echo "=== AIX > Networking > Hosts"===
cat /etc/hosts

echo "=== AIX > Networking > DNS"===
cat /etc/resolv.conf

echo "=== AIX > Networking > Internet"===
ping -c 5 www.google.co.uk
ping -c 5 8.8.8.8

echo "=== AIX > Networking > Listening services"===
netstat -an | grep -v "unix" | grep "LISTEN"

echo "=== AIX > Networking > IPv6"===
ifconfig lo0 | grep "::1"

echo "=== AIX > Network stack tuning > IP forwarding"===
/usr/sbin/no -a | grep "ipforwarding"

echo "=== AIX > Access control > Firewall configured"===
lsfilt

echo "=== AIX > Access control > TCP wrappers used"===
cat /etc/hosts.allow
cat /etc/hosts.deny

echo "=== AIX > Access control > .rhosts used"===
find / -name .rhosts -ls

echo "=== AIX > Access control > hosts.equiv used"===
cat /etc/hosts.equiv

echo "=== AIX > Access control > .netrc used"===
find / -name .netrc -ls

echo "=== AIX > Access control > Remote X"===
netstat -an | grep "LISTEN" | egrep "6000|177"

echo "=== AIX > Access control > Accounts with non-standard shells"===
grep -v "/sh$" /etc/passwd

echo "=== AIX > Access control > Valid shells"===
cat /etc/shells

echo "=== AIX > Access control > SSH ACLs configured"===
grep "Match" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH user logins"===
egrep "AllowUsers|DenyUsers|AllowGroups|DenyGroups" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH root logins"===
grep "PermitRootLogin" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH TCP forwarding"===
grep "AllowTCPForwarding" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH gateway ports"===
grep "GatewayPorts" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH VPN"===
grep "PermitTunnel" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH agent forwarding"===
grep "AllowAgentForwarding" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH X11 forwarding"===
grep "X11Forwarding" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH binds X11 to localhost"===
grep "X11UseLocalhost" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH reads environment from user file"===
grep "PermitUserEnvironment" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH accepts environment variables"===
grep "AcceptEnv" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH looks up connections in DNS"===
grep "UseDNS" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH uses privilege separation"===
grep "UsePrivilegeSeparation" /etc/ssh/sshd_config

echo "=== AIX > Access control > .shosts used"===
find / -name .shosts -ls

echo "=== AIX > Access control > shosts.equiv used"===
cat /etc/shosts.equiv

echo "=== AIX > Access control > SSH allows .rhosts"===
grep "IgnoreRhosts" /etc/ssh/sshd_config

echo "=== AIX > Access control > SSH public/private keys used"===
find / -name id_dsa -o -name id_dsa.pub -o -name id_rsa -o -name id_rsa.pub -o -name authorized_keys -ls

echo "=== AIX > Access control > SSH sessions are throttled"===
egrep "MaxAuthTries|MaxSessions|MaxStartups" /etc/ssh/sshd_config

echo "=== AIX > Access control > FTP users disallowed"===
cat /etc/ftpusers

echo "=== AIX > Access control > NFS shares"===
cat /etc/exports

echo "=== AIX > Access control > Secure consoles"===
cat /etc/security/user

echo "=== AIX > Authentication > Banner"===
cat /etc/issue

echo "=== AIX > Authentication > MOTD"===
cat /etc/motd

echo "=== AIX > Authentication > Passwords"===
cat /etc/passwd
cat /etc/security/passwd

echo "=== AIX > Authentication > SNMP community strings"===
grep "community" /etc/snmpd.conf

echo "=== AIX > Authentication > Login policy"===
cat /etc/security/login.cfg

echo "=== AIX > Authentication > Password aging"===
cat /etc/security/users

echo "=== AIX > Authentication > Password minimum strength"===
cat /etc/security/users

echo "=== AIX > Authentication > Unlocked accounts"===
cat /etc/security/passwd

echo "=== AIX > Authentication > Session timeout"===
echo $TMOUT

echo "=== AIX > Authentication > SSH shows banner"===
grep "Banner" /etc/ssh/sshd_config

echo "=== AIX > Authentication > SSH shows MOTD"===
grep "PrintMotd" /etc/ssh/sshd_config

echo "=== AIX > Authentication > SSH allows empty passwords"===
grep "PermitEmptyPasswords" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > known_hosts encrypted"===
cat /.ssh/known_hosts

echo "=== AIX > Cryptography > SSH protocol"===
grep "Protocol" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH protocol 1 key regeneration"===
grep "KeyRegenerationInterval" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH protocol 1 key size"===
grep "ServerKeyBits" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH protocol 2 public key authentication"===
grep "PubkeyAuthentication" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH allows .rhosts with protocol 1 RSA"===
grep "RhostsRSAAuthentication" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH allows protocol 1 RSA"===
grep "RSAAuthentication" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH password based authentication"===
grep "PasswordAuthentication" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH ciphers"===
grep "Ciphers" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > SSH MACs"===
grep "MACs" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > Blacklisted keys"===
grep "PermitBlacklistedKeys" /etc/ssh/sshd_config

echo "=== AIX > Cryptography > Crypto used for shadow"===
grep "pwd_algorithm" /etc/security/login.cfg

echo "=== AIX > Software installed > OS release"===
oslevel -sq
oslevel -rq

echo "=== AIX > Software installed > Packages installed"===
lslpp -Lc
rpm -q -a

echo "=== AIX > Software installed > Processes"===
ps -aef

echo "=== AIX > Software installed > Services"===
lssrc -a
lssrc -a | grep -v "Sub" | while read subsystem _
do
echo "Subsystem: $subsystem"
lssrc -ls $subsystem
done

echo "=== AIX > Software installed > Development tools"===
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name gdb \)

echo "=== AIX > Software installed > 3rd party software"===
find /usr/local -ls
find /opt -ls

echo "=== AIX > Logging > Time synchronisation"===
ps -aef | grep "ntp"

echo "=== AIX > Logging > Remote logging"===
grep "@" /etc/syslog.conf

echo "=== AIX > Logging > Cron logging"===
grep "cron" /etc/syslog.conf

echo "=== AIX > Resource limits > Configured limits"===
cat /etc/security/limits

echo "=== AIX > Resource limits > Running limits"===
ulimit -a

echo "=== AIX > Resource limits > Disk quotas"===
lsfs | grep "Quota"

echo "=== AIX > File permissions > Init umask"===
grep "umask" /etc/rc.*

echo "=== AIX > File permissions > FTP umask"===
grep "ftpd" /etc/inetd.conf

echo "=== AIX > File permissions > Root umask"===
umask

echo "=== AIX > File permissions > User umask"===
grep "umask" /home/*/.[a-z]*
grep "umask" /etc/security/.profile
grep "umask" /etc/profile
cat /etc/security/user

echo "=== AIX > File permissions > Service umasks"===
grep "umask" /etc/rc*.d/*

echo "=== AIX > File permissions > World readable files / directories"===
find / -perm -o+r -ls

echo "=== AIX > File permissions > World writable files / directories"===
find / -perm -o+w -ls

echo "=== AIX > File permissions > Group writable files / directories"===
find / -perm -o+w -ls

echo "=== AIX > File permissions > Unowned files / directories"===
find / -nouser -ls

echo "=== AIX > File permissions > Ungrouped files / directories"===
find / -nogroup -ls

echo "=== AIX > File permissions > Log files"===
find /var/log /var/adm -ls

echo "=== AIX > File permissions > SSH strict mode"===
grep "StrictModes" /etc/ssh/sshd_config

echo "=== AIX > File permissions > Root home"===
find /root -ls

echo "=== AIX > Exploit mitigation > Active mounts secure"===
mount | grep -v "nosetuid"
mount | grep -v "noexec"
lsfs

echo "=== AIX > Exploit mitigation > Configured mounts secure"===
cat /etc/filesystems

echo "=== AIX > Exploit mitigation > Separate partitions"===
mount | grep "/var"
mount | grep "/var/log"
mount | grep "/home"

echo "=== AIX > Exploit mitigation > Cron users"===
cat /var/adm/cron/cron.allow /var/adm/cron/cron.deny

echo "=== AIX > Exploit mitigation > At users"===
cat /var/adm/cron/at.allow /var/adm/cron/at.deny

echo "=== AIX > Exploit mitigation > Non executable stack"===
sedmgr

echo "=== AIX > Privilege escalation > Init scripts run"===
cat /etc/inittab
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
echo "File: $file"
ls -la $file
done
ls -la /etc/rc.*

echo "=== AIX > Privilege escalation > At scripts run"===
for file in /var/spool/atjobs/*
do
echo "File: $file"
ls -l $file
cat $file
done

echo "=== AIX > Privilege escalation > Cron scripts run"===
for file in /var/spool/cron/*
do
echo "File: $file"
ls -l $file
cat $file
done

echo "=== AIX > Privilege escalation > Default path"===
echo $PATH

echo "=== AIX > Privilege escalation > User paths"===
grep "PATH" /home/*/.[a-z]*

echo "=== AIX > Privilege escalation > Init paths"===
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
echo "File: $file"
grep "PATH" $file
done
grep "PATH" /etc/rc.*

echo "=== AIX > Privilege escalation > Default linker path"===
grep "LD_LIBRARY_PATH" /etc/profile
echo $LD_LIBRARY_PATH

echo "=== AIX > Privilege escalation > User linker paths"===
egrep "LIBPATH|LD_LIBRARY_PATH" /home/*/.[a-z]*

echo "=== AIX > Privilege escalation > Init linker paths"===
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
	echo "File: $file"
	egrep "LIBPATH|LD_LIBRARY_PATH" $file
done
egrep "LIBPATH|LD_LIBRARY_PATH" /etc/rc.*

echo "=== AIX > Privilege escalation > SetUID files"===
find / -perm -u+s -type f -ls

echo "=== AIX > Privilege escalation > SetGID files"===
find / -perm -g+s -type f -ls

echo "=== AIX > Privilege escalation > Sudo configuration"===
cat /etc/sudoers

echo "=== AIX > Common services > SSH running config"===
sshd -T

echo "=== AIX > Common services > Web server config"===
find / -name httpd.conf | while read file
do
	echo "File: $file"
	ls -l $file
	cat $file
done

echo "=== AIX > Common services > Web server cgi-bin"===
find /usr/lib -name cgi-bin | while read file
do
	echo "File: $file"
	ls -l $file
done


