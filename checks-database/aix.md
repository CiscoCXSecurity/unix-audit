# AIX
PlatformTag: aix
## Informational
Tags: informational
### Hostname
```
hostname
```
### Kernel version
```
uname -a
```
### Network interfaces
```
ifconfig -a
```
## Environment
Tags: environment
### PCI cards accessible
```
lsdev -C
```
### USB peripherals accessible
```
lsdev -C
```
## Networking
Tags: networking
### ARP
```
arp -an
```
### Routing
```
netstat -rn
```
### Name services
```
cat /etc/netsvc.conf
```
### Hosts
```
cat /etc/hosts
```
### DNS
```
cat /etc/resolv.conf
```
### Internet
```
ping -c 5 www.google.co.uk
ping -c 5 8.8.8.8
```
### Listening services
```
netstat -an | grep -v "unix" | grep "LISTEN"
```
### IPv6
```
ifconfig lo0 | grep "::1"
```
## Network stack tuning
Tags: network-stack-tuning
### IP forwarding
```
/usr/sbin/no -a | grep "ipforwarding"
```
## Access control
Tags: access-control
### Firewall configured
```
lsfilt
```
### TCP wrappers used
```
cat /etc/hosts.allow
cat /etc/hosts.deny
```
### .rhosts used
```
find / -name .rhosts -ls
```
### hosts.equiv used
```
cat /etc/hosts.equiv
```
### .netrc used
```
find / -name .netrc -ls
```
### Remote X
```
netstat -an | grep "LISTEN" | egrep "6000|177"
```
### Accounts with non-standard shells
```
grep -v "/sh$" /etc/passwd
```
### Valid shells
```
cat /etc/shells 
```
### SSH ACLs configured
```
grep "Match" /etc/ssh/sshd_config
```
### SSH user logins
```
egrep "AllowUsers|DenyUsers|AllowGroups|DenyGroups" /etc/ssh/sshd_config
```
### SSH root logins
```
grep "PermitRootLogin" /etc/ssh/sshd_config
```
### SSH TCP forwarding
```
grep "AllowTCPForwarding" /etc/ssh/sshd_config
```
### SSH gateway ports
```
grep "GatewayPorts" /etc/ssh/sshd_config
```
### SSH VPN
```
grep "PermitTunnel" /etc/ssh/sshd_config
```
### SSH agent forwarding
```
grep "AllowAgentForwarding" /etc/ssh/sshd_config
```
### SSH X11 forwarding
```
grep "X11Forwarding" /etc/ssh/sshd_config
```
### SSH binds X11 to localhost
```
grep "X11UseLocalhost" /etc/ssh/sshd_config
```
### SSH reads environment from user file
```
grep "PermitUserEnvironment" /etc/ssh/sshd_config
```
### SSH accepts environment variables
```
grep "AcceptEnv" /etc/ssh/sshd_config
```
### SSH looks up connections in DNS
```
grep "UseDNS" /etc/ssh/sshd_config
```
### SSH uses privilege separation
```
grep "UsePrivilegeSeparation" /etc/ssh/sshd_config
```
### .shosts used
```
find / -name .shosts -ls
```
### shosts.equiv used
```
cat /etc/shosts.equiv
```
### SSH allows .rhosts
```
grep "IgnoreRhosts" /etc/ssh/sshd_config
```
### SSH public/private keys used
```
find / -name id_dsa -o -name id_dsa.pub -o -name id_rsa -o -name id_rsa.pub -o -name authorized_keys -ls
```
### SSH sessions are throttled
```
egrep "MaxAuthTries|MaxSessions|MaxStartups" /etc/ssh/sshd_config
```
### FTP users disallowed
```
cat /etc/ftpusers
```
### NFS shares
```
cat /etc/exports
```
### Secure consoles
```
cat /etc/security/user
```
## Authentication
Tags: authentication
### Banner
```
cat /etc/issue
```
### MOTD
```
cat /etc/motd
```
### Passwords
```
cat /etc/passwd
cat /etc/security/passwd
```
### SNMP community strings
```
grep "community" /etc/snmpd.conf
```
### Login policy
```
cat /etc/security/login.cfg
```
### Password aging
```
cat /etc/security/users
```
### Password minimum strength
```
cat /etc/security/users
```
### Unlocked accounts
```
cat /etc/security/passwd
```
### Session timeout
```
echo $TMOUT
```
### SSH shows banner
```
grep "Banner" /etc/ssh/sshd_config
```
### SSH shows MOTD
```
grep "PrintMotd" /etc/ssh/sshd_config
```
### SSH allows empty passwords
```
grep "PermitEmptyPasswords" /etc/ssh/sshd_config
```
## Cryptography
Tags: cryptography
### known_hosts encrypted
```
cat /.ssh/known_hosts
```
### SSH protocol
```
grep "Protocol" /etc/ssh/sshd_config
```
### SSH protocol 1 key regeneration
```
grep "KeyRegenerationInterval" /etc/ssh/sshd_config
```
### SSH protocol 1 key size
```
grep "ServerKeyBits" /etc/ssh/sshd_config
```
### SSH protocol 2 public key authentication
```
grep "PubkeyAuthentication" /etc/ssh/sshd_config
```
### SSH allows .rhosts with protocol 1 RSA
```
grep "RhostsRSAAuthentication" /etc/ssh/sshd_config
```
### SSH allows protocol 1 RSA
```
grep "RSAAuthentication" /etc/ssh/sshd_config
```
### SSH password based authentication
```
grep "PasswordAuthentication" /etc/ssh/sshd_config
```
### SSH ciphers
```
grep "Ciphers" /etc/ssh/sshd_config
```
### SSH MACs
```
grep "MACs" /etc/ssh/sshd_config
```
### Blacklisted keys
```
grep "PermitBlacklistedKeys" /etc/ssh/sshd_config
```
### Crypto used for shadow
```
grep "pwd_algorithm" /etc/security/login.cfg
```
## Software installed
Tags: software-installed
### OS release
```
oslevel -sq
oslevel -rq
```
### Packages installed
```
lslpp -Lc
rpm -q -a
```
### Processes
```
ps -aef
```
### Services
```
lssrc -a
lssrc -a | grep -v "Sub" | while read subsystem _
do
echo "Subsystem: $subsystem"
lssrc -ls $subsystem
done
```
### Development tools
```
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name gdb \)
```
### 3rd party software
```
find /usr/local -ls
find /opt -ls
```
## Logging
Tags: logging
### Time synchronisation
```
ps -aef | grep "ntp"
```
### Remote logging
```
grep "@" /etc/syslog.conf
```
### Cron logging
```
grep "cron" /etc/syslog.conf
```
## Resource limits
Tags: resource-limits
### Configured limits
```
cat /etc/security/limits
```
### Running limits
```
ulimit -a
```
### Disk quotas
```
lsfs | grep "Quota"
```
## File permissions
Tags: file-permissions
### Init umask
```
grep "umask" /etc/rc.*
```
### FTP umask
```
grep "ftpd" /etc/inetd.conf
```
### Root umask
```
umask
```
### User umask
```
grep "umask" /home/*/.[a-z]*
grep "umask" /etc/security/.profile
grep "umask" /etc/profile
cat /etc/security/user
```
### Service umasks
```
grep "umask" /etc/rc*.d/*
```
### World readable files / directories
```
find / -perm -o+r -ls
```
### World writable files / directories
```
find / -perm -o+w -ls
```
### Group writable files / directories
```
find / -perm -o+w -ls
```
### Unowned files / directories
```
find / -nouser -ls
```
### Ungrouped files / directories
```
find / -nogroup -ls
```
### Log files
```
find /var/log /var/adm -ls
```
### SSH strict mode
```
grep "StrictModes" /etc/ssh/sshd_config
```
### Root home
```
find /root -ls
```
## Exploit mitigation
Tags: exploit-mitigation
### Active mounts secure
```
mount | grep -v "nosetuid"
mount | grep -v "noexec"
lsfs
```
### Configured mounts secure
```
cat /etc/filesystems
```
### Separate partitions
```
mount | grep "/var"
mount | grep "/var/log"
mount | grep "/home"
```
### Cron users
```
cat /var/adm/cron/cron.allow /var/adm/cron/cron.deny
```
### At users
```
cat /var/adm/cron/at.allow /var/adm/cron/at.deny
```
### Non executable stack
```
sedmgr
```
## Privilege escalation
Tags: privilege-escalation
### Init scripts run
```
cat /etc/inittab
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
echo "File: $file"
ls -la $file
done
ls -la /etc/rc.*
```
### At scripts run
```
for file in /var/spool/atjobs/*
do
echo "File: $file"
ls -l $file
cat $file
done
```
### Cron scripts run
```
for file in /var/spool/cron/*
do
echo "File: $file"
ls -l $file
cat $file
done
```
### Default path
```
echo $PATH
```
### User paths
```
grep "PATH" /home/*/.[a-z]*
```
### Init paths
```
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
echo "File: $file"
grep "PATH" $file
done
grep "PATH" /etc/rc.*
```
### Default linker path
```
grep "LD_LIBRARY_PATH" /etc/profile 
echo $LD_LIBRARY_PATH
```
### User linker paths
```
egrep "LIBPATH|LD_LIBRARY_PATH" /home/*/.[a-z]*
```
### Init linker paths
```
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
	echo "File: $file"
	egrep "LIBPATH|LD_LIBRARY_PATH" $file
done
egrep "LIBPATH|LD_LIBRARY_PATH" /etc/rc.*
```
### SetUID files
```
find / -perm -u+s -type f -ls
```
### SetGID files
```
find / -perm -g+s -type f -ls
```
### Sudo configuration
```
cat /etc/sudoers
```
## Common services
Tags: common-services
### SSH running config
```
sshd -T
```
### Web server config
```
find / -name httpd.conf | while read file
do
	echo "File: $file"
	ls -l $file
	cat $file
done
```
### Web server cgi-bin
```
find /usr/lib -name cgi-bin | while read file
do
	echo "File: $file"
	ls -l $file
done
