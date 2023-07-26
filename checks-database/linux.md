# Linux
PlatformTag: linux
## Informational
Tags: informational
### Date
```
date
```
### Hostname
```
hostname
```
### Kernel version
```
uname -a
```
### Network interfaces (ifconfig)
```
ifconfig -a
```
### Network interfaces (ip)
```
ip -a
```
### Running as
```
id
```
## Environment
Tags: environment
### PCI cards accessible
```
lspci
```
### USB peripherals accessible
```
lsusb
```
### Boot flags
```
cat /proc/cmdline
```
### Kernel logs
```
dmesg
```
### Kernel config
```
cat /boot/config-`uname -r`
```
### Loaded kernel modules
```
lsmod
```
### Kernel modules supported
```
grep "CONFIG_MODULES" /boot/config-`uname -r`
```
### Kernel modules
```
sysctl kernel.modules_disabled
```
### Grub password set
```
grep "password" /boot/grub/menu.lst
```
### Ctrl-alt-delete
```
grep "ctrlaltdel" /etc/inittab
```
### Kernel debugging
```
grep "sysrq" /etc/sysctl.conf
```
### Kernel hardening
```
cat /etc/sysctl.conf
```
### Active kernel hardening
```
sysctl -a
```
### Host is KVM
```
cat /proc/cpuinfo | grep -i "qemu"
```
### Host is VMware
```
dmidecode | grep -i "vmware"
```
### Host is VirtualBox
```
dmidecode | grep -i "virtualbox"
```
### Host is Xen
```
dmidecode | grep -i "xen"
```
### Host is container
```
cat /proc/1/cgroup
```
### Containers
```
docker ps -a
```
### K8s cluster
```
kubectl config view
```
### Environment variables set
```
env
```
### Currently logged in
```
who
```
### Logins
```
last
```
## Networking
Tags: networking
### ARP
```
arp -an
```
### ARP (using ip)
```
ip -4 neigh show
```
### IPv6 neighbor table
```
ip -6 neigh show
```
### Routing (netstat)
```
netstat -rn
```
### Routing (ip)
```
ip route show
```
### Name services
```
cat /etc/nsswitch.conf
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
### Web accessible
```
wget -O - https://216.58.213.164
wget -O - https://www.google.com
curl https://216.58.213.164
curl https://www.google.com
```
### Internet by proxy
```
echo $http_proxy
echo $https_proxy
echo $ftp_proxy
```
### Listening services (netstat)
```
netstat -anp | grep -v "unix" | grep "LISTEN"
```
### Listening services (socket stat)
```
ss -tulpan  | grep LISTEN
```

### RPC services
```
rpcinfo -p
```
### IPv6 (ifconfig)
```
ifconfig lo | grep "::1"
```
### IPv6 (ip)
```
ip addr show dev lo | grep ::1
```
### Network traffic
```
# Possible alternative to which for non Linux systems:
# if ! [ -x "$(command -v tcpdump)" ]; then
if ! [ "$(which tcpdump)" ]; then
echo 'Error: tcpdump is not installed.' >&2
else
# Capture traffic on all interfaces, for 60 seconds:
# -G 60 (rotate dump files every x seconds)
# -W 1 (limit number of dump files)
# Filter out traffic on port 22 to avoid feedback loop:
# port not 22
tcpdump -G 60 -W 1 -i any -s 65535 port not 22 -w packet_capture-`hostname`.pcap
fi
tar cvf packet_capture-`hostname`.tar packet_capture-`hostname`.pcap
gzip packet_capture-`hostname`.tar
rm packet_capture-`hostname`.pcap
```
## Network stack tuning
Tags: network-stack-tuning
### Syncookies
```
cat /proc/sys/net/ipv4/tcp_syncookies
grep "syncookies" /etc/sysctl.conf
```
### IP forwarding
```
cat /proc/sys/net/ipv4/ip_forward
grep "ip_forward" /etc/sysctl.conf
```
### Network shares mounted
```
mount | grep "cifs"
mount | grep "nfs"
```
## Access control
Tags: access-control
### Firewall configured
```
iptables -L
ip6tables -L
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
grep "nolistentcp" /etc/X11/xdm/Xservers /etc/kde/kdm/Xservers /etc/X11/gdm/gdm.conf /etc/X11/xinit/xserverrc
```
### X root logins
```
grep "AllowRootLogin" /etc/X11/xdm/kdmrc
```
### Account statuses
```
passwd -S -a
```
### Accounts with non-standard shells
```
grep -v "/bash$" /etc/passwd
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
find / \( -name id_dsa -o -name id_dsa.pub -o -name id_rsa -o -name id_rsa.pub -o -name authorized_keys \) | while read file
do
ls -l $file
cat $file
done
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
### SMB shares
```
cat /etc/samba/smb.conf
```
### Secure consoles
```
cat /etc/securetty
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
cat /etc/shadow
```
### Active Directory enabled
```
ps -aef | grep "vasd|sssd|pbis|slapd|adclient"
```
### Non-local users
```
getent passwd
getent group
```
### Using NIS
```
ypcat passwd
```
### Using Kerberos
```
for file in /tmp/krb5*
do
ls -l $file
done
```
### Using LDAP
```
cat /etc/ldap/ldap.conf
```
### SNMP community strings
```
grep community /etc/snmp/snmpd.conf
```
### System Auth PAM
```
grep "limits" /etc/pam.d/*
grep "crack" /etc/pam.d/*
grep "nullok" /etc/pam.d/*
grep "md5" /etc/pam.d/*
grep "shadow" /etc/pam.d/*
grep "cap" /etc/pam.d/*
```
### Login PAM
```
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "cap" /etc/pam.d/*
```
### Su PAM
```
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "wheel" /etc/pam.d/*
grep "cap" /etc/pam.d/*
```
### Sudo PAM
```
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "wheel" /etc/pam.d/*
grep "cap" /etc/pam.d/*
```
### Password aging
```
grep "MAX_DAYS" /etc/login.defs
grep "MIN_DAYS" /etc/login.defs
```
### Password minimum strength
```
grep "MIN_LEN" /etc/login.defs
```
### Unlocked accounts
```
grep -v "!!" /etc/shadow
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
### SSH uses PAM
```
grep "UsePAM" /etc/ssh/sshd_config
```
### SSH allows empty passwords
```
grep "PermitEmptyPasswords" /etc/ssh/sshd_config
```
## Cryptography
Tags: cryptography
### known_hosts encrypted
```
find / -name known_hosts | while read file
do
ls -l $file
cat $file
done
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
### Grub password obfuscated
```
grep "password" /boot/grub/menu.lst | grep "md5"
```
### Crypto used for shadow
```
egrep "MD5_CRYPT_ENAB|ENCRYPT_METHOD" /etc/login.defs
```
### Trusted CAs
```
md5sum /etc/ssl/certs/*
```
### Trusted keyrings
```
md5sum /etc/apt/trusted.gpg.d/*
md5sum /etc/pki/rpm-gpg/*
```
## Software installed
Tags: software-installed
### OS release
```
cat /etc/*-release /etc/debian_version
```
### Packages installed
```
rpm -q -a
dpkg --list --no-pager
```
### Packages for NOPC
```
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'
dpkg -l --no-pager
```
### Package management
```
cat /etc/apt/apt.conf
for file in /etc/apt/apt.conf /etc/apt/apt.conf.d/* /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/yum.conf /etc/yum.repos.d/*.repo /etc/dnf/dnf.conf
do
ls -l $file
cat $file
done
```
### Processes
```
ps -aef
```
### Services
```
chkconfig --list
```
### Systemd services
```
systemctl --no-pager
```
### Systemd configs
```
find /usr/lib/systemd/* /etc/systemd/* -type f | while read file
do
ls -l $file
cat $file
done
```
### Development tools
```
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name gdb \) -ls
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
### Syslog process
```
ps -aef | grep syslog
```
### Remote logging
```
grep "@" /etc/syslog.conf
```
### Syslog with rsyslog
```
for file in /etc/rsyslog.conf /etc/rsyslog.d/*
do
ls -l $file
cat $file
done
```
### Syslog with syslog-ng
```
cat /etc/syslog-ng/syslog-ng.conf
```
### Cron logging
```
grep "cron" /etc/syslog.conf
```
### User histories
```
find /home \( -name .sh_history -o -name .bash_history \) | while read file
do
ls -l $file
cat $file
done
```
### Auditing
```
ps -aef | grep auditd
auditctl -s
```
### Auditd policy
```
for file in /etc/audit/audit.rules /etc/audit/audit.rules.d/*
do
ls -l $file
cat $file
done
```
## Resource limits
Tags: resource-limits
### Configured limits
```
cat /etc/security/limits.conf
```
### Running limits
```
ulimit -a
```
### Tmp size
```
mount | grep "/tmp" | grep "size"
```
### Disk quotas
```
mount | grep "quota"
```
## File permissions
Tags: file-permissions
### Init umask
```
grep "umask" /etc/rc.d/init.d/functions
```
### Syslog umask
```
grep "umask" /etc/rc.d/init.d/syslog /etc/sysconfig/syslog
```
### Root umask
```
umask
```
### User umask
```
grep "UMASK" /etc/login.defs
grep "umask" /home/*/.[a-z]*
```
### Service umasks
```
grep "umask" /etc/rc.d/rc*.d/*
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
ls -la /var/log
```
### SSH strict mode
```
grep "StrictModes" /etc/ssh/sshd_config
```
### Root home
```
find /root -ls
```
### User homes
```
ls -la /home/*
```
## Exploit mitigation
Tags: exploit-mitigation
### Active mounts secure
```
mount | grep -v "nosetuid"
mount | grep -v "noexec"
```
### Configured mounts secure
```
grep -v "nosetuid" /etc/fstab
grep -v "noexec" /etc/fstab
```
### Separate partitions
```
mount | grep "/var"
mount | grep "/var/log"
mount | grep "/home"
```
### SELinux supported
```
grep "SELINUX=" /etc/selinux/config
```
### SELinux policy
```
grep "SELINUXTYPE=" /etc/selinux/config
```
### SELinux running
```
selinux -v
```
### SELinux processes
```
ps -aefZ
```
### AppArmour supported
```
cat /sys/module/apparmor/parameters/enabled
```
### AppArmour policy
```
aa-status
```
### AppArmour processes
```
aa-unconfined
ps -aefZ
```
### Cron users
```
cat /etc/cron.allow /etc/cron.deny
```
### At users
```
cat /etc/at.allow /etc/at.deny
```
### Stack randomisation
```
sysctl kernel.randomize_va_space
```
### Non executable stack
```
grep "stack" /proc/[0-9]*/maps
```
### Stack smashing protection
```
for x in /proc/[0-9]*
do
ls -l $x/exe | sed "s/.* -> //g"
objdump -D $x/exe | grep stack_chk | sort | uniq
done
find / \( -perm -u+s -o -perm -g+s \) | while read file
do
ls -l $file
objdump -D $file | grep "stack_chk" | sort | uniq
done
```
### SetUID debug
```
ls -l /etc/suid-debug
```
### PTrace scope
```
sysctl -a | grep "ptrace_scope"
```
## Privilege escalation
Tags: privilege-escalation
### User capabilities
```
ls -l /etc/security/capability.conf
cat /etc/security/capability.conf
```
### Init scripts run
```
for file in /etc/rc.d/*.d/*
do
ls -l $file
cat $file
done
```
### At scripts run
```
for file in /var/spool/atjobs/*
do
ls -l $file
cat $file
done
```
### Cron scripts run
```
for file in /etc/crontab /var/spool/crontabs/* /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.hourly/*
do
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
for file in /etc/profile /etc/bash.bashrc /home/*/.[a-z]*
do
ls -l $file
grep "PATH" $file
done
```
### Init paths
```
for file in /etc/rc.d/init.d/*
do
ls -l $file
grep "PATH" $file
done
```
### Default linker path
```
for file in /etc/ld.so.conf /etc/ld.so.conf.d/*
do
ls -l $file
cat $file
done
```
### User linker paths
```
for file in /etc/profile /etc/bash.bashrc /home/*/.[a-z]*
do
ls -l $file
grep "LD_LIBRARY_PATH" $file
done
```
### Init linker paths
```
for file in /etc/rc.d/init.d/*
do
ls -l $file
grep "LD_LIBRARY_PATH" $file
done
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
for file in /etc/sudoers /etc/sudoers.d/*
do
ls -l $file
cat $file
done
```
### Insecure RPATHs
```
find / \( -perm -o+s -o -g+s \) | while read file
do
ls -l $file
objdump -x $file | egrep "RPATH|RUNPATH"
done
```
### Processes with open files
```
lsof
```
### Proc tree
```
find /proc -type f | while read file
do
ls -l $file
strings $file
done
```
### Sys tree
```
find /sys -type f | while read file
do
ls -l $file
strings $file
done
```
### POSIX shared memory
```
ls -la /dev/shm
```
### System V shared memory
```
ipcs -a
```
### UNIX sockets
```
find / -type s -ls
```
## Common services
Tags: common-services
### SSH config
```
cat /etc/ssh/sshd_config
```
### SSH client config
```
cat /etc/ssh/ssh_config
```
### SSH running config
```
sshd -T
```
### Web server config
```
find / -name httpd.conf | while read file
do
ls -l $file
cat $file
done
```
### Web server logs
```
find / -name access.log | while read file
do
ls -l $file
grep -i "curl|wget|python|perl" $file
done
```
### Web server cgi-bin
```
find / -name cgi-bin | while read file
do
ls -l $file
done
```
## Important file locations
Tags: important-file-locations
### Configs
```
tar cvf etc-`hostname`.tar /etc
gzip etc-`hostname`.tar
```
### Logs
```
tar cvf logs-`hostname`.tar /var/log
gzip logs-`hostname`.tar
```
### SetUID and setGIDs files
```
tar cvf suids-`hostname`.tar `find / \( -perm -o+s -o -perm -g+s \)`
gzip suids-`hostname`.tar
```
### Temporary locations
```
tar cvf tmp-`hostname`.tar /tmp /var/tmp /dev/shm /dev/mqueue /run/screen /run/lock /var/crash
gzip tmp-`hostname`.tar
```
### Core files
```
tar cvf core-`hostname`.tar `find / -type f \( -name core -o -name core.[0-9]* \)`
gzip core-`hostname`.tar
```
