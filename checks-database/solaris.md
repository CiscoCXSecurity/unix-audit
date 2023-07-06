# Solaris
PlatformTag: solaris
## Informational
Tags: informational
### Hostname
```
cat /etc/nodename
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
prtconf -v
```
### USB peripherals accessible
```
prtconf -v
```
### Loaded kernel modules
```
modinfo
```
### OBP password set
```
eeprom | grep "security-mode"
```
### OBP banner set
```
eeprom | grep "oem-banner"
```
### Grub password set
```
/sbin/bootadm list-menu
grep password "/path/to/menu.lst"
```
### Stop-A
```
grep "abort_enable" /etc/system
```
### Zones
```
zoneadm list
```
## Networking
Tags: networking
### ARP
```
arp -a
cat /etc/ethers
```
### Routing
```
netstat -rn
cat /etc/defaultrouter
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
### Listening services
```
netstat -an | egrep "LISTEN|TCP|UDP"
netstat -aun | egrep "LISTEN|TCP|UDP" 
```
### IPv6
```
ifconfig lo | grep "::1"
ls /etc/hostname6.*
```
## Network stack tuning
Tags: network-stack-tuning
### IP forwarding
```
cat /etc/notrouter
ndd /dev/ip ip_forwarding
ndd /dev/ip ip6_forwarding
```
### Source routing
```
ndd /dev/ip ip_forward_src_routed
ndd /dev/ip ip6_forward_src_routed
```
### Directed broadcasts
```
ndd /dev/ip ip_forward_directed_broadcasts
ndd /dev/ip ip6_forward_directed_broadcasts
```
### Echo broadcasts
```
ndd /dev/ip ip_respond_to_echo_broadcasts
ndd /dev/ip ip_respond_to_echo_multicast
ndd /dev/ip ip6_respond_to_echo_multicast
```
### Timestamp broadcasts
```
ndd /dev/ip ip_respond_to_timestamp
ndd /dev/ip ip_respond_to_timestamp_broadcast
```
### Redirects
```
ndd /dev/ip ip_ignore_redirect
ndd /dev/ip ip6_ignore_redirect
```
### Netmask broadcasts
```
ndd /dev/ip ip_respond_to_address_mask_broadcast
```
### TCP limits
```
ndd /dev/tcp tcp_conn_req_max_q
ndd /dev/tcp tcp_conn_req_max_q0
```
### Strict multihoming
```
ndd /dev/ip ip_strict_dst_multihoming
ndd /dev/ip ip6_strict_dst_multihoming
```
### Strong ISS
```
grep "TCP_STRONG_ISS" /etc/default/inetinit
ndd /dev/tcp tcp_strong_iss
```
### Generic tuning - we should break this down and cross reference OS
```
for device in arp ip ip6 rawip rawip6 sockets tcp udp
do
echo "Device: $device"
ndd /dev/$device '?' | grep -v '?' | while read parameter _
do
echo "Parameter: $parameter"
ndd /dev/$device $parameter
done
done
```
## Access control
Tags: access-control
### Firewall configured
```
cat /etc/ipf/ipf.conf
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
grep "AllowTcpForwarding" /etc/ssh/sshd_config
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
find / -name .ssh -type d -exec ls -la {} \;
```
### SSH sessions are throttled
```
grep "MaxStartups" /etc/ssh/sshd_config
```
### FTP users disallowed
```
cat /etc/ftpd/ftpusers
```
### NFS shares
```
cat /etc/dfs/sharetab
share -A
```
### Secure consoles
```
grep "CONSOLE" /etc/default/login
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
passwd -a -s | grep "NP"
```
### SNMP community strings
```
grep "community" /etc/snmp/conf/snmpd.conf
grep "community" /etc/net-snmp/conf/snmpd.conf
```
### Login policy
```
cat /etc/default/login
```
### Password aging
```
grep "WEEKS" /etc/default/passwd
```
### Password minimum strength
```
cat /etc/default/passwd
```
### Unlocked accounts
```
passwd -a -s | egrep -v "LK|NL"
```
### Lock after retries
```
grep "LOCK_AFTER_RETRIES" /etc/security/policy.conf
grep "RETRIES" /etc/default/login
```
### Session timeout
```
grep "TMOUT" /etc/profile
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
grep "HashKnownHosts" /etc/ssh/ssh_config
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
grep "password" /path/to/menu.lst | grep "md5"
```
### Crypto used for shadow
```
grep "CRYPT_DEFAULT" /etc/security/policy.conf
```
### Crypto allowed for shadow
```
grep "CRYPT_ALGORITHMS_ALLOW" /etc/security/policy.conf
```
## Software installed
Tags: software-installed
### OS release
```
uname -r
```
### Packages installed
```
pkginfo
pkg list
```
### Packages legit
```
pkg verify
```
### Patches installed
```
showrev -p
smpatch analyze
```
### Processes
```
ps -aef
```
### Services
```
svcs
```
### Development tools
```
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name cc -o -name gdb -o -name mdb \)
```
### 3rd party software
```
find /usr/local /opt -type f -ls
```
## Logging
Tags: logging
### Time synchronisation
```
grep "server" /etc/inet/ntp.conf
```
### Remote logging
```
grep "@" /etc/syslog.conf
```
### Cron logging
```
grep "CRONLOG" /etc/default/cron
```
### Auditing
```
ps -aef | grep "auditd"
```
## Resource limits
Tags: resource-limits
### Running limits
```
ulimit -a
```
### Tmp size
```
grep "swap" /etc/vfstab | grep "size"
```
### Disk quotas
```
mount | grep "quota"
```
## File permissions
Tags: file-permissions
### Init umask
```
grep "CMASK" /etc/default/init
```
### Root umask
```
grep "umask" /root/.profile
```
### User umask
```
grep "umask" /etc/profile
```
### Service umasks
```
grep "umask" /etc/init.d/* /etc/rc*.d/*
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
ls -la /var/log /var/adm
```
### SSH strict mode
```
grep "StrictModes" /etc/ssh/sshd_config
```
### Root home
```
ls -ld `cat /etc/passwd | grep "root" | cut -f 6 -d ":"`
ls -la /path/to/root
```
### IPC
```
ipcs -A
```
### Device policy
```
cat /etc/security/device_policy
```
## Exploit mitigation
Tags: exploit-mitigation
### Active mounts secure
```
mount | grep -v "noexec"
mount | grep -v "nosetuid"
mount | grep -v "nosuid"
mount | grep -v "norstchown"
```
### Configured mounts secure
```
grep -v "noexec" /etc/vfstab
grep -v "nosetuid" /etc/vfstab
grep -v "nosuid" /etc/vfstab
grep -v "norstchown" /etc/vfstab
```
### Separate partitions
```
mount
```
### Cron users
```
cat /etc/cron.allow
```
### At users
```
cat /etc/at.allow
```
### Non executable stack
```
grep "noexec_user_stack" /etc/system
```
### Stack randomisation
```
sxadm info
```
### Randomised binaries
```
find / -type f \( -perm -u+s -o -perm -g+s \) | while read file
do
echo "File: $file"
elfdump $file | grep "ASLR"
done
```
### Basic profile
```
grep "_GRANTED" /etc/security/policy.conf
```
### Console profile
```
grep "CONSOLE_USER" /etc/security/policy.conf
```
### Basic privs
```
grep "PRIV_DEFAULT" /etc/security/policy.conf
```
### Priv limits
```
grep "PRIV_LIMIT" /etc/security/policy.conf
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
```
### At scripts run
```
for file in /var/spool/cron/atjobs/*
do
echo "File: $file"
ls -l $file
cat $file
done
```
### Cron scripts run
```
for file in /var/spool/cron/crontabs/*
do
echo "File: $file"
ls -l $file
cat $file
done
```
### Default path
```
grep "PATH" /etc/profile
echo $PATH
```
### User paths
```
grep "PATH" /etc/skel/.profile
echo $PATH
```
### Init paths
```
grep "PATH" /etc/init.d/* /etc/rc*.d
```
### Default linker path
```
grep "LD_LIBRARY_PATH" /etc/profile
echo $LD_LIBRARY_PATH
```
### User linker paths
```
grep "LD_LIBRARY_PATH" /etc/skel/.profile
```
### Init linker paths
```
grep "LD_LIBRARY_PATH" /etc/init.d/* /etc/rc*.d
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
for file in /etc/sudoers.d/*
do
echo "File: $file"
cat $file
done
```
### Roles
```
cat /etc/user_attr
cat /etc/passwd | cut -f 1 -d ":" | while read user
do
echo "User: $user"
roles $user
done
```
### Profiles
```
cat /etc/security/prof_attr
for file in /etc/security/prof_attr.d/*
do
echo "File: $file"
cat $file
done
```
### Command profiles
```
cat /etc/security/exec_attr
for file in /etc/security/exec_attr.d/*
do
echo "File: $file"
cat $file
done
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
