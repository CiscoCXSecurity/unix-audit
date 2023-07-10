echo "=== Solaris > Informational > Hostname"===
cat /etc/nodename

echo "=== Solaris > Informational > Kernel version"===
uname -a

echo "=== Solaris > Informational > Network interfaces"===
ifconfig -a

echo "=== Solaris > Environment > PCI cards accessible"===
prtconf -v

echo "=== Solaris > Environment > USB peripherals accessible"===
prtconf -v

echo "=== Solaris > Environment > Loaded kernel modules"===
modinfo

echo "=== Solaris > Environment > OBP password set"===
eeprom | grep "security-mode"

echo "=== Solaris > Environment > OBP banner set"===
eeprom | grep "oem-banner"

echo "=== Solaris > Environment > Grub password set"===
/sbin/bootadm list-menu
grep password "/path/to/menu.lst"

echo "=== Solaris > Environment > Stop-A"===
grep "abort_enable" /etc/system

echo "=== Solaris > Environment > Zones"===
zoneadm list

echo "=== Solaris > Networking > ARP"===
arp -a
cat /etc/ethers

echo "=== Solaris > Networking > Routing"===
netstat -rn
cat /etc/defaultrouter

echo "=== Solaris > Networking > Name services"===
cat /etc/nsswitch.conf

echo "=== Solaris > Networking > Hosts"===
cat /etc/hosts

echo "=== Solaris > Networking > DNS"===
cat /etc/resolv.conf

echo "=== Solaris > Networking > Internet"===
ping -c 5 www.google.co.uk
ping -c 5 8.8.8.8

echo "=== Solaris > Networking > Listening services"===
netstat -an | egrep "LISTEN|TCP|UDP"
netstat -aun | egrep "LISTEN|TCP|UDP"

echo "=== Solaris > Networking > IPv6"===
ifconfig lo | grep "::1"
ls /etc/hostname6.*

echo "=== Solaris > Network stack tuning > IP forwarding"===
cat /etc/notrouter
ndd /dev/ip ip_forwarding
ndd /dev/ip ip6_forwarding

echo "=== Solaris > Network stack tuning > Source routing"===
ndd /dev/ip ip_forward_src_routed
ndd /dev/ip ip6_forward_src_routed

echo "=== Solaris > Network stack tuning > Directed broadcasts"===
ndd /dev/ip ip_forward_directed_broadcasts
ndd /dev/ip ip6_forward_directed_broadcasts

echo "=== Solaris > Network stack tuning > Echo broadcasts"===
ndd /dev/ip ip_respond_to_echo_broadcasts
ndd /dev/ip ip_respond_to_echo_multicast
ndd /dev/ip ip6_respond_to_echo_multicast

echo "=== Solaris > Network stack tuning > Timestamp broadcasts"===
ndd /dev/ip ip_respond_to_timestamp
ndd /dev/ip ip_respond_to_timestamp_broadcast

echo "=== Solaris > Network stack tuning > Redirects"===
ndd /dev/ip ip_ignore_redirect
ndd /dev/ip ip6_ignore_redirect

echo "=== Solaris > Network stack tuning > Netmask broadcasts"===
ndd /dev/ip ip_respond_to_address_mask_broadcast

echo "=== Solaris > Network stack tuning > TCP limits"===
ndd /dev/tcp tcp_conn_req_max_q
ndd /dev/tcp tcp_conn_req_max_q0

echo "=== Solaris > Network stack tuning > Strict multihoming"===
ndd /dev/ip ip_strict_dst_multihoming
ndd /dev/ip ip6_strict_dst_multihoming

echo "=== Solaris > Network stack tuning > Strong ISS"===
grep "TCP_STRONG_ISS" /etc/default/inetinit
ndd /dev/tcp tcp_strong_iss

echo "=== Solaris > Network stack tuning > Generic tuning - we should break this down and cross reference OS"===
for device in arp ip ip6 rawip rawip6 sockets tcp udp
do
echo "Device: $device"
ndd /dev/$device '?' | grep -v '?' | while read parameter _
do
echo "Parameter: $parameter"
ndd /dev/$device $parameter
done
done

echo "=== Solaris > Access control > Firewall configured"===
cat /etc/ipf/ipf.conf

echo "=== Solaris > Access control > TCP wrappers used"===
cat /etc/hosts.allow
cat /etc/hosts.deny

echo "=== Solaris > Access control > .rhosts used"===
find / -name .rhosts -ls

echo "=== Solaris > Access control > hosts.equiv used"===
cat /etc/hosts.equiv

echo "=== Solaris > Access control > .netrc used"===
find / -name .netrc -ls

echo "=== Solaris > Access control > Remote X"===
netstat -an | grep "LISTEN" | egrep "6000|177"

echo "=== Solaris > Access control > Accounts with non-standard shells"===
grep -v "/bash$" /etc/passwd

echo "=== Solaris > Access control > Valid shells"===
cat /etc/shells

echo "=== Solaris > Access control > SSH ACLs configured"===
grep "Match" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH user logins"===
egrep "AllowUsers|DenyUsers|AllowGroups|DenyGroups" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH root logins"===
grep "PermitRootLogin" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH TCP forwarding"===
grep "AllowTcpForwarding" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH gateway ports"===
grep "GatewayPorts" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH VPN"===
grep "PermitTunnel" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH agent forwarding"===
grep "AllowAgentForwarding" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH X11 forwarding"===
grep "X11Forwarding" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH binds X11 to localhost"===
grep "X11UseLocalhost" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH reads environment from user file"===
grep "PermitUserEnvironment" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH accepts environment variables"===
grep "AcceptEnv" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH looks up connections in DNS"===
grep "UseDNS" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH uses privilege separation"===
grep "UsePrivilegeSeparation" /etc/ssh/sshd_config

echo "=== Solaris > Access control > .shosts used"===
find / -name .shosts -ls

echo "=== Solaris > Access control > shosts.equiv used"===
cat /etc/shosts.equiv

echo "=== Solaris > Access control > SSH allows .rhosts"===
grep "IgnoreRhosts" /etc/ssh/sshd_config

echo "=== Solaris > Access control > SSH public/private keys used"===
find / -name .ssh -type d -exec ls -la {} \;

echo "=== Solaris > Access control > SSH sessions are throttled"===
grep "MaxStartups" /etc/ssh/sshd_config

echo "=== Solaris > Access control > FTP users disallowed"===
cat /etc/ftpd/ftpusers

echo "=== Solaris > Access control > NFS shares"===
cat /etc/dfs/sharetab
share -A

echo "=== Solaris > Access control > Secure consoles"===
grep "CONSOLE" /etc/default/login

echo "=== Solaris > Authentication > Banner"===
cat /etc/issue

echo "=== Solaris > Authentication > MOTD"===
cat /etc/motd

echo "=== Solaris > Authentication > Passwords"===
cat /etc/passwd
cat /etc/shadow
passwd -a -s | grep "NP"

echo "=== Solaris > Authentication > SNMP community strings"===
grep "community" /etc/snmp/conf/snmpd.conf
grep "community" /etc/net-snmp/conf/snmpd.conf

echo "=== Solaris > Authentication > Login policy"===
cat /etc/default/login

echo "=== Solaris > Authentication > Password aging"===
grep "WEEKS" /etc/default/passwd

echo "=== Solaris > Authentication > Password minimum strength"===
cat /etc/default/passwd

echo "=== Solaris > Authentication > Unlocked accounts"===
passwd -a -s | egrep -v "LK|NL"

echo "=== Solaris > Authentication > Lock after retries"===
grep "LOCK_AFTER_RETRIES" /etc/security/policy.conf
grep "RETRIES" /etc/default/login

echo "=== Solaris > Authentication > Session timeout"===
grep "TMOUT" /etc/profile

echo "=== Solaris > Authentication > SSH shows banner"===
grep "Banner" /etc/ssh/sshd_config

echo "=== Solaris > Authentication > SSH shows MOTD"===
grep "PrintMotd" /etc/ssh/sshd_config

echo "=== Solaris > Authentication > SSH allows empty passwords"===
grep "PermitEmptyPasswords" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > known_hosts encrypted"===
grep "HashKnownHosts" /etc/ssh/ssh_config

echo "=== Solaris > Cryptography > SSH protocol"===
grep "Protocol" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH protocol 1 key regeneration"===
grep "KeyRegenerationInterval" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH protocol 1 key size"===
grep "ServerKeyBits" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH protocol 2 public key authentication"===
grep "PubkeyAuthentication" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH allows .rhosts with protocol 1 RSA"===
grep "RhostsRSAAuthentication" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH allows protocol 1 RSA"===
grep "RSAAuthentication" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH password based authentication"===
grep "PasswordAuthentication" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH ciphers"===
grep "Ciphers" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > SSH MACs"===
grep "MACs" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > Blacklisted keys"===
grep "PermitBlacklistedKeys" /etc/ssh/sshd_config

echo "=== Solaris > Cryptography > Grub password obfuscated"===
grep "password" /path/to/menu.lst | grep "md5"

echo "=== Solaris > Cryptography > Crypto used for shadow"===
grep "CRYPT_DEFAULT" /etc/security/policy.conf

echo "=== Solaris > Cryptography > Crypto allowed for shadow"===
grep "CRYPT_ALGORITHMS_ALLOW" /etc/security/policy.conf

echo "=== Solaris > Software installed > OS release"===
uname -r

echo "=== Solaris > Software installed > Packages installed"===
pkginfo
pkg list

echo "=== Solaris > Software installed > Packages legit"===
pkg verify

echo "=== Solaris > Software installed > Patches installed"===
showrev -p
smpatch analyze

echo "=== Solaris > Software installed > Processes"===
ps -aef

echo "=== Solaris > Software installed > Services"===
svcs

echo "=== Solaris > Software installed > Development tools"===
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name cc -o -name gdb -o -name mdb \)

echo "=== Solaris > Software installed > 3rd party software"===
find /usr/local /opt -type f -ls

echo "=== Solaris > Logging > Time synchronisation"===
grep "server" /etc/inet/ntp.conf

echo "=== Solaris > Logging > Remote logging"===
grep "@" /etc/syslog.conf

echo "=== Solaris > Logging > Cron logging"===
grep "CRONLOG" /etc/default/cron

echo "=== Solaris > Logging > Auditing"===
ps -aef | grep "auditd"

echo "=== Solaris > Resource limits > Running limits"===
ulimit -a

echo "=== Solaris > Resource limits > Tmp size"===
grep "swap" /etc/vfstab | grep "size"

echo "=== Solaris > Resource limits > Disk quotas"===
mount | grep "quota"

echo "=== Solaris > File permissions > Init umask"===
grep "CMASK" /etc/default/init

echo "=== Solaris > File permissions > Root umask"===
grep "umask" /root/.profile

echo "=== Solaris > File permissions > User umask"===
grep "umask" /etc/profile

echo "=== Solaris > File permissions > Service umasks"===
grep "umask" /etc/init.d/* /etc/rc*.d/*

echo "=== Solaris > File permissions > World readable files / directories"===
find / -perm -o+r -ls

echo "=== Solaris > File permissions > World writable files / directories"===
find / -perm -o+w -ls

echo "=== Solaris > File permissions > Group writable files / directories"===
find / -perm -o+w -ls

echo "=== Solaris > File permissions > Unowned files / directories"===
find / -nouser -ls

echo "=== Solaris > File permissions > Ungrouped files / directories"===
find / -nogroup -ls

echo "=== Solaris > File permissions > Log files"===
ls -la /var/log /var/adm

echo "=== Solaris > File permissions > SSH strict mode"===
grep "StrictModes" /etc/ssh/sshd_config

echo "=== Solaris > File permissions > Root home"===
ls -ld `cat /etc/passwd | grep "root" | cut -f 6 -d ":"`
ls -la /path/to/root

echo "=== Solaris > File permissions > IPC"===
ipcs -A

echo "=== Solaris > File permissions > Device policy"===
cat /etc/security/device_policy

echo "=== Solaris > Exploit mitigation > Active mounts secure"===
mount | grep -v "noexec"
mount | grep -v "nosetuid"
mount | grep -v "nosuid"
mount | grep -v "norstchown"

echo "=== Solaris > Exploit mitigation > Configured mounts secure"===
grep -v "noexec" /etc/vfstab
grep -v "nosetuid" /etc/vfstab
grep -v "nosuid" /etc/vfstab
grep -v "norstchown" /etc/vfstab

echo "=== Solaris > Exploit mitigation > Separate partitions"===
mount

echo "=== Solaris > Exploit mitigation > Cron users"===
cat /etc/cron.allow

echo "=== Solaris > Exploit mitigation > At users"===
cat /etc/at.allow

echo "=== Solaris > Exploit mitigation > Non executable stack"===
grep "noexec_user_stack" /etc/system

echo "=== Solaris > Exploit mitigation > Stack randomisation"===
sxadm info

echo "=== Solaris > Exploit mitigation > Randomised binaries"===
find / -type f \( -perm -u+s -o -perm -g+s \) | while read file
do
echo "File: $file"
elfdump $file | grep "ASLR"
done

echo "=== Solaris > Exploit mitigation > Basic profile"===
grep "_GRANTED" /etc/security/policy.conf

echo "=== Solaris > Exploit mitigation > Console profile"===
grep "CONSOLE_USER" /etc/security/policy.conf

echo "=== Solaris > Exploit mitigation > Basic privs"===
grep "PRIV_DEFAULT" /etc/security/policy.conf

echo "=== Solaris > Exploit mitigation > Priv limits"===
grep "PRIV_LIMIT" /etc/security/policy.conf

echo "=== Solaris > Privilege escalation > Init scripts run"===
cat /etc/inittab
cat /etc/inittab | cut -f 4 -d: | cut -f 1 -d " " | while read file
do
echo "File: $file"
ls -la $file
done

echo "=== Solaris > Privilege escalation > At scripts run"===
for file in /var/spool/cron/atjobs/*
do
echo "File: $file"
ls -l $file
cat $file
done

echo "=== Solaris > Privilege escalation > Cron scripts run"===
for file in /var/spool/cron/crontabs/*
do
echo "File: $file"
ls -l $file
cat $file
done

echo "=== Solaris > Privilege escalation > Default path"===
grep "PATH" /etc/profile
echo $PATH

echo "=== Solaris > Privilege escalation > User paths"===
grep "PATH" /etc/skel/.profile
echo $PATH

echo "=== Solaris > Privilege escalation > Init paths"===
grep "PATH" /etc/init.d/* /etc/rc*.d

echo "=== Solaris > Privilege escalation > Default linker path"===
grep "LD_LIBRARY_PATH" /etc/profile
echo $LD_LIBRARY_PATH

echo "=== Solaris > Privilege escalation > User linker paths"===
grep "LD_LIBRARY_PATH" /etc/skel/.profile

echo "=== Solaris > Privilege escalation > Init linker paths"===
grep "LD_LIBRARY_PATH" /etc/init.d/* /etc/rc*.d

echo "=== Solaris > Privilege escalation > SetUID files"===
find / -perm -u+s -type f -ls

echo "=== Solaris > Privilege escalation > SetGID files"===
find / -perm -g+s -type f -ls

echo "=== Solaris > Privilege escalation > Sudo configuration"===
cat /etc/sudoers
for file in /etc/sudoers.d/*
do
echo "File: $file"
cat $file
done

echo "=== Solaris > Privilege escalation > Roles"===
cat /etc/user_attr
cat /etc/passwd | cut -f 1 -d ":" | while read user
do
echo "User: $user"
roles $user
done

echo "=== Solaris > Privilege escalation > Profiles"===
cat /etc/security/prof_attr
for file in /etc/security/prof_attr.d/*
do
echo "File: $file"
cat $file
done

echo "=== Solaris > Privilege escalation > Command profiles"===
cat /etc/security/exec_attr
for file in /etc/security/exec_attr.d/*
do
echo "File: $file"
cat $file
done

echo "=== Solaris > Common services > SSH running config"===
sshd -T

echo "=== Solaris > Common services > Web server config"===
find / -name httpd.conf | while read file
do
echo "File: $file"
ls -l $file
cat $file
done

echo "=== Solaris > Common services > Web server cgi-bin"===
find /usr/lib -name cgi-bin | while read file
do
echo "File: $file"
ls -l $file
done


