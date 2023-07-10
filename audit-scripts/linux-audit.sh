echo "=== Linux > Informational > Date"===
date

echo "=== Linux > Informational > Hostname"===
hostname

echo "=== Linux > Informational > Kernel version"===
uname -a

echo "=== Linux > Informational > Network interfaces"===
ifconfig -a

echo "=== Linux > Informational > Running as"===
id

echo "=== Linux > Environment > PCI cards accessible"===
lspci

echo "=== Linux > Environment > USB peripherals accessible"===
lsusb

echo "=== Linux > Environment > Boot flags"===
cat /proc/cmdline

echo "=== Linux > Environment > Kernel logs"===
dmesg

echo "=== Linux > Environment > Kernel config"===
cat /boot/config-`uname -r`

echo "=== Linux > Environment > Loaded kernel modules"===
lsmod

echo "=== Linux > Environment > Kernel modules supported"===
grep "CONFIG_MODULES" /boot/config-`uname -r`

echo "=== Linux > Environment > Kernel modules"===
sysctl kernel.modules_disabled

echo "=== Linux > Environment > Grub password set"===
grep "password" /boot/grub/menu.lst

echo "=== Linux > Environment > Ctrl-alt-delete"===
grep "ctrlaltdel" /etc/inittab

echo "=== Linux > Environment > Kernel debugging"===
grep "sysrq" /etc/sysctl.conf

echo "=== Linux > Environment > Kernel hardening"===
cat /etc/sysctl.conf

echo "=== Linux > Environment > Active kernel hardening"===
sysctl -a

echo "=== Linux > Environment > Host is KVM"===
cat /proc/cpuinfo | grep -i "qemu"

echo "=== Linux > Environment > Host is VMware"===
dmidecode | grep -i "vmware"

echo "=== Linux > Environment > Host is VirtualBox"===
dmidecode | grep -i "virtualbox"

echo "=== Linux > Environment > Host is Xen"===
dmidecode | grep -i "xen"

echo "=== Linux > Environment > Host is container"===
cat /proc/1/cgroup

echo "=== Linux > Environment > Containers"===
docker ps -a

echo "=== Linux > Environment > K8s cluster"===
kubectl config view

echo "=== Linux > Environment > Environment variables set"===
env

echo "=== Linux > Environment > Currently logged in"===
who

echo "=== Linux > Environment > Logins"===
last

echo "=== Linux > Networking > ARP"===
arp -an

echo "=== Linux > Networking > Routing"===
netstat -rn

echo "=== Linux > Networking > Name services"===
cat /etc/nsswitch.conf

echo "=== Linux > Networking > Hosts"===
cat /etc/hosts

echo "=== Linux > Networking > DNS"===
cat /etc/resolv.conf

echo "=== Linux > Networking > Internet"===
ping -c 5 www.google.co.uk
ping -c 5 8.8.8.8

echo "=== Linux > Networking > Web accessible"===
wget -O - https://216.58.213.164
wget -O - https://www.google.com
curl https://216.58.213.164
curl https://www.google.com

echo "=== Linux > Networking > Internet by proxy"===
echo $http_proxy
echo $https_proxy
echo $ftp_proxy

echo "=== Linux > Networking > Listening services"===
netstat -anp | grep -v "unix" | grep "LISTEN"

echo "=== Linux > Networking > RPC services"===
rpcinfo -p

echo "=== Linux > Networking > IPv6"===
ifconfig lo | grep "::1"

echo "=== Linux > Networking > Network traffic"===
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

echo "=== Linux > Network stack tuning > Syncookies"===
cat /proc/sys/net/ipv4/tcp_syncookies
grep "syncookies" /etc/sysctl.conf

echo "=== Linux > Network stack tuning > IP forwarding"===
cat /proc/sys/net/ipv4/ip_forward
grep "ip_forward" /etc/sysctl.conf

echo "=== Linux > Network stack tuning > Network shares mounted"===
mount | grep "cifs"
mount | grep "nfs"

echo "=== Linux > Access control > Firewall configured"===
iptables -L
ip6tables -L

echo "=== Linux > Access control > TCP wrappers used"===
cat /etc/hosts.allow
cat /etc/hosts.deny

echo "=== Linux > Access control > .rhosts used"===
find / -name .rhosts -ls

echo "=== Linux > Access control > hosts.equiv used"===
cat /etc/hosts.equiv

echo "=== Linux > Access control > .netrc used"===
find / -name .netrc -ls

echo "=== Linux > Access control > Remote X"===
grep "nolistentcp" /etc/X11/xdm/Xservers /etc/kde/kdm/Xservers /etc/X11/gdm/gdm.conf /etc/X11/xinit/xserverrc

echo "=== Linux > Access control > X root logins"===
grep "AllowRootLogin" /etc/X11/xdm/kdmrc

echo "=== Linux > Access control > Account statuses"===
passwd -S -a

echo "=== Linux > Access control > Accounts with non-standard shells"===
grep -v "/bash$" /etc/passwd

echo "=== Linux > Access control > Valid shells"===
cat /etc/shells

echo "=== Linux > Access control > SSH ACLs configured"===
grep "Match" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH user logins"===
egrep "AllowUsers|DenyUsers|AllowGroups|DenyGroups" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH root logins"===
grep "PermitRootLogin" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH TCP forwarding"===
grep "AllowTCPForwarding" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH gateway ports"===
grep "GatewayPorts" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH VPN"===
grep "PermitTunnel" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH agent forwarding"===
grep "AllowAgentForwarding" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH X11 forwarding"===
grep "X11Forwarding" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH binds X11 to localhost"===
grep "X11UseLocalhost" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH reads environment from user file"===
grep "PermitUserEnvironment" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH accepts environment variables"===
grep "AcceptEnv" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH looks up connections in DNS"===
grep "UseDNS" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH uses privilege separation"===
grep "UsePrivilegeSeparation" /etc/ssh/sshd_config

echo "=== Linux > Access control > .shosts used"===
find / -name .shosts -ls

echo "=== Linux > Access control > shosts.equiv used"===
cat /etc/shosts.equiv

echo "=== Linux > Access control > SSH allows .rhosts"===
grep "IgnoreRhosts" /etc/ssh/sshd_config

echo "=== Linux > Access control > SSH public/private keys used"===
find / \( -name id_dsa -o -name id_dsa.pub -o -name id_rsa -o -name id_rsa.pub -o -name authorized_keys \) | while read file
do
ls -l $file
cat $file
done

echo "=== Linux > Access control > SSH sessions are throttled"===
egrep "MaxAuthTries|MaxSessions|MaxStartups" /etc/ssh/sshd_config

echo "=== Linux > Access control > FTP users disallowed"===
cat /etc/ftpusers

echo "=== Linux > Access control > NFS shares"===
cat /etc/exports

echo "=== Linux > Access control > SMB shares"===
cat /etc/samba/smb.conf

echo "=== Linux > Access control > Secure consoles"===
cat /etc/securetty

echo "=== Linux > Authentication > Banner"===
cat /etc/issue

echo "=== Linux > Authentication > MOTD"===
cat /etc/motd

echo "=== Linux > Authentication > Passwords"===
cat /etc/passwd
cat /etc/shadow

echo "=== Linux > Authentication > Active Directory enabled"===
ps -aef | grep "vasd|sssd|pbis|slapd|adclient"

echo "=== Linux > Authentication > Non-local users"===
getent passwd
getent group

echo "=== Linux > Authentication > Using NIS"===
ypcat passwd

echo "=== Linux > Authentication > Using Kerberos"===
for file in /tmp/krb5*
do
ls -l $file
done

echo "=== Linux > Authentication > Using LDAP"===
cat /etc/ldap/ldap.conf

echo "=== Linux > Authentication > SNMP community strings"===
grep community /etc/snmp/snmpd.conf

echo "=== Linux > Authentication > System Auth PAM"===
grep "limits" /etc/pam.d/*
grep "crack" /etc/pam.d/*
grep "nullok" /etc/pam.d/*
grep "md5" /etc/pam.d/*
grep "shadow" /etc/pam.d/*
grep "cap" /etc/pam.d/*

echo "=== Linux > Authentication > Login PAM"===
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "cap" /etc/pam.d/*

echo "=== Linux > Authentication > Su PAM"===
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "wheel" /etc/pam.d/*
grep "cap" /etc/pam.d/*

echo "=== Linux > Authentication > Sudo PAM"===
grep "nologin" /etc/pam.d/*
grep "securetty" /etc/pam.d/*
grep "limits" /etc/pam.d/*
grep "wheel" /etc/pam.d/*
grep "cap" /etc/pam.d/*

echo "=== Linux > Authentication > Password aging"===
grep "MAX_DAYS" /etc/login.defs
grep "MIN_DAYS" /etc/login.defs

echo "=== Linux > Authentication > Password minimum strength"===
grep "MIN_LEN" /etc/login.defs

echo "=== Linux > Authentication > Unlocked accounts"===
grep -v "!!" /etc/shadow

echo "=== Linux > Authentication > Session timeout"===
echo $TMOUT

echo "=== Linux > Authentication > SSH shows banner"===
grep "Banner" /etc/ssh/sshd_config

echo "=== Linux > Authentication > SSH shows MOTD"===
grep "PrintMotd" /etc/ssh/sshd_config

echo "=== Linux > Authentication > SSH uses PAM"===
grep "UsePAM" /etc/ssh/sshd_config

echo "=== Linux > Authentication > SSH allows empty passwords"===
grep "PermitEmptyPasswords" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > known_hosts encrypted"===
find / -name known_hosts | while read file
do
ls -l $file
cat $file
done

echo "=== Linux > Cryptography > SSH protocol"===
grep "Protocol" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH protocol 1 key regeneration"===
grep "KeyRegenerationInterval" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH protocol 1 key size"===
grep "ServerKeyBits" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH protocol 2 public key authentication"===
grep "PubkeyAuthentication" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH allows .rhosts with protocol 1 RSA"===
grep "RhostsRSAAuthentication" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH allows protocol 1 RSA"===
grep "RSAAuthentication" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH password based authentication"===
grep "PasswordAuthentication" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH ciphers"===
grep "Ciphers" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > SSH MACs"===
grep "MACs" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > Blacklisted keys"===
grep "PermitBlacklistedKeys" /etc/ssh/sshd_config

echo "=== Linux > Cryptography > Grub password obfuscated"===
grep "password" /boot/grub/menu.lst | grep "md5"

echo "=== Linux > Cryptography > Crypto used for shadow"===
egrep "MD5_CRYPT_ENAB|ENCRYPT_METHOD" /etc/login.defs

echo "=== Linux > Cryptography > Trusted CAs"===
md5sum /etc/ssl/certs/*

echo "=== Linux > Cryptography > Trusted keyrings"===
md5sum /etc/apt/trusted.gpg.d/*
md5sum /etc/pki/rpm-gpg/*

echo "=== Linux > Software installed > OS release"===
cat /etc/*-release /etc/debian_version

echo "=== Linux > Software installed > Packages installed"===
rpm -q -a
dpkg --list --no-pager

echo "=== Linux > Software installed > Packages for NOPC"===
rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\n'
dpkg -l --no-pager

echo "=== Linux > Software installed > Package management"===
cat /etc/apt/apt.conf
for file in /etc/apt/apt.conf /etc/apt/apt.conf.d/* /etc/apt/sources.list /etc/apt/sources.list.d/* /etc/yum.conf /etc/yum.repos.d/*.repo /etc/dnf/dnf.conf
do
ls -l $file
cat $file
done

echo "=== Linux > Software installed > Processes"===
ps -aef

echo "=== Linux > Software installed > Services"===
chkconfig --list

echo "=== Linux > Software installed > Systemd services"===
systemctl --no-pager

echo "=== Linux > Software installed > Systemd configs"===
find /usr/lib/systemd/* /etc/systemd/* -type f | while read file
do
ls -l $file
cat $file
done

echo "=== Linux > Software installed > Development tools"===
find / -type f \( -name perl -o -name gcc -o -name javac -o -name python -o -name ruby -o -name gdb \) -ls

echo "=== Linux > Software installed > 3rd party software"===
find /usr/local -ls
find /opt -ls

echo "=== Linux > Logging > Time synchronisation"===
ps -aef | grep "ntp"

echo "=== Linux > Logging > Syslog process"===
ps -aef | grep syslog

echo "=== Linux > Logging > Remote logging"===
grep "@" /etc/syslog.conf

echo "=== Linux > Logging > Syslog with rsyslog"===
for file in /etc/rsyslog.conf /etc/rsyslog.d/*
do
ls -l $file
cat $file
done

echo "=== Linux > Logging > Syslog with syslog-ng"===
cat /etc/syslog-ng/syslog-ng.conf

echo "=== Linux > Logging > Cron logging"===
grep "cron" /etc/syslog.conf

echo "=== Linux > Logging > User histories"===
find /home \( -name .sh_history -o -name .bash_history \) | while read file
do
ls -l $file
cat $file
done

echo "=== Linux > Logging > Auditing"===
ps -aef | grep auditd
auditctl -s

echo "=== Linux > Logging > Auditd policy"===
for file in /etc/audit/audit.rules /etc/audit/audit.rules.d/*
do
ls -l $file
cat $file
done

echo "=== Linux > Resource limits > Configured limits"===
cat /etc/security/limits.conf

echo "=== Linux > Resource limits > Running limits"===
ulimit -a

echo "=== Linux > Resource limits > Tmp size"===
mount | grep "/tmp" | grep "size"

echo "=== Linux > Resource limits > Disk quotas"===
mount | grep "quota"

echo "=== Linux > File permissions > Init umask"===
grep "umask" /etc/rc.d/init.d/functions

echo "=== Linux > File permissions > Syslog umask"===
grep "umask" /etc/rc.d/init.d/syslog /etc/sysconfig/syslog

echo "=== Linux > File permissions > Root umask"===
umask

echo "=== Linux > File permissions > User umask"===
grep "UMASK" /etc/login.defs
grep "umask" /home/*/.[a-z]*

echo "=== Linux > File permissions > Service umasks"===
grep "umask" /etc/rc.d/rc*.d/*

echo "=== Linux > File permissions > World readable files / directories"===
find / -perm -o+r -ls

echo "=== Linux > File permissions > World writable files / directories"===
find / -perm -o+w -ls

echo "=== Linux > File permissions > Group writable files / directories"===
find / -perm -o+w -ls

echo "=== Linux > File permissions > Unowned files / directories"===
find / -nouser -ls

echo "=== Linux > File permissions > Ungrouped files / directories"===
find / -nogroup -ls

echo "=== Linux > File permissions > Log files"===
ls -la /var/log

echo "=== Linux > File permissions > SSH strict mode"===
grep "StrictModes" /etc/ssh/sshd_config

echo "=== Linux > File permissions > Root home"===
find /root -ls

echo "=== Linux > File permissions > User homes"===
ls -la /home/*

echo "=== Linux > Exploit mitigation > Active mounts secure"===
mount | grep -v "nosetuid"
mount | grep -v "noexec"

echo "=== Linux > Exploit mitigation > Configured mounts secure"===
grep -v "nosetuid" /etc/fstab
grep -v "noexec" /etc/fstab

echo "=== Linux > Exploit mitigation > Separate partitions"===
mount | grep "/var"
mount | grep "/var/log"
mount | grep "/home"

echo "=== Linux > Exploit mitigation > SELinux supported"===
grep "SELINUX=" /etc/selinux/config

echo "=== Linux > Exploit mitigation > SELinux policy"===
grep "SELINUXTYPE=" /etc/selinux/config

echo "=== Linux > Exploit mitigation > SELinux running"===
selinux -v

echo "=== Linux > Exploit mitigation > SELinux processes"===
ps -aefZ

echo "=== Linux > Exploit mitigation > AppArmour supported"===
cat /sys/module/apparmor/parameters/enabled

echo "=== Linux > Exploit mitigation > AppArmour policy"===
aa-status

echo "=== Linux > Exploit mitigation > AppArmour processes"===
aa-unconfined
ps -aefZ

echo "=== Linux > Exploit mitigation > Cron users"===
cat /etc/cron.allow /etc/cron.deny

echo "=== Linux > Exploit mitigation > At users"===
cat /etc/at.allow /etc/at.deny

echo "=== Linux > Exploit mitigation > Stack randomisation"===
sysctl kernel.randomize_va_space

echo "=== Linux > Exploit mitigation > Non executable stack"===
grep "stack" /proc/[0-9]*/maps

echo "=== Linux > Exploit mitigation > Stack smashing protection"===
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

echo "=== Linux > Exploit mitigation > SetUID debug"===
ls -l /etc/suid-debug

echo "=== Linux > Exploit mitigation > PTrace scope"===
sysctl -a | grep "ptrace_scope"

echo "=== Linux > Privilege escalation > User capabilities"===
ls -l /etc/security/capability.conf
cat /etc/security/capability.conf

echo "=== Linux > Privilege escalation > Init scripts run"===
for file in /etc/rc.d/*.d/*
do
ls -l $file
cat $file
done

echo "=== Linux > Privilege escalation > At scripts run"===
for file in /var/spool/atjobs/*
do
ls -l $file
cat $file
done

echo "=== Linux > Privilege escalation > Cron scripts run"===
for file in /etc/crontab /var/spool/crontabs/* /etc/cron.d/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* /etc/cron.hourly/*
do
ls -l $file
cat $file
done

echo "=== Linux > Privilege escalation > Default path"===
echo $PATH

echo "=== Linux > Privilege escalation > User paths"===
for file in /etc/profile /etc/bash.bashrc /home/*/.[a-z]*
do
ls -l $file
grep "PATH" $file
done

echo "=== Linux > Privilege escalation > Init paths"===
for file in /etc/rc.d/init.d/*
do
ls -l $file
grep "PATH" $file
done

echo "=== Linux > Privilege escalation > Default linker path"===
for file in /etc/ld.so.conf /etc/ld.so.conf.d/*
do
ls -l $file
cat $file
done

echo "=== Linux > Privilege escalation > User linker paths"===
for file in /etc/profile /etc/bash.bashrc /home/*/.[a-z]*
do
ls -l $file
grep "LD_LIBRARY_PATH" $file
done

echo "=== Linux > Privilege escalation > Init linker paths"===
for file in /etc/rc.d/init.d/*
do
ls -l $file
grep "LD_LIBRARY_PATH" $file
done

echo "=== Linux > Privilege escalation > SetUID files"===
find / -perm -u+s -type f -ls

echo "=== Linux > Privilege escalation > SetGID files"===
find / -perm -g+s -type f -ls

echo "=== Linux > Privilege escalation > Sudo configuration"===
for file in /etc/sudoers /etc/sudoers.d/*
do
ls -l $file
cat $file
done

echo "=== Linux > Privilege escalation > Insecure RPATHs"===
find / \( -perm -o+s -o -g+s \) | while read file
do
ls -l $file
objdump -x $file | egrep "RPATH|RUNPATH"
done

echo "=== Linux > Privilege escalation > Processes with open files"===
lsof

echo "=== Linux > Privilege escalation > Proc tree"===
find /proc -type f | while read file
do
ls -l $file
strings $file
done

echo "=== Linux > Privilege escalation > Sys tree"===
find /sys -type f | while read file
do
ls -l $file
strings $file
done

echo "=== Linux > Privilege escalation > POSIX shared memory"===
ls -la /dev/shm

echo "=== Linux > Privilege escalation > System V shared memory"===
ipcs -a

echo "=== Linux > Privilege escalation > UNIX sockets"===
find / -type s -ls

echo "=== Linux > Common services > SSH config"===
cat /etc/ssh/sshd_config

echo "=== Linux > Common services > SSH client config"===
cat /etc/ssh/ssh_config

echo "=== Linux > Common services > SSH running config"===
sshd -T

echo "=== Linux > Common services > Web server config"===
find / -name httpd.conf | while read file
do
ls -l $file
cat $file
done

echo "=== Linux > Common services > Web server logs"===
find / -name access.log | while read file
do
ls -l $file
grep -i "curl|wget|python|perl" $file
done

echo "=== Linux > Common services > Web server cgi-bin"===
find / -name cgi-bin | while read file
do
ls -l $file
done

echo "=== Linux > Important file locations > Configs"===
tar cvf etc-`hostname`.tar /etc
gzip etc-`hostname`.tar

echo "=== Linux > Important file locations > Logs"===
tar cvf logs-`hostname`.tar /var/log
gzip logs-`hostname`.tar

echo "=== Linux > Important file locations > SetUID and setGIDs files"===
tar cvf suids-`hostname`.tar `find / \( -perm -o+s -o -perm -g+s \)`
gzip suids-`hostname`.tar

echo "=== Linux > Important file locations > Temporary locations"===
tar cvf tmp-`hostname`.tar /tmp /var/tmp /dev/shm /dev/mqueue /run/screen /run/lock /var/crash
gzip tmp-`hostname`.tar

echo "=== Linux > Important file locations > Core files"===
tar cvf core-`hostname`.tar `find / -type f \( -name core -o -name core.[0-9]* \)`
gzip core-`hostname`.tar


