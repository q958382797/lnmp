#!/usr/bin/env bash
export LANG=en_US.UTF-8
#查看当前用户是否是root用户
if [ $UID -ne 0 ];then
echo -e "\033[31mError: 你应该用root账户执行该脚本\033[0m"
exit 1;
fi
clear
#==================================================================#
#绿字正确输出
succ_echo()
        {
            printf "\033[32m $* \033[0m\n"
        }		
#==================================================================#
#环境配置
Inst_System(){
#建立软件下载目录、脚本存放目录
mkdir -p /root/{software,sh}
#手工配置主机名和端口号
echo '自定义主机名:'
read 'Hostname'
echo '自定义远程端口:'
read 'Port'
#SSH
#修改ssh端口号
sed -i "s@^#Port.*@Port "$Port"@g" /etc/ssh/sshd_config
#OpenSSH在用户登录的时候会验证IP，它根据用户的IP使用反向DNS找到主机名，再使用DNS找到IP地址，最后匹配一下登录的IP是否合法。如果客户机的IP没有域名，或者DNS服务器很慢或不通，那么登录就会很花时间
sed -i 's/#UseDNS yes/UseDNS no/g' /etc/ssh/sshd_config
#关闭ssh的gssapi认证
sed -i 's/^GSSAPIAuthentication yes$/GSSAPIAuthentication no/' /etc/ssh/sshd_config
#关闭maildrop,其他用户的CRONTAB也注意加上MAILTO="" 避免脚本的输出信息或错误信息塞满maildrop目录
sed -i 's/MAILTO=root/MAILTO=""/g' /etc/crontab
#判断centos7.x或者centos6.x

if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
hostnamectl set-hostname $Hostname
hostname $Hostname
echo "$Hostname" > /etc/hostname
systemctl restart sshd
systemctl restart crond

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
sed -i /HOSTNAME/d /etc/sysconfig/network
echo "HOSTNAME="$Hostname"" >>/etc/sysconfig/network
/etc/init.d/sshd restart
/etc/init.d/crond restart
fi

#关闭selinux
sed -i "s@SELINUX=enforcing@SELINUX=disabled@g" /etc/selinux/config
setenforce 0

grep "nameserver 8.8.8.8" /etc/resolv.conf
[ $? -ne 0 ] && echo "nameserver 8.8.8.8" >>/etc/resolv.conf && echo "nameserver 114.114.114.114" >>/etc/resolv.conf

#调整文件打开数
echo "* soft nofile 655360" >> /etc/security/limits.conf
echo "* hard nofile 655360" >> /etc/security/limits.conf
echo "* soft nproc 655360" >> /etc/security/limits.conf
echo "* hard nproc 655360" >> /etc/security/limits.conf
echo "* soft memlock unlimited" >> /etc/security/limits.conf
echo "* hard memlock unlimited" >> /etc/security/limits.conf
echo "DefaultLimitNOFILE=1024000" >> /etc/systemd/system.conf 
echo "DefaultLimitNPROC=1024000" >> /etc/systemd/system.conf
ulimit -SHn 655350
#更新yum源为阿里云
#判断centos7.x或者centos6.x
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
yum -y install wget
mkdir -p /etc/yum.repos.d/bak
mv /etc/yum.repos.d/*.repo  /etc/yum.repos.d/bak
wget -O /etc/yum.repos.d/CentOS7-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
wget -O /etc/yum.repos.d/epel7.repo http://mirrors.aliyun.com/repo/epel-7.repo
sed -i "s@gpgcheck=1@gpgcheck=0@g" /etc/yum.repos.d/*.repo
yum clean all
yum makecache
yum install -y net-tools bind-utils

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
yum -y install wget
mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo.bak
wget -O /etc/yum.repos.d/CentOS6-Base.repo http://mirrors.aliyun.com/repo/Centos-6.repo
mv /etc/yum.repos.d/epel.repo /etc/yum.repos.d/epel.repo.backup
mv /etc/yum.repos.d/epel-testing.repo /etc/yum.repos.d/epel-testing.repo.backup
wget -O /etc/yum.repos.d/epel6.repo http://mirrors.aliyun.com/repo/epel-6.repo
sed -i "s@gpgcheck=1@gpgcheck=0@g" /etc/yum.repos.d/*.repo
yum clean all
yum makecache
fi

#下载base和lib
#centos6和7大部分通用
yum -y epel-release
yum -y update
yum -y install gcc gcc-c++ make automake cmake tcl dstat bison flex screen libjpeg-turbo cronie kernel-devel krb5-devel libffi-devel \
openssl openssl-devel ncurses ncurses-devel pcre pcre-devel curl curl-devel lrzsz patch vixie-cron imake compat-libstdc++-33 \
telnet iftop bash  strace mtr sysstat lsof bind-utils rsync libtool libtool-ltdl ntp readline autoconf e2fsprogs e2fsprogs-devel \
libpcap libpcap-devel libxml2.x86_64 libxml2-devel.x86_64 bc libpng libpng-devel libtool-ltdl-devel gettext gettext-devel openldap openldap-devel \
freetype freetype-devel zlib zlib-devel libmcrypt libmcrypt-devel htop git libjpeg-turbo-devel ImageMagick ImageMagick-devel \
libxml2 libxml2-devel bzip2 bzip2-devel libXpm-devel libX11-devel libxslt-devel expat-devel libcurl libevent-devel libevent \
libcurl-devel glibc glibc-devel glib2 glib2-devel gd gd-devel gmp-devel readline-devel xmlrpc-c xmlrpc-c-devel ImageMagick ImageMagick-devel

#优化TCP
chmod +x /etc/rc.d/rc.local
cp /etc/sysctl.conf{,.bk}
#判断centos7.x或者centos6.x
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
cat <<EOF > /etc/rc.d/rc.local
#!/bin/bash
# THIS FILE IS ADDED FOR COMPATIBILITY PURPOSES
#
# It is highly advisable to create own systemd services or udev rules
# to run scripts during boot instead of using this file.
#
# In contrast to previous versions due to parallel execution during boot
# this script will NOT be run after all other services.
#
# Please note that you must run 'chmod +x /etc/rc.d/rc.local' to ensure
# that this script will be executed during boot.

touch /var/lock/subsys/local
modprobe kvm_intel
modprobe ip_conntrack
modprobe br_netfilter
/usr/bin/rsync --daemon
ulimit -SHn 65535
EOF
cat <<EOF > /etc/sysctl.conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_retries2 = 5
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 40000
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_wmem = 8192 436600 873200
net.ipv4.tcp_rmem  = 32768 436600 873200
net.ipv4.tcp_mem = 94500000 91500000 92700000
net.ipv4.tcp_max_orphans = 3276800	
net.ipv4.tcp_fin_timeout = 30
net.core.netdev_max_backlog = 32768
net.core.somaxconn = 32768
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
net.nf_conntrack_max = 655360
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
fs.file-max = 6553560
kernel.sysrq = 0
kernel.core_uses_pid = 1
kernel.sem = 500 64000 64 256
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.shmmax = 68719476736
kernel.shmall = 4294967296
EOF
modprobe ip_conntrack
modprobe br_netfilter
sysctl -p

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
cat  <<EOF > /etc/rc.d/rc.local
#!/bin/sh
#
# This script will be executed *after* all the other init scripts.
# You can put your own initialization stuff in here if you don't
# want to do the full Sys V style init stuff.

ulimit -SHn 65535
modprobe nf_conntrack
modprobe ip_conntrack
modprobe bridge
/usr/bin/rsync --daemon
touch /var/lock/subsys/local
EOF
cat  << EOF > /etc/sysctl.conf
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_mem = 94500000 915000000 927000000
net.ipv4.tcp_max_syn_backlog = 819200
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_fin_timeout = 30
net.netfilter.nf_conntrack_tcp_timeout_established = 120
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_close_wait = 60
net.netfilter.nf_conntrack_tcp_timeout_fin_wait = 120
net.netfilter.nf_conntrack_max = 1048576
net.bridge.bridge-nf-call-ip6tables = 0
net.bridge.bridge-nf-call-iptables = 0
net.bridge.bridge-nf-call-arptables = 0
net.ipv4.ip_local_port_range = 1024  65535
net.ipv4.ip_forward = 0
net.nf_conntrack_max = 655360
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.accept_source_route = 0
net.core.wmem_max = 16777216
net.core.wmem_default = 8388608
net.core.somaxconn = 32768
net.core.rmem_max = 16777216
net.core.rmem_default = 8388608
net.core.netdev_max_backlog = 32768
kernel.sysrq = 0
kernel.shmmax = 4294967295
kernel.shmall = 268435456
kernel.msgmnb = 65536
kernel.msgmax = 65536
kernel.core_uses_pid = 1
fs.file-max = 6553560
net.ipv4.tcp_max_tw_buckets = 30000
EOF
modprobe nf_conntrack
modprobe ip_conntrack
modprobe bridge
sysctl -p
fi

# 加载依赖库 编译时候没指定prefix会安装到/usr/local/下 会导致寻找不到依赖库 
if [ -z "`grep "/usr/local/lib" /etc/ld.so.conf`" ];then
echo "/usr/local/lib" >> /etc/ld.so.conf
ldconfig
fi

#rsync配置
cat << EOF > /etc/rsyncd.conf
uid = root
gid = root
use chroot = no
max connections = 4
pid file = /var/run/rsyncd.pid
lock file = /var/run/rsync.lock
log file = /var/log/rsyncd.log

#[lalala]
#path = /
#ignore errors
#read only = no
#hosts allow = 192.168.1.0/24
EOF

#防火墙配置
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl stop firewalld
systemctl disable firewalld
yum -y install iptables-devel iptables-services
#先允许所有  
\iptables -P INPUT ACCEPT  
#清空所有默认规则  
\iptables -F  
#清空所有自定义规则  
\iptables -X  
#所有计数器归0  
\iptables -Z  
#允许来自于lo接口的数据包(本地访问)
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT  
iptables -A INPUT -i lo -j ACCEPT
#防止syn攻击
iptables -I FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
#ping洪水攻击每秒一次
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
#防止端口扫描
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
#开放22端口 
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
#开放21端口(FTP)  
iptables -A INPUT -p tcp --dport 21 -j ACCEPT  
#允许ping
iptables -A INPUT -p icmp -j ACCEPT
#允许rsync
iptables -A INPUT -p tcp --dport 873 -j ACCEPT
service iptables save
systemctl restart iptables
systemctl enable iptables

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
#先允许所有,不然有可能会杯具  
\iptables -P INPUT ACCEPT  
#清空所有默认规则  
\iptables -F  
#清空所有自定义规则  
\iptables -X  
#所有计数器归0  
\iptables -Z 
#允许ping
iptables -A INPUT -p icmp -j ACCEPT
#rsync
iptables -A INPUT -p tcp --dport 873 -j ACCEPT
#允许本地回环接口(即运行本机访问本机)
iptables -A INPUT -s 127.0.0.1 -d 127.0.0.1 -j ACCEPT
iptables -A INPUT -i lo -p all -j ACCEPT
#防止syn攻击
iptables -I FORWARD -p tcp --syn -m limit --limit 1/s -j ACCEPT
#ping洪水攻击每秒一次
iptables -A FORWARD -p icmp --icmp-type echo-request -m limit --limit 1/s -j ACCEPT
#防止端口扫描
iptables -A FORWARD -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s -j ACCEPT
#允许已建立的或相关连的通行 
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
#开放22端口  
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
#开放21端口(FTP)  
iptables -A INPUT -p tcp --dport 21 -j ACCEPT
service iptables save
service iptables restart
fi

}

Inst_Nginx-1.16.1(){
#关闭selinux
setenforce 0
sed -i "s@SELINUX=enforcing@SELINUX=disabled@g" /etc/selinux/config
#测试有没有mysql用户以及有没有配置完nginx
test -f /usr/local/nginx/sbin/nginx && echo "nginx已经配置好了" && exit 0
[ -z "`grep www /etc/group`" ] && groupadd www && useradd -g www www -M -s /sbin/nologin
yum -y install git gcc gcc-c++ zip unzip automake autoconf libtool make glibc gd-devel pcre-devel libmcrypt-devel mhash-devel libxslt-devel libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel libxml2 libxml2-devel zlib zlib-devel glibc glibc-devel glib2 glib2-devel bzip2 bzip2-devel ncurses ncurses-devel curl curl-devel e2fsprogs e2fsprogs-devel krb5-devel libidn libidn-devel openssl openssl-devel libevent libevent-devel
mkdir -p /root/software && cd /root/software
#官网下载nginx-1.16.1
if [ ! -f /root/software/nginx-1.16.1.tar.gz ];then
wget -c http://nginx.org/download/nginx-1.16.1.tar.gz
fi
#waf防护
if [ ! -f /root/software/0.56.tar.gz ];then
cd /root/software && wget https://github.com/nbs-system/naxsi/archive/0.56.tar.gz && tar -xf 0.56.tar.gz
fi
#下载并安装ngx_cache_purge模块
if [ ! -f /root/software/ngx_cache_purge-2.3.tar.gz ];then
cd /root/software && wget http://labs.frickle.com/files/ngx_cache_purge-2.3.tar.gz && tar -xvf ngx_cache_purge-2.3.tar.gz
fi
#下载并安装nginx-module-vts模块
if [ ! -f /root/software/nginx-module-vts ];then
git clone https://github.com/vozlt/nginx-module-vts
fi
#下载并安装fair模块
cd /root/software && git clone https://github.com/gnosek/nginx-upstream-fair.git && sed -i 's/default_port/no_port/g' /root/software/nginx-upstream-fair/ngx_http_upstream_fair_module.c
#安装nginx
cd /root/software && tar -xvf nginx-1.16.1.tar.gz && cd nginx-1.16.1
./configure --prefix=/usr/local/nginx --user=www --group=www --with-http_ssl_module --with-stream --with-http_stub_status_module --with-http_gzip_static_module --with-http_v2_module --add-module=/root/software/ngx_cache_purge-2.3 --add-module=/root/software/nginx-upstream-fair --add-module=/root/software/nginx-module-vts --add-module=/root/software/naxsi-0.56/naxsi_src/
make && make install
mkdir -p /usr/local/nginx/conf/ssl && mkdir -p /usr/local/nginx/conf/vhosts
chown www:www -R /usr/local/nginx
#配置支持文件类型安卓apk和苹果ipa pxl
sed -i '/application\/zip/a\    application/iphone pxl ipa;' /usr/local/nginx/conf/mime.types
sed -i '/application\/zip/a\    application/vnd.android.package-archive apk;' /usr/local/nginx/conf/mime.types
#隐藏版本
sed -i 's@fastcgi_param  SERVER_SOFTWARE    nginx/$nginx_version@fastcgi_param  SERVER_SOFTWARE    nginx@g' /usr/local/nginx/conf/fastcgi.conf
#修改配置文件
cat <<'EOF' > /usr/local/nginx/conf/nginx.conf
user  www www;
worker_processes  auto;
  
#error_log  logs/error.log;
#error_log  logs/error.log  notice;
error_log   /usr/local/nginx/logs/error.log  warn;
  
pid         /usr/local/nginx/nginx.pid;
  
worker_rlimit_nofile 65535;
events {
#高性能配置
   use epoll;
   worker_connections  65535;
}

#tcp端口转发
#stream {
#    upstream backend {
#
#       # hash $remote_addr consistent;
#
#        #server 127.0.0.1:8333;
#
#        server 10.2.1.12:22;
#
#    }
#
#    server {
#
#        listen 8333;
#
#       # proxy_connect_timeout 1s;
#
#       # proxy_timeout 3s;
#
#        proxy_pass backend;
#
#    }
#}
  
http {
    include       naxsi_core.rules;
    include       mime.types;
    default_type  application/octet-stream;
    charset utf-8;
          
    ######
    ##设置允许日志类型
    ######
    log_format access '$remote_addr $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer" '
                      '"$http_user_agent" $host $request_time "$http_x_forwarded_for"'
                      '$upstream_addr $upstream_response_time';
  
    #######
    ## http 设置
    #######
    vhost_traffic_status_zone;
    vhost_traffic_status_filter_by_host on; 
    sendfile       on;
    tcp_nopush     on;
    tcp_nodelay    on;
    server_tokens off;
    keepalive_timeout  65;
    fastcgi_connect_timeout 300;
    fastcgi_send_timeout 300;
    fastcgi_read_timeout 300;
    fastcgi_buffer_size 128k;
    fastcgi_buffers 8 128k;
    fastcgi_busy_buffers_size 256k;
    fastcgi_temp_file_write_size 256k;
    fastcgi_intercept_errors on;
    server_names_hash_bucket_size 100;
    add_header Access-Control-Allow-Origin *;
    add_header Access-Control-Allow-Headers X-Requested-With;
    add_header Access-Control-Allow-Methods GET,POST,OPTIONS;


    #限制ip
    limit_conn_zone $binary_remote_addr zone=one:10m; #限制ip并发
    limit_req_zone  $binary_remote_addr zone=two:10m rate=30r/s; #限制同一IP请求频率
  
    ##缓存##
    proxy_temp_path /home/temp_dir;
    proxy_cache_path /home/cache levels=1:2 keys_zone=cache_one:200m inactive=1d max_size=30g;
    ##end##

    ##压缩##
    gzip on;
    gzip_disable "msie6";
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 3;
    gzip_min_length 1k;
    gzip_buffers 4 16k;
    gzip_http_version 1.1;
    gzip_types text/plain text/css application/json application/x-javascript text/xml application/xml application/xml+rss text/javascript;
    gzip_disable "MSIE [1-6]\.";
	
    server {
        listen 80;
        server_name localhost;
        root /usr/local/nginx/html;
        index index.html;
        access_log off;
		
    location /status {
        vhost_traffic_status_display;
        vhost_traffic_status_display_format html; 
        access_log   off;
        allow 127.0.0.1;
        #allow  ip;
        deny all;
        }
#php
#    location ~ .*\.php?$ {
#        root /usr/local/nginx/html/;
#        try_files $uri =404;
#        fastcgi_pass  127.0.0.1:9000;
#        fastcgi_index index.php;
#        include fastcgi.conf;
#        }

    }
	
    ## includes vhosts
    include /usr/local/nginx/conf/vhosts/*.conf;
    include /usr/local/nginx/conf/vhosts/*/*.conf;
}
EOF

#waf启用
cp /root/software/naxsi-0.56/naxsi_config/naxsi_core.rules  /usr/local/nginx/conf/
touch /usr/local/nginx/conf/naxsi.rules
cat <<'EOF' > /usr/local/nginx/conf/naxsi.rules
# 启用Naxsi模块
SecRulesEnabled;

# 拒绝访问时展示的页面
DeniedUrl "/RequestDenied";

# 检查规则
CheckRule "$SQL >= 8" BLOCK;
CheckRule "$RFI >= 8" BLOCK;
CheckRule "$TRAVERSAL >= 4" BLOCK;
CheckRule "$EVADE >= 4" BLOCK;
CheckRule "$XSS >= 8" BLOCK;
EOF
#写一个一键添加nginx虚拟主机脚本
if [ ! -f /root/sh/nginxweb.sh ];then
mkdir -p /root/sh/ && touch /root/sh/nginxweb.sh && chmod +x /root/sh/nginxweb.sh
cat <<'EOF' > /root/sh/nginxweb.sh
#!/usr/bin/env bash
#################################
#一键添加nginx虚拟主机脚本
#################################
if [ $UID -ne 0 ];then
echo “你应该用root用户执行该脚本
exit 1
fi

dx=$1
echo $dx | grep -E "[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.?" >/dev/null

if [ $? == 0 ];then
touch /usr/local/nginx/conf/vhosts/${dx}.conf
cat <<'EOF1' > /usr/local/nginx/conf/vhosts/${dx}.conf
#代理后端
#upstream  xx.cn {
#        server xx:80;
#        server xx:80;
#        server xx:80;
#        fair;
#      }
server {
    listen 80;

#https配置
#   listen 443 ssl http2;
#   ssl on;
#   ssl_certificate   /usr/local/nginx/conf/ssl/abab.pem;
#   ssl_certificate_key  /usr/local/nginx/conf/ssl/abab.key;
#   ssl_prefer_server_ciphers on;
#   ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
#   ssl_ciphers "EECDH+ECDSA+AESGCM EECDH+aRSA+AESGCM EECDH+ECDSA+SHA384 EECDH+ECDSA+SHA256 EECDH+aRSA+SHA384 EECDH+aRSA+SHA256 EECDH+aRSA+RC4 EECDH EDH+aRSA !aNULL !eNULL !LOW !3DES !MD5 !EXP !PSK !SRP !DSS !RC4";
#   ssl_session_timeout 10m;
#
#   http2_push_preload on;
#
#   ssi off;
#   ssi_silent_errors off;
#   ssi_types text/shtml;
#
#http跳https
#   if ($scheme != "http") {
#   return 301 https://$host$request_uri;
#   }
#
#HSTS保护
#   add_header Strict-Transport-Security "max-age=31536000;includeSubdomains;preload";
#
#跳转
#   if ($host != abab) {
#       rewrite ^/(.*)$ http://abab/$1 permanent;
#   }
#禁止请求方法
    set $block_user_agent 0;
    if ($http_user_agent ~ "Wget|ApacheBench|WebBench|TurnitinBot|libwww-perl"){
        set $block_user_agent 1;
    }
    if ($block_user_agent = 1) {
        return 403 ;
    }	
    if ($request_method !~ ^(GET|POST|HEAD)$ ) {
    return 444;
    }
#防爬虫优化
#禁止Scrapy等工具的抓取  
#   if ($http_user_agent ~* (Scrapy|Curl|HttpClient)) {  
#       return 403;  
#   }
#禁止指定UA及UA为空的访问  
#   if ($http_user_agent ~ "WinHttp|WebZIP|FetchURL|node-superagent|java/|FeedDemon|Jullo|JikeSpider|Indy Library|Alexa Toolbar|AskTbFXTV|AhrefsBot|CrawlDaddy|Java|Feedly|Apache-HttpAsyncClient|UniversalFeedParser|ApacheBench|Microsoft URL Control|Swiftbot|ZmEu|oBot|jaunty|Python-urllib|lightDeckReports Bot|YYSpider|DigExt|HttpClient|MJ12bot|heritrix|EasouSpider|Ezooms|BOT/0.1|YandexBot|FlightDeckReports|Linguee Bot|^$") {  
#       return 403;               
#   }
#   if ($http_user_agent ~* "qihoobot|Baiduspider|Googlebot|Googlebot-Mobile|Googlebot-Image|Mediapartners-Google|Adsbot-Google|Yahoo! Slurp China|YoudaoBot|Sosospider|Sogou spider|Sogou web spider|MSNBot") {
#       return 403;
#   }

    gzip on;
    server_name abab;
    root  /data/web/abab/;
    #access_log /usr/local/logs/abab.access.log;
    access_log  off;
    error_log   /usr/local/nginx/logs/abab.error.log;
    include fastcgi.conf;

    location / {
#       limit_conn one 30; #限制并发为30
#       limit_rate 300k;   #对每个连接限速300k
#       limit_req  zone=two burst=5 nodelay; #限制请求频率      
#       include    naxsi.rules;  #waf启用规则的配置文件
#       proxy_pass http://xx.cn;
        index index.html index.htm index.php;
#       if ( !-e $request_filename ) {
#           rewrite ^/(.*)$ /index.php?s=$1 last;
#           break;
#       }
        error_page 404 = /404.html;
    }

#php
#   location ~ .*\.php?$ {
#       root /data/web/abab/;
#       try_files $uri =404;
#       fastcgi_pass  127.0.0.1:9000;
#       fastcgi_index index.php;
#       include fastcgi.conf;
#   }

#proxy配置
#   location ~ / {
#       limit_conn one 30; #限制并发为30
#       limit_rate 300k;   #对每个连接限速300k
#       limit_req  zone=two burst=5 nodelay; #限制请求频率
#       proxy_pass                  http://xx.cn;
#       proxy_redirect              off;           #地址重写
#       proxy_set_header            Host            $host;         #当后端web服务器上也配置多个虚拟主机时，需要用该header来区分反向代理哪个主机名。
#       proxy_set_header            X-Real-IP       $remote_addr;  #通过$remote_addr变量获取前端客户真实IP地址。
#       proxy_set_header            X-Forwarded-For $proxy_add_x_forwarded_for;               #通过$remote_addr变量获取前端客户真实IP地址。
#       proxy_set_header            Accept-Encoding '';            #修改请求头。
#       proxy_ignore_headers        Set-Cookie;    #忽略请求头为Set-Cookie的
#       client_max_body_size        10M;           #允许客户端请求的最大的单个文件字节数，这个参数可以限制body的大小，默认是1m。如果上传的文件较大，那么需要调大这个参数。
#       client_body_buffer_size     256k;          #接收客户请求报文body的缓冲区大小；默认为16k；超出此指定大小时，其将被移存于磁盘上；
#       proxy_connect_timeout       600;           #表示与后端服务器连接的超时时间
#       proxy_send_timeout          300;           #表示后端服务器的数据回传时间
#       proxy_read_timeout          300;           #设置nginx从代理的后端服务器获取信息的时间
#       proxy_cache                 cache_one;     #启用缓存
#       proxy_cache_valid 200       7200s;         #缓存200页面7200s
#       proxy_cache_valid 302 301   3600s;         #缓存302 301页面3600s
#       proxy_cache_valid any       60s;           #缓存其他页面60s
#       proxy_buffer_size           4k;            #设置后端服务器的响应头大小，是响应头的缓冲区。
#       proxy_buffers               4 32k;         #设置缓冲区的数量和大小，nginx从代理的后端服务器获取的响应信息会放置到缓冲区。
#       proxy_busy_buffers_size     64k;           #此设置表示nginx会在没有完全读完后端响应的时候就开始向客户端传送数据，所以它会划出一部分缓冲区来专门向客户端传送数据。建议为proxy_buffers中单个缓冲区大小的2倍)
#       proxy_temp_file_write_size  64k;           #一次访问能写入的临时文件的大小，默认是proxy_buffer_size和proxy_buffers中设置的缓冲区大小的2倍
#       proxy_max_temp_file_size    128m;          #指定当响应内容大于proxy_buffers指定的缓冲区时, 写入硬盘的临时文件的大小。
#   }

#waf拦截后显示页面
    location /RequestDenied {
        return 403;
    }
	
#图片缓存
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|bmp|swf|eot|svg|ttf|woff|woff2|xml)$ {
        expires        7d;
        access_log     off;
    }
	
#禁止.sh运行	
    location ~ (.*\.sh?$|/\.) {
        return 403;
    }

}

EOF1
else
echo "你应该输入示例:/root/sh/nginxweb.sh 1.com或者/root/sh/nginxweb.sh abc.com"
exit 0

fi
mkdir -p /data/web/${dx}
sed -i "s/abab/${dx}/g" /usr/local/nginx/conf/vhosts/${dx}.conf
EOF
fi

#根据Centos6或者7版本设置开机自启
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
find /usr/lib/systemd/system -name nginx.service
[ $? != 0 ] && touch /usr/lib/systemd/system/nginx.service && chmod 754 /usr/lib/systemd/system/nginx.service
cat <<EOF >/usr/lib/systemd/system/nginx.service
[Unit]
Description=nginx - high performance web server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
PIDFile=/usr/local/nginx/nginx.pid
ExecStart=/usr/local/nginx/sbin/nginx -c /usr/local/nginx/conf/nginx.conf
ExecReload=/usr/local/nginx/sbin/nginx -s reload
ExecStop=/usr/local/nginx/sbin/nginx -s stop

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl stop firewalld
systemctl disable firewalld
yum -y install iptables-devel iptables-services
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
service iptables save
systemctl restart iptables
systemctl start nginx
systemctl enable nginx
ln -s /usr/local/nginx/sbin/nginx  /usr/bin/
succ_echo "你可以通过systemctl restart|stop|start nginx 来使用nginx"
succ_echo "也可以用nginx命令来使用nginx"

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
/usr/local/nginx/sbin/nginx
grep "/usr/local/nginx/" /etc/rc.d/rc.local >/dev/null
[ $? != 0 ] && echo "/usr/local/nginx/sbin/nginx" >> /etc/rc.d/rc.local
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
service iptables save
service iptables restart
ln -sf /usr/local/nginx/sbin/nginx /usr/bin/nginx
succ_echo "你可以通过nginx和nginx -s stop|-s reload来使用nginx"
fi

#nginx日志切割脚本,清除两周前的日志
if [ ! -f /root/sh/nginx_cut_log.sh ];then
touch /root/sh/nginx_cut_log.sh && chmod +x /root/sh/nginx_cut_log.sh
cat <<'EOF' >/root/sh/nginx_cut_log.sh
#!/bin/bash
test -d  /usr/local/nginx/oldlogs || mkdir -p /usr/local/nginx/oldlogs
log_dir="/usr/local/nginx/logs"
olglog_dir="/usr/local/nginx/oldlogs"
time=`date +%Y%m%d --date="-1 day"`
time1=`date +%Y%m%d --date="-14 day"`

for i in `ls $log_dir`
do
mv "$log_dir"/"$i" "$oldlog_dir"/"$i"."$time"
done
find $oldlog_dir -name "*""$time1""*" -exec -rm -f {} \;
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl restart nginx
elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
nginx -s reload
fi
EOF
echo "00 00 * * * /bin/bash /root/sh/nginx_cut_log.sh" >> /etc/crontab
fi
succ_echo "nginx安装成功"
succ_echo "你可以通过/root/sh/nginxweb.sh脚本来添加虚拟主机"

}

Inst_Mysql-5.7.27(){
Mem=`free -m |grep "Mem" | awk '{print $4}'` 
yum -y install gcc gcc-c++ ncurses ncurses-devel bison make git autoconf automake

if [ ! -f /root/software/mysql-5.7.27-linux-glibc2.12-x86_64.tar.gz ];then
mkdir -p /root/software && cd /root/software && wget https://dev.mysql.com/get/Downloads/MySQL-5.7/mysql-5.7.27-linux-glibc2.12-x86_64.tar.gz
fi

id -u mysql >/dev/null 2>&1
[ $? -ne 0 ] && groupadd mysql && useradd  -g mysql -M -s /sbin/nologin mysql

if [ ! -d /usr/local/mysql ];then
cd /root/software && tar -xvf mysql-5.7.27-linux-glibc2.12-x86_64.tar.gz && mv mysql-5.7.27-linux-glibc2.12-x86_64 /usr/local/mysql && chown -R mysql.mysql /usr/local/mysql && mkdir /usr/local/mysql/logs
fi

if [ ! -f /root/software/jemalloc ];then
cd /root/software && git clone https://github.com/jemalloc/jemalloc && cd jemalloc && ./autogen.sh && ./configure && make && make install
echo '/usr/local/lib' > /etc/ld.so.conf.d/local.conf
ldconfig
fi

# 配置my.cnf
cat > /etc/my.cnf << EOF
[client]
port = 3306
socket = /tmp/mysql.sock
default-character-set = utf8mb4

[mysql]
no-auto-rehash

[mysqld]
skip-grant-tables
port = 3306
socket = /tmp/mysql.sock
basedir = /usr/local/mysql
datadir = /usr/local/mysql/data
pid-file = /usr/local/mysql/mysql.pid
user = mysql
bind-address = 0.0.0.0
character-set-server = utf8mb4

skip-name-resolve
#skip-networking
back_log = 300

max_connections = 1000
max_connect_errors = 4000
open_files_limit = 65535
table_open_cache = 128
max_allowed_packet = 500M
binlog_cache_size = 1M
max_heap_table_size = 8M
tmp_table_size = 16M

read_buffer_size = 2M
read_rnd_buffer_size = 8M
sort_buffer_size = 8M
join_buffer_size = 8M
key_buffer_size = 4M

thread_cache_size = 8

query_cache_type = 1
query_cache_size = 8M
query_cache_limit = 2M

ft_min_word_len = 4

#二进制日志
log_bin = mysql-bin
binlog_format = mixed
expire_logs_days = 7

#主从同步
server-id = 1
#binlog-ignore-db=information_schema
#binlog-ignore-db=performation_schema
#binlog-ignore-db=sys
#relay-log = slave-relay-bin
#relay-log-index = slave-relay-bin.index


#开启慢日志
slow-query-log = on        #开启慢查询
slow_query_log_file = /usr/local/mysql/logs/mysql_slow_query.log        #定义慢查询日志的路径 
log_output = FILE      #设置日志输出到文件，默认为输出到table
long_query_time = 5        #定义查过多少秒的查询算是慢查询
log_queries_not_using_indexes = ON    #记录下没有使用索引的query

#lower_case_table_names = 1

skip-external-locking

innodb_file_per_table = 1
innodb_open_files = 500
innodb_buffer_pool_size = 64M
innodb_write_io_threads = 4
innodb_read_io_threads = 4
innodb_thread_concurrency = 0
innodb_purge_threads = 1
innodb_flush_log_at_trx_commit = 2
innodb_log_buffer_size = 2M
innodb_log_file_size = 32M
innodb_log_files_in_group = 3
innodb_max_dirty_pages_pct = 90
innodb_lock_wait_timeout = 120

interactive_timeout = 28800
wait_timeout = 28800

#使用jemalloc
#[mysqld_safe]
#malloc-lib=/usr/local/lib/libjemalloc.so

EOF

sed -i "s@max_connections.*@max_connections = $((${Mem}/2))@" /etc/my.cnf

if [ ${Mem} -gt 256  -a ${Mem} -le 1024 ]; then
  sed -i 's@^thread_cache_size.*@thread_cache_size = 32@' /etc/my.cnf
  sed -i 's@^query_cache_size.*@query_cache_size = 32M@' /etc/my.cnf
  sed -i 's@^key_buffer_size.*@key_buffer_size = 32M@' /etc/my.cnf
  sed -i 's@^innodb_buffer_pool_size.*@innodb_buffer_pool_size = 256M@' /etc/my.cnf
  sed -i 's@^tmp_table_size.*@tmp_table_size = 64M@' /etc/my.cnf
  sed -i 's@^table_open_cache.*@table_open_cache = 512@' /etc/my.cnf
elif [ ${Mem} -gt 1024 -a ${Mem} -le 2048 ]; then
  sed -i 's@^thread_cache_size.*@thread_cache_size = 64@' /etc/my.cnf
  sed -i 's@^query_cache_size.*@query_cache_size = 64M@' /etc/my.cnf
  sed -i 's@^key_buffer_size.*@key_buffer_size = 128M@' /etc/my.cnf
  sed -i 's@^innodb_buffer_pool_size.*@innodb_buffer_pool_size = 1024M@' /etc/my.cnf
  sed -i 's@^tmp_table_size.*@tmp_table_size = 128M@' /etc/my.cnf
  sed -i 's@^table_open_cache.*@table_open_cache = 1024@' /etc/my.cnf
elif [ ${Mem} -gt 2048 ]; then
  sed -i 's@^thread_cache_size.*@thread_cache_size = 128@' /etc/my.cnf
  sed -i 's@^query_cache_size.*@query_cache_size = 128M@' /etc/my.cnf
  sed -i 's@^key_buffer_size.*@key_buffer_size = 512M@' /etc/my.cnf
  sed -i 's@^innodb_buffer_pool_size.*@innodb_buffer_pool_size = 2048M@' /etc/my.cnf
  sed -i 's@^tmp_table_size.*@tmp_table_size = 256M@' /etc/my.cnf
  sed -i 's@^table_open_cache.*@table_open_cache = 2048@' /etc/my.cnf
fi

if [ ! -f /etc/rc.d/init.d/mysqld ];then
chmod 754 /etc/my.cnf
touch /usr/local/mysql/logs/mysql_slow_query.log
chmod 764 /usr/local/mysql/logs/mysql_slow_query.log
/usr/local/mysql/bin/mysqld --initialize --user=mysql --basedir=/usr/local/mysql --datadir=/usr/local/mysql/data/
cp /usr/local/mysql/support-files/mysql.server /etc/rc.d/init.d/mysqld
chmod +x /etc/rc.d/init.d/mysqld
chkconfig --add mysqld
chown -R mysql.mysql /usr/local/mysql
ln -s /usr/local/mysql/bin/mysql /usr/bin
fi

#密码设置
mysql_root_pwd=`date +%s | sha256sum | base64 | head -c 8`
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl stop firewalld
systemctl disable firewalld
yum -y install iptables-devel iptables-services
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
service iptables save
systemctl restart iptables
systemctl start mysqld
chmod -R 755 /usr/local/mysql
chkconfig mysqld on
mysql -e "update mysql.user set authentication_string=password('$mysql_root_pwd') where user='root' and Host = 'localhost';"
sed -i "s@skip-grant-tables@@g" /etc/my.cnf
systemctl restart mysqld
echo "$mysql_root_pwd" > /etc/sqlps
mysql --connect-expired-password -uroot -p`cat /etc/sqlps` -e "alter user root@localhost identified by '$mysql_root_pwd';"
systemctl restart mysqld
ln -s /usr/local/mysql/lib/libmysqlclient.so.20 /usr/local/lib/libmysqlclient.so.20
ldconfig -v
elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
iptables -A INPUT -p tcp --dport 3306 -j ACCEPT
service iptables save
service iptables restart
service mysqld start
chmod -R 755 /usr/local/mysql
chkconfig mysqld on
mysql -e "update mysql.user set authentication_string=password('$mysql_root_pwd') where user='root' and Host = 'localhost';"
sed -i "s@skip-grant-tables@@g" /etc/my.cnf
service mysqld restart
echo "$mysql_root_pwd" > /etc/sqlps
mysql --connect-expired-password -uroot -p`cat /etc/sqlps` -e "alter user root@localhost identified by '$mysql_root_pwd';"
service mysqld restart

fi

if [ ! -f /etc/sqlps ];then
echo "$mysql_root_pwd" > /etc/sqlps
fi

succ_echo "mysql安装成功"
succ_echo "慢日志已开启"
succ_echo "二进制日志已开启"
succ_echo "登录:mysql -uroot -p`cat /etc/sqlps` ,密码在/etc/sqlps"

}

Inst_php-7.3.8(){
if [ ! -f /root/software/php7.tar.gz ];then
mkdir -p /root/software && cd /root/software && wget -O php7.tar.gz http://hk1.php.net/get/php-7.3.8.tar.bz2/from/this/mirror
fi

if [ ! -f /root/software/libzip-1.2.0.tar.gz ];then
yum -y remove libzip && cd /root/software && wget https://nih.at/libzip/libzip-1.2.0.tar.gz && tar -xf libzip-1.2.0.tar.gz && cd libzip-1.2.0  && ./configure && make && make install
cp /usr/local/lib/libzip/include/zipconf.h /usr/local/include/zipconf.h
fi

yum -y install libxml2 libxml2-devel openssl openssl-devel bzip2 bzip2-devel \
libcurl libcurl-devel libjpeg libjpeg-devel libpng php-pecl-zip \
libpng-devel freetype freetype-devel gmp gmp-devel \
libmcrypt libmcrypt-devel readline readline-devel libxslt libxslt-devel

[ -z "`grep www /etc/group`" ] && groupadd www && useradd -M -s /sbin/nologin -g www www
if [ ! -d /usr/local/php ];then
cd /root/software && tar -xf php7.tar.gz && cd php-7.3.8 && ./configure --prefix=/usr/local/php --with-config-file-path=/usr/local/php/etc --enable-fpm --with-fpm-user=www  --with-fpm-group=www --enable-inline-optimization --with-libdir=lib64 --with-ldap  --disable-debug  --disable-rpath  --enable-shared  --enable-soap  --with-libxml-dir --with-xmlrpc  --with-openssl  --with-pcre-regex  --with-sqlite3  --with-zlib  --enable-bcmath  --with-iconv  --with-bz2  --enable-calendar  --with-curl  --with-cdb  --enable-dom  --enable-exif  --enable-fileinfo  --enable-filter  --with-pcre-dir --enable-ftp --with-gd  --with-openssl-dir --with-jpeg-dir --with-png-dir --with-zlib-dir --with-freetype-dir --enable-gd-jis-conv --with-gettext --with-gmp --with-mhash --enable-json --enable-mbstring --enable-mbregex --enable-mbregex-backtrack --with-onig --enable-pdo --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd --with-pdo-sqlite --with-readline --enable-session --enable-shmop --enable-simplexml --enable-sockets --enable-sysvmsg --enable-sysvsem --enable-sysvshm --enable-wddx --with-xsl --enable-zip --enable-mysqlnd-compression-support --with-pear --enable-opcache && make -j `grep processor /proc/cpuinfo | wc -l` && make install
mkdir -p /usr/local/php/logs
cp /usr/local/php/etc/php-fpm.conf.default /usr/local/php/etc/php-fpm.conf
sed -i "s@;pid = run/php-fpm.pid@pid = /usr/local/php/var/run/php-fpm.pid@" /usr/local/php/etc/php-fpm.conf
sed -i "s@;error_log = log/php-fpm.log@error_log = /usr/local/php/logs/php-fpm.log@" /usr/local/php/etc/php-fpm.conf

#基础优化www.conf
cp /usr/local/php/etc/php-fpm.d/www.conf.default /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@;listen.owner = www@listen.owner = www@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@;listen.group = www@listen.group = www@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@;catch_workers_output = yes@catch_workers_output = yes@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@;slowlog = log/\$pool.log.slow@slowlog = /usr/local/php/logs/\$pool.log.slow@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@;request_slowlog_timeout = 0@request_slowlog_timeout = 10s@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@pm.max_children = 5@pm.max_children = 20@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@pm.start_servers = 2@pm.start_servers = 10@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@pm.min_spare_servers = 1@pm.min_spare_servers = 10@"  /usr/local/php/etc/php-fpm.d/www.conf
sed -i "s@pm.max_spare_servers = 3@pm.max_spare_servers = 20@"  /usr/local/php/etc/php-fpm.d/www.conf

#配置php.ini文件
cp /root/software/php-7.3.8/php.ini-development  /usr/local/php/etc/php.ini
sed -i "s@expose_php = On@expose_php = Off@" /usr/local/php/etc/php.ini
sed -i "s@;extension_dir = "./"@extension_dir = "/usr/local/php/ext"@" /usr/local/php/etc/php.ini
sed -i "s@short_open_tag = Off@short_open_tag = On@" /usr/local/php/etc/php.ini
sed -i "s@max_execution_time = 30@max_execution_time = 300@" /usr/local/php/etc/php.ini
sed -i "s@;date.timezone =@date.timezone = Asia/Shanghai@" /usr/local/php/etc/php.ini
sed -i "s@display_errors = On@display_errors = Off@" /usr/local/php/etc/php.ini
sed -i "s@;opcache.enable=1@opcache.enable=1@" /usr/local/php/etc/php.ini
sed -i "s@max_input_time = 60@max_input_time = 300@" /usr/local/php/etc/php.ini
sed -i "s@post_max_size = 8M@post_max_size = 16M@" /usr/local/php/etc/php.ini

#设置开机自启
cp /root/software/php-7.3.8/sapi/fpm/init.d.php-fpm /etc/init.d/php-fpm && chmod +x /etc/init.d/php-fpm && chkconfig --add php-fpm && chkconfig php-fpm on
service php-fpm start

fi

succ_echo "php-fpm安装完成"
succ_echo "你可以使用service php-fpm start|restart|stop|reload|status|force-quit使用php-fpm"

}

Inst_jdk8(){
if [ ! -f /root/software/jdk1.8.0_212 ];then
yum -y remove java-* && mkdir -p /root/software && cd /root/software && wget https://github.com/frekele/oracle-java/releases/download/8u212-b10/jdk-8u212-linux-x64.tar.gz && tar -xf jdk-8u212-linux-x64.tar.gz && cd jdk1.8.0_212 && unzip javafx-src.zip && unzip src.zip
fi

grep "JAVA_HOME" /etc/profile
[ $? -ne 0 ] && echo "export JAVA_HOME=/root/software/jdk1.8.0_212" >> /etc/profile && echo 'export PATH=$JAVA_HOME/bin:$PATH' >> /etc/profile && source /etc/profile

}

Inst_zabbix-server-4.4.0(){
echo '自定义DBHost:'
read 'DBHost'

if [ ! -f /root/software/zabbix-4.4.0.tar.gz ];then
yum -y install net-snmp-devel java-1.8.0-openjdk-devel
cd /root/software && wget -O zabbix-4.4.0.tar.gz  http://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/4.4.0/zabbix-4.4.0.tar.gz/download && tar -xf zabbix-4.4.0.tar.gz && cd zabbix-4.4.0 && ./configure --prefix=/usr/local/zabbix --enable-server --enable-agent --with-mysql=/usr/local/mysql/bin/mysql_config --with-net-snmp --with-libcurl --with-libxml2 --enable-java --enable-ipv6 && make && make install
mkdir -p /usr/local/zabbix/log
id -u zabbix >/dev/null 2>&1
[ $? -ne 0 ] && groupadd zabbix && useradd -M -s /sbin/nologin -g zabbix zabbix
chown -R zabbix.zabbix /usr/local/zabbix
ln -s /usr/local/zabbix/sbin/zabbix_server  /usr/bin/zabbix_server
sed -i "s@# PidFile=/tmp/zabbix_server.pid@PidFile=/usr/local/zabbix/zabbix_server.pid@g" /usr/local/zabbix/etc/zabbix_server.conf
sed -i "s@LogFile=/tmp/zabbix_server.log@LogFile=/usr/local/zabbix/log/zabbix_server.log@g" /usr/local/zabbix/etc/zabbix_server.conf
sed -i "s@# DBHost=localhost@DBHost=$DBHost @g" /usr/local/zabbix/etc/zabbix_server.conf
sed -i "s@# DBPassword=@DBPassword=zabbix@g" /usr/local/zabbix/etc/zabbix_server.conf
mysql --connect-expired-password -uroot -p`cat /etc/sqlps` -e "create database zabbix character set utf8 collate utf8_bin;"
mysql --connect-expired-password -uroot -p`cat /etc/sqlps` -e "grant all privileges on zabbix.* to zabbix@'%' identified by 'zabbix';"
mysql -uzabbix -h$DBHost -pzabbix zabbix < /root/software/zabbix-4.4.0/database/mysql/schema.sql
mysql -uzabbix -h$DBHost -pzabbix zabbix < /root/software/zabbix-4.4.0/database/mysql/images.sql
mysql -uzabbix -h$DBHost -pzabbix zabbix < /root/software/zabbix-4.4.0/database/mysql/data.sql
iptables -A INPUT -p tcp --dport 10051 -j ACCEPT
service iptables save
touch /etc/init.d/zabbix_server
cat <<'EOF' >/etc/init.d/zabbix_server
#!/bin/sh
#chkconfig: 345 95 95
#description: Zabbix_Server

SERVICE="Zabbix server"
DAEMON=/usr/local/zabbix/sbin/zabbix_server
PIDFILE=/tmp/zabbix_server.pid

case $1 in
  'start')
    if [ -x ${DAEMON} ]
    then
      $DAEMON
      # Error checking here would be good...
      echo "${SERVICE} started."
    else
      echo "Can't find file ${DAEMON}."
      echo "${SERVICE} NOT started."
    fi
  ;;
  'stop')
    if [ -s ${PIDFILE} ]
    then
      if kill `cat ${PIDFILE}` >/dev/null 2>&1
      then
        echo "${SERVICE} terminated."
        rm -f ${PIDFILE}
      fi
    fi
  ;;
  'restart')
    $0 stop
    sleep 10
    $0 start
  ;;
  *)
    echo "Usage: $0 start|stop|restart"
    ;;
esac
EOF
chmod +x /etc/init.d/zabbix_server
chkconfig --add zabbix_server
chkconfig zabbix_server on
fi

if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl restart iptables
elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
service iptables restart
fi

succ_echo "你可以使用service zabbix_server start|stop|restart"
}

Inst_zabbix-agentd-4.4.0(){
IP=`curl ip.6655.com/ip.aspx`
echo "自定义zabbix-server:"
read 'Server'
if [ ! -f /root/software/zabbix-agentd-4.4.0.tar.gz ];then
yum -y install net-snmp-devel java-1.8.0-openjdk-devel
cd /root/software && wget -O zabbix-agentd-4.4.0.tar.gz  http://sourceforge.net/projects/zabbix/files/ZABBIX%20Latest%20Stable/4.4.0/zabbix-4.4.0.tar.gz/download && tar -xf zabbix-agentd-4.4.0.tar.gz && mv zabbix-4.4.0 zabbix-agentd-4.4.0 && cd zabbix-agentd-4.4.0 && ./configure --prefix=/usr/local/zabbix-agentd --enable-agent && make && make install
mkdir -p /usr/local/zabbix-agentd/log
id -u zabbix >/dev/null 2>&1
[ $? -ne 0 ] && groupadd zabbix && useradd -M -s /sbin/nologin -g zabbix zabbix
chown -R zabbix.zabbix /usr/local/zabbix-agentd
ln -sf /usr/local/zabbix-agentd/sbin/zabbix_agentd  /usr/bin/zabbix_agentd
sed -i "s@LogFile=/tmp/zabbix_agentd.log@LogFile=/usr/local/zabbix-agentd/log/zabbix_agentd.log@g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@Server=127.0.0.1@Server=$Server @g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@ServerActive=127.0.0.1@ServerActive=$Server @g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@# UnsafeUserParameters=0@UnsafeUserParameters=1@g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@# EnableRemoteCommands=0@EnableRemoteCommands=1@g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@Hostname=Zabbix server@Hostname=$IP @g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
sed -i "s@# Include=/usr/local/etc/zabbix_agentd.conf.d/ @Include=/usr/local/zabbix-agentd/etc/zabbix_agentd.conf.d/*@g" /usr/local/zabbix-agentd/etc/zabbix_agentd.conf
iptables -A INPUT -p tcp --dport 10050 -j ACCEPT
service iptables save
touch /etc/init.d/zabbix_agentd
cat <<'EOF' > /etc/init.d/zabbix_agentd
#!/bin/sh
#chkconfig: 345 95 95
#description: Zabbix_Agentd

SERVICE="Zabbix Agent"
DAEMON=/usr/local/zabbix-agentd/sbin/zabbix_agentd
PIDFILE=/tmp/zabbix_agentd.pid

case $1 in
  'start')
    if [ -x ${DAEMON} ]
    then
      $DAEMON
      # Error checking here would be good...
      echo "${SERVICE} started."
    else
      echo "Can't find file ${DAEMON}."
      echo "${SERVICE} NOT started."
    fi
  ;;
  'stop')
    if [ -s ${PIDFILE} ]
    then
      if kill `cat ${PIDFILE}` >/dev/null 2>&1
      then
        echo "${SERVICE} terminated."
        rm -f ${PIDFILE}
      fi
    fi
  ;;
  'restart')
    $0 stop
    sleep 10
    $0 start
  ;;
  *)
    echo "Usage: $0 start|stop|restart"
    ;;
esac
EOF
chmod +x /etc/init.d/zabbix_agentd
chkconfig --add zabbix_agentd
chkconfig zabbix_agentd on
fi

if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl restart iptables
elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
service iptables restart
fi

succ_echo "你可以使用service zabbix_agentd start|stop|restart"
}

Inst_redis-5.0.5(){
if [ ! -f /root/software/redis-5.0.5.tar.gz ];then
cd /root/software && wget http://download.redis.io/releases/redis-5.0.5.tar.gz && tar -xf redis-5.0.5.tar.gz && cd redis-5.0.5 && make && cd src && make install PREFIX=/usr/local/redis && mkdir -p /usr/local/redis/etc && cp /root/software/redis-5.0.5/redis.conf /usr/local/redis/etc && groupadd redis && useradd  -g redis -M -s /sbin/nologin redis && chown -R redis.redis /usr/local/redis
sed -i "s@^daemonize no@daemonize yes@" /usr/local/redis/etc/redis.conf
sed -i "s@bind 127.0.0.1@#bind 127.0.0.1@" /usr/local/redis/etc/redis.conf
sed -i "s@protected-mode yes@protected-mode no@" /usr/local/redis/etc/redis.conf
sed -i "s@pidfile /var/run/redis_6379.pid@pidfile /usr/local/redis/redis_6379.pid@" /usr/local/redis/etc/redis.conf
touch /etc/init.d/redis
cat > /etc/init.d/redis << 'EOF'
#!/bin/sh

REDISPORT=6379
EXEC=/usr/local/redis/bin/redis-server
CLIEXEC=/usr/local/redis/bin/redis-cli

PIDFILE=/usr/local/redis/redis_${REDISPORT}.pid
CONF="/usr/local/redis/etc/redis.conf"

case "$1" in
    start)
        if [ -f $PIDFILE ];then
                echo "$PIDFILE exists, process is already running or crashed"
        else
                echo "Starting Redis server..."
                $EXEC $CONF
        fi
        ;;
    stop)
        if [ ! -f $PIDFILE ];then
                echo "$PIDFILE does not exist, process is not running"
        else
                PID=$(cat $PIDFILE)
                echo "Stopping ..."
                $CLIEXEC -p $REDISPORT shutdown
                while [ -x /proc/${PID} ]
                do
                    echo "Waiting for Redis to shutdown ..."
                    sleep 1
                done
                echo "Redis stopped"
        fi
        ;;
    *)
        echo "Please use start or stop as first argument"
        ;;
esac
EOF
chmod +x /etc/init.d/redis
chkconfig --add redis  
chkconfig redis on
service redis start
iptables -A INPUT -p tcp --dport 6379 -j ACCEPT
service iptables save

if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl restart iptables
elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
service iptables restart
fi

if [ -d /usr/local/php ];then
cd /root/software && wget https://github.com/phpredis/phpredis/archive/5.1.0RC2.tar.gz && tar -xf 5.1.0RC2.tar.gz && cd phpredis-5.1.0RC2 && /usr/local/php/bin/phpize && ./configure --with-php-config=/usr/local/php/bin/php-config && make && make install
grep "redis" /usr/local/php/etc/php.ini
[ $? -ne 0 ] && sed -i "/;extension=bz2/i\extension=redis" /usr/local/php/etc/php.ini
service php-fpm restart
fi

fi

succ_echo "你可以通过service redis start|stop使用"
}

Inst_mongo-4.2.1(){
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then

if [ ! -f /root/software/mongodb-linux-s390x-rhel72-4.2.1.tgz ];then
cd /root/software && wget https://fastdl.mongodb.org/linux/mongodb-linux-s390x-rhel72-4.2.1.tgz && tar -xf mongodb-linux-s390x-rhel72-4.2.1.tgz && cp -r /root/software/mongodb-linux-s390x-rhel72-4.2.1  /usr/local/mongo && groupadd mongo && useradd  -g mongo -M -s /sbin/nologin mongo && chown -R /usr/local/mongo
fi

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then

if [ ! -f /root/software/mongodb-linux-x86_64-rhel62-4.2.1.tgz ];then
cd /root/software && wget https://fastdl.mongodb.org/linux/mongodb-linux-x86_64-rhel62-4.2.1.tgz && tar -xf mongodb-linux-x86_64-rhel62-4.2.1.tgz && cp -r /root/software/mongodb-linux-x86_64-rhel62-4.2.1 /usr/local/mongo
fi

fi

grep "mongo" /etc/profile
[ $? -ne 0 ] && echo 'export PATH=/usr/local/mongo/bin:$PATH' >> /etc/profile && source /etc/profile && mkdir -p /data/mongodb && mongod --dpath /data/mongodb

if [ -d /usr/local/php ];then
cd /root/software && wget http://pecl.php.net/get/mongodb-1.6.0.tgz && tar -xf mongodb-1.6.0.tgz && cd mongodb-1.6.0 && /usr/local/php/bin/phpize && ./configure --with-php-config=/usr/local/php/bin/php-config && make && make install
grep "mongodb" /usr/local/php/etc/php.ini
[ $? -ne 0 ] && sed -i "/;extension=bz2/i\extension=mongodb" /usr/local/php/etc/php.ini
service php-fpm restart
fi

}

Inst_docker () {
if [ `awk '{print $4}' /etc/redhat-release|head -1|cut -c 1` = '7' ];then
systemctl stop docker
yum erase docker \
docker-client \
docker-client-latest \
docker-common \
docker-latest \
docker-latest-logrotate \
docker-logrotate \
docker-selinux \
docker-engine-selinux \
docker-engine \
docker-ce
yum -y remove docker
yum install -y yum-utils  device-mapper-persistent-data lvm2
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce -y
systemctl start docker
systemctl enable docker

elif [ `awk '{print $3}' /etc/redhat-release|head -1|cut -c 1` = '6' ];then
service docker stop
yum erase docker \
docker-client \
docker-client-latest \
docker-common \
docker-latest \
docker-latest-logrotate \
docker-logrotate \
docker-selinux \
docker-engine-selinux \
docker-engine \
docker-ce
yum -y remove docker
yum install -y yum-utils  device-mapper-persistent-data lvm2
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
yum install docker-ce -y
service docker start
chkconfig --add docker
chkconfig docker on
fi

}

#=====================================================#
succ_echo "lnmp环境+一些小配置"
succ_echo "1.安装Centos7或者Centos6的优化环境"
succ_echo "2.安装nginx-1.16.1"
succ_echo "3.安装mysql-5.7.27"
succ_echo "4.安装php-7.3.8"
succ_echo "5.安装jdk8环境"
succ_echo "6.安装zabbix-server-4.4.0"
succ_echo "7.安装zabbix-agentd-4.4.0"
succ_echo "8.安装redis-5.0.5"
succ_echo "9.安装mongodb-4.2.1"
succ_echo "10.安装最新版docker"
#=====================================================#

succ_echo "请输入你的选择"
read lalala
case $lalala in

1)
Inst_System
;;
2)
Inst_Nginx-1.16.1
;;
3)
Inst_Mysql-5.7.27
;;
4)
Inst_php-7.3.8
;;
5)
Inst_jdk8
;;
6)
Inst_zabbix-server-4.4.0
;;
7)
Inst_zabbix-agentd-4.4.0
;;
8)
Inst_redis-5.0.5
;;
9)
Inst_mongo-4.2.1
;;
10)
Inst_docker
;;
*)
echo "请输入(1,2....)"
exit 0
;;
esac
