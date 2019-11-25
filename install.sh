#!/bin/bash
Titel="\
############################################
#  Dscription: v2ray+ws+tls onekey script  #
#  Author: raixen@qq.com   Version: 1.0.1  #
############################################"
msg(){ echo -e$2 "\e[1;38m$1\e[0m"; }
Rmsg(){ echo -e$2 "\e[1;31m$1\e[0m"; }
Gmsg(){ echo -e$2 "\e[1;32m$1\e[0m"; }
Cmsg(){ echo -e$2 "\e[0;36m$1\e[0m"; }
Ymsg(){ echo -e$2 "\e[1;33m$1\e[0m"; }
Bmsg(){ echo -en "\e[1;34m$1\e[0m"; }
Info(){ echo -en "\e[1;32m[信息]\e[0m"; }
Error(){ echo -en "\e[1;31m[出错]\e[0m"; }
WorkDir="/tmp/"; cd $WorkDir
judge(){
    if [[ $? == 0 ]];then
        Info; msg "${1}完成"
        sleep 0.5
    else
        Error; msg "${1}失败"
        [[ "$2" == 0 ]] && return 1 || exit 1
    fi
}
option_judge(){
	unset input
	read -n1 -ep " :" input
	case $input in
	[yY])
		return 1;;
	[nN])
		return 2;;
	*)
		Ymsg "[提示]" n; msg "请输入 y 或 n" n; option_judge;;
	esac
}

check_env(){
	[[ `id -u` != 0 ]] && Rmsg "当前用户非root用户，请切换到root用户后执行脚本" && exit 1
	bit=$(uname -m)
	[[ $bit != "x86_64" ]] && Rmsg "此脚本不支持当前系统" && exit 1
	if [[ -e /usr/bin/apt-get || -e /usr/bin/yum ]] && [[ -e /bin/systemctl ]]; then
		[[ -e /usr/bin/apt-get ]] && Ins="apt-get"
		[[ -e /usr/bin/yum ]] && Ins="yum"
	else
		Rmsg "此脚本不支持当前系统"
		echo "仅支持 CentOS 7+ / Debian 8+ / Ubuntu 16+"
		exit 1
	fi
}
domain_check(){
	Info; msg "开始检查域名${domain}的DNS解析情况"
	[[ -z ${domain} ]] && Rmsg "域名不能为空" && exit 1
	ping ${domain} -c 1 &> /dev/null
	domain_ip=`ping ${domain} -c 1 2> /dev/null| sed '1{s/[^(]*(//;s/).*//;q}'`
	msg "      DNS解析到 ${domain} IP：${domain_ip}"
	command -v curl &> /dev/null || $Ins install curl -y
	local_ip=`curl -4 ip.sb 2> /dev/null`
	msg "      本机IP: ${local_ip}"
	if [[ "${local_ip}" == "${domain_ip}" ]] && [[ -n ${domain_ip} ]];then
		Info; msg "DNS解析IP 与 本机IP 匹配"
		sleep 1
	else
		Ymsg "[警告]" n; msg "请确认你的域名解析添加了正确的A记录，否则将无法正常使用v2ray"
		msg "     以及 脚本无法申请到SSL证书"; ip_match="1"
		Bmsg "[提示]" n; msg "DNS解析到的IP 与 本机IP 不匹配 是否继续安装？[Y/n]" n && read -ep " :" install
		[[ -z $install ]] && install="y"
		case $install in
		[yY])
			Info; msg "开始全自动安装..." ;;
		*)
			Ymsg "[结束]" n; msg "操作已被终止";exit ;;
		esac
	fi
}
input_parameter(){
	Info; msg "在执行此脚本之前，请您先准备一个解析至本机的域名。"
	read -s -n1 -p "按任意键开始( Ctrl+C 中止操作)..."; echo
	if [[ "$Ins" == "yum" ]];then
		Bmsg "[选项]"; msg "是否需要安装bbr内核优化网速?[y/n]" n;option_judge; bbr="$?"
	fi
	Bmsg "[选项]"; msg "请输入解析到本机的域名(www.example.com)" n
	read -ep " :" domain
	Bmsg "[选项]"; msg "是否需要脚本自动申请域名SSL证书?[y/n]" n
	option_judge;domain_ssl="$?"
	if [[ $domain_ssl == "2" ]];then
		Ymsg "请将域名SSL证书文件放置在 /ssl-cert 目录下，\n并更改证书文件名分别为 v2ray.crt 、v2ray.key" && mkdir /ssl-cert &> /dev/null
		msg "      3s后继续..."
		sleep 4
	fi
	domain_check
}
dependency_install(){
	$Ins install -y wget curl unzip rdate cronie lsof
	judge "依赖包安装"
	systemctl start crond &> /dev/null && systemctl enable crond &> /dev/null
}
install_nginx_v2ray(){
	Info; msg "准备安装nginx、v2ray"
	cd $WorkDir
	(systemctl stop v2ray.service &> /dev/null;systemctl stop nginx.service &> /dev/null)&
	wget --no-check-certificate https://raw.githubusercontent.com/raixen/v2ray-script/master/tools/nginx-bin.tgz
	judge "下载nginx"
	tag_url="https://api.github.com/repos/v2ray/v2ray-core/releases/latest"
	new_ver=`curl -s $tag_url --connect-timeout 10| grep '"tag_name":' | cut -d\" -f4`
	[[ -z "$new_ver" ]] && new_ver="v4.21.3"
	v2ray_link="https://github.com/v2ray/v2ray-core/releases/download/${new_ver}/v2ray-linux-64.zip"
	wget --no-check-certificate -P /tmp/v2ray $v2ray_link
	judge "下载v2ray"
	\mv /usr/local/nginx /usr/local/nginx_old
	tar -xzf nginx-bin.tgz && cd nginx-bin_1.17.5 && sh install.sh
	find /usr/local/nginx/* -exec touch -t `date +%Y%m%d%H%M.%S` {} \; &>/dev/null
	systemctl daemon-reload && systemctl enable nginx.service &> /dev/null
	judge "nginx安装"
	cd /tmp/v2ray
	unzip /tmp/v2ray/v2ray-linux-64.zip &>/dev/null
	chmod +x /tmp/v2ray/v2ray && chmod +x /tmp/v2ray/v2ctl
	rm -rf /usr/local/v2ray; mkdir /usr/local/v2ray/bin -p && mkdir /usr/local/v2ray/conf -p
	mv /tmp/v2ray/v2ray /usr/local/v2ray/bin/
	mv /tmp/v2ray/v2ctl /usr/local/v2ray/bin/
	mv /tmp/v2ray/geoip.dat /usr/local/v2ray/bin/
	mv /tmp/v2ray/geosite.dat /usr/local/v2ray/bin/
	mv /tmp/v2ray/vpoint_vmess_freedom.json /usr/local/v2ray/conf/config.json.example
	wget -P /usr/local/v2ray/conf/ https://raw.githubusercontent.com/raixen/v2ray-script/master/tools/config.json
	rm -f /usr/lib/systemd/system/v2ray.service;rm -f /etc/systemd/system/v2ray.service
	sed -i '/^ExecStart/c\ExecStart=/usr/local/v2ray/bin/v2ray -config /usr/local/v2ray/conf/config.json' /tmp/v2ray/systemd/v2ray.service
	\cp /tmp/v2ray/systemd/v2ray.service /usr/lib/systemd/system/
	systemctl daemon-reload && systemctl enable v2ray.service &> /dev/null
	judge "v2ray安装"
	rm -rf /tmp/nginx* ;rm -rf /tmp/v2ray
	cd ~
}
configre(){
	sed -i '/rdate/d' /var/spool/cron/root &> /dev/null
	rdate -s time.nist.gov &> /dev/null && echo "30 3 * * * /bin/rdate -s time.nist.gov" >> /var/spool/cron/root 2> /dev/null
	cat >/usr/local/nginx/conf/vhost.d/default.conf<<-EOF
server {
    listen       443 ssl http2;
    server_name  $domain;

    ssl_certificate      /ssl-cert/v2ray.crt;
    ssl_certificate_key  /ssl-cert/v2ray.key;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_protocols TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_early_data on;
    ssl_prefer_server_ciphers on;
    ssl_ciphers TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-CHACHA20-POLY1305:ECDHE-RSA-AES128-SHA256:ECDHE-RSA-AES128-SHA;
    ssl_ecdh_curve X25519:P-256;

    # default 404 error page
#    error_page   404              /404.html;
#    location = /404.html {
#        root   html;
#    }
    # redirect server error pages to the static page /50x.html
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   html;
    }

    location / {
        root   html;
        index  index.html index.htm;
    }

    location /v2-proxy {
    access_log off;
    proxy_redirect off;
    proxy_pass http://127.0.0.1:10443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header Host \$host;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
	EOF
	judge "配置nginx"
	UUID=`cat /proc/sys/kernel/random/uuid`
	cat >/usr/local/v2ray/conf/vmess_info.txt <<-END
{
    "v": "2",
    "ps": "${domain}",
    "add": "${domain}",
    "port": "443",
    "id": "${UUID}",
    "aid": "64",
    "net": "ws",
    "type": "none",
    "host": "${domain}",
    "path": "/v2-proxy",
    "tls": "tls"
}
	END
	sed -i s/UUID/$UUID/ /usr/local/v2ray/conf/config.json
	judge "配置v2ray"
	if [[ -e /usr/bin/yum ]]; then
		sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config &>/dev/null
		setenforce 0 &>/dev/null
		tuned-adm profile network-latency &>/dev/null
	fi
}
ssl_install(){
	${Ins} install socat nc netcat -y
	judge "安装SSL证书生成脚本依赖包" 0
	curl  https://get.acme.sh | sh
	judge "安装SSL证书生成脚本" 0
}
acme(){
	~/.acme.sh/acme.sh --issue -d ${domain} --standalone -k ec-256 --force
	if [[ $? -eq 0 ]];then
		Info; msg "SSL证书生成成功"
		sleep 1
		mkdir /ssl-cert &> /dev/null
		~/.acme.sh/acme.sh --installcert -d ${domain} --fullchainpath /ssl-cert/v2ray.crt --keypath /ssl-cert/v2ray.key --ecc
		if [[ $? -eq 0 ]];then
		Info; msg "SSL证书配置成功"
		sleep 1
		fi
	else
		Error; msg "SSL证书生成失败，请手动申请SSL证书"
	fi
}
install_bbr(){
	rm -f kernel-4.14.129-bbrplus.rpm
	wget --no-check-certificate https://github.com/cx9208/bbrplus/raw/master/centos7/x86_64/kernel-4.14.129-bbrplus.rpm
	judge "bbr内核下载" 0
	sed -i '/net.core.default_qdisc/d' /etc/sysctl.conf
	sed -i '/net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf
	yum install -y kernel-4.14.129-bbrplus.rpm
	[[ $? == 0 ]] && grub2-set-default 0
	if [[ $? != 0 ]];then
		Error; msg "bbr内核安装失败";exit 1
	fi
	\mv /etc/sysctl.conf /etc/sysctl.old
	echo "net.ipv4.tcp_congestion_control = bbrplus
net.core.default_qdisc = fq
fs.file-max = 1000000
fs.inotify.max_user_instances = 8192
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.ip_local_port_range = 1024 65000
net.ipv4.tcp_max_syn_backlog = 16384
net.ipv4.tcp_max_tw_buckets = 6000
net.ipv4.route.gc_timeout = 100
net.ipv4.tcp_syn_retries = 1
net.ipv4.tcp_synack_retries = 1
net.core.somaxconn = 32768
net.core.netdev_max_backlog = 32768
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_max_orphans = 32768
net.ipv4.ip_forward = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1" > /etc/sysctl.conf
	judge "bbr内核安装" 0;bbr_status="$?"
}
script_output(){
	cat >/usr/sbin/v2mgr <<-'EEF'
#!/bin/bash
#v2ray管理脚本 (by raixen@qq.com)

Echo(){ echo -e$2 "\e[0;38m$1\e[0m"; }
EchoG(){ echo -en "\e[0;32m$1\e[0m"; }
EchoR(){ echo -en "\e[0;31m$1\e[0m"; }
Green="\e[0;32m"; Red="\e[0;31m"; Blue="\e[0;36m"; Font="\e[0m"
v2_conf="/usr/local/v2ray/conf/config.json"
v2_info="/usr/local/v2ray/conf/vmess_info.txt"
ng_conf="/usr/local/nginx/conf/vhost.d/default.conf"

option_judge(){
	unset input
	read -n1 -ep " :" input
	case $input in
	[yY])
		return 1;;
	[nN])
		return 2;;
	*)
		EchoR "[提示]"; Echo "请输入 y 或 n" n; option_judge;;
	esac
}
show_status(){
	systemctl status nginx.service &>/dev/null
	[[ $? == 0 ]] && ngx=0
	systemctl status v2ray.service &>/dev/null
	[[ $? == 0 ]] && v2=0
	if [[ $ngx == 0 ]] && [[ $v2 == 0 ]] ;then
		EchoG "  [服务状态] ";Echo "v2ray、nginx 正在运行"
	else
		EchoR "  [服务状态] "
		[[ $v2 != 0 ]] && Echo "v2ray未运行 " n
		[[ $ngx != 0 ]] && Echo "nginx未运行" n
		echo
	fi
}
restart_service(){
	systemctl enable nginx.service &>/dev/null
	systemctl restart nginx.service &>/dev/null
	if [[ $? == 0 ]]; then
		EchoG "[信息]";Echo "nginx正在运行"
	else
		EchoR "[警告]";Echo "nginx重启失败，请检查配置文件(域名及证书)"
	fi
	systemctl enable v2ray.service &>/dev/null
	systemctl restart v2ray.service &>/dev/null
	if [[ $? == 0 ]]; then
		EchoG "[信息]";Echo "v2ray正在运行"
	else
		EchoR "[警告]";Echo "v2ray重启失败，请检查配置文件"
	fi
}
disable_v2(){
	systemctl disable v2ray.service &>/dev/null && systemctl stop v2ray.service &>/dev/null
	EchoG "[信息]";EchoR "已停用v2ray服务";echo
}

v2_variable(){
	if [[ ! -e $v2_info ]];then
		EchoR "[出错]";Echo "未找到文件:vmess_info.txt"; exit 1
	fi
	UUID=`grep '"id"' $v2_info|awk -F'"' '{print$4}'`
	Domain=`grep '"add"' $v2_info|awk -F'"' '{print$4}'`
	Port=`grep '"port"' $v2_info|awk -F'"' '{print$4}'`
	Net=`grep '"net"' $v2_info|awk -F'"' '{print$4}'`
	Path=`grep '"path"' $v2_info|awk -F'"' '{print$4}'`
}
show_vmess(){
	v2_variable
    vmess_url="vmess://`cat $v2_info | base64 -w 0`"
    vmess_qr="https://redkey.top/qr/?text=${vmess_url}&size=500"
    curl -I "${vmess_qr}" &>/dev/null && QR="0"
	echo -e "\
${Blue} -- v2ray 配置信息如下：${Font}
${Blue} 地址（address）：${Font}$Domain
${Blue} 端口（port）：${Font}$Port
${Blue} 用户ID（UUID）：${Font}$UUID
${Blue} 额外ID（alterID）：${Font}64
${Blue} 加密方式（security）：${Font}auto
${Blue} 传输协议（network）：${Font}$Net
${Blue} 伪装类型（type）：${Font}none
${Blue} 路径（path）：${Font}$Path
${Blue} 传输层安全：${Font}tls
${Blue} tls证书：${Font} 允许不安全 (allowInsecure true)"
	echo -e "${Blue} 配置信息URL链接：${Font}"; EchoG "${vmess_url}"; echo
	[[ $QR == 0 ]] && (echo -e "${Blue} 浏览器生成二维码：${Font}";EchoG "${vmess_qr}";echo)
}
v2ray_config(){
modfiy_port(){
	while [[ -z $new_Port ]]
	do
	read -ep "请输入端口号（建议443）；" iport
	if [[ $iport == 80 ]];then
		new_Port="$iport"
		elif [[ $iport == 443 ]];then
			new_Port="$iport"
		elif ([ $iport -ge 1024 ] && [ $iport -le 65535 ] && [[ $iport != 10443 ]]) &>/dev/null; then
			new_Port="$iport"
	else
		EchoR "端口限定范围：(80、443、1024-65535)";echo
	fi
	done
}
modfiy_net(){
	Echo "推荐使用以下安全传输协议"
	echo -e "${Green}1.${Font} WebSocket(ws) \t ${Green}2.${Font} http2(h2)"
	Echo "请选择协议[1、2]" n
	read -ep " :" protocol
	case $protocol in
	1)
		new_Net="ws";;
	2)
		new_Net="h2";;
	*)
		EchoR "[提示]"; Echo "请输入 1 或 2" n;modfiy_net;;
	esac
}
mod_conf(){
	[[ -n $new_UUID ]] && sed -i s/"$UUID"/"$new_UUID"/ $v2_conf $v2_info
	[[ -n $new_Port ]] && sed -i s/$Port/$new_Port/ $ng_conf $v2_info
	[[ -n $new_Net ]] && sed -i s/$Net/$new_Net/ $v2_conf $v2_info
	[[ -n $new_Path ]] && sed -i s/"$Path"/"$new_Path"/ $v2_conf $ng_conf $v2_info
	systemctl reload nginx.service &>/dev/null; systemctl restart v2ray.service &>/dev/null
}
	v2_variable
	Echo "是否需要生成新UUID?[y/n]" n
	option_judge;[[ $? == 1 ]] && new_UUID=`cat /proc/sys/kernel/random/uuid`
	Echo "是否需要更改端口号?[y/n]" n
	option_judge;[[ $? == 1 ]] && modfiy_port
	Echo "是否需要更改传输协议?[y/n]" n
	option_judge;[[ $? == 1 ]] && modfiy_net
	Echo "是否需要更换web路径?[y/n]" n
	option_judge;[[ $? == 1 ]] && new_Path="/`cat /proc/sys/kernel/random/uuid|md5sum|head -c 8`"
	Echo "确定要修改配置吗?[y/n]" n
	option_judge;[[ $? == 2 ]] && exit
	mod_conf
	show_vmess
}
remove_all(){
	rm -rf /usr/local/v2ray; rm -rf /usr/local/nginx
	rm -f /usr/lib/systemd/system/nginx.service; rm -f /usr/lib/systemd/system/v2ray.service
	chattr -i /usr/sbin/v2mgr &>/dev/null; rm -f /usr/sbin/v2mgr
}
help_info(){
	Echo "v2ray安装目录：/usr/local/v2ray"
	Echo "v2ray配置文件：/usr/local/v2ray/conf/config.json"
	Echo "nginx安装目录：/usr/local/nginx"
	Echo "nginx配置文件：/usr/local/nginx/conf/vhost.d/default.conf"
	Echo "重新配置安装及升级v2ray："; EchoG "bash <(curl -sL https://raw.githubusercontent.com/raixen/v2ray-script/master/install.sh)";echo
	Echo "卸载v2ray所有相关文件：" n; EchoG "bash $0 remove_all";echo
}
menu(){
	echo -e "------v2ray管理脚本------

  ${Green}1.${Font} 查看配置信息
  ${Green}2.${Font} 修改v2ray配置
  ${Green}3.${Font} 重启相关服务
  ${Green}4.${Font} 停用v2ray服务
  ${Green}5.${Font} 查看帮助"
	show_status
	echo && echo -e "请输入数字 [${Red}1-5${Font}]"
	read -n1 -ep "<退出脚本？or :" num
	[[ -z ${num} ]] && num=0
	case "$num" in
	1)
		show_vmess
		;;
	2)
		v2ray_config
		;;
	3)
		restart_service
		;;
	4)
		disable_v2
		;;
	5)
		help_info
		;;
	0)
		echo -e "${Red}已退出！${Font}" && exit
		;;
	*)
		EchoR "[提示]"; Echo " 请输入正确的数字 [1-4]"
		;;
	esac
}
[[ -z $1 ]] && menu || $1
	EEF
	chmod 555 /usr/sbin/v2mgr; chattr +i /usr/sbin/v2mgr &>/dev/null
}
port_exist_check(){
	if [[ 0 -eq `ss -tnl|grep ":$1"|wc -l` ]];then
		Info; msg "$1 端口未被占用"
		sleep 1
	else
		Ymsg "[提示]";msg "检测到 $1 端口被占用，以下为 $1 端口占用信息"
		lsof -i:"$1"
		Ymsg "[提示]";msg "3s 后将尝试 关闭 端口占用进程"
		sleep 3
		lsof -i:"$1" | awk '{print $2}'| grep -v "PID" | xargs kill -9
		Info; msg "kill 完成"
	fi
}
start_run_service(){
	port_exist_check 443
	port_exist_check 10443
	systemctl enabled v2ray.service &> /dev/null ; systemctl restart v2ray.service &> /dev/null
	judge "v2ray服务启动" 0
	if [[ ! -e /ssl-cert/v2ray.crt ]]; then
		nginx_status="1"
	else
		systemctl enabled nginx.service &> /dev/null
		systemctl restart nginx.service &> /dev/null
		judge "nginx服务启动" 0; nginx_status="$?"
	fi
}
main(){
	check_env; Cmsg "$Titel"
	input_parameter
	dependency_install
	install_nginx_v2ray
	configre
	[[ $bbr == "1" ]] && install_bbr
	([[ $domain_ssl == "1" ]] && [[ $ip_match != "1" ]]) && ssl_install && acme
	start_run_service
	[[ $nginx_status != "0" ]] && (Ymsg "[警告]" n;msg "请将域名SSL证书文件放置在 /ssl-cert 目录下，\n并更改证书文件名分别为 v2ray.crt 、v2ray.key")
	script_output && (Info; msg "已安装管理v2ray脚本：" n;echo -e "\e[1;35mv2mgr\e[0m\n      v2mgr可修改配置及管理相应服务")
	bash /usr/sbin/v2mgr show_vmess && (Cmsg " v2ray客户端下载："; Gmsg "https://redkey.top/downloads/tool/v2ray")
	msg "v2ray+ws+tls安装脚本 已执行完所有操作"
	if [[ bbr_status == "0" ]]; then
		Ymsg "[提示]" n; msg "bbr模块生效需要重启系统，是否立即重启？[Y/n]" n && read -ep " :" reboot
		[[ -z $reboot ]] && install="y"
		case $reboot in
		[yY])
			Info; msg "正在重启系统..."
			reboot ;;
		*)
			Ymsg "[提示]" n; msg "请您选择合适的时间手动重启系统" ;;
		esac
	fi
	rm -f $0 ~/$0
}
main