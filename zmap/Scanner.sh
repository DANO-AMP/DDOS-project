#!/bin/bash
echo -e "\e[1;32mSETTING UP YOUR SCANNING SHIT RETARD"
yum install cpan wget curl glibc.i686 -y
cpan force install Parallel::ForkManager
cpan force install IO::Socket
cpan force install IO::Select
sleep 2
yum install gcc php-devel php-pear libssh2 libssh2-devel libpcap -y
pecl install -f ssh2
touch /etc/php.d/ssh2.ini
echo extension=ssh2.so > /etc/php.d/ssh2.ini
cpan force install Net::SSH2
echo -e "\e[1;36mYOUR SCANNING SHIT SETUP IS DONE U NIGGER"