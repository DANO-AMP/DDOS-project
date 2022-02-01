# API PHP

API in PHP for DDoS Attacks


Install on Ubuntu 18:

apt install apache2 php php-fpm php-ssh2 -y

service apache2 restart


Usage

Change the credentals on the API to your server info

Line 4: Put your server IP, if using same server just use localhost

Line 8: Your server User, most times just root

Line 10: Your server password

Line 12: Methods, to add a new method put , "METHOD" after , "stop"

Line 14: API Key, change that to your API Key so its protected

Line 78: Add new method, just copy the same from any method and replace with your method usage


Upload file to /var/www/html


API Link: http://YOURSERVERIP/api.php?key=superkey&host=[host]&port=[port]&time=[time]&method=[method]


Credits: @fork
