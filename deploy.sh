#!/bin/sh
cp -p *lua /tmp/testsite/
cp nginx_site /etc/nginx/sites-enabled/yubi-test 

/etc/init.d/nginx restart
