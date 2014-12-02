ngx-lua-yubikey-auth
====================

About
-----

This is a ngx-lua application that implements a web
authentication gateway using a yubikey otp. It uses
access_by_lua to check for a authentication token stored
in a cookie. If the cookie is missing or is invalid then
the client is redirected to a form that requests a yubikey
hash. A yubikey authentication service is then queried via
a nginx subrequest.

Installation
------------

There is a deployment script that is relevant only for debian-based operating systems. Basically there is an example nginx server block that you can follow to add this to your site. Just change the server secret key.

License
-------
You can do anything you want with this code. I don't give any warranties for it.
