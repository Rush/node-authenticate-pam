node-authenticate
=================

Asynchronous PAM authentication for NodeJS 0.8.0 and later (using libuv and gyp)

It tries to superseed the previous and outdated node-pam extension with the following improvements:
* Allows to provide own service name, for example common-auth or any custom service name defined in `/etc/pam.d`
* Already mentioned utilization of libuv and node-gyp
* Proper type checking in C++ code, it throws exception if bad types are given
* In case of error it passes the error string containing both pam function and `pam_strerror()` results

Example
=========

Simple usage
------------
    var pam = require('authenticate-pam');
    pam.authenticate('rush', 'mysecretpassword', function(err) {
        if(err) {
          console.log(err);
        }
        else {
          console.log("Authenticated!");
        }
      });

Usage with options:
-------------------
    var pam = require('authenticate-pam');
    pam.authenticate('rush', 'mysecretpassword', function(err) {
        if(err) {
          console.log(err);
        }
        else {
          console.log("Authenticated!");
        }
    }, {serviceName: 'sshd'});
    
Install
-------------------
To be commited to npm registry and sent to github soon