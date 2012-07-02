var assert = require('assert');
var pam = require('./build/Release/authenticate_pam');

pam.authenticate(process.argv[2], process.argv[3],
	function(err) {
		if(err) {
			console.log("Login failure: " + err)
		}
		else {
			console.log("Authenticated!");
		}
	}, {'remoteHost': "localhost"}
);
