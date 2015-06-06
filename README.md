# ProxySocket

[![Join the chat at https://gitter.im/krisives/proxysocket](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/krisives/proxysocket?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

A Node.js module for connecting to a SOCKS5 proxy. This is mainly
a rewrite of `socks5-client` as that module was not working for me in more
recent versions of NodeJS (in particular `node-webkit`)

## Making Connections

First require the module:

	var ProxySocket = require('proxysocket');

Create a `ProxySocket` object, passing the host and port
that the SOCKS5 proxy is bound to. For example if you were
running `tor` without any custom settings/ports you would
use port `9050`

	var socket = new ProxySocket('localhost', 9050);

The returned socket behaves like an ordinary `Socket` object
and you can call `connect()` on it:

	socket.connect('website.com', 80, function () {
		// Connection handler
	});

Also note if you're using Tor it's fine to pass `.onion` hosts:

	socket.connect('p4fsi4ockecnea7l.onion', 6667);


## Making HTTP Requests

You can use `ProxySocket.createAgent()` to create an object
like `http.Agent` which will make proxy sockets for you. Here is
an example of making an http request:

	var ProxySocket = require('proxysocket');
	var http = require('http');
	var agent = ProxySocket.createAgent();

	http.request({
		host: 'foo.com',
		agent: agent
	});
