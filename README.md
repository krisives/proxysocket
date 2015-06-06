# proxysocket

[![Join the chat at https://gitter.im/krisives/proxysocket](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/krisives/proxysocket?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

`proxysocket` is a nodejs module for seamlessly making socket connections via a
SOCKS5 proxy. Use it in place of a regular `net.Socket` to easily talk over
Tor or an SSH tunnel.

## Install

Available on npm for easy install:

	npm install proxysocket

You can also download a [release](https://github.com/krisives/proxysocket/releases) manually and
extract it as `proxysocket` has no dependencies.

## Usage

Because `proxysocket` provides the same API as a regular `net.Socket` object
you can use it in many places where sockets and streams are used.

### Making a Socket

Create a new socket that will use the proxy:

	var proxysocket = require('proxysocket');
	var socket = proxysocket.create('localhost', 9050);

The returned object behaves like an ordinary `net.Socket` object.
For example, you can call `connect()` or listen for events:

	socket.connect('website.com', 80, function () {
		// Connected
	});

	socket.on('data', function (data) {
		// Receive data
	});

Also note if you're using Tor it's fine to pass `.onion` hosts:

	socket.connect('p4fsi4ockecnea7l.onion', 6667);


### Making HTTP Requests

You can use `proxysocket.createAgent()` to create an object
like `http.Agent` which will make proxy sockets for you when using
`http.request()`. Here is an example:

	var proxysocket = require('proxysocket');
	var http = require('http');
	var agent = proxysocket.createAgent();

	http.request({
		host: 'foo.com',
		agent: agent
	});


## API

### proxysocket.create(socksHost, socksPort, socket)

Create a new socket object that uses a SOCKS5 proxy provided.

* `socksHost` is the host of the SOCKS5 proxy. Default is `localhost`
* `socksPort` is the port of the SOCKS5 proxy. Default is `9050`
* `socket` can be an existing `net.Socket` object. Default is a `new Socket()`

### proxysocket.createAgent(socksHost, socksPort)

Returns an object like `http.Agent` which makes new sockets
using `proxysocket.create()` as needed.

### socket

The object returned from `proxysocket.create()` is just like a regular
`net.Socket`. This documentation lists additions to the API.

*Note This documentation doesn't list all of the methods, properties,
or events of `net.Socket`, `Readable` or `Writable`.*

### socket.socksHost

Get the host address of the proxy. By default this will be `localhost`.

### socket.socksPort

Get the port of the proxy. By default this will be `9050`.

### socket.realSocket

Get the underlying raw `net.Socket` connection to the proxy. You don't need
to use this and instead should listen on `this` socket instead.

### socket 'socksdata' event

`socksdata` is emitted whenever underlying data is received from the proxy
before the socket is ready for use. This is mainly here for debugging and you
should use the `data` event instead.

## Contributing

Please fork and make a pull request if you have anything cool to add. You're
also welcome to join the [Gitter](https://gitter.im/krisives/proxysocket?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) chat.
