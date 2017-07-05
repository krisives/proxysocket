

var net = require('net');
var EventEmitter = require('events').EventEmitter;
var inherits = require('util').inherits;

function proxysocket(socksHost, socksPort, socket) {
	var self = this;

	// Set when we start connect()
	var connecting = false;

	// Set when connection stages are finished
	var connected = false;

	// Stages in the SOCKS5 connection
	var connectionStages = [
		receiveSocksAuth,
		receiveSocksConnect
	];

	// What stage we are in currently
	var stage = 0;

	// Set from connect() to what host and port we are connecting to
	var host = '', port = 0;

	// While the SOCKS connection is going we buffer the
	// requests to write()
	var unsent = [];
	// and to pipe()
	var unpiped = [];

	// While the socket is still being setup the encoding
	// is saved as we expect binray encoding on the socket
	// until then
	var socketEncoding = null;

	// Default host/ports to use if not given
	self.socksHost = socksHost = socksHost || 'localhost';
	self.socksPort = socksPort = socksPort || '9050';

	// Users can pass their own socket if they already have one
	// connected to the SOCKS proxy
	self.realSocket = socket = socket || (new net.Socket({
		readable: true,
		writable: true
	}));

	// A socket emits events like 'data' and 'connect'
	EventEmitter.call(self);

	self.readable = true;
	self.writable = true;

	// Read event for the real socket
	socket.on('data', function (buffer) {
		if (connected) {
			self.emit('data', buffer);
		} else {
			// Emit an event useful for debugging the raw SOCKS data
			self.emit('socksdata', buffer);

			// Handle SOCKS protocol data
			receiveSocksData(buffer);
		}
	});

	socket.on('error', function (e) {
		self.emit('error', e);
	});

	socket.on('end', function () {
		self.writable = false;

		self.emit('end');
	});

	socket.on('timeout', function () {
		self.emit('timeout');
	});

	socket.on('close', function () {
		self.writable = false;

		if (connected) {
			self.emit('close');
		}
	});

	socket.on('drain', function () {
		if (connected) {
			self.emit('drain');
		}
	});

	socket.on('readable', function () {
		if (connected) {
			self.emit('readable');
		}
	});

	self.read = function (size) {
		if (!connected) {
			return null;
		}

		return socket.read(size);
	};

	self.destroy = function () {
		self.writable = false;

		return socket.destroy();
	};

	self.destroySoon = function () {
		self.writable = false;

		return socket.destroySoon();
	};

	self.ref = function () {
		return socket.ref();
	};

	self.unref = function () {
		return socket.unref();
	};

	self.setKeepAlive = function (enable, initialDelay) {
		return socket.setKeepAlive(enable, initialDelay);
	};

	self.pipe = function (dest, opts) {
		if (connected) {
			return socket.pipe(dest, opts);
		}

		unpiped.push([dest, opts]);
		return dest;
	};

	// Handle SOCKS protocol specific data
	function receiveSocksData(data) {
		while (data && stage < connectionStages.length) {
			data = connectionStages[stage](data);
			stage++;
		}

		// Emit the sockets first packet
		if (connected && data) {
			self.emit('data', data);
		}
	}

	// Handle the response after sending authentication
	function receiveSocksAuth(d) {
		var error;

		if (d.length !== 2) {
			error = new Error('SOCKS authentication failed. Unexpected number of bytes received.');
		} else if (d[0] !== 0x05) {
			error = new Error('SOCKS authentication failed. Unexpected SOCKS version number: ' + d[0] + '.');
		} else if (d[1] !== 0x00) {
			error = new Error('SOCKS authentication failed. Unexpected SOCKS authentication method: ' + d[1] + '.');
		}

		if (error) {
			self.emit('error', error);
			return;
		}

		sendConnect();
	}

	// Handle the response after sending connection request
	function receiveSocksConnect(d) {
		var error;

		if (d[0] !== 0x05) {
			error = new Error('SOCKS connection failed. Unexpected SOCKS version number: ' + d[0] + '.');
		} else if (d[1] !== 0x00) {
			error = new Error('SOCKS connection failed. ' + connectErrors[d[1]] + '.');
		} else if (d[2] !== 0x00) {
			error = new Error('SOCKS connection failed. The reserved byte must be 0x00.');
		}

		if (error) {
			self.emit('error', error);
			return;
		}

		connected = true;

		// TODO map some of the addresses?
		self.localPort = socket.localPort;
		self.localAddress = socket.localAddress;
		self.remotePort = socket.remotePort;
		self.remoteAddress = socket.remoteAddress;
		self.bufferSize = socket.bufferSize;

		// Set the real encoding which could have been
		// changed while the socket was connecting
		setEncoding(socketEncoding);

		if (unsent.length) {
			for (var i=0; i < unsent.length; i++) {
				socket.write(unsent[i][0], unsent[i][1], unsent[i][2]);
			}

			unsent = [];
		}

		if (unpiped.length) {
			for (var i=0; i < unpiped.length; i++) {
				socket.pipe(unpiped[i][0], unpiped[i][1]);
			}

			unpiped = [];
		}

		// Emit the real 'connect' event
		self.emit('connect');
	}

	function sendAuth() {
		var request = new Buffer(3);
		request[0] = 0x05;  // SOCKS version
		request[1] = 0x01;  // number of authentication methods
		request[2] = 0x00;  // no authentication

		if (!socket.write(request)) {
			throw new Error("Unable to write to SOCKS socket");
		}
	}

	// Parse a domain name into a buffer
	function parseDomainName(host, buffer) {
		var i, c;

		buffer.push(host.length);

		for (i = 0; i < host.length; i++) {
			c = host.charCodeAt(i);
			buffer.push(c);
		}
	}

	// Parse an host like 1.2.3.4 into a 32-bit number
	function parseIPv4(host, buffer) {
		var i, n;
		var parts = host.split('.');

		for (i = 0; i < parts.length; ++i) {
			n = parseInt(parts[i], 10);
			buffer.push(n);
		}
	}

	// Parse a IPv6 host into a buffer
	function parseIPv6(host, buffer) {
		var parts = host.split(':');
		var i, ind;
		var zeros = [];

		parts[0] = parts[0] || '0000';
		parts[parts.length - 1] = parts[parts.length - 1] || '0000';
		ind = parts.indexOf('');

		if (ind >= 0) {
			for (i = 0; i < 8 - parts.length + 1; ++i) {
				zeros.push('0000');
			}

			parts = parts.slice(0, ind).concat(zeros).concat(parts.slice(ind + 1));
		}

		for (i = 0; i < 8; ++i) {
			var num = parseInt(parts[i], 16);
			buffer.push(num / 256 | 0);
			buffer.push(num % 256);
		}
	}

	function sendConnect() {
		var request;
		var buffer = [
			0x05, // SOCKS version
			0x01, // Command code: establish a TCP/IP stream connection
			0x00  // Reserved - myst be 0x00
		];

		switch (net.isIP(host)) {
			default:
			case 0:
				buffer.push(0x03);
				parseDomainName(host, buffer);
				break;
			case 4:
				buffer.push(0x01);
				parseIPv4(host, buffer);
				break;
			case 6:
				buffer.push(0x04);
				parseIPv6(host, buffer);
				break;
		}

		htons(buffer, buffer.length, port);
		request = new Buffer(buffer);

		if (!socket.write(request)) {
			throw new Error("Unable to write to SOCKS socket");
		}
	}

	self.setTimeout = function (timeout, f) {
		return socket.setTimeout(timeout, f);
	};

	self.setNoDelay = function (noDelay) {
		return socket.setNoDelay(noDelay);
	};

	self.connect = function (connectPort, connectHost, f) {
		var tmp;

		// Backward compatibility
		if (typeof(connectHost) === 'number' || isNaN(connectPort)) {
			tmp = connectHost;
			connectHost = connectPort;
			connectPort = tmp;
		}

		if (connected) {
			throw new Error("Socket is already connected");
		}

		if (connecting) {
			throw new Error("Socket is already connecting");
		}

		host = connectHost;
		port = connectPort;
		connected = false;
		connecting = true;

		if (f) {
			self.on('connect', f);
		}

		setEncoding(null);

		return socket.connect(socksPort, socksHost, function () {
			connecting = false;
			sendAuth();
		});
	};

	self.write = function (data, encoding, f) {
		if (!connected) {
			unsent.push([data, encoding, f]);
			return;
		}

		return socket.write(data, encoding, f);
	};

	self.pause = function () {
		socket.pause();
	};

	self.resume = function () {
		socket.resume();
	};

	self.address = function () {
		return socket.address();
	};

	self.end = function (data, encoding) {
		socket.writable = false;

		if (!connected) {
			return socket.end();
		}

		return socket.end(data, encoding);
	};

	self.setEncoding = function (encoding) {
		if (connected) {
			setEncoding(encoding);
		} else {
			// Save encoding to be set once connected
			socketEncoding = encoding;
		}
	};

	function setEncoding(enc) {
		if (enc === null) {
			// Accroding to nodejs documentation, readable.setEncoding(null)
			// is a way to disable encoding.
			// However, it's not. So, need to hack into readable structure.
			socket.decoder = null;
			socket.encoding = null;
		} else {
			socket.setEncoding(enc);
		}
	}

	return self;
}

inherits(proxysocket, EventEmitter);

proxysocket.create = function (socksHost, socksPort, socket) {
	return new proxysocket(socksHost, socksPort, socket);
};

// A simple agent so that requests can be made using http.request()
// and anything else using the same Agent API
proxysocket.createAgent = function (socksHost, socksPort) {
	var http = require('http');

	var agent = new http.Agent({
	//	keepAlive: true
	});

	function connect(host, port, f) {
		var socket = proxysocket.create(socksHost, socksPort);
		socket.connect(port, host, f);
		return socket;
	}

	agent.createConnection = function (options, f) {
		return connect(
			options.host,
			options.port,
			f
		);
	};

	return agent;
};

module.exports = proxysocket;

// Converts a 16-bit short from Host To Network Storage
function htons(b, i, v) {
	b[i] = (0xff & (v >> 8));
	b[i + 1] = (0xff & (v));
}

// Error messages for when the proxy responds to sendConnect() used in handleConnect()
var connectErrors = {
	// Messages are taken from Wikipedia
	0x00: 'request granted',
	0x01: 'general failure',
	0x02: 'connection not allowed by ruleset',
	0x03: 'network unreachable',
	0x04: 'host unreachable',
	0x05: 'connection refused by destination host',
	0x06: 'TTL expired',
	0x07: 'command not supported / protocol error',
	0x08: 'address type not supported'
};
