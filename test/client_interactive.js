#!/usr/bin/env node

var config = require('./config.js');
var chalk = require('chalk');
var WebSocket = require('ws');

console.log("startig server.js script");

var link;
var session_id;
var ubus_id = config.ubus_id;
var i = 0;
var j = 0;
var session_json='{"jsonrpc": "2.0", "id": UBUS_ID, "method": "call", "params": [ "00000000000000000000000000000000", "session", "login", { "username": "root", "password": "root"}]}'

process.argv.forEach(function (val, index, array) {
    if (index == 2) {
        session_id = val;
        console.log("session id is:" + session_id);
    }
});

function strncmp(str1, str2, n) {
    str1 = str1.substring(0, n);
    str2 = str2.substring(0, n);
    return ( ( str1 == str2 ) ? 1 : 0);
}

var ws = new WebSocket(config.url, {
    protocol: config.protocol,
    origin: config.origin
});

ws.on('open', function open() {
    console.log('connected');
    if ( typeof session_id === 'undefined') {
        var msg = session_json.replace(/UBUS_ID/g, ubus_id);
        ws.send(msg, {mask: true});
        console.log("> " + msg);
    }
});

ws.on('close', function close() {
  console.log('disconnected');
});

ws.on('error', function close() {
  console.log('error');
});

ws.on('message', function message(data, flags) {

    if ( typeof session_id === 'undefined') {
        session_id = data.split("\"")[11];
    }

    var object = JSON.parse(data);
    var util = require('util');

    console.log(util.inspect(object, {depth: null, colors: true}));

    console.log();
});

process.stdin.resume();
process.stdin.setEncoding('utf8');
var util = require('util');

process.stdin.on('data', function (text) {
    ubus_id = ubus_id + 1;
    var msg = text.replace(/SESSION_ID/g, session_id).replace(/UBUS_ID/g, ubus_id);
    ws.send(msg, {mask: true});
    if (text === 'quit\n') {
        done();
    }
});

function done() {
    ws.close();
    process.exit();
}
