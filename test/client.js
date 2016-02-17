#!/usr/bin/env node

var config = require('./config')
var chalk = require('chalk');
var WebSocket = require('ws');

var session_id;
var ubus_id = config.ubus_id;
var tests = [];
var i = 0;
var j = 0;
var session_json='{"jsonrpc": "2.0", "id": UBUS_ID, "method": "call", "params": [ "00000000000000000000000000000000", "session", "login", { "username": "root", "password": "root"}]}'

var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream(config.test_file)
});

function strncmp(str1, str2, n) {
    str1 = str1.substring(0, n);
    str2 = str2.substring(0, n);
    return ( ( str1 == str2 ) ? 1 : 0);
}

console.log("startig server.js script");


process.argv.forEach(function (val, index, array) {
    if (index == 2) {
        session_id = val;
        console.log("session id is:" + session_id);
    }
});

lineReader.on('line', function (line) {
    if (line.length > 0 && line.substring(0, 1) !== '#') {
        tests[i] = line;
        i = i + 1;
    }
});

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
    } else {
       ubus_id = ubus_id + 1;
       var msg = tests[j].replace(/SESSION_ID/g, session_id).replace(/UBUS_ID/g, ubus_id);
       ws.send(msg, {mask: true});
       console.log("> " + msg);
       j = j + 2;
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
        session_id = data.split("\"")[11]
    } else {
        var compare = tests[j - 1].replace(/SESSION_ID/g, session_id).replace(/UBUS_ID/g, ubus_id);

        if (strncmp(data, compare, compare.length )) {
            console.log(chalk.green("PASS"));
        } else {
            console.log(chalk.red("FAIL"));
            console.log("got");
            console.log(chalk.red(data));
            console.log("expected");
            console.log(chalk.green(tests[j-1].replace(/SESSION_ID/g, session_id).replace(/UBUS_ID/g, ubus_id)));
        }

            console.log();
            console.log();
    }
   if (j < i) {
       ubus_id = ubus_id + 1;
       var msg = tests[j].replace(/SESSION_ID/g, session_id).replace(/UBUS_ID/g, ubus_id);
       ws.send(msg, {mask: true});
       console.log("> " + msg);
   }

   if (j >= (i - 1)) {
       ws.close()
   } else {
       j = j + 2;
   }
});
