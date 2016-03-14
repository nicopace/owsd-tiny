#!/usr/bin/env node

var config = require('./config')
var chalk = require('chalk');
var WebSocket = require('ws');

var session_id;
var ubus_id = config.ubus_id;

var tests = [];
var tests_by_id = [];

var events = [];

var read_events = 0;

var sent_tests = 0;
var recv_tests = 0;

var session_json='{"jsonrpc": "2.0", "id": UBUS_ID, "method": "call", "params": [ "00000000000000000000000000000000", "session", "login", { "username": "owsd_test", "password": "x"}]}'

var lineReader = require('readline').createInterface({
	input: require('fs').createReadStream(config.test_file)
});

function strncmp(str1, str2, n) {
	str1 = str1.substring(0, n);
	str2 = str2.substring(0, n);
	return ( ( str1 == str2 ) ? 1 : 0);
}

console.log("startig test script");


process.argv.forEach(function (val, index, array) {
	if (index == 2) {
		session_id = val;
		console.log("session id is:" + session_id);
	}
});

if (typeof session_id === 'undefined') {
	session_json = session_json.replace(/UBUS_ID/g, ubus_id++)
		var session_json_obj = JSON.parse(session_json);
	var tmp = { req_line: session_json, obj: session_json_obj, resp_line: "" };
	tests.push(tmp);
}

var reading_req_line = true;
var reading_event = false;

lineReader.on('line', function (line) {
	if (line.length == 0 || line.charAt(0) === '#')
		return;

	line = line.replace(/UBUS_ID/g, ubus_id);

	if (reading_req_line) {
		reading_req_line = false;

		if (line.charAt(0) === "+") {
			//console.log(chalk.blue(" EVENT "));
			var curr_event = { req_line: line, obj: null}
			events.push(curr_event);
			reading_event = true;
		} else {
			// what we send
			try {
				var obj = JSON.parse(line);
				var curr_test = {req_line: line, obj: obj};
				tests_by_id[obj.id] = curr_test;
				tests.push(curr_test);
			} catch (e) {
				// skip invalid test
				console.log("skip line with error" + e);
				reading_req_line = true;
				return;
			}
		}
	} else {
		if (reading_event) {
			events[events.length-1].resp_line = line;
		} else {
			tests[tests.length-1].resp_line = line;
			++ubus_id;
		}
		reading_event = false;
		reading_req_line = true;
	}
});

var ws = new WebSocket(config.url, {
	protocol: config.protocol,
	rejectUnauthorized: false,
	origin: config.origin
});

ws.on('open', function open() {
	console.log('connected');
	var msg = tests[sent_tests++].req_line;
	ws.send(msg, {mask: true});
	console.log("> " + msg);
});

ws.on('close', function close(e) {
	console.log('disconnected ' + e);
});

ws.on('error', function close(e) {
	console.log('error ' + e);
});

ws.on('message', function message(data, flags) {
	var obj = JSON.parse(data);
	if (typeof session_id === 'undefined' && recv_tests == 0) {
		console.log(data);
		session_id = obj.result[1].ubus_rpc_session;
		console.log(chalk.blue("LOGIN " + session_id));
		++recv_tests;
	} else {
		if (typeof obj.id === 'undefined') {
			// we received event
			var compare = events[read_events++].resp_line.replace(/SESSION_ID/g, session_id);
			//console.log(chalk.magenta("event"));
		} else {
			var compare = tests_by_id[obj.id].resp_line.replace(/SESSION_ID/g, session_id);
			//console.log(chalk.yellow("resp"));
			++recv_tests;
		}

		if (strncmp(data, compare, compare.length )) {
			console.log(chalk.green("PASS"));
		} else {
			console.log(chalk.red("FAIL"));
			console.log("got");
			console.log(chalk.red(data));
			console.log("expected");
			console.log(chalk.green(compare));
		}
	}

	console.log();
	console.log();

	if (recv_tests == tests.length && read_events == events.length) {
		ws.close();
	} else {
		if (sent_tests === recv_tests) {
			var msg = tests[sent_tests++].req_line.replace(/SESSION_ID/g, session_id);
			ws.send(msg, {mask: true});
			console.log("> " + msg);
		} else {
			console.log("+ ");
		}
	}
});
