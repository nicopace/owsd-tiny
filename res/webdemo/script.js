"use strict";

window.onload = function() {

var url_in = document.getElementById("url");

url_in.value = window.location;
url_in.value = url_in.value.replace(/^http/, "ws");

var ta_in = document.getElementById("ta_in");
var ta_out = document.getElementById("ta_out");
var st = document.getElementById("status");
var iost = document.getElementById("io_status");
var btn_go = document.getElementById('btn_go');
var btn_send = document.getElementById('btn_send');

var w;

btn_go.onclick = function() {
	try {
		w = new WebSocket(url_in.value, "ubus-json");
	} catch (exc) {
		st.textContent = "Exception " + exc;
	}

	w.onopen = function(ev) {
		st.textContent = "Connected " + ev;
	};
	w.onmessage = function(ev) {
		var jp = JSON.parse(ev.data);
		if (jp.method === "event" && "params" in jp) {
			ta_out.value += "Event " + jp.params.type + " = " + JSON.stringify(jp.params.data);
		}
		ta_out.value += "\n-------\n\n" + ev.data;
		ta_out.scrollTop = ta_out.scrollHeight;
	};
	w.onerror = function(e) {
		st.textContent += "[Error]";
	};
	w.onclose = function(e) {
		st.textContent = "Close(" + e.reason + ")";
	};

	btn_send.disabled = "";
};

btn_send.onclick = function() {
	try {
		var jobj = JSON.parse(ta_in.value);
		w.send(JSON.stringify(jobj));
		iost.textContent = "";
	} catch (exc) {
		iost.textContent = "Error " + exc;
	}
};

} // onload
