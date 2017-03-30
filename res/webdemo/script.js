"use strict";

window.onload = function() {

var url_in = document.getElementById("url");

url_in.value = window.location;
url_in.value = url_in.value.replace(/^http/, "ws");

var ta_in = document.getElementById("ta_in");
var ta_out = document.getElementById("ta_out");
var st = document.getElementById("status");
var iost = document.getElementById("io_status");
var upfile = document.getElementById("upfile");
var upform = document.getElementById("upform");
var btn_go = document.getElementById('btn_go');
var btn_send = document.getElementById('btn_send');

var w;

var sessionId;
var globalCallId = 0;
var fileChunkSize = 64000;

btn_go.onclick = function() {
	try {
		w = new WebSocket(url_in.value, "ubus-json");
	} catch (exc) {
		st.textContent = "Exception " + exc.message;
		return;
	}

	st.textContent = "Connecting";

	w.onopen = function(ev) {
		st.textContent = "Connected " + w.readyState;
		btn_send.disabled = "";
	};
	w.onmessage = function(ev) {
		var jp = JSON.parse(ev.data);
		if (jp.method === "event" && "params" in jp) {
			ta_out.value += "Event " + jp.params.type + " = " + JSON.stringify(jp.params.data);
		} else {
			ta_out.value += "\n-------\n\n" + ev.data;
		}

		if (jp && jp.result[1] && jp.result[1].ubus_rpc_session !== undefined) {
			sessionId = jp.result[1].ubus_rpc_session;
			st.textContent += ", session " + sessionId;
		}

		ta_out.scrollTop = ta_out.scrollHeight;
	};
	w.onerror = function(e) {
		st.textContent += "[Error] " + e;
	};
	w.onclose = function(e) {
		st.textContent = "Close(" + e.reason + ")";
	};
};

btn_send.onclick = function() {
	try {
		var jobj = JSON.parse(ta_in.value);
		w.send(JSON.stringify(jobj));
		iost.textContent = "";
	} catch (exc) {
		iost.textContent = "Error " + exc.message;
	}
};

upfile.onchange = function(e) {
	btn_up.disabled = "";
};

upform.onsubmit = function(e) {
	var fileUploadState = {
		file: upfile.files[0],
		reader: new FileReader(),
		offset: 0,
		id: ++globalCallId,
		respwatcher: null,
	};
	console.log(fileUploadState.file);

	fileUploadState.reader.onload = function(e) {
		if (e.target.error != null) {
			console.log("error reading file " + e.target.error);
			return false;
		}
		var rpc = {
			jsonrpc: "2.0",
			id: fileUploadState.id,
			method: "call",
			params: [
				sessionId, "file", "write", {
					path: "/tmp/tmp.bin",
					data: e.target.result.split(",")[1],
					base64: true,
					append: fileUploadState.offset > 0,
				}
			]
		};
		w.send(JSON.stringify(rpc));
	}

	fileUploadState.respwatcher = function(e) {
		var obj;
		var skip = true;
		var done = false;

		try {
			obj = JSON.parse(e.data);
			if (obj.id === fileUploadState.id)
				skip = false;
			else
				console.log("skip response id " + obj.id);
		} catch (exc) {
			console.log("skip invalid json message " + exc.message);
		}

		if (skip)
			return;

		try {
			if (obj.result[0] !== 0)
				throw { message: "unexpected result in file write response" };
			fileUploadState.id = ++globalCallId;
			fileUploadState.offset += fileChunkSize;
			if (fileUploadState.offset >= fileUploadState.file.size)
				done = true;
		} catch (exc) {
			iost.textContent = "FileError " + exc.message;
			done = true;
		}

		if (!done) {
			fileUploadState.reader.readAsDataURL(
					fileUploadState.file.slice(
						fileUploadState.offset, fileUploadState.offset + fileChunkSize));
		} else {
			w.removeEventListener("message", fileUploadState.respwatcher, false);
		}
	}

	w.addEventListener("message", fileUploadState.respwatcher, false);
	fileUploadState.reader.readAsDataURL(
			fileUploadState.file.slice(
				fileUploadState.offset, fileUploadState.offset + fileChunkSize));

	return false;
};

} // onload
