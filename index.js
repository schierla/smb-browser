import express from "express";
import bodyparser from "body-parser";
import cookieparser from "cookie-parser";
import smb2 from "./smb2/lib/smb2.js";
import mime from "mime";
import escape from "escape-html";
import uid from "uid-safe";
import fs from "fs";

// load config file
const config = JSON.parse(fs.readFileSync(process.argv.length>2 ? process.argv[2] : './config/config.json'));
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 'loopback');
app.use(bodyparser.urlencoded({extended: false}));
app.use(cookieparser());
app.use('/fa', express.static(import.meta.dirname + '/node_modules/@fortawesome/fontawesome-free'));

if(!config.shares) {
	console.error("Configuration file must include shares.");
	process.exit();
}

// store sessions and share tokens
var session = {};
var tokens = {};

// file type icons
var icons = {
	'file-word': ['docx', 'doc', 'odt'],
	'file-excel': ['xlsx', 'xls', 'ods'],
	'file-powerpoint': ['pptx', 'ppt', 'odp'], 
	'file-image': ['png', 'jpg', 'jpeg', 'bmp'],
	'file-video': ['mp4', 'mov', 'avi'], 
	'file-audio': ['mp3', 'wav'], 
	'file-pdf': ['pdf'], 
	'file-csv': ['csv'],
	'file-archive': ['zip', '7z', 'tgz', 'gz', 'rar'], 
	'file-code': ['js', 'htm', 'html', 'css', 'c', 'cpp', 'cxx', 'h', 'hpp', 'hxx', 'cs', 'scala', 'java'], 
	'file-alt': ['txt']
};

// main handler
app.use('/', (req, res) => {

	// this is a request to validate credentials
	if(req.method == 'POST') {

		// destroy the old session for share
		if(req.cookies && req.cookies.sessionId && session[req.cookies.sessionId]) {
			if(req.body.share in session[req.cookies.sessionId]) {
				session[req.cookies.sessionId][req.body.share].close();
				delete session[req.cookies.sessionId][req.body.share];
			}
		}

		// rate limit login requests
		if(checkRateLimit('ip_' + req.ip) || checkRateLimit('user_' + req.body.user)) {
			return errorPage(req, res, 'Too many failed login attempts. Try again later.');
		}

		// empty user name or password are not allowed
		if(req.body.user == "" || req.body.password == "") {
			req.query.failed = true; 
			return res.redirect(req.path + "?" + Object.keys(req.query).join("&"));
		}

		// establish smb connection
		var smb = new smb2({ 
			share: config.shares[req.body.share], 
			domain: config.domain || "", 
			username: req.body.user, 
			password: req.body.password, 
			autoCloseTimeout: 0 
		});

		// try to read the top level directory
		smb.readdir('', (err, files) => {

			// if it fails, the login must have been incorrect (or inappropriate for the selected share)
			if(err) {
				req.query.failed = true; 
				return res.redirect(req.path + "?" + Object.keys(req.query).join("&"));

			} else {

				// create a session and store the smb connection
				var sid = uid.sync(24);
				if(req.cookies.sessionId && session[req.cookies.sessionId]) {
					sid = req.cookies.sessionId;
				} else {
					session[sid] = {};
					res.cookie('sessionId', sid);
				}
				session[sid][req.body.share] = smb;

				// clear rate limits
				clearRateLimit('ip_' + req.ip); clearRateLimit('user_' + req.body.user);

				// if the chosen share does not match the current path, redirect to the selected share
				var path = req.url;
				if(!path.startsWith("/" + req.body.share + "/")) path = "/" + req.body.share + "/";
				res.redirect(path);
			}
		});
		return;
	}

	// this is a logout request
	if("logout" in req.query) {
		// clear the session
		if(req.cookies && req.cookies.sessionId) {
			if(session[req.cookies.sessionId]) {
				for(var share in config.shares) {
					if(share in session[req.cookies.sessionId]) {
						session[req.cookies.sessionId][share].close();
					}
				}
				delete session[req.cookies.sessionId];
			}
			res.clearCookie("sessionId");
		}

		// redirect back to page
		return res.redirect(req.path);
	}

	// if the path does not contain a share name, show a share overview
	if(req.path.substr(1).indexOf('/') == -1) {
		return overviewPage(req, res);
	}

	// extract share name and directory
	var share = req.path.substr(1, (req.path.substr(1) + "/").indexOf('/'));
	var dir = decodeURI(req.path.substr(share.length + 2));

	// if the share name matches a share token, provide corresponding file
	if(share in tokens && tokens[share].session in session && tokens[share].share in session[tokens[share].session] && tokens[share].file.endsWith('/' + dir)) {
		return downloadFile(req, res, session[tokens[share].session][tokens[share].share], tokens[share].file);
	}

	if(!(share in config.shares)) {
		return errorPage(req, res, "If you are trying to access a shared link, it may have expired.");
	}

	// if the user is not logged in, or not logged in for this share, show a login page
	if(!req.cookies || !req.cookies.sessionId || !session[req.cookies.sessionId] || !(share in session[req.cookies.sessionId])) {
		return loginPage(req, res, "failed" in req.query ? 'Login failed' : 'Please login for ' + escape(share));
	}

	// this is a share request - create share link and store the token
	if("share" in req.query && (!("allowSharing" in config) || config.allowSharing)) {
		var token = uid.sync(16);
		tokens[token] = {session: req.cookies.sessionId, share: share, file: dir};
		var baseUrl = config.externalUrl || (req.protocol + "://" + (req.get('x-forwarded-host') || req.get('host'))); 
		return sharePage(req, res, baseUrl + '/' + token + dir.substr(dir.lastIndexOf('/')));
	}

	// remove trailing slashes
	if(dir.endsWith("/")) dir = dir.substr(0, dir.length - 1);

	// check smb connection
	var smb = session[req.cookies.sessionId][share];
	if(!smb.socket.writable) {
		smb.close(); 
		delete session[req.cookies.sessionId][share];
		return res.redirect(req.url);
	}
	
	// try to open the given path as directory
	smb.readdir(dir, (err, all) => {
		if(err) {

			// if it is a file, download it instead
			if(err.code == 'STATUS_NOT_A_DIRECTORY') {
				return downloadFile(req, res, smb, dir);
			}
			
			// handle common errors
			if(err.code == 'STATUS_ACCESS_DENIED') {
				res.status(403);
			} else if(err.code == 'STATUS_OBJECT_NAME_NOT_FOUND') {
				res.status(404); 
			}

			// show an error page
			return errorPage(req, res, err);

		} else {
			// show the directory listing
			return directoryPage(req, res, all);
		}
	});
});


// provide a file as download
function downloadFile(req, res, smb, file) {

	// files may not end with a slash
	if(req.path.endsWith("/")) {
		return res.redirect(req.path.substr(0, req.path.length - 1));
	}

	// stop download when the connection is closed
	var cancelled = false;
	res.on('close', () => { 
		cancelled = true; 
	});

	// try to read the file
	smb.readFile(
		file, 
		(len) => {
			// set mime type
			res.type(mime.getType(file) || 'application/octet-stream'); 
			
			// set size headers, allow partial downloads / streaming, and keep HEAD requests short
			var range = req.range(len);
			if(range && range.type === 'bytes') {
				var start = range[0].start, end = range[0].end;
				res.status(206);
				res.set('Content-Length', end-start+1);
				res.set('Content-Range', `bytes ${start}-${end}/${len}`);
				if(req.method.toLowerCase() == 'head') return {start: 0, end: 0};
				return {start: start, end: end};
			} else {
				res.set('Content-Length', len);
				res.set('Accept-Ranges', 'bytes');
				if(req.method.toLowerCase() == 'head') return {start: 0, end: 0};
			}
		}, 
		(data, next) => {
			// and send data chunks (unless the connection fails)
			if(!res.finished) {
				res.write(data, () => next(!cancelled));
			} else {
				next(false);
			}
		}, 
		(err) => {
			// in case of errors, show an error page
			if(err) {
				if(err.code == 'STATUS_ACCESS_DENIED') res.status(403);
				else if(err.code == 'STATUS_OBJECT_NAME_NOT_FOUND') res.status(404);
				if(!res.finished) return errorPage(req, res, err);
			} else {
				// download has finished, close the connection
				if(!res.finished) res.end();
			}
		}
	);
}


// rate limiting
var ratelimit = {};

// check if rate limiting applies to the given key
function checkRateLimit(key) {

	// read config
	var failedRequests = config.failedRequests || 5, blockTime = config.blockTime || 300;

	// unknown key means this is the first request
	if(!(key in ratelimit)) ratelimit[key] = {time: Date.now(), count: 0};

	// if the block time has exceeded since the last access, reset counter to zero
	if(ratelimit[key].time + blockTime * 1000 < Date.now()) ratelimit[key].count = 0;

	// update counter and last access time
	ratelimit[key].count++;
	ratelimit[key].time = Date.now();

	// block if counter exceeds allowed number of failed requests
	return ratelimit[key].count > failedRequests;
}

// clears rate limiting for a given key (e.g. if login succeeds)
function clearRateLimit(key) {
	delete ratelimit[key];
}


// show breadcrumbs for a given path
function breadcrumbs(path) {
	var parts = path.split('/'), prefix = '';
	var ret = '<a href="/">ROOT</a>';
	for(var part of parts) {
		if(part == '') continue;
		ret = ret + " / "; 
		prefix += "/" + part; 
		ret += `<a href="${prefix}/">${escape(decodeURI(part))}</a>`;
	}
	return ret;
}

// page footer
function header(req) {
	return `
<!DOCTYPE html>
<html>	
<head>
	<meta charset="utf-8">
	<meta name="viewport" content="width=device-width, initial-scale=1">			
	<title>${escape(decodeURI(req.path))}</title>
	<link rel="stylesheet" href="/fa/css/all.css">
	<style>
		body {font-family: Arial, Helvetica, sans-serif; }
		h1 {font-size: 1em; }
		a {text-decoration: none; }
		a:hover {text-decoration: underline; }
		tr:hover {background: #ccc; }
		table {border: none 0px; border-collapse: collapse; }
		td {padding: 4px; }
		td a {display: block; }
		label {display: flex; }
		label i {flex-grow: 0; padding: 4px; margin: 0 4px 0 12px; }
		label input, label select { flex-grow: 1; padding: 4px; margin: 0 16px 0 4px; }
		button {display: block; padding: 4px; width: 60%; margin: 4px auto; }
		.infobox {max-width: 30em; margin: 5em auto; border: solid #4f5452 1px; background: #ccc; box-shadow: 5px 5px 10px #aaa; padding: 5px; }
		.infobox h2 {font-size: 1.2em; font-weight: normal; margin: -5px -5px 10px -5px; padding: 5px; text-align: center; background: #ff7f00; }
		.infobox h2 i {float: left; }
		.size {text-align: right; }
		.icon, .share {width: 20px; }
		table {width: 95%; margin: 0 auto; }
		.hidden {opacity: 0.5; }
		.logout {float: right; }
		.footer {text-align: center; margin-top: 2em; }
		.share a {opacity: 0; color: #777; }
		tr:hover .share a {opacity: 0.5; }
		.share a:hover {color: #000; }
	</style>
</head>            
<body>
	${"sessionId" in req.cookies ? `<a class="logout" href="${req.path}?logout">Logout</a>`:``}
	<h1>${breadcrumbs(req.path)}</h1>`;
}

// page header
function footer() {
	return `
	<div class="footer">
		${config.legalNoticeUrl?'<a href="'+config.legalNoticeUrl+'">Legal Notice</a>':''}
		${(config.legalNoticeUrl && config.privacyUrl)?' | ':''}
		${config.privacyUrl?'<a href="'+config.privacyUrl+'">Privacy Policy</a>':''}
	</div>
</body>
</html>`;
}

// shows the login page
function loginPage(req, res, title) {
	var share = req.path.substr(1, (req.path.substr(1) + "/").indexOf('/'));
	res.type("text/html");
	res.charset = "utf-8";
	res.write(header(req));
	res.write(`
	<div class="infobox">
		<h2>${title}</h2>
		<form action="${req.url}" method="post">
			<label><i class="fa fa-user"> </i> <input type="text" name="user" id="user" placeholder="Username" autofocus></label><br>
			<label><i class="fa fa-unlock"> </i> <input type="password" name="password" placeholder="Password" id="pass"></label><br>
			<label><i class="fa fa-share-alt"> </i> <select name="share" id="share">`);
	for(var s in config.shares)
		res.write(`
				<option value="${s}"${s==share?' selected':''}>${s}</option>`
		);
	res.write(`
			</select></label><br>
			<button type="submit">Login</button>
		</form>
	</div>`);
	return res.end(footer());
}

// shows the share link for a chosen file
function sharePage(req, res, link) {
	res.type("text/html");
	res.charset = "utf-8";
	res.write(header(req));
	res.write(`
	<div class="infobox">
		<h2>Share link created</h2>
		<label><i class="fas fa-link"> </i> <input type="text" readonly onfocus="this.select();" value="${escape(link)}"></label>
		<p>The link is valid until you logout (or are automatically logged out).</p>
	</div>`);
	return res.end(footer());
}

// shows an error page
function errorPage(req, res, err) {
	res.type("text/html");
	res.charset = "utf-8";
	res.write(header(req));
	res.write(`
	<div class="infobox">
		<h2><i class="fas fa-exclamation-triangle"> </i> Failed to load</h2>
		${err}
	</div>`);
	return res.end(footer());
}

// shows a share overview page
function overviewPage(req, res) {
	res.type("text/html");
	res.charset = "utf-8";
	res.write(header(req));
	res.write(`
	<table>`
	);

	for(var share in config.shares) {
		// output entry
		var icon = (req.cookies && req.cookies.sessionId && session[req.cookies.sessionId] && share in session[req.cookies.sessionId]) ? 'lock-open' : 'lock';
		res.write(`
		<tr><td class="icon"><i class="fa fa-${icon}"></i></td><td class="name"><a href="/${encodeURIComponent(share)}/">${escape(share)}</a></td><td class="size">[SHARE]</td><td class="share"></td></tr>`
		);
	}
	res.write(`
	</table>
	`);
	return res.end(footer());	
}

// shows a directory listing
function directoryPage(req, res, all) {
	// directories have to end with a slash
	if(!req.path.endsWith("/")) {
		return res.redirect(req.path + "/");
	} 

	res.type("text/html");
	res.charset = "utf-8";
	res.write(header(req));
	res.write(`
	<table>`
	);

	// sort files - based on lower case and with directories first
	all.sort((a,b) => {
		var aDir = !!(a.FileAttributes & 0x10);
		var bDir = !!(b.FileAttributes & 0x10);
		if(aDir && !bDir) return -1; 
		else if(bDir && !aDir) return 1;
		if(a.Filename.toLowerCase() < b.Filename.toLowerCase()) return -1; 
		else if(a.Filename.toLowerCase() > b.Filename.toLowerCase()) return 1; 
		else return 0;
	});

	for(var file of all) {
		// hide . and ..
		if(file.Filename == '.' || file.Filename == '..') 
			continue;
		
		// show directories
		if(file.FileAttributes & 0x10) {

			// check if hidden
			var hidden = file.Filename.startsWith(".") ? ' class="hidden"':'';

			// output entry
			res.write(`
		<tr${hidden}><td class="icon"><i class="fa fa-folder"></i></td><td class="name"><a href="${req.path + file.Filename}/">${escape(file.Filename)}</a></td><td class="size">[DIR]</td><td class="share"></td></tr>`
			);

		// and files
		} else {

			// find icon
			var icon = 'file'; for(var name in icons) for(var ext of icons[name]) if(file.Filename.toLowerCase().endsWith("." + ext)) icon = name;

			// find file size and make human readable
			var size = 0, factor = 1, unit = 'B';
			for(var i=0; i<file.EndofFile.length; i++) {
				size += (file.EndofFile[i] * factor); factor = factor * 256;
			}
			size = size / 1024; unit = 'KB'; 
			if(size > 1024) {size = size / 1024; unit = 'MB'; }
			if(size > 1024) {size = size / 1024; unit = 'GB'; }
			if(size > 1024) {size = size / 1024; unit = 'TB'; }
			size = Number.parseFloat(size).toFixed(2) + '&nbsp;' + unit;

			// check if hidden
			var hidden = file.Filename.startsWith(".") ? ' class="hidden"':'';

			// output entry
			res.write(`
		<tr${hidden}><td class="icon"><i class="far fa-${icon}"></i></td><td class="name"><a href="${req.path + file.Filename}">${escape(file.Filename)}</a></td><td class="size">${size}</td><td class="share"><a href="${req.path + file.Filename}?share" class="fas fa-link"> </a></td></tr>`
			);
		}
	}
	res.write(`
	</table>
	`);
	return res.end(footer());
}


// initialize server
app.listen(config.serverPort || 8080, () => {
	console.log('Server started.');
})
