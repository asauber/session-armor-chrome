var _ = require("underscore");
var Hashes = require("jshashes");
var compare = require("secure-compare");

var hashAlgoMask = "\x01\x05";

var hashModules = [
    [1 << 0, Hashes.SHA256],
//    [1 << 1, Hashes.SHA384],
    [1 << 2, Hashes.SHA512],
    [1 << 3, Hashes.RMD160]
]
hashModules = _.object(hashModules);

var headerChoices = [
    'Host',
    'User-Agent',
    'Accept',
    'Connection',
    'Accept-Encoding',
    'Accept-Language',
    'Referer',
    'Cookie',
    'Accept-Charset',
    'If-Modified-Since',
    'If-None-Match',
    'Range',
    'Date',
    'Authorization',
    'Cache-Control',
    'Origin',
    'Pragma',
    'DNT',
    'X-Csrf-Token',
    'Sec-WebSocket-Version',
    'Sec-WebSocket-Protocol',
    'Sec-WebSocket-Key',
    'Sec-WebSocket-Extensions',
    'TE',
    'X-Requested-With',
    'X-Forwarded-For',
    'X-Forwarded-Proto',
    'Forwarded',
    'From',
    'HTTP2-Settings',
    'Upgrade',
    'Proxy-Authorization',
    'If',
    'If-Match',
    'If-Range',
    'If-Unmodified-Since',
    'Max-Forwards',
    'Prefer',
    'Via',
    'ALPN',
    'Expect',
    'Alt-Used',
    'CalDAV-Timezones',
    'Schedule-Reply',
    'If-Schedule-Tag-Match',
    'Destination',
    'Lock-Token',
    'Timeout',
    'Ordering-Type',
    'Overwrite',
    'Position',
    'Depth',
    'SLUG',
    'Trailer',
    'MIME-Version'
];

function getHost(url) {
    // capture everything up to the first lone slash
    // excluding the scheme and port
    return url.match(/(.+:\/\/)([^/:]+)(.*)?\/([^/]|$)/)[2];
}

function getOrigin(url) {
    // capture everything up to the first lone slash
    // including the scheme, host, and port
    return url.match(/(.+:\/\/[^/]+)\/([^/]|$)/)[1];
}

function getPath(url) {
    // capture everything after the first lone slash
    var path = url.match(/(.+:\/\/[^/]+)\/(.*|$)/)[2];
    return '/' + path;
}

function domainHasSession(url) {
    return localStorage[getOrigin(url)] !== undefined;
}

function unpackMask(mask) {
    return stringToBytes(mask.slice(1));
}

function stringToBytes(str) {
    var bytes = [], charCode;
    for (var i = 0, len = str.length; i < len; ++i) {
        charCode = str.charCodeAt(i);
        if ((charCode & 0xFF00) >> 8) {
            bytes.push((charCode & 0xFF00) >> 8);
        }
        bytes.push(charCode & 0xFF);
    }
    return bytes;
}

function bytesToInt(bytes) {
    var n = 0;
    for (var i = bytes.length - 1, len = bytes.length; i >= 0; --i) {
        n |= bytes[i] << (8 * (len - 1 - i));
    }
    return n;
}

function intToBytes(i) {
    return [
        (i >> 24 & 0x00ff),
        (i >> 16 & 0x00ff),
        (i >>  8 & 0x00ff),
        (i >>  0 & 0x00ff)
    ];
}

function bytesToString(bytes) {
    return String.fromCharCode.apply(this, bytes);
}

function objToHeaderString(obj) {
    return _.map(_.keys(obj), function (key) {
        return key + ':' + btoa(obj[key]);
    }).join(';');
}

function headerStringToObj(str) {
    if (!str) return {};
    var pairs = str.split(';');
    var headerValues = {};
    _.each(pairs, function(pair) {
        pair = pair.split(':');
        headerValues[pair[0]] = atob(pair[1]);
    });
    headerValues.hashMask = unpackMask(headerValues.h)[0];
    headerValues.headerMask = unpackMask(headerValues.ah);
    return headerValues;
}

function hmac(key, hashMask, string) {
    var macObj = new hashModules[hashMask]({'utf8': false});
    return macObj.b64_hmac(key, string);
}

function headerValuesToAuth(headerMask, extraHeaders, requestHeaders, url) {
    var selectedHeaders = [];
    for (var i = 0, len = headerMask.length; i < len; ++i) {
        var currentByte = headerMask[len - 1 - i];
        for (var j = 0; j < 8; ++j) {
            if (currentByte & (1 << j)) {
                selectedHeaders.push(headerChoices[i * 8 + j]);
            }
        }
    }

    // These need to be in bitmask order
    var authHeaderValues = [];
    for (var header of selectedHeaders) {
        for (var reqHeader of requestHeaders) {
            if (header === reqHeader.name) {
                authHeaderValues.push(reqHeader.value);
            }
        }
    }

    if (selectedHeaders[0] === "Host") {
        authHeaderValues.unshift(getHost(url));
    }

    return authHeaderValues;
}

function stringForAuth(nonce, expirationTime, authHeaderValues, path, body) {
    // Request expiration time is now + 4 minutes
    var macTokens = ['+', expirationTime];
    if (nonce !== null) {
        macTokens.unshift(nonce);
    }
    macTokens = macTokens.concat(authHeaderValues);
    macTokens = macTokens.concat(path);
    // TODO: auth request body
    macTokens.push(body || '');
    return macTokens.join('|');
}

function requestHeaderString(originValues, ourMac, expirationTime,
                             nonce) {
    var requestValues = {}
    requestValues.c = ourMac;
    requestValues.t = expirationTime;
    requestValues.s = originValues.s;
    requestValues.ctr = originValues.ctr;
    // TODO change mC to sm for 'server mac' for lowercase consistency
    requestValues.sm = originValues.mC
    requestValues.h = originValues.h;
    requestValues.ah = originValues.ah;
    if (originValues.eah) {
        requestValues.eah = originValues.eah;
    }
    if (nonce !== null) {
        requestValues.n = nonce;
    }

    return objToHeaderString(requestValues);
}

function genSignedHeader(details) {
    var originValues = JSON.parse(localStorage[getOrigin(details.url)]);
    var hmacKey = originValues['Kh'];

    // HMAC inputs

    // TODO: check 'ah' for MSB indicator
    var nonce = getNonce(details.url);
    nonce = nonce ? setAndIncrementNonce(details.url, nonce) : null;

    var expirationTime = Math.floor(Date.now() / 1000) + 60 * 4;
    var path = getPath(details.url);
    var body = ''; // details.body?
    var headerValues = headerValuesToAuth(originValues.headerMask, [],
                                          details.requestHeaders, details.url);
    var authString = stringForAuth(nonce, expirationTime,
                                   headerValues, path, body);
    var ourMac = hmac(hmacKey, originValues.hashMask, authString);
    ourMac = atob(ourMac);

    return requestHeaderString(originValues, ourMac, expirationTime, nonce);
}

function genReadyHeader() {
    var headerValue = objToHeaderString({
        'r': hashAlgoMask
    });
    return headerValue;
}

function getNonce(url) {
    var origin = getOrigin(url);
    return bytesToInt(stringToBytes(localStorage[origin + '|nonce']));
}

function setNonce(url, nonce) {
    var origin = getOrigin(url);
    nonce = bytesToString(intToBytes(nonce));
    localStorage[origin + '|nonce'] = nonce;
    return nonce;
}

function setAndIncrementNonce(url, nonce) {
    nonce++;
    return setNonce(url, nonce);
}

function storeNewSession(url, headerValues) {
    var origin = getOrigin(url);
    if (!origin.startsWith("https")) {
        console.log("Won't store SessionArmor session delivered insecurely.");
        return;
    }
    setNonce(url, bytesToInt(stringToBytes(headerValues['n'])));
    localStorage[origin] = JSON.stringify(headerValues);
}

function invalidateSession(url, serverMac) {
    var origin = getOrigin(url);
    var originValues = JSON.parse(localStorage[origin]);
    var hmacKey = originValues['Kh'];
    var ourMac = hmac(hmacKey, "Session Expired", originValues.hashMask);
    serverMac = btoa(serverMac);
    if (!compare(serverMac, ourMac)) return;
    localStorage.removeItem(origin);
}

function onHeaderReceived(details) {
    var headerValues = {};
    _.each(details.responseHeaders, function(header) {
        if (header.name !== "X-S-Armor") return;
        headerValues = headerStringToObj(header.value);
    });

    if (headerValues.hasOwnProperty('s')) {
        storeNewSession(details.url, headerValues);
    } else if (headerValues.hasOwnProperty('i')) {
        invalidateSession(details.url, headerValues['i']);
    }
    console.log(headerValues, details);
}

function beforeSendHeader(details) {
    var headerValue = 
        domainHasSession(details.url)
            ? genSignedHeader(details)
            : genReadyHeader();
    details.requestHeaders.push({
        "name": "X-S-Armor",
        "value": headerValue 
    });
    details.requestHeaders.push({
        "name": "Host",
        "value": getHost(details.url)
    });
    return {requestHeaders: details.requestHeaders};
}

chrome.webRequest.onBeforeSendHeaders.addListener(
    beforeSendHeader,
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "requestHeaders"]
);

chrome.webRequest.onHeadersReceived.addListener(
    onHeaderReceived,
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "responseHeaders"]
);
