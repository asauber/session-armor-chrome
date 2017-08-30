"use strict";
/*
Session Armor Protocol, Google Chrome Extension

Copyright (C) 2016 Andrew Sauber

This software is licensed under the AGPLv3 open source license. See
LICENSE.txt. The license can also be found at the following URL, please note
the above copyright notice. https://www.gnu.org/licenses/agpl-3.0.en.html
*/

var _ = require("underscore");
var Hashes = require("jshashes");
var compare = require("secure-compare");

/* request related */

var hashAlgoMask = "\x01\x05";

var hashModules = [
    [1 << 0, new Hashes.SHA256({'utf8': false})],
//    [1 << 1, Hashes.SHA384],
    [1 << 2, new Hashes.SHA512({'utf8': false})],
    [1 << 3, new Hashes.RMD160({'utf8': false})]
]
hashModules = _.object(hashModules);

var bodyCache = {}

var headerChoices = [
    '', /* least-significant bit used for nonce flag */
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
    // Not using an arbitrary precision implementation of this for two reasons:
    // 1. Bitwise operators in JavaScript convert operands to 32-bit signed
    //    integers, unlike Python, which maintains arbitrary precision.
    // 2. If the input has it's MSB as 1, it's treated as negative number, and
    //    gets 1-filled on the right when shifted, resulting in "negative" byte
    //    values which are not amenable to string encoding.
    // Thus, this 0x00ff mask, which is used to kill the 1-filled bits of
    // parameters which happen to be negative when coerced.
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

function unpackMasks(headerValues) {
    if (headerValues.h) {
        headerValues.hashMask = unpackMask(headerValues.h)[0];
    }
    /*
    if (headerValues.ah) {
        headerValues.headerMask = unpackMask(headerValues.ah);
    }
    */
    return headerValues;
}

function headerStringToObj(str) {
    if (!str) return {};
    var pairs = str.split(';');
    var headerValues = {};
    _.each(pairs, function(pair) {
        pair = pair.split(':');
        headerValues[pair[0]] = atob(pair[1]);
    });
    headerValues = unpackMasks(headerValues);
    return headerValues;
}

function hmac(key, hashMask, string) {
    var macObj = hashModules[hashMask];
    return macObj.b64_hmac(key, string);
}

function headerValuesToAuth(headerMask, extraHeaders, requestHeaders) {
    var selectedHeaders = [];
    for (var i = 0, len = headerMask.length; i < len; ++i) {
        var currentByte = headerMask[len - 1 - i];
        for (var j = 0; j < 8; ++j) {
            if (currentByte & (1 << j)) {
                selectedHeaders.push(headerChoices[i * 8 + j]);
            }
        }
    }

    // Append the extra authenticated headers in their order
    selectedHeaders = selectedHeaders.concat(extraHeaders);

    // These need to be appended in the bitmask order
    var authHeaderValues = [];
    for (var header of selectedHeaders) {
        for (var reqHeader of requestHeaders) {
            if (header.toLowerCase() === reqHeader.name.toLowerCase()) {
                authHeaderValues.push(reqHeader.value);
            }
        }
    }

    return authHeaderValues;
}

function stringForAuth(nonce, requestTime, lastRequestTime, authHeaderValues,
                       path, body) {
    var macTokens = ['+', requestTime, lastRequestTime];
    /*
    if (nonce !== null) {
        macTokens.unshift(nonce);
    }
    macTokens = macTokens.concat(authHeaderValues);
    */
    macTokens = macTokens.concat(path);
    macTokens.push(body || '');
    return macTokens.join('|');
}

function genHeaderString(originValues, ourMac, requestTime, lastRequestTime,
                         nonce) {
    var requestValues = {}
    requestValues.c = ourMac;
    requestValues.t = requestTime;
    requestValues.lt = lastRequestTime;
    requestValues.s = originValues.s;
    requestValues.iv = originValues.iv;
    requestValues.tag = originValues.tag;
    requestValues.h = originValues.h;
    /*
    requestValues.ah = originValues.ah;
    if (originValues.eah) {
        requestValues.eah = originValues.eah;
    }
    if (nonce !== null) {
        requestValues.n = nonce;
    }
    */

    return objToHeaderString(requestValues);
}

function genSignedHeader(details) {
    var originValues = JSON.parse(localStorage[getOrigin(details.url)]);
    var hmacKey = originValues['kh'];

    /*
    if (usingNonceReplayPrevention(originValues.ah)) {
        var nonce = getNonce(details.url);
    }
    nonce = nonce ? setAndIncrementNonce(details.url, nonce) : null;
    */

    var requestTime = Math.floor(Date.now() / 1000);
    var lastRequestTime = localStorage[getOrigin(details.url) + '|lrt'];
    var path = getPath(details.url);
    var body = bodyCache[details.requestId];

    /* we use two seperate callbacks, so don't leak memory*/
    delete bodyCache[details.requestId];

    /*
    var authHeaderValues = headerValuesToAuth(originValues.headerMask,
                                          originValues.eah.split(','),
                                          details.requestHeaders);
    */
    var authString = stringForAuth(null, requestTime, lastRequestTime,
                                   null, path, body);
    var ourMac = hmac(hmacKey, originValues.hashMask, authString);
    ourMac = atob(ourMac);

    return genHeaderString(originValues, ourMac, requestTime, lastRequestTime,
                           null);
}

function genReadyHeader() {
    var headerValue = objToHeaderString({
        'r': hashAlgoMask
    });
    return headerValue;
}

function usingNonceReplayPrevention(headerMask) {
    var charCode = headerMask.charCodeAt(headerMask.length - 1);
    return !!(charCode & 0x01);
}

function getNonce(url) {
    var origin = getOrigin(url);
    var nonce = localStorage[origin + '|nonce'];
    return nonce ?
        bytesToInt(stringToBytes(nonce)) :
        null;
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

    /*
    if (usingNonceReplayPrevention(headerValues.ah)) {
        setNonce(url, bytesToInt(stringToBytes(headerValues['n'])));
    }
    */

    localStorage[origin] = JSON.stringify(headerValues);
}

function invalidateSession(url, serverMac) {
    var origin = getOrigin(url);
    var originValues = JSON.parse(localStorage[origin]);
    var hmacKey = originValues['kh'];
    var ourMac = hmac(hmacKey, originValues.hashMask, "Session Expired");
    serverMac = btoa(serverMac);
    if (!compare(serverMac, ourMac)) return;
    localStorage.removeItem(origin);
    localStorage.removeItem(origin + '|nonce');
    localStorage.removeItem(origin + '|lrt');
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
}

function beforeSendHeader(details) {
    var startTime = performance.now();
    details.requestHeaders.push({
        "name": "Host",
        "value": getHost(details.url)
    });
    var headerValue = 
        domainHasSession(details.url)
            ? genSignedHeader(details)
            : genReadyHeader();
    details.requestHeaders.push({
        "name": "X-S-Armor",
        "value": headerValue 
    });

    // Set "last request time" for this domain to now
    var lastRequestTimeKey = getOrigin(details.url) + '|lrt';
    localStorage[lastRequestTimeKey] = Math.floor(Date.now() / 1000);
    localStorage[getOrigin(details.url) + '|perfA'] = localStorage[getOrigin(details.url) + '|perfA'] + "," + (performance.now() - startTime);
    return {requestHeaders: details.requestHeaders};
}

/* body-related */

function extendedEncodeURIComponent(s) {
    return encodeURIComponent(s).replace(/[()'!]/g, function(c) {
        return '%' + c.charCodeAt(0).toString(16);
    });
}

function formDataToString(formData) {
    return _.map(Object.keys(formData), function(key) {
        // each key has an array of values
        return _.map(formData[key], function(value) {
            return key + '=' +
                   extendedEncodeURIComponent(value).replace(/%20/g, '+');
        }).join('&');
        // forms are encoded with key=value pairs joined with '&'
        // keys can be repeated
    }).join('&');
}

function beforeRequest(details) {
    var startTime = performance.now();

    /* Skip this step if this request does not have a related, active,
     * SessionArmor session, or does not have body data */
    if (!domainHasSession(details.url) || !details.requestBody) return;

    if (details.requestBody.error) {
        /* If Chrome has a problem parsing the request body,
         * log and continue. The request will fail on the server side. */
        console.log("request body error: " + details.requestBody.error);
    } else if (details.requestBody.raw) {
        /*
        Raw body authentication requires patching Chromium as follows. This
        forces Chrome to use the "raw" presenter for both the MIME type of
        multipart/form-data _and_ the MIME type of 
        application/x-www-form-urlencoded
        (as of 2016-08-24)

        diff --git
          a/extensions/browser/api/web_request/web_request_event_details.cc
          b/extensions/browser/api/web_request/web_request_event_details.cc
        index a9f2f83..835b0eb5 100644
        --- a/extensions/browser/api/web_request/web_request_event_details.cc
        +++ b/extensions/browser/api/web_request/web_request_event_details.cc
        @@ -84,7 +84,6
        @@ void WebRequestEventDetails::SetRequestBody(
               const net::URLRequest* request) {
             if (presenters[i]->Succeeded()) {
               request_body->Set(kKeys[i], presenters[i]->Result());
               some_succeeded = true;
        -      break;
             }
           }
        */
        bodyCache[details.requestId] = String.fromCharCode.apply(null,
                new Uint8Array(details.requestBody.raw[0].bytes));
    }

    localStorage[getOrigin(details.url) + '|perfB'] = localStorage[getOrigin(details.url) + '|perfB'] + "," + (performance.now() - startTime);
}

/* handle body data and store it for HMAC */
chrome.webRequest.onBeforeRequest.addListener(
    beforeRequest,
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "requestBody"]
);

/* prepare HMAC before requests */
chrome.webRequest.onBeforeSendHeaders.addListener(
    beforeSendHeader,
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "requestHeaders"]
);

/* handle Session initialization */
chrome.webRequest.onHeadersReceived.addListener(
    onHeaderReceived,
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "responseHeaders"]
);
