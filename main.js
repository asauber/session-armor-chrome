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

function getOrigin(url) {
    // capture everything up to the first lone slash
    // including the scheme, host, and port
    return url.match(/(.+\/\/[^/]+)\/([^/]|$)/)[1];
}

function domainHasSession(url) {
    return localStorage[getOrigin(url)] !== undefined;
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
    return headerValues;
}

function hmac(key, string, hashMask) {
    var macObj = new hashModules[hashMask]({'utf8': false});
    return macObj.b64_hmac(key, string);
}

function genSignedHeader(details) {
    var originValues = JSON.parse(localStorage[getOrigin(details.url)]);
    var hmacKey = originValues['Kh'];
    delete originValues['Kh'];

    // hmac headers
    var flatRequestHeaders = JSON.stringify(details.requestHeaders);
    var ourMac = hmac(hmacKey, flatRequestHeaders, originValues['h']);

    // add mac to request header


    return objToHeaderString(originValues);
}

function genReadyHeader() {
    var headerValue = objToHeaderString({
        'r': hashAlgoMask
    });
    return headerValue;
}

function storeNewSession(url, headerValues) {
    var origin = getOrigin(url);
    if (!origin.startsWith("https")) {
        console.log("Won't store SessionArmor session delivered insecurely.");
        return;
    }
    localStorage[origin] = JSON.stringify(headerValues);
}

function invalidateSession(url, serverMac) {
    var origin = getOrigin(url);
    var originValues = JSON.parse(localStorage[origin]);
    var hmacKey = originValues['Kh'];
    var ourMac = hmac(hmacKey, "Session Expired", originValues['h']);
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
