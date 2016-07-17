var _ = require("underscore");
var Hashes = require("jshashes");
var compare = require("secure-compare");

var hashAlgoMask = btoa("\x01\x05");

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

function genSignedHeader(details) {
    domainValues = headerStringToObj(localStorage[getOrigin(details.url)]);
    return objToHeaderString(domainValues);
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
    // use the header string format for internal serialization
    localStorage[origin] = objToHeaderString(headerValues);
}

function invalidateSession(url, serverMac) {
    var origin = getOrigin(url);
    var originValues = headerStringToObj(localStorage[origin]);
    var hmacKey = originValues['Kh'];
    // TODO select hash module based on selected algo for origin
    var hmac = new Hashes.SHA256({'utf8': false});
    var ourMac = hmac.b64_hmac(hmacKey, "Session Expired");
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
