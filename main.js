re

var hashAlgoMask = btoa("\x01\x05");

function origin(url) {
    // capture everything up to the first lone slash
    // this includes the scheme, host, and port
    return url.match(/(.+[^/])\/([^/]|$)/)[1];
}

function domainHasSession(url) {
    return localStorage[origin(url)] !== undefined;
};

function objToHeaderString(obj) {
    
}

function genSignedHeader(details) {
    return "";
};

function genReadyHeader(details) {
    return ;
};

chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        var headerValue = domainHasSession(details.url) ? 
            genSignedHeader(details) :
            genReadyHeader(details);
        details.requestHeaders.push({
            "name": "X-S-Armor",
            "value": headerValue 
        });
        return {requestHeaders: details.requestHeaders};
    },
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "requestHeaders"]
);


