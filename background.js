chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        hashAlgoSupport = btoa("\x01\x01");
        xSessionArmorHeader = {
            "name": "X-S-Armor",
            "value": "r:" + hashAlgoSupport
        }
        details.requestHeaders.push(xSessionArmorHeader);
        return {requestHeaders: details.requestHeaders};
    },
    {"urls": ["https://*/*", "http://*/*"]},
    ["blocking", "requestHeaders"]
);
