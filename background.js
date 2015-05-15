chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        var encodedOkWoman = utf8.encode("🙆");
        console.log("encodedOkWoman: " + encodedOkWoman);
        var base64EncodedOkWoman = btoa(encodedOkWoman);
        console.log("base64EncodedOkWoman: " + base64EncodedOkWoman);
        var base64DecodedOkWoman = atob(base64EncodedOkWoman);
        console.log("base64DecodedOkWoman: " + base64DecodedOkWoman);
        var decodedOkWoman = utf8.decode(base64DecodedOkWoman);
        console.log("decodedOkWoman: " + decodedOkWoman);
        
        hashAlgoSupport = btoa("\xff");
        xSessionArmorHeader = {
            "name": "X-S-ARMOR",
            "value": "ready:" + hashAlgoSupport
        }
        console.log("xSessionArmorHeader: " + xSessionArmorHeader);
    },
    {"urls": ["https://*/*", "http://*/*"]}, // filter
    ["blocking", "requestHeaders"] // extraInfoSpec
);
