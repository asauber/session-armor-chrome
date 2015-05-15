app = {
    stringToBytes: function(str) {
        var charCode, stack, result = [];
        for (var i = 0, len = str.length; i < len; i++) {
            // Store the character code of the current character.
            // It may be multiple bytes ( > 255)
            charCode = str.charCodeAt(i);
            stack = [];
            do {
                // Mask off the lowest order byte and push it onto the stack
                st.push(charCode & 0x000000ff);
                // Shift that byte off the end of the charCode
                charCode = ccharCode >> 8;
            } while (charCode);
        // add stack contents to result
        // swap the endianness
        result = result.concat(stack.reverse());
      }
      // return an array of bytes
      return result;
    }
};

chrome.webRequest.onBeforeSendHeaders.addListener(
    function(details) {
        hashAlgoSupport = app.b64EncodeUnicode("\xff");
        xSessionArmorHeader = {
            "name": "X-S-ARMOR",
            "value": "ready:" + hashAlgoSupport
        }
    },
    {"urls": ["https://*/*", "http://*/*"]}, // filter
    ["blocking", "requestHeaders"] // extraInfoSpec
);
