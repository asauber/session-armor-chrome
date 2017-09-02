/*
 * Sets the state of the extension icon to reflect the state of SessionArmor
 */

function getOrigin(url) {
    // capture everything up to the first lone slash
    // including the scheme, host, and port
    return url.match(/(.+:\/\/[^/]+)\/([^/]|$)/)[1];
}

function domainHasSession(url) {
    return localStorage[getOrigin(url)] !== undefined;
}

function newActiveUrl(url) {
    if (url && domainHasSession(url)) {
        chrome.browserAction.setIcon({
            path: "icon-big-green.png"
        });
    } else {
        chrome.browserAction.setIcon({
            path: "icon-big-red.png"
        });
    }
}

function tabUpdated(tabId, changeInfo, tab) {
    if (tab.active) {
        newActiveUrl(tab.url);
    }
}

function tabActivated(activeInfo) {
    chrome.tabs.get(activeInfo.tabId, function(tab) {
        if (tab.active) {
            newActiveUrl(tab.url);
        }
    });
}

/* handle status icon changes */
chrome.tabs.onActivated.addListener(tabActivated);

chrome.tabs.onUpdated.addListener(tabUpdated);
