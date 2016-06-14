/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};

/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {

/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId])
/******/ 			return installedModules[moduleId].exports;

/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			exports: {},
/******/ 			id: moduleId,
/******/ 			loaded: false
/******/ 		};

/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);

/******/ 		// Flag the module as loaded
/******/ 		module.loaded = true;

/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}


/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;

/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;

/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";

/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ function(module, exports) {

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




/***/ }
/******/ ]);