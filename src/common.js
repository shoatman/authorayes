(function (factory) {
    if (typeof module === 'object' && typeof module.exports === 'object') {
        var v = factory(require, exports); if (v !== undefined) module.exports = v;
    }
    else if (typeof define === 'function' && define.amd) {
        define(["require", "exports", 'bluebird'], factory);
    }
})(function (require, exports) {
    "use strict";
    const Promise = require('bluebird');
    (function (InteractiveAuthorizationResultType) {
        InteractiveAuthorizationResultType[InteractiveAuthorizationResultType["Success"] = 1] = "Success";
        InteractiveAuthorizationResultType[InteractiveAuthorizationResultType["CancelledByUser"] = 2] = "CancelledByUser";
        InteractiveAuthorizationResultType[InteractiveAuthorizationResultType["Timeout"] = 3] = "Timeout";
        InteractiveAuthorizationResultType[InteractiveAuthorizationResultType["NotAuthorized"] = 4] = "NotAuthorized";
    })(exports.InteractiveAuthorizationResultType || (exports.InteractiveAuthorizationResultType = {}));
    var InteractiveAuthorizationResultType = exports.InteractiveAuthorizationResultType;
    class interactiveAuthorizationCommand {
    }
    exports.interactiveAuthorizationCommand = interactiveAuthorizationCommand;
    class redeemAuthorizationCommand {
    }
    exports.redeemAuthorizationCommand = redeemAuthorizationCommand;
    class AuthorizationContext {
        constructor() {
        }
        decodeJWT(jwt) {
            if (this.isEmpty(jwt)) {
                return null;
            }
            ;
            var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;
            var matches = idTokenPartsRegex.exec(jwt);
            if (!matches || matches.length < 4) {
                return null;
            }
            var tokenPayload = matches[2];
            var claims = JSON.parse(this.base64DecodeStringUrlSafe(tokenPayload));
            var crackedToken = {
                validated: false,
                header: matches[1],
                claims: claims,
                JWSSig: matches[3]
            };
            return crackedToken;
        }
        base64DecodeStringUrlSafe(base64IdToken) {
            base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');
            if (window.atob) {
                return decodeURIComponent(encodeURI(window.atob(base64IdToken)));
            }
            else {
                return decodeURIComponent(encodeURI(this.decode(base64IdToken)));
            }
        }
        ;
        decode(base64IdToken) {
            var codes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
            base64IdToken = String(base64IdToken).replace(/=+$/, '');
            var length = base64IdToken.length;
            if (length % 4 === 1) {
                throw new Error('The token to be decoded is not correctly encoded.');
            }
            var h1;
            var h2;
            var h3;
            var h4;
            var bits;
            var c1;
            var c2;
            var c3;
            var decoded = '';
            for (var i = 0; i < length; i += 4) {
                h1 = codes.indexOf(base64IdToken.charAt(i));
                h2 = codes.indexOf(base64IdToken.charAt(i + 1));
                h3 = codes.indexOf(base64IdToken.charAt(i + 2));
                h4 = codes.indexOf(base64IdToken.charAt(i + 3));
                if (i + 2 === length - 1) {
                    bits = h1 << 18 | h2 << 12 | h3 << 6;
                    c1 = bits >> 16 & 255;
                    c2 = bits >> 8 & 255;
                    decoded += String.fromCharCode(c1, c2);
                    break;
                }
                else if (i + 1 === length - 1) {
                    bits = h1 << 18 | h2 << 12;
                    c1 = bits >> 16 & 255;
                    decoded += String.fromCharCode(c1);
                    break;
                }
                bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;
                c1 = bits >> 16 & 255;
                c2 = bits >> 8 & 255;
                c3 = bits & 255;
                decoded += String.fromCharCode(c1, c2, c3);
            }
            return decoded;
        }
        ;
        isEmpty(str) {
            return (typeof str === 'undefined' || !str || 0 === str.length);
        }
        getAccountName(tokenType, resourceId) {
            return tokenType + "|" + resourceId;
        }
        getTokenSecureStorage(storage, service, account) {
            if (storage) {
                return storage.getPassword(service, account);
            }
            else {
                return null;
            }
        }
        setTokenSecureStorage(storage, service, account, password) {
            if (storage) {
                storage.addPassword(service, account, password);
            }
        }
        isTokenExpiring(token) {
            var expiresDateTimeUTC = token.claims.exp;
            var now = 1000;
            var expiringWindow = 300;
            var timeRemaining = (expiresDateTimeUTC - now);
            return (timeRemaining > expiringWindow);
        }
    }
    exports.AuthorizationContext = AuthorizationContext;
    exports.CONTSTANTS = {
        ACCESS_TOKEN: 'access_token',
        EXPIRES_IN: 'expires_in',
        ID_TOKEN: 'id_token',
        AUTHORIZATION_CODE: 'code'
    };
    class AADAuthorizationContext extends AuthorizationContext {
        constructor(config) {
            super();
            this._authority = 'https://login.microsoftonline.com/';
            this._config = config;
        }
        getToken(parameters) {
            return new Promise(function (resolve, reject) {
                var account = this.getAccountName(exports.CONTSTANTS.ACCESS_TOKEN, parameters.resourceId);
                var accessToken = this.getTokenFromSecureStorage(this._config.appName, account);
                if (accessToken) {
                    if (this.isTokenExpiring(accessToken)) {
                    }
                    else {
                        resolve(accessToken);
                    }
                }
                else {
                }
            });
        }
        requestAuthorization() {
            return new Promise(function (resolve, reject) {
                var url;
                var config = {};
                config.height = 100;
                config.width = 100;
                config.showDeveloperTools = true;
                this._config.interactiveAuthorizationCommand.execute(url, config).then(function (result) {
                    var token;
                    resolve(token);
                }).catch(function (err) {
                    reject(err);
                });
            });
        }
        getAuthorizationRequestUrl() {
            var url;
            return url;
        }
        getTokenRequestUrl() {
            var url;
            return url;
        }
    }
    exports.AADAuthorizationContext = AADAuthorizationContext;
});
//# sourceMappingURL=common.js.map