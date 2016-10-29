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
    exports.CONTSTANTS = {
        ACCESS_TOKEN: 'access_token',
        EXPIRES_IN: 'expires_in',
        ID_TOKEN: 'id_token',
        AUTHORIZATION_CODE: 'code'
    };
    class TokenBroker {
        constructor(config) {
            this._baseConfig = config;
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
        getResourceStorageAccountNames(resourceId) {
            var names = {
                accessTokenAccount: this.getAccountName(exports.CONTSTANTS.ACCESS_TOKEN, resourceId),
                refreshTokenAccount: this.getAccountName(exports.CONTSTANTS.REFRESH_TOKEN, resourceId)
            };
            return names;
        }
        getToken(parameters) {
            return new Promise(function (resolve, reject) {
                var tokenNames = this.getResourceStorageAccountNames(parameters.resourceId);
                var accessToken = this.getTokenFromSecureStorage(this._config.appName, tokenNames.accessTokenAccount);
                var token = this.decodeJWT(accessToken);
                if (accessToken) {
                    if (this.isTokenExpiring(token)) {
                        var refreshToken = this.getTokenFromSecureStorage(this._config.appName, tokenNames.refreshTokenAccount);
                        if (refreshToken) {
                            this.renewToken(refreshToken).then(function (result) {
                                resolve(result);
                            }).catch(function (err) {
                                this.requestAuthorization(parameters.resourceId).then(function (result) {
                                    this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
                                    this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
                                    resolve(result.accessToken);
                                }).catch(function (err) { reject(null); });
                            });
                        }
                        else {
                            this.requestAuthorization(parameters.resourceId).then(function (result) {
                                this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
                                this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
                                resolve(result.accessToken);
                            }).catch(function (err) { reject(null); });
                        }
                    }
                    else {
                        resolve(accessToken);
                    }
                }
                else {
                    this.requestAuthorization(parameters.resourceId).then(function (result) {
                        this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
                        this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
                        resolve(result.accessToken);
                    }).catch(function (err) { reject(null); });
                }
            });
        }
        requestAuthorization(resourceId) {
            this._state = this.generateGuid();
            return new Promise(function (resolve, reject) {
                var url = this.getAuthorizationRequestUrl(resourceId);
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
        renewToken(refreshToken) {
            this._state = this.generateGuid();
            return new Promise(function (resolve, reject) {
            });
        }
        generateGuid() {
            if (this._baseConfig.crypto && this._baseConfig.crypto.getRandomValues) {
                var buffer = new Uint8Array(16);
                this._baseConfig.crypto.getRandomValues(buffer);
                buffer[6] |= 0x40;
                buffer[6] &= 0x4f;
                buffer[8] |= 0x80;
                buffer[8] &= 0xbf;
                return this.decimalToHex(buffer[0]) + this.decimalToHex(buffer[1]) + this.decimalToHex(buffer[2]) + this.decimalToHex(buffer[3]) + '-' + this.decimalToHex(buffer[4]) + this.decimalToHex(buffer[5]) + '-' + this.decimalToHex(buffer[6]) + this.decimalToHex(buffer[7]) + '-' +
                    this.decimalToHex(buffer[8]) + this.decimalToHex(buffer[9]) + '-' + this.decimalToHex(buffer[10]) + this.decimalToHex(buffer[11]) + this.decimalToHex(buffer[12]) + this.decimalToHex(buffer[13]) + this.decimalToHex(buffer[14]) + this.decimalToHex(buffer[15]);
            }
            else {
                var guidHolder = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx';
                var hex = '0123456789abcdef';
                var r = 0;
                var guidResponse = "";
                for (var i = 0; i < 36; i++) {
                    if (guidHolder[i] !== '-' && guidHolder[i] !== '4') {
                        r = Math.random() * 16 | 0;
                    }
                    if (guidHolder[i] === 'x') {
                        guidResponse += hex[r];
                    }
                    else if (guidHolder[i] === 'y') {
                        r &= 0x3;
                        r |= 0x8;
                        guidResponse += hex[r];
                    }
                    else {
                        guidResponse += guidHolder[i];
                    }
                }
                return guidResponse;
            }
        }
        ;
        decimalToHex(number) {
            var hex = number.toString(16);
            while (hex.length < 2) {
                hex = '0' + hex;
            }
            return hex;
        }
    }
    exports.TokenBroker = TokenBroker;
    class AADTokenBroker extends TokenBroker {
        constructor(config) {
            super(config);
            this._authority = 'https://login.microsoftonline.com/';
            this._config = config;
        }
        getAuthorizationRequestConfig(config) {
            var requestConfig = {
                url: "",
                headers: {}
            };
            requestConfig.url = this.getAuthorizationRequestUrl(config.tokenParameters.resourceId);
            return requestConfig;
        }
        getRefreshTokenRequestConfig(config) {
            var requestConfig = {
                url: "",
                headers: {}
            };
            return requestConfig;
        }
        getTokenRequestConfig(config) {
            var requestConfig = {
                url: "",
                headers: {}
            };
            return requestConfig;
        }
        getAuthorizationRequestUrl(resourceId) {
            var tenant = 'common';
            if (this._config.tenantId) {
                tenant = this._config.tenantId;
            }
            var urlNavigate = this._authority + tenant + '/oauth2/authorize' + this.serializeAuthRequest("code", this._config, resourceId);
            return urlNavigate;
        }
        getTokenRequestUrl() {
            var url;
            return url;
        }
        serializeAuthRequest(responseType, obj, resource) {
            var str = [];
            if (obj !== null) {
                str.push('?response_type=' + responseType);
                str.push('client_id=' + encodeURIComponent(obj.clientId));
                if (resource) {
                    str.push('resource=' + encodeURIComponent(resource));
                }
                str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
                str.push('state=' + encodeURIComponent(this._state));
            }
            return str.join('&');
        }
        ;
        serializeTokenRequest(responseType, obj, resource) {
            var str = [];
            if (obj !== null) {
                str.push('?response_type=' + responseType);
                str.push('client_id=' + encodeURIComponent(obj.clientId));
                if (resource) {
                    str.push('resource=' + encodeURIComponent(resource));
                }
                str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
                str.push('state=' + encodeURIComponent(this._state));
            }
            return str.join('&');
        }
        ;
    }
    exports.AADTokenBroker = AADTokenBroker;
});
//# sourceMappingURL=common.js.map