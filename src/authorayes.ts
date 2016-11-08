
import 'whatwg-fetch';

export enum InteractiveAuthorizationResultType {
	Success = 1,
	CancelledByUser,
	Timeout,
	NotAuthorized
}

export interface InterativeAuthorizationResult{
	result: InteractiveAuthorizationResultType;
	hash: string;
	details: string;
}

export interface InteractiveAuthorizationConfig{
	width?: number;
	height?: number;
	showDeveloperTools?: boolean;
	expectedRedirectUri: string;
}

export interface secureStorageGetPassword{
	(service:string, account:string): string;
}

export interface secureStorageAddPassword{
	(service:string, account:string, password:string):void;
}

export interface secureStorageDeletePassword{
	(service:string, account:string):void;
}

export interface secureStorageReplacePassword{
	(service:string, account:string, password:string):void;
}

export interface SecureStorage{
	getPassword: secureStorageGetPassword;
	addPassword: secureStorageAddPassword;
	deletePassword: secureStorageDeletePassword;
	replacePassword: secureStorageReplacePassword;
}

export abstract class InteractiveAuthorizationCommand {
	abstract execute(url:string, config:InteractiveAuthorizationConfig): Promise<any>;
}

/*
NOTE: For future consideration... allowing the code redemption to happen server side rather than client side...

- Basically support a satellizer like model in addition to the client side authorization code redemption.
*/
export abstract class redeemAuthorizationCommand {
	abstract execute(url:string, config:InteractiveAuthorizationConfig): Promise<any>;
}

export interface TokenBrokerConfig {
	clientId:string;
	redirectUri:string;
	interactiveAuthorizationCommand: InteractiveAuthorizationCommand;
	appName:string;
	storage?: Storage;
	secureStorage?: SecureStorage;
	crypto:Crypto;
}

export interface TokenParameters {
	resourceId?: string;
	scopes?:string[];
}

export interface DecodedToken {
	validated:boolean;
	header: string;
	claims: TokenClaims;
	JWSSig: string;
}

export interface TokenClaims {
	aud:string;
	iss:string;
	iat:number;
	nbf:number;
	exp:number;
	ver?:string;
	tid?:string;
	oid?:string;
	upn?:string;
	unique_name?:string;
	sub:string;
	family_name?:string;
	given_name?:string;

}

export interface ResourceAccountNames {
	accessTokenAccount:string;
	refreshTokenAccount:string;
}

export interface AuthorizationResult {
	accessToken:string;
	refreshToken:string;
	resourceId:string;
}

export interface AADTokenBrokerConfig extends TokenBrokerConfig {
	tenantId?:string;
	authority?:string;
}

export const CONTSTANTS:any = {
	ACCESS_TOKEN: 'access_token',
    EXPIRES_IN: 'expires_in',
    ID_TOKEN: 'id_token',
    AUTHORIZATION_CODE: 'code',
    REFRESH_TOKEN:'referesh_token'

}

export interface RequestConfig {
	url:string,
	headers: any,
	body?:string,
	baseUrl?:string
}

export interface RequestConfigParameters {
	tokenParameters?: TokenParameters,
	authorizationCode?: string,
	refreshToken?:string
}

export interface AuthorizationResponse {
	admin_consent?:boolean, //Crazy non-standard response for AAD Only... need to figure out correct model for these extras...
	code:string,
	session_state?:string, //Another extra for AAD Only...
	state:string,
	error?:string,
	error_description?:string,
	error_uri?:string
}



export interface TokenResponse{
	access_token?:string,
	token_type?:string,
	expires_in?:number,
	refresh_token?:string,
	scope?:string,
	error?:TokenRequestErrors,
	error_description?:string,
	error_uri?:string
}



export type TokenRequestErrors = "invalid_request" | "invalid_client" | "invalid_grant" | "unauthorized_client" | "unsupported_grant_type" | "invalid_scope"

//These are the values supported by the spec... need to extend for specific IDPs
export type AuthorizationRequestErrors = "unauthorized_client" | "access_denied" | "unsupported_response_type" | "invalid_scope" | "server_error" | "temporarily_unavailable"



export abstract class TokenBroker {

	constructor(config:TokenBrokerConfig){
		this._baseConfig = config;
	}

	protected _baseConfig: TokenBrokerConfig;
	protected _state: string;


	/*
	//Abstract Methods - Template Method Pattern 
	*/
	protected abstract getAuthorizationRequestConfig(config:RequestConfigParameters): RequestConfig;
	protected abstract getTokenRequestConfig(config:RequestConfigParameters):RequestConfig;
	protected abstract getRefreshTokenRequestConfig(config:RequestConfigParameters):RequestConfig;
	

	private decodeJWT(jwt:string) : DecodedToken{
		if (this.isEmpty(jwt)) {
            return null;
        };

        var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

        var matches = idTokenPartsRegex.exec(jwt);
        if (!matches || matches.length < 4) {
            return null;
        }

        var tokenPayload: string = matches[2];
        var claims:TokenClaims = JSON.parse(this.base64DecodeStringUrlSafe(tokenPayload))

        var crackedToken :DecodedToken = {
        	validated: false, //we're not doing signature validation...hence the token is not validated
            header: matches[1],
            claims: claims,
            JWSSig: matches[3]
        };

        return crackedToken;
	}

	private base64DecodeStringUrlSafe(base64IdToken:string) {
        // html5 should support atob function for decoding
        base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');
        if (window.atob) {
            return decodeURIComponent(encodeURI(window.atob(base64IdToken))); // jshint ignore:line
        }
        else {
            return decodeURIComponent(encodeURI(this.decode(base64IdToken)));
        }
    };

    private decode(base64IdToken:string):string {
        var codes = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=';
        base64IdToken = String(base64IdToken).replace(/=+$/, '');

        var length = base64IdToken.length;
        if (length % 4 === 1) {
            throw new Error('The token to be decoded is not correctly encoded.');
        }

        var h1:any;
        var h2:any; 
        var h3:any; 
        var h4:any;
        var bits:any; 
        var c1:any;
        var c2:any;
        var c3:any; 
        var decoded:string = '';
        for (var i = 0; i < length; i += 4) {
            //Every 4 base64 encoded character will be converted to 3 byte string, which is 24 bits
            // then 6 bits per base64 encoded character
            h1 = codes.indexOf(base64IdToken.charAt(i));
            h2 = codes.indexOf(base64IdToken.charAt(i + 1));
            h3 = codes.indexOf(base64IdToken.charAt(i + 2));
            h4 = codes.indexOf(base64IdToken.charAt(i + 3));

            // For padding, if last two are '='
            if (i + 2 === length - 1) {
                bits = h1 << 18 | h2 << 12 | h3 << 6;
                c1 = bits >> 16 & 255;
                c2 = bits >> 8 & 255;
                decoded += String.fromCharCode(c1, c2);
                break;
            }
                // if last one is '='
            else if (i + 1 === length - 1) {
                bits = h1 << 18 | h2 << 12
                c1 = bits >> 16 & 255;
                decoded += String.fromCharCode(c1);
                break;
            }

            bits = h1 << 18 | h2 << 12 | h3 << 6 | h4;

            // then convert to 3 byte chars
            c1 = bits >> 16 & 255;
            c2 = bits >> 8 & 255;
            c3 = bits & 255;

            decoded += String.fromCharCode(c1, c2, c3);
        }

        return decoded;
    };

	protected isEmpty(str:string):boolean{
		return (typeof str === 'undefined' || !str || 0 === str.length);
	}

	private getAccountName(tokenType:string, resourceId:string):string{
		return tokenType + "|" + resourceId;
	}

	private getTokenSecureStorage(service:string, account:string):string {
		if(this._baseConfig.secureStorage){
			return this._baseConfig.secureStorage.getPassword(service, account);
		}else{
			return null;
		}
	}

	private setTokenSecureStorage(service:string, account:string, password:string){
		if(this._baseConfig.secureStorage){
			this._baseConfig.secureStorage.addPassword(service, account, password);
		}
	}

	private isTokenExpiring(token: DecodedToken): boolean{
		var expiresDateTimeUTC:number = token.claims.exp;
		var now: number = Date.now() / 1000;
		var expiringWindow: number = 300; //5 minutes
		var timeRemaining: number = (expiresDateTimeUTC - now);

		console.log(now);
		console.log(expiresDateTimeUTC);
		console.log(timeRemaining);
		console.log(expiringWindow);


		return (timeRemaining < expiringWindow);
	}

	private getResourceStorageAccountNames (resourceId:string):ResourceAccountNames{
		var names: ResourceAccountNames = {
			accessTokenAccount: this.getAccountName(CONTSTANTS.ACCESS_TOKEN, resourceId),
			refreshTokenAccount: this.getAccountName(CONTSTANTS.REFRESH_TOKEN, resourceId)
		}

		return names;
	}

	getToken(parameters:TokenParameters):Promise<any>{
		
		var self : TokenBroker = this;
		var config: TokenBrokerConfig = this._baseConfig;

		return new Promise(function(resolve, reject){
			var tokenNames: ResourceAccountNames = self.getResourceStorageAccountNames(parameters.resourceId);
			var accessToken:string = self.getTokenSecureStorage(config.appName, tokenNames.accessTokenAccount);

			if(accessToken){
				var token:DecodedToken = self.decodeJWT(accessToken);
				if(self.isTokenExpiring(token)){
					//Need to renew the access Token and/or interactively request authorization
					console.log('access token is expiring...');
					var refreshToken:string = self.getTokenSecureStorage(config.appName, tokenNames.refreshTokenAccount);

					if(refreshToken){
						self.renewToken(parameters, refreshToken).then(function(tokenResponse:TokenResponse){
							self.setTokenSecureStorage(config.appName, tokenNames.accessTokenAccount, tokenResponse.access_token);
							self.setTokenSecureStorage(config.appName, tokenNames.refreshTokenAccount, tokenResponse.refresh_token);
							resolve(tokenResponse.access_token);
						}).catch(function(err:any){
							//TODO: Log Error
							//Need to interactively request authorization
							self.requestAuthorization(parameters,tokenNames, resolve, reject);
						});
					}else{
						//Need to interactively request authorization
						self.requestAuthorization(parameters,tokenNames, resolve, reject);
					}

				}else{
					//Access Token Still Good (As far as we know)
					resolve(accessToken);
				}
			}else{
				//Need to interactively request authorization
				self.requestAuthorization(parameters,tokenNames, resolve, reject);
				
			}
		});
	}

	private requestAuthorization(parameters:TokenParameters, tokenNames:ResourceAccountNames, resolve:any, reject:any) {

		
		var config: TokenBrokerConfig = this._baseConfig;
		var self : TokenBroker = this;

		this.requestInteractiveAuthorization(parameters.resourceId).then(function(result:AuthorizationResponse){
			var requestConfigParams : RequestConfigParameters = {
				tokenParameters: {
					resourceId: parameters.resourceId
				}
			};
			requestConfigParams.authorizationCode = result.code;
			self.exchangeAuthorizationCodeForToken(requestConfigParams).then(function(result:any){
				if(result.ok){
					result.json().then(function(tokenResponse:TokenResponse){
						//var tokenResponse: SuccessTokenResponse = json;
						self.setTokenSecureStorage(config.appName, tokenNames.accessTokenAccount, tokenResponse.access_token);
						self.setTokenSecureStorage(config.appName, tokenNames.refreshTokenAccount, tokenResponse.refresh_token);
						resolve(tokenResponse.access_token);
					});
				}else{
					result.json().then(function(tokenResponse:TokenResponse){
						//Deal with Error Response
						reject(tokenResponse);
					});
				}

			}).catch(function(err:any){
				throw err;
			})

			
		}).catch(function(err:any){reject(err);});

	}

	private requestInteractiveAuthorization(resourceId: string):Promise<any> {

		this._state = this.generateGuid();

		var self: TokenBroker = this;
		var config: InteractiveAuthorizationConfig = {
			height: 100,
			width: 100,
			showDeveloperTools: true,
			expectedRedirectUri: self._baseConfig.redirectUri
		};

		return new Promise(function(resolve, reject){

			var requestConfigParams : RequestConfigParameters = {
				tokenParameters: {
					resourceId: resourceId
				}
			};
			var requestConfig:RequestConfig = self.getAuthorizationRequestConfig(requestConfigParams);

			console.log(requestConfig.url);
			
			self._baseConfig.interactiveAuthorizationCommand.execute(requestConfig.url, config).then(function(result:any){
				console.log(result);
				var authResponse:AuthorizationResponse = self.parseAuthorizationResponse(result);
				self.validateAuthorizationResponse(authResponse);
				resolve(authResponse);
			}).catch(function(err:any){
				reject(err);
			});
		});
	}

	private exchangeAuthorizationCodeForToken(config:RequestConfigParameters):Promise<any> {
		var tokenRequestConfig: RequestConfig = this.getTokenRequestConfig(config);


		return fetch(tokenRequestConfig.baseUrl, {
			method:"POST",
			headers:{
				"Content-Type": "application/x-www-form-urlencoded"
			},
			body: tokenRequestConfig.body
		});

	}

	private validateAuthorizationResponse(authResponse:AuthorizationResponse){
		console.log(this._state);
		console.log(authResponse.state);
		if(this._state === authResponse.state)
			//TODO: Add code to check for error value againsta known set...
			return;
		else
			throw new Error("State mis-match in authorization response");

	}

	private parseAuthorizationResponse(urlResponse:string):AuthorizationResponse {
    	
		var params:any = this.parseQueryString(urlResponse);

		console.log(params);
    	var response:AuthorizationResponse = {
    		code: params["code"],
    		state: params["state"]
    	}

    	return response;
    }

    private parseQueryString(url: string):any{
    	var params: any = {};
    	var queries:string[];
    	var temp:string[];
    	var i:number;

    	var queryString:string = url.substring(url.indexOf('?') + 1);

    	queries = queryString.split('&');

    	for (var i = queries.length - 1; i >= 0; i--) {
    		temp = queries[i].split('=');
    		params[temp[0]] = temp[1];
    	}

    	return params;

    }

	private renewToken(parameters:TokenParameters, refreshToken:string):Promise<any> {

		this._state = this.generateGuid();

		var requestConfigParams : RequestConfigParameters = {
				tokenParameters: {
					resourceId: parameters.resourceId
				}
			};
			requestConfigParams.refreshToken = refreshToken;

		var tokenRequestConfig: RequestConfig = this.getRefreshTokenRequestConfig(requestConfigParams);

		return fetch(tokenRequestConfig.baseUrl, {
			method:"POST",
			headers:{
				"Content-Type": "application/x-www-form-urlencoded"
			},
			body: tokenRequestConfig.body
		});
	}

    
    private generateGuid (): string {
        
        if (this._baseConfig.crypto && this._baseConfig.crypto.getRandomValues) {
            var buffer = new Uint8Array(16);
            this._baseConfig.crypto.getRandomValues(buffer);
            //buffer[6] and buffer[7] represents the time_hi_and_version field. We will set the four most significant bits (4 through 7) of buffer[6] to represent decimal number 4 (UUID version number).
            buffer[6] |= 0x40; //buffer[6] | 01000000 will set the 6 bit to 1.
            buffer[6] &= 0x4f; //buffer[6] & 01001111 will set the 4, 5, and 7 bit to 0 such that bits 4-7 == 0100 = "4".
            //buffer[8] represents the clock_seq_hi_and_reserved field. We will set the two most significant bits (6 and 7) of the clock_seq_hi_and_reserved to zero and one, respectively.
            buffer[8] |= 0x80; //buffer[8] | 10000000 will set the 7 bit to 1.
            buffer[8] &= 0xbf; //buffer[8] & 10111111 will set the 6 bit to 0.
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
                    // each x and y needs to be random
                    r = Math.random() * 16 | 0;
                }
                if (guidHolder[i] === 'x') {
                    guidResponse += hex[r];
                } else if (guidHolder[i] === 'y') {
                    // clock-seq-and-reserved first hex is filtered and remaining hex values are random
                    r &= 0x3; // bit and with 0011 to set pos 2 to zero ?0??
                    r |= 0x8; // set pos 3 to 1 as 1???
                    guidResponse += hex[r];
                } else {
                    guidResponse += guidHolder[i];
                }
            }
            return guidResponse;
        }
    };

    private decimalToHex(number:number):string {
        var hex = number.toString(16);
        while (hex.length < 2) {
            hex = '0' + hex;
        }
        return hex;
    }
}


export class AADTokenBroker extends TokenBroker {

	protected _config: AADTokenBrokerConfig;
	protected _authority: string = 'https://login.microsoftonline.com/';


	constructor(config: AADTokenBrokerConfig){
		super(config);
		this._config = config;
	}

	protected getAuthorizationRequestConfig(config:RequestConfigParameters):RequestConfig{
		var requestConfig:RequestConfig = {
			url: "",
			headers: {}
		};

		requestConfig.url = this.getAuthorizationRequestUrl(config.tokenParameters.resourceId);

		return requestConfig;
	}

	protected getRefreshTokenRequestConfig(config:RequestConfigParameters):RequestConfig{
		var requestConfig:RequestConfig = {
			url: "",
			headers: {}
		};
		requestConfig.baseUrl = this.getTokenRequestBaseUrl(config.authorizationCode, config.tokenParameters.resourceId);
		requestConfig.body = this.serializeRefreshTokenRequest("refresh_token", config.refreshToken, this._config, config.tokenParameters.resourceId);
		return requestConfig;
	}

	protected getTokenRequestConfig(config:RequestConfigParameters):RequestConfig{
		var requestConfig:RequestConfig = {
			url: "",
			headers: {}
		};
		requestConfig.baseUrl = this.getTokenRequestBaseUrl(config.authorizationCode, config.tokenParameters.resourceId);
		requestConfig.body = this.serializeTokenRequest("authorization_code", config.authorizationCode, this._config, config.tokenParameters.resourceId);
		return requestConfig;
	}

	private getTokenRequestBaseUrl(code:string, resourceId:string):string{
		var tenant = 'common';
        if (this._config.tenantId) {
            tenant = this._config.tenantId;
        }

        var urlNavigate = this._authority + tenant + '/oauth2/token';
        return urlNavigate;
	}

	private getAuthorizationRequestUrl(resourceId:string):string{
		var tenant = 'common';
        if (this._config.tenantId) {
            tenant = this._config.tenantId;
        }

        var urlNavigate = this._authority + tenant + '/oauth2/authorize' + this.serializeAuthRequest("code", this._config, resourceId);
        return urlNavigate;
	}

	private serializeAuthRequest(responseType:string, obj:AADTokenBrokerConfig, resource:string) {
        var str:any = [];
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
    };

    /*
	Hmm... probably need to use different strategy for each flow type... need to think about design for that....
    */
    private serializeTokenRequest(grantType:string, code: string, obj:AADTokenBrokerConfig, resource:string) {
        var str:any = [];
        if (obj !== null) {
            str.push('grant_type=' + grantType);
            str.push('client_id=' + encodeURIComponent(obj.clientId));
            if (resource) {
                str.push('resource=' + encodeURIComponent(resource));
            }
            str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
            str.push('code=' + encodeURIComponent(code));
            str.push('state=' + encodeURIComponent(this._state));
        }

        return str.join('&');
    };

    private serializeRefreshTokenRequest(grantType:string, refreshToken: string, obj:AADTokenBrokerConfig, resource:string) {
        var str:any = [];
        if (obj !== null) {
            str.push('grant_type=' + grantType);
            str.push('client_id=' + encodeURIComponent(obj.clientId));
            if (resource) {
                str.push('resource=' + encodeURIComponent(resource));
            }
            str.push('redirect_uri=' + encodeURIComponent(obj.redirectUri));
            str.push('refresh_token=' + encodeURIComponent(refreshToken));
            str.push('state=' + encodeURIComponent(this._state));
        }

        return str.join('&');
    };





}

