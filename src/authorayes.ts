
import * as Promise from 'bluebird';

export enum InteractiveAuthorizationResultType {
	Success = 1,
	CancelledByUser,
	Timeout,
	NotAuthorized
}

export interface interativeAuthorizationResult{
	result: InteractiveAuthorizationResultType;
	hash: string;
	details: string;
}

export interface interactiveAuthorizationConfig{
	width?: number;
	height?: number;
	showDeveloperTools?: boolean;
}

export interface interactiveAuthorizationExecute{
	(url:string, interactiveAuthorizationConfig:any): Promise<any>;
}

export interface interactiveAuthorizationExecute{
	(url:string, interactiveAuthorizationConfig:any): Promise<any>;
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

export abstract class interactiveAuthorizationCommand {
	execute: interactiveAuthorizationExecute;
}

/*
NOTE: For future consideration... allowing the code redemption to happen server side rather than client side...

- Basically support a satellizer like model in addition to the client side authorization code redemption.
*/
export abstract class redeemAuthorizationCommand {
	execute: interactiveAuthorizationExecute;
}

export interface TokenBrokerConfig {
	clientId:string;
	redirectUri:string;
	interactiveAuthorizationCommand: interactiveAuthorizationCommand;
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
    AUTHORIZATION_CODE: 'code'
}

export interface RequestConfig {
	url:string,
	headers: any
}

export interface RequestConfigParameters {
	tokenParameters?: TokenParameters,
	authorizationCode?: string,
	refreshToken?:string
}

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

	private getTokenSecureStorage(storage:SecureStorage, service:string, account:string):string {

		if(storage){
			return storage.getPassword(service, account);
		}else{
			return null;
		}
		
	}

	private setTokenSecureStorage(storage:SecureStorage, service:string, account:string, password:string){
		if(storage){
			storage.addPassword(service, account, password);
		}
	}

	private isTokenExpiring(token: DecodedToken): boolean{
		var expiresDateTimeUTC:number = token.claims.exp;
		var now: number = 1000;//(new Date()).UTC;
		var expiringWindow: number = 300; //5 minutes
		var timeRemaining: number = (expiresDateTimeUTC - now);

		return (timeRemaining > expiringWindow);
	}

	private getResourceStorageAccountNames (resourceId:string):ResourceAccountNames{
		var names: ResourceAccountNames = {
			accessTokenAccount: this.getAccountName(CONTSTANTS.ACCESS_TOKEN, resourceId),
			refreshTokenAccount: this.getAccountName(CONTSTANTS.REFRESH_TOKEN, resourceId)
		}

		return names;
	}

	getToken(parameters:TokenParameters):Promise<any>{
		return new Promise(function(resolve, reject){
			var tokenNames: ResourceAccountNames = this.getResourceStorageAccountNames(parameters.resourceId);
			var accessToken:string = this.getTokenFromSecureStorage(this._config.appName, tokenNames.accessTokenAccount);
			var token:DecodedToken = this.decodeJWT(accessToken);

			if(accessToken){
				if(this.isTokenExpiring(token)){
					//Need to renew the access Token and/or interactively request authorization
					var refreshToken:string = this.getTokenFromSecureStorage(this._config.appName, tokenNames.refreshTokenAccount);

					if(refreshToken){
						this.renewToken(refreshToken).then(function(result:string){
							resolve(result);
						}).catch(function(err:any){
							//TODO: Log Error
							//Need to interactively request authorization
							this.requestAuthorization(parameters.resourceId).then(function(result:AuthorizationResult){
								this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
								this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
								resolve(result.accessToken);
							}).catch(function(err:any){reject(null);});
						});
					}else{
						//Need to interactively request authorization
						this.requestAuthorization(parameters.resourceId).then(function(result:AuthorizationResult){
							this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
							this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
							resolve(result.accessToken);
						}).catch(function(err:any){reject(null);});
					}

				}else{
					//Access Token Still Good (As far as we know)
					resolve(accessToken);
				}
			}else{
				//Need to interactively request authorization
				this.requestAuthorization(parameters.resourceId).then(function(result:AuthorizationResult){
					this.setTokenSecureStorage(this._config.appName, tokenNames.accessTokenAccount, result.accessToken);
					this.setTokenSecureStorage(this._config.appName, tokenNames.refreshTokenAccount, result.refreshToken);
					resolve(result.accessToken);
				}).catch(function(err:any){reject(null);});
			}
		});
	}

	private requestAuthorization(resourceId: string):Promise<any> {

		this._state = this.generateGuid();

		return new Promise(function(resolve, reject){
			var url:string = this.getAuthorizationRequestUrl(resourceId);
			var config: interactiveAuthorizationConfig = {}; 
			config.height = 100;
			config.width = 100;
			config.showDeveloperTools = true;
			this._config.interactiveAuthorizationCommand.execute(url, config).then(function(result:any){
				//Exchange Code For Token
				var token:string;
				resolve(token);
			}).catch(function(err:any){
				reject(err);
			});
		});
	}

	private renewToken(refreshToken:string):Promise<any> {

		this._state = this.generateGuid();

		return new Promise(function(resolve, reject){

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
		return requestConfig;
	}

	protected getTokenRequestConfig(config:RequestConfigParameters):RequestConfig{
		var requestConfig:RequestConfig = {
			url: "",
			headers: {}
		};
		return requestConfig;
	}

	private getAuthorizationRequestUrl(resourceId:string):string{
		var tenant = 'common';
        if (this._config.tenantId) {
            tenant = this._config.tenantId;
        }

        var urlNavigate = this._authority + tenant + '/oauth2/authorize' + this.serializeAuthRequest("code", this._config, resourceId);
        return urlNavigate;
	}

	private getTokenRequestUrl():string {
		var url: string;

		return url;
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

    private serializeTokenRequest(responseType:string, obj:AADTokenBrokerConfig, resource:string) {
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


}

