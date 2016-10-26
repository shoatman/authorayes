
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

export interface AuthorizationContextConfig {
	clientId:string;
	redirectUri:string;
	interactiveAuthorizationCommand: interactiveAuthorizationCommand;
	appName:string;
	storage?: Storage;
	secureStorage?: SecureStorage;
}

export interface getTokenParameters {
	resourceId?: string;
	scopes?:string[];
}

export interface DecodedToken {
	validated:boolean;
	header: string;
	claims: any;
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

export abstract class AuthorizationContext {

	constructor(){}
	abstract getToken(parameters:getTokenParameters):Promise<any>;

	decodeJWT(jwt:string) : DecodedToken{
		if (this.isEmpty(jwt)) {
            return null;
        };

        var idTokenPartsRegex = /^([^\.\s]*)\.([^\.\s]+)\.([^\.\s]*)$/;

        var matches = idTokenPartsRegex.exec(jwt);
        if (!matches || matches.length < 4) {
            return null;
        }

        var tokenPayload: string = matches[2];
        var claims:any = JSON.parse(this.base64DecodeStringUrlSafe(tokenPayload))

        var crackedToken = {
        	validated: false, //we're not doing signature validation...hence the token is not validated
            header: matches[1],
            claims: claims,
            JWSSig: matches[3]
        };

        return crackedToken;
	}

	base64DecodeStringUrlSafe(base64IdToken:string) {
        // html5 should support atob function for decoding
        base64IdToken = base64IdToken.replace(/-/g, '+').replace(/_/g, '/');
        if (window.atob) {
            return decodeURIComponent(encodeURI(window.atob(base64IdToken))); // jshint ignore:line
        }
        else {
            return decodeURIComponent(encodeURI(this.decode(base64IdToken)));
        }
    };

    decode(base64IdToken:string):string {
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

	isEmpty(str:string):boolean{
		return (typeof str === 'undefined' || !str || 0 === str.length);
	}

	getAccountName(tokenType:string, resourceId:string):string{
		return tokenType + "|" + resourceId;
	}

	getTokenSecureStorage(storage:SecureStorage, service:string, account:string):string {

		if(storage){
			return storage.getPassword(service, account);
		}else{
			return null;
		}
		
	}

	setTokenSecureStorage(storage:SecureStorage, service:string, account:string, password:string){
		if(storage){
			storage.addPassword(service, account, password);
		}
	}
}

export interface AADAuthorizationContextConfig extends AuthorizationContextConfig {
	tenantId?:string;
	authority?:string;
}

export const CONTSTANTS:any = {
	ACCESS_TOKEN: 'access_token',
    EXPIRES_IN: 'expires_in',
    ID_TOKEN: 'id_token',
    AUTHORIZATION_CODE: 'code'
}

export class AADAuthorizationContext extends AuthorizationContext {

	private _config: AADAuthorizationContextConfig;
	private _state: string;
	private _authority: string = 'https://login.microsoftonline.com/';

	constructor(config: AADAuthorizationContextConfig){
		super();
		this._config = config;

	}

	getToken(parameters:getTokenParameters):Promise<any>{
		return new Promise(function(resolve, reject){
			var account:string = this.getAccountName(CONTSTANTS.ACCESS_TOKEN, parameters.resourceId);
			var accessToken:string = this.getTokenFromSecureStorage(this._config.appName, account);

			

			if(accessToken){
				resolve(accessToken);
			}else{

			}
		});
	}

	private requestAuthorization():Promise<any> {

		return new Promise(function(resolve, reject){
			var url:string; //Get Url to Navigate to for Authorization
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

	private getAuthorizationRequestUrl():string{
		var url:string;

		return url;
	}

	private getTokenRequestUrl():string {
		var url: string;

		return url;
	}


}

