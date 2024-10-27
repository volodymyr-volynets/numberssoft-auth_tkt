'use strict';

import ip_module from 'ip';
import pack from 'locutus/php/misc/pack.js';
import ip2long from 'locutus/php/network/ip2long.js';
import { Buffer as buffer } from 'buffer/index.js';
import { serialize, unserialize } from 'php-serialize';
import md5 from 'md5';
import { sprintf } from 'sprintf-js';
import { encode, decode } from 'urlencode';
import converter from 'hex2dec';

class AuthTkt {
	#options = {
		"token_key" : "",
		"base64": false,
		"check_ip": false,
		"valid_hours": 0
	};

	constructor() {
		
	}

	/**
	 * Set options
	 *
	 * @param {object} options 
	 */
	setOptions(options) {
		this.#options = Object.assign({}, this.#options, options);
	}

	/**
	 * Create token
	 *
	 * @param {int} id 
	 * @param {string} token 
	 * @param {mixed} data 
	 * @param {object} options 
	 * @returns {string}
	 */
	tokenCreate(id, token, data, options) {
		options = options || {};
		let time = options.hasOwnProperty('time') ? options['time'] : Math.floor(new Date().getTime() / 1000);
		let ip = options.hasOwnProperty('ip') ? options['ip'] : ip_module.address();
		let packed;
		if (!this.#options['check_ip']) {
			packed = pack('NN', 0, time);
		} else {
			packed = pack('NN', ip2long(ip), time);
		}
		if (data) {
			data = buffer.from(serialize(data)).toString('base64');
		} else {
			data = '';
		}
		let digest0 = md5(packed + this.#options['token_key'] + id + "\0" + token + "\0" + data);
		let digest = md5(digest0 + this.#options['token_key']);
		let result = sprintf('%s%08x%s!%s!%s', digest, time, id, token, data);
		if (this.#options['base64']) {
			return encode(buffer.from(result).toString('base64'));
		} else {
			return encode(result);
		}
	}

	/**
	 * Token validate
	 *
	 * @param {string} token 
	 * @param {object} options 
	 * @returns {bool|object}
	 */
	tokenValidate(token, options) {
		if (!token) {
			return false;
		}
		options = options || {};
		let result = {
			"id": null,
			"data": null,
			"time": null,
			"ip": ip_module.address()
		};
		let token_decoded;
		if (this.isBase64(token)) {
			token_decoded = buffer.from(token, 'base64');
		}  else {
			token_decoded = decode(token);
			if (this.isBase64(token_decoded)) {
				token_decoded = buffer.from(token_decoded, 'base64');
			}
		}
		result['time'] = converter.hexToDec(token_decoded.substring(32, 40));
		let temp = token_decoded.substring(40, token_decoded.length).split('!');
		result['id'] = temp[0] ?? 0;
		result['token'] = temp[1] ?? '';
		if (2 in temp && temp[2] !== '') {
			result['data'] = unserialize(buffer.from(temp[2], 'base64'));
		} else {
			result['data'] = null;
		}
		let rebuilt = this.tokenCreate(result['id'], result['token'], result['data'], {"time": result["time"], "ip": result['ip']});
		if (decode(rebuilt) != token) {
			return false;
		} else if ('skip_time_validation' in options && !options['skip_time_validation']) {
			// expiration
			if (this.#options['valid_hours'] > 0) {
				hours = (time() - result['time']) / 60 / 60;
				if (hours > this.#options['valid_hours']) {
					return false;
				}
			}
		}
		return result;
	}

	/**
	 * Is base64
	 *
	 * @param {string} token 
	 * @returns {bool}
	 */
	isBase64(token) {
		const decoded =  buffer.from(token, 'base64');
		if (buffer.from(decoded).toString('base64') === token) {
			return true;
		} else {
			return false;
		}
	}
}
export default AuthTkt;