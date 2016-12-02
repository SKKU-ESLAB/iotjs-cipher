/* Copyright 2016 Gyeonghwan Hong <redcarrottt@gmail.com> All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var assert = require('assert');
var cipher = require('cipher');

// Key
var key_str = "0123456789012345"
var key = new Buffer(16);
key.write(key_str);

// Encrypt input
var encrypt_input_str = "Hello World!!!!!";
var encrypt_input = new Buffer(16);
encrypt_input.write(encrypt_input_str);

// Encrypt output
var encrypt_output = cipher.encrypt(encrypt_input, key);

// Encrypt output -> Decrypt input
var decrypt_input = encrypt_output;

// Decrypt output
var decrypt_output = cipher.decrypt(decrypt_input, key);
var decrypt_output_str = decrypt_output.toString();

assert.equal(encrypt_input_str, decrypt_output_str);
