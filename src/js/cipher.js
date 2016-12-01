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

// Cipher module: module to encrypt or decrypt a message with AES-128 ECB

var util = require('util');
var cipherBuiltin = process.binding(process.binding.cipher);

function Cipher() {
}

// cipher.encrypt()
// * input - input message buffer to be encrypted
// * key - key bits buffer
// return value - encrypted output message buffer
Cipher.prototype.encrypt = function(input, key) {
  if(!util.isBuffer(input)) {
    throw new TypeError("Bad arguments: cipher.encrypt([buffer], [buffer])");
  }
  if(!util.isBuffer(key)) {
    throw new TypeError("Bad arguments: cipher.encrypt([buffer], [buffer])");
  }
  if(input.length != 16) {
    throw new RangeError("Bad arguments: input's length should be 16Bytes."
        + " Given input is " + input.length + "Bytes.");
  }
  if(key.length != 16) {
    throw new RangeError("Bad arguments: key's length should be 16Bytes."
        + " Given key is " + key.length + "Bytes.");
  }

  return cipherBuiltin.encrypt(input, key);
};

// cipher.decrypt()
// * input - encrypted input message buffer
// * key - key bits buffer
// return value - decrypted output message buffer
Cipher.prototype.decrypt = function(input, key) {
  if(!util.isBuffer(input)) {
    throw new TypeError("Bad arguments: cipher.encrypt([buffer], [buffer])");
  }
  if(!util.isBuffer(key)) {
    throw new TypeError("Bad arguments: cipher.encrypt([buffer], [buffer])");
  }
  if(input.length != 16) {
    throw new RangeError("Bad arguments: input's length should be 16Bytes."
        + " Given input is " + input.length + "Bytes.");
  }
  if(key.length != 16) {
    throw new RangeError("Bad arguments: key's length should be 16Bytes."
        + " Given key is " + key.length + "Bytes.");
  }

  return cipherBuiltin.decrypt(input, key);
};

module.exports = new Cipher();
