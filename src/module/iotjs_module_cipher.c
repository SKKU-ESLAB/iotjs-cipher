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

#include "iotjs_def.h"
#include "iotjs_module_buffer.h"

JHANDLER_FUNCTION(Encrypt) {
  JHANDLER_CHECK_ARGS(2, object, object);

  // 1st argument: input (Buffer object)
  const iotjs_jval_t* input = JHANDLER_GET_ARG(0, object);
  iotjs_bufferwrap_t* input_buffer_wrap = iotjs_bufferwrap_from_jbuffer(input);
  uint8_t* input_array = (uint8_t*)iotjs_bufferwrap_buffer(input_buffer_wrap);

  // 2nd arguement: key (Buffer object)
  const iotjs_jval_t* key = JHANDLER_GET_ARG(1, object);
  iotjs_bufferwrap_t* key_buffer_wrap = iotjs_bufferwrap_from_jbuffer(key);
  uint8_t* key_array = (uint8_t*)iotjs_bufferwrap_buffer(key_buffer_wrap);

  // Return value: output (Buffer object)
  iotjs_jval_t output_jbuffer = iotjs_bufferwrap_create_buffer(input_length);
  iotjs_bufferwrap_t* output_buffer_wrap =
      iotjs_bufferwrap_from_jbuffer(&output_jbuffer);
  uint8_t* output_array = (uint8_t*)iotjs_bufferwrap_buffer(output_buffer_wrap);

  // TODO: Encrypt Logic

  // Return output!
  iotjs_jhandler_return_jval(jhandler, &output_jbuffer);
  iotjs_jval_destroy(&output_jbuffer);
}

JHANDLER_FUNCTION(Decrypt) {
  JHANDLER_CHECK_ARGS(2, object, object);

  // 1st argument: input (Buffer object)
  const iotjs_jval_t* input = JHANDLER_GET_ARG(0, object);
  iotjs_bufferwrap_t* input_buffer_wrap = iotjs_bufferwrap_from_jbuffer(input);
  uint8_t* input_array = (uint8_t*)iotjs_bufferwrap_buffer(input_buffer_wrap);

  // 2nd arguement: key (Buffer object)
  const iotjs_jval_t* key = JHANDLER_GET_ARG(1, object);
  iotjs_bufferwrap_t* key_buffer_wrap = iotjs_bufferwrap_from_jbuffer(key);
  uint8_t* key_array = (uint8_t*)iotjs_bufferwrap_buffer(key_buffer_wrap);

  // Return value: output (Buffer object)
  iotjs_jval_t output_jbuffer = iotjs_bufferwrap_create_buffer(input_length);
  iotjs_bufferwrap_t* output_buffer_wrap =
      iotjs_bufferwrap_from_jbuffer(&output_jbuffer);
  uint8_t* output_array = (uint8_t*)iotjs_bufferwrap_buffer(output_buffer_wrap);

  // TODO: Decrypt Logic

  // Return output!
  iotjs_jhandler_return_jval(jhandler, &output_jbuffer);
  iotjs_jval_destroy(&output_jbuffer);
}

iotjs_jval_t InitCipher() {
  iotjs_jval_t cipher = iotjs_jval_create_object();

  iotjs_jval_set_method(&cipher, "encrypt", Encrypt);
  iotjs_jval_set_method(&cipher, "decrypt", Decrypt);

  return cipher;
}
