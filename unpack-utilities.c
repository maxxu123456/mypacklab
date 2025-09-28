// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

uint64_t get64(uint8_t* beginning) {
  return ((u_int64_t)beginning[0])| 
  ((u_int64_t)beginning[1] << 8) | 
  ((u_int64_t)beginning[2] << 16)| 
  ((u_int64_t)beginning[3] << 24)| 
  ((u_int64_t)beginning[4] << 32)| 
  ((u_int64_t)beginning[5] << 40)| 
  ((u_int64_t)beginning[6] << 48)|
   ((u_int64_t)beginning[7] << 56);
}


void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {

  // TODO
  // Validate the header and set configurations based on it
  // Look at unpack-utilities.h to see what the fields of config are
  // Set the is_valid field of config to false if the header is invalid
  // or input_len (length of the input_data) is shorter than expected
  config->is_valid = false; // default to this before checking everything
  if (input_len < 20) {
    return; 
  }

  uint16_t magic = (input_data[0] << 8) | input_data[1];

  if (magic != 0x0213) {
    config->is_valid = false;
    return;
  }

  uint8_t version = input_data[2];

  if (version != 0x03) {
    config->is_valid = false;
    return;
  }

  uint8_t flags = input_data[3];

  // should be 20 with the flags. Check every time accessing input_data
  config->header_len = 20;

  config->is_compressed = (flags & (1 << 7))>0;
  config->is_encrypted = (flags & (1 << 6))>0;
  config->is_checksummed = (flags & (1 << 5))>0;
  config->should_continue = (flags & (1 << 4))>0;
  config->should_float = (flags & (1 << 3))>0;
  config->should_float3 = (flags & (1 << 2))>0;

  config->orig_data_size = get64(4 + input_data);
  config->data_size = get64(12 + input_data);

  

  // check for compression. if compressed, get the dictionary data. 
  if(config->is_compressed){
    config->header_len += 16;
    if (config->header_len > input_len) {
      return; 
    }
    memcpy(config->dictionary_data, &input_data[20], 16);
    
  }


  // is this right?
  if(config->is_checksummed){
    config->header_len += 2; 
    if (config->header_len > input_len) {
      return; 
    }
    uint8_t* ptr = input_data + config->header_len - 2;
    config->checksum_value = (u_int16_t)ptr[1] | ((u_int16_t)ptr[0] << 8); // big endian? Yes, it's big endian
  }

  config->is_valid = true; 
  
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {

  uint16_t checksum = 0;

  for (size_t i = 0; i < input_len; i++) {
    checksum = checksum + (uint16_t) input_data[i];
  }

  return checksum;
}

uint16_t lfsr_step(uint16_t oldstate) {

  // TODO
  // Calculate the new LFSR state given previous state
  // Return the new LFSR state

  uint16_t combined = oldstate  ^ (oldstate >> 6) ^ (oldstate >> 9) ^ (oldstate >> 13) & 0x1;

  return combined << 15 | oldstate >> 1;
}

void decrypt_data(uint8_t* input_data, size_t input_len,
                  uint8_t* output_data, size_t output_len,
                  uint16_t encryption_key) {

  // TODO
  // Decrypt input_data and write result to output_data
  // Uses lfsr_step() to calculate psuedorandom numbers, initialized with encryption_key
  // Step the LFSR once before encrypting data
  // Apply psuedorandom number with an XOR in little-endian order
  // Beware: input_data may be an odd number of bytes

  uint16_t curr_state = encryption_key;

  size_t i = 0;

  for (i = 0; i < input_len -1; i+=2) {
    curr_state = lfsr_step(curr_state);
    uint8_t first_byte = curr_state >> 8;
    uint8_t second_byte = curr_state & 0xFF;
    
    output_data[i] = input_data[i] ^ second_byte;
    output_data[i+1] = input_data[i+1] ^ first_byte;

  }
  if (i < input_len) {
    i++;
    curr_state = lfsr_step(curr_state);
    uint8_t least_sig = curr_state & 0xFF;
    output_data[i] = input_data[i] ^ least_sig;

  }

}

size_t decompress_data(uint8_t* input_data, size_t input_len,
                       uint8_t* output_data, size_t output_len,
                       uint8_t* dictionary_data) {

  // TODO
  // Decompress input_data and write result to output_data
  // Return the length of the decompressed data

  uint8_t output_index = 0;

  for(uint8_t input_index = 0; input_index < input_len; input_index++) {
    u_int8_t byte = input_data[input_index];

    if (byte != 0x07) {
      // Regular character
      if(output_index < output_len) {
        output_data[output_index] = 0x07;
        output_index++;
      }
    } else {
      //is escape acharacter

      if(input_index == input_len-1) {
        //last character
        output_data[output_index] = 0x07;
        output_index++;
      } else {
        //not the last chacter
        input_index++;
        uint8_t info = input_data[input_index];

        if (info == 0x00) {
          //literal escape achacter
          output_data[output_index] = 0x07;
          output_index ++;
        } else {
          //no tliteral escape character = main case where char repats
          uint8_t repeat = (info >> 4) &0x0F;
          uint8_t dic_index = info &0x0F;
          uint8_t character = dictionary_data[dic_index];

          for (uint8_t j = 0; j < repeat; j++) {
            if(output_index < output_len) {
              output_data[output_index] = character;
            }
          }
        }
      }

    }

  }


}

void join_float_array(uint8_t* input_signfrac, size_t input_len_bytes_signfrac,
                      uint8_t* input_exp, size_t input_len_bytes_exp,
                      uint8_t* output_data, size_t output_len_bytes) {

  // TODO
  // Combine two streams of bytes, one with signfrac data and one with exp data,
  // into one output stream of floating point data
  // Output bytes are in little-endian order

}
/* End of mandatory implementation. */

/* Extra credit */
void join_float_array_three_stream(uint8_t* input_frac,
                                   size_t   input_len_bytes_frac,
                                   uint8_t* input_exp,
                                   size_t   input_len_bytes_exp,
                                   uint8_t* input_sign,
                                   size_t   input_len_bytes_sign,
                                   uint8_t* output_data,
                                   size_t   output_len_bytes) {

  // TODO
  // Combine three streams of bytes, one with frac data, one with exp data,
  // and one with sign data, into one output stream of floating point data
  // Output bytes are in little-endian order

}

