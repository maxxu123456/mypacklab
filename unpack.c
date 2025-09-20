// Application to unpack files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "unpack-utilities.h"


#define MAX_STREAMS 16
#define ROUNDUP_ALIGN(N, A) ((A)*(((N) / (A)) + (!!((N) % (A)))))


static int analyze_streams(uint8_t* buf, uint64_t len, uint64_t* nums, uint64_t* offsets, uint64_t* orig_sizes,
                           uint64_t* stored_sizes) {
  uint64_t curoff = 0;
  packlab_config_t config;

  uint64_t maxnums = *nums;
  for (uint64_t i = 0; i < maxnums; i++) {
    memset(&config, 0, sizeof(config));
    parse_header(buf, len, &config);
    if (!config.is_valid) {
      fprintf(stderr, "header %lu is not valid\n", i);
      return -1;
    }

    orig_sizes[i]   = config.orig_data_size;
    stored_sizes[i] = config.data_size;
    offsets[i]      = curoff;

    if (!config.should_continue) {
      *nums = i + 1;

      // check for the specific cases we will support
      if (*nums == 1) {
        // generic raw format, anything goes
        return 0;
      } else if (*nums == 2) {
        // must be the 2 stream float format
        if (config.should_float && !config.should_float3) {
          return 0;
        } else {
          fprintf(stderr, "2 stream file, but not valid FP\n");
          return -1;
        }
      } else if (*nums == 3) {
        // must be the 3 stream float format
        if (config.should_float && config.should_float3) {
          return 0;
        } else {
          fprintf(stderr, "3 stream file, but not valid FP\n");
          return -1;
        }
      } else {
        fprintf(stderr, "number of streams is not 1, 2 (FP), or 3 (FP3)\n");
        return -1;
      }
    }

    if (!config.should_float) {
      fprintf(stderr, "continuation outside of float is currently unsupported\n");
      return -1;
    }

    uint64_t oldoff = curoff;

    // skip to data
    curoff = ROUNDUP_ALIGN(curoff + config.header_len, DATA_ALIGN);
    // skip to next header
    curoff = ROUNDUP_ALIGN(curoff + config.data_size, HEADER_ALIGN);
    // advance buffer to match, which should land us in the next header
    buf += (curoff - oldoff);

    if (curoff >= len) {
      fprintf(stderr, "continuation extends past end of buffer/file...\n");
      return -1;
    }
  }

  // ran out of room to put streams
  fprintf(stderr, "too many streams in file...\n");
  return -1;
}

int main(int argc, char* argv[]) {
  // Parse app flags
  // No flags for unpack, just input and output filenames
  if (argc != 3) {
    printf("usage: %s inputfilename outputfilename\n", argv[0]);
    error_and_exit("\n");
  }
  char* input_filename  = argv[1];
  char* output_filename = argv[2];

  // Validate input data
  if (strcmp(input_filename, output_filename) == 0) {
    // This check is for safety to make sure we don't overwrite a file
    error_and_exit("ERROR: input and output filename match\n");
  }

  // Open input file
  FILE* input_fd = fopen(input_filename, "r");
  if (input_fd == NULL) {
    error_and_exit("ERROR: input file likely does not exist\n");
  }

  // Determine size of input file
  struct stat st;
  int result = stat(input_filename, &st);
  if (result != 0) {
    error_and_exit("ERROR: input file likely does not exist\n");
  }
  size_t raw_len = st.st_size;

  // Read entire input file contents
  uint8_t* raw_data = malloc_and_check(raw_len);
  size_t read_len   = fread(raw_data, sizeof(uint8_t), raw_len, input_fd);
  if (read_len != raw_len) {
    error_and_exit("ERROR: fread failed on input\n");
  }
  fclose(input_fd);

  // Now find the streams to prepare for student
  // processing.   The only supported formats here
  // are
  //    normal - single stream
  //    f2     - 2 streams, floats, with 8 bit exponent stream and 24 bit sign+mantissa
  //    f3     - 3 streams, floats, with 8 bit exponent stream, 23 bit mantissa stream, 1 bit sign stream

  uint64_t num_streams = MAX_STREAMS;
  uint64_t offsets[MAX_STREAMS];       // byte offset to header of stream k
  uint64_t orig_sizes[MAX_STREAMS];    // size of the original data in streak k
  uint64_t stored_sizes[MAX_STREAMS];  // size of the stored data in streak k

  if (analyze_streams(raw_data, raw_len, &num_streams, offsets, orig_sizes, stored_sizes)) {
    error_and_exit("ERROR: cannot analyze streams\n");
  }

  offsets[num_streams] = raw_len;

  // now we will generate our pointers into the input data for each
  // stream, space for storing the output data, and space for the final result
  // this setup is generalized, though the later code will only handle
  // the 1 stream raw, and 2 or 3 stream float formats

  uint8_t* output_data[num_streams];
  for (uint64_t stream = 0; stream < num_streams; stream++) {
    output_data[stream] = malloc_and_check(orig_sizes[stream]);
    memset(output_data[stream], 0, orig_sizes[stream]);
  }

  // FP assumptions here
  uint64_t final_output_size = 0;
  if (num_streams == 1) {
    final_output_size = orig_sizes[0];
  } else if (num_streams == 2 || num_streams == 3) {
    final_output_size = 4 * orig_sizes[1];  // "exponent stream" size
  } else {
    error_and_exit("ERROR: have too many streams\n");
  }

  uint8_t* final_output_data = malloc_and_check(final_output_size);
  memset(final_output_data, 0, final_output_size);

  // now reconstruct each stream
  for (uint64_t stream = 0; stream < num_streams; stream++) {
    // Create a zero'd out configuration
    packlab_config_t config = {0};

    uint8_t* input_data = &raw_data[offsets[stream]];
    uint64_t input_len  = offsets[stream + 1] - offsets[stream];

    // Parse the header to determine the packed file's configuration
    parse_header(input_data, input_len, &config);

    // Check if header is valid
    if (!config.is_valid) {
      error_and_exit("ERROR: header is invalid\n");
    }

    // Check independently if this is sane if it's a continuation
    if (config.should_continue && !config.should_float) {
      error_and_exit("ERROR: have non-float continuation\n");
    }

    if (stream == 1 && !config.should_float) {
      error_and_exit("ERROR: have 2nd stream without float\n");
    }

    if (stream == 2 && !config.should_float3) {
      error_and_exit("ERROR: have 3rd stream without float3\n");
    }

    // Create a buffer containing the file data only
    if (config.header_len > input_len) {
      error_and_exit("ERROR: input stream is shorter than expected\n");
    }

    // this is convoluted because we are trying to preserve
    // Branden's handling for the single stream case as closely as possible
    // and we do not care about performance...
    size_t data_len = stored_sizes[stream];
    uint8_t* data   = malloc_and_check(data_len);
    memcpy(data, &(input_data[ROUNDUP_ALIGN(config.header_len, DATA_ALIGN)]), data_len);

    // Handle checksumming
    if (config.is_checksummed) {

      // Calculate checksum of data
      uint16_t calc_checksum = calculate_checksum(data, data_len);

      // Validate checksum
      if (calc_checksum != config.checksum_value) {
        error_and_exit("ERROR: checksum is invalid\n");
      }
    }

    // Handle decryption
    if (config.is_encrypted) {
      // Get a password from the user, only the first time
      static char password[80] = "";
      if (strlen(password) == 0) {
        if (getenv("PACKLAB_PASSWORD")) {
          strcpy(password, getenv("PACKLAB_PASSWORD"));
        } else {
          printf("Type the file password and hit enter: ");
          int match_count = scanf("%79s", password);
          if (match_count != 1) {
            error_and_exit("ERROR: invalid password entered\n");
          }
        }
      }

      // Use a checksum as a lazy method for "hashing" the password
      // This isn't ideal as it will have many collisions (password "ab" equals password "ba")
      uint16_t encryption_key = calculate_checksum((uint8_t*)password, strlen(password));

      // Decrypt the data
      size_t output_len    = data_len;
      uint8_t* output_temp = malloc_and_check(output_len);
      decrypt_data(data, data_len, output_temp, output_len, encryption_key);

      // Replace data with new output
      free(data);
      data     = output_temp;
      data_len = output_len;
    }

    // Handle decompression
    if (config.is_compressed) {
      // Decompress the data
      size_t output_len    = (MAX_RUN_LENGTH * input_len) / 2; // worst-case output could be MAX_RUN_LENGTH bytes for every two bytes
      uint8_t* output_temp = malloc_and_check(output_len);
      output_len = decompress_data(data, data_len, output_temp, output_len, config.dictionary_data);

      // Replace data with new output
      free(data);
      data     = output_temp;
      data_len = output_len;
    }

    // check for size mis-matches and copy data
    if (data_len != orig_sizes[stream]) {
      error_and_exit("ERROR: reconstructed stream is wrong length\n");
    }
    memcpy(output_data[stream], data, data_len);

    free(data);

  }

  if (num_streams == 1) {
    memcpy(final_output_data, output_data[0], orig_sizes[0]);
  } else if (num_streams == 2) {
    // there can't be any size error here, so this function will always work
    join_float_array(output_data[0], orig_sizes[0], output_data[1],
        orig_sizes[1], final_output_data, final_output_size);
  } else if (num_streams == 3) {
    join_float_array_three_stream(output_data[0], orig_sizes[0],
        output_data[1], orig_sizes[1], output_data[2], orig_sizes[2],
        final_output_data, final_output_size);
  } else {
    error_and_exit("ERROR: impossible number of streams at reconstruction\n");
  }

  // Cleanup
  for (uint64_t stream = 0; stream < num_streams; stream++) {
    free(output_data[stream]);
  }

  // Create output file
  // This is done late in the process in case the input was invalid
  FILE* output_fd = fopen(output_filename, "w");
  if (output_fd == NULL) {
    error_and_exit("ERROR: could not open output file\n");
  }

  // Write data to output file
  size_t write_len = fwrite(final_output_data, sizeof(uint8_t), final_output_size, output_fd);
  if (write_len != final_output_size) {
    error_and_exit("ERROR: could not write output file data\n");
  }
  fclose(output_fd);
  free(final_output_data);
  free(raw_data);

  return 0;
}

