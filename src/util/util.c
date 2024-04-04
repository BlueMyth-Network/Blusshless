#include <string.h>
#include "util.h"
#include "../io/io.h"

size_t utl_to_minecraft_hex(char* str, const byte_t* val, size_t size) {

	size_t str_size = 0;

	byte_t value[size];
	memcpy(value, val, size);

	// negate if negative
	if (value[0] & 0x80) {

		// not
		for (uint32_t i = 0; i < size; ++i) {
			value[i] = ~value[i];
		}

		// add 1
		int_fast32_t i = size - 1;
		do {
			value[i]++;
		} while (value[i] == 0 && --i >= 0);

		str[0] = '-';
		str_size = 1;

	}

	bool begin = true;
	for (size_t i = 0; i < size; ++i) {

		if (begin) {

			if (value[i] == 0) continue;

			if (value[i] & 0xF0) {

				utl_write_byte_hex(str + str_size, value[i]);
				str_size += 2;

			} else {

				str[str_size] = utl_hexmap[value[i]];
				str_size += 1;

			}
			begin = false;

		} else {
			utl_write_byte_hex(str + str_size, value[i]);
			str_size += 2;
		}

	}
	str[str_size] = '\0';

	return str_size;

}

#ifndef __APPLE__
char *stpcpy(char *__restrict__ dest, const char *__restrict__ src) {
	while ((*dest++ = *src++) != '\0')
		/* nothing */;
	return --dest;
}
#endif