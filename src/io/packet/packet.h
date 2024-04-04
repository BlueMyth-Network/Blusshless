#pragma once
#include "../../main.h"
#include "../io.h"
#include "../nbt/mnbt.h"
#include <assert.h>

typedef struct {

	size_t cursor;
	size_t length;

	int32_t sub_length;
	
	io_endianness_t endianness : 1;
	
	byte_t length_prefix[6]; // the custom packet data
	byte_t bytes[];

} pck_packet_t;

// can't think of a good place to put this
typedef struct {

	int32_t x;
	int32_t z;
	int16_t y;

} pck_position_t;

#define PCK_INLINE(name, len, end) byte_t name ##_r[sizeof(pck_packet_t) + len]; pck_packet_t* name = (pck_packet_t*) name ##_r; name->cursor = 0; name->length = len; name->endianness = end;

#define PCK_READ_STRING(name, packet) int32_t name ##_length = pck_read_var_int(packet); char name [name ##_length + 1]; pck_read_bytes(packet, (uint8_t*) name, name ##_length); if (name ##_length + 1 != 0) { name [name ##_length] = '\0'; }
#define PCK_ALLOC_STRING(name, packet) int32_t name ##_length = pck_read_var_int(packet); char* name = malloc(name ##_length + 1); pck_read_bytes(packet, (uint8_t*) name, name ##_length); name[name ##_length] = '\0';

extern pck_packet_t* pck_create(size_t, io_endianness_t);
extern pck_packet_t* pck_from_bytes(byte_t*, size_t, io_endianness_t);

extern void pck_init_from_bytes(pck_packet_t*, byte_t*, size_t, io_endianness_t);

static inline size_t pck_left_over(pck_packet_t* packet){
	return packet->length - packet->cursor;
}

static inline void pck_cursor_skip(pck_packet_t* packet, size_t size){
	assert(packet->length - packet->cursor >= size);

	packet->cursor += size;
}

static inline int8_t pck_read_int8(pck_packet_t* packet) {

	assert(packet->length - packet->cursor >= 1);

	packet->cursor += 1;

	return io_read_int8(packet->bytes + packet->cursor - 1);

}

static inline int16_t pck_read_int16(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 2);

	packet->cursor += 2;

	return io_read_int16(packet->bytes + packet->cursor - 2, packet->endianness);

}

static inline int32_t pck_read_int24(pck_packet_t* packet) {
	uint32_t rt = ((uint8_t) pck_read_int8(packet) & 0xff);
	rt |= ((uint8_t) pck_read_int8(packet) & 0xff) << 8;
	rt |= ((uint8_t) pck_read_int8(packet) & 0xff) << 16;
	return *(int32_t*)&rt;
}

static inline int32_t pck_read_intb32(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 4);

	packet->cursor += 4;

	return io_read_int32(packet->bytes + packet->cursor - 4, io_big_endian);

}

static inline int32_t pck_read_int32(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 4);

	packet->cursor += 4;

	return io_read_int32(packet->bytes + packet->cursor - 4, packet->endianness);

}

static inline int64_t pck_read_int64(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 8);

	packet->cursor += 8;

	return io_read_int64(packet->bytes + packet->cursor - 8, packet->endianness);

}

static inline float32_t pck_read_float32(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 4);

	packet->cursor += 4;

	return io_read_float32(packet->bytes + packet->cursor - 4, packet->endianness);

}

static inline float64_t pck_read_float64(pck_packet_t* packet) {
	
	assert(packet->length - packet->cursor >= 8);

	packet->cursor += 8;

	return io_read_float64(packet->bytes + packet->cursor - 8, packet->endianness);

}

static inline int32_t pck_read_var_int(pck_packet_t* packet) {

	size_t size = 0;
	int32_t value = io_read_var_int(packet->bytes + packet->cursor, packet->length - packet->cursor, &size);

	packet->cursor += size;

	return value;

}

static inline int64_t pck_read_var_long(pck_packet_t* packet) {

	size_t size = 0;
	int64_t value = io_read_var_long(packet->bytes + packet->cursor, packet->length - packet->cursor, &size);

	packet->cursor += size;

	return value;

}

static inline void pck_read_bytes(pck_packet_t* packet, byte_t* bytes, int32_t length) {

	assert(packet->length - packet->cursor >= (unsigned) length);

	memcpy(bytes, packet->bytes + packet->cursor, length);
	packet->cursor += length;

}

static inline void pck_write_int8(pck_packet_t* packet, int8_t value) {

	assert(packet->length - packet->cursor >= 1);

	io_write_int8(packet->bytes + packet->cursor, value);

	packet->cursor += 1;

}

static inline void pck_write_int16(pck_packet_t* packet, int16_t value) {

	assert(packet->length - packet->cursor >= 2);

	io_write_int16(packet->bytes + packet->cursor, value, packet->endianness);

	packet->cursor += 2;

}

static inline void pck_write_int24(pck_packet_t* packet, int32_t value) {//weird raknet shit
	pck_write_int8(packet, ((uint32_t) value) & 0xff);
	pck_write_int8(packet, ((uint32_t) value >> 8) & 0xff);
	pck_write_int8(packet, ((uint32_t) value >> 16) & 0xff);
}

static inline void pck_write_inte32(pck_packet_t* packet, int32_t value, io_endianness_t endianness) {

	assert(packet->length - packet->cursor >= 4);

	io_write_int32(packet->bytes + packet->cursor, value, endianness);

	packet->cursor += 4;

}

static inline void pck_write_int32(pck_packet_t* packet, int32_t value) {

	assert(packet->length - packet->cursor >= 4);

	io_write_int32(packet->bytes + packet->cursor, value, packet->endianness);

	packet->cursor += 4;

}

static inline void pck_write_int64(pck_packet_t* packet, int64_t value) {

	assert(packet->length - packet->cursor >= 8);

	io_write_int64(packet->bytes + packet->cursor, value, packet->endianness);

	packet->cursor += 8;

}

static inline void pck_write_float32(pck_packet_t* packet, float32_t value) {

	assert(packet->length - packet->cursor >= 4);

	io_write_float32(packet->bytes + packet->cursor, value, packet->endianness);

	packet->cursor += 4;

}

static inline void pck_write_float64(pck_packet_t* packet, float64_t value) {

	assert(packet->length - packet->cursor >= 8);

	io_write_float64(packet->bytes + packet->cursor, value, packet->endianness);

	packet->cursor += 8;

}

static inline void pck_write_var_int(pck_packet_t* packet, int32_t value) {

	packet->cursor += io_write_var_int(packet->bytes + packet->cursor, value, packet->length - packet->cursor);

}

// waste between 0-4 bytes but you can always come back to it later and change it
static inline void pck_write_long_var_int(pck_packet_t* packet, int32_t value) {

	assert(packet->length - packet->cursor >= 5);

	io_write_long_var_int(packet->bytes + packet->cursor, value);
	packet->cursor += 5;

}

static inline void pck_write_var_long(pck_packet_t* packet, int64_t value) {

	packet->cursor += io_write_var_long(packet->bytes + packet->cursor, value, packet->length - packet->cursor);

}

static inline void pck_write_bytes(pck_packet_t* packet, const byte_t* bytes, int32_t length) {

	memcpy(packet->bytes + packet->cursor, bytes, length);
	packet->cursor += length;

}

static inline void pck_write_string(pck_packet_t* packet, const char* string, size_t length) {

	pck_write_var_int(packet, length);
	pck_write_bytes(packet, (byte_t*) string, length);

}

static inline void pck_write_nbt(pck_packet_t* packet, mnbt_doc* doc) {

	packet->cursor += mnbt_write(doc, packet->bytes + packet->cursor, MNBT_NONE);

}

static inline void pck_write_position(pck_packet_t* packet, pck_position_t position) {

	pck_write_int64(packet, ((uint64_t) (position.x & 0x3FFFFFF) << 38) | ((uint64_t) (position.z & 0x3FFFFFF) << 12) | ((uint64_t) position.y & 0xFFF));

}

static inline byte_t* pck_cursor(pck_packet_t* packet) {
	return packet->bytes + packet->cursor;
}

#if NDEBUG
#define pck_log(packet) {}
#else
extern void pck_log(pck_packet_t* packet);
#endif