/*
 * This file is part of ltrace.
 * Copyright (C) 2011, 2012 Petr Machata, Red Hat Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */

#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "lens_enum.h"
#include "lens_default.h"
#include "value.h"
#include "sysdep.h"
#include "type.h"

struct enum_entry {
	char *key;
	int own_key;
	struct value *value;
	int own_value;
};

static void
enum_entry_dtor(struct enum_entry *entry, void *data)
{
	if (entry->own_key)
		free(entry->key);
	if (entry->own_value) {
		value_destroy(entry->value);
		free(entry->value);
	}
}

static void
enum_lens_destroy_cb(struct lens *lens)
{
	struct enum_lens *self = (void *)lens;

	VECT_DESTROY(&self->entries, struct enum_entry,
		     enum_entry_dtor, NULL);
}

enum {
#ifdef ARCH_ENDIAN_BIG
	big_endian = 1,
#elif defined (ARCH_ENDIAN_LITTLE)
	big_endian = 0,
#else
# error Undefined endianness.
#endif
};

/* Returns 0 if they are not equal, >0 if they are, and <0 if there
 * was an error.  */
static int
enum_values_equal(struct value *inf_value, struct value *enum_value,
		  struct value_dict *arguments)
{
	/* Width may not match between what's defined in config file
	 * and what arrives from the back end.  Typically, if there is
	 * a mismatch, the config file size will be larger, as we are
	 * in a situation where 64-bit tracer traces 32-bit process.
	 * But opposite situation can occur e.g. on PPC, where it's
	 * apparently possible for 32-bit tracer to trace 64-bit
	 * inferior, or hypothetically in a x32/x86_64 situation.  */

	unsigned char *inf_data = value_get_data(inf_value, arguments);
	size_t inf_sz = value_size(inf_value, arguments);
	if (inf_data == NULL || inf_sz == (size_t)-1)
		return -1;

	assert(inf_value->type->type == enum_value->type->type);

	unsigned char *enum_data = value_get_data(enum_value, arguments);
	size_t enum_sz = value_size(enum_value, arguments);
	if (enum_data == NULL || enum_sz == (size_t)-1)
		return -1;

	size_t sz = enum_sz > inf_sz ? inf_sz : enum_sz;

	if (big_endian)
		return memcmp(enum_data + enum_sz - sz,
			      inf_data + inf_sz - sz, sz) == 0;
	else
		return memcmp(enum_data, inf_data, sz) == 0;
}

static const char *
enum_get(struct enum_lens *lens, struct value *value,
	 struct value_dict *arguments)
{
	size_t i;
	for (i = 0; i < vect_size(&lens->entries); ++i) {
		struct enum_entry *entry = VECT_ELEMENT(&lens->entries,
							struct enum_entry, i);
		int st = enum_values_equal(value, entry->value, arguments);
		if (st < 0)
			return NULL;
		else if (st != 0)
			return entry->key;
	}
	return NULL;
}

const int
flags_next(struct enum_lens *lens, struct value *value,
	   struct value_dict *arguments, const char **retp)
{
	size_t i;
	for (i = 0; i < vect_size(&lens->entries); ++i) {
		struct enum_entry *entry = VECT_ELEMENT(&lens->entries,
							struct enum_entry, i);
		unsigned char *v = value_get_data(value, arguments);
		size_t v_sz = value_size(value, arguments);
		if (v == NULL || v_sz == (size_t)-1)
			return -1;

		const unsigned char *mask
			= value_get_data(entry->value, arguments);
		size_t mask_sz = value_size(entry->value, arguments);
		if (mask == NULL || mask_sz == (size_t)-1)
			return -1;

		size_t sz = v_sz < mask_sz ? v_sz : mask_sz;

		/* The following doesn't work well with cross-tracing
		 * on one of the endians.  What's intended is:
		 *  |   value   |
		 *       | mask |
		 *
		 * What we are doing is:
		 *  |   value   |
		 *  | mask |
		 */
		size_t j;
		int mismatch = 0;
		for (j = 0; j < sz; ++j) {
			unsigned char m = mask[j];
			if ((m & v[j]) != m) {
				mismatch = 1;
				break;
			}
		}
		/* This takes care of the following scenario:
		 *  | value |
		 *  |    mask   |
		 */
		for (j = sz; j < mask_sz; ++j) {
			if (mask[j] != 0) {
				mismatch = 1;
				break;
			}
		}

		if (mismatch)
			continue;

		for (j = 0; j < sz; ++j)
			v[j] &= ~mask[j];
		*retp = entry->key;
		return 0;
	}

	*retp = NULL;
	return 0;
}

static int
enum_lens_format_cb(struct lens *lens, FILE *stream,
		    struct value *value, struct value_dict *arguments)
{
	struct enum_lens *self = (void *)lens;

	if (self->et == ELT_ENUM) {
		const char *name = enum_get(self, value, arguments);
		if (name != NULL)
			return fprintf(stream, "%s", name);
		return lens_format(&default_lens, stream, value, arguments);

	} else {
		assert(self->et == ELT_FLAGS);

		/* We will need to reify and unshare later anyway, and
		 * semantically no harm is done if originals are
		 * modified instead.  */
		if (value_reify(value, arguments) < 0
		    || value_unshare(value) < 0)
			return -1;

		/* Now we clone so that we can modify the value.  */
		struct value copy;
		if (value_clone(&copy, value) < 0)
			return -1;

		int o = 0;
		while (!value_is_zero(&copy, arguments)) {
			const char *name;
			if (flags_next(self, &copy, arguments, &name) < 0) {
			fail:
				value_destroy(&copy);
				return -1;
			}
			if (name == NULL)
				break;

			/* Emit a divider if we've written
			 * anything...  */
			if (o > 0) {
				int rc = fprintf(stream, "|");
				if (rc < 0)
					goto fail;
				o += rc;
			}

			int rc = fprintf(stream, "%s", name);
			if (rc < 0)
				goto fail;
			o += rc;
		}

		int rc = lens_format(&default_lens, stream, &copy, arguments);
		value_destroy(&copy);
		if (rc < 0)
			return -1;
		return o + rc;
	}
}


void
lens_init_enum(struct enum_lens *lens, enum enum_lens_type et)
{
	*lens = (struct enum_lens){
		.super = {
			.format_cb = enum_lens_format_cb,
			.destroy_cb = enum_lens_destroy_cb,
		},
		.et = et,
	};
	VECT_INIT(&lens->entries, struct enum_entry);
}

int
lens_enum_add(struct enum_lens *lens,
	      const char *key, int own_key,
	      struct value *value, int own_value)
{
	struct enum_entry entry = { (char *)key, own_key, value, own_value };
	return VECT_PUSHBACK(&lens->entries, &entry);
}

size_t
lens_enum_size(struct enum_lens *lens)
{
	return vect_size(&lens->entries);
}
