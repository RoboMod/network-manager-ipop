/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2010 Red Hat, Inc.
 */

#ifndef UTILS_H
#define UTILS_H

#include <glib.h>
#include <glib-object.h>

//gboolean is_pkcs12 (const char *filepath);
//gboolean is_encrypted (const char *filename);

GValue* str_to_gvalue(const char *str, gboolean try_convert);
GValue* addr_to_gvalue(const char *str);
GValue* bool_to_gvalue(gboolean b);

const char* find_file(const char** file_paths);

void nm_ipop_free_args(GPtrArray *args);
void nm_ipop_add_arg(GPtrArray *args, const char *arg);
void nm_ipop_add_optional_arg(GPtrArray *args, const char* option, const char *arg);

#endif  /* UTILS_H */

