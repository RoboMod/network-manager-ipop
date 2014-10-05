/* utils.c -- helpers for ipop connections
 *
 * Copyright (C) 2010 Red Hat, Inc., Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2014 Andreas Ihrig <mod.andy@gmx.de>
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
 */

#include <string.h>
#include "utils.h"
#include "nm-utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/**
 * @brief str_to_gvalue
 * @param str
 * @param try_convert
 * @return
 */
GValue* str_to_gvalue(const char *str, gboolean try_convert) {
    GValue *val;

    /* Empty */
    if (!str || strlen (str) < 1)
        return NULL;

    if (!g_utf8_validate (str, -1, NULL)) {
        if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1",
                                              "UTF-8", NULL, NULL, NULL)))
            str = g_convert (str, -1, "C", "UTF-8", NULL, NULL, NULL);

        if (!str)
            /* Invalid */
            return NULL;
    }
    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_STRING);
    g_value_set_string (val, str);

    return val;
}

/**
 * @brief addr_to_gvalue
 * @param str
 * @return
 */
GValue* addr_to_gvalue(const char *str) {
    struct in_addr  temp_addr;
    GValue *val;

    /* Empty */
    if (!str || strlen (str) < 1)
        return NULL;

    if (inet_pton (AF_INET, str, &temp_addr) <= 0)
        return NULL;

    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_UINT);
    g_value_set_uint (val, temp_addr.s_addr);

    return val;
}

/**
 * @brief bool_to_gvalue
 * @param b
 * @return
 */
GValue* bool_to_gvalue(gboolean b) {
    GValue *val;
    val = g_slice_new0 (GValue);
    g_value_init (val, G_TYPE_BOOLEAN);
    g_value_set_boolean (val, b);
    return val;
}

/**
 * @brief find_file
 * @detail searchs for file needed for ipop service
 * @return
 */
const char* find_file(const char** file_paths) {
    while (*file_paths != NULL) {
        if (g_file_test(*file_paths, G_FILE_TEST_EXISTS))
            break;
        file_paths++;
    }

    return *file_paths;
}

/**
 * @brief nm_ipop_free_args
 * @param args
 */
void nm_ipop_free_args(GPtrArray *args) {
    g_ptr_array_foreach(args, (GFunc) g_free, NULL);
    g_ptr_array_free(args, TRUE);
}

/**
 * @brief nm_ipop_add_arg
 * @param args
 * @param arg
 */
void nm_ipop_add_arg(GPtrArray *args, const char *arg) {
    g_return_if_fail(args != NULL);
    g_return_if_fail(arg != NULL);

    g_ptr_array_add(args, (gpointer)g_strdup(arg));
}

/**
 * @brief nm_ipop_add_optional_arg
 * @param args
 * @param option
 * @param arg
 */
void nm_ipop_add_optional_arg(GPtrArray *args, const char* option,
                              const char *arg) {
    g_return_if_fail(args != NULL);
    g_return_if_fail(option != NULL);
    g_return_if_fail(arg != NULL);

    g_ptr_array_add(args, (gpointer)g_strdup(option));
    g_ptr_array_add(args, (gpointer)g_strdup(arg));
}
