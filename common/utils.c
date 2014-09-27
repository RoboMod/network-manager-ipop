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

#include <string.h>
//#include <nm-setting-8021x.h>
#include "utils.h"
#include "nm-utils.h"
#include <netinet/in.h>
#include <arpa/inet.h>

//gboolean
//is_pkcs12 (const char *filepath)
//{
//	NMSetting8021xCKFormat ck_format = NM_SETTING_802_1X_CK_FORMAT_UNKNOWN;
//	NMSetting8021x *s_8021x;

//	if (!filepath || !strlen (filepath))
//		return FALSE;

//	if (!g_file_test (filepath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))
//		return FALSE;

//	s_8021x = (NMSetting8021x *) nm_setting_802_1x_new ();
//	g_return_val_if_fail (s_8021x != NULL, FALSE);

//	nm_setting_802_1x_set_private_key (s_8021x,
//	                                   filepath,
//	                                   NULL,
//	                                   NM_SETTING_802_1X_CK_SCHEME_PATH,
//	                                   &ck_format,
//	                                   NULL);
//	g_object_unref (s_8021x);

//	return (ck_format == NM_SETTING_802_1X_CK_FORMAT_PKCS12);
//}

//#define PROC_TYPE_TAG "Proc-Type: 4,ENCRYPTED"
//#define PKCS8_TAG "-----BEGIN ENCRYPTED PRIVATE KEY-----"

///** Checks if a file appears to be an encrypted private key.
// * @param filename the path to the file
// * @return returns true if the key is encrypted, false otherwise
// */
//gboolean
//is_encrypted (const char *filename)
//{
//	GIOChannel *pem_chan;
//	char *str = NULL;
//	gboolean encrypted = FALSE;

//	if (!filename || !strlen (filename))
//		return FALSE;

//	if (is_pkcs12 (filename))
//		return TRUE;

//	pem_chan = g_io_channel_new_file (filename, "r", NULL);
//	if (!pem_chan)
//		return FALSE;

//	while (g_io_channel_read_line (pem_chan, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
//		if (str) {
//			if (g_str_has_prefix (str, PROC_TYPE_TAG) || g_str_has_prefix (str, PKCS8_TAG)) {
//				encrypted = TRUE;
//				break;
//			}
//			g_free (str);
//		}
//	}

//	g_io_channel_shutdown (pem_chan, FALSE, NULL);
//	g_io_channel_unref (pem_chan);
//	return encrypted;
//}

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
        if (try_convert && !(str = g_convert (str, -1, "ISO-8859-1", "UTF-8", NULL, NULL, NULL)))
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
void nm_ipop_add_optional_arg(GPtrArray *args, const char* option, const char *arg) {
    g_return_if_fail(args != NULL);
    g_return_if_fail(option != NULL);
    g_return_if_fail(arg != NULL);

    g_ptr_array_add(args, (gpointer)g_strdup(option));
    g_ptr_array_add(args, (gpointer)g_strdup(arg));
}
