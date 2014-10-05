/* nm-ipop.h : GNOME UI dialogs for configuring ipop VPN connections
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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

#ifndef _NM_IPOP_H_
#define _NM_IPOP_H_

#include <glib-object.h>

typedef enum
{
	IPOP_PLUGIN_UI_ERROR_UNKNOWN = 0,
	IPOP_PLUGIN_UI_ERROR_INVALID_CONNECTION,
	IPOP_PLUGIN_UI_ERROR_INVALID_PROPERTY,
	IPOP_PLUGIN_UI_ERROR_MISSING_PROPERTY,
	IPOP_PLUGIN_UI_ERROR_FILE_NOT_READABLE,
	IPOP_PLUGIN_UI_ERROR_FILE_NOT_IPOP
} IPOPPluginUiError;

#define IPOP_TYPE_PLUGIN_UI_ERROR (ipop_plugin_ui_error_get_type ()) 
GType ipop_plugin_ui_error_get_type (void);

#define IPOP_PLUGIN_UI_ERROR (ipop_plugin_ui_error_quark ())
GQuark ipop_plugin_ui_error_quark (void);


#define IPOP_TYPE_PLUGIN_UI            (ipop_plugin_ui_get_type ())
#define IPOP_PLUGIN_UI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), IPOP_TYPE_PLUGIN_UI, IPOPPluginUi))
#define IPOP_PLUGIN_UI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), IPOP_TYPE_PLUGIN_UI, IPOPPluginUiClass))
#define IPOP_IS_PLUGIN_UI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), IPOP_TYPE_PLUGIN_UI))
#define IPOP_IS_PLUGIN_UI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), IPOP_TYPE_PLUGIN_UI))
#define IPOP_PLUGIN_UI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), IPOP_TYPE_PLUGIN_UI, IPOPPluginUiClass))

typedef struct _IPOPPluginUi IPOPPluginUi;
typedef struct _IPOPPluginUiClass IPOPPluginUiClass;

struct _IPOPPluginUi {
	GObject parent;
};

struct _IPOPPluginUiClass {
	GObjectClass parent;
};

GType ipop_plugin_ui_get_type (void);


#define IPOP_TYPE_PLUGIN_UI_WIDGET            (ipop_plugin_ui_widget_get_type ())
#define IPOP_PLUGIN_UI_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), IPOP_TYPE_PLUGIN_UI_WIDGET, IPOPPluginUiWidget))
#define IPOP_PLUGIN_UI_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), IPOP_TYPE_PLUGIN_UI_WIDGET, IPOPPluginUiWidgetClass))
#define IPOP_IS_PLUGIN_UI_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), IPOP_TYPE_PLUGIN_UI_WIDGET))
#define IPOP_IS_PLUGIN_UI_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), IPOP_TYPE_PLUGIN_UI_WIDGET))
#define IPOP_PLUGIN_UI_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), IPOP_TYPE_PLUGIN_UI_WIDGET, IPOPPluginUiWidgetClass))

typedef struct _IPOPPluginUiWidget IPOPPluginUiWidget;
typedef struct _IPOPPluginUiWidgetClass IPOPPluginUiWidgetClass;

struct _IPOPPluginUiWidget {
	GObject parent;
};

struct _IPOPPluginUiWidgetClass {
	GObjectClass parent;
};

GType ipop_plugin_ui_widget_get_type (void);

#endif	/* _NM_IPOP_H_ */

