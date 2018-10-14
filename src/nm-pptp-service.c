/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-pptp-service - PPTP VPN integration with NetworkManager
 *
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
 * (C) Copyright 2008 - 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-pptp-service.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <locale.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "nm-ppp-status.h"
#include "nm-pptp-pppd-service-dbus.h"
#include "nm-utils/nm-shared-utils.h"
#include "nm-utils/nm-vpn-plugin-macros.h"

#if !defined(DIST_VERSION)
# define DIST_VERSION VERSION
#endif

static struct {
	gboolean debug;
	int log_level;
} gl/*lobal*/;

static void nm_pptp_plugin_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMPptpPlugin, nm_pptp_plugin, NM_TYPE_VPN_SERVICE_PLUGIN,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_pptp_plugin_initable_iface_init));

typedef struct {
	GPid pid;
	guint32 ppp_timeout_handler;
	NMConnection *connection;
	NMDBusPptpPpp *dbus_skeleton;

	/* IP of PPtP gateway in numeric and string format */
	guint32 naddr;
	char *saddr;
} NMPptpPluginPrivate;

#define NM_PPTP_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPTP_PLUGIN, NMPptpPluginPrivate))

#define NM_PPTP_PPPD_PLUGIN PLUGINDIR "/nm-pptp-pppd-plugin.so"
#define NM_PPTP_WAIT_PPPD 10000 /* 10 seconds */
#define PPTP_SERVICE_SECRET_TRIES "pptp-service-secret-tries"

/*****************************************************************************/

#define _NMLOG(level, ...) \
    G_STMT_START { \
         if (gl.log_level >= (level)) { \
              g_print ("nm-pptp[%ld] %-7s " _NM_UTILS_MACRO_FIRST (__VA_ARGS__) "\n", \
                       (long) getpid (), \
                       nm_utils_syslog_to_str (level) \
                       _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
         } \
    } G_STMT_END

static gboolean
_LOGD_enabled (void)
{
	return gl.log_level >= LOG_INFO;
}

#define _LOGD(...) _NMLOG(LOG_INFO,    __VA_ARGS__)
#define _LOGI(...) _NMLOG(LOG_NOTICE,  __VA_ARGS__)
#define _LOGW(...) _NMLOG(LOG_WARNING, __VA_ARGS__)

/*****************************************************************************/

typedef struct {
	const char *name;
	GType type;
	bool required:1;
} ValidProperty;

static const ValidProperty valid_properties[] = {
	{ NM_PPTP_KEY_GATEWAY,           G_TYPE_STRING, TRUE },
	{ NM_PPTP_KEY_USER,              G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_DOMAIN,            G_TYPE_STRING, FALSE },
	{ NM_PPTP_KEY_REFUSE_EAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_PAP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_CHAP,       G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAP,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REFUSE_MSCHAPV2,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE,      G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_40,   G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_REQUIRE_MPPE_128,  G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_MPPE_STATEFUL,     G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NOBSDCOMP,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NODEFLATE,         G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_NO_VJ_COMP,        G_TYPE_BOOLEAN, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_FAILURE,  G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_LCP_ECHO_INTERVAL, G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_UNIT_NUM,          G_TYPE_UINT, FALSE },
	{ NM_PPTP_KEY_PASSWORD"-flags",  G_TYPE_UINT, FALSE },
	{ NULL }
};

static const ValidProperty valid_secrets[] = {
	{ NM_PPTP_KEY_PASSWORD,          G_TYPE_STRING, FALSE },
	{ NULL }
};

static gboolean
validate_gateway (const char *gateway)
{
	const char *p = gateway;

	if (!gateway || !strlen (gateway))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	p = gateway;
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

typedef struct ValidateInfo {
	const ValidProperty *table;
	GError **error;
	gboolean have_items;
} ValidateInfo;

static void
validate_one_property (const char *key, const char *value, gpointer user_data)
{
	ValidateInfo *info = (ValidateInfo *) user_data;
	int i;

	if (*(info->error))
		return;

	info->have_items = TRUE;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp (key, NM_SETTING_NAME))
		return;

	for (i = 0; info->table[i].name; i++) {
		const ValidProperty prop = info->table[i];
		long int tmp;

		if (strcmp (prop.name, key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			if (   !strcmp (prop.name, NM_PPTP_KEY_GATEWAY)
			    && !validate_gateway (value)) {
				g_set_error (info->error,
				             NM_VPN_PLUGIN_ERROR,
				             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				             _("invalid gateway “%s”"),
				             key);
				return;
			}
			return; /* valid */
		case G_TYPE_UINT:
			errno = 0;
			tmp = strtol (value, NULL, 10);
			if (errno == 0)
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid integer property “%s”"),
			             key);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp (value, "yes") || !strcmp (value, "no"))
				return; /* valid */

			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("invalid boolean property “%s” (not yes or no)"),
			             key);
			break;
		default:
			g_set_error (info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("unhandled property “%s” type %s"),
			             key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!info->table[i].name) {
		g_set_error (info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("property “%s” invalid or not supported"),
		             key);
	}
}

static gboolean
nm_pptp_properties_validate (NMSettingVpn *s_vpn,
                             GError **error)
{
	ValidateInfo info = { &valid_properties[0], error, FALSE };
	int i;

	nm_setting_vpn_foreach_data_item (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN configuration options."));
		return FALSE;
	}

	if (*error)
		return FALSE;

	/* Ensure required properties exist */
	for (i = 0; valid_properties[i].name; i++) {
		const ValidProperty prop = valid_properties[i];
		const char *value;

		if (!prop.required)
			continue;

		value = nm_setting_vpn_get_data_item (s_vpn, prop.name);
		if (!value || !strlen (value)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Missing required option “%s”."),
			             prop.name);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
nm_pptp_secrets_validate (NMSettingVpn *s_vpn, GError **error)
{
	ValidateInfo info = { &valid_secrets[0], error, FALSE };

	nm_setting_vpn_foreach_secret (s_vpn, validate_one_property, &info);
	if (!info.have_items) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             _("No VPN secrets!"));
		return FALSE;
	}

	return *error ? FALSE : TRUE;
}

static void
pppd_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			_LOGW ("pppd exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		_LOGW ("pppd stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("pppd died with signal %d", WTERMSIG (status));
	else
		_LOGW ("pppd died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 16:
		/* hangup */
		// FIXME: better failure reason
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		break;
	}
}

static inline const char *
nm_find_pppd (void)
{
	static const char *pppd_binary_paths[] =
		{
			"/sbin/pppd",
			"/usr/sbin/pppd",
			"/usr/local/sbin/pppd",
			NULL
		};

	const char  **pppd_binary = pppd_binary_paths;

	while (*pppd_binary != NULL) {
		if (g_file_test (*pppd_binary, G_FILE_TEST_EXISTS))
			break;
		pppd_binary++;
	}

	return *pppd_binary;
}

static inline const char *
nm_find_pptp (void)
{
	static const char *pptp_binary_paths[] =
		{
			"/sbin/pptp",
			"/usr/sbin/pptp",
			"/usr/local/sbin/pptp",
			NULL
		};

	const char  **pptp_binary = pptp_binary_paths;

	while (*pptp_binary != NULL) {
		if (g_file_test (*pptp_binary, G_FILE_TEST_EXISTS))
			break;
		pptp_binary++;
	}

	return *pptp_binary;
}

static gboolean
pppd_timed_out (gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);

	_LOGW ("Looks like pppd didn't initialize our dbus module");
	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);

	return FALSE;
}

static void
free_pppd_args (GPtrArray *args)
{
	int i;

	if (!args)
		return;

	for (i = 0; i < args->len; i++)
		g_free (g_ptr_array_index (args, i));
	g_ptr_array_free (args, TRUE);
}

static gboolean
str_to_int (const char *str, long int *out)
{
	long int tmp_int;

	if (!str)
		return FALSE;

	errno = 0;
	tmp_int = strtol (str, NULL, 10);
	if (errno == 0) {
		*out = tmp_int;
		return TRUE;
	}
	return FALSE;
}

static GPtrArray *
construct_pppd_args (NMPptpPlugin *plugin,
                     NMSettingVpn *s_vpn,
                     const char *pppd,
                     const char *gwaddr,
                     GError **error)
{
	GPtrArray *args = NULL;
	const char *value, *pptp_binary;
	char *ipparam, *tmp;
	char log_level;
    
    FILE *file;
    char *istr;

	pptp_binary = nm_find_pptp ();
	if (!pptp_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("Could not find pptp client binary."));
		return FALSE;
	}

	args = g_ptr_array_new ();
	g_ptr_array_add (args, (gpointer) g_strdup (pppd));

	/* PPTP options */
	if (!gwaddr || !strlen (gwaddr)) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		             "%s",
		             _("Missing VPN gateway."));
		goto error;
	}

	ipparam = g_strdup_printf ("nm-pptp-service-%d", getpid ());
    
    /* PPTP options for NM */
    /* They improve performance on modern 100mbit+ connections
     * which are used in some old Russian networks, for example.
     * See https://forum.rosalinux.ru/viewtopic.php?t=9229 
     * for more details about this problem
     */
    char buff[128];
    char s[1024] = "%s %s ";

    const char *prm[17];
    prm[0] = "phone";
    prm[1] = "nolaunchpppd";
    prm[2] = "quirks";
    prm[3] = "debug ";
    prm[4] = "sync";
    prm[5] = "timeout";

    prm[6] = "nobuffer";
    prm[7] = "idle-wait";
    prm[8] = "max-echo-wait";
    prm[9] = "logstring";
    prm[10] = "localbind";
    prm[11] = "rtmark";
    prm[12] = "nohostroute";

    prm[13] = "loglevel";
    prm[14] = "test-type";
    prm[15] = "test-rate";
    prm[16] = "missing-window";

    /* Read options from config file if it's available */
    file = fopen("/etc/ppp/options.pptp","r");

    if (!file) 
    {
        strcpy(s, "%s %s --nolaunchpppd --loglevel 0");
    }
    else
    {
        while(fgets (buff, sizeof(buff), file) != NULL)
        {
            if (buff[0] != '#')
            {
                for (int i = 0; i < 17; i++)
                {
                    istr = strstr (buff, prm[i]); 

                    if (istr != NULL)
                    {
                        for(int j = 0; j < 127; j++)
                        {
                            if (buff[j] == '\r') buff[j] = '\0';   
                            if (buff[j] == '\n') buff[j] = '\0';    
                        }
                        
                        strcat(s, " --");
                        strcat(s, buff);
                    }
                }
            }
        }
          
        fclose(file);
    }
    
	g_ptr_array_add (args, (gpointer) g_strdup ("pty"));
    tmp = g_strdup_printf (s,
	                       pptp_binary, gwaddr,
	                       log_level,
	                       ipparam);
	g_ptr_array_add (args, (gpointer) tmp);

	if (_LOGD_enabled ())
		g_ptr_array_add (args, (gpointer) g_strdup ("debug"));

	/* PPP options */
	g_ptr_array_add (args, (gpointer) g_strdup ("ipparam"));
	g_ptr_array_add (args, (gpointer) ipparam);

	g_ptr_array_add (args, (gpointer) g_strdup ("nodetach"));
	g_ptr_array_add (args, (gpointer) g_strdup ("lock"));
	g_ptr_array_add (args, (gpointer) g_strdup ("usepeerdns"));
	g_ptr_array_add (args, (gpointer) g_strdup ("noipdefault"));
	g_ptr_array_add (args, (gpointer) g_strdup ("nodefaultroute"));

	/* Don't need to auth the PPTP server */
	g_ptr_array_add (args, (gpointer) g_strdup ("noauth"));

	/* Username; try PPTP specific username first, then generic username */
	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_USER);
	if (!value || !*value)
		value = nm_setting_vpn_get_user_name (s_vpn);
	if (value && *value) {
		g_ptr_array_add (args, (gpointer) g_strdup ("user"));
		g_ptr_array_add (args, (gpointer) g_strdup (value));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
	if (value && *value) {
		g_ptr_array_add (args, (gpointer) g_strdup ("remotename"));
		g_ptr_array_add (args, (gpointer) g_strdup (value));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_EAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-eap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_PAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-pap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_CHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-chap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REFUSE_MSCHAPV2);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("refuse-mschap-v2"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_40);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-40"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_REQUIRE_MPPE_128);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("require-mppe-128"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_MPPE_STATEFUL);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("mppe-stateful"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NOBSDCOMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nobsdcomp"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NODEFLATE);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("nodeflate"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_NO_VJ_COMP);
	if (value && !strcmp (value, "yes"))
		g_ptr_array_add (args, (gpointer) g_strdup ("novj"));

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_FAILURE);
	if (value && strlen (value)) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			_LOGW ("failed to convert lcp-echo-failure value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-failure"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_LCP_ECHO_INTERVAL);
	if (value && *value) {
		long int tmp_int;

		/* Convert to integer and then back to string for security's sake
		 * because strtol ignores some leading and trailing characters.
		 */
		if (str_to_int (value, &tmp_int)) {
			g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else {
			_LOGW ("failed to convert lcp-echo-interval value '%s'", value);
		}
	} else {
		g_ptr_array_add (args, (gpointer) g_strdup ("lcp-echo-interval"));
		g_ptr_array_add (args, (gpointer) g_strdup ("0"));
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_UNIT_NUM);
	if (value && *value) {
		long int tmp_int;
		if (str_to_int (value, &tmp_int)) {
			g_ptr_array_add (args, (gpointer) g_strdup ("unit"));
			g_ptr_array_add (args, (gpointer) g_strdup_printf ("%ld", tmp_int));
		} else
			_LOGW ("failed to convert unit value '%s'", value);
	}

	g_ptr_array_add (args, (gpointer) g_strdup ("plugin"));
	g_ptr_array_add (args, (gpointer) g_strdup (NM_PPTP_PPPD_PLUGIN));

	g_ptr_array_add (args, NULL);

	return args;

error:
	free_pppd_args (args);
	return FALSE;
}

static gboolean
nm_pptp_start_pppd_binary (NMPptpPlugin *plugin,
                           NMSettingVpn *s_vpn,
                           GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	GPid pid;
	const char *pppd_binary;
	GPtrArray *pppd_argv;

	pppd_binary = nm_find_pppd ();
	if (!pppd_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             _("Could not find the pppd binary."));
		return FALSE;
	}

	pppd_argv = construct_pppd_args (plugin, s_vpn, pppd_binary, priv->saddr, error);
	if (!pppd_argv)
		return FALSE;

	if (!g_spawn_async (NULL, (char **) pppd_argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		g_ptr_array_free (pppd_argv, TRUE);
		return FALSE;
	}
	free_pppd_args (pppd_argv);

	_LOGI ("pppd started with pid %d", pid);

	NM_PPTP_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	g_child_watch_add (pid, pppd_watch_cb, plugin);

	priv->ppp_timeout_handler = g_timeout_add (NM_PPTP_WAIT_PPPD, pppd_timed_out, plugin);

	return TRUE;
}

static void
remove_timeout_handler (NMPptpPlugin *plugin)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static gboolean
handle_need_secrets (NMDBusPptpPpp *object,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
	NMPptpPlugin *self = NM_PPTP_PLUGIN (user_data);
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (self);
	NMSettingVpn *s_vpn;
	const char *user, *password, *domain;
	gchar *username;

	remove_timeout_handler (NM_PPTP_PLUGIN (user_data));

	s_vpn = nm_connection_get_setting_vpn (priv->connection);
	g_assert (s_vpn);

	/* Username; try PPTP specific username first, then generic username */
	user = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_USER);
	if (!user || !strlen (user))
		user = nm_setting_vpn_get_user_name (s_vpn);
	if (!user || !strlen (user)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_VPN_PLUGIN_ERROR,
		                                               NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                               _("Missing VPN username."));
		return FALSE;
	}

	password = nm_setting_vpn_get_secret (s_vpn, NM_PPTP_KEY_PASSWORD);
	if (!password || !strlen (password)) {
		g_dbus_method_invocation_return_error_literal (invocation,
		                                               NM_VPN_PLUGIN_ERROR,
		                                               NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION,
		                                               _("Missing or invalid VPN password."));
		return FALSE;;
	}

	/* Domain is optional */
	domain = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_DOMAIN);

	/* Success */
	if (domain && strlen (domain))
		username = g_strdup_printf ("%s\\%s", domain, user);
	else
		username = g_strdup (user);

	nmdbus_pptp_ppp_complete_need_secrets (object, invocation, username, password);
	g_free (username);

	return TRUE;
}

static gboolean
handle_set_state (NMDBusPptpPpp *object,
                  GDBusMethodInvocation *invocation,
                  guint arg_state,
                  gpointer user_data)
{
	remove_timeout_handler (NM_PPTP_PLUGIN (user_data));
	if (arg_state == NM_PPP_STATUS_DEAD || arg_state == NM_PPP_STATUS_DISCONNECT)
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (user_data), NULL);

	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}

static gboolean
handle_set_ip4_config (NMDBusPptpPpp *object,
                       GDBusMethodInvocation *invocation,
                       GVariant *arg_config,
                       gpointer user_data)
{
	NMPptpPlugin *plugin = NM_PPTP_PLUGIN (user_data);
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	GVariantIter iter;
	const char *key;
	GVariant *value;
	GVariantBuilder builder;
	GVariant *new_config;

	remove_timeout_handler (plugin);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_variant_iter_init (&iter, arg_config);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &value)) {
		g_variant_builder_add (&builder, "{sv}", key, value);
		g_variant_unref (value);
	}

	/* Insert the external VPN gateway into the table, which the pppd plugin
	 * simply doesn't know about.
	 */
	g_variant_builder_add (&builder, "{sv}", NM_PPTP_KEY_GATEWAY, g_variant_new_uint32 (priv->naddr));
	new_config = g_variant_builder_end (&builder);
	g_variant_ref_sink (new_config);

	nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (plugin), new_config);
	g_variant_unref (new_config);

	g_dbus_method_invocation_return_value (invocation, NULL);
	return TRUE;
}


static gboolean
lookup_gateway (NMPptpPlugin *self,
                const char *src,
                GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (self);
	const char *p = src;
	gboolean is_name = FALSE;
	struct in_addr naddr;
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int err;
	char buf[INET_ADDRSTRLEN];

	g_return_val_if_fail (src != NULL, FALSE);

	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

	while (*p) {
		if (*p != '.' && !isdigit (*p)) {
			is_name = TRUE;
			break;
		}
		p++;
	}

	if (is_name == FALSE) {
		errno = 0;
		if (inet_pton (AF_INET, src, &naddr) <= 0) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
			             _("couldn’t convert PPTP VPN gateway IP address “%s” (%d)"),
			             src, errno);
			return FALSE;
		}
		priv->naddr = naddr.s_addr;
		priv->saddr = g_strdup (src);
		return TRUE;
	}

	/* It's a hostname, resolve it */
	memset (&hints, 0, sizeof (hints));
	hints.ai_family = AF_INET;
	hints.ai_flags = AI_ADDRCONFIG;
	err = getaddrinfo (src, NULL, &hints, &result);
	if (err != 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("couldn’t look up PPTP VPN gateway IP address “%s” (%d)"),
		             src, err);
		return FALSE;
	}

	/* If the hostname resolves to multiple IP addresses, use the first one.
	 * FIXME: maybe we just want to use a random one instead?
	 */
	memset (&naddr, 0, sizeof (naddr));
	for (rp = result; rp; rp = rp->ai_next) {
		if (   (rp->ai_family == AF_INET)
		    && (rp->ai_addrlen == sizeof (struct sockaddr_in))) {
			struct sockaddr_in *inptr = (struct sockaddr_in *) rp->ai_addr;

			memcpy (&naddr, &(inptr->sin_addr), sizeof (struct in_addr));
			break;
		}
	}
	freeaddrinfo (result);

	if (naddr.s_addr == 0) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             _("no usable addresses returned for PPTP VPN gateway “%s”"),
		             src);
		return FALSE;
	}

	priv->naddr = naddr.s_addr;
	priv->saddr = g_strdup (inet_ntop (AF_INET, &naddr, buf, sizeof (buf)));

	return TRUE;
}


static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection *connection,
              GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	const char *gwaddr;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_assert (s_vpn);

	gwaddr = nm_setting_vpn_get_data_item (s_vpn, NM_PPTP_KEY_GATEWAY);
	if (!gwaddr || !strlen (gwaddr)) {
		g_set_error_literal (error,
		                     NM_VPN_PLUGIN_ERROR,
		                     NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		                     _("Invalid or missing PPTP gateway."));
		return FALSE;
	}

	/* Look up the IP address of the PPtP server; if the server has multiple
	 * addresses, because we can't get the actual IP used back from pptp itself,
	 * we need to do name->addr conversion here and only pass the IP address
	 * down to pppd/pptp.  If only pptp could somehow return the IP address it's
	 * using for the connection, we wouldn't need to do this...
	 */
	if (!lookup_gateway (NM_PPTP_PLUGIN (plugin), gwaddr, error))
		return FALSE;

	if (!nm_pptp_properties_validate (s_vpn, error))
		return FALSE;

	if (!nm_pptp_secrets_validate (s_vpn, error))
		return FALSE;

	g_clear_object (&priv->connection);
	priv->connection = g_object_ref (connection);

	if (   getenv ("NM_PPP_DUMP_CONNECTION")
	    || _LOGD_enabled ())
		nm_connection_dump (connection);

	return nm_pptp_start_pppd_binary (NM_PPTP_PLUGIN (plugin),
	                                  s_vpn,
	                                  error);
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn;
	NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

	g_return_val_if_fail (NM_IS_VPN_SERVICE_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = nm_connection_get_setting_vpn (connection);

	nm_setting_get_secret_flags (NM_SETTING (s_vpn), NM_PPTP_KEY_PASSWORD, &flags, NULL);

	/* Don't need the password if it's not required */
	if (flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
		return FALSE;

	/* Don't need the password if we already have one */
	if (nm_setting_vpn_get_secret (NM_SETTING_VPN (s_vpn), NM_PPTP_KEY_PASSWORD))
		return FALSE;

	/* Otherwise we need a password */
	*setting_name = NM_SETTING_VPN_SETTING_NAME;
	return TRUE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		_LOGI ("Terminated ppp daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	g_clear_object (&priv->connection);
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

	return TRUE;
}

static void
state_changed_cb (GObject *object, NMVpnServiceState state, gpointer user_data)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);

	switch (state) {
	case NM_VPN_SERVICE_STATE_STARTED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		break;
	case NM_VPN_SERVICE_STATE_UNKNOWN:
	case NM_VPN_SERVICE_STATE_INIT:
	case NM_VPN_SERVICE_STATE_SHUTDOWN:
	case NM_VPN_SERVICE_STATE_STOPPING:
	case NM_VPN_SERVICE_STATE_STOPPED:
		remove_timeout_handler (NM_PPTP_PLUGIN (object));
		g_clear_object (&priv->connection);
		if (priv->saddr) {
			g_free (priv->saddr);
			priv->saddr = NULL;
		}
		break;
	default:
		break;
	}
}

static void
dispose (GObject *object)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);
	GDBusInterfaceSkeleton *skeleton = NULL;

	if (priv->dbus_skeleton)
		skeleton = G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton);

	if (skeleton) {
		if (g_dbus_interface_skeleton_get_object_path (skeleton))
			g_dbus_interface_skeleton_unexport (skeleton);
		g_signal_handlers_disconnect_by_func (skeleton, handle_need_secrets, object);
		g_signal_handlers_disconnect_by_func (skeleton, handle_set_state, object);
		g_signal_handlers_disconnect_by_func (skeleton, handle_set_ip4_config, object);
	}

	g_clear_object (&priv->connection);
	if (priv->saddr) {
		g_free (priv->saddr);
		priv->saddr = NULL;
	}

	G_OBJECT_CLASS (nm_pptp_plugin_parent_class)->dispose (object);
}

static void
nm_pptp_plugin_init (NMPptpPlugin *plugin)
{
}

static void
nm_pptp_plugin_class_init (NMPptpPluginClass *pptp_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (pptp_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (pptp_class);

	g_type_class_add_private (object_class, sizeof (NMPptpPluginPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

static GInitableIface *ginitable_parent_iface = NULL;

static gboolean
init_sync (GInitable *object, GCancellable *cancellable, GError **error)
{
	NMPptpPluginPrivate *priv = NM_PPTP_PLUGIN_GET_PRIVATE (object);
	GDBusConnection *bus;

	if (!ginitable_parent_iface->init (object, cancellable, error))
		return FALSE;

	g_signal_connect (G_OBJECT (object), "state-changed", G_CALLBACK (state_changed_cb), NULL);

	bus = nm_vpn_service_plugin_get_connection (NM_VPN_SERVICE_PLUGIN (object)),
	priv->dbus_skeleton = nmdbus_pptp_ppp_skeleton_new ();
	if (!g_dbus_interface_skeleton_export (G_DBUS_INTERFACE_SKELETON (priv->dbus_skeleton),
	                                       bus,
	                                       NM_DBUS_PATH_PPTP_PPP,
	                                       error)) {
		g_prefix_error (error, "Failed to export helper interface: ");
		g_object_unref (bus);
		return FALSE;
	}

	g_dbus_connection_register_object (bus, NM_DBUS_PATH_PPTP_PPP,
	                                   nmdbus_pptp_ppp_interface_info (),
	                                   NULL, NULL, NULL, NULL);

	g_signal_connect (priv->dbus_skeleton, "handle-need-secrets", G_CALLBACK (handle_need_secrets), object);
	g_signal_connect (priv->dbus_skeleton, "handle-set-state", G_CALLBACK (handle_set_state), object);
	g_signal_connect (priv->dbus_skeleton, "handle-set-ip4-config", G_CALLBACK (handle_set_ip4_config), object);

	g_object_unref (bus);
	return TRUE;
}

static void
nm_pptp_plugin_initable_iface_init (GInitableIface *iface)
{
	ginitable_parent_iface = g_type_interface_peek_parent (iface);
	iface->init = init_sync;
}

NMPptpPlugin *
nm_pptp_plugin_new (const char *bus_name)
{
	NMPptpPlugin *plugin;
	GError *error = NULL;

	plugin = g_initable_new (NM_TYPE_PPTP_PLUGIN, NULL, &error,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME, bus_name,
	                         NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER, !gl.debug,
	                         NULL);
	if (!plugin) {
		_LOGW ("Failed to initialize a plugin instance: %s", error->message);
		g_error_free (error);
	}

	return plugin;
}

static void
quit_mainloop (NMPptpPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMPptpPlugin *plugin;
	GMainLoop *main_loop;
	gboolean persist = FALSE;
	GOptionContext *opt_ctx = NULL;
	char *conntrack_module[] = { "/sbin/modprobe", "nf_conntrack_pptp", NULL };
	GError *error = NULL;
	gs_free char *bus_name_free = NULL;
	const char *bus_name;
	char sbuf[30];

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, N_("Don’t quit when VPN connection terminates"), NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &gl.debug, N_("Enable verbose debug logging (may expose passwords)"), NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name_free, N_("D-Bus name to use for this instance"), NULL },
		{NULL}
	};

	nm_g_type_init ();

	/* locale will be set according to environment LC_* variables */
	setlocale (LC_ALL, "");

	bindtextdomain (GETTEXT_PACKAGE, NM_PPTP_LOCALEDIR);
	bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
	textdomain (GETTEXT_PACKAGE);

	/* Parse options */
	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_translation_domain (opt_ctx, GETTEXT_PACKAGE);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	g_option_context_set_summary (opt_ctx,
	    _("nm-pptp-service provides integrated PPTP VPN capability (compatible with Microsoft and other implementations) to NetworkManager."));

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing the command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_error_free (error);
		return EXIT_FAILURE;
	}
	g_option_context_free (opt_ctx);

	bus_name = bus_name_free ?: NM_DBUS_SERVICE_PPTP;

	if (getenv ("NM_PPP_DEBUG"))
		gl.debug = TRUE;

	gl.log_level = _nm_utils_ascii_str_to_int64 (getenv ("NM_VPN_LOG_LEVEL"),
	                                             10, 0, LOG_DEBUG,
	                                             gl.debug ? LOG_INFO : LOG_NOTICE);

	_LOGD ("nm-pptp-service (version " DIST_VERSION ") starting...");
	_LOGD ("   uses%s --bus-name \"%s\"", bus_name_free ? "" : " default", bus_name);

	setenv ("NM_VPN_LOG_LEVEL", nm_sprintf_buf (sbuf, "%d", gl.log_level), TRUE);
	setenv ("NM_VPN_LOG_PREFIX_TOKEN", nm_sprintf_buf (sbuf, "%ld", (long) getpid ()), TRUE);
	setenv ("NM_DBUS_SERVICE_PPTP", bus_name, 0);

	plugin = nm_pptp_plugin_new (bus_name);
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	if (!persist)
		g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), main_loop);

	/* Newer kernels require nf_conntrack_pptp kernel module so that PPTP
	 * worked correctly. Load the module now. Ignore errors, the module
	 * might not exist (older kernels).
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1187328
	 */
	if (!g_spawn_sync (NULL, conntrack_module, NULL, 0, NULL, NULL, NULL, NULL, NULL, &error)) {
		_LOGW ("modprobing nf_conntrack_pptp failed: %s", error->message);
		g_error_free (error);
	}

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	return EXIT_SUCCESS;
}
