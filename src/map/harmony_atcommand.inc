#ifndef WIN32
	#include <sys/socket.h>
	#include <netinet/in.h>
	#include <arpa/inet.h>
#endif

ACMD(reloadgrfintegrity) {
	harm_funcs->zone_grf_reload();
	clif->message(fd, "GRF integrity definitions reloaded.");
	return true;
}

ACMD(reloadharmony) {
	harm_funcs->zone_reload();
	clif->message(fd, "Harmony configuration reloaded.");
	return true;
}

ACMD(showautoban) {
	harm_funcs->zone_autoban_show(fd);
	return true;
}

ACMD(liftautoban) {
	uint32 ip;

	if (!message || !*message) {
	__usage:
		clif->message(fd, "Usage:");
		clif->message(fd, "	@liftautoban <IP address> / all");
		return false;
	}
	
	if ( (ip=inet_addr(message)) != INADDR_NONE)
		ip = htonl(ip);
	else if (stricmp(message, "all") == 0)
		ip = 0;
	else
		goto __usage;

	harm_funcs->zone_autoban_lift(ip);

	if (ip != 0) {
		sprintf(atcmd_output, "Unblocked %u.%u.%u.%u.", CONVIP(ip));
		clif->message(fd, atcmd_output);
	} else {
		clif->message(fd, "Removed all autoban entries.");
	}

	return true;	
}

/*==========================================
 * Network Information
 *------------------------------------------*/
ACMD(netinfo)
{
	uint32 ip;
	int8 mac_address[20];

	nullpo_retr(-1,sd);
	sprintf(atcmd_output, "Network Information Request for %s (AID %d | CID %d)", sd->status.name, sd->status.account_id, sd->status.char_id);
	clif->message(fd,atcmd_output);
	harm_funcs->zone_get_mac_address(sd->fd, mac_address);
	sprintf(atcmd_output, "- Mac Address : %s", mac_address);
	clif->message(fd,atcmd_output);

	ip = session[sd->fd]->client_addr;
	sprintf(atcmd_output, "- IP Address : %d.%d.%d.%d", CONVIP(ip));
	clif->message(fd,atcmd_output);

	return true;
}

/*==========================================
 * Mac Address Ban
 *------------------------------------------*/
ACMD(showmacban)
{
	SqlStmt* stmt = SQL->StmtMalloc(map->mysql_handle);
	char mac_address[20];
	char comment[90];

	if (SQL_SUCCESS != SQL->StmtPrepare(stmt, "SELECT `mac`, `comment` FROM mac_bans ORDER BY `mac` DESC LIMIT 100") ||
		SQL_SUCCESS != SQL->StmtExecute(stmt) ||
		SQL_SUCCESS != SQL->StmtBindColumn(stmt, 0,  SQLDT_STRING, mac_address, sizeof(mac_address), NULL, NULL) ||
		SQL_SUCCESS != SQL->StmtBindColumn(stmt, 1,  SQLDT_STRING, comment, sizeof(comment), NULL, NULL)) {
			Sql_ShowDebug(map->mysql_handle);
	} else {
		clif->message(fd, "Mac address bans:");
		while (SQL_SUCCESS == SQL->StmtNextRow(stmt)) {
			// Gravity client crashes when this sequence occurs on a bad position :(
			char *p = comment;
			while ((p = strstr(p, " : ")) != NULL)
				*(++p) = ';';

			sprintf(atcmd_output, "%-20s%s", mac_address, comment);
			clif->message(fd, atcmd_output);
		}
	}
	SQL->StmtFree(stmt);

	return true;
}

ACMD(macban)
{
	char mac_address[20];
	char buf1[400];
	char buf2[400];
	TBL_PC *src_sd = (TBL_PC*) session[fd]->session_data;
	size_t len;

	if (sd->fd == fd) {
		unsigned int d[6];
		char comment[60];
		*comment = 0;

		if (!message || !*message || sscanf(message, "%2x:%2x:%2x:%2x:%2x:%2x %59[^\n]", &d[0], &d[1], &d[2], &d[3], &d[4], &d[5], comment) < 6) {
			clif->message(fd, "Incorrect syntax. Use '@macban <MAC address> [<comment>]' or '#macban <player name> [<comment>]'");
			return false;
		}

		safesnprintf(mac_address, sizeof(mac_address), "%02x:%02x:%02x:%02x:%02x:%02x", d[0], d[1], d[2], d[3], d[4], d[5]);
		len = safesnprintf(buf1, sizeof(buf1)/2, "%s (%u) banned %s : %s", src_sd->status.name, src_sd->status.account_id, mac_address, strlen(comment) > 1 ? comment : "(no comment)");
	} else {
		harm_funcs->zone_get_mac_address(sd->fd, (signed char *)mac_address);
		len = safesnprintf(buf1, sizeof(buf1)/2, "%s (%u) banned %s (%u) : %s", src_sd->status.name, src_sd->status.account_id, sd->status.name, sd->status.account_id, strlen(message) > 1 ? message : "(no comment)");
	}

	SQL->EscapeStringLen(map->mysql_handle, buf2, buf1, len);
	sprintf(buf1, "INSERT INTO `mac_bans` (`mac`, `comment`) VALUES ('%s', '%s')", mac_address, buf2);
	if( SQL_ERROR == SQL->QueryStr(map->mysql_handle, buf1) )
	{
		Sql_ShowDebug(map->mysql_handle);
		return false;
	}

	sprintf(atcmd_output, "Mac Address %s banned.", mac_address);
	clif->message(fd, atcmd_output);
	return true;
}

ACMD(liftmacban)
{
	char buf[41];
	size_t len = min(20, strlen(message));

	SQL->EscapeStringLen(map->mysql_handle, buf, message, len);
	sprintf(atcmd_output, "SELECT 1 FROM `mac_bans` WHERE `mac` LIKE '%s'", buf);
	if( SQL_ERROR == SQL->QueryStr(map->mysql_handle, atcmd_output) )
	{
		Sql_ShowDebug(map->mysql_handle);
		return false;
	}

	if (SQL->NumRows(map->mysql_handle) == 0) {
		sprintf(atcmd_output, "No MAC ban found for address '%s'", buf);
		clif->message(fd, atcmd_output);
		return true;
	}

	sprintf(atcmd_output, "DELETE FROM `mac_bans` WHERE `mac` LIKE '%s'", buf);
	if( SQL_ERROR == SQL->QueryStr(map->mysql_handle, atcmd_output) )
	{
		Sql_ShowDebug(map->mysql_handle);
		return false;
	}

	sprintf(atcmd_output, "Mac Address '%s' unbanned.", message);
	clif->message(fd, atcmd_output);
	return true;
}

ACMD(checkhotpatch)
{
	if (!harm_funcs->zone_run_hotpatch(fd, sd->fd, message, false)) {
		sprintf(atcmd_output, "Patch '%s' does not exist.", message);
		clif->message(fd, atcmd_output);
	} else {
		sprintf(atcmd_output, "Patch '%s' started, waiting for reply... This can take up to a few minutes.", message);
		clif->message(fd, atcmd_output);
	}
	return true;
}

ACMD(runhotpatch)
{
	if (!harm_funcs->zone_run_hotpatch(fd, sd->fd, message, true)) {
		sprintf(atcmd_output, "Patch '%s' does not exist.", message);
		clif->message(fd, atcmd_output);
	} else {
		sprintf(atcmd_output, "Patch '%s' started, waiting for reply... This can take up to a few minutes.", message);
		clif->message(fd, atcmd_output);
	}
	return true;
}
