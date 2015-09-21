#include "../common/harmony.h"
#include "../common/socket.h"

BUILDIN(harm_map_multicount)
{
	const char *var = script_getstr(st,2);
	struct map_session_data *sd = script_rid2sd(st);
	int cnt = 0, m;

	if( sd && (m = map->mapname2mapid(var)) >= 0 )
	{
		struct map_session_data* pl_sd;
		struct s_mapiterator* iter;
		int8 s_mac_address[20], t_mac_address[20];
		bool byip = false;

		harm_funcs->zone_get_mac_address(sd->fd,s_mac_address);

		if( !strncmp((const char *)s_mac_address,"00:00:00:", 8) || !strncmp((const char *)s_mac_address,"0:0:0:", 6) || !strcmpi((const char *)s_mac_address,"00:53:45:00:00:00") )
			byip = true; // Ignored Mac Address

		iter = mapit_getallusers();
		for( pl_sd = (TBL_PC*)mapit->first(iter); mapit->exists(iter); pl_sd = (TBL_PC*)mapit->next(iter) )
		{
			if( pl_sd->bl.m != m )
				continue;
			if( !byip )
			{
				harm_funcs->zone_get_mac_address(pl_sd->fd,t_mac_address);
				if( !strcmpi((const char*)s_mac_address,(const char *)t_mac_address) )
					cnt++;
			}
			else if( session[sd->fd]->client_addr == session[pl_sd->fd]->client_addr )
				cnt++;
		}
		mapit->free(iter);
	}

	script_pushint(st,cnt);
	return 0;
}

BUILDIN(harm_bg_multicount)
{
	struct map_session_data *sd = script_rid2sd(st);
	int m = map->mapname2mapid("bat_room");
	int cnt = 0;
	
	if (sd)
	{
		struct map_session_data* pl_sd;
		struct s_mapiterator* iter;
		int8 s_mac_address[20], t_mac_address[20];
		bool byip = false;

		harm_funcs->zone_get_mac_address(sd->fd,s_mac_address);

		if( !strncmp((const char *)s_mac_address,"00:00:00:", 8) || !strncmp((const char *)s_mac_address,"0:0:0:", 6) || !strcmpi((const char *)s_mac_address,"00:53:45:00:00:00") )
			byip = true; // Ignored Mac Address
			
		iter = mapit_getallusers();
		for( pl_sd = (TBL_PC*)mapit->first(iter); mapit->exists(iter); pl_sd = (TBL_PC*)mapit->next(iter) )
		{
			if( pl_sd->bl.m != m && !map->list[sd->bl.m].flag.battleground )
				continue;
			if( !byip )
			{
				harm_funcs->zone_get_mac_address(pl_sd->fd,t_mac_address);
				if( !strcmpi((const char *)s_mac_address,(const char *)t_mac_address) )
					cnt++;
			}
			else if( session[sd->fd]->client_addr == session[pl_sd->fd]->client_addr )
				cnt++;
		}
		mapit->free(iter);
	}

	script_pushint(st,cnt);
	return 0;
}



