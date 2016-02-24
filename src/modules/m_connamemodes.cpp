/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Johanna Abrahamsson <johanna@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "u_listmode.h"

/** Handle channel mode +u and +U
 */
class ConnNameModeu : public ListModeBase
{
 public:

	ConnNameModeu(Module* Creator)
		: ListModeBase(Creator, "connamemodesmallu", 'u', "End of channel connamefilter list", 991, 990, false , "connamemodes")
	{
		levelrequired = OP_VALUE;
	}

};

class ConnNameModeU : public ListModeBase
{
 public:

	ConnNameModeU(Module* Creator)
		: ListModeBase(Creator, "connamemodebigu", 'U', "End of channel connamefilter list", 993, 992, false , "connamemodes")
	{
		levelrequired = OP_VALUE;
	}

};

class ModuleConnNameModes : public Module
{

	ConnNameModeu cnmu;
	ConnNameModeU cnmU;

 public:
	ModuleConnNameModes()
		: cnmu(this)
		, cnmU(this)
	{
	}

	void ReadConfig() 
	{
		cnmu.DoRehash();
		cnmU.DoRehash();
	}

	void init()
	{
		ReadConfig();
		ServerInstance->Modules->AddService(cnmu);
		ServerInstance->Modules->AddService(cnmU);
		Implementation eventlist[] = { I_OnUserPreJoin, I_OnWhois, I_OnRehash };
		ServerInstance->Modules->Attach(eventlist, this, sizeof(eventlist)/sizeof(Implementation));
	}

	virtual ModResult OnUserPreJoin(User *user, Channel *chan, const char *cname, std::string &privs, const std::string &keygiven)
	{
		modelist* list = cnmu.extItem.get(chan);
		LocalUser *localUser=IS_LOCAL(user);
		if (!localUser)
			return MOD_RES_PASSTHRU;

		if (list)
		{
			for (modelist::iterator it = list->begin(); it != list->end(); it++)
			{
				if (!localUser->GetClass()->name.compare(it->mask))
				{
					localUser->WriteNumeric(489, "%s :Cannot join channel; No users from connection %s (+u)", cname, it->mask.c_str());
					return MOD_RES_DENY;
				}
			}
		}

		list = cnmU.extItem.get(chan);

		if (list && !list->empty())
		{
			for (modelist::iterator it = list->begin(); it != list->end(); it++)
			{
				if (!localUser->GetClass()->name.compare(it->mask))
				{
					return MOD_RES_PASSTHRU;
				}
			}
			localUser->WriteNumeric(489, "%s :Cannot join channel; Not on connection list (+U)", cname);
			return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}

	virtual void OnWhois(User* src, User* dst)
	{
		LocalUser* localuser = IS_LOCAL(dst);
		if ((src == dst || IS_OPER(src)) && localuser)
			ServerInstance->SendWhoisLine(src, dst, 671, src->nick+" "+dst->nick+" :is using connection "+localuser->GetClass()->name.c_str());
	}

	void OnRehash(User* user)
	{
		ReadConfig();
	}

	Version GetVersion()
	{
		return Version("Provides channel mode +u/+U to filter users based on connection name", VF_OPTCOMMON);
	}
};

MODULE_INIT(ModuleConnNameModes)
