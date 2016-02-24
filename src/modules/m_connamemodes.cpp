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
#include "listmode.h"

/** Handle channel mode +u and +U
 */
class ConnNameModeu : public ListModeBase
{
 public:

	ConnNameModeu(Module* Creator)
		: ListModeBase(Creator, "connamemodesmallu", 'u', "End of channel connamefilter list", 991, 990, false , "connamemodes") { }

};

class ConnNameModeU : public ListModeBase
{
 public:

	ConnNameModeU(Module* Creator)
		: ListModeBase(Creator, "connamemodebigu", 'U', "End of channel connamefilter list", 993, 992, false , "connamemodes") { }

};

class ModuleConnNameModes : public Module, public Whois::EventListener
{

	ConnNameModeu cnmu;
	ConnNameModeU cnmU;

 public:
	ModuleConnNameModes()
		: Whois::EventListener(this)
		, cnmu(this)
		, cnmU(this)
	{
	}

	ModResult OnUserPreJoin(LocalUser* user, Channel* chan, const std::string& cname, std::string& privs, const std::string& keygiven) CXX11_OVERRIDE
	{
		ListModeBase::ModeList* list = cnmu.GetList(chan);

		if (list)
		{
			for (ListModeBase::ModeList::iterator it = list->begin(); it != list->end(); it++)
			{
				if (!user->GetClass()->name.compare(it->mask))
				{
					user->WriteNumeric(489, "%s :Cannot join channel; No users from connection %s (+u)", cname.c_str(), it->mask.c_str());
					return MOD_RES_DENY;
				}
			}
		}

		list = cnmU.GetList(chan);

		if (list && !list->empty())
		{
			for (ListModeBase::ModeList::iterator it = list->begin(); it != list->end(); it++)
			{
				if (!user->GetClass()->name.compare(it->mask))
				{
					return MOD_RES_PASSTHRU;
				}
			}
			user->WriteNumeric(489, "%s :Cannot join channel; Not on connection list (+U)", cname.c_str());
			return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}

	void OnWhois(Whois::Context& whois) CXX11_OVERRIDE
	{
		LocalUser* localuser = IS_LOCAL(whois.GetTarget());
		if ((whois.IsSelfWhois() || whois.GetSource()->IsOper()) && localuser)
			whois.SendLine(671, ":is using connection %s", localuser->GetClass()->name.c_str());
	}

	void ReadConfig(ConfigStatus& status) CXX11_OVERRIDE
	{
		cnmu.DoRehash();
		cnmU.DoRehash();
	}

	Version GetVersion() CXX11_OVERRIDE
	{
		return Version("Provides channel mode +u/+U to filter users based on connection name", VF_OPTCOMMON);
	}
};

MODULE_INIT(ModuleConnNameModes)
