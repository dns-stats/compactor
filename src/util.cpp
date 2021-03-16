/*
 * Copyright 2019, 2021 Internet Corporation for Assigned Names and Numbers.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, you can obtain one at https://mozilla.org/MPL/2.0/.
 */

/*
 * Developed by Sinodun IT (www.sinodun.com)
 */

#include <cerrno>
#include <exception>
#include <thread>
#include <system_error>

#include "config.h"

#ifdef HAVE_PTHREAD
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#endif

#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <boost/filesystem.hpp>

#include "util.hpp"

namespace bf = boost::filesystem;

void set_file_owner_perms(const std::string& path,
                          const std::string& owner,
                          const std::string& group,
                          const std::string& write)
{
    if ( !owner.empty() || !group.empty() )
    {
        struct stat stat;

        if ( ::stat(path.c_str(), &stat) )
            throw std::system_error(errno, std::system_category(), "reading file info");

        uid_t uid = stat.st_uid;
        gid_t gid = stat.st_gid;

        if ( !owner.empty() )
        {
            struct passwd* pwd = ::getpwnam(owner.c_str());
            if ( !pwd )
                throw std::system_error(errno, std::system_category(), owner + ": no such user");
            uid = pwd->pw_uid;
        }
        if ( !group.empty() )
        {
            struct group* grp = ::getgrnam(group.c_str());
            if ( !grp )
                throw std::system_error(errno, std::system_category(), group + ": no such group");
            gid = grp->gr_gid;
        }

        if ( ::chown(path.c_str(), uid, gid) )
            throw std::system_error(errno, std::system_category(), "changing path ownership");
    }

    if ( write.empty() )
        return;

    bf::perms perms;

    if ( write == "owner" )
        perms = bf::owner_write;
    else if ( write == "group" )
        perms = bf::owner_write | bf::group_write;
    else if ( write == "all" )
        perms = bf::owner_write | bf::group_write | bf::others_write;
    else
        throw std::invalid_argument("write permission must be 'owner', 'group' or 'all'");

    bf::permissions(path, perms | bf::add_perms);
}

void set_thread_name(const char* name)
{
#if HAVE_PTHREAD_SETNAME_NP
  #ifdef __APPLE__
    pthread_setname_np(name);
  #else
    pthread_setname_np(pthread_self(), name);
  #endif
#else
    (void) name;
#endif
}
