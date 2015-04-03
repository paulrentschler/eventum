<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 encoding=utf-8: */
// +----------------------------------------------------------------------+
// | Eventum - Issue Tracking System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2012 - 2013 Eventum Team.                              |
// |                                                                      |
// | This program is free software; you can redistribute it and/or modify |
// | it under the terms of the GNU General Public License as published by |
// | the Free Software Foundation; either version 2 of the License, or    |
// | (at your option) any later version.                                  |
// |                                                                      |
// | This program is distributed in the hope that it will be useful,      |
// | but WITHOUT ANY WARRANTY; without even the implied warranty of       |
// | MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the        |
// | GNU General Public License for more details.                         |
// |                                                                      |
// | You should have received a copy of the GNU General Public License    |
// | along with this program; if not, write to:                           |
// |                                                                      |
// | Free Software Foundation, Inc.                                       |
// | 59 Temple Place - Suite 330                                          |
// | Boston, MA 02111-1307, USA.                                          |
// +----------------------------------------------------------------------+
// | Authors: Paul Rentschler <paul@rentschler.ws>                        |
// +----------------------------------------------------------------------+

/**
 * This auth backend trusts the web server (i.e., Apache) to set the REMOTE_USER
 * variable that provides the username of an already authenticated user that
 * should be trusted by Eventum.
 *
 * This backend will look for users in the default mysql backend and only allow
 * the user to proceed if a matching username is found.
 *
 * Set define('APP_AUTH_BACKEND', 'external_auth_backend') in the config file
 *
 * Set define('APP_AUTH_REMOTE_USER_SUFFIX', '@domain.tld') in the config file
 * to append something to the end of the REMOTE_USER variable before looking up
 * the user account by email address. If REMOTE_USER contains a valid email
 * address, APP_AUTH_REMOTE_USER_SUFFIX can remain blank which is the default
 * value.
 */
class External_Auth_Backend extends Mysql_Auth_Backend
{
    public function verifyPassword($login, $password)
    {
        $usr_id = User::getUserIDByEmail($login, true);
        $user = User::getDetails($usr_id);
        if ($user['usr_id'] > 0) {
            self::resetFailedLogins($usr_id);
            return true;
        } else {
            self::incrementFailedLogins($usr_id);
            return false;
        }
    }

    public function canUserUpdatePassword($usr_id)
    {
        return false;
    }

    public function isExternalAuth()
    {
        return true;
    }
}
