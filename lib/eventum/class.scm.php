<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 encoding=utf-8: */
// +----------------------------------------------------------------------+
// | Eventum - Issue Tracking System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2003 - 2008 MySQL AB                                   |
// | Copyright (c) 2008 - 2010 Sun Microsystem Inc.                       |
// | Copyright (c) 2011 - 2014 Eventum Team.                              |
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
// | 51 Franklin Street, Suite 330                                          |
// | Boston, MA 02110-1301, USA.                                          |
// +----------------------------------------------------------------------+
// | Authors: João Prado Maia <jpm@mysql.com>                             |
// | Authors: Elan Ruusamäe <glen@delfi.ee>                               |
// +----------------------------------------------------------------------+

/**
 * Class to handle the business logic related to the source control management
 * integration features of the application.
 */
class SCM
{
    /**
     * Method used to remove all checkins associated with a list of issues.
     *
     * @param   array $ids The list of issues
     * @return  boolean
     */
    public static function removeByIssues($ids)
    {
        $items = DB_Helper::buildList($ids);
        $stmt = "DELETE FROM
                    {{%issue_checkin}}
                 WHERE
                    isc_iss_id IN ($items)";
        try {
            DB_Helper::getInstance()->query($stmt, $ids);
        } catch (DbException $e) {
            return false;
        }

        return true;
    }

    /**
     * Method used to remove a specific list of checkins
     *
     * @param   int[] $items list to remove
     * @return  integer 1 if the update worked, -1 otherwise
     */
    public static function remove($items)
    {
        $itemlist = DB_Helper::buildList($items);

        $stmt = "SELECT
                    isc_iss_id
                 FROM
                    {{%issue_checkin}}
                 WHERE
                    isc_id IN ($itemlist)";
        $issue_id = DB_Helper::getInstance()->getOne($stmt, $items);

        $stmt = "DELETE FROM
                    {{%issue_checkin}}
                 WHERE
                    isc_id IN ($itemlist)";
        try {
            DB_Helper::getInstance()->query($stmt, $items);
        } catch (DbException $e) {
            return -1;
        }

        // need to mark this issue as updated
        Issue::markAsUpdated($issue_id);
        // need to save a history entry for this
        $summary = ev_gettext('SCM Checkins removed by %1$s', User::getFullName(Auth::getUserID()));
        History::add($issue_id, Auth::getUserID(), History::getTypeID('scm_checkin_removed'), $summary);

        return 1;
    }

    /**
     * Method used to get the full list of checkins associated with an issue.
     *
     * @param   integer $issue_id The issue ID
     * @return  array The list of checkins
     */
    public static function getCheckinList($issue_id)
    {
        $stmt = "SELECT
                    *
                 FROM
                    {{%issue_checkin}}
                 WHERE
                    isc_iss_id=?
                 ORDER BY
                    isc_created_date ASC";
        try {
            $res = DB_Helper::getInstance()->getAll($stmt, array($issue_id));
        } catch (DbException $e) {
            return array();
        }

        if (empty($res)) {
            return array();
        }

        foreach ($res as $i => &$checkin) {
            $scm = self::getScmCheckinByName($checkin['isc_reponame']);

            // add ADDED and REMOVED fields
            $checkin['added'] = !isset($checkin['isc_old_version']);
            $checkin['removed'] = !isset($checkin['isc_new_version']);

            $checkin["isc_commit_msg"] = Link_Filter::processText(
                Issue::getProjectID($issue_id), nl2br(htmlspecialchars($checkin["isc_commit_msg"]))
            );
            $checkin["checkout_url"] = $scm->getCheckoutUrl($checkin);
            $checkin["diff_url"] = $scm->getDiffUrl($checkin);
            $checkin["scm_log_url"] = $scm->getLogUrl($checkin);
            $checkin["isc_created_date"] = Date_Helper::getFormattedDate($checkin["isc_created_date"]);
        }

        return $res;
    }

    /**
     * Method used to associate checkins to an existing issue
     *
     * @param   integer $issue_id The ID of the issue.
     * @param   string $commit_time Time when commit occurred (in UTC)
     * @param   string $scm_name SCM definition name in Eventum
     * @param   string $username SCM user doing the checkin.
     * @param   string $commit_msg Message associated with the SCM commit.
     * @param   array $files Files info with their version numbers changes made on.
     * @return  integer 1 if the update worked, -1 otherwise
     */
    public static function addCheckins($issue_id, $commit_time, $scm_name, $username, $commit_msg, $files)
    {
        // validate that $scm_name is valid
        // this will throw if invalid
        self::getScmCheckinByName($scm_name);

        // TODO: add workflow pre method first, so it may setup username, etc
        $usr_id = APP_SYSTEM_USER_ID;

        // workflow needs to know project_id to find out which workflow class to use.
        $prj_id = Issue::getProjectID($issue_id);

        foreach ($files as $file) {
            self::insertCheckin($issue_id, $commit_time, $scm_name, $file, $username, $commit_msg);
        }

        // need to mark this issue as updated
        Issue::markAsUpdated($issue_id, 'scm checkin');

        // need to save a history entry for this
        // TRANSLATORS: %1: scm username
        $summary = ev_gettext('SCM Checkins associated by SCM user "%1$s"', $username);
        History::add($issue_id, $usr_id, History::getTypeID('scm_checkin_associated'), $summary);

        Workflow::handleSCMCheckins($prj_id, $issue_id, $files, $username, $commit_msg);

        return 1;
    }

    /**
     * insert single checkin to database
     *
     * @param   integer $issue_id The ID of the issue.
     * @param   string $commit_time Time when commit occurred (in UTC)
     * @param   string $scm_name SCM definition name in Eventum
     * @param   array $file File info with their version numbers changes made on.
     * @param   string $username SCM user doing the checkin.
     * @param   string $commit_msg Message associated with the SCM commit.
     * @return  integer 1 if the update worked, -1 otherwise
     */
    protected static function insertCheckin($issue_id, $commit_time, $scm_name, $file, $username, $commit_msg)
    {
        $stmt = "INSERT INTO
                    {{%issue_checkin}}
                 (
                    isc_iss_id,
                    isc_reponame,
                    isc_module,
                    isc_filename,
                    isc_old_version,
                    isc_new_version,
                    isc_created_date,
                    isc_username,
                    isc_commit_msg
                 ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?
                 )";
        $params = array(
            $issue_id,
            $scm_name,
            $file['module'],
            $file['file'],
            $file['old_version'],
            $file['new_version'],
            $commit_time,
            $username,
            $commit_msg,
        );
        try {
            DB_Helper::getInstance()->query($stmt, $params);
        } catch (DbException $e) {
            return -1;
        }

        return 1;
    }

    /**
     * Get ScmCheckin based on SCM name
     *
     * @param string $scm_name
     * @return ScmCheckin
     * @throws Exception
     */
    private static function getScmCheckinByName($scm_name)
    {
        static $instances;

        if (isset($instances[$scm_name])) {
            return $instances[$scm_name];
        }

        $setup = &Setup::load();

        // handle legacy setup, convert existing config to be known under name 'default'
        if (!isset($setup['scm'])) {
            $scm = array(
                'name' => 'default',
                'checkout_url' => $setup['checkout_url'],
                'diff_url' => $setup['diff_url'],
                'log_url' => $setup['scm_log_url'],
            );
            $setup['scm'][$scm['name']] = $scm;
            Setup::save($setup);
        }

        if (!isset($setup['scm'][$scm_name])) {
            throw new Exception("SCM '$scm_name' not defined");
        }

        return $instances[$scm_name] = new ScmCheckin($setup['scm'][$scm_name]);
    }
}
