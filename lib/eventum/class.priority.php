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
 * Class to handle project priority related issues.
 */

class Priority
{
    /**
     * Method used to quickly change the ranking of a reminder entry
     * from the administration screen.
     *
     * @param   integer $pri_id The reminder entry ID
     * @param   string $rank_type Whether we should change the reminder ID down or up (options are 'asc' or 'desc')
     * @return  boolean
     */
    public static function changeRank($prj_id, $pri_id, $rank_type)
    {
        // check if the current rank is not already the first or last one
        $ranking = self::_getRanking($prj_id);
        $ranks = array_values($ranking);
        $ids = array_keys($ranking);
        $last = end($ids);
        $first = reset($ids);
        if ((($rank_type == 'asc') && ($pri_id == $first)) ||
                (($rank_type == 'desc') && ($pri_id == $last))) {
            return false;
        }

        if ($rank_type == 'asc') {
            $diff = -1;
        } else {
            $diff = 1;
        }
        $new_rank = $ranking[$pri_id] + $diff;
        if (in_array($new_rank, $ranks)) {
            // switch the rankings here...
            $index = array_search($new_rank, $ranks);
            $replaced_pri_id = $ids[$index];
            $stmt = "UPDATE
                        {{%project_priority}}
                     SET
                        pri_rank=?
                     WHERE
                        pri_prj_id=? AND
                        pri_id=?";
            DB_Helper::getInstance()->query($stmt, array($ranking[$pri_id], $prj_id, $replaced_pri_id));
        }
        $stmt = "UPDATE
                    {{%project_priority}}
                 SET
                    pri_rank=?
                 WHERE
                    pri_prj_id=? AND
                    pri_id=?";
        DB_Helper::getInstance()->query($stmt, array($new_rank, $prj_id, $pri_id));

        return true;
    }

    /**
     * Returns an associative array with the list of reminder IDs and
     * their respective ranking.
     *
     * @param   integer $prj_id The ID of the project
     * @return  array The list of reminders
     */
    private function _getRanking($prj_id)
    {
        $stmt = "SELECT
                    pri_id,
                    pri_rank
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_prj_id=?
                 ORDER BY
                    pri_rank ASC";
        try {
            $res = DB_Helper::getInstance()->getPair($stmt, array($prj_id));
        } catch (DbException $e) {
            return array();
        }

        return $res;
    }

    /**
     * Method used to get the full details of a priority.
     *
     * @param   integer $pri_id The priority ID
     * @return  array The information about the priority provided
     */
    public static function getDetails($pri_id)
    {
        $stmt = "SELECT
                    *
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_id=?";
        try {
            $res = DB_Helper::getInstance()->getRow($stmt, array($pri_id));
        } catch (DbException $e) {
            return "";
        }

        return $res;
    }

    /**
     * Method used to remove all priorities related to a set of
     * specific projects.
     *
     * @param   array $ids The project IDs to be removed
     * @return  boolean Whether the removal worked or not
     */
    public function removeByProjects($ids)
    {
        $items = DB_Helper::buildList($ids);
        $stmt = "DELETE FROM
                    {{%project_priority}}
                 WHERE
                    pri_prj_id IN ($items)";
        try {
            DB_Helper::getInstance()->query($stmt, $ids);
        } catch (DbException $e) {
            return false;
        }

        return true;
    }

    /**
     * Method used to remove user-selected priorities from the
     * database.
     *
     * @return  boolean Whether the removal worked or not
     */
    public static function remove()
    {
        $items = $_POST["items"];
        $itemlist = DB_Helper::buildList($items);
        $stmt = "DELETE FROM
                    {{%project_priority}}
                 WHERE
                    pri_id IN ($itemlist)";
        try {
            DB_Helper::getInstance()->query($stmt, $items);
        } catch (DbException $e) {
            return false;
        }

        return true;
    }

    /**
     * Method used to update the values stored in the database.
     * Typically the user would modify the title of the priority in
     * the application and this method would be called.
     *
     * @return  integer 1 if the update worked properly, any other value otherwise
     */
    public static function update()
    {
        if (Validation::isWhitespace($_POST["title"])) {
            return -2;
        }
        $stmt = "UPDATE
                    {{%project_priority}}
                 SET
                    pri_title=?,
                    pri_rank=?
                 WHERE
                    pri_prj_id=? AND
                    pri_id=?";
        try {
            DB_Helper::getInstance()->query($stmt, array($_POST["title"], $_POST['rank'], $_POST["prj_id"], $_POST["id"]));
        } catch (DbException $e) {
            return -1;
        }

        return 1;
    }

    /**
     * Method used to add a new priority to the application.
     *
     * @return  integer 1 if the update worked properly, any other value otherwise
     */
    public static function insert()
    {
        if (Validation::isWhitespace($_POST["title"])) {
            return -2;
        }
        $stmt = "INSERT INTO
                    {{%project_priority}}
                 (
                    pri_prj_id,
                    pri_title,
                    pri_rank
                 ) VALUES (
                    ?, ?, ?
                 )";
        try {
            DB_Helper::getInstance()->query($stmt, array($_POST["prj_id"], $_POST["title"], $_POST['rank']));
        } catch (DbException $e) {
            return -1;
        }

        return 1;
    }

    /**
     * Method used to get the full list of priorities associated with
     * a specific project.
     *
     * @param   integer $prj_id The project ID
     * @return  array The full list of priorities
     */
    public static function getList($prj_id)
    {
        $stmt = "SELECT
                    pri_id,
                    pri_title,
                    pri_rank
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_prj_id=?
                 ORDER BY
                    pri_rank ASC";
        try {
            $res = DB_Helper::getInstance()->getAll($stmt, array($prj_id));
        } catch (DbException $e) {
            return "";
        }

        return $res;
    }

    /**
     * Method used to get the title for a priority ID.
     *
     * @param   integer $pri_id The priority ID
     * @return  string The priority title
     */
    public static function getTitle($pri_id)
    {
        $stmt = "SELECT
                    pri_title
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_id=?";
        try {
            $res = DB_Helper::getInstance()->getOne($stmt, array($pri_id));
        } catch (DbException $e) {
            return "";
        }

        return $res;
    }

    /**
     * Method used to get the list of priorities as an associative array in the
     * style of (id => title)
     *
     * @param   integer $prj_id The project ID
     * @return  array The list of priorities
     */
    public static function getAssocList($prj_id)
    {
        static $list;

        if (count(@$list[$prj_id]) > 0) {
            return $list[$prj_id];
        }

        $stmt = "SELECT
                    pri_id,
                    pri_title
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_prj_id=?
                 ORDER BY
                    pri_rank ASC";
        try {
            $res = DB_Helper::getInstance()->getPair($stmt, array($prj_id));
        } catch (DbException $e) {
            return "";
        }

        $list[$prj_id] = $res;

        return $res;
    }

    /**
     * Method used to get the pri_id of a project by priority title.
     *
     * @param   integer $prj_id The project ID
     * @param   string $pri_title The priority title
     * @return  integer $pri_id The priority ID
     */
    public function getPriorityID($prj_id, $pri_title)
    {
        $stmt = "SELECT
                    pri_id
                 FROM
                    {{%project_priority}}
                 WHERE
                    pri_prj_id=?
                    AND pri_title = ?";

        try {
            $res = DB_Helper::getInstance()->getOne($stmt, array($prj_id, $pri_title));
        } catch (DbException $e) {
            return null;
        }

        return $res;
    }
}
