<?php
/* vim: set expandtab tabstop=4 shiftwidth=4 encoding=utf-8: */
// +----------------------------------------------------------------------+
// | Eventum - Issue Tracking System                                      |
// +----------------------------------------------------------------------+
// | Copyright (c) 2003 - 2008 MySQL AB                                   |
// | Copyright (c) 2008 - 2010 Sun Microsystem Inc.                       |
// | Copyright (c) 2011 - 2015 Eventum Team.                              |
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

class FAQ
{
    /**
     * Returns the list of FAQ entries associated to a given support level.
     *
     * @param   array $support_level_ids The support level IDs
     * @return  array The list of FAQ entries
     */
    public static function getListBySupportLevel($support_level_ids)
    {
        if (!is_array($support_level_ids)) {
            $support_level_ids = array($support_level_ids);
        }
        $prj_id = Auth::getCurrentProject();

        if (count($support_level_ids) == 0) {
            $stmt = "SELECT
                        *
                     FROM
                        {{%faq}}
                     WHERE
                        faq_prj_id = ?
                     ORDER BY
                        faq_rank ASC";
            $params = array($prj_id);
        } else {
            $stmt = "SELECT
                        *
                     FROM
                        {{%faq}},
                        {{%faq_support_level}}
                     WHERE
                        faq_id=fsl_faq_id AND
                        fsl_support_level_id IN (" . DB_Helper::buildList($support_level_ids) . ") AND
                        faq_prj_id = ?
                     GROUP BY
                        faq_id
                     ORDER BY
                        faq_rank ASC";
            $params = $support_level_ids;
            $params[] = $prj_id;
        }

        try {
            $res = DB_Helper::getInstance()->getAll($stmt, $params);
        } catch (DbException $e) {
            return "";
        }

        for ($i = 0; $i < count($res); $i++) {
            if (empty($res[$i]['faq_updated_date'])) {
                $res[$i]['faq_updated_date'] = $res[$i]['faq_created_date'];
            }
            $res[$i]['faq_updated_date'] = Date_Helper::getSimpleDate($res[$i]["faq_updated_date"]);
        }

        return $res;
    }

    /**
     * Method used to remove a FAQ entry from the system.
     *
     * @return  boolean
     */
    public static function remove()
    {
        $items = $_POST["items"];
        $stmt = "DELETE FROM
                    {{%faq}}
                 WHERE
                    faq_id IN (" . DB_Helper::buildList($items) . ")";
        try {
            DB_Helper::getInstance()->query($stmt, $items);
        } catch (DbException $e) {
            return false;
        }

        self::removeSupportLevelAssociations($items);

        return true;
    }

    /**
     * Method used to remove the support level associations for a given
     * FAQ entry.
     *
     * @param   integer $faq_id The FAQ ID
     * @return  boolean
     */
    public function removeSupportLevelAssociations($faq_id)
    {
        if (!is_array($faq_id)) {
            $faq_id = array($faq_id);
        }

        $stmt = "DELETE FROM
                    {{%faq_support_level}}
                 WHERE
                    fsl_faq_id IN (" . DB_Helper::buildList($faq_id) . ")";
        try {
            DB_Helper::getInstance()->query($stmt, $faq_id);
        } catch (DbException $e) {
            return false;
        }

        return true;
    }

    /**
     * Method used to update a FAQ entry in the system.
     *
     * @return  integer 1 if the update worked, -1 otherwise
     */
    public static function update()
    {
        if (Validation::isWhitespace($_POST["title"])) {
            return -2;
        }
        if (Validation::isWhitespace($_POST["message"])) {
            return -3;
        }

        $faq_id = $_POST['id'];
        $stmt = "UPDATE
                    {{%faq}}
                 SET
                    faq_prj_id=?,
                    faq_updated_date=?,
                    faq_title=?,
                    faq_message=?,
                    faq_rank=?
                 WHERE
                    faq_id=?";
        $params = array($_POST['project'], Date_Helper::getCurrentDateGMT(), $_POST["title"], $_POST["message"], $_POST['rank'], $faq_id);
        try {
            DB_Helper::getInstance()->query($stmt, $params);
        } catch (DbException $e) {
            return -1;
        }

        // remove all of the associations with support levels, then add them all again
        self::removeSupportLevelAssociations($faq_id);
        if (isset($_POST['support_levels']) && count($_POST['support_levels']) > 0) {
            foreach ($_POST['support_levels'] as $support_level_id) {
                self::addSupportLevelAssociation($faq_id, $support_level_id);
            }
        }

        return 1;
    }

    /**
     * Method used to add a FAQ entry to the system.
     *
     * @return  integer 1 if the insert worked, -1 otherwise
     */
    public static function insert()
    {
        if (Validation::isWhitespace($_POST["title"])) {
            return -2;
        }
        if (Validation::isWhitespace($_POST["message"])) {
            return -3;
        }
        $stmt = "INSERT INTO
                    {{%faq}}
                 (
                    faq_prj_id,
                    faq_usr_id,
                    faq_created_date,
                    faq_title,
                    faq_message,
                    faq_rank
                 ) VALUES (
                    ?, ?, ?, ?, ?, ?
                 )";
        $params = array($_POST['project'], Auth::getUserID(), Date_Helper::getCurrentDateGMT(), $_POST["title"], $_POST["message"], $_POST['rank']);
        try {
            DB_Helper::getInstance()->query($stmt, $params);
        } catch (DbException $e) {
            return -1;
        }

        $new_faq_id = DB_Helper::get_last_insert_id();
        if (isset($_POST['support_levels']) && count($_POST['support_levels']) > 0) {
            // now populate the faq-support level mapping table
            foreach ($_POST['support_levels'] as $support_level_id) {
                self::addSupportLevelAssociation($new_faq_id, $support_level_id);
            }
        }

        return 1;
    }

    /**
     * Method used to add a support level association to a FAQ entry.
     *
     * @param   integer $faq_id The FAQ ID
     * @param   integer $support_level_id The support level ID
     * @return  void
     */
    public function addSupportLevelAssociation($faq_id, $support_level_id)
    {
        $stmt = "INSERT INTO
                    {{%faq_support_level}}
                 (
                    fsl_faq_id,
                    fsl_support_level_id
                 ) VALUES (
                    ?, ?
                 )";
        DB_Helper::getInstance()->query($stmt, array($faq_id, $support_level_id));
    }

    /**
     * Method used to get the details of a FAQ entry for a given FAQ ID.
     *
     * @param   integer $faq_id The FAQ entry ID
     * @return  array The FAQ entry details
     */
    public static function getDetails($faq_id)
    {
        $stmt = "SELECT
                    *
                 FROM
                    {{%faq}}
                 WHERE
                    faq_id=?";
        try {
            $res = DB_Helper::getInstance()->getRow($stmt, array($faq_id));
        } catch (DbException $e) {
            return "";
        }

        if ($res == NULL) {
            return "";
        }
        $res['support_levels'] = array_keys(self::getAssociatedSupportLevels($res['faq_prj_id'], $res['faq_id']));
        if (empty($res['faq_updated_date'])) {
            $res['faq_updated_date'] = $res['faq_created_date'];
        }
        $res['faq_updated_date'] = Date_Helper::getFormattedDate($res['faq_updated_date']);
        $res['message'] = Misc::activateLinks(nl2br(htmlspecialchars($res['faq_message'])));

        return $res;
    }

    /**
     * Method used to get the list of FAQ entries available in the system.
     *
     * @return  array The list of news entries
     */
    public static function getList()
    {
        $stmt = "SELECT
                    faq_id,
                    faq_prj_id,
                    faq_title,
                    faq_rank
                 FROM
                    {{%faq}}
                 ORDER BY
                    faq_rank ASC";
        try {
            $res = DB_Helper::getInstance()->getAll($stmt);
        } catch (DbException $e) {
            return "";
        }

        // get the list of associated support levels
        for ($i = 0; $i < count($res); $i++) {
            $res[$i]['support_levels'] = implode(", ", array_values(self::getAssociatedSupportLevels($res[$i]['faq_prj_id'], $res[$i]['faq_id'])));
        }

        return $res;
    }

    /**
     * Method used to get the list of associated support levels for a given
     * FAQ entry.
     *
     * @param   integer $prj_id The project ID
     * @param   integer $faq_id The FAQ ID
     * @return  array The list of projects
     */
    public function getAssociatedSupportLevels($prj_id, $faq_id)
    {
        if (CRM::hasCustomerIntegration($prj_id)) {
            $crm = CRM::getInstance($prj_id);
            $stmt = "SELECT
                        fsl_support_level_id
                     FROM
                        {{%faq_support_level}}
                     WHERE
                        fsl_faq_id=?";
            $ids = DB_Helper::getInstance()->getColumn($stmt, array($faq_id));

            $t = array();
            $levels = $crm->getSupportLevelAssocList();
            foreach ($levels as $support_level_id => $support_level) {
                if (in_array($support_level_id, $ids)) {
                    $t[$support_level_id] = $support_level;
                }
            }

            return $t;
        } else {
            return array();
        }
    }

    /**
     * Method used to quickly change the ranking of a faq entry
     * from the administration screen.
     *
     * @param   integer $faq_id The faq entry ID
     * @param   string $rank_type Whether we should change the entry down or up (options are 'asc' or 'desc')
     * @return  boolean
     */
    public static function changeRank($faq_id, $rank_type)
    {
        // check if the current rank is not already the first or last one
        $ranking = self::_getRanking();
        $ranks = array_values($ranking);
        $ids = array_keys($ranking);
        $last = end($ids);
        $first = reset($ids);
        if ((($rank_type == 'asc') && ($faq_id == $first)) ||
                (($rank_type == 'desc') && ($faq_id == $last))) {
            return false;
        }

        if ($rank_type == 'asc') {
            $diff = -1;
        } else {
            $diff = 1;
        }
        $new_rank = $ranking[$faq_id] + $diff;
        if (in_array($new_rank, $ranks)) {
            // switch the rankings here...
            $index = array_search($new_rank, $ranks);
            $replaced_faq_id = $ids[$index];
            $stmt = "UPDATE
                        {{%faq}}
                     SET
                        faq_rank=?
                     WHERE
                        faq_id=?";
            DB_Helper::getInstance()->query($stmt, array($ranking[$faq_id], $replaced_faq_id));
        }
        $stmt = "UPDATE
                    {{%faq}}
                 SET
                    faq_rank=?
                 WHERE
                    faq_id=?";
        DB_Helper::getInstance()->query($stmt, array($new_rank, $faq_id));

        return true;
    }

    /**
     * Returns an associative array with the list of faq entry
     * IDs and their respective ranking.
     *
     * @return  array The list of faq entries
     */
    private function _getRanking()
    {
        $stmt = "SELECT
                    faq_id,
                    faq_rank
                 FROM
                    {{%faq}}
                 ORDER BY
                    faq_rank ASC";
        try {
            $res = DB_Helper::getInstance()->fetchAssoc($stmt);
        } catch (DbException $e) {
            return array();
        }

        return $res;
    }
}
