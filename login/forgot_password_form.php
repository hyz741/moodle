<?php

// This file is part of Moodle - http://moodle.org/
//
// Moodle is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Moodle is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with Moodle.  If not, see <http://www.gnu.org/licenses/>.

/**
 * Reset forgotten password form definition.
 *
 * @package    core
 * @subpackage auth
 * @copyright  2006 Petr Skoda {@link http://skodak.org}
 * @license    http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */

defined('MOODLE_INTERNAL') || die();

require_once $CFG->libdir.'/formslib.php';

class login_forgot_password_form extends moodleform {

    function definition() {
        $mform    = $this->_form;

        $mform->addElement('header', '', get_string('enterusername'), '');

        $mform->addElement('text', 'username', get_string('username'));
        $mform->setType('username', PARAM_RAW);

        $submitlabel = get_string('search');
        $mform->addElement('submit', 'submitbuttonusername', $submitlabel);
    }

    function validation($data, $files) {
        global $CFG, $DB;

        $errors = parent::validation($data, $files);

        if (empty($data['username'])) {
            $errors['username'] = get_string('enterusername');

        } else {
            if ($user = get_complete_user_data('username', $data['username'])) {
                if (empty($user->confirmed)) {
                    $errors['email'] = get_string('confirmednot');
                }
                if ($user->auth == 'nologin'){
                    $nologin_cfgs = get_config('auth/nologin');
                    if(!empty($nologin_cfgs->enable_specific_message)){
                        $errors['username'] = $nologin_cfgs->specific_message_text;
                    }
                }
            }
            if (!$user and empty($CFG->protectusernames)) {
                $errors['username'] = get_string('usernamenotfound');
            }
        }

        return $errors;
    }

}
