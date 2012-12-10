<?php

/**
 * @author Petr Skoda
 * @license http://www.gnu.org/copyleft/gpl.html GNU Public License
 * @package moodle multiauth
 *
 * Authentication Plugin: No Authentication
 *
 * No authentication at all. This method approves everything!
 *
 * 2007-02-18  File created.
 */

if (!defined('MOODLE_INTERNAL')) {
    die('Direct access to this script is forbidden.');    ///  It must be included from a Moodle page
}

require_once($CFG->libdir.'/authlib.php');

/**
 * Plugin for no authentication - disabled user.
 */
class auth_plugin_nologin extends auth_plugin_base {


    /**
     * Constructor.
     */
    function auth_plugin_nologin() {
        $this->authtype = 'nologin';
    }

    /**
     * Do not allow any login.
     *
     */
    function user_login($username, $password) {
        return false;
    }

    /**
     * No password updates.
     */
    function user_update_password($user, $newpassword) {
        return false;
    }

    function prevent_local_passwords() {
        // just in case, we do not want to loose the passwords
        return false;
    }

    /**
     * No external data sync.
     *
     * @return bool
     */
    function is_internal() {
        //we do not know if it was internal or external originally
        return true;
    }

    /**
     * No changing of password.
     *
     * @return bool
     */
    function can_change_password() {
        return false;
    }

    /**
     * No password resetting.
     */
    function can_reset_password() {
        return false;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     */
    function config_form($config, $err, $user_fields) {
        include "config.html";
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset($config->enable_specific_message)) {
            $config->enable_specific_message = false;
        }
        if (!isset($config->specific_message_text)) {
            $config->specific_message_text = get_string('invalidlogin');
        }

        // save settings
        set_config('enable_specific_message',   $config->enable_specific_message,   'auth/nologin');
        set_config('specific_message_text',     $config->specific_message_text,     'auth/nologin');

        return true;
    }
}
