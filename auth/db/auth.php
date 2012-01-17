<?php
/**
 * Authentication Plugin: External Database Authentication
 *
 * Checks against an external database.
 *
 * @package    auth
 * @subpackage db
 * @author     Martin Dougiamas
 * @license    http://www.gnu.org/copyleft/gpl.html GNU Public License
 */

defined('MOODLE_INTERNAL') || die();

require_once($CFG->libdir.'/authlib.php');
require_once($CFG->libdir.'/adodb/adodb.inc.php');
require_once($CFG->libdir.'/ddllib.php');

/**
 * External database authentication plugin.
 */
class auth_plugin_db extends auth_plugin_base {

    /**
     * Constructor.
     */
    function auth_plugin_db() {
        $this->authtype = 'db';
        $this->config = get_config('auth/db');
        if (empty($this->config->extencoding)) {
            $this->config->extencoding = 'utf-8';
        }
    }

    /**
     * Returns true if the username and password work and false if they are
     * wrong or don't exist.
     *
     * @param string $username The username
     * @param string $password The password
     *
     * @return bool Authentication success or failure.
     */
    function user_login($username, $password) {
        global $CFG, $DB;

        $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);
        $extpassword = textlib::convert($password, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        if ($this->is_internal()) {
            // lookup username externally, but resolve
            // password locally -- to support backend that
            // don't track passwords
            $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                     WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."' ");
            if (!$rs) {
                $authdb->Close();
                debugging(get_string('auth_dbcantconnect','auth_db'));
                return false;
            }

            if (!$rs->EOF) {
                $rs->Close();
                $authdb->Close();
                // user exists externally
                // check username/password internally
                if ($user = $DB->get_record('user', array('username'=>$username, 'mnethostid'=>$CFG->mnet_localhost_id))) {
                    return validate_internal_user_password($user, $password);
                }
            } else {
                $rs->Close();
                $authdb->Close();
                // user does not exist externally
                return false;
            }

        } else {
            // normal case: use external db for both usernames and passwords

            if ($this->config->passtype === 'md5') {   // Re-format password accordingly
                $extpassword = md5($extpassword);
            } else if ($this->config->passtype === 'sha1') {
                $extpassword = sha1($extpassword);
            }

            $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."'
                                  AND {$this->config->fieldpass} = '".$this->ext_addslashes($extpassword)."' ");
            if (!$rs) {
                $authdb->Close();
                debugging(get_string('auth_dbcantconnect','auth_db'));
                return false;
            }

            if (!$rs->EOF) {
                $rs->Close();
                $authdb->Close();
                return true;
            } else {
                $rs->Close();
                $authdb->Close();
                return false;
            }

        }
    }

    function db_init() {
        // Connect to the external database (forcing new connection)
        $authdb = &ADONewConnection($this->config->type);
        if (!empty($this->config->debugauthdb)) {
            $authdb->debug = true;
            ob_start();//start output buffer to allow later use of the page headers
        }
        $authdb->Connect($this->config->host, $this->config->user, $this->config->pass, $this->config->name, true);
        $authdb->SetFetchMode(ADODB_FETCH_ASSOC);
        if (!empty($this->config->setupsql)) {
            $authdb->Execute($this->config->setupsql);
        }
        if (!empty($this->config->extencoding)) {
            $authdb->SetCharSet($this->config->extencoding);
        }

        return $authdb;
    }

    /**
     * Returns user attribute mappings between moodle and ldap
     *
     * @return array
     */
    function db_attributes() {
        $moodleattributes = array();
        foreach ($this->userfields as $field) {
            if (!empty($this->config->{"field_map_$field"})) {
                $moodleattributes[$field] = $this->config->{"field_map_$field"};
            }
        }
        $moodleattributes['username'] = $this->config->fielduser;
        return $moodleattributes;
    }

    /**
     * Reads any other information for a user from external database,
     * then returns it in an array
     *
     * @param string $username
     *
     * @return array without magic quotes
     */
    function get_userinfo($username) {
        global $CFG;

        $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        //Array to map local fieldnames we want, to external fieldnames
        $selectfields = $this->db_attributes();

        $result = array();
        //If at least one field is mapped from external db, get that mapped data:
        if ($selectfields) {
            $select = '';
            foreach ($selectfields as $localname=>$externalname) {
                $select .= ", $externalname AS $localname";
            }
            $select = 'SELECT ' . substr($select,1);
            $sql = $select .
                " FROM {$this->config->table}" .
                " WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."'";
            if ($rs = $authdb->Execute($sql)) {
                if ( !$rs->EOF ) {
                    $fields_obj = $rs->FetchObj();
                    $fields_obj = (object)array_change_key_case((array)$fields_obj , CASE_LOWER);
                    foreach ($selectfields as $localname=>$externalname) {
                        $result[$localname] = textlib::convert($fields_obj->{$localname}, $this->config->extencoding, 'utf-8');
                     }
                 }
                 $rs->Close();
            }
        }
        $authdb->Close();
        return $result;
    }

    /**
     * Change a user's password
     *
     * @param  object  $user        User table object
     * @param  string  $newpassword Plaintext password
     *
     * @return bool                  True on success
     */
    function user_update_password($user, $newpassword) {
        if ($this->is_internal()) {
            return update_internal_user_password($user, $newpassword);
        } else {
            $username = $user->username;

            $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);
            $extpassword = textlib::convert($newpassword, 'utf-8', $this->config->extencoding);

            switch ($this->config->passtype) {
                case 'md5':
                    $extpassword = md5($extpassword);
                    break;
                case 'sha1':
                    $extpassword = sha1($extpassword);
                    break;
                case 'plaintext':
                default:
                    break; // plaintext
            }

            $authdb = $this->db_init();

            $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                     WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."'");

            if (!$rs) {
                $authdb->Close();
                debugging(get_string('auth_dbcantconnect','auth_db'));
                return false;
            }

            if (!$rs->EOF) {

                $authdb->Execute("UPDATE {$this->config->table}
                                     SET {$this->config->fieldpass} =  '".$this->ext_addslashes($extpassword)."'
                                   WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."'");
                $rs->Close();
                $authdb->Close();
                return true;
            } else {
                $rs->Close();
                $authdb->Close();
                return false;
            }
        }
    }

    /**
     * synchronizes user from external db to moodle user table
     *
     * Sync should be done by using idnumber attribute, not username.
     * You need to pass firstsync parameter to function to fill in
     * idnumbers if they don't exists in moodle user table.
     *
     * Syncing users removes (disables) users that don't exists anymore in external db.
     * Creates new users and updates coursecreator status of users.
     *
     * This implementation is simpler but less scalable than the one found in the LDAP module.
     *
     * @param bool $do_updates  Optional: set to true to force an update of existing accounts
     * @param bool $verbose
     * @return int 0 means success, 1 means failure
     */
    function sync_users($do_updates=false, $verbose=false) {
        global $CFG, $DB;

        // list external users
        echo get_string('auth_dbconnecting', 'auth_db'), "\n";
        $externaldbconnection = $this->db_init();

        $dbman = $DB->get_manager();

        /// Define table user to be created
        echo get_string('auth_dbcreatingtemptable', 'auth_db'), "\n";

        $table = new xmldb_table('tmp_extuser');
        $table->add_field('id', XMLDB_TYPE_INTEGER, '10', XMLDB_UNSIGNED, XMLDB_NOTNULL, XMLDB_SEQUENCE, null);
        $table->add_field('username', XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
        $table->add_field('mnethostid', XMLDB_TYPE_INTEGER, '10', XMLDB_UNSIGNED, XMLDB_NOTNULL, null, null);
        $table->add_key('primary', XMLDB_KEY_PRIMARY, array('id'));
        $table->add_index('username', XMLDB_INDEX_UNIQUE, array('mnethostid', 'username'));

        $fields_select = $this->config->fielduser;
        $fields_update = '';
        $fields_add = 'e.id, e.username, e.mnethostid';
        if ($do_updates) {

            $sql_fields = array();
            $add_array = array();
            $map_array = array();

            $all_keys = array_keys(get_object_vars($this->config));
            foreach ($all_keys as $key) {
                if (preg_match('/^field_map_(.+)$/',$key, $match)) {
                    if (!empty($this->config->{$key})) {
                        $add_array[] = "e.{$match[1]}";
                        $up_array[]  = " u.{$match[1]} = t.{$match[1]}";
                        $sel_array[] = $this->config->{$key};
                        $map_array[$match[1]] = $this->config->{$key};
                    }
                }
            }

            if (!empty($map_array)) {
                foreach ($map_array as $mdl_field => $ext_field) {
                    $table->add_field($mdl_field, XMLDB_TYPE_CHAR, '100', null, XMLDB_NOTNULL, null, null);
                }
                $fields_select .= ', '.implode($sel_array, ',');
                $fields_add    .= ','.implode($add_array, ',');
                $fields_update  = implode($up_array, ',');
            }
            unset($all_keys); unset($key); unset($add_array); unset($up_array); unset($sel_array);
        }

        $dbman->create_temp_table($table);

        echo get_string('auth_dbdownloadingusers', 'auth_db'), "\n";
        /// get users from external database and store in temporary table
        $rs = $externaldbconnection->Execute("SELECT {$fields_select} FROM {$this->config->table}");

        if (!$rs) {
            $dbman->drop_temp_table($table);
            print_error('auth_dbcantgetusers','auth_db');
        } else if (!$rs->EOF) {
            while ($rec = $rs->FetchRow()) {
                $data = new stdclass();
                $data->username = moodle_strtolower($rec['username']);
                $data->mnethostid = $CFG->mnet_localhost_id;
                foreach ($map_array as $mdl_field => $ext_field) {
                    $data->{$mdl_field} = mysql_escape_string($rec[$ext_field]);
                }
                $DB->insert_record_raw('tmp_extuser', $data, false);
            }
        }

        /// preserve our user database
        /// if the temp table is empty, it probably means that something went wrong, exit
        /// so as to avoid mass deletion of users; which is hard to undo
        $count = $DB->count_records_sql('SELECT COUNT(username) AS count, 1 FROM {tmp_extuser}');
        if ($count < 1) {
            echo get_string('auth_dbgotnousers', 'auth_db'), "\n";
            exit;
        } else {
            echo get_string('auth_dbcountrecords', 'auth_db', $count), "\n";
        }

        /// User removal
        // Find users in DB that aren't in external db -- to be removed!
        // this is still not as scalable (but how often do we mass delete?)
        if (!empty($this->config->removeuser) and $this->config->removeuser !== AUTH_REMOVEUSER_KEEP) {
            $sql = 'SELECT u.id, u.username, u.email, u.auth
                      FROM {user} u
                 LEFT JOIN {tmp_extuser} e
                        ON (u.username = e.username AND
                            u.mnethostid = e.mnethostid)
                     WHERE u.auth = ?
                       AND u.deleted = 0
                       AND e.username IS NULL';
            $remove_users = $DB->get_records_sql($sql, array($this->authtype));

            if (!empty($remove_users)) {
                echo get_string('auth_dbuserstoremove','auth_db', count($remove_users)), "\n";

                foreach ($remove_users as $user) {
                    if ($this->config->removeuser == AUTH_REMOVEUSER_FULLDELETE) {
                        if (delete_user($user)) {
                            echo "\t", get_string('auth_dbdeleteuser', 'auth_db', array('name'=>$user->username, 'id'=>$user->id)), "\n";
                        } else {
                            echo "\t", get_string('auth_dbdeleteusererror', 'auth_db', $user->username), "\n";
                        }
                    } else if ($this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {
                        $updateuser = new stdClass();
                        $updateuser->id   = $user->id;
                        $updateuser->auth = 'nologin';
                        $updateuser->timemodified = time();
                        $DB->update_record('user', $updateuser);
                        echo "\t", get_string('auth_dbsuspenduser', 'auth_db', array('name'=>$user->username, 'id'=>$user->id)), "\n";
                    }
                }
            } else {
                echo get_string('auth_dbnouserentriestoremove', 'auth_db'), "\n";
            }
            unset($remove_users); // free mem!
        }

        /// Revive suspended users
        if (!empty($this->config->removeuser) and $this->config->removeuser == AUTH_REMOVEUSER_SUSPEND) {
            $sql = "SELECT u.id, u.username
                      FROM {user} u
                      JOIN {tmp_extuser} e
                        ON (u.username = e.username AND
                            u.mnethostid = e.mnethostid)
                     WHERE u.auth = 'nologin'
                       AND u.deleted = 0";
            $revive_users = $DB->get_records_sql($sql);

            if (!empty($revive_users)) {
                echo get_string('userentriestorevive', 'auth_db', count($revive_users)), "\n";

                foreach ($revive_users as $user) {
                    $updateuser = new stdClass();
                    $updateuser->id = $user->id;
                    $updateuser->auth = $this->authtype;
                    $DB->update_record('user', $updateuser);
                    echo "\t", get_string('auth_dbreviveduser', 'auth_db', array('name'=>$user->username, 'id'=>$user->id)), "\n";
                }
            } else {
                echo get_string('nouserentriestorevive', 'auth_ldap'), "\n";
            }

            unset($revive_users);
        }

        /// User Updates
        if (!empty($fields_update)) {

            echo get_string("auth_dbupdatingentries", 'auth_db');
            $sql = "UPDATE {user} u
                      JOIN {tmp_extuser} t
                        ON t.username = u.username
                       SET {$fields_update}
                     WHERE u.deleted = 0
                       AND u.auth = '{$this->authtype}'
                       AND u.mnethostid = {$CFG->mnet_localhost_id}";
            $DB->execute($sql);
            echo "updated! \n" ;

        } else {
            echo get_string('auth_dbnoupdatestobedone', 'auth_db'), "\n";
        }

        /// User Additions
        // Find users missing in DB that are in EXTERNAL DB
        // and gives me a nifty object I don't want.
        // note: we do not care about deleted accounts anymore, this feature was replaced by suspending to nologin auth plugin
        $sql = "SELECT {$fields_add}
                  FROM {tmp_extuser} e
             LEFT JOIN {user} u
                    ON (e.username = u.username AND
                        e.mnethostid = u.mnethostid)
                 WHERE u.id IS NULL";
        $add_users = $DB->get_records_sql($sql);

        if (!empty($add_users)) {

            echo get_string('auth_dbuserstoadd','auth_db',count($add_users)), "\n";

            foreach($add_users as $user) {

                if (!validate_email($user->email)) {
                    echo get_string('auth_dbinvalidemail', 'auth_db', $user), "\n";
                    continue;
                }

                // prep a few params
                $user->modified   = time();
                $user->confirmed  = 1;
                $user->auth       = $this->authtype;
                $user->mnethostid = $CFG->mnet_localhost_id;
                $user->username = trim(moodle_strtolower($user->username));// Make sure it's lowercase
                if (empty($user->lang)) {
                    $user->lang = $CFG->lang;
                }
                foreach ($map_array as $mdl_field => $ext_field) {
                    $user->{$mdl_field} = mysql_escape_string($user->{$mdl_field});
                }

                if ($id = $DB->insert_record('user',$user)) {
                    echo "\t", get_string('auth_dbinsertuser', 'auth_db', array('name'=>$user->username, 'id'=>$id)), "\n";
                } else {
                    echo "\t", var_export($user, true), get_string('cantcreateuser', 'auth_db', $user->username), "\n";
                }
                // if relevant, tag for password generation
                if ($this->is_internal()) {
                    set_user_preference('auth_forcepasswordchange', 1, $id);
                    set_user_preference('create_password',          1, $id);
                }
            }
            unset($add_users); // free mem
        } else {
            echo get_string('auth_dbnouserentriestoadd', 'auth_db'), "\n";
        }

        echo get_string('auth_dbsuccess', 'auth_db'), "\n";

        $dbman->drop_temp_table($table);
        $externaldbconnection->Close();
        return true;
    }

    function user_exists($username) {

    /// Init result value
        $result = false;

        $extusername = textlib::convert($username, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        $rs = $authdb->Execute("SELECT * FROM {$this->config->table}
                                     WHERE {$this->config->fielduser} = '".$this->ext_addslashes($extusername)."' ");

        if (!$rs) {
            print_error('auth_dbcantconnect','auth_db');
        } else if (!$rs->EOF) {
            // user exists externally
            $result = true;
        }

        $authdb->Close();
        return $result;
    }


    function get_userlist() {

    /// Init result value
        $result = array();

        $authdb = $this->db_init();

        // fetch userlist
        $rs = $authdb->Execute("SELECT {$this->config->fielduser} AS username
                                FROM   {$this->config->table} ");

        if (!$rs) {
            print_error('auth_dbcantconnect','auth_db');
        } else if (!$rs->EOF) {
            while ($rec = $rs->FetchRow()) {
                $rec = (object)array_change_key_case((array)$rec , CASE_LOWER);
                array_push($result, $rec->username);
            }
        }

        $authdb->Close();
        return $result;
    }

    /**
     * Called when the user record is updated.
     * Modifies user in external database. It takes olduser (before changes) and newuser (after changes)
     * compares information saved modified information to external db.
     *
     * @param mixed $olduser     Userobject before modifications
     * @param mixed $newuser     Userobject new modified userobject
     * @return boolean result
     *
     */
    function user_update($olduser, $newuser) {
        if (isset($olduser->username) and isset($newuser->username) and $olduser->username != $newuser->username) {
            error_log("ERROR:User renaming not allowed in ext db");
            return false;
        }

        if (isset($olduser->auth) and $olduser->auth != $this->authtype) {
            return true; // just change auth and skip update
        }

        $curruser = $this->get_userinfo($olduser->username);
        if (empty($curruser)) {
            error_log("ERROR:User $olduser->username found in ext db");
            return false;
        }

        $extusername = textlib::convert($olduser->username, 'utf-8', $this->config->extencoding);

        $authdb = $this->db_init();

        $update = array();
        foreach($curruser as $key=>$value) {
            if ($key == 'username') {
                continue; // skip this
            }
            if (empty($this->config->{"field_updateremote_$key"})) {
                continue; // remote update not requested
            }
            if (!isset($newuser->$key)) {
                continue;
            }
            $nuvalue = $newuser->$key;
            if ($nuvalue != $value) {
                $update[] = $this->config->{"field_map_$key"}."='".$this->ext_addslashes(textlib::convert($nuvalue, 'utf-8', $this->config->extencoding))."'";
            }
        }
        if (!empty($update)) {
            $authdb->Execute("UPDATE {$this->config->table}
                                 SET ".implode(',', $update)."
                               WHERE {$this->config->fielduser}='".$this->ext_addslashes($extusername)."'");
        }
        $authdb->Close();
        return true;
    }

    /**
     * A chance to validate form data, and last chance to
     * do stuff before it is inserted in config_plugin
     *
     * @param stfdClass config form
     * @param array $error errors
     * @return void
     */
     function validate_form($form, &$err) {
        if ($form->passtype === 'internal') {
            $this->config->changepasswordurl = '';
            set_config('changepasswordurl', '', 'auth/db');
        }
    }

    function prevent_local_passwords() {
        if (!isset($this->config->passtype)) {
            return false;
        }
        return ($this->config->passtype != 'internal');
    }

    /**
     * Returns true if this authentication plugin is "internal".
     *
     * Internal plugins use password hashes from Moodle user table for authentication.
     *
     * @return bool
     */
    function is_internal() {
        return ($this->config->passtype === 'internal');
    }

    /**
     * Indicates if moodle should automatically update internal user
     * records with data from external sources using the information
     * from auth_plugin_base::get_userinfo().
     *
     * @return bool true means automatically copy data from ext to user table
     */
    function is_synchronised_with_external() {
        return true;
    }

    /**
     * Returns true if this authentication plugin can change the user's
     * password.
     *
     * @return bool
     */
    function can_change_password() {
        return true;
    }

    /**
     * Returns the URL for changing the user's pw, or empty if the default can
     * be used.
     *
     * @return moodle_url
     */
    function change_password_url() {
        if (isset($this->config->changepasswordurl) && !empty($this->config->changepasswordurl)) {
            return new moodle_url($this->config->changepasswordurl);
        } else {
            return null;
        }
    }

    /**
     * Returns true if plugin allows resetting of internal password.
     *
     * @return bool
     */
    function can_reset_password() {
        return true;
    }

    /**
     * Prints a form for configuring this authentication plugin.
     *
     * This function is called from admin/auth.php, and outputs a full page with
     * a form for configuring this plugin.
     *
     * @param stdClass $config
     * @param array $err errors
     * @param array $user_fields
     * @return void
     */
    function config_form($config, $err, $user_fields) {
        include 'config.html';
    }

    /**
     * Processes and stores configuration data for this authentication plugin.
     * @param srdClass $config
     * @return bool always true or exception
     */
    function process_config($config) {
        // set to defaults if undefined
        if (!isset($config->host)) {
            $config->host = 'localhost';
        }
        if (!isset($config->type)) {
            $config->type = 'mysql';
        }
        if (!isset($config->sybasequoting)) {
            $config->sybasequoting = 0;
        }
        if (!isset($config->name)) {
            $config->name = '';
        }
        if (!isset($config->user)) {
            $config->user = '';
        }
        if (!isset($config->pass)) {
            $config->pass = '';
        }
        if (!isset($config->table)) {
            $config->table = '';
        }
        if (!isset($config->fielduser)) {
            $config->fielduser = '';
        }
        if (!isset($config->fieldpass)) {
            $config->fieldpass = '';
        }
        if (!isset($config->passtype)) {
            $config->passtype = 'plaintext';
        }
        if (!isset($config->extencoding)) {
            $config->extencoding = 'utf-8';
        }
        if (!isset($config->setupsql)) {
            $config->setupsql = '';
        }
        if (!isset($config->debugauthdb)) {
            $config->debugauthdb = 0;
        }
        if (!isset($config->removeuser)) {
            $config->removeuser = AUTH_REMOVEUSER_KEEP;
        }
        if (!isset($config->changepasswordurl)) {
            $config->changepasswordurl = '';
        }

        // save settings
        set_config('host',          $config->host,          'auth/db');
        set_config('type',          $config->type,          'auth/db');
        set_config('sybasequoting', $config->sybasequoting, 'auth/db');
        set_config('name',          $config->name,          'auth/db');
        set_config('user',          $config->user,          'auth/db');
        set_config('pass',          $config->pass,          'auth/db');
        set_config('table',         $config->table,         'auth/db');
        set_config('fielduser',     $config->fielduser,     'auth/db');
        set_config('fieldpass',     $config->fieldpass,     'auth/db');
        set_config('passtype',      $config->passtype,      'auth/db');
        set_config('extencoding',   trim($config->extencoding), 'auth/db');
        set_config('setupsql',      trim($config->setupsql),'auth/db');
        set_config('debugauthdb',   $config->debugauthdb,   'auth/db');
        set_config('removeuser',    $config->removeuser,    'auth/db');
        set_config('changepasswordurl', trim($config->changepasswordurl), 'auth/db');

        return true;
    }

    function ext_addslashes($text) {
        // using custom made function for now
        if (empty($this->config->sybasequoting)) {
            $text = str_replace('\\', '\\\\', $text);
            $text = str_replace(array('\'', '"', "\0"), array('\\\'', '\\"', '\\0'), $text);
        } else {
            $text = str_replace("'", "''", $text);
        }
        return $text;
    }
}


