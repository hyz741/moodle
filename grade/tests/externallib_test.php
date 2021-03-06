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

defined('MOODLE_INTERNAL') || die();

global $CFG;

require_once($CFG->dirroot . '/webservice/tests/helpers.php');

/**
 * External core grade functions unit tests
 *
 * @package core_grade
 * @category external
 * @copyright 2013 Paul Charsley
 * @license http://www.gnu.org/copyleft/gpl.html GNU GPL v3 or later
 */
class core_grade_external_testcase extends externallib_advanced_testcase {

    /**
     * Tests set up
     */
    protected function setUp() {
        global $CFG;
        require_once($CFG->dirroot . '/grade/externallib.php');
    }

    /**
     * Test get_definitions
     */
    public function test_get_definitions () {
        global $DB, $CFG, $USER;

        $this->resetAfterTest(true);
        // Create a course and assignment.
        $coursedata['idnumber'] = 'idnumbercourse';
        $coursedata['fullname'] = 'Lightwork Course';
        $coursedata['summary'] = 'Lightwork Course description';
        $coursedata['summaryformat'] = FORMAT_MOODLE;
        $course = self::getDataGenerator()->create_course($coursedata);

        $assigndata['course'] = $course->id;
        $assigndata['name'] = 'lightwork assignment';

        $cm = self::getDataGenerator()->create_module('assign', $assigndata);

        // Create manual enrolment record.
        $manual_enrol_data['enrol'] = 'manual';
        $manual_enrol_data['status'] = 0;
        $manual_enrol_data['courseid'] = $course->id;
        $enrolid = $DB->insert_record('enrol', $manual_enrol_data);

        // Create a teacher and give them capabilities.
        $coursecontext = context_course::instance($course->id);
        $roleid = $this->assignUserCapability('moodle/course:viewparticipants', $coursecontext->id, 3);
        $modulecontext = context_module::instance($cm->id);
        $this->assignUserCapability('mod/assign:grade', $modulecontext->id, $roleid);

        // Create the teacher's enrolment record.
        $user_enrolment_data['status'] = 0;
        $user_enrolment_data['enrolid'] = $enrolid;
        $user_enrolment_data['userid'] = $USER->id;
        $DB->insert_record('user_enrolments', $user_enrolment_data);

        // Create a grading area.
        $gradingarea = array(
            'contextid' => $modulecontext->id,
            'component' => 'mod_assign',
            'areaname' => 'submissions',
            'activemethod' => 'rubric'
        );
        $areaid = $DB->insert_record('grading_areas', $gradingarea);

        // Create a rubric grading definition.
        $rubricdefinition = array (
            'areaid' => $areaid,
            'method' => 'rubric',
            'name' => 'test',
            'status' => 20,
            'copiedfromid' => 1,
            'timecreated' => 1,
            'usercreated' => $USER->id,
            'timemodified' => 1,
            'usermodified' => $USER->id,
            'timecopied' => 0
        );
        $definitionid = $DB->insert_record('grading_definitions', $rubricdefinition);

        // Create a criterion with levels.
        $rubriccriteria1 = array (
            'definitionid' => $definitionid,
            'sortorder' => 1,
            'description' => 'Demonstrate an understanding of disease control',
            'descriptionformat' => 0
        );
        $criterionid1 = $DB->insert_record('gradingform_rubric_criteria', $rubriccriteria1);
        $rubriclevel1 = array (
            'criterionid' => $criterionid1,
            'score' => 5,
            'definition' => 'pass',
            'definitionformat' => 0
        );
        $DB->insert_record('gradingform_rubric_levels', $rubriclevel1);
        $rubriclevel2 = array (
            'criterionid' => $criterionid1,
            'score' => 10,
            'definition' => 'excellent',
            'definitionformat' => 0
        );
        $DB->insert_record('gradingform_rubric_levels', $rubriclevel2);

        // Create a second criterion with levels.
        $rubriccriteria2 = array (
            'definitionid' => $definitionid,
            'sortorder' => 2,
            'description' => 'Demonstrate an understanding of brucellosis',
            'descriptionformat' => 0
        );
        $criterionid2 = $DB->insert_record('gradingform_rubric_criteria', $rubriccriteria2);
        $rubriclevel1 = array (
            'criterionid' => $criterionid2,
            'score' => 5,
            'definition' => 'pass',
            'definitionformat' => 0
        );
        $DB->insert_record('gradingform_rubric_levels', $rubriclevel1);
        $rubriclevel2 = array (
            'criterionid' => $criterionid2,
            'score' => 10,
            'definition' => 'excellent',
            'definitionformat' => 0
        );
        $DB->insert_record('gradingform_rubric_levels', $rubriclevel2);

        // Call the external function.
        $cmids = array ($cm->id);
        $areaname = 'submissions';
        $result = core_grade_external::get_definitions($cmids, $areaname);

        $this->assertEquals(1, count($result['areas']));
        $this->assertEquals(1, count($result['areas'][0]['definitions']));
        $definition = $result['areas'][0]['definitions'][0];

        $this->assertEquals($rubricdefinition['method'], $definition['method']);
        $this->assertEquals($USER->id, $definition['usercreated']);

        require_once("$CFG->dirroot/grade/grading/lib.php");
        require_once($CFG->dirroot.'/grade/grading/form/'.$rubricdefinition['method'].'/lib.php');

        $gradingmanager = get_grading_manager($areaid);

        $this->assertEquals(1, count($definition[$rubricdefinition['method']]));

        $rubricdetails = $definition[$rubricdefinition['method']];
        $details = call_user_func('gradingform_'.$rubricdefinition['method'].'_controller::get_external_definition_details');

        $this->assertEquals(2, count($rubricdetails[key($details)]));

        $found = false;
        foreach ($rubricdetails[key($details)] as $criterion) {
            if ($criterion['id'] == $criterionid1) {
                $this->assertEquals($rubriccriteria1['description'], $criterion['description']);
                $this->assertEquals(2, count($criterion['levels']));
                $found = true;
                break;
            }
        }
        $this->assertTrue($found);
    }

}
