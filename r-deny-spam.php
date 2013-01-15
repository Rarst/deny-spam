<?php
/*
Plugin Name: R Deny Spam
Plugin URI: http://www.Rarst.net/
Description: 
Version: 0.3
Author: Andrey "Rarst" Savchenko
Author URI: http://www.Rarst.net
License: GPL2

Copyright 2010 Andrey "Rarst" Savchenko ( email : contact@rarst.net )

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License, version 2, as
published by the Free Software Foundation.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

/* scbFramework dependency check */
require_once dirname(__FILE__) . '/scb-check.php';
if ( ! scb_check(__FILE__) ) return;

/* Plugin initialization */
rds_init();

/**
 * Plugin initialization.
 *
 * @global $rds_options stores plugin settings in database
 *
 * @uses add_action() to add rds_check() into comment processing
 * @uses wp_schedule_event() to register async tasks
 * @uses scbOptions
 * @uses scbAdminPage
 *
 */
function rds_init() {

	
	load_plugin_textdomain('r-deny-spam', '', basename(dirname(__FILE__)) . '/lang');

	/* Plugin options to be stored in database */
	global $rds_options;
	$rds_options = new scbOptions('r-deny-spam', __FILE__, array(

		'links_limit' => 5,
		'links_limit_action' => 'reject',

		'duplicate_action' => 'reject',

		'known_sites' => array(),
		'known_sites_action' => 'spam',

		'known_ip_limit' => 3,
		'known_ip_action' => 'spam',
		
		'group_action' => 'reject'
	));

	/* Comment analyze routine */
	add_action( 'wp_blacklist_check', 'rds_check', 10, 6 );

	/* Async tasks scheduling */
	if ( !wp_next_scheduled('rds_cron') ) {
		wp_schedule_event( time(), 'hourly', 'rds_cron' );
	}
	add_action('rds_cron', 'rds_cron_functions');

	/* Settings page */
	if ( is_admin() )
		scbAdminPage::register('RDS_Settings', __FILE__, $rds_options);
}

/**
 * Analyzes the comment.
 *
 * @uses $wpdb
 * @uses $rds_options
 * @uses add_filter() to add rds_set_approved_spam() to 'pre_comment_approved' filter
 *
 * @param string $author The author of the comment
 * @param string $email The email of the comment
 * @param string $url The url used in the comment
 * @param string $comment The comment content
 * @param string $user_ip The comment author IP address
 * @param string $user_agent The author's browser user agent
 */
function rds_check($author, $email, $url, $comment, $user_ip, $user_agent) {

	global $wpdb;
	global $rds_options;

	if ( 0 > $rds_options->links_limit ) 
			$rds_options->links_limit = 0;
	
	if ( 0 > $rds_options->known_ip_limit )
			$rds_options->known_ip_limit = 0;

	/* links limit */
	if ( substr_count(strtolower($comment), 'http://') > $rds_options->links_limit ) {
		if( 'reject' == $rds_options->links_limit_action )
			wp_die( __('Comment has <strong>over ', 'r-deny-spam')
					.($rds_options->links_limit)
					.__(' links</strong>. Please go <a href="javascript: history.go(-1)">back</a> and reduce number of those.', 'r-deny-spam') );
		else
			add_filter('pre_comment_approved','rds_set_approved_spam');

		return;
	}

	/* duplicate comment content */
	$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_content = '$comment' LIMIT 1";
	if ( $wpdb->get_var($dupe) ) {
		if( 'reject' == $rds_options->duplicate_action )
			wp_die( __('Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam') );
		else
			add_filter('pre_comment_approved','rds_set_approved_spam');

		return;
	}

	/* known spam URL */
	if ( !empty($url) ) {
		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url = '$url' LIMIT 1";
		if ( $wpdb->get_var($dupe) || rds_is_known_spam_domain( $url ) ) {
			if( 'reject' == $rds_options->known_sites_action )
				wp_die( __('Your URL or domain is in list of known spam-promoted sites. If you believe this to be an error please contact site admin.', 'r-deny-spam') );
			else
				add_filter('pre_comment_approved','rds_set_approved_spam');

			return;
		}
	}

	/* known spam IP */
	$dupe = "SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_IP = '$user_ip'";
	if ( $wpdb->get_var($dupe) > $rds_options->known_ip_limit ) {
		if( 'reject' == $rds_options->known_ip_action )
			wp_die( __('Your IP is in list of known spam sources. If you believe this to be an error please contact site admin.', 'r-deny-spam') );
		else
			add_filter('pre_comment_approved','rds_set_approved_spam');
		return;
	}


	/* group of spam duplicates */
	$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='0' AND comment_content = '$comment' LIMIT 1";
	if ( $wpdb->get_var($dupe) ) {
		if( 'reject' == $rds_options->group_action ) {
			$wpdb->query("UPDATE $wpdb->comments SET comment_approved='trash' WHERE comment_content = '$comment'");
			wp_die( __('Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam') );
		}
		else {
			$wpdb->query("UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_content = '$comment'");
			add_filter('pre_comment_approved','rds_set_approved_spam');
		}
		return;
	}
}

/**
 * Async tasks to be scheduled with WP Cron API
 *
 * @uses $rds_options
 * @uses rds_delete_old_spam()
 * @uses rds_known_sites()
 * @uses rds_retroactive_check_ip()
 */
function rds_cron_functions() {
	
	global $rds_options;

	rds_delete_old_spam();
	rds_groups_by_url();
	rds_retroactive_check_ip();
	rds_groups_by_ip();
	$rds_options->known_sites = rds_known_sites( 10 );
}


/**
 * Overrides approved status with 'spam'
 *
 * @param string $approved status
 * 
 * @return string spam
 */
function rds_set_approved_spam( $approved ) {
	return 'spam';
}

/**
 * Queries database for URLs in spam, calculates top encountered domains.
 *
 * @uses $wpdb
 *
 * @param int $count number of domains to return (from the top)
 * 
 * @return array top $count domains in spam comments
 */
function rds_known_sites( $count ) {

	global $wpdb;
	$hosts = array();
	
	$query = "SELECT comment_author_url FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url<>'' AND comment_author_url<>'http://';";
	$urls = $wpdb->get_col($query);
	$urls = array_unique($urls);	

	foreach( $urls as $key => $url) {

		$host = parse_url( strtolower($url), PHP_URL_HOST );
		if( false === $host )
			break;
		if( $host )
			$hosts[]=$host;
	}
	
	$hosts = array_count_values( $hosts );
	arsort( $hosts );
	$hosts = array_slice( $hosts, 0, $count );
	$hosts = array_flip ( $hosts );

	return $hosts;
}

/**
 * Deletes spam older than one month.
 *
 * @uses $wpdb
 *
 * @return int deleted count
 */
function rds_delete_old_spam() {

    global $wpdb;
    
    $query = "DELETE FROM $wpdb->comments WHERE comment_approved='spam' AND comment_date < DATE_SUB( NOW(), INTERVAL 1 MONTH )";
    return $wpdb->query($query);
}

/**
 * Checks URL against top spam domains.
 *
 * @uses $rds_options
 *
 * @param string $url
 * 
 * @return boolean true on known domain match
 */
function rds_is_known_spam_domain( $url ) {

	global $rds_options;

	$host = parse_url( $url, PHP_URL_HOST );
	if ( false === $host )
		return false;

	$host = strtolower( $host );
	if ( in_array( $host, $rds_options->known_sites ) )
		return true;
	else
		return false;
}

/**
 * Sends to spam unapproved comments that match known spam IPs.
 *
 * @uses $wpdb
 */
function rds_retroactive_check_ip() {

	global $wpdb;

	$query = "SELECT DISTINCT comment_author_IP FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_IP IN (SELECT DISTINCT comment_author_IP FROM $wpdb->comments WHERE comment_approved='spam')";
	$matches = $wpdb->get_col( $query );
	foreach ( $matches as $ip ) {
		$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_approved='0' AND comment_author_IP='$ip'" );
	}
}

/**
 * Spams unapproved comments with same author URL but different name and email.
 *
 * @uses $wpdb
 */
function rds_groups_by_url() {

	global $wpdb;

	$query = "SELECT comment_author_url FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_url <> '' AND comment_author_url <> 'http://' GROUP BY comment_author_url HAVING COUNT(comment_author_url) > 1";
	$matches = $wpdb->get_col( $query );
	foreach ( $matches as $url ) {
		$query = "SELECT DISTINCT comment_author_url, comment_author, comment_author_email FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_url = '$url'";
		$count = $wpdb->get_col( $query );
		if ( count( $count ) > 1 )
			$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_approved='0' AND comment_author_url='$url'" );
	}
}

/**
 * Spams unapproved comments with same IP but different name and email.
 *
 * @uses $wpdb
 */
function rds_groups_by_ip() {

	global $wpdb;

	$query = "SELECT comment_author_IP FROM $wpdb->comments WHERE comment_approved='0' GROUP BY comment_author_IP HAVING COUNT(comment_author_IP) > 1";
	$matches = $wpdb->get_col( $query );
	foreach ( $matches as $ip ) {
		$query = "SELECT DISTINCT comment_author_IP, comment_author, comment_author_email FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_IP = '$ip'";
		$count = $wpdb->get_col( $query );
		if ( count( $count ) > 1 )
			$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_approved='0' AND comment_author_IP='$ip'" );
	}
}

/**
 * Configures settings page in administration area
 *
 * @uses scbAdminPage
 */
class RDS_Settings extends scbAdminPage {

	function setup() {
		$this->textdomain = 'r-deny-spam';

		$this->args = array(
			'page_title' => __('R Deny Spam Settings', $this->textdomain),
			'menu_title' => __('R Deny Spam', $this->textdomain),
			'page_slug' => 'r-deny-spam'
		);
	}

	function page_content() {
		$output = '';

		$output .= $this->_subsection( __('Links limit', $this->textdomain), 'links', array(
				array(
					'title' => __('Match if more than', $this->textdomain),
					'desc' => __('links in comment text', $this->textdomain),
					'type' => 'text',
					'name' => 'links_limit',
					'value' => $this->options->links_limit,
					'extra' => 'style="width:25px;text-align:center;"'
				),
				$this->_radio_match('links_limit_action')
			)
		)

		.$this->_subsection( __('Known spam comment content', $this->textdomain), 'content', array( $this->_radio_match('duplicate_action') ) )

		.$this->_subsection( __('Known spam-related sites', $this->textdomain), 'sites', array( $this->_radio_match('known_sites_action') ) )

		.$this->_subsection( __('Known spam-related IPs', $this->textdomain), 'ips', array(
				array(
						'title' => __('Match if encountered over', $this->textdomain),
						'desc' => __('times in database', $this->textdomain),
						'type' => 'text',
						'name' => 'known_ip_limit',
						'value' => $this->options->known_ip_limit,
						'extra' => 'style="width:25px;text-align:center;"'
					),
				$this->_radio_match('known_ip_action')
			)
		)

		.$this->_subsection( __('Groups of spam comments', $this->textdomain), 'groups', array( $this->_radio_match('group_action') ) );

		echo $this->form_wrap($output);
	}

	function form_handler() {
		if ( empty($_POST['action']) )
			return false;

		check_admin_referer($this->nonce);

		$new_data = array();
		foreach ( array_keys($this->formdata) as $key ) {
			if ( isset( $_POST[$key] ) )
				$new_data[$key] = @$_POST[$key];
			elseif ( isset( $this->options->$key ) )
				$new_data[$key] = $this->options->$key;
			else
				$new_data[$key] = '';
		}

		$new_data = stripslashes_deep($new_data);

		$this->formdata = $this->validate($new_data, $this->formdata);

		if ( isset($this->options) )
			$this->options->update($this->formdata);

		$this->admin_msg();
	}

	function _radio_match($name) {
		return array(
					'title' => __('On match', $this->textdomain),
					'type' => 'radio',
					'name' => $name,
					'value' => array( 'reject', 'spam' ),
					'desc' => array( __('Reject comment', $this->textdomain), __('Send comment to spam', $this->textdomain) )
				);
	}

	function _subsection($title, $id, $rows) {
		return html("div id='$id'",
			"\n" . html('h3', $title)
			."\n" . $this->table($rows)
		);
	}
}
//__('Save Changes', 'r-deny-spam');
?>