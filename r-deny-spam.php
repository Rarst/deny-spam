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
require_once dirname( __FILE__ ) . '/scb-check.php';

if ( ! scb_check( __FILE__ ) )
	return;

require dirname( __FILE__ ) . '/php/class-deny-spam.php';
require dirname( __FILE__ ) . '/php/class-deny-spam-admin-page.php';

/* Plugin initialization */
rds_init();

/**
 * Plugin initialization.
 *
 * @global scbOptions $rds_options stores plugin settings in database
 *
 * @uses add_action() to add rds_check() into comment processing
 * @uses wp_schedule_event() to register async tasks
 * @uses scbOptions
 * @uses scbAdminPage
 *
 */
function rds_init() {

	load_plugin_textdomain( 'r-deny-spam', '', basename( dirname( __FILE__ ) ) . '/lang' );

	/* Plugin options to be stored in database */
	global $rds_options;

	$rds_options = new scbOptions( 'r-deny-spam', __FILE__, array(
		'links_limit'        => 5,
		'links_limit_action' => 'reject',
		'duplicate_action'   => 'reject',
		'known_sites'        => array(),
		'known_sites_action' => 'spam',
		'known_ip_limit'     => 3,
		'known_ip_action'    => 'spam',
		'group_action'       => 'reject',
	) );

	/* Comment analyze routine */
	add_action( 'wp_blacklist_check', 'rds_check', 10, 6 );

	/* Async tasks scheduling */
	if ( ! wp_next_scheduled( 'rds_cron' ) ) {
		wp_schedule_event( time(), 'hourly', 'rds_cron' );
	}
	add_action( 'rds_cron', 'rds_cron_functions' );

	/* Settings page */
	if ( is_admin() )
		scbAdminPage::register( 'Deny_Spam_Admin_Page', __FILE__, $rds_options );
}

/**
 * Analyzes the comment.
 *
 * @uses $wpdb
 * @uses $rds_options
 * @uses add_filter() to add rds_set_approved_spam() to 'pre_comment_approved' filter
 *
 * @param string $author     The author of the comment
 * @param string $email      The email of the comment
 * @param string $url        The url used in the comment
 * @param string $comment    The comment content
 * @param string $user_ip    The comment author IP address
 * @param string $user_agent The author's browser user agent
 */
function rds_check( $author, $email, $url, $comment, $user_ip, $user_agent ) {

	/** @var wpdb $wpdb */
	global $wpdb;
	global $rds_options;

	if ( 0 > $rds_options->links_limit )
		$rds_options->links_limit = 0;

	if ( 0 > $rds_options->known_ip_limit )
		$rds_options->known_ip_limit = 0;

	/* links limit */
	if ( substr_count( strtolower( $comment ), 'http://' ) > $rds_options->links_limit ) {

		if ( 'reject' == $rds_options->links_limit_action ) {

			wp_die( __( 'Comment has <strong>over ', 'r-deny-spam' )
					. ( $rds_options->links_limit )
					. __( ' links</strong>. Please go <a href="javascript: history.go(-1)">back</a> and reduce number of those.', 'r-deny-spam' ) );
		}
		else {

			add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );
		}

		return;
	}

	/* duplicate comment content */
	$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_content = '$comment' LIMIT 1";

	if ( $wpdb->get_var( $dupe ) ) {

		if ( 'reject' == $rds_options->duplicate_action )
			wp_die( __( 'Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam' ) );
		else
			add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

		return;
	}

	/* known spam URL */
	if ( ! empty( $url ) ) {

		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url = '$url' LIMIT 1";

		if ( $wpdb->get_var( $dupe ) || rds_is_known_spam_domain( $url ) ) {

			if ( 'reject' == $rds_options->known_sites_action )
				wp_die( __( 'Your URL or domain is in list of known spam-promoted sites. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

			return;
		}
	}

	/* known spam IP */
	$dupe = "SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_IP = '$user_ip'";

	if ( $wpdb->get_var( $dupe ) > $rds_options->known_ip_limit ) {

		if ( 'reject' == $rds_options->known_ip_action )
			wp_die( __( 'Your IP is in list of known spam sources. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
		else
			add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

		return;
	}

	/* group of spam duplicates */
	$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='0' AND comment_content = '$comment' LIMIT 1";

	if ( $wpdb->get_var( $dupe ) ) {

		if ( 'reject' == $rds_options->group_action ) {

			$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='trash' WHERE comment_content = '$comment'" );
			wp_die( __( 'Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam' ) );
		}
		else {

			$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_content = '$comment'" );
			add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );
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
 * @return string spam
 */
function rds_set_approved_spam() {
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

	/** @var wpdb $wpdb */
	global $wpdb;
	$hosts = array();

	$query = "SELECT comment_author_url FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url<>'' AND comment_author_url<>'http://';";
	$urls  = $wpdb->get_col( $query );
	$urls  = array_unique( $urls );

	foreach ( $urls as $url ) {

		$host = parse_url( strtolower( $url ), PHP_URL_HOST );
		if ( false === $host )
			break;
		if ( $host )
			$hosts[] = $host;
	}

	$hosts = array_count_values( $hosts );
	arsort( $hosts );
	$hosts = array_slice( $hosts, 0, $count );
	$hosts = array_flip( $hosts );

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

	/** @var wpdb $wpdb */
	global $wpdb;

	$query = "DELETE FROM $wpdb->comments WHERE comment_approved='spam' AND comment_date < DATE_SUB( NOW(), INTERVAL 1 MONTH )";

	return $wpdb->query( $query );
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

	/** @var wpdb $wpdb */
	global $wpdb;

	$query   = "SELECT DISTINCT comment_author_IP FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_IP IN (SELECT DISTINCT comment_author_IP FROM $wpdb->comments WHERE comment_approved='spam')";
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

	/** @var wpdb $wpdb */
	global $wpdb;

	$query   = "SELECT comment_author_url FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_url <> '' AND comment_author_url <> 'http://' GROUP BY comment_author_url HAVING COUNT(comment_author_url) > 1";
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

	/** @var wpdb $wpdb */
	global $wpdb;

	$query   = "SELECT comment_author_IP FROM $wpdb->comments WHERE comment_approved='0' GROUP BY comment_author_IP HAVING COUNT(comment_author_IP) > 1";
	$matches = $wpdb->get_col( $query );

	foreach ( $matches as $ip ) {

		$query = "SELECT DISTINCT comment_author_IP, comment_author, comment_author_email FROM $wpdb->comments WHERE comment_approved='0' AND comment_author_IP = '$ip'";
		$count = $wpdb->get_col( $query );

		if ( count( $count ) > 1 )
			$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_approved='0' AND comment_author_IP='$ip'" );
	}
}
