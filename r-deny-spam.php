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

Deny_Spam::on_load();

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
