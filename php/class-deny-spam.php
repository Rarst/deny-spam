<?php

/**
 * Main plugin's class wrapper.
 */
class Deny_Spam {

	static $options;

	static function on_load() {

		add_action( 'init', array( __CLASS__, 'init' ) );
		add_action( 'admin_init', array( __CLASS__, 'admin_init' ) );
	}

	static function init() {

		load_plugin_textdomain( 'r-deny-spam', '', basename( dirname( __FILE__ ) ) . '/lang' );

		self::$options = new scbOptions( 'r-deny-spam', __FILE__, array(
			'links_limit'        => 5,
			'links_limit_action' => 'reject',
			'duplicate_action'   => 'reject',
			'known_sites'        => array(),
			'known_sites_action' => 'spam',
			'known_ip_limit'     => 3,
			'known_ip_action'    => 'spam',
			'group_action'       => 'reject',
		) );

		add_action( 'wp_blacklist_check', 'rds_check', 10, 6 );

		if ( ! wp_next_scheduled( 'rds_cron' ) ) {

			wp_schedule_event( time(), 'hourly', 'rds_cron' );
		}

		add_action( 'rds_cron', 'rds_cron_functions' );
	}

	static function admin_init() {

		scbAdminPage::register( 'Deny_Spam_Admin_Page', __FILE__, self::$options );
	}
}
