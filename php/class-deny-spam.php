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

		add_action( 'wp_blacklist_check', array( __CLASS__, 'wp_blacklist_check' ), 10, 6 );

		if ( ! wp_next_scheduled( 'rds_cron' ) ) {

			wp_schedule_event( time(), 'hourly', 'rds_cron' );
		}

		add_action( 'rds_cron', 'rds_cron_functions' );
	}

	static function admin_init() {

		scbAdminPage::register( 'Deny_Spam_Admin_Page', __FILE__, self::$options );
	}

	/**
	 * Analyzes the comment.
	 *
	 * @param string $author
	 * @param string $email
	 * @param string $url
	 * @param string $comment
	 * @param string $user_ip
	 * @param string $user_agent
	 */
	static function wp_blacklist_check( $author, $email, $url, $comment, $user_ip, $user_agent ) {

		/** @var wpdb $wpdb */
		global $wpdb;

		if ( 0 > self::$options->links_limit )
			self::$options->links_limit = 0;

		if ( 0 > self::$options->known_ip_limit )
			self::$options->known_ip_limit = 0;

		/* links limit */
		if ( substr_count( strtolower( $comment ), 'http://' ) > self::$options->links_limit ) {

			if ( 'reject' == self::$options->links_limit_action ) {

				wp_die( __( 'Comment has <strong>over ', 'r-deny-spam' )
						. ( self::$options->links_limit )
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

			if ( 'reject' == self::$options->duplicate_action )
				wp_die( __( 'Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

			return;
		}

		/* known spam URL */
		if ( ! empty( $url ) ) {

			$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url = '$url' LIMIT 1";

			if ( $wpdb->get_var( $dupe ) || rds_is_known_spam_domain( $url ) ) {

				if ( 'reject' == self::$options->known_sites_action )
					wp_die( __( 'Your URL or domain is in list of known spam-promoted sites. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
				else
					add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

				return;
			}
		}

		/* known spam IP */
		$dupe = "SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_IP = '$user_ip'";

		if ( $wpdb->get_var( $dupe ) > self::$options->known_ip_limit ) {

			if ( 'reject' == self::$options->known_ip_action )
				wp_die( __( 'Your IP is in list of known spam sources. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', 'rds_set_approved_spam' );

			return;
		}

		/* group of spam duplicates */
		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='0' AND comment_content = '$comment' LIMIT 1";

		if ( $wpdb->get_var( $dupe ) ) {

			if ( 'reject' == self::$options->group_action ) {

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
}
