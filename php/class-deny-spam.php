<?php

/**
 * Main plugin's class wrapper.
 */
class Deny_Spam {

	/** @var string path to main plugin's file */
	static $plugin_file;

	/** @var scbOptions */
	static $options;

	/**
	 * @param string $plugin_file
	 */
	static function on_load( $plugin_file ) {

		self::$plugin_file = $plugin_file;
		add_action( 'init', array( __CLASS__, 'init' ) );

		require_once dirname( self::$plugin_file ) . '/scb/load.php';
		scb_init( array( __CLASS__, 'scb_init' ) );
	}

	static function scb_init() {

		require_once dirname( __FILE__ ) . '/class-deny-spam-admin-page.php';

		self::$options = new scbOptions( 'deny-spam', self::$plugin_file, array(
			'links_limit'        => 5,
			'links_limit_action' => 'reject',
			'duplicate_action'   => 'reject',
			'known_sites'        => array(),
			'known_sites_action' => 'spam',
			'known_ip_limit'     => 3,
			'known_ip_action'    => 'spam',
			'group_action'       => 'reject',
		) );

		new scbCron( self::$plugin_file, array(
			'schedule' => 'hourly',
			'callback' => array( __CLASS__, 'cron_callback' ),
		) );

		if( is_admin() )
			scbAdminPage::register( 'Deny_Spam_Admin_Page', self::$plugin_file, self::$options );
	}

	static function init() {

		load_plugin_textdomain( 'deny-spam', '', dirname( plugin_basename( self::$plugin_file )  ). '/lang' );

		add_action( 'wp_blacklist_check', array( __CLASS__, 'wp_blacklist_check' ), 10, 6 );
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

				wp_die( sprintf( __( 'Comment has <strong>over %s links</strong>. Please reduce number of those.', 'deny-spam' ), self::$options->links_limit ) );
			}
			else {

				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );
			}

			return;
		}

		/* duplicate comment content */
		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_content = '$comment' LIMIT 1";

		if ( $wpdb->get_var( $dupe ) ) {

			if ( 'reject' == self::$options->duplicate_action )
				wp_die( __( 'Duplicate comment content. Please rephrase.', 'deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

			return;
		}

		/* known spam URL */
		if ( ! empty( $url ) ) {

			$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url = '$url' LIMIT 1";

			if ( $wpdb->get_var( $dupe ) || self::is_known_spam_domain( $url ) ) {

				if ( 'reject' == self::$options->known_sites_action )
					wp_die( __( 'Your URL or domain is in list of known spam-promoted sites. If you believe this to be an error please contact site admin.', 'deny-spam' ) );
				else
					add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

				return;
			}
		}

		/* known spam IP */
		$dupe = "SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_IP = '$user_ip'";

		if ( $wpdb->get_var( $dupe ) > self::$options->known_ip_limit ) {

			if ( 'reject' == self::$options->known_ip_action )
				wp_die( __( 'Your IP is in list of known spam sources. If you believe this to be an error please contact site admin.', 'deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

			return;
		}

		/* group of spam duplicates */
		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='0' AND comment_content = '$comment' LIMIT 1";

		if ( $wpdb->get_var( $dupe ) ) {

			if ( 'reject' == self::$options->group_action ) {

				$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='trash' WHERE comment_content = '$comment'" );
				wp_die( __( 'Duplicate comment content. Please rephrase.', 'deny-spam' ) );
			}
			else {

				$wpdb->query( "UPDATE $wpdb->comments SET comment_approved='spam' WHERE comment_content = '$comment'" );
				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );
			}

			return;
		}
	}

	/**
	 * Overrides approved status with 'spam'
	 *
	 * @return string spam
	 */
	static function pre_comment_approved_spam() {

		return 'spam';
	}

	/**
	 * Async tasks to be scheduled with WP Cron API
	 */
	static function cron_callback() {

		self::delete_old_spam();
		self::spam_pending_by_url_pattern();
		self::spam_pending_by_known_ip();
		self::spam_pending_by_ip_pattern();
		self::$options->known_sites = self::get_top_spam_hosts( 10 );
	}

	/**
	 * Deletes spam older than one month.
	 *
	 * TODO customize interval to retain
	 *
	 * @return int deleted count
	 */
	static function delete_old_spam() {

		/** @var wpdb $wpdb */
		global $wpdb;

		$query = "DELETE FROM $wpdb->comments WHERE comment_approved='spam' AND comment_date < DATE_SUB( NOW(), INTERVAL 1 MONTH )";

		return $wpdb->query( $query );
	}

	/**
	 * Checks URL against top spam domains.
	 *
	 * @param string $url
	 *
	 * @return boolean true on known domain match
	 */
	static function is_known_spam_domain( $url ) {

		$host = @parse_url( $url, PHP_URL_HOST );

		if ( empty( $host ) )
			return false;

		return in_array( strtolower( $host ), self::$options->known_sites );
	}

	/**
	 * Sends to spam unapproved comments that match known spam IPs.
	 */
	static function spam_pending_by_known_ip() {

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
	 */
	static function spam_pending_by_url_pattern() {

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
	 */
	static function spam_pending_by_ip_pattern() {

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

	/**
	 * Queries database for URLs in spam, calculates top encountered domains.
	 *
	 * @param int $count number of domains to return (from the top)
	 *
	 * @return array top $count domains in spam comments
	 */
	static function get_top_spam_hosts( $count ) {

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
}
