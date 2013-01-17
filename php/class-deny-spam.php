<?php

/**
 * Main plugin's class wrapper.
 */
class Deny_Spam {

	static $options;

	static function on_load() {

		require_once dirname( __FILE__ ) . '/class-deny-spam-admin-page.php';

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

		// TODO move on to scbFramework and on activation/deactivation
//		if ( ! wp_next_scheduled( 'rds_cron' ) ) {
//
//			wp_schedule_event( time(), 'hourly', 'rds_cron' );
//		}
//
//		add_action( 'rds_cron', 'rds_cron_functions' );
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

				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );
			}

			return;
		}

		/* duplicate comment content */
		$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_content = '$comment' LIMIT 1";

		if ( $wpdb->get_var( $dupe ) ) {

			if ( 'reject' == self::$options->duplicate_action )
				wp_die( __( 'Duplicate comment content. Please go <a href="javascript: history.go(-1)">back</a> and rephrase.', 'r-deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

			return;
		}

		/* known spam URL */
		if ( ! empty( $url ) ) {

			$dupe = "SELECT comment_ID FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_url = '$url' LIMIT 1";

			if ( $wpdb->get_var( $dupe ) || self::is_known_spam_domain( $url ) ) {

				if ( 'reject' == self::$options->known_sites_action )
					wp_die( __( 'Your URL or domain is in list of known spam-promoted sites. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
				else
					add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

				return;
			}
		}

		/* known spam IP */
		$dupe = "SELECT COUNT(comment_ID) FROM $wpdb->comments WHERE comment_approved='spam' AND comment_author_IP = '$user_ip'";

		if ( $wpdb->get_var( $dupe ) > self::$options->known_ip_limit ) {

			if ( 'reject' == self::$options->known_ip_action )
				wp_die( __( 'Your IP is in list of known spam sources. If you believe this to be an error please contact site admin.', 'r-deny-spam' ) );
			else
				add_filter( 'pre_comment_approved', array( __CLASS__, 'pre_comment_approved_spam' ) );

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
	static function rds_cron_functions() {

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

		$host = parse_url( $url, PHP_URL_HOST );

		if ( false === $host )
			return false;

		$host = strtolower( $host );

		// TODO shame! fix!
		if ( in_array( $host, self::$options->known_sites ) )
			return true;
		else
			return false;
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
	function get_top_spam_hosts( $count ) {

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
