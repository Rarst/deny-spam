<?php

/**
 * Configures settings page in administration area
 *
 * @uses scbAdminPage
 */
class Deny_Spam_Admin_Page extends scbAdminPage {

	function setup() {

		$this->textdomain = 'deny-spam';

		$this->args = array(
			'page_title' => __( 'Deny Spam Settings', $this->textdomain ),
			'menu_title' => __( 'Deny Spam', $this->textdomain ),
			'page_slug'  => 'deny-spam',
		);
	}

	function page_content() {

		$output = '';

		$output .= $this->_subsection( __( 'Links limit', $this->textdomain ), 'links', array(
				array(
					'title' => __( 'Match if more than', $this->textdomain ),
					'desc'  => __( 'links in comment text', $this->textdomain ),
					'type'  => 'text',
					'name'  => 'links_limit',
					'value' => $this->options->links_limit,
					'extra' => 'style="width:25px;text-align:center;"',
				),
				$this->_radio_match( 'links_limit_action' ),
			)
		)

				. $this->_subsection( __( 'Known spam comment content', $this->textdomain ), 'content', array( $this->_radio_match( 'duplicate_action' ) ) )

				. $this->_subsection( __( 'Known spam-related sites', $this->textdomain ), 'sites', array( $this->_radio_match( 'known_sites_action' ) ) )

				. $this->_subsection( __( 'Known spam-related IPs', $this->textdomain ), 'ips', array(
						array(
							'title' => __( 'Match if encountered over', $this->textdomain ),
							'desc'  => __( 'times in database', $this->textdomain ),
							'type'  => 'text',
							'name'  => 'known_ip_limit',
							'value' => $this->options->known_ip_limit,
							'extra' => 'style="width:25px;text-align:center;"',
						),
						$this->_radio_match( 'known_ip_action' ),
					)
				)

				. $this->_subsection( __( 'Groups of spam comments', $this->textdomain ), 'groups', array( $this->_radio_match( 'group_action' ) ) );

		echo $this->form_wrap( $output );
	}

	/**
	 * @param array $new_data
	 *
	 * @return array
	 */
	function validate( $new_data ) {

		foreach ( $new_data as $key => $value ) {

			if( ! in_array( $value, array( 'spam', 'reject', true ) ) )
				$new_data[$key] = (int) $value;
		}

		return $new_data;
	}

	/**
	 * @param string $name
	 *
	 * @return array
	 */
	function _radio_match( $name ) {

		return array(
			'title' => __( 'On match', $this->textdomain ),
			'type'  => 'radio',
			'name'  => $name,
			'value' => array( 'reject', 'spam' ),
			'desc'  => array( __( 'Reject comment', $this->textdomain ), __( 'Send comment to spam', $this->textdomain ) )
		);
	}

	/**
	 * @param string $title
	 * @param string $id
	 * @param array  $rows
	 *
	 * @return string
	 */
	function _subsection( $title, $id, $rows ) {

		return html( "div id='$id'",
				"\n" . html( 'h3', $title )
						. "\n" . $this->table( $rows )
		);
	}
}