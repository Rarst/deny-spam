<?php
/*
Plugin Name: Deny Spam
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
