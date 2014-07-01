<?php
	//TODO: check/sanitize/filter the IP in input
	write_STIX_IP_Watchlist('127.0.0.1');
	
	function write_STIX_IP_Watchlist($ip)
	{
		//Create a new STIX package from a sample
		//here https://raw.github.com/STIXProject/schemas/version_1.1.1/samples/STIX_IP_Watchlist.xml
		//Example use: as "WP-STIX" in https://wordpress.org/plugins/all-in-one-wp-security-and-firewall/
		//	CAPEC-49: Password Brute Forcing
		/*
		Copyright (C) 2014  Jerome Athias
		
		This program is free software: you can redistribute it and/or modify
		it under the terms of the GNU General Public License as published by
		the Free Software Foundation, either version 3 of the License, or
		(at your option) any later version.

		This program is distributed in the hope that it will be useful,
		but WITHOUT ANY WARRANTY; without even the implied warranty of
		MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
		GNU General Public License for more details.

		You should have received a copy of the GNU General Public License
		along with this program.  If not, see <http://www.gnu.org/licenses/>.
		*/
		date_default_timezone_set('UTC');
		
		if (!file_exists('STIX_IP_Watchlist.xml')) {
		 exit('ERROR on STIX_IP_Watchlist.xml.');
		}
		$stixpackage = simplexml_load_file('STIX_IP_Watchlist.xml');
	
		$newuuid=gen_uuid();	//New id for the STIX_Package
		$stixpackage_newid='xorcism:STIX_Package-' . $newuuid;
		$stixpackage[0]['id'] = $stixpackage_newid;
	
		$timezone = new DateTimeZone('UTC');
		$date = new DateTime('now', $timezone);
		$stixpackage[0]['timestamp'] = $date->format('Y-m-d\TH:i:s.u\Z');	//Zulu
		
		//Using Namespaces
		$namespaces = $stixpackage->getNamespaces(true);
		$stix = $stixpackage->children($namespaces["stix"]);
		$stix->STIX_Header->Title='Watchlist that contains IP information.';
		
		//Using XPath
		$stixindicators = $stixpackage->xpath('/stix:STIX_Package/stix:Indicators/stix:Indicator');
		//New id for the stix:Indicator
		$stixindicators[0]['id'] = 'xorcism:Indicator-' . gen_uuid();
		$stixindicators[0]['timestamp'] = $date->format('Y-m-d\TH:i:s.u\Z');
		
		
		$stix->Indicators->Indicator->Description='IP Address Indicator for this watchlist';
		
		//New id for the indicator:Observable
		$observables = $stixpackage->xpath('/stix:STIX_Package/stix:Indicators/stix:Indicator/indicator:Observable');
		$observables[0]['id'] = 'xorcism:Observable-' . gen_uuid();
		
		//New id for the cybox:Object
		$observables = $stixpackage->xpath('/stix:STIX_Package/stix:Indicators/stix:Indicator/indicator:Observable/cybox:Object');
		$observables[0]['id'] = 'xorcism:Object-' . gen_uuid();
		
		$stix->Indicators->Indicator->Observable->Object->Properties->Address_Value=$ip;
	
		$xml = $stixpackage->asXML();
		file_put_contents('STIX_IP_Watchlist_'.$newuuid.'.xml', $xml);
	}
	
	//************************************************************************************
	//Generates version 4 UUID: random
	function gen_uuid() {
    return sprintf( '%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        // 32 bits for "time_low"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

        // 16 bits for "time_mid"
        mt_rand( 0, 0xffff ),

        // 16 bits for "time_hi_and_version",
        // four most significant bits holds version number 4
        mt_rand( 0, 0x0fff ) | 0x4000,

        // 16 bits, 8 bits for "clk_seq_hi_res",
        // 8 bits for "clk_seq_low",
        // two most significant bits holds zero and one for variant DCE1.1
        mt_rand( 0, 0x3fff ) | 0x8000,

        // 48 bits for "node"
        mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
    );
}
?>
