<?php // Copyright (c) 2024, Switch

/*
******************************************************************************
This file contains common functions of the SWITCHwayf
******************************************************************************
*/

// Initilizes default configuration options if they were not set already
function initConfigOptions()
{
    global $defaultLanguage;
    global $commonDomain;
    global $cookieNamePrefix;
    global $redirectCookieName;
    global $redirectStateCookieName;
    global $SAMLDomainCookieName;
    global $SPCookieName;
    global $cookieSecurity;
    global $cookieValidity;
    global $showPermanentSetting;
    global $selectionListType;
    global $disableRemoteLogos;
    global $useSAML2Metadata;
    global $SAML2MetaOverLocalConf;
    global $includeLocalConfEntries;
    global $enableDSReturnParamCheck;
    global $useACURLsForReturnParamCheck;
    global $useKerberos;
    global $useReverseDNSLookup;
    global $useEmbeddedWAYF;
    global $useEmbeddedWAYFPrivacyProtection;
    global $useEmbeddedWAYFRefererForPrivacyProtection;
    global $exportPreselectedIdP;
    global $federationName;
    global $supportContactEmail;
    global $federationURL;
    global $organizationURL;
    global $faqURL;
    global $helpURL;
    global $privacyURL;
    global $imageURL;
    global $javascriptURL;
    global $apiURL;
    global $cssURL;
    global $logoURL;
    global $smallLogoURL;
    global $organizationLogoURL;
    global $customStrings;
    global $IDPConfigFile;
    global $backupIDPConfigFile;
    global $metadataFile;
    global $metadataIDPFile;
    global $metadataSPFile;
    global $metadataLockFile;
    global $logDestination;
    global $logFile;
    global $logFacility;
    global $logRequests;
    global $kerberosRedirectURL;
    global $instanceIdentifier;
    global $developmentMode;
    global $topLevelDir;
    global $select2PageSize;
    global $allowedCORSDomain;
    global $errorRedirectURL;


    // Set independet default configuration options
    $defaults = array();
    $defaults['instanceIdentifier'] = 'SWITCHwayf';
    $defaults['defaultLanguage'] = 'en';
    $defaults['commonDomain'] = getTopLevelDomain($_SERVER['SERVER_NAME']);
    $defaults['cookieNamePrefix'] = '';
    $defaults['cookieSecurity'] = false;
    $defaults['cookieValidity'] = 100;
    $defaults['showPermanentSetting'] = false;
    $defaults['selectionListType'] = 'improved';
    $defaults['select2PageSize'] = 100;
    $defaults['allowedCORSDomain'] = '*';
    $defaults['disableRemoteLogos'] = false;
    $defaults['useSAML2Metadata'] = false;
    $defaults['SAML2MetaOverLocalConf'] = false;
    $defaults['includeLocalConfEntries'] = true;
    $defaults['enableDSReturnParamCheck'] = true;
    $defaults['useACURLsForReturnParamCheck'] = false;
    $defaults['useKerberos'] = false;
    $defaults['useReverseDNSLookup'] = false;
    $defaults['useEmbeddedWAYF'] = false;
    $defaults['useEmbeddedWAYFPrivacyProtection'] = false;
    $defaults['useEmbeddedWAYFRefererForPrivacyProtection'] = false;
    $defaults['exportPreselectedIdP'] = false;
    $defaults['federationName'] = 'Identity Federation';
    $defaults['organizationURL'] = 'http://www.'.$defaults['commonDomain'];
    $defaults['federationURL'] = $defaults['organizationURL'].'/aai';
    $defaults['faqURL'] = $defaults['federationURL'].'/faq';
    $defaults['helpURL'] = $defaults['federationURL'].'/help';
    $defaults['privacyURL'] = $defaults['federationURL'].'/privacy';
    $defaults['supportContactEmail'] = 'support-contact@'.$defaults['commonDomain'];
    $defaults['imageURL'] = 'https://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME']).'/images';
    $defaults['javascriptURL'] = 'https://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME']).'/js';
    $defaults['apiURL'] = 'https://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME']).'/api.php';
    $defaults['cssURL'] = 'https://'.$_SERVER['SERVER_NAME'].dirname($_SERVER['SCRIPT_NAME']).'/css';
    $defaults['IDPConfigFile'] = 'IDProvider.conf.php';
    $defaults['backupIDPConfigFile'] = 'IDProvider.conf.php';
    $defaults['metadataFile'] = '/etc/shibboleth/metadata.switchaai.xml';
    $defaults['metadataIDPFile'] = 'IDProvider.metadata.php';
    $defaults['metadataSPFile'] = 'SProvider.metadata.php';
    $lockFileName = preg_replace('/[^-_\.a-zA-Z]/', '', $defaults['instanceIdentifier']);
    $defaults['metadataLockFile'] = (substr($_SERVER['PATH'], 0, 1) == '/') ? '/tmp/wayf_metadata-'.$lockFileName.'.lock' : 'C:\windows\TEMP\wayf_metadata-'.$lockFileName.'.lock';
    $defaults['logDestination'] = 'syslog';
    $defaults['logFile'] = '/var/log/apache2/wayf.log';
    $defaults['logPriority'] = LOG_USER;
    $defaults['logRequests'] = true;
    $defaults['kerberosRedirectURL'] = dirname($_SERVER['SCRIPT_NAME']).'kerberosRedirect.php';
    $defaults['developmentMode'] = false;
    $defaults['customStrings'] = array();
    $defaults['errorRedirectURL'] = '';

    // Initialize independent defaults
    foreach ($defaults as $key => $value) {
        if (!isset($$key)) {
            $$key = $value;
        }
    }

    // Set dependent default configuration options
    $defaults = array();
    $defaults['redirectCookieName'] = $cookieNamePrefix.'_redirect_user_idp';
    $defaults['redirectStateCookieName'] = $cookieNamePrefix.'_redirection_state';
    $defaults['SAMLDomainCookieName'] = $cookieNamePrefix.'_saml_idp';
    $defaults['SPCookieName'] = $cookieNamePrefix.'_saml_sp';
    $defaults['logoURL'] = $imageURL.'/federation-logo.png';
    $defaults['smallLogoURL'] = $imageURL.'/small-federation-logo.png';
    $defaults['organizationLogoURL'] = $imageURL.'/organization-logo.png';

    // Initialize dependent defaults
    foreach ($defaults as $key => $value) {
        if (!isset($$key)) {
            $$key = $value;
        }
    }

    // Turn relatives paths into absolute ones
    $files = array(
        'IDPConfigFile', 'backupIDPConfigFile', 'metadataFile',
        'metadataIDPFile', 'metadataSPFile', 'metadataLockFile'
    );
    foreach ($files as $file) {
        if (substr($$file, 0, 1) != '/') {
            $$file = $topLevelDir . '/etc/' . $$file;
        }
    }
}

/******************************************************************************/
// Generates an array of IDPs using the cookie value
function getIdPArrayFromValue($value)
{

    // Decodes and splits cookie value
    $CookieArray = preg_split('/ /', $value);
    $CookieArray = array_map('base64_decode', $CookieArray);

    return $CookieArray;
}

/******************************************************************************/
// Generate the value that is stored in the cookie using the list of IDPs
function getValueFromIdPArray($CookieArray)
{

    // Merges cookie content and encodes it
    $CookieArray = array_map('base64_encode', $CookieArray);
    $value = implode(' ', $CookieArray);
    return $value;
}

/******************************************************************************/
// Append a value to the array of IDPs, ensure no more than 5
// entries are in array
function appendValueToIdPArray($value, $CookieArray)
{

    // Remove value if it already existed in array
    foreach (array_keys($CookieArray) as $i) {
        if ($CookieArray[$i] == $value) {
            unset($CookieArray[$i]);
        }
    }

    // Add value to end of array
    $CookieArray[] = $value;

    // Shorten array from beginning as latest entry should
    // be at end according to SAML spec
    while (count($CookieArray) > 5) {
        array_shift($CookieArray);
    }

    return $CookieArray;
}

/******************************************************************************/
// Checks if the configuration file has changed. If it has, check the file
// and change its timestamp.
function checkConfig($IDPConfigFile, $backupIDPConfigFile)
{

    // Do files have the same modification time
    if (filemtime($IDPConfigFile) == filemtime($backupIDPConfigFile)) {
        return true;
    }

    // Availability check
    if (!file_exists($IDPConfigFile)) {
        return false;
    }

    // Readability check
    if (!is_readable($IDPConfigFile)) {
        return false;
    }

    // Size check
    if (filesize($IDPConfigFile) < 200) {
        return false;
    }

    // Make modification time the same
    // If that doesnt work we won't notice it
    touch($IDPConfigFile, filemtime($backupIDPConfigFile));

    return true;
}

/******************************************************************************/
// Checks if an IDP exists and returns true if it does, false otherwise
function checkIDP($IDP)
{
    global $IDProviders;

    if (isset($IDProviders[$IDP])) {
        return true;
    } else {
        return false;
    }
}

/******************************************************************************/
// Checks if an IDP exists and returns true if it exists and prints an error
// if it doesnt
function checkIDPAndShowErrors($IDP)
{
    global $IDProviders;

    if (checkIDP($IDP)) {
        return true;
    }

    // Otherwise show an error
    $message = sprintf(getLocalString('invalid_user_idp'), htmlentities($IDP))."</p><p>\n<code>";
    foreach ($IDProviders as $key => $value) {
        if (isset($value['SSO'])) {
            $message .= $key."<br>\n";
        }
    }
    $message .= "</code>\n";

    printError($message);
    releaseLogger();
    exit;
}


/******************************************************************************/
// Validates the URL and returns it if it is valid or false otherwise
function getSanitizedURL($url)
{
    $components = parse_url($url);

    if ($components) {
        return $url;
    } else {
        return false;
    }
}

/******************************************************************************/
// Parses the hostname out of a string and returns it
function getHostNameFromURI($string)
{

    // Check if string is URN
    if (preg_match('/^urn:mace:/i', $string)) {
        // Return last component of URN
        $components = explode(':', $string);
        return end($components);
    }

    // Apparently we are dealing with something like a URL
    if (preg_match('/([a-zA-Z0-9\-\.]+\.[a-zA-Z0-9\-\.]{2,6})/', $string, $matches)) {
        return $matches[0];
    } else {
        return '';
    }
}

/******************************************************************************/
// Parses the domain out of a string and returns it
function getDomainNameFromURI($string)
{

    // Check if string is URN
    if (preg_match('/^urn:mace:/i', $string)) {
        // Return last component of URN
        $components = explode(':', $string);
        return getTopLevelDomain(end($components));
    }

    // Apparently we are dealing with something like a URL
    if (preg_match('/[a-zA-Z0-9\-\.]+\.([a-zA-Z0-9\-\.]{2,6})/', $string, $matches)) {
        return getTopLevelDomain($matches[0]);
    } else {
        return '';
    }
}

/******************************************************************************/
// Returns top level domain name from a DNS name
function getTopLevelDomain($string)
{
    $hostnameComponents = explode('.', $string);
    if (count($hostnameComponents) >= 2) {
        return $hostnameComponents[count($hostnameComponents)-2].'.'.$hostnameComponents[count($hostnameComponents)-1];
    } else {
        return $string;
    }
}

/******************************************************************************/
// Returns client IP adress, from X-Forward-For header if set, from source
// address otherwise
function getClientIPAdress()
{
    if (array_key_exists("HTTP_X_FORWARDED_FOR", $_SERVER)) {
        $ips = explode(",", $_SERVER["HTTP_X_FORWARDED_FOR"]);
        return $ips[0];
    } else {
        return $_SERVER["REMOTE_ADDR"];
    }
}

/******************************************************************************/
// Determines the IdP according to the client domain name
function getDomainNameHint($clientIP)
{
    global $IDProviders;

    $clientHostname = gethostbyaddr($clientIP);
    if ($clientHostname == $clientIP) {
        return '-';
    }

    // Get domain name from client host name
    $clientDomainName = getDomainNameFromURI($clientHostname);
    if ($clientDomainName == '') {
        return '-';
    }

    // Return first matching IdP entityID that contains the client domain name
    foreach ($IDProviders as $name => $idp) {
        if (is_array($idp) && array_key_exists("DomainHint", $idp)) {
            foreach ($idp["DomainHint"] as $domain) {
                if ($clientDomainName == $domain) {
                    return $name;
                }
            }
        }
    }

    // No matching entityID was found
    return '-';
}

/******************************************************************************/
// Get the user's language using the accepted language http header
function determineLanguage()
{
    global $langStrings, $defaultLanguage;

    // Check if language is enforced by PATH-INFO argument
    if (isset($_SERVER['PATH_INFO']) && !empty($_SERVER['PATH_INFO'])) {
        foreach ($langStrings as $lang => $values) {
            if (preg_match('#/'.$lang.'($|/)#', $_SERVER['PATH_INFO'])) {
                return $lang;
            }
        }
    }

    // Check if there is a language GET argument
    if (isset($_GET['lang'])) {
        $localeComponents = decomposeLocale($_GET['lang']);
        if (
            $localeComponents !== false
            && isset($langStrings[$localeComponents[0]])
            ) {

            // Return language
            return $localeComponents[0];
        }
    }

    // Return default language if no headers are present otherwise
    if (!isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
        return $defaultLanguage;
    }

    // Inspect Accept-Language header which looks like:
    // Accept-Language: en,de-ch;q=0.8,fr;q=0.7,fr-ch;q=0.5,en-us;q=0.3,de;q=0.2
    $languages = explode(',', trim($_SERVER['HTTP_ACCEPT_LANGUAGE']));
    foreach ($languages as $language) {
        $languageParts = explode(';', $language);

        // Only treat art before the prioritization
        $localeComponents = decomposeLocale($languageParts[0]);
        if (
            $localeComponents !== false
            && isset($langStrings[$localeComponents[0]])
            ) {

            // Return language
            return $localeComponents[0];
        }
    }

    return $defaultLanguage;
}

/******************************************************************************/

// Splits up a  string (relazed) according to
// http://www.debian.org/doc/manuals/intro-i18n/ch-locale.en.html#s-localename
// and returns an array with the four components
function decomposeLocale($locale)
{

    // Locale name syntax:  language[_territory][.codeset][@modifier]
    if (!preg_match('/^([a-zA-Z]{2})([-_][a-zA-Z]{2})?(\.[^@]+)?(@.+)?$/', $locale, $matches)) {
        return false;
    } else {
        // Remove matched string in first position
        array_shift($matches);

        return $matches;
    }
}

/******************************************************************************/
// Gets a string in a specific language. Fallback to default language and
// to English.
function getLocalString($string, $encoding = '')
{
    global $defaultLanguage, $langStrings, $language;

    $textString = '';
    if (isset($langStrings[$language][$string])) {
        $textString = $langStrings[$language][$string];
    } elseif (isset($langStrings[$defaultLanguage][$string])) {
        $textString = $langStrings[$defaultLanguage][$string];
    } elseif (isset($langStrings['en'][$string])) {
        $textString = $langStrings['en'][$string];
    } else {
        $textString = $string;
    }

    // Change encoding if necessary
    if ($encoding == 'js') {
        $textString = convertToJSString($textString);
    }

    return $textString;
}

/******************************************************************************/
// Converts string to a JavaScript format that can be used in JS alert
function convertToJSString($string)
{
    return addslashes(html_entity_decode($string, ENT_COMPAT, 'UTF-8'));
}

/******************************************************************************/
// Replaces all newlines with spaces and then trims the string to get one line
function trimToSingleLine($string)
{
    return trim(preg_replace("|\n|", ' ', $string));
}

/******************************************************************************/
// Checks if entityID hostname of a valid IdP exists in path info
function getIdPPathInfoHint()
{
    global $IDProviders;

    // Check if path info is available at all
    if (!isset($_SERVER['PATH_INFO']) || empty($_SERVER['PATH_INFO'])) {
        return '-';
    }

    // Check for entityID hostnames of all available IdPs
    foreach ($IDProviders as $key => $value) {
        // Only check actual IdPs
        if (isset($value['SSO'])
            && !empty($value['SSO'])
            && $value['Type'] != 'wayf') {
            $hostName = getHostNameFromURI($key);
            if ($hostName && preg_match('|/'.$hostName.'|', $_SERVER['PATH_INFO'])) {
                return $key;
            }
        }
    }

    // Check for entityID domain names of all available IdPs
    foreach ($IDProviders as $key => $value) {
        // Only check actual IdPs
        if (isset($value['SSO'])
            && !empty($value['SSO'])
            && $value['Type'] != 'wayf') {
            $domainName = getDomainNameFromURI($key);
            if ($domainName && preg_match('|/'.$domainName.'|', $_SERVER['PATH_INFO'])) {
                return $key;
            }
        }
    }

    return '-';
}

/******************************************************************************/
// Joins localized names and keywords of an IdP to a single string
function composeOptionData($IdPValues)
{
    $data = '';
    foreach ($IdPValues as $key => $value) {
        if (is_array($value) && isset($value['Name'])) {
            $data .= ' '.$value['Name'];
        }

        if (is_array($value) && isset($value['Keywords'])) {
            $data .= ' '.$value['Keywords'];
        }
    }

    return $data;
}

/******************************************************************************/
// Parses the Kerbores realm out of the string and returns it
function getKerberosRealm($string)
{
    global $IDProviders;

    if ($string !='') {
        // Find a matching Kerberos realm
        foreach ($IDProviders as $key => $value) {
            if ($value['Realm'] == $string) {
                return $key;
            }
        }
    }

    return '-';
}


/******************************************************************************/
// Determines the IdP according to the client IP adress
function getIPAdressHint($clientIP)
{
    global $IDProviders;

    foreach ($IDProviders as $name => $idp) {
        if (is_array($idp) && array_key_exists("IPHint", $idp)) {
            foreach ($idp["IPHint"] as $network) {
                if (isIPinCIDRBlock($network, $clientIP)) {
                    return $name;
                }
            }
        }
    }
    return '-';
}

/******************************************************************************/
// Returns true if IP is in IPv4/IPv6 CIDR range
// and returns false otherwise
function isIPinCIDRBlock($cidr, $ip)
{

    // Split CIDR notation
    list($net, $mask) = preg_split("|/|", $cidr);

    // Convert to binary string value of 1s and 0s
    $netAsBinary = convertIPtoBinaryForm($net);
    $ipAsBinary =  convertIPtoBinaryForm($ip);

    // Return false if netmask and ip are using different protocols
    if (strlen($netAsBinary) != strlen($ipAsBinary)) {
        return false;
    }

    // Compare the first $mask bits
    for ($i = 0; $i < $mask; $i++) {

        // Return false if bits don't match
        if ($netAsBinary[$i] != $ipAsBinary[$i]) {
            return false;
        }
    }

    // If we got here, ip matches net
    return true;
}

/******************************************************************************/
// Converts IP in human readable format to binary string
function convertIPtoBinaryForm($ip)
{

    //  Handle IPv4 IP
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return sprintf("%032s", base_convert(ip2long($ip), 10, 2));
    }

    // Return false if IP is neither IPv4 nor a IPv6 IP
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
        return false;
    }

    // Convert IP to binary structure and return false if this fails
    if (($ipAsBinStructure = inet_pton($ip)) === false) {
        return false;
    }


    $numOfBytes = 16;
    $ipAsBinaryString = '';

    // Convert IP to binary string
    while ($numOfBytes > 0) {
        // Convert current byte to decimal number
        $currentByte = ord($ipAsBinStructure[$numOfBytes - 1]);

        // Convert currenty byte to string of 1 and 0
        $currentByteAsBinary = sprintf("%08b", $currentByte);

        // Prepend to rest of IP in binary string
        $ipAsBinaryString = $currentByteAsBinary.$ipAsBinaryString;

        // Decrease byte counter
        $numOfBytes--;
    }

    return $ipAsBinaryString;
}

/******************************************************************************/
// Returns URL without GET arguments
function getURLWithoutArguments($url)
{
    return preg_replace('/\?.*/', '', $url);
}

/******************************************************************************/
// Returns true if URL could be verified or if no check is necessary, false otherwise
function verifyReturnURL($entityID, $returnURL)
{
    global $SProviders, $useACURLsForReturnParamCheck;

    // Prevent attacks with return URLs like https://ilias.unibe.ch@google.com
    $returnURL = preg_replace('|(https?://)(.+@)(.+)|','\1\3', $returnURL);

    // If SP has a <idpdisc:DiscoveryResponse>, check return param
    if (isset($SProviders[$entityID]['DSURL'])) {
        $returnURLWithoutArguments = getURLWithoutArguments($returnURL);
        foreach ($SProviders[$entityID]['DSURL'] as $DSURL) {
            $DSURLWithoutArguments = getURLWithoutArguments($DSURL);
            if ($DSURLWithoutArguments == $returnURLWithoutArguments) {
                return true;
            }
        }

        // DS URLs did not match the return URL
        return false;
    }

    // Return true if SP has no <idpdisc:DiscoveryResponse>
    // and $useACURLsForReturnParamCheck is disabled (we don't check anything)
    if (!$useACURLsForReturnParamCheck) {
        return true;
    }

    // $useACURLsForReturnParamCheck is enabled, so
    // check return param against host name of assertion consumer URLs

    // Check hostnames
    $returnURLHostName = getHostNameFromURI($returnURL);
    foreach ($SProviders[$entityID]['ACURL'] as $ACURL) {
        if (getHostNameFromURI($ACURL) == $returnURLHostName) {
            return true;
        }
    }

    // We haven't found a matching assertion consumer URL, therefore we return false
    return false;
}

/******************************************************************************/
// Returns a reasonable value for returnIDParam
function getReturnIDParam()
{
    if (isset($_GET['returnIDParam']) && !empty($_GET['returnIDParam'])) {
        return $_GET['returnIDParam'];
    } else {
        return 'entityID';
    }
}

/******************************************************************************/
// Returns true if valid Shibboleth 1.x request or Directory Service request
function isValidShibRequest()
{
    return (isValidShib1Request() || isValidDSRequest());
}

/******************************************************************************/
// Returns true if valid Shibboleth request
function isValidShib1Request()
{
    if (isset($_GET['shire']) && isset($_GET['target'])) {
        return true;
    } else {
        return false;
    }
}

/******************************************************************************/
// Returns true if request is a valid Directory Service request
function isValidDSRequest()
{
    global $SProviders;

    // If entityID is not present, request is invalid
    if (!isset($_GET['entityID'])) {
        return false;
    }

    // If entityID and return parameters are present, request is valid
    if (isset($_GET['return'])) {
        return true;
    }

    // If no return parameter and no Discovery Service endpoint is available
    // for SP, request is invalid
    if (!isset($SProviders[$_GET['entityID']]['DSURL'])) {
        return false;
    }

    if (count($SProviders[$_GET['entityID']]['DSURL']) < 1) {
        return false;
    }

    // EntityID is available and there is at least one DiscoveryService
    // endpoint defined. Therefore, the request is valid
    return true;
}

/******************************************************************************/
// Sets the Location header to redirect the user's web browser
function redirectTo($url)
{
    header('Location: '.$url);
}

/******************************************************************************/
// Sets the Location that is used for redirect the web browser back to the SP
function redirectToSP($url, $IdP)
{
    if (preg_match('/\?/', $url) > 0) {
        redirectTo($url.'&'.getReturnIDParam().'='.urlencode($IdP));
    } else {
        redirectTo($url.'?'.getReturnIDParam().'='.urlencode($IdP));
    }
}
/******************************************************************************/
// Logs all events where users were redirected to their IdP or back to an SP
// The log then can be used to approximately detect how many users were served
// by the SWITCHwayf
function logAccessEntry($protocol, $type, $sp, $idp, $return)
{
    global $logRequests;

    // Return if logging deactivated
    if (!$logRequests) {
        return;
    }

    // Compose log entry
    $entry = $_SERVER['REMOTE_ADDR'].' '.$protocol.' '.$type.' '.$idp.' '.$return.' '.$sp;

    logInfo($entry);
}

/******************************************************************************/
// Init connection to system logger
function initLogger()
{
    global $logDestination, $logFile, $logHandle, $instanceIdentifier, $logFacility;

    switch($logDestination) {
        case 'file':
            // Create log file if it does not exist yet
            if (!file_exists($logFile) && !touch($logFile)) {
                // File does not exist and cannot be written to
                error_log("[ERROR] WAYF log file $logFile does not exist and could not be created.");
                exit;
            }

            // Ensure that the file exists and is writable
            if (!is_writable($logFile)) {
                error_log("[ERROR] Current file permission do not allow WAYF to write to its log file $logFile.");
                exit;
            }

            // Open file in append mode
            if (!$logHandle = fopen($logFile, 'a')) {
                error_log("[ERROR] Could not open file $logFile for appending log entries.");
                exit;
            }
            break;

        case 'syslog':
            openlog($instanceIdentifier, LOG_NDELAY, $logFacility);
            break;
    }

}

// release connection to system logger
function releaseLogger()
{
    global $logDestination, $logHandle;

    switch($logDestination) {
        case 'file':
            fclose($logHandle);
            break;

        case 'syslog':
            closelog();
            break;
    }
}

/******************************************************************************/
// Logs a debug message
function logDebug($infoMsg)
{
    wayfLog("DEBUG", $infoMsg);
}

// Logs an info message
function logInfo($infoMsg)
{
    wayfLog("INFO", $infoMsg);
}

/******************************************************************************/
// Logs an warnimg message
function logWarning($warnMsg)
{
    wayfLog("WARN", $warnMsg);
}

/******************************************************************************/
// Logs an error message
function logError($errorMsg)
{
    wayfLog("ERROR", $errorMsg);
}

/******************************************************************************/
// Logs an fatal error message
function logFatalErrorAndExit($errorMsg)
{
    logError($errorMsg);
    releaseLogger();
    exit;
}

/******************************************************************************/
// Logs a message to errorLog
function wayfLog($level, $message)
{
    global $logDestination, $logHandle;

    switch($logDestination) {
        case 'error':
            error_log(sprintf("[%s] %s", $level, $message));
            break;

        case 'file':
            // Try getting the lock
            while (!flock($logHandle, LOCK_EX)) {
                usleep(rand(10, 100));
            }

            // Write entry
            fwrite($logHandle, sprintf("[%s] [%s] %s\n", date('Y-m-d H:i:s'), $level, $message));

            // Release the lock
            flock($logHandle, LOCK_UN);

            break;

        case 'syslog':
            switch($level) {
                case 'ERROR':
                    $priority = LOG_ERR;
                    break;
                case 'WARN':
                    $priority = LOG_WARNING;
                    break;
                default:
                    $priority = LOG_INFO;
            }

            syslog($priority, $message);
            break;
    }
}

/******************************************************************************/
// Returns true if PATH info indicates a request of type $type
function isRequestType($type)
{
    // Make sure the type is checked at end of path info
    return isPartOfPathInfo($type.'$');
}

/******************************************************************************/
// Checks for substrings in Path Info and returns true if match was found
function isPartOfPathInfo($needle)
{
    if (
        isset($_SERVER['PATH_INFO'])
        && !empty($_SERVER['PATH_INFO'])
        && preg_match('|/'.$needle.'|', $_SERVER['PATH_INFO'])) {
        return true;
    } else {
        return false;
    }
}

/******************************************************************************/
// Converts to the unified datastructure that the Shibboleth DS will be using
function convertToShibDSStructure($IDProviders)
{
    $ShibDSIDProviders = array();

    foreach ($IDProviders as $key => $value) {

        // Skip unknown and category entries
        if (
            !isset($value['Type'])
            || $value['Type'] == 'category'
            || $value['Type'] == 'wayf'
            ) {
            continue;
        }

        // Init and fill IdP data
        $identityProvider = array();
        $identityProvider['entityID'] = $key;
        $identityProvider['DisplayNames'][] = array('lang' => 'en', 'value' => $value['Name']);

        // Add DisplayNames in other languages
        foreach ($value as $lang => $name) {
            if (
                   $lang == 'Name'
                || $lang == 'SSO'
                || $lang == 'Realm'
                || $lang == 'Type'
                || $lang == 'IP'

            ) {
                continue;
            }

            if (isset($name['Name'])) {
                $identityProvider['DisplayNames'][] = array('lang' => $lang, 'value' => $name['Name']);
            }
        }

        // Add data to ShibDSIDProviders
        $ShibDSIDProviders[] = $identityProvider;
    }

    return $ShibDSIDProviders;
}

/******************************************************************************/
// Sorts the IDProviders array
function sortIdentityProviders(&$IDProviders)
{
    global $language;
    $orderedCategories = array();

    // Create array with categories and IdPs in categories
    $unknownCategory = array();
    foreach ($IDProviders as $entityId => $IDProvider) {
        // Add categories
        if (isset($IDProvider['Type']) && $IDProvider['Type'] == 'category') {
            $orderedCategories[$entityId]['data'] = $IDProvider;
        }
    }


    // Add category 'unknown' if not present
    if (!isset($orderedCategories['unknown'])) {
        $orderedCategories['unknown']['data'] = array(
            'Name' => 'Unknown',
            'Type' => 'category',
        );
    }

    foreach ($IDProviders as $entityId => $IDProvider) {

        // Skip categories
        if (isset($IDProvider['Type']) && $IDProvider['Type'] == 'category') {
            continue;
        }

        // Skip incomplete descriptions
        if (!is_array($IDProvider) || !isset($IDProvider['Name'])) {
            continue;
        }

        // Sanitize category
        if (!isset($IDProvider['Type'])) {
            $IDProvider['Type'] = 'unknown';
        }

        // Add IdP
        $orderedCategories[$IDProvider['Type']]['IdPs'][$entityId] = $IDProvider;

        if (isset($IDProvider['Type'])) {
            $orderedCategories[$IDProvider['Type']]['IdPs'][$entityId]['TypeForSort'] = removeAccents($IDProvider['Type']);
        }
        if (isset($IDProvider['Index'])) {
            $orderedCategories[$IDProvider['Type']]['IdPs'][$entityId]['IndexForSort'] = removeAccents($IDProvider['Index']);
        }

        $localName = (isset($IDProvider[$language]['Name'])) ? $IDProvider[$language]['Name'] : $IDProvider['Name'];
        $orderedCategories[$IDProvider['Type']]['IdPs'][$entityId]['NameForSort'] = removeAccents($localName);
    }

    // Relocate all IdPs for which no category with a name was defined
    $toremoveCategories = array();
    foreach ($orderedCategories as $category => $object) {
        if (!isset($object['data'])) {
            foreach ($object['IdPs'] as $entityId => $IDProvider) {
                $unknownCategory[$entityId] = $IDProvider;
            }
            $toremoveCategories[] = $category;
        }
    }

    // Remove categories without descriptions
    foreach ($toremoveCategories as $category) {
        unset($orderedCategories[$category]);
    }

    // Recompose $IDProviders
    $IDProviders = array();
    foreach ($orderedCategories as $category => $object) {

        // Skip category if it contains no IdPs
        if (!isset($object['IdPs']) || count($object['IdPs']) < 1) {
            continue;
        }

        // Add category
        $IDProviders[$category] = $object['data'];

        // Sort IdPs in category
        uasort($object['IdPs'], 'sortUsingTypeIndexAndName');

        // Add IdPs
        foreach ($object['IdPs'] as $entityId => $IDProvider) {
            $IDProviders[$entityId] = $IDProvider;
        }
    }
}

/******************************************************************************/
// Sorts two entries according to their Type, Index and (local) Name
function sortUsingTypeIndexAndName($a, $b)
{
    global $language;

    if (isset($a['TypeForSort']) && isset($b['TypeForSort']) &&  $a['TypeForSort'] != $b['TypeForSort']) {
        return strcasecmp($a['TypeForSort'], $b['TypeForSort']);
    } elseif (isset($a['IndexForSort']) && isset($b['IndexForSort']) && $a['IndexForSort'] != $b['IndexForSort']) {
        return strcasecmp($a['IndexForSort'], $b['IndexForSort']);
    } else {
        // Sort using locale names
        return strcasecmp($a['NameForSort'], $b['NameForSort']);
    }
}

/******************************************************************************/
// Return given Strring without accents
function removeAccents($string)
{

    $accents =    array("À","Á","Â","Ã","Ä","Å","à","á","â","ã","ä","å","Ò","Ó","Ô","Õ","Ö","Ø","ò","ó","ô","õ","ö","ø","È","É","Ê","Ë","è","é","ê","ë","Ç","ç","Ì","Í","Î","Ï","ì","í","î","ï","Ù","Ú","Û","Ü","ù","ú","û","ü","ÿ","Ñ","ñ");
    $nonAccents = array("a","a","a","a","a","a","a","a","a","a","a","a","o","o","o","o","o","o","o","o","o","o","o","o","e","e","e","e","e","e","e","e","c","c","i","i","i","i","i","i","i","i","u","u","u","u","u","u","u","u","y","n","n");
    return str_replace(
        $accents,
        $nonAccents,
        $string
        );
}


/******************************************************************************/
// Returns true if the referer of the current request is matching an assertion
// consumer or discovery service URL of a Service Provider
function isRequestRefererMatchingSPHost()
{
    global $SProviders;

    // If referer is not available return false
    if (!isset($_SERVER["HTTP_REFERER"]) || $_SERVER["HTTP_REFERER"] == '') {
        return false;
    }

    if (!isset($SProviders) || !is_array($SProviders)) {
        return false;
    }

    $refererHostname = getHostNameFromURI($_SERVER["HTTP_REFERER"]);
    foreach ($SProviders as $key => $SProvider) {
        // Check referer against entityID
        $spHostname = getHostNameFromURI($key);
        if ($refererHostname == $spHostname) {
            return true;
        }

        // Check referer against Discovery Response URL(DSURL)
        if (isset($SProvider['DSURL'])) {
            foreach ($SProvider['DSURL'] as $url) {
                $spHostname = getHostNameFromURI($url);
                if ($refererHostname == $spHostname) {
                    return true;
                }
            }
        }

        // Check referer against Assertion Consumer Service URL(ACURL)
        if (isset($SProvider['ACURL'])) {
            foreach ($SProvider['ACURL'] as $url) {
                $spHostname = getHostNameFromURI($url);
                if ($refererHostname == $spHostname) {
                    return true;
                }
            }
        }
    }

    return false;
}

/******************************************************************************/
// Is this script run in CLI mode
function isRunViaCLI()
{
    return !isset($_SERVER['REMOTE_ADDR']);
}

/******************************************************************************/
// Is this script run in CLI mode
function isRunViaInclude()
{
    return basename($_SERVER['SCRIPT_NAME']) != 'readMetadata.php';
}

function printSubmitAction()
{
    global $selectionListType;

    switch($selectionListType) {
        case 'select2':
            return "return select2CheckForm()";
            break;
        default:
            return "return checkForm()";
    }
}

function getSelect2PageSize()
{
    global $select2PageSize;

    if (!isset($_GET["select2PageSize"])) {
        return $select2PageSize;
    }

    return $_GET["select2PageSize"];
}

function buildIdpData($IDProvider, $key)
{
    $data = getDomainNameFromURI($key);
    $data .= composeOptionData($IDProvider);
    return $data;
}

// Handle error: either display it locally, or redirect to an external service
function handleError($type, $message)
{

    global $errorRedirectURL;
    global $SProviders;

    if ($errorRedirectURL) {
        $entityID    = $_GET['entityID'];

        $variables = array(
            '$time'         => date('%c'),
            '$url'          => urlencode(sprintf("%s://%s%s", isset($_SERVER['HTTPS'])?"https":"http", $_SERVER['HTTP_HOST'], $_SERVER['PHP_SELF'])),
            '$entityID'     => urlencode($entityID),
            '$type'         => $type,
            '$message'      => urlencode($message),
        );

        if (isset($entityID) &&
            isset($SProviders[$entityID]) &&
            isset($SProviders[$entityID]['Contacts'])
        ) {
            $contact = $SProviders[$entityID]['Contacts'][0];
            $variables['$contactName']  = isset($contact['name'])  ? $contact['name']  : '';
            $variables['$contactEmail'] = isset($contact['email']) ? $contact['email'] : '';
        } else {
            $variables['$contactName']  = '';
            $variables['$contactEmail'] = '';
        }

        redirectTo(strtr($errorRedirectURL, $variables));
    } else {
        printError($message);
    }
}
