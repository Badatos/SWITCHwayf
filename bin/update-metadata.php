<?php // Copyright (c) 2024, Switch
$MAN=<<<PAGE
Name:        SWITCHwayf
Author:      Lukas Haemmerle, SWITCH
Description: This script is used to dynamically create the list of
             IdPs and SP to be displayed for the WAYF/DS service 
             based on the federation metadata.
             It is intended to be run periodically, e.g. with a cron
             entry like:
             5 * * * * /usr/bin/php update-metadata.php \
                 --metadata-file /var/cache/shibboleth/metadata.switchaai.xml \
                 --metadata-idp-file /tmp/IDProvider.metadata.php \
                 --metadata-sp-file /tmp/SProvider.metadata.php \
                 > /dev/null

Usage
-----
php update-metadata.php -help|-h
php update-metadata.php --metadata-file <file> [--metadata-file <file>] \
    --metadata-idp-file <file> --metadata-sp-file <file> \
    [--min-sp-count <count>] [--min-idp-count <count>] \
    [--language <locale>]
php update-metadata.php --metadata-url <url> [--metadata-url <url>] \
    --metadata-idp-file <file> --metadata-sp-file <file> \
    [--min-sp-count <count>] [--min-idp-count <count>] \
    [--language <locale>]

Argument Description
--------------------
--metadata-url <url>        SAML2 metadata URL
--metadata-file <file>      SAML2 metadata file
--metadata-idp-file <file>  File containing service providers 
--metadata-sp-file <file>   File containing identity providers 
--min-idp-count <count>     Minimum expected number of IdPs in metadata
--min-sp-count <count>      Minimum expected number of SPs in metadata
--language <locale>         Language locale, e.g. 'en', 'jp', ...
--filter-idps-by-ec         Only process IdPs that are in given 
                            entity category. Multiple categories
                            can be provided space separated. 
                            If the IdP is in none, the IdP is ignored.
--help | -h                 Print this man page


PAGE;

$topLevelDir = dirname(__DIR__);

if (isset($_SERVER['SWITCHWAYF_CONFIG'])) {
    require_once($_SERVER['SWITCHWAYF_CONFIG']);
} else {
    require_once($topLevelDir . '/etc/config.php');
}

require_once($topLevelDir . '/lib/functions.php');
require_once($topLevelDir . '/lib/readMetadata.php');


// Script options
$longopts = array(
    "metadata-url:",
    "metadata-file:",
    "metadata-idp-file:",
    "metadata-sp-file:",
    "min-idp-count:",
    "min-sp-count:",
    "filter-idps-by-ec:",
    "language:",
    "help",
);

$options = getopt('hv', $longopts);

if (isset($options['help']) || isset($options['h'])) {
    exit($MAN);
} 

// Set default config options
initConfigOptionsCLI();

// Logger initialisation
initLogger();

// simple options
$language = isset($options['language']) ? $options['language'] : 'en';

if (isset($options['metadata-url'])) {
    $metadataURL = $options['metadata-url'];
} elseif (isset($options['metadata-file'])) {
    $metadataFile = $options['metadata-file'];
} else {
    logError("Exiting: both --metadata-url and --metadata-file parameters missing");
    exit(1);
}

if (!isset($options['metadata-sp-file'])) {
    logError("Exiting: mandatory --metadata-sp-file parameter missing");
    exit(1);
} else {
    $metadataSPFile = $options['metadata-sp-file'];
    $metadataTempSPFile = $metadataSPFile.'.swp';
}

if (!isset($options['metadata-idp-file'])) {
    logError("Exiting: mandatory --metadata-idp-file parameter missing");
    exit(1);
} else {
    $metadataIDPFile = $options['metadata-idp-file'];
    $metadataTempIDPFile = $metadataIDPFile.'.swp';
}

if (isset($options['min-sp-count'])) {
    if (preg_match('/^(\d+)%$/', $options['min-sp-count'], $matches)) {
        if (file_exists($metadataSPFile)) {
            require_once($metadataSPFile);
            $SPCount = count($metadataSProviders);
            $minSPCount = floor($SPCount * $matches[1] / 100);
        } else {
            $minSPCount = 0;
        }
    } elseif (preg_match('/^\d+$/', $options['min-sp-count'])) {
        $minSPCount = $options['min-sp-count'];
    } else {
        logError("Exiting: invalid value for --min-sp-count parameter\n");
        exit(1);
    }
} else {
    $minSPCount = 0;
}

if (isset($options['min-idp-count'])) {
    if (preg_match('/^(\d+)%$/', $options['min-idp-count'], $matches)) {
        if (file_exists($metadataIDPFile)) {
            require_once($metadataIDPFile);
            $IDPCount = count($metadataIDProviders);
            $minIDPCount = floor($IDPCount * $matches[1] / 100);
        } else {
            $minIDPCount = 0;
        }
    } elseif (preg_match('/^\d+$/', $options['min-idp-count'])) {
        $minIDPCount = $options['min-idp-count'];
    } else {
        logError("Exiting: invalid value for --min-idp-count parameter");
        exit(1);
    }
} else {
    $minIDPCount = 0;
}

if(isset($options['filter-idps-by-ec'])){
    $filterEntityCategory = $options['filter-idps-by-ec'];
} else {
    $filterEntityCategory = false;
}

$metadataSources = array();

// Input validation
if (isset($metadataURL) && $metadataURL) {
    if (!ini_get('allow_url_fopen')) {
        logError("Exiting: allow_url_fopen disabled, unabled to download $metadataURL");
        exit(1);
    }
    if (!is_array($metadataURL)) {
        downloadMetadataFile($metadataURL);
    } else {
        foreach ($metadataURL as $url) {
            downloadMetadataFile($url);
        }
    }
} else {
    if (!is_array($metadataFile)) {
        checkMetadataFile($metadataFile);
    } else {
        foreach ($metadataFile as $file) {
            checkMetadataFile($file);
        }
    }
}

$metadataIDProviders = array();
$metadataSProviders = array();

foreach ($metadataSources as $source) {
    logDebug("Parsing metadata file $source");
    list($IDProviders, $SProviders) = parseMetadata($source, $language);
    $metadataIDProviders = array_merge($metadataIDProviders, $IDProviders);
    $metadataSProviders = array_merge($metadataSProviders, $SProviders);
}

// If $metadataIDProviders is not FALSE, dump results in $metadataIDPFile.
if (is_array($metadataIDProviders)){
    $IDPCount = count($metadataIDProviders);
    if ($IDPCount < $minIDPCount) {
        logError("Exiting: number of identity providers found ($IDPCount) lower than expected ($minIDPCount)");
        exit(1);
    }

    logInfo("Dumping $IDPCount extracted identity providers to file $metadataIDPFile");
    dumpFile($metadataTempIDPFile, $metadataIDProviders, 'metadataIDProviders');

    if(!rename($metadataTempIDPFile, $metadataIDPFile)){
        logError("Exiting: could not rename temporary file $metadataTempIDPFile to $metadataIDPFile");
        exit(1);
    }
}

// If $metadataSProviders is not FALSE, dump results in $metadataSPFile.
if (is_array($metadataSProviders)){
    $SPCount = count($metadataSProviders);
    if ($SPCount < $minSPCount) {
        logError("Exiting: number of service providers found ($SPCount) lower than expected ($minSPCount)");
        exit(1);
    }

    logInfo("Dumping $SPCount extracted service providers to file $metadataSPFile");
    dumpFile($metadataTempSPFile, $metadataSProviders, 'metadataSProviders');

    if(!rename($metadataTempSPFile, $metadataSPFile)){
        logError("Exiting: could not rename temporary file $metadataTempSPFile to $metadataSPFile");
        exit(1);
    }
}

// clean up if needed
if (isset($metadataURL) && $metadataURL) {
    foreach ($metadataSources as $source) {
        $result = @unlink($source);
        if (!$result) {
            $error = error_get_last();
            $message = $error['message'];
            logError("Exiting: could not delete temporary file $source: $message");
            exit(1);
        }
    }
}

releaseLogger();

function downloadMetadataFile($url) {
    global $metadataSources;

    $file = tempnam(sys_get_temp_dir(), 'metadata');
    logDebug("Downloading metadata file from $url");
    $result = @copy($url, $file);
    if (!$result) {
        $error = error_get_last();
        $message = explode(': ', $error['message'])[2];
        logError("Exiting: could not download $url: $message");
        exit(1);
    }
    array_push($metadataSources, $file);
}

function checkMetadataFile($file) {
    global $metadataSources;

    if (
        !file_exists($file)
        || filesize($file) == 0
        ) {
        logError("Exiting: file $file is empty or does not exist");
        exit(1);
    }

    if (!is_readable($file)){
        logError("Exiting: file $file is not readable");
        exit(1);
    }

    array_push($metadataSources, $file);
}
