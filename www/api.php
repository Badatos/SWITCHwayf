<?php // Copyright (c) 2019 Geoffroy Arnoud, Guillaume Rousse, and SWITCHwayf contributors

/*------------------------------------------------*/
// JSON Api to retrieve IDPs with paging and query
// The API is compliant with select2 (https://select2.org/)
/*------------------------------------------------*/

$topLevelDir = dirname(__DIR__);
require_once($topLevelDir . '/lib/functions.php');
require_once($topLevelDir . '/lib/common.php');
require_once($topLevelDir . '/lib/idpApiObjects.php');

header('Content-Type: application/json');

if (array_key_exists("idpCookie", $_GET)) {
    // Small tweaks, because for unknown reason, the cookie value provided in GET
    // param is not formatted as in regular cookie.
    $idpCookie = str_replace(
        array("%3D", "%2B", "+"),
        array("=", " ", " "),
        $_GET["idpCookie"]
      );

    $IDPArray = getIdPArrayFromValue($idpCookie);
}

$idpRepository = new IdpRepository($IDProviders, $IDPArray);

if (array_key_exists("page", $_GET)) {
    if (array_key_exists("search", $_GET)) {
        //error_log("Search with request ".$_GET["search"]);
        echo $idpRepository->toJsonByQuery($_GET["search"], $_GET["page"], getSelect2PageSize());
    } else {
        //error_log("Search page ".$_GET["page"]);
        echo $idpRepository->toJsonByPage($_GET["page"], getSelect2PageSize());
    }
} elseif (array_key_exists("lastIdp", $_GET)) {
    // Provide lastUsedIdp
    echo $idpRepository->getLastUsedIdpJson();
} else {
    echo $idpRepository->toJson();
}
