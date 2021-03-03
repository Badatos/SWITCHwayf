<?php // Copyright (c) 2019 Geoffroy Arnoud, Guillaume Rousse, and SWITCHwayf contributors

use PHPUnit\Framework\TestCase;

require("../lib/idpApiObjects.php");
require("../lib/readMetadata.php");

function time_elapsed($message)
{
    static $last = null;

    $now = microtime(true);

    if ($last != null) {
        printf("%s => %f\n", $message, $now - $last);
    }

    $last = $now;
}

final class IdpApiTest extends TestCase
{
    public function testSort()
    {
	$customStrings = array(
    		'federationName' => 'Fédération eduGAIN',
    		'providersIdPId' => 'https://dev-idp-fournisseurs.renater.fr/idp/shibboleth',
   		 'supdataIdPId'   => 'https://dev-idp-supdata.renater.fr/idp/shibboleth'
	);
        time_elapsed("[Sort] Init");

	$IDProviders = array();
$IDProviders['unknown'] = array (
    'Name' => $customStrings['federationName'],
    'Type' => 'category'
);

$IDProviders['external'] = array (
    'Name' => getLocalString('external'),
    'Type' => 'category'
);
	$language="fr";
        require("edugain-IDProvider.metadata.php");
	$IDProviders = mergeInfo($IDProviders, $metadataIDProviders, true, true);

        time_elapsed("[Sort] doSort");

        sortIdentityProviders($IDProviders);

        time_elapsed("[Sort] endSort");
         $repo = new IdpRepository($metadataIDProviders);
    
        time_elapsed("[GetFirstPage] Creating repository");
    }

    // public function testGetFirstPage()
    // {
    //     time_elapsed("[GetFirstPage] init");
    //
    //     require("edugain-IDProvider.metadata.php");
    //
    //     time_elapsed("[GetFirstPage] Loading eduGain IDP");
    //
    //     $repo = new IdpRepository($metadataIDProviders);
    //
    //     time_elapsed("[GetFirstPage] Creating repository");
    //
    //     file_put_contents("/tmp/eduGainFirstPage.json", $repo->toJsonByPage(1, 100));
    //
    //     time_elapsed("[GetFirstPage] Putting 1st page to a file");
    // }
    //
    //
    // public function testQuery()
    // {
    //     time_elapsed("[Query] init");
    //     global $IDProviders;
    //
    //
    //     require("edugain-IDProvider.metadata.php");
    //
    //     $IDProviders = $metadataIDProviders;
    //
    //     time_elapsed("[Query] Loading eduGain IDP");
    //
    //     $repo = new IdpRepository($metadataIDProviders);
    //
    //     time_elapsed("[Query] Creating repository");
    //
    //     file_put_contents(
    //       "/tmp/eduGainFirstPageQuery.json",
    //       $repo->toJsonByQuery("renater", 1, 100)
    //     );
    //
    //     time_elapsed("[Query] Putting 1st page to a file");
    // }
}
