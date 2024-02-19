Copyright (c) 2024, Switch
See LICENSE file for details.

-------------------------------------------------------------------------------

SWITCHwayf Changes
==================

SWITCHwayf version: v2.1
Bundled with:

* JQuery v3.7.1
* ImprovedDropDown v1.0.2 (with modifications)
* Select2 v4.0.6-rc.0 and i18n files for languages supported by SWITCHwayf

Find below the changes for past releases of the SWITCHwayf and in the credits
sections the people who contributed to the SWITCHwayf.

-------------------------------------------------------------------------------

**This document is written in the markdown syntax**

-------------------------------------------------------------------------------

Version Number Policy
---------------------

* Releases with a version number 'X.Y.Z' are bug fix releases
  correcting small bugs, typos and graphical issues.
* Releases with a version number 'X.Y' are minor releases that
  introduce new functionality of fix non-trivial bugs.
  Few adaptions in the configuration might be necessary to
  upgrade to minor releases.
* Releases with a version number X are major releases that will
  require major changes in the configuration files. Therefore,
  a clean installation might be necessary for such releases.

-------------------------------------------------------------------------------

SWITCHwayf Version History
--------------------------
* Version 2.1 - Release data: 19. February 2024
  - Output hostname and remote address in HTML as comments for debugging multi-node setups
  - HTML and graphics beautifications
  - Updated installation instructions
  - Fixed bug where keywords separated with + were not processed correctly 
  - Updated Jquery to v3.7.1
  - Add support for a new type of (experimental) dropdown: select2 (https://select2.org/),
    which loads IDP from a new JSON API. All loading of IDP occurs through ajax
    calls, including searches. Works with both standard and embedded WAYF.
    This and related code were provided by Geoffroy Arnoud and Guillaume Rousse from RENATER.

* Version 2.0 - Release date: 7. March 2019
  This version comes with a new directory structure that
  is quite different from previous versions.
   - Changed structure of directory and files
     Added update-metadata.php for handling metadata.
     Code provided by Guillaume Rousse
   - Added code to filter IdPs by entity categories.
     Code provided by Michael Simon
   - Added Turkish translation provided by M. Uğur Yilmaz
   - Added improved sorting for accented strings.
     Code provided by Geoffroy Arnoud

* Version 1.21 - Release date: 19. January 2018
  - Allow loading configuration from a path in a
    web server environment variable to allow multi-tenant
    deployments. Code provided by Guillaume Rousse.
  - Added code to readMetadata.php to ignore comments
    Contributed by Chris Philips
  - Manually added/Discovery Feed IdPs can now also be
    added as most used IdPs
  - Updated JQuery to v3.2.1
  - Hide IdPs also from category 'Last Used IdP'
  - User HTTP post has preference over session cookies
    set by 'remember' checkbox
  - Various other improvements suggested by Guillaume Rousse.
  - Removed SWITCH-specific strings from languages file
  - Made Javascript less prone to conflicts thanks to
    contributed code from Christian Glahn

* Version 1.20.2 - Release date: 22. December 2015
  - Upgraded JQuery library to 3.1
  - Fixed bug #3736 that causes SProvider.metadata.php not to
    be written/updated if metadata file only contains IdPs.
  - Updated in copyright information

* Version 1.20.1 - Release date: 22. December 2015
  - Added code to prevent WAYF loading invalid metadata files
    Reported with a patch by Olivier Salaün
  - Fixed an HTML issue that caused the interface elements
    in Chrome to be displayed in the wrong order
  - Fixed a few typos in the configuration help texts

* Version 1.20 - Release date: 30. April 2015
  - Added support for Hide-From-Discovery
  - Ensured that metadata is not processed multiple times
    when it changed
  - Fixed a bug that affected Discovery URLs in metadata
    containing GET arguments
  - Added an option to central and embedded WAYF to disable
    loading logo images from third party hosts.
  - Improved logging to system log
  - Updated Japanese language pack.
    Contributed by Takeshi Nishimura
  - Updated JQuery library to v1.11.2

* Version 1.19.4 - Release date: 10. October 2014
  - Fixed/improved some CSS and HTML code for better rendering
    of the stand-alone WAYF on mobile devices.
    Reported with a patch by Olivier Salaün

* Version 1.19.3 - Release date: 27. August 2014
  - Fixed a bug that would cause readMetadata.php not read the correct
    SAML1 SSO endpoint which could result in users being redirected
    to a wrong URL when the Shibboleth protocol is used for SAML1.
    Bug reported with a patch by Olivier Salaün
  - Sorting of Identity Providers is now case-insensitive
  - Improved the code to handle large metadata files to prevent memory
    limit issues
  - Improved drop-down list now does not reload JQuery 1.x unless JQuery
    version is older than 1.5
  - Updated JQuery library to latest version, which is 1.11.1

* Version 1.19.2 - Release date: 7. March 2014
  - Fixed a bug that caused JavaScript errors because of new lines in
    certain metadata elements.
  - Fixed a bug where text for the Embedded WAYF would not be properly
    substituted
  - Fixed a bug where the height of the Embedded WAYF improved drop down
    list would be too small to read/select an entry.
  - Fixed a bug which caused that the wayf_default_idp setting was
    ignored

* Version 1.19.1 - Release date: 10. January 2014
  - Fixed a bug that listed the last used IdPs in wrong order
  - Fixed a bug where Identity Providers would not be shown in the drop-down  
    list unless there was at least one entry in IDProviders.conf.php
  - The default category 'unknown' is now also shown in case the last used
    category is displayed.
  - Saved one click to permanently save a default organisation.
  - Changed some language strings

* Version 1.19 - Release date: 29. October 2013
  - Added search-as-you-type support to Embedded WAYF. This feature is off by
    default as it is currently experimental. Can be activated with:  
    var wayf_use_improved_drop_down_list = true
  - Added MDUI logo support. Only favicon logos (16x16 px) will be used.
    The logos will be dynamically loaded and only if they are visible
  - Added new setting $showNumOfPreviouslyUsedIdPs to standalone and embedded  
    WAYF to show last n used IdPs at top of drop down list. Default is 3.
  - Added Embedded WAYF option wayf_overwrite_from_other_federations_text  
    to overwrite the category name of IdPs from other federations
  - Added Embedded WAYF option wayf_auto_redirect_if_logged_in that
    automatically sends a user to the wayf_return_url if he already is
    authenticated.
  - Various Javascript improvements to offload computation from WAYF to client
    and to improve the code quality.
  - Replaced the term 'Home Organisation' in the language strings to more
    generic terms that probably are better understood by users.
  - SP names from MDUI metadata elements are now used if available
  - Added new version of JQuery library
  - Some small styling changes/CSS improvements

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/56>
  Please read the specific update instructions in the README file.

* Version 1.18 - Release date:  5. August 2013
  - Changed default SessionInitiator of the Embedded WAYF to
    /Login because this has been the default SessionInitiator in
    Shibboleth for quite some time now.
  - Corrected viewport meta tag separator of default header as suggested
    by Andrew Sokolov from Saint Petersburg State University
  - Fixed a bug in the IdP preselection of the embedded wayf when
    additional IdPs where added
  - Removed as many SWITCH-specific graphics and texts as possible.
  - Introduced configuration options to allow easier customization.
  - Fixed a few small bugs
  - Added some optimizations to the drop-down list search-as-you type
    feature
  - The log file now logs - if possible - also the SP entityID/providerId
  - Some small styling changes/CSS improvements
  - Added Japanese locales from the GakuNin version of the WAYF

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/62>
  Please read the specific update instructions in the README file, as some
  new configuration options were introduced that should be revised.

* Version 1.17.1 -  Release date:  14. June 2012
  - Fixed a bug occuring when wayf_sp_samlDSURL contains GET arguments  
    Bug reported with a patch by Takeshi Nishimura
  - Fixed typo in configuration otpion useImprovedDropDownList
  - Added Javascripts required for improved drop down list

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/55>

* Version 1.17    Release date:  18. May 2012
  - Added CSS styles for mobile view
  - Embedded WAYF now reads 'entityID' and 'return' GET arguments.  
    They get precedence over the values configured for the Embedded WAYF.
  - Embedded WAYF logged in message now contains a link to target URL

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/45>

* Version 1.16 - Release date: 19. January 2012
  - Added an improved version of the drop down list to the WAYF  
    Inspired by code from Takeshi Nishimura from NII (Japan)  
    Uses modified ImprovedDropdown JQuery library by John Fuex  
    See LICENSE file for further information
  - Added cookieSecurity option to set and transmit cookies securely  
    Code contributed by Takeshi Nishimura from NII (Japan)
  - Added additional data protection feature that uses the referer to
    decide whether or not to preselect an Identity Provider in the
    Embedded WAYF.  
    Code contributed by Takeshi Nishimura from NII (Japan)
  - If the Discovery Feed feature is activated only those IdPs are shown
    that are contained in the feed. Others will be hidden automatically.
  - Added Keywords property to format of IDP entries to allow users to
    search Identity Providers using a keyword.

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/40>

* Version 1.15 - Release date: 21. October 2011
  - A default and custom CSS file can now be used
  - Graphical design now is based new SWITCH harmos elements
  - Adapted JSON output to use format used by Shibboleth SP
  - Renamed some string keys to make them independent from SWITCH
    **Please review the 'Specific Update Instructions' in the README file**
  - Added support for the Shibboleth SP 2.4 Discovery Feed JSON output
    in Embedded WAYF
  - Focus on submit button works better with different browsers
  - Invalid values for width and height are now defaulted to auto for
    Embedded WAYF
  - Fixed a URL composing bug that resulted in a wrong return URL to
    the Service Provider if the return parameter did not contain any GET
    arguments. Reported by Tom Scavo
  - Made implementation behave according to the Discovery Service protocol
    specification when it comes to the return parameter. This parameter
    is optional in case the DS knows the SP Discovery URL.  
    Reported by Tom Scavo.

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/26>

* Version 1.14.3 - Release date: 4. March 2011
  - Fixed a race condition.  
    Thanks go to Robert Basch for reporting the issue and providing a patch.

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/32>

* Version 1.14.2 - Release date: 15. December 2010
  - IDProvider.conf.php and config.php are not overwritten anymore by upgrades
  - Logging to syslog now works properly and is more consistent
  - Access log now properly locks file
  - Unknown category is not shown anymore when there is no other category
  - Namespaces are now taken properly into account when parsing SAML2
    metadata. Thanks go to Olivier Salaün for reporting this issue and
    submitting a patch.
  - Improved installation instructions

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/25>

* Version 1.14.1 - Release date: 12. November 2010
  - Fixed an encoding bug that affected non-ASCII characters in JavaScripts.  
    Thanks to Prof. Kazutsuna Yamaji for reporting this issue.
  - Corrected behaviour of $enableDSReturnParamCheck and
    $useACURLsForReturnParamCheck. There won't be an error anymore if an SP
    has no <idpdisc:DiscoveryResponse> extension defined. In such a case
    there will only be a check if $useACURLsForReturnParamCheck is enabled.
  - Fixed a bug in readMetadata.php that prevented CLI execution
  - Changed the default configuration option to generate the Embedded WAYF
    to false due to some concerns regarding phishing attacks
  - Added proper copyright statements to all source code files

  Issues: <https://forge.switch.ch/redmine/projects/wayf/versions/21>


The revision history of older versions, can be found on the SWITCHwayf web page:
<https://forge.switch.ch/redmine/projects/wayf/wiki/Changes>

-------------------------------------------------------------------------------

Credits
-------

Main developer of the SWITCHwayf: Lukas Hämmerle (SWITCH)

The SWITCHwayf uses code from the following libraries:

* jQuery by the jQuery Foundation and other contributors,
  http://jquery.com/
* Improved Dropdown by John Fuex
  https://bitbucket.org/Johnfx/improveddropdown-jquery-plugin/src
* jQuery Plug-in "Basic Visibility Detection" by Digital Fusion
  http://teamdf.com/

Please consult the LICENSE.txt file for the individual licenses of these components.

Find below a list of people who have contributed to the code, either because they
found bugs, suggested improvements or contributed code. Have a look at the
version history in order to see the individual contributions. The list is sorted
alphabetically.

- Geoffroy Arnoud from RENATER (FR)
- Robert Basch from MIT (US)
- Pavlos Drandakis from University of Athens (GR)
- Nicolas Dunand from Université Lausanne (CH)
- Michael R. Gettes from Internet2 (US)
- Christian Glahn, HTW Chur (CH)
- Nuno Gonçalves from FCCN (PT)
- Florent Guilleux from CRU (FR)
- Guillaume Rousse from RENATER (FR)
- Josh Howlett from University of Bristol (UK)
- Franz Kuster from ETH Zurich (CH)
- Wolgang Lierz from ETH Zurich (CH)
- Takeshi Nishimura NII National Institute of Informatics (JP)
- Lourival Pereira Vieira Neto from RNP (BR)
- Chris Philips, Canarie (CA)
- Martins Purins from Latvijas Universitates (LV)
- Olivier Salaün from RENATER (FR)
- Tom Scavo from Internet2 (US)
- Michael Simon from KIT (DE)
- Andrew Sokolov, Saint Petersburg State University (RU)
- Mika Suvanto from CSC (FI)
- Huân Thebault from Centre de Calcul de l'IN2P3 (FR)
- Prof. Kazutsuna Yamaji from NII National Institute of Informatics (JP)
- M. Uğur Yilmaz, TÜBİTAK-ULAKBİM (TR)
- And of course all SWITCH staff members who have contributed suggestions,
  bug fixes and translation to this code.

Special thanks also go to RENATER, the French
Research & Education Network. The main developer
(Lukas Hämmerle) has been a guest at RENATER for 6 months in
2013, during which he worked - among other things - also on the
versions 1.18 and 1.19 of the SWITCHwayf.
