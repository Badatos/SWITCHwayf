Copyright (c) 2024, Switch
See LICENSE file for details.

-------------------------------------------------------------------------------

SWITCHwayf Documentation
========================

Find below the documentation and configuration options for the SWITCHwayf.

-------------------------------------------------------------------------------

**This document is written in the markdown syntax**

-------------------------------------------------------------------------------

Description
-----------
The SWITCHwayf is an implementation of the Shibboleth WAYF and SAML2 Discovery
Service protocol for use withing a Shibboleth architecture.

Some of the Features:

- Supports Discovery Service and the Shibboleth authentication request protocol
- Supports processing SAML2 metadata files
- The central Discovery Service also works without Java Script
- Search-as-you type or selection from a list of organisations
- Various customizations options for header, footer, language strings etc.
- I18N support, currently language packs for en, de, it, fr, tr and some other
  languages are included
- HTML code generation for embedding the WAYF directly into a web page
- Support for remembering IdP selection accross different services (when
  Embedded WAYF is used)
- Preselecting entry in drop down list by
  - SAML common domain cookie that contains selected Identity Providers
  - resource path info hint (e.g.
    /WAYF/unige.ch?shire=https://... selects University  of Geneva, depends
    of course on the ID scheme a federation uses)
  - Kerberos preselection
  - IP range preselection
  - IP reverse DNS lookup preselection
- Transparent redirection mode, e.g. /WAYF/unige.ch/redirect?shire=https://...

-------------------------------------------------------------------------------

Customization Options
---------------------
Since version 1.12 any graphical aspects can be customized such that these
changes normally should survive bug-fix and minor version upgrades.
Files whose names start with 'default-' can be copied and renamed to start with
'custom-' in order to  customize the file's behaviour.

In particular, the following customizations can be applied:

* HTML Header:   `custom-header.php`
  Customize page header

* HTML Footer:   `custom-footer.php`
  Customize page footer

* HTML Body:     `custom-body.php`
  Customize WAYF/DS body

* HTML Body:     `custom-settings.php`
  Customize WAYF/DS permanent settings body

* HTML Body:     `custom-notice.php`
  Customize WAYF/DS permanent settings notice body

* HTML Body:     `custom-embedded-wayf.php`
  Customize WAYF/DS body

* HTML Error:    `custom-error.php`
  Customize error messages

* CSS Main Style:    `css/custom-styles.css`
  Customize CSS styles that are loaded in addition to the default-styles.css.
  Therefore, they can be used to overwrite the default CSS styles.

* CSS Improved Drop Down Style:    `css/custom-ImprovedDropDown.css`
  Customize CSS styles to alter the appearance of the improved drop-down list,
  both for the stand-alone WAYF as well as the Embedded WAYF. The styles are
  loaded in addition to the default-ImprovedDropDown.css.

* CSS Improved Drop Down Style:    `css/custom-select2.css`
  Customize CSS styles to alter the appearance of the Select2 drop-down list,
  both for the stand-alone WAYF as well as the Embedded WAYF. The styles are
  loaded in addition to the default-select2.css.

* Languages:     `custom-languages.php`
  Can be used to change default or add new language strings. The custom
  languages strings in addition to the default styles. Therefore, they can be
  used to overwrite the default CSS styles.
  This file can also be used to white or black list certain languages by
  adding to the end of the file:

        // Example to black list Japanase and Portuguese
        unset($langStrings['ja']);
        unset($langStrings['pt']);

        // Example to white list English, Italian, French and German
        foreach($langStrings as $lang => $strings){
          if ($lang != 'en' && $lang != 'it' && $lang != 'fr' && $lang != 'de'){
            unset($langStrings[$lang]);
          }
        }


If a custom file doesn't exist yet, the default templates and settings
are used. To create a custom template, copy the default files with:

`cp default-{$template}.php custom-{$template}.php`

where {$template} stands for the file you want to customize. Unless otherwise
mentioned the custom files replace the default files completely. Please read the
above information for each custom file.

-------------------------------------------------------------------------------

Logging
-------

The SWITCHwayf currently uses two types of logs:

* General Log
  Whenever a warning or an error message is thrown, this goes
  to the system log file. Errors occur when for example files
  cannot be read or written due to permission problems.

* Audit Log
  This is file-based logging. Whenever a user is redirected
  to an Identity Provider, a new entry is added to the file
  $WAYFLogFile which typically is in the same directory as
  the web server access log files (because it's the web server
  that writes to this file)


On the Audit log:
If the configuration option $useLogging is true, an audit log
file will be written to the path specified in $WAYFLogFile.
This log file is an audit log file where each line is an entry
of the form:

{DATE} {TIME} {IP} {IDP-SELECTION} {REQUEST-TYPE} {IDP-ENTITYID} {FORWARDING-URL}

Log entries are only created if the user was forwarded to an Identity Provider.

- {DATE}             = Date of request, e.g. 2010-11-02
- {TIME}             = Time of request, e.g. 06:25:13
- {IP}               = IP of requester, e.g. 127.0.0.1
- {IDP-SELECTION}    = How the IdP was selected: Cookie or Request
- {REQUEST-TYPE}     = Type of request: DS, WAYF, Embedded-DS, Embedded-WAYF
- {IDP-ENTITYID}     = EntityID of the IdP the user was forwarded to.
- {FORWARDING-URL}   = URL the user was redirected to
- {SP-ENTITYID}      = EntityID of the SP the user was coming from.

-------------------------------------------------------------------------------

Optimizations
-------------

If an instance of the SWITCHwayf has to deal with many requests and the load
is becoming  higher and higher, one should consider using a PHP opcode
cacher like XCache, apc,  eaccelerator, phpa, truck-mmcache or similar.

Using such a tool can decrease the processing time of the PHP code almost by
half. However, own tests have shown that the bottleneck in general is not
the PHP processing but the TLS handshake, which has nothing to do with PHP
or the SWITCHwayf itself. Still, the more entities (Identity Providers and
Service Provider) and instance consumes, the higher the processing speed gain.

Benchmark tests conducted by SWITCH demonstrated that generating the
Javascript WAYF/embedded-wayf.js can be speed up using APC or XCache
considerably (> 15%) if the  script is accessed via HTTP (without TLS).
However, if the script is accessed via HTTPS, the overall speed gain by using
an opcode cacher is much less because the TLS hand-shake is what
needs most time.

When having lot's of IDP, using Select2 drop-down can provide great performane
increase from end-user point of view, because the full IDP list is not
downloaded.

-------------------------------------------------------------------------------

SAML2 Metadata support
----------------------

If the SWITCHwayf should display the list of IdPs by parsing them from a
SAML2 Medatadata file that is used by Shibboleth:

- Set $useSAML2Metadata in config.php to true
- Specify the path to the metadata file that should be read in $metadataFile
  and make sure this file is updated regularely by Shibboleth or a cron job
- Make sure the files specified in $metadataIDPFile and $metadataSPFile can be
  written by the userthat executes the PHP script (the web server user,
  e.g. www-data or _www)
- You may want to execute php SWITCHwayf/bin/update-metadata.php
  manually or with a cron job to avoid that delayed requests for users
  who happen to trigger automatic processing of new metadata files.
  See php bin/update-metadata.php -h for some details and
  suggestions on how to use the script.

The parsed IDP and SP entries will be stored in $metadataIDPFile and
$metadataSPFile as executable PHP code, thus benefiting from opcode caching
(see chapter "Optimization" above) if enabled.

If an entry should be changed, removed or extended in this automatically
generated file, one can extend the IDP definitions by modifying them in
the $IDPConfigFile. To overwrite IDP values with entries in the $IDPConfigFile,
make sure the entry $SAML2MetaOverLocalConf is set to 'false';
For example one could change the displayed name of an IdP by adding an entry in
the file $IDPConfigFile like:

    $IDProviders["https://sso.example.org/idp/shibboleth"]["Name"] = "Foobar";

If an entry is in the SAML metadata file but should not be shown in the drop
down list, it can be hidden/removed with:

    $IDProviders["https://sso.example.org/idp/shibboleth"] = '';

To force a periodic refresh of the IdP, run readMetadata.php in command line
mode, i.e. by executing a cron script like:

    5 * * * * /usr/bin/php readMetadata.php > /dev/null

-------------------------------------------------------------------------------

Embedded WAYF support
---------------------

With the embedded WAYF support administrators of a Shibboleth protected
application can easily integrate a Discovery Service on the any page of their
application just by copying and adapting the HTML code snippet generated by the
SWITCHwayf via the URL /WAYF/embedded-wayf.js/snippet.html

The embedded WAYF then will display on the remote site a drop-down list with the
Identity Provider to authenticate.

One can also configure the embedded WAYF to hide or add Identity Providers
(even from remote federations) or adapt the look and feel of the embedded wayf.
This can be done by simpling modifying the JavaScript variables in the HTML
snippet.


**Note**
When activating the Embedded WAYF, carefully protect the host where the WAYF is
operated on. If an instance of SWITCHwayf gets compromised, an attacker could
modify the JavaScript that is embedded on the remote site in a malicous wayf
(e.g. phish the user's password, redirect users to malicous pages, steal their
sessions etc). One should also ensure that a centrally operated WAYF has a very
high availability because many services will depend on it.

Also, please be aware that using the Embedded WAYF allows anybody to guess a
user's Home Organisation without much effort. This information then could be
used for phising attacks for example!

Example Embedded WAYF Usage:

* https://toolbox.switch.ch/
* https://aai-viewer.switch.ch/
* https://www.olat.uzh.ch/
* https://ilias.unibe.ch/
* https://sympa.unil.ch/

-------------------------------------------------------------------------------

How to use the Embedded WAYF?
-----------------------------

1. Find a web page where a Discovery Service in form of the Embedded WAYF
   can be placed. This page of course may not enforce a Shibboleth session.

2. Get a sample HTML snippet to embed on the page. To get the snippet access the
   WAYF with this URL:
   https://{HOSTNAME}/{PATH-TO-WAYF}/WAYF/embedded-wayf.js/snippet.html
   The script should return HTML code that consists of a configuration
   JavaScript, a JavaScript loaded from the
   https://{HOSTNAME}/{PATH-TO-WAYF}/WAYF/embedded-wayf.js and a
   NoScript element for cases where a user has JavaScript not enabled.

3. Adapt at minimum all the 'ESSENTIAL SETTINGS' at the top of the snippet and
   the URL in the NoScript element.
   Optionally also adapt the recommended and advanced settings.
   Optionally remove all commented-out/obsolete settings of the configuration
   JavaScript.

4. Insert the edited snippet anywhere in the body of a page outside any HTML
   'form' element.

5. Save the page and then access it with your web browser to check whether it
   works. Also try logging in with JavaScript disabled.

Embedded WAYF code limitations:
* The Embedded WAYF won't work if placed within an HTML form element.
* If the embedded WAYF is placed on the right side or at the bottom of a web page,
  it may be that the web browser cannot expand and render the complete drop-down
  list of Identity Providers. Turning on the wayf_use_improved_drop_down_list
  setting might be a solution in this case.
* If placed on a host where no Service Provider is installed, the Embedded WAYF
  might not be able to detect whether a user is logged in or not. Also, the
  wayf_use_disco_feed might not be used.
* When using Select2, one must activate settings both in the embedding web page
  and as query param of the downloaded JS (this is explained in snippet)
* IDP Api allows '*' as origin for requests, but limiting this can obviously
  prevent embedded WAYF to work with Select2

-------------------------------------------------------------------------------

Kerberos support
----------------

If this features is used, the web server needs to support Negotiate/SPNEGO
Kerberos protocol. For example by using mod_auth_kerb.

1. Make a symlink of the file 'WAYF' and name it like configured in the variable
   $kerberosRedirectURL

2. Protect file $kerberosRedirectURL with Kerberos. The Kerberos realm must be
   specified in "IDProvider.conf.php" for each IdP. Each IdP's KDC must also
   establish a Kerberos cross-realm trust with the WAYF's KDC. This was tested
   with a Windows 2000 KDC, with the WAYF running on RHEL4.

-------------------------------------------------------------------------------

Configuration file format
-------------------------

Have a look at the file 'SWITCHwayf/etc/IDProvider.conf.php' for an example of the file format
that is used to configure the list of Identity Provider to display. It's
supposed to be mostly self-explanatory. Basically the file format is PHP code
that defines an array of arrays called $IDProviders.

The keys of the array $IDProviders must correspond to the entityIDs of the
Identity Providers or a unique value in case of a cascaded WAYF/DS or
a category. The entityID must be a valid URI (URL or URN) where in the
case of a URN the last component must be a valid hostname.

If metadata is not parsed from SAML2 metadta (using the setting
$useSAML2Metadata = false), the IdPs and category entries will be displayed
in order as defined in the configuration file and no sorting is done.

If SAML2 metadata is used ($useSAML2Metadata = true) to generate the list of
Identity Providers, they are sorted within the category/type according to their
Index value (see below) and then alphabetically after their (local) Name.
If an IdP has no type, it will be in the category 'unknown', which will be added
at the end of the drop down list.
If an IdP has a type for which no category was defined, it will also be added
to the category unknown but  will keep its type value, which is used for sorting
and for the categories of the Embedded Discovery Service.

A general entry for an Identity Provider, a cascaded WAYF/DS or a category is
of the following form:

$IDProviders[{KEY}] = {ENTRY}

* {KEY} is a unique value that must correspond to the entity's entityID in case
  the entry stands for an Identity Provider. For entries of Type category, the
  {KEY'} should be an identifier that corresponds to a 'Type' of an IdP.

* '{ENTRY} is a hash array with the following keys:

  * ['Type']:   Optional
    Type that is used for the embedded wayf to hide or show certain categories.
    Default type will be 'unknown' if not specified.
    An entry for another WAYF/DS that the user should be redirected to should
    have ['Type'] ='wayf
    The Type values 'category' and 'wayf' are reserved words that are not allowed
    to be assigned to entries for Identity Providers.

  * ['Name']:   Mandatory
    Default name to display in drop-down list

  * [{LANG}]:   Optional
    {LANG} is a language identifier, e.g. 'en-GB', 'it', 'fr-F', 'de', ...
    The value is an array with the following keys:
    - ['Name']:     Optional
      Display name
    - ['Keywords']: Optional
      Keywords associated with the Identity Provider.
      Used for search-as-you-type feature of improved drop-down list. Space delimited.

  * ['SSO']:    Mandatory
    Should be the SAML1 SSO endpoint of the IdP
  * ['Realm']:  Optional
    Kerberos Realm
  * ['IP'][]:   Optional
    IP ranges of that organizations that can be used to guess a user's Identity
     Provider
  * ['Index']:  Optional
    An alphanumerical value that is used for sorting categories and Identity
    Provider in ascending order if the Identity Providers are parsed from metadata.
    This is only relevant if $includeLocalConfEntries = true


For category entries, only Type, (local) Name and Index are relevant.
The format for the file $metadataSPFile is very similar.
A general entry for an Identity Provider, a cascaded WAYF/DS or a category is
of the following form:

$metadataSProviders[{KEY}] = {ENTRY}

* {KEY} is a unique value that must correspond to the Service Provider's entityID.

* 'ENTRY} is a hash array with the following keys:

  * ['Name']:       Mandatory
    Default name to display in drop-down list. By default the MDUI:DisplayName,
    the ServiceName or the entityID is used. If there is a display name
    available in the WAYF's default language that one will be used. Otherwise
    English or the only  available DisplayName is used.

  * [{LANG}]:   Optional
    {LANG} is a language identifier, e.g. 'en-GB', 'it', 'fr-F', 'de', ...
    The value is an array with the following keys:
    - ['Name']:     Optional
      Display name

  * ['DSURL']:      Optional
    List of DiscoveryService endpoints of the SP.

  * ['ACURL']:      Mandatory
    List of Assertion Consumer endpoints of the SP.

  * ['Protocols']:  Mandatory
    Protocols supported by the SP, e.g.: urn:oasis:names:tc:SAML:2.0:protocol
    urn:oasis:names:tc:SAML:1.1:protocol

-------------------------------------------------------------------------------

Path Info parameters and files
------------------------------

Modifying the WAYF's URL it is possible to influence its behaviour. This can be
done by appending certain Path Info extension to the URL. The Path Info
components can also be combined. The allowed syntax is:

* [/{I18N-STRING}][/redirect][/{ENTITYID-HOSTNAME}]
* [/{I18N-STRING}][/embedded-wayf.js]
* [/embedded-wayf.js/snippet.html]
* [/IDProviders.json]
* [/IDProviders.php]
* [/IDProviders.txt]

**Note:**
The web server must support the use of Path Info.

-------------------------------------------------------------------------------


Hinted Identity Provider and transparent redirects
--------------------------------------------------
Path Info Extensions: [/redirect][/{ENTITYID-HOSTNAME}]

{ENTITYID-HOSTNAME} must be the host name of an entityId or the last component
of a URN. Examples:

* https://aai-login.switch.ch/idp/shibboleth         -> aai-login.switch.ch
* urn:mace:switch.ch:aaitest:aai-demo-idp.switch.ch  -> aai-demo-idp.switch.ch

If '/redirect' is included in the Path Info as well, the web browser is
redirected transparently to the specified entityID hostname.

**Note**
One must make sure that the entityID hostname is not the same as one of
the reserved keywords like 'redirect', the below mentioned file types
or a i18n langauge abbreviation.

-------------------------------------------------------------------------------

Language preselection:
----------------------
Path Info Extensions: [/{I18N-STRING}]

Examples of {I18N-STRING} strings are 'en', 'de_CH' or 'fr_CH.ISO8859-1' etc.
However, in the default distribution only 'en', 'de', 'fr', 'it' and 'pt' are
available and  supported. But it would be easy to create sub types of existing
languages  for country/region support by adding something like this to
languages.php:


    // Create a country specific copy of the German language strings
    $langStrings['de_CH'] = $langStrings['de'];

    // Overwrite a specific string
    $langStrings['de_CH']['title'] = 'Auswahl der Heimorganisation';

-------------------------------------------------------------------------------

Multi-tenant Deployment:
------------------------
If there should be deployed multiple instances of the SWITCHwayf
on the same host, it might be desired to make all instances
use the same code base but different configuration files.
To achieve this, the SWITCHWAYF_CONFIG environment variable can
be used.

The usage of SWITCHWAYF_CONFIG environment variable allows to
specify an alternative location for the configuration file.
The default configuration file is still used, if this variable
is not defined. This allows a single software deployment to
provides a discovery services for multiple federations,
depending of virtual host or URL used.

Below is an example of an Apache httpd server configuration
with two different virtual hosts using different
configuration files:

    DocumentRoot /usr/share/SWITCHWwayf
    <Directory /usr/share/SWITCHWwayf>
        Require all granted
        DirectoryIndex WAYF
    </Directory>

    <VirtualHost *:443>
        ServerName wayf.switch.ch
        SetEnv SWITCHWAYF_CONFIG=/etc/SWITCHWwayf/switch_config.php
    </VirtualHost>

    <VirtualHost *:443>
        ServerName wayf.edugain.org
        SetEnv SWITCHWAYF_CONFIG=/etc/SWITCHWwayf/edugain_config.php
    </VirtualHost>

-------------------------------------------------------------------------------


Special handlers:
-----------------
In order for the Embedded WAYF feature to work there are some special files that
need to be generated. The following Path Info Extensions must be the last
components of the Path Info URL.

Path Info Extensions:

* [/deleteSettings]
  As the name suggests, this handler delete all settings cookies that were stored
  by the WAYF service in cookies. Unless there is a 'return' GET argument
  provided the user is sent to the settings page.

* [/embedded-wayf.js]
  Generates the JavaScript for the Embedded WAYF

* [/embedded-wayf.js/snippet.html
  Generates HTML snippet for the Embedded WAYF

* [/ShibbolethDS-IDProviders.js]
  Returns JavaScript consisting of only a variable called myJSONObject. It
  contains the IDProviders array. If $exportPreselectedIdP = true, the last
  element of that array will be a key called 'preselectedIDP', which contains
  the  Identity Provider that would be preselected in the drop-down list for
  that user.

* [/ShibbolethDS-IDProviders.json]
  Same as above but as a JSON data array.

* [/IDProviders.txt]
  Same as above but in human readable form.

* [/IDProviders.php]
  Same as above but as PHP code

* [/api/idps]
  JSON API used by Select2 to fetch IDP. Supports pagination and server-side
  searches. 
