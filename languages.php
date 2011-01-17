<?php // Copyright (c) 2011, SWITCH - Serving Swiss Universities

// WAYF localized language strings
// Make sure to use HTML entities instead of plain UTF-8 characters for 
// non-ASCII characters if you are using the Embedded WAYF. It could be that the
// Embedded WAYF is used on non-UTF8 web pages, which then could cause 
// encoding issues

// English, default
$langStrings['en'] = array (
'title' => 'Home Organisation Selection',
'header' => 'Select your Home Organisation',
'about_aai' => 'About AAI',
'about_switch' => 'About SWITCH',
'faq' => 'FAQ',
'help' => 'Help',
'privacy' => 'Privacy',
'make_selection' => 'You must select a valid Home Organisation.',
'settings' => 'Default Home Organisation for this Web Browser',
'permanent_select_header' => 'Permanently set your Home Organisation',
'permanent_cookie' => 'On this page you can set a <strong>default Home Organisation</strong> for this web browser. Setting a default Home Organisation will henceforth redirect you directly to your Home Organisation when you access AAI services. Don\'t use this feature if you use several AAI accounts.',
'permanent_cookie_notice' => 'A default setting for your Home Organisation has the effect that you don\'t need to select your Home Organisation anymore when accessing AAI services with this web browser. <br>The default setting is:',
'permanent_cookie_note' => 'You can reset the default setting by going to: https://test.php',
'delete_permanent_cookie_button' => 'Reset',
'goto_sp' => 'Save and continue to your Home Organisation',
'permanently_remember_selection' => 'Remember selection permanently and bypass the WAYF service from now on.',
'confirm_permanent_selection' => 'Are you sure that you want to set the selected entry as your default Home Organisation? Don\'t do this if you use several AAI accounts.',
'save_button' => 'Save',
'access_target' => 'In order to access the service <tt>\'<a href="%s">%s</a>\'</tt> you must authenticate yourself.',
'access_host' => 'In order to access a service on host <tt>\'%s\'</tt> you must authenticate yourself.',
'select_idp' => 'Select the Home Organisation you are affiliated with',
'remember_selection' => 'Remember selection for this web browser session.',
'switch_description' => 'The <a href="http://www.switch.ch/" target="_blank">SWITCH</a> foundation operates the Swiss education and research network which guarantees high-speed connectivity to the Internet and to science networks globally for the benefit of higher education in Switzerland.',
'invalid_user_idp' => 'There may be an error in the data you just submitted.<br>The value of your input <tt>\'%s\'</tt> is invalid.<br>Only the following values are allowed:',
'contact_assistance' => 'Please contact <a href="mailto:aai@switch.ch">aai@switch.ch</a> for assistance.',
'no_arguments' => 'No arguments received!',
'arguments_missing' => 'The web server received an invalid query because there are some arguments missing<br>The following arguments were received:',
'valid_request_description' => 'A valid request needs at least the arguments <tt>shire</tt> and <tt>target</tt> with valid values. Optionally the arguments <tt>providerID</tt>, <tt>origin</tt> and <tt>redirect</tt> can be supplied to automtically redirect the web browser to a Home Organisation and to do that automatically for the current web browser session',
'valid_saml2_request_description' => 'A valid SAML2 request needs at least the arguments <tt>entityID</tt> and <tt>return</tt> with valid values. Optionally the arguments <tt>isPassive</tt>, <tt>policy</tt> and <tt>returnIDParam</tt> can be supplied to automtically redirect the web browser to a Home Organisation and to do that automatically for the current web browser session',
'invalid_query' => 'Error: Invalid Query',
'select_button' => 'Select',
'login' => 'Login',
'login_with' => 'Login with:',
'other_federation' => 'From other federations',
'logged_in' => 'You are already authenticated.',
'most_used' => 'Most often used Home Organisations',
'invalid_return_url' => 'The return URL <tt>\'%s\'</tt> is not a valid URL.',
'unverified_return_url' => 'The return URL <tt>\'%s\'</tt> could not be verified for Service Provider <tt>\'%s\'</tt>.',
'unknown_sp' => 'The Service Provider <tt>\'%s\'</tt> could not be found in metadata and is therefore unknown.',
);


// Deutsch
$langStrings['de'] = array (
'title' => 'Auswahl der Home Organisation',
'header' => 'Home Organisation ausw&auml;hlen',
'about_aai' => '&Uuml;ber AAI',
'about_switch' => '&Uuml;ber SWITCH',
'faq' => 'FAQ',
'help' => 'Hilfe',
'privacy' => 'Datenschutz',
'make_selection' => 'Sie m&uuml;ssen eine g&uuml;ltige Home Organisation ausw&auml;hlen',
'settings' => 'Standard Home Organisation f&uuml;r diesen Webbrowser',
'permanent_select_header' => 'Home Organisation speichern',
'permanent_cookie' => 'Auf dieser Seite k&ouml;nnen Sie die <strong>Standardeinstellung Ihrer Home Organisation</strong> f&uuml;r diesen Webbrowser dauerhaft zu speichern. Sie werden darauf beim Zugriff auf AAI Dienste jedes Mal direkt zur Loginseite Ihrer Home Organisation weitergeleitet. Dies wird jedoch nicht empfohlen wenn sie mehrere AAI Benutzerkonnten verwenden.',
'permanent_cookie_notice' => 'Wenn Sie die folgende Home Organisation als Standardeinstellung speichern, werden Sie jedes Mal automatisch zu deren Login Seite weitergeleitet, wenn Sie auf AAI Dienste zugreifen. Die Einstellung lautet momentan:',
'permanent_cookie_note' => 'Sie k&ouml;nnen die Home Organisation Einstellung zur&uuml;cksetzen auf der Seite: https://test.php',
'delete_permanent_cookie_button' => 'Zur&uuml;cksetzen',
'goto_sp' => 'Speichern und weiter zur Home Organisation',
'permanently_remember_selection' => 'Auswahl permanent speichern und den WAYF Dienst von jetzt an umgehen.',
'confirm_permanent_selection' => 'Sind Sie sicher, dass Sie die Auswahl als Home Organisation Einstellung speichern wollen? Dies ist z.B. nicht empfehlenswert, wenn Sie mehrere AAI Accounts verwenden.',
'save_button' => 'Speichern',
'access_target' => 'Eine g&uuml;ltige Benutzerauthentifizierung ist n&ouml;tig um auf den Dienst <tt>\'<a href="%s">%s</a>\'</tt> zuzugreifen.',
'access_host' => 'Um auf Dienste auf dem Server <tt>\'%s\'</tt> zuzugreifen, ist eine g&uuml;ltige Benutzerauthentifizierung n&ouml;tig.',
'select_idp' => 'W&auml;hlen Sie Ihre Home Organisation',
'remember_selection' => 'Auswahl f&uuml;r die laufende Webbrowser Sitzung speichern.',
'switch_description' => 'Die <a href="http://www.switch.ch/" target="_blank">Stiftung SWITCH</a> betreibt neben anderen Dienstleistungen das Schweizer Bildungs- und Forschungsnetzwerk, welches allen h&ouml;heren Ausbildungseinrichtungen Hochgeschwindigkeitsanschl&uuml;sse ans Internet und an andere globale Wissenschaftsnetze zur Verf&uuml;gung stellt.',
'invalid_user_idp' => 'M&ouml;glicherweise sind die &uuml;bermittelten Daten fehlerhaft.<br>Der Wert der Eingabe <tt>\'%s\'</tt> ist ung&uuml;ltig.<br>Es sind ausschliesslich die folgenden Wert erlaubt:',
'contact_assistance' => 'F&uuml;r Unterst&uuml;tzung und Hilfe, kontaktieren Sie bitte <a href="mailto:aai@switch.ch">aai@switch.ch</a>.',
'no_arguments' => 'Keine Argumente erhalten!',
'arguments_missing' => 'Der Webserver hat eine fehlerhafte Anfrage erhalten da einige Argumente in der Anfrage fehlen.<br>Folgende Argumente wurden empfangen:',
'valid_request_description' => 'Eine g&uuml;ltige Anfrage muss mindestens die Argumente <tt>shire</tt> und <tt>target</tt> enthalten. Zus&auml;tzlich k&ouml;nnen die Argumente <tt>providerID</tt>, <tt>origin</tt> und <tt>redirect</tt> benutzt werden um den Webbrowser automatisch an die Home Organisation weiter zu leiten und um sich die ausgew&auml;hlte Home Organisation f&uuml;r l&auml;ngere Zeit zu merken.',
'valid_saml2_request_description' => 'Eine g&uuml;ltige Anfrage muss mindestens die Argumente <tt>entityID</tt> und <tt>return</tt> enthalten. Zus&auml;tzlich k&ouml;nnen die Argumente <tt>isPassive</tt>, <tt>policy</tt> und <tt>returnIDParam</tt> benutzt werden um den Webbrowser automatisch an die Home Organisation weiter zu leiten und um sich die ausgew&auml;hlte Home Organisation f&uuml;r l&auml;ngere Zeit zu merken.',
'invalid_query' => 'Error: Fehlerhafte Anfrage',
'select_button' => 'Ausw&auml;hlen',
'login' => 'Anmelden',
'login_with' => 'Anmelden &uuml;ber:',
'other_federation' => 'Von anderen F&ouml;derationen',
'logged_in' => 'Sie sind bereits angemeldet.',
'most_used' => 'Meist genutzte Home Organisationen',
'invalid_return_url' => 'Die return URL <tt>\'%s\'</tt> ist keine g&uuml;tige URL.',
'unverified_return_url' => 'Die return URL <tt>\'%s\'</tt> ist nicht g&uuml;tige f&uuml;r den Service Provider <tt>\'%s\'</tt>.',
'unknown_sp' => 'Der Service Provider <tt>\'%s\'</tt> konnte nicht in den Metadaten gefunden werden und ist deshalb unbekannt.',
);


// Francais
$langStrings['fr'] =  array (
'title' => 'S&eacute;lection de votre Home Organisation',
'header' => 'S&eacute;lectionnez votre Home Organisation',
'about_aai' => '&Agrave; propos de l\'AAI',
'about_switch' => '&Agrave; propos de SWITCH',
'faq' => 'FAQ',
'help' => 'Aide',
'privacy' => 'Protection des donn&eacute;es',
'make_selection' => 'Vous devez s&eacute;lectionner une Home Organisation valide.',
'settings' => 'Home Organisation par d&eacute;faut pour ce navigateur',
'permanent_select_header' => 'D&eacute;finir une Home Organisation de fa&ccedil;on permanente',
'permanent_cookie' => 'Sur cette page vous pouvez d&eacute;finir une <strong>Home Organisation par d&eacute;faut</strong> pour ce navigateur. En d&eacute;finissant une Home Organisation par d&eacute;faut, vous serez automatiquement redirig&eacute; vers cette Home Organisation lorsque vous acc&eacute;dez &agrave; une ressource AAI. N\'utilisez pas cette fonction si vous avez plusieurs identit&eacute;s AAI.',
'permanent_cookie_notice' => 'En choisissant une Home Organisation par d&eacute;faut, vous ne devez plus s&eacute;lectionner votre Home Organisation dans la liste lorsque vous acc&eacute;dez &agrave; une ressource AAI avec ce navigateur.<br>D&eacute;faut : ',
'permanent_cookie_note' => 'Vous pouvez r&eacute;initialiser la propri&eacute;t&eacute; par d&eacute;faut en allant &agrave; l\'adresse: https://test.php',
'delete_permanent_cookie_button' => 'R&eacute;initialiser',
'goto_sp' => 'Sauver et continuez vers votre Home Organisation',
'permanently_remember_selection' => 'Se souvenir de mon choix d&eacute;finitivement et contourner le service WAYF &agrave; partir de maintenant.',
'confirm_permanent_selection' => '&Ecirc;tes-vous s&ucirc; de vouloir d&eacute;finir votre s&eacute;lection comme votre Home Organisation par d&eacute;faut ? N\'utilisez pas cette fonction si vous avez plusieurs identit&eacute;s AAI.',
'save_button' => 'Sauver',
'access_target' => 'Vous devez vous authentifier pour acc&eacute;der &agrave; la ressource <tt>\'<a href="%s">%s</a>\'</tt>.',
'access_host' => 'Vous devez vous authentifier pour acc&eacute;der &agrave; la ressource <tt>\'%s\'</tt>.',
'select_idp' => 'Veuillez s&eacute;lectionner votre Home Organisation',
'remember_selection' => 'Se souvenir de mon choix pour cette session.',
'switch_description' => 'La fondation <a href="http://www.switch.ch/" target="_blank">SWITCH</a> g&egrave;re entre autres le r&eacute;seau pour l\'enseignement et la recherche suisse. Il garantit une connectivit&eacute; &agrave; haut-d&eacute;bit &agrave; Internet et aux r&eacute;seaux de recherche dans l\'int&eacute;r&ecirc;t global de l\'&eacute;ducation sup&eacute;rieure en Suisse.',
'invalid_user_idp' => 'Une erreur s\'est produite.<br>La valeur de votre donn&eacute;e <tt>\'%s\'</tt> n\'est pas valide.<br>Seules ces valeurs sont admises :',
'contact_assistance' => 'Contactez le support <a href="mailto:aai@switch.ch">aai@switch.ch</a> si l\'erreur persiste.',
'no_arguments' => 'Pas de param&egrave;tre re&ccedil;u !',
'arguments_missing' => 'La requ&ecirc;te n\'est pas valide, certains param&egrave;tres sont manquants.<br>Les param&egrave;tres suivants ont &eacute;t&eacute; re&ccedil;us :',
'valid_request_description' => 'Une requ&ecirc;te valide doit contenir au moins les param&egrave;tres <tt>shire</tt> et <tt>target</tt>. Les param&egrave;tres optionnels <tt>providerID</tt>, <tt>origin</tt> et <tt>redirect</tt> peuvent &ecirc;tre utilis&eacute;s pour rediriger automatiquement le navigateur vers une Home Organisation.',
'valid_saml2_request_description' => 'Une requ&ecirc;te valide doit contenir au moins les param&egrave;tres <tt>entityID</tt> et <tt>return</tt>. Les param&egrave;tres optionnel <tt>isPassive</tt>, <tt>policy</tt> et <tt>returnIDParam</tt> peuvent &ecirc;tre utilis&eacute;s pour rediriger automatiquement le navigateur vers une Home Organisation.',
'invalid_query' => 'Erreur : La requ&ecirc;te n\'est pas valide',
'select_button' => 'S&eacute;lection',
'login' => 'Connexion',
'login_with' => 'Se connecter avec:',
'other_federation' => 'D\'autres f&eacute;derations',
'logged_in' => 'Vous &ecirc;tes d&eacute;j&agrave; authentifi&eacute;.',
'most_used' => 'Home Organisations les plus utilis&eacute;es',
);


// Italian
$langStrings['it'] = array (
'title' => 'Selezione della vostra Home Organisation',
'header' => 'Selezioni la sua Home Organisation',
'about_aai' => 'Informazioni su AAI',
'about_switch' => 'Informazioni su SWITCH',
'faq' => 'FAQ',
'help' => 'Aiuto',
'privacy' => 'Protezione dei dati',
'make_selection' => 'Per favore, scelga una valida Home Organisation.',
'settings' => 'Home Organisation predefinita per questo Web Browser.',
'permanent_select_header' => 'Salvare la Home Organisation.',
'permanent_cookie' => 'In questa pagina pu&ograve; impostare la <strong>Home Organisation predefinita</strong> per questo Web Browser. Impostare una Home Organisation predefinita consentir&agrave; al suo Web Browser di venir reindirizzato alla sua Home Organisation automaticamente ogni qual volta lei tenter&agrave; di accedere a risorse AAI per le quali necessita un\'autentificazione. Non &egrave; da impostare se lei possiede e usa correntemente differenti account AAI.',
'permanent_cookie_notice' => 'Se sceglie di impostare una Home Organisation predefinita, la sua scelta verr&agrave; ricordata e non dovr&agrave; pi&ugrave; preoccuparsene quando acceder&agrave; a risorse AAI con questo Web Browser. <br>L\'impostazione predefinita &egrave;:',
'permanent_cookie_note' => 'Pu&ograve; cambiare la sua impostazione predefinita sulla pagina: https://test.php',
'delete_permanent_cookie_button' => 'Cancella',
'goto_sp' => 'Salvare e proseguire verso la Home Organisation',
'permanently_remember_selection' => 'Salvare la scelta permanentemente e non passare pi&ugrave; per il WAYF.',
'confirm_permanent_selection' => 'E\' sicuro di voler impostare la Home Organisation selezionata come sua Home Organisation predefinita? Non &egrave; da impostare se usa regolarmente diversi account AAI.',
'save_button' => 'Salva',
'access_target' => '&Egrave; necessario autenticarsi per poter accedere alla risorsa <tt>\'<a href="%s">%s</a>\'<tt>.',
'access_host' => '&Egrave; necessario autenticarsi per poter accedere alla risorsa sull\' host <tt>\'%s\'</tt>.',
'select_idp' => 'Selezioni la Home Organisation con la quale &egrave; affiliato.',
'remember_selection' => 'Ricorda la selezione per questa sessione.',
'switch_description' => 'La fondazione <a href="http://www.switch.ch/" target="_blank">SWITCH</a> opera all\'interno della rete per l\'insegnamento e la ricerca Svizzera. Essa garantisce un collegamento ad alta velocit&agrave; verso Internet e verso le reti scientifiche mondiali a beneficio dell\'educazione superiore in Svizzera.',
'invalid_user_idp' => 'Errore nei parametri pervenuti.<br>Il valore del parametro <tt>\'%s\'</tt> non &#143; valido.<br>Solo i seguenti valori sono ammessi:',
'contact_assistance' => 'Se l\' errore persiste, si prega di contattare <a href="mailto:aai@switch.ch">aai@switch.ch</a>.',
'no_arguments' => 'Parametri non pervenuti!',
'arguments_missing' => 'La richiesta non &egrave; valida per la mancanza di alcuni parametri. <br>I seguenti parametri sono stati ricevuti:',
'valid_request_description' => 'Una richiesta valida &egrave; deve contenere almeno i parametri <tt>shire</tt> e <tt>target</tt>. I parametri opzionali <tt>providerID</tt>, <tt>origin</tt> e <tt>redirect</tt> possono essere utilizzati per ridirigere automaticamente il browser web verso una Home Organisation.',
'valid_saml2_request_description' => 'Una richiesta valida &egrave; deve contenere almeno i parametri <tt>entityID</tt> e <tt>return</tt>. I parametri opzionali <tt>isPassive</tt>, <tt>policy</tt> e <tt>returnIDParam</tt> possono essere utilizzati per ridirigere automaticamente il browser web verso una Home Organisation.',
'invalid_query' => 'Errore: Richiesta non Valida',
'select_button' => 'Seleziona',
'login' => 'Login',
'login_with' => 'Login con:',
'other_federation' => 'Di altra federaziones',
'logged_in' => 'Lei &egrave; gi&agrave; autenticato.',
'most_used' => 'Home Organisations utilizzate pi&ugrave; spesso',
);

// Portuguese
$langStrings['pt'] = array (
'title' => 'SWITCHaai: Selec&ccedil;&atilde;o de Institui&ccedil;&atilde;o de Origem',
'header' => 'Seleccione a sua Institui&ccedil;&atilde;o de Origem',
'about_aai' => 'Sobre AAI',
'about_switch' => 'Sobre a Switch',
'faq' => 'FAQ',
'help' => 'Ajuda',
'privacy' => 'Privacidade',
'make_selection' => 'Dever&aacute; seleccionar uma Institui&ccedil;&atilde;o de Origem V&aacute;lida',
'settings' => 'Institui&ccedil;&atilde;o de Origem por defeito para este Web Browser',
'permanent_select_header' => 'Defina permanentemente a sua Institui&ccedil;&atilde;o de Origem',
'permanent_cookie' => 'Nesta p&aacute;gina poder&aacute; definir a sua <strong>Institui&ccedil;&atilde;o de Origem</strong> para este Web Browser. Defenir uma Institui&ccedil;&atilde;o de Origem levar&aacute; a que seja redireccionado directamente para a sua Institui&ccedil;&atilde;o de Origem aquando do acesso de recursos-AAI. N&atilde;o use esta funcionalidade se possuir v&aacute;rias contas de AAI.',
'permanent_cookie_notice' => 'Por omiss&atilde;o a configura&ccedil;&atilde;o da sua institui&ccedil;&atilde;o de origem ter&acute; a funcionalidade de n&atilde;o ser necess&acute;rio seleccionar novamente recursos federados.<br>A configura&ccedil;&atilde;o &ecute;:',
'permanent_cookie_note' => 'Poder&aacute; efectuar um reset &agrave;s configura&ccedil;&otilde;es no url wayf.switch.ch/SWITCHaai/WAYF',
'delete_permanent_cookie_button' => 'Reset',
'goto_sp' => 'Salve e continue para a sua Institui&ccedil;&atilde;o de Origem',
'permanently_remember_selection' => 'Memorize a sua selec&ccedil;&atilde;o permanentemente e passe o mecanismo WAYF apartir de agora.',
'confirm_permanent_selection' => 'Tem a certeza que pretende seleccionar a op&ccedil;&atilde;o escolhida como a sua institui&ccedil;&atilde;o de origem? N&atilde;o seleccione se possui v&aacute;rias contas AAI.',
'save_button' => 'Guarde',
'access_target' => 'No sentido de aceder ao recurso em <tt>\'<a href="%s">%s</a>\'</tt> dever&aacute; autenticar-se.',
'access_host' => 'No sentido de aceder ao recurso em <tt>\'%s\'</tt> dever&aacute; autenticar-se.',
'select_idp' => 'Seleccione a sua Institui&ccedil;&atilde;o de Origem',
'no_idp' => 'N&atilde;o existem Organiza&ccedil;&otilde;es de Origem na federa&ccedil;&atilde;o \'<i>%s</i>\'',
'remember_selection' => 'Memorize a selec&ccedil;&atilde;o para esta sess&atilde;o.',
'import_swisssign' => 'A SWITCH recomenda <a href="http://www.switch.ch/pki/import.html" target="_blank">a importa&ccedil;&atilde;o do\'SwissSign Root CA Certificate\'</a> no seu browser. Desta forma, o seu browser estabelecer&acute; uma liga&ccedil;&atilde;o segura com os servidores AAI.',
'switch_description' => 'A SWITCH foundation &eacute; uma institui&ccedil;&atilde;o gere e opera a rede de investiga&ccedil;&atilde;o e ensino sui&ccedil;a por forma a garantir conectividade de alto desempenho &agrave; Internet e a redes de I&amp;D globais para o beneficio de uma educa&ccedil;&atilde;o superior na sui&ccedil;a',
'invalid_user_idp' => 'Poder&aacute; existir um erro nos dados que enviou.<br>Os valores enviados <tt>\'%s\'</tt> s&atilde;o inv&aacute;lidos.<br>Apenas os valores seguintes s&atilde;o permitidos:',
'contact_assistance' => 'Contacte <a href="mailto:aai@fccn.pt">aai@fccn.pt</a> para assistencia.',
'no_arguments' => 'Nenhum argumento recebido!',
'arguments_missing' => 'O servidor web recebeu uma query inv&acute;lida devido &agrave; falta de alguns argumentos. Foram recebidos os seguintes argumentos:',
'valid_request_description' => 'Um pedido v&acute;lido necessita de pelo menos dos atributos <tt>shire</tt> e <tt>target</tt> com valores v&acute;lidos. Opcionalmente os argumentos <tt>providerID</tt>, <tt>origin</tt> e <tt>redirect</tt> podem ser fornecidos para de uma forma autom&acute;tica redireccionar o browser do utilizador.',
'invalid_query' => 'Erro: Query Invalida',
'select_button' => 'Seleccione',
'login' => 'Autenticar',
'login_with' => 'Autenticar em:',
'other_federation' => 'Outra Federa&ccedil;Atilde;o',
'logged_in' => 'J&aacute; se encontra autenticado',
'most_used' => 'Institui&ccedil;&atilde;o de Origem mais utilizada',
);

?>
