<?php

/**
 * Description of infoLdap
 *
 * Date - $Date: 2012-12-03 12:00:00 +0200 (lun., 03 décembre 2012) $
 * @author Sophien
 */

 /*
 * @copyright  GPL License 2012 - Mehboub Sophien - Badreddine Zeghiche - sociaNova (http://www.socianova.com)
 * @license    http://www.gnu.org/licenses/gpl-3.0.fr.html  GPL License
 * @version 1.0
 */
class infoLdap {
    
    // ip ou domaine
    static public $ldaphost = '***.***.***.***';
    // port du serveur 389 ou autre
    static public $ldapport = 389;
    // racine du serveur par ex : "dc=microsoft, dc=com"
    static public $racine = "dc=******, dc=******";
    // l'utilisateur admin de connexion
    static public $userAdmin = "cn=******";
    // mot de passe admin
    static public $mdp = "******";
    // conteneur ou groupe des utilisateurs
    static public $contenerUser = "ou=******";
    // attribut utilisateur uid ou cn
    static public $attributUser = "uid=";
    // gid - id group utilisateurs
    static public $gidnumber = 513;

}

?>
