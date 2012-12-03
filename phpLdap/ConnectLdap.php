<?php

include_once('conf/smbHash.class.php');
include_once('conf/infoLdap.php');

/**
 * Description of ConnectLdap
 *
 * Date - $Date: 2012-12-03 12:00:00 +0200 (lun., 03 décembre 2012) $
 * @author Sophien
 */

 /*
 * @copyright  GPL License 2012 - Mehboub Sophien - sociaNova (http://www.socianova.com)
 * @license    http://www.gnu.org/licenses/gpl-3.0.fr.html  GPL License
 * @version 1.0
 */
class ConnectLdap {

    private $ldaphost;  // ip ou domaine
    private $ldapport;  // port du serveur 
    private $racine;    // racine du serveur par ex : "dc=microsoft, dc=com"
    private $userAdmin; // l'utilisateur de connexion
    private $filter;    // filtre de recherche
    private $mdp;       // mot de passe
    private $ldap_connect;
    private $ldapbind;
    private $contenerUser;
    private $attributUser;

    public function __construct() {

        $this->contenerUser = infoLdap::$contenerUser;
        $this->attributUser = infoLdap::$attributUser;


        $array = array('ldaphost' => infoLdap::$ldaphost,
            'ldapport' => infoLdap::$ldapport,
            'racine' => infoLdap::$racine,
            'userAdmin' => infoLdap::$userAdmin,
            'mdp' => infoLdap::$mdp);

        foreach ($array as $k => $v) {

            $this->{$k} = $v;

            $funct = "set" . ucfirst($k);
            $this->{$funct}($v);
        }
        $this->setFilter("(|($this->attributUser*))");
    }

    public function getLdaphost() {
        return $this->ldaphost;
    }

    public function getLdapport() {
        return $this->ldapport;
    }

    public function getRacine() {
        return $this->racine;
    }

    public function getUserAdmin() {
        return $this->userAdmin;
    }

    public function getMdp() {
        return $this->mdp;
    }

    public function getFilter() {
        return $this->filter;
    }

    public function setLdaphost($ldaphost) {
        $this->ldaphost = $ldaphost;
    }

    public function setLdapport($ldapport) {
        $this->ldapport = $ldapport;
    }

    public function setRacine($racine) {
        $this->racine = $racine;
    }

    public function setUserAdmin($user) {
        $this->userAdmin = $user;
    }

    public function setMdp($mdp) {
        $this->mdp = $mdp;
    }

    public function setFilter($filter) {
        $this->filter = $filter;
    }

    public function connection() {

        $this->ldap_connect = ldap_connect($this->ldaphost, $this->ldapport)
                or die("Could not connect to {$this->ldaphost}");
    }

    public function DeConnect() {
        return ldap_close($this->ldap_connect);
    }

    public function getUsersLdap() {
        $users = array();
        if ($this->ldap_connect) {
            // on s'authentifie en tant que super-utilisateur, ici, userAdmin
            ldap_set_option($this->ldap_connect, LDAP_OPT_PROTOCOL_VERSION, 3);
            $ldapbind = ldap_bind($this->ldap_connect, "$this->userAdmin,$this->racine", $this->mdp);
        }

        $sr = ldap_search($this->ldap_connect, $this->racine, $this->filter);

        $info = ldap_get_entries($this->ldap_connect, $sr);

        foreach ($info as $i) {

            if (isset($i['givenname'])) {
                $users[$i["cn"][0]] = $i["dn"];
            }
        }
        return $users;
    }

    public function getUserLdapInfos($user) {
        $infos = array();
        $dn = $this->attributUser . "$user,$this->contenerUser," . $this->racine;
        $filter = "(|(cn=*))";
//$justthese = array("ou", "sn", "givenname", "mail");

        $sr = ldap_search($this->ldap_connect, $dn, $filter/* , $justthese */);
        $data = ldap_get_entries($this->ldap_connect, $sr);

        for ($z = 0; $z < count($data[0]['objectclass']) - 1; $z++) {
            $infos[key($data[0])] = $data[0]['objectclass'][$z];
        }
        for ($i = 0; $i < $data["count"]; $i++) {
            for ($j = 1; $j < $data[$i]["count"]; $j++) {
                $infos[$data[$i][$j]] = $data[$i][$data[$i][$j]][0];
            }
        }
        return $infos;
    }

    public function verifUser($user, $passwd) {

        $connexion_serveur = ldap_connect($this->ldaphost, $this->ldapport);
        ldap_set_option($connexion_serveur, LDAP_OPT_PROTOCOL_VERSION, 3);

        // Si la connexion au LDAP fonctionne avec les identifiants saisie et que l'utilisateur se trouve dans l'OU "people", alors on retourne true			
        return (ldap_bind($connexion_serveur, $this->attributUser . $user . ',' . $this->contenerUser . ',' . $this->racine, $passwd)) ? true : false;
    }

    public function getSshaPassword($password) {
        $smb = new smbHash();
        $ssha = $smb->ssha_encode($password);
        return $ssha;
    }

    public function addUser($user, $pass) {

        $array = $this->getUsersLdap();
        $uidnumber[] = array();

        foreach ($array as $key => $value) {
            $dn = $value;
            $filter = "(|(cn=*))";

            $sr = ldap_search($this->ldap_connect, $dn, $filter);
            $data = ldap_get_entries($this->ldap_connect, $sr);

            for ($i = 0; $i < $data["count"]; $i++) {
                for ($j = 1; $j < $data[$i]["count"]; $j++) {
                    if ($data[$i][$j] == 'uidnumber') {
                        $uidnumber[] = $data[$i][$data[$i][$j]][0];
                    }
                }
            }
        }

        $ssha = $this->getSshaPassword($pass);

        $ldaprecord['objectclass'][0] = "top";
        $ldaprecord['objectclass'][1] = "person";
        $ldaprecord['objectclass'][2] = "organizationalPerson";
        $ldaprecord['objectclass'][3] = "inetOrgPerson";
        $ldaprecord['objectclass'][4] = "posixAccount";
        $ldaprecord['objectclass'][5] = "shadowAccount";



        $ldaprecord['cn'] = $user;
        $ldaprecord['givenName'] = $user;
        $ldaprecord['sn'] = $user;
        $ldaprecord['displayName'] = $user;
        $ldaprecord['uidNumber'] = $uidnumber[count($uidnumber) - 1] + 1;
        $ldaprecord['gidNumber'] = infoLdap::$gidnumber;
        $ldaprecord['userPassword'] = $ssha;
        $ldaprecord['gecos'] = 'System User';
        $ldaprecord['loginShell'] = '/bin/bash';
        $ldaprecord['homeDirectory'] = "/home/$user";
        $ldaprecord['shadowMax'] = '45';
        $ldaprecord['shadowLastChange'] = '18877';

        $dn = $this->attributUser . "$user,$this->contenerUser," . $this->racine;
        return(ldap_add($this->ldap_connect, $dn, $ldaprecord));
    }

    public function deleteUser($user) {

        $dn = $this->attributUser . "$user,$this->contenerUser," . $this->racine;

        return(ldap_delete($this->ldap_connect, $dn));
    }

    public function modifyUserLdap($user, array $array) {

        return ldap_modify($this->ldap_connect, $this->attributUser . "$user,$this->contenerUser," . $this->racine, $array);
    }

    public function modifyPassUserLdap($user, $mdp) {

        $ssha = $test->getSshaPassword($mdp);
        $ldaprecord['userPassword'] = $ssha;
        $this->modifyUserLdap($user, $ldaprecord);
    }

}

?>
