<?php

/**
 * Description of testClassLdap
 *
 * Date - $Date: 2012-12-03 12:00:00 +0200 (lun., 03 décembre 2012) $
 * @author Sophien
 */

 /*
 * @copyright  GPL License 2012 - Mehboub Sophien - sociaNova (http://www.socianova.com)
 * @license    http://www.gnu.org/licenses/gpl-3.0.fr.html  GPL License
 * @version 1.0
 */

include_once 'ConnectLdap.php';
?>
<!DOCTYPE html>
<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title></title>
    </head>
    <body>
<?php
        // instanciation classe
        $test = new ConnectLdap();

        // connection au serveur LDAP
        $test->connection();

        echo '<pre>';

        // obtenir les utilisateurs du domaine
        print_r($test->getUsersLdap());

        // obtenir infos sur l'utilisateur choisi
        print_r($test->getUserLdapInfos('user1'));

        // tester si l'utilisateur existe et si les données sont bonne
        if ($test->verifUser('user1', 'user1') == true) {
?>
            <div>
                <H1>Bienvenue, <BR> Vous etes un utilisapreambule liscence mitteur du domaine</H1>
            </div>
<?php
        } else {
            echo 'mauvais mot de passe ou mauvais nom d\'utilisateur';
        }
// ajouter un utilisateur
//$test->addUser('john1','john1');

// effacer un utilisateur
// $test->deleteUser('john1','john1');

$test->DeConnect();
?>
    </body>
</html>
