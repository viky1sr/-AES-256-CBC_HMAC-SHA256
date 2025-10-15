<?php

require_once __DIR__.'/../vendor/autoload.php';

$password1 = (new Kelompok1\CryptoGraphy\Security\PasswordHasher)->hash('kepo123');
$password2 = (new Kelompok1\CryptoGraphy\Security\PasswordHasher)->hash('kepo123');
var_dump($password1);
var_dump($password2);
