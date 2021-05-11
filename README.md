# jwt-php

## About
Jwt PHP Simple

Create and Validate Jwt PHP class.

## Example

##### Create Jwt PHP
```sh
<?php 
require_once 'jwt.php';

$jwtphp = new Jwt();
$jwtphp->setToken( 'Bmn0c8rQDJoGTibk' );//base64_encode(random_bytes(12))
$jwtphp->setSecret( 'yXWczx0LwgKInpMFfgh0gCYCA8EKbOnw' );//base64_encode(random_bytes(24))

$token = $jwtphp->generateJWT();

var_dump( $token );
?>
```
##### Validate Jwt PHP in Server
```sh
<?php 
require_once 'jwt.php';

$jwtphp = new Jwt(); 
$jwtphp->setSecret( 'yXWczx0LwgKInpMFfgh0gCYCA8EKbOnw' );
$is_valid = $jwtphp->validateJWT(); 
var_dump( $is_valid ); 


var_dump( $is_valid );
?>
```
