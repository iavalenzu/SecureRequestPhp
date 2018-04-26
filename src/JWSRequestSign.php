<?php


namespace SecureRequestPhp;

require __DIR__ . '/../vendor/autoload.php';


/* 
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

class JWSRequestSign 
{
    
    static public function hashSHA256($data = "")
    {
        return hash('sha256', $data);
    }     
    
    static public function nonce($numBytes = 20)
    {
        return bin2hex(random_bytes($numBytes));
    }     
    
    static public function timestamp()
    {
        return intval(microtime(true) * 1000);
    }     
    
    static public function getAuthorizationHeader($options = array())
    {
        
        if(!$options["privateKey"]){
            throw new \Exception("No esta definida la llave privada del cliente");
        }    

        if(!$options["clientId"]){
            throw new \Exception("No esta definido el id de cliente");
        }

        if(!$options["applicationId"]){
            throw new \Exception("No esta definido el id de aplicaicon");
        }
        
        if(!isset($options['body'])){
            throw new \Exception("No esta definido el body");
        }
        if(!isset($options['query'])){
            throw new \Exception("No esta definido el query");
        }
        
            
        $headers = array(
            'alg' => 'RS256', 
            'typ' => 'JWT',
            'kid' => $options["clientId"]
        );
        
        $payload = array(
            'aid' => $options["applicationId"],
            'ts' =>  JWSRequestSign::timestamp(),
            'bh' => JWSRequestSign::hashSHA256($options['body']),
            'qh' => JWSRequestSign::hashSHA256($options['query']),
            'nc' => JWSRequestSign::nonce(20)
        );
        
        //print_r($headers);
        //print_r($payload);
       
        $jws = new \Gamegos\JWS\JWS();
        
        return 'JWT ' . $jws->encode($headers, $payload, $options["privateKey"]);          
    }
    
}