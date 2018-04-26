<?php


namespace SecureRequestPhp;

require __DIR__ . '/../vendor/autoload.php';

class JWSRequestVerifier 
{
    static public function hashSHA256($data = "")
    {
        return hash('sha256', $data);
    }      
    
    static public function isTimestampValid($timestamp, $delta)
    {
        if(!$timestamp){
            throw new \Exception("No esta definido el timestamp");
        }

        if(!$delta){
            throw new \Exception("No esta definido el delta de tiempo del timestamp");
        }

        return (intval(timestamp) - intval(microtime(true) * 1000)) < delta;
    }
    
    static public function isBodyHashCorrect($bodyHash, $bodyString)
    {
        if(!$bodyHash){
            throw new \Exception("No esta definido el bodyHash");
        }

        if(!$bodyString){
            throw new \Exception("No esta definido el rawBody");
        }

        return $bodyHash === JWSRequestVerifier::hashSHA256($bodyString);
    }

    static public function isQueryHashCorrect($queryHash, $queryString)
    {
        if(!$queryHash){
            throw new \Exception("No esta definido el queryHash");
        }    

        if(!$queryString){
            throw new \Exception("No esta definido el queryString");
        }

        return $queryHash === JWSRequestVerifier::hashSHA256($queryString);
    }    
    
    
    static public function verify($request = [], $options = [])
    {
        
        if(!$options['clientPublicKeyFn']){
            throw new \Exception("No esta definida la promesa que obtiene al llave publica del cliente");
        }    
    
        $clientPublicKeyFunction = $options['clientPublicKeyFn'];    
    
        if(!$request['headers']['authorization']){
            throw new \Exception("El header de authorizacion no esta definido");
        }

        if(!$request['query']){
            throw new \Exception("La query no esta definida");
        }

        if(!$request['body']){
            throw new \Exception("El body no esta definido");
        }

        $authorization = $request['headers']['authorization'];

        $parts = explode(" ", $authorization);
       
        if(count($parts) > 2){
            throw new \Exception("El formato del header de autorizacion no es correcto");
        }
    
        if($parts[0] !== 'JWT'){
            throw new \Exception("El header de autorizacion no corresponde a un JWT");
        }

        if(!isset($parts[1])){
            throw new \Exception("El header de autorizacion no incluye un token");
        }
    
        //Se obtiene el token

        $token = $parts[1];        
        
        $jws = new \Gamegos\JWS\JWS();
        
        $decoded = $jws->decode($token);        
        
        if(!$decoded){
            throw new \Exception("La firma no es valida");
        }
    
        //Se verifica que el client id este incluido
        if(!isset($decoded['headers']['kid'])){
            throw new \Exception("No esta definido el id de cliente");
        }
        $client_id = $decoded['headers']['kid'];

        //Se verifica que el nonce este incluido    
        if(!isset($decoded['payload']['nc'])){
            throw new \Exception("No esta definido el nonce");
        }
        $nonce = $decoded['payload']['nc'];

        //Se obtienen el timestamp del payload 
        if(!isset($decoded['payload']['ts'])){
            throw new \Exception("No esta definido el timestamp");
        }
        $timestamp = $decoded['payload']['ts'];

        //Se obtienen el body hash del payload 
        if(!isset($decoded['payload']['bh'])){
            throw new \Exception("No esta definido el hash del body");
        }
        $bodyHash = $decoded['payload']['bh'];

        //Se obtienen el query hash del payload 
        if(!isset($decoded['payload']['qh'])){
            throw new \Exception("No esta definido el hash del query");
        }
        $queryHash = $decoded['payload']['qh'];    
        
        
        //*************************************
        // Se verifica la antiguedad del request
        //*************************************

        if(!JWSRequestVerifier::isTimestampValid($timestamp, 20 * 60 * 1000)){
            throw new \Exception("Se excedio el tiempo maximo");
        }

        //*************************************
        // Se verifica que coincidan los hashes
        //*************************************

        if(!JWSRequestVerifier::isBodyHashCorrect($bodyHash, $request['body'])){
            throw new \Exception("El hash del body no coincide");
        }
    
        if(!JWSRequestVerifier::isQueryHashCorrect($queryHash, $request['query'])){
            throw new \Exception("El hash de la query no coincide");
        }
        
        
        $clientPublicKey = $clientPublicKeyFunction($client_id);
        
        if(!isset($clientPublicKey)){
            throw new \Exception("La llave publica no esta definida");
        }
        
        print_r($clientPublicKey);
        
        //$clientPublicKey = str_replace("\n", "", $clientPublicKey);
        
        //print_r($clientPublicKey);
        
        //$pubkeyid = openssl_get_publickey($clientPublicKey);
        
        return $jws->verify($token, $clientPublicKey);

    }
    
    
}
