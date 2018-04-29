<?php

namespace SecureRequestPhp;


use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\Middlewares\JWSMiddlewareRequestInterface;

use SecureRequestPhp\Middlewares\CheckTimestampMiddleware;
use SecureRequestPhp\Middlewares\CheckBodyHashMiddleware;
use SecureRequestPhp\Middlewares\CheckQueryHashMiddleware;
use SecureRequestPhp\JWSDecodedToken;

class JWSRequestVerifier 
{
    private $middlewares;
    
     
    public function __construct() 
    {
        $this->middlewares = array();
        
        $this->middlewares['CheckTimestampMiddleware'] = new CheckTimestampMiddleware(20 * 60 * 1000);
        $this->middlewares['CheckBodyHashMiddleware'] = new CheckBodyHashMiddleware();
        $this->middlewares['CheckQueryHashMiddleware'] = new CheckQueryHashMiddleware();
        
        
    }
    
    public function addMiddleware(JWSMiddlewareRequestInterface $middleware, $name)
    {
        $this->middlewares[$name] = $middleware;
    }
    
    /****************************************************************
     * Se verifica que el algoritmo de firma este definido
     * https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/
     ****************************************************************/

    private function passSecurityCheck(JWSDecodedToken $decodedToken)
    {
        $typHeader = $decodedToken->getHeader('typ');
        
        if($typHeader !== "JWT"){
            throw new \Exception("El tipo de token no es JWT");
        }

        $algHeader = $decodedToken->getHeader('alg');
        
        if($algHeader !== "RS256"){
            throw new \Exception("El algoritmo de firma no es RS256");
        }

        return true;
    }    

    private function checkMiddlewares(JWSDecodedToken $decodedToken, JWSVerifiableRequestInterface $request)
    {
        foreach ($this->middlewares as $name => $middleware)
        {
            if(!$middleware->check($decodedToken, $request)){
                throw new \Exception("Ocurrio un error");
            }
        }
    }
    
    public function verify(JWSVerifiableRequestInterface $request)
    {
        $authorizationHeader = $request->getAuthorizationHeader();
    
        if(!$authorizationHeader){
            throw new \Exception("El header de authorizacion no esta definido");
        }

        
        //*************************************
        // Se verifica el header de authorizacion
        //*************************************        

        $parts = explode(" ", $authorizationHeader);
       
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
        
        $decodedToken = new JWSDecodedToken($decoded);
        
        
        //*************************************
        // Chequeo de seguridad
        //*************************************

        if(!JWSRequestVerifier::passSecurityCheck($decodedToken)){
            throw new \Exception("Ocurrio un error de seguridad");
        }          
        
        //*************************************
        // Se verifica que los parametros vengan definidos 
        //*************************************
    
        //Se verifica que el client id este incluido
        if(!$decodedToken->existsHeader('kid')){
            throw new \Exception("No esta definido el id de cliente");
        }

        //Se verifica que el nonce este incluido    
        if(!$decodedToken->existsPayload('nc')){
            throw new \Exception("No esta definido el nonce");
        } 

        //Se obtienen el timestamp del payload 
        if(!$decodedToken->existsPayload('ts')){ 
            throw new \Exception("No esta definido el timestamp");
        }

        //Se obtienen el body hash del payload 
        if(!$decodedToken->existsPayload('bh')){
            throw new \Exception("No esta definido el hash del body");
        }

        //Se obtienen el query hash del payload 
        if(!$decodedToken->existsPayload('qh')){ 
            throw new \Exception("No esta definido el hash del query");
        }
        
        //*************************************
        // Se evaluan los middlewares
        //*************************************
        
        $this->checkMiddlewares($decodedToken, $request);
        

        //*************************************
        // Se obtiene la llave public del cliente segun su client id
        //*************************************
        
        $client_id = $decodedToken->getHeader('kid');
        
        $clientPublicKey = $request->getPublicKey($client_id);
        
        if(!isset($clientPublicKey)){
            throw new \Exception("La llave publica no esta definida");
        }
        
        return $jws->verify($token, $clientPublicKey);

    }
    
    
}
