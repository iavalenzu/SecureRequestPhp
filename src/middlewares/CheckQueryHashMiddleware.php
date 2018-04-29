<?php
namespace SecureRequestPhp\Middlewares;


use SecureRequestPhp\Middlewares\JWSMiddlewareRequestInterface;
use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\JWSDecodedToken;

class CheckQueryHashMiddleware implements JWSMiddlewareRequestInterface
{
    public function __construct() {
    }
    
    
    static public function hashSHA256($data = "")
    {
        return hash('sha256', $data);
    }  
    
    public function check(JWSDecodedToken $decodedToken, JWSVerifiableRequestInterface $request)
    {
        $queryString = $request->getQuery();

        if(!$queryString){
            throw new \Exception("No esta definido el query");
        }

        $queryHash = $decodedToken->getPayload('qh');
        
        if($queryHash !== CheckQueryHashMiddleware::hashSHA256($queryString))
        {
            throw new \Exception("El hash de la query no coincide");
        }
        
        return true;
    }    
}