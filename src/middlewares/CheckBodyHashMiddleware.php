<?php
namespace SecureRequestPhp\Middlewares;


use SecureRequestPhp\Middlewares\JWSMiddlewareRequestInterface;
use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\JWSDecodedToken;

class CheckBodyHashMiddleware implements JWSMiddlewareRequestInterface
{
    public function __construct() {
    }
    
    
    static public function hashSHA256($data = "")
    {
        return hash('sha256', $data);
    }  
    
    public function check(JWSDecodedToken $decodedToken, JWSVerifiableRequestInterface $request)
    {
        $bodyString = $request->getBody();
        
        if(!$bodyString){
            throw new \Exception("No esta definido el rawBody");
        }

        $bodyHash = $decodedToken->getPayload('bh');
        
        if($bodyHash !== CheckBodyHashMiddleware::hashSHA256($bodyString))
        {
            throw new \Exception("El hash del body no coincide");
        }        
        
        return true;
    }    
}