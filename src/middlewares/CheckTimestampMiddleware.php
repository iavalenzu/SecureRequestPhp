<?php

namespace SecureRequestPhp\Middlewares;

use SecureRequestPhp\Middlewares\JWSMiddlewareRequestInterface;
use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\JWSDecodedToken;

class CheckTimestampMiddleware implements JWSMiddlewareRequestInterface
{
    private $delta;
    
    public function __construct($delta = 20 * 60 * 1000) {
        $this->delta = $delta;
    }
    
    public function check(JWSDecodedToken $decodedToken, JWSVerifiableRequestInterface $request)
    {
        if(!$this->delta){
            throw new \Exception("No esta definido el delta de tiempo del timestamp");
        }

        $timestamp = $decodedToken->getPayload('ts');
        
        if( (intval($timestamp) - intval(microtime(true) * 1000)) > $this->delta)
        {
            throw new \Exception("Se excedio el tiempo maximo");            
        }
        
        return true;
    }
}