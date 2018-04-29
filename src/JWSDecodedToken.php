<?php
namespace SecureRequestPhp;

class JWSDecodedToken
{
    private $decodeToken;
    
    public function __construct($decodeToken) {
        
        if(!$decodeToken){
            throw new \Exception("El token no es valido");
        }        
        
       $this->decodeToken = $decodeToken;
    }
    
    public function existsHeader($name)
    {
        return isset($this->decodeToken['headers'][$name]);
    }

    public function existsPayload($name)
    {
        return isset($this->decodeToken['payload'][$name]);
    }

    public function getHeader($name)
    {
        if(!$this->existsHeader($name)){
            throw new \Exception("No existe el header " . $name);
        }
        
        return $this->decodeToken['headers'][$name];
    }
    
    public function getPayload($name)
    {
        if(!$this->existsPayload($name)){
            throw new \Exception("No existe el payload " . $name);
        }
        
        return $this->decodeToken['payload'][$name];
    }    
    
}