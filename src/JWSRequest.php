<?php

namespace SecureRequestPhp;

require __DIR__ . '/../vendor/autoload.php';


use Psr\Http\Message\RequestInterface;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Handler\CurlHandler;
use GuzzleHttp\Client;

class JWSRequest
{
    static public function middleware()
    {
        return function (callable $handler) {
            return function (RequestInterface $request, array $options) use ($handler) {
                
                $path = $request->getUri()->getPath();
                $body = $request->getBody()->getContents();
                
                if(!$options['credentials']){
                    throw new Exception("No estan definidas las credenciales");
                }
                
                $credentials = $options['credentials'];
                
                if(!$credentials['clientId']){
                    throw new Exception("No esta definido el id de cliente");
                }
                if(!$credentials['applicationId']){
                    throw new Exception("No esta definido el id de application");
                }
                if(!$credentials['privateKey']){
                    throw new Exception("No esta definida la llave privada del cliente");
                }
                
                
                $options = array(
                    "privateKey" => $credentials['privateKey'],
                    "clientId" => $credentials['clientId'],
                    "applicationId" => $credentials['applicationId'],
                    "body" => $body,
                    "query" => $path
                );

                $token = JWSRequestSign::getAuthorizationHeader($options);
                
                $request = $request->withHeader('Authorization', $token);
                
                
                return $handler($request, $options);
            };
        };
    }
    
    static public function getSecureClient($options = [])
    {
        $stack = new HandlerStack();
        $stack->setHandler(new CurlHandler());
        $stack->push(JWSRequest::middleware());
        
        $credentials = $options['credentials'];
        
        if(is_string($credentials))
        {
            $content = file_get_contents($credentials);
            $credentials = json_decode($content, true);
        }
        
        $client = new Client(['handler' => $stack, 'credentials' => $credentials]);
        
        return $client;
    }
    
    
}