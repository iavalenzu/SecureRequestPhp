<?php
namespace SecureRequestPhp;

require __DIR__ . '/../vendor/autoload.php';


/*
$config = array(
    "private_key_bits" => 2048
);
// Create the private and public key
$res = openssl_pkey_new($config);

// Extract the private key from $res to $privKey
openssl_pkey_export($res, $privKey);
print_r($privKey);

// Extract the public key from $res to $pubKey
$pubKey = openssl_pkey_get_details($res);
print_r($pubKey["type"]);

$pubKey = $pubKey["key"];
print_r($pubKey);
*/

//SecureRequestPhp vendor/bin/phpunit test/SecureRequestPhpTest


use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\JWSRequestVerifier;

class CustomRequest implements JWSVerifiableRequestInterface
{
    private $token, $query, $body, $publicKey;
    
    function __construct($token, $query, $body, $publicKey) {
        $this->token = $token;
        $this->query = $query;
        $this->body = $body;
        $this->publicKey = $publicKey;
    }    
    
    public function getAuthorizationHeader(){
        return $this->token;
    }
    public function getQuery(){
        return $this->query;
    }
    public function getBody(){
        return $this->body;
    }
    
    public function getPublicKey($clientId)
    {
        return $this->publicKey;
    }
    
}


class SecureRequestPhpTest extends \PHPUnit\Framework\TestCase
{
    public function testGenerateAndVerifyToken()
    {
        $content = file_get_contents(__DIR__ . '/../config/credentials_1.json');
        $credentials = json_decode($content, true);

        $privKey = $credentials['privateKey'];
        $pubKey = $credentials['publicKey'];

        $options = array(
            "privateKey" => $privKey,
            "clientId" => 'clientId',
            "applicationId" => 'applicationId',
            "body" => "body",
            "query" => "query"
        );

        $token = JWSRequestSign::getAuthorizationHeader($options);

        print_r($out);
        print_r("\n");
        
        $request = new CustomRequest($token, "query", "body", $pubKey);
        
        $verifier = new JWSRequestVerifier();
        
        $out = $verifier->verify($request);

        print_r($out);

        
    }
    
    public function testJavascriptGeneratedToken()
    {
        $content = file_get_contents(__DIR__ . '/../config/credentials_1.json');
        $credentials = json_decode($content, true);

        $privKey = $credentials['privateKey'];
        $pubKey = $credentials['publicKey'];

        $token = "JWT eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImNsaWVudElkIn0.eyJhaWQiOiJhcHBsaWNhdGlvbl9pZCIsInRzIjoxNTI0NzY0ODc5MTA2LCJiaCI6IjIzMGQ4MzU4ZGM4ZTg4OTBiNGM1OGRlZWI2MjkxMmVlMmYyMDM1N2FlOTJhNWNjODYxYjk4ZTY4ZmUzMWFjYjUiLCJxaCI6ImE4Yjc3MTkyMGI4MzE5ZTQ3MjUxZDEzNjBmNWU4ODBiYzE4ZThkMzI5YjBmMGQwMDNlYTNjN2U2MTU1NTg5NDciLCJuYyI6IjZmZTlkMTQyM2U1OWYwNmIyNjkzMTAwM2NiODdhNzM4MzE1OTc4MTcifQ.ES9JglskLgem4-0Gfx0qu0iFT-88CiMW9PWHSXGkDvERM--YST0mJkJVDMBp83Fh8DWt9yPSOPCAa3NNpp3Jge1d31Pb4GGjyFXLcRSJVYMkA7bislq1dm_53fc8I9zMWvp9mhk1BdaJUXNuLHh1B6tIoOxghSFRe2evhtWMzVV7lk0VeFO5xfCFZwZd9qs2Mssz6KwTjMU8jpLuvYrSbkDgSzdhYavyvws4WGgn04F1MjcxpjX0ha41FWB3h2chDBvnfkOzKrA5THBvuIJN-d3u4jMlCm1_ItLY8Jf6uwbUzJXjRw0ajpDrpenZ3GLvV7PlmT194PF3JzJIcp3vBA";
        
        $request = new CustomRequest($token, "query", "body", $pubKey);
        
        $verifier = new JWSRequestVerifier();
        
        $out = $verifier->verify($request);

        print_r($out);        
        
    }   
    
    public function testGetRequest()
    {
        $client = JWSRequest::getSecureClient(['credentials' => __DIR__ . '/../config/credentials_1.json']);

        $response = $client->request('GET', 'https://webhook.site/21a8c2dd-55d6-49f5-97d4-f4a02cedfd6c');

        print_r($response);
    }

    public function testPostRequest()
    {
        $client = JWSRequest::getSecureClient(['credentials' => __DIR__ . '/../config/credentials_1.json']);

        $response = $client->request('POST', 'https://webhook.site/21a8c2dd-55d6-49f5-97d4-f4a02cedfd6c', [
            'body' => "Holassssss"
        ]);

        print_r($response);
    }

    
}
