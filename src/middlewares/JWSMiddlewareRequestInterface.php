<?php

namespace SecureRequestPhp\Middlewares;

use SecureRequestPhp\JWSVerifiableRequestInterface;
use SecureRequestPhp\JWSDecodedToken;

/**
 *
 * @author ivalenzu
 */
interface JWSMiddlewareRequestInterface {
    public function check(JWSDecodedToken $decodedToken, JWSVerifiableRequestInterface $request);
}
