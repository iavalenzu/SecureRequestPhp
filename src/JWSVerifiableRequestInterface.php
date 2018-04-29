<?php

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

namespace SecureRequestPhp;

/**
 *
 * @author ivalenzu
 */
interface JWSVerifiableRequestInterface {
    public function getAuthorizationHeader();
    public function getQuery();
    public function getBody();
    public function getPublicKey($clientId);
}
