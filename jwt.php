<?php
/**
 * 
 * @author Paulo Nhaia
 * 
 *
 */
class Jwt {
    
    public $token;
    public $secret;
    
    /**
     * Set Token
     * @param string $token
     */
    public function setToken($token){
        $this->token = $token;
    }
    /**
     * Set Secret
     * @param string $secret
     */
    public function setSecret($secret){
        $this->secret = $secret;
    }
    /**
     * Valid Token JWT
     * @return boolean
     */
    public function validateJWT(){
        $jwt = $this->getBearerToken();
        // Split the token
        $tokenParts = explode('.', $jwt);
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];
        
        $base64UrlHeader = $this->base64url_encode($header);
        $base64UrlPayload = $this->base64url_encode($payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secret, TRUE);
        $base64UrlSignature = $this->base64url_encode($signature);
        
        $signatureValid = ($base64UrlSignature === $signatureProvided);
        //echo "Header:\n" . $header . "\n";
        //echo "Payload:\n" . $payload . "\n";
        if ($signatureValid) {
            return TRUE;//The signature is valid.
        } else {
            return FALSE;////The signature is NOT valid.
        }
    }
    /**
     * Get Token JWT
     * @return string
     */
    public function generateJWT(){
        // RFC-defined structure
        $header = [
            "alg" => "HS256",
            "typ" => "JWT"
        ];
        // whatever you want
        $payload = [
            "token" => $this->token
        ];
        // Encode Header
        $base64UrlHeader = $this->base64url_encode(json_encode($header));
        // Encode Payload
        $base64UrlPayload = $this->base64url_encode(json_encode($payload));
        // Create Signature Hash
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $this->secret, TRUE);
        // Encode Signature to Base64Url String
        $base64UrlSignature = $this->base64url_encode($signature);
        // Create JWT
        $jwt2 = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
        return $jwt2;
    }
    
    /**
     * Get Header Authorization
     * @return string Authorization
     */
    private function getAuthorizationHeader(){
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            //print_r($requestHeaders);
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }
    /**
     * Get Access Token From Header
     * @return string Bearer Token
     */
    private function getBearerToken() {
        $headers = $this->getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            $matches = array();
            if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
                return $matches[1];
            }
        }
        return null;
    }
    /**
     * Base64urlEncode
     * @return string 
     */
    private function base64url_encode($data) {
        $b64 = base64_encode($data);
        if ($b64 === false) {
            return false;
        }
        $url = strtr($b64, '+/', '-_');
        return rtrim($url, '=');
    }
}
?>
