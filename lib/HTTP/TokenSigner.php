<?php

class TokenSigner extends HTTP_UrlSigner
{
    public function createToken(array $params): string
    {
        $token = http_build_query($params);
        if (function_exists('gzdeflate')) {
            $deflated = gzdeflate($token);
            if ($this->_strlen($deflated) < $this->_strlen($token)) {
                $token = "z" . $deflated;
            } else {
                $token = "a" . $token;
            }
        } else {
            $token = "a" . $token;
        }
        $token = base64_encode($token);
        $token = str_replace($this->_safeBase64[0], $this->_safeBase64[1], $token);
        $token = join("/", str_split($token, 80));
        // Add digital signature to the end of the PACKED result. We cannot insert
        // the signature before packing, because else a hacked may create another
        // pack which unpacks to the same result. Add signatures at the beginning,
        // because we need an easy way to explode() them back.
        $token =
            $this->_hash($this->_secret . $token ) .
            "/" .
            $token;
        return $token;
    }

    public function parseToken(string $token): array
    {
        @list ($sign, $token) = explode("/", $token, 2);

        // Checked URL is relative [we know that base URL is absolute].
        $ok = $this->_hash($this->_secret . $token) === $sign;
        if (!$ok) {
            throw new \Exception("Wrong digital signature");
        }
        $token = str_replace('/', '', $token);
        $token = str_replace($this->_safeBase64[1], $this->_safeBase64[0], $token);
        $token = @base64_decode($token);
        if (!$token) {
            throw new \Exception("Invalid URL token encoding");
        }
        if (@$token[0] == "z") {
            $token = gzinflate($this->_substr($token, 1));
        } else {
            $token = $this->_substr($token, 1);
        }
        $params = null;
        parse_str($token, $params);
        return $params;
    }
}