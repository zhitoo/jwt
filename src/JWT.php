<?php

namespace Zhitoo\Jwt;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Str;

class JWT
{

    private static $jwt;
    private $secret;
    private $expiration;
    private $blacklist_path;

    /**
     *
     */
    private function __construct()
    {
        $this->expiration = (config('jwt.expiration') ?? 0) * 60; //change minutes to seconds
        $this->secret = config('jwt.secret');

        $this->blacklist_path = config('jwt.blacklist_path');
        $this->blacklist_path = trim($this->blacklist_path, '/\\ ');
        $this->blacklist_path = DIRECTORY_SEPARATOR . str_replace('/\\', DIRECTORY_SEPARATOR, $this->blacklist_path);

        //create path if not exists
        if (!file_exists($this->blacklist_path)) {
            mkdir($this->blacklist_path, 0755, true);
        }
    }

    /**
     * @return mixed
     */
    public static function getInstance()
    {
        if (!isset(static::$jwt)) {
            static::$jwt = new static();
        }
        return static::$jwt;
    }


    /**
     * @param string $text
     * @return array|string|string[]
     */
    protected function base64UrlEncode(string $text)
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($text)
        );
    }


    /**
     * @param Request $request
     * @return mixed|null
     */
    public function getTokenableIfTokenValid(Request $request)
    {
        $jwt = $this->getTokenFromRequest($request);


        if (empty($jwt)) return null;

        if ($this->isTokenInBlackList($jwt)) return null;

        $secret = $this->secret;
        // split the token
        $tokenParts = $this->getTokenParts($jwt);
        if (count($tokenParts) < 3) {
            return null;
        }
        $header = $tokenParts['header'];
        $payload = $tokenParts['payload'];
        $signatureProvided = $tokenParts['signature'];

        // build a signature based on the header and payload using the secret
        $base64UrlHeader = $this->base64UrlEncode($header);
        $base64UrlPayload = $this->base64UrlEncode($payload);
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secret, true);
        $base64UrlSignature = $this->base64UrlEncode($signature);


        // check the expiration time - note this will cause an error if there is no 'exp' claim in the token
        $payLoadObj = json_decode($payload);
        if (!empty($payLoadObj->exp) and $payLoadObj->exp != 0) {
            $expiration = Carbon::createFromTimestamp($payLoadObj->exp);
            $tokenExpired = (Carbon::now()->diffInSeconds($expiration, false) < 0);
            if ($tokenExpired) {
                return null;
            }
        }
        // verify it matches the signature provided in the token
        $signatureValid = ($base64UrlSignature === $signatureProvided);
        if (!$signatureValid) {
            return null;
        }
        //check user agent
        if ($payLoadObj->agent != $request->server('HTTP_USER_AGENT')) {
            return null;
        }
        //check user ip
        if ($payLoadObj->ip != $request->ip()) {
            return null;
        }

        return $this->getTokenable($jwt);
    }

    /**
     * @param Request $request
     * @param Model $tokenable
     * @return string
     */
    public function createToken(Request $request, Model $tokenable): string
    {
        $secret = $this->secret;
        // Create the token header
        $header = json_encode([
            'typ' => 'JWT',
            'alg' => 'HS256'
        ]);

        // Create the token payload
        $payload = json_encode([
            'tokenable_id' => $tokenable->id,
            'tokenable_type' => get_class($tokenable),
            'agent' => $request->server('HTTP_USER_AGENT'),
            'ip' => $request->ip(),
            'created_at' => time(),
            'exp' => $this->expiration ? time() + $this->expiration : 0
        ]);

        // Encode Header
        $base64UrlHeader = $this->base64UrlEncode($header);

        // Encode Payload
        $base64UrlPayload = $this->base64UrlEncode($payload);

        // Create Signature Hash
        $signature = hash_hmac('sha256', $base64UrlHeader . "." . $base64UrlPayload, $secret, true);

        // Encode Signature to Base64Url String
        $base64UrlSignature = $this->base64UrlEncode($signature);

        // Create JWT
        return $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
    }

    /**
     * @param string $jwt
     * @return mixed|null
     */
    private function getTokenPayLoadInfo(string $jwt)
    {
        $parts = $this->getTokenParts($jwt);
        return isset($parts['payload']) ? json_decode($parts['payload']) : null;
    }

    /**
     * @param string $jwt
     * @return array
     */
    private function getTokenParts(string $jwt): array
    {
        // split the token
        $tokenParts = explode('.', $jwt);
        if (count($tokenParts) < 3) {
            return [];
        }
        $header = base64_decode($tokenParts[0]);
        $payload = base64_decode($tokenParts[1]);
        $signatureProvided = $tokenParts[2];
        return [
            'header' => $header,
            'payload' => $payload,
            'signature' => $signatureProvided
        ];
    }

    /**
     * @param string $jwt
     * @return mixed
     */
    private function getTokenable(string $jwt)
    {
        $payload = $this->getTokenPayLoadInfo($jwt);
        return (new $payload->tokenable_type)->query()->find($payload->tokenable_id);
    }

    /**
     * @param string $jwt
     * @return void
     */
    public function addTokenToBlackList(string $jwt)
    {
        $data = $this->getTokenPayLoadInfo($jwt);

        //if token already expired don't need to add it to black list
        if ($data->exp <= time()) {
            return;
        }

        //add random string for create unique file if two person generate jwt at the same time
        $file = $this->blacklist_path . DIRECTORY_SEPARATOR . $data->exp . '-' . Str::random(4);

        if (!file_exists($file)) {
            touch($file);
            file_put_contents($file, $jwt);
        }
    }

    /**
     * @param Request $request
     * @return mixed|string
     */
    public function getTokenFromRequest(Request $request)
    {
        $token = $request->bearerToken() ?? '';

        $map = [
            'token',
            'api_token'
        ];
        if (empty($token)) {
            foreach ($map as $m) {
                $token = $request->input($m);
                if (!empty($token)) break;
            }
        }
        return $token;
    }

    /**
     * @param $token
     * @return bool
     */
    private function isTokenInBlackList($token)
    {
        $path = $this->blacklist_path;
        $oldFiles = array_diff(scandir($path), array('.', '..'));
        foreach ($oldFiles as $oldFile) {
            $parts = explode('-', $oldFile);
            $timestamp = $parts[0] ?? 0;
            if ($timestamp <= time()) {
                unlink($path . '/' . $oldFile);
                continue;
            }
            $content = file_get_contents($path . '/' . $oldFile);
            if ($content == $token) {
                return true;
            }
        }
        return false;
    }
}
