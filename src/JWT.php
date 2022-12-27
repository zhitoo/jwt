<?php

namespace Zhitoo\Jwt;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Str;

class JWT
{

    private static $jwt;
    private $secret;
    private $expiration;

    private function __construct(int $expiration, string $secret)
    {
        $this->expiration = $expiration * 60;//change minutes to seconds
        $this->secret = $secret;
    }

    public static function getInstance(int $expiration, string $secret)
    {
        if (!isset(static::$jwt)) {
            static::$jwt = new static($expiration, $secret);
        }
        return static::$jwt;
    }


    protected function base64UrlEncode(string $text)
    {
        return str_replace(
            ['+', '/', '='],
            ['-', '_', ''],
            base64_encode($text)
        );
    }


    public function getTokenableIfTokenValid(Request $request)
    {
        $jwt = $request->bearerToken() ?? '';

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
        if (empty($jwt)) return null;
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
        if (!empty($payLoadObj->exp)) {
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

        return $this->getTokenable($jwt);
    }

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
            'exp' => time() + $this->expiration
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

    private function getTokenPayLoadInfo(string $jwt)
    {
        $parts = $this->getTokenParts($jwt);
        return isset($parts['payload']) ? json_decode($parts['payload']) : null;
    }

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
        $path = storage_path() . '/jwt/blacklist';
        //create path if not exists
        if (!file_exists($path)) {
            mkdir($path, 0755, true);
        }

        $this->removeExpiredTokenFromBlackList($path);


        //if token already expired don't need to add it to black list
        if ($data->exp <= time()) {
            return;
        }

        //add random string for create unique file if two person generate jwt at the same time
        $file = $path . '/' . $data->exp . '-' . Str::random(4);

        if (!file_exists($file)) {
            touch($file);
            file_put_contents($file, $jwt);
        }
    }


    /**
     * @param string $path
     * @return void
     */
    private function removeExpiredTokenFromBlackList(string $path)
    {
        //remove expired tokens
        $oldFiles = $files = array_diff(scandir($path), array('.', '..'));
        foreach ($oldFiles as $oldFile) {
            $parts = explode('-', $oldFile);
            $timestamp = $parts[0] ?? 0;
            if ($timestamp <= time()) {
                unlink($path . '/' . $oldFile);
            }
        }
    }
}
