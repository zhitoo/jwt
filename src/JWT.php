<?php

namespace Hshafiei374\Jwt;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Log;

class JWT
{
    /**
     * The personal access client model class name.
     *
     * @var string
     */
    public static $JwtTokenModel = JwtToken::class;

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
        if (!JwtToken::isTokenValid($jwt)) return null;

        try {
            JwtToken::updateLastUsedAt($jwt);
        } catch (\Exception $exception) {
            Log::error($exception);
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
        $jwt = $base64UrlHeader . "." . $base64UrlPayload . "." . $base64UrlSignature;
        return $jwt;
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
        try {
            return (new $payload->tokenable_type)->find($payload->tokenable_id);
        } catch (\Exception $exception) {
            return null;
        }

    }


}
