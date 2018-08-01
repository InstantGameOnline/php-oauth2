<?php

namespace InstantGameOnline\OAuth2\Client\Provider;

use Clue\React\Buzz\Browser;
use Psr\Http\Message\ResponseInterface;
use React\Promise\PromiseInterface;

trait ReactTrait
{
    /**
     * @var Browser
     */
    protected $browser;

    public function setBrowser(Browser $browser)
    {
        $this->browser = $browser;

        return $this;
    }

    public function getBrowser()
    {
        return $this->browser;
    }

    /**
     * Requests an access token using a specified grant and option set.
     *
     * @param  mixed $grant
     * @param  array $options
     * @return PromiseInterface
     */
    public function getAccessTokenReact($grant, array $options = []): PromiseInterface
    {
        $grant = $this->verifyGrant($grant);

        $params = [
            'client_id'     => $this->clientId,
            'client_secret' => $this->clientSecret,
            'redirect_uri'  => $this->redirectUri,
        ];

        $params   = $grant->prepareRequestParameters($params, $options);
        $request  = $this->getAccessTokenRequest($params);

        return $this->getBrowser()->send($request)
            ->then(function (ResponseInterface $response) use ($grant) {
                $parsed = $this->parseResponse($response);

                $this->checkResponse($response, $parsed);

                $prepared = $this->prepareAccessTokenResponse($parsed);

                return $this->createAccessToken($prepared, $grant);
            });
    }
}
