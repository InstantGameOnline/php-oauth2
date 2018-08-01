<?php

namespace InstantGameOnline\OAuth2\Client\Provider;

use Lcobucci\JWT\Parser;
use League\OAuth2\Client\Grant\AbstractGrant;
use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use React\Promise\PromiseInterface;
use RuntimeException;

class InstantGameOnline extends AbstractProvider
{
    use BearerAuthorizationTrait;
    use ReactTrait;

    const WEB_URL = 'https://instantgame.online';
    const API_URL = 'https://api.instantgame.online/v1';

    protected $webUrl;
    protected $apiUrl;

    public function __construct(array $options = [], array $collaborators = [])
    {
        $this->webUrl = static::WEB_URL;
        $this->apiUrl = static::API_URL;

        if (isset($collaborators['browser'])) {
            $this->setBrowser($collaborators['browser']);
        }

        parent::__construct($options, $collaborators);
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

    /**
     * Returns the base URL for authorizing a client.
     *
     * Eg. https://oauth.service.com/authorize
     *
     * @return string
     */
    public function getBaseAuthorizationUrl()
    {
        return $this->webUrl . '/oauth/authorize';
    }

    /**
     * Returns the base URL for requesting an access token.
     *
     * Eg. https://oauth.service.com/token
     *
     * @param array $params
     * @return string
     */
    public function getBaseAccessTokenUrl(array $params)
    {
        return $this->apiUrl . '/oauth/access-token';
    }

    /**
     * Returns the URL for requesting the resource owner's details.
     *
     * @param AccessToken $token
     * @return string
     */
    public function getResourceOwnerDetailsUrl(AccessToken $token)
    {
        return $this->apiUrl . '/profile';
    }

    /**
     * Returns the default scopes used by this provider.
     *
     * This should only be the scopes that are required to request the details
     * of the resource owner, rather than all the available scopes.
     *
     * @return array
     */
    protected function getDefaultScopes()
    {
        return [
            'profile',
        ];
    }

    protected function getScopeSeparator()
    {
        return ' ';
    }

    protected function getDefaultHeaders()
    {
        return [
            'Accept' => 'application/json',
        ];
    }

    /**
     * Checks a provider response for errors.
     *
     * @throws IdentityProviderException
     * @param  ResponseInterface $response
     * @param  array|string $data Parsed response data
     * @return void
     */
    protected function checkResponse(ResponseInterface $response, $data)
    {
        if ($response->getStatusCode() === 200) {
            return;
        }

        throw new IdentityProviderException(
            $data['message'],
            $response->getStatusCode(),
            $response->getBody()->getContents()
        );
    }

    protected function createAccessToken(array $response, AbstractGrant $grant)
    {
        $jwtToken = (new Parser())->parse($response['access_token']);

        $response['scopes'] = $jwtToken->getClaim('scopes');

        return new AccessToken($response);
    }

    /**
     * Generates a resource owner object from a successful resource owner
     * details request.
     *
     * @param  array $response
     * @param  AccessToken $token
     * @return ResourceOwnerInterface
     */
    protected function createResourceOwner(array $response, AccessToken $token)
    {
        throw new RuntimeException('This has not been implemented');
    }

    protected function getAllowedClientOptions(array $options)
    {
        $allowedClientOptions = parent::getAllowedClientOptions($options);
        $allowedClientOptions[] = 'verify';

        return $allowedClientOptions;
    }
}
