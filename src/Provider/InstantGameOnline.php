<?php

namespace InstantGameOnline\OAuth2\Client\Provider;

use League\OAuth2\Client\Provider\AbstractProvider;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Tool\BearerAuthorizationTrait;
use Psr\Http\Message\ResponseInterface;
use RuntimeException;

class InstantGameOnline extends AbstractProvider
{
    use BearerAuthorizationTrait;

    const WEB_URL = 'https://instantgame.online';
    const API_URL = 'https://api.instantgame.online/v1';

    protected $webUrl;
    protected $apiUrl;

    public function __construct(array $options = [], array $collaborators = [])
    {
        $this->webUrl = static::WEB_URL;
        $this->apiUrl = static::API_URL;

        parent::__construct($options, $collaborators);
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
            $response->getReasonPhrase(),
            $response->getStatusCode(),
            $response->getBody()->getContents()
        );
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
}
