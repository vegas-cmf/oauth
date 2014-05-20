<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage https://bitbucket.org/amsdard/vegas-phalcon
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Security\OAuth\Storage;

use OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException;
use OAuth\Common\Storage\Exception\TokenNotFoundException;
use OAuth\Common\Storage\TokenStorageInterface;
use OAuth\Common\Token\TokenInterface;

/**
 * Class Session
 * @package Vegas\Security\OAuth\Storage
 */
class Session implements TokenStorageInterface
{
    const SESSION_NAME = 'vegas_oauth';
    const SESSION_STATE = 'state';
    const SESSION_TOKEN = 'token';

    /**
     * @var null|\Vegas\Session\Scope
     */
    protected $sessionScope = null;

    /**
     * @param $serviceName
     * @return string
     */
    private function normalizeServiceName($serviceName)
    {
        return strtolower($serviceName);
    }

    /**
     *
     */
    public function __construct()
    {
        $this->sessionScope = new \Vegas\Session\Scope(self::SESSION_NAME);
        if (!$this->sessionScope->has(self::SESSION_TOKEN)) {
            $this->sessionScope->set(self::SESSION_TOKEN, array());
        }
        if (!$this->sessionScope->has(self::SESSION_STATE)) {
            $this->sessionScope->set(self::SESSION_STATE, array());
        }
    }

    /**
     * @param string $service
     *
     * @return TokenInterface
     *
     * @throws TokenNotFoundException
     */
    public function retrieveAccessToken($service)
    {
        $service = $this->normalizeServiceName($service);

        if ($this->hasAccessToken($service)) {
            $tokens = $this->sessionScope->get(self::SESSION_TOKEN);
            return unserialize($tokens[$service]);
        }

        throw new TokenNotFoundException('Token not found in session, are you sure you stored it?');
    }

    /**
     * @param string $service
     * @param TokenInterface $token
     *
     * @return TokenStorageInterface
     */
    public function storeAccessToken($service, TokenInterface $token)
    {
        $service = $this->normalizeServiceName($service);

        $serializedToken = serialize($token);
        $tokens = $this->sessionScope->get(self::SESSION_TOKEN);
        $tokens[$service] = $serializedToken;
        $this->sessionScope->set(self::SESSION_TOKEN, $tokens);

        return $this;
    }

    /**
     * @param string $service
     *
     * @return bool
     */
    public function hasAccessToken($service)
    {
        $service = $this->normalizeServiceName($service);

        $tokens = $this->sessionScope->get(self::SESSION_TOKEN);
        return isset($tokens[$service]);
    }

    /**
     * Delete the users token. Aka, log out.
     *
     * @param string $service
     *
     * @return TokenStorageInterface
     */
    public function clearToken($service)
    {
        $service = $this->normalizeServiceName($service);

        $tokens = $this->sessionScope->get(self::SESSION_TOKEN);
        if (array_key_exists($service, $tokens)) {
            unset($tokens, $service);
        }
        $this->sessionScope->set(self::SESSION_TOKEN, $tokens);

        return $this;
    }

    /**
     * Delete *ALL* user tokens. Use with care. Most of the time you will likely
     * want to use clearToken() instead.
     *
     * @return TokenStorageInterface
     */
    public function clearAllTokens()
    {
        $this->sessionScope->set(self::SESSION_TOKEN, array());

        return $this;
    }

    /**
     * Store the authorization state related to a given service
     *
     * @param string $service
     * @param string $state
     *
     * @return TokenStorageInterface
     */
    public function storeAuthorizationState($service, $state)
    {
        $service = $this->normalizeServiceName($service);

        $states = $this->sessionScope->get(self::SESSION_STATE);
        $states[$service] = $state;
        $this->sessionScope->set(self::SESSION_STATE, $state);

        return $this;
    }

    /**
     * Check if an authorization state for a given service exists
     *
     * @param string $service
     *
     * @return bool
     */
    public function hasAuthorizationState($service)
    {
        $service = $this->normalizeServiceName($service);

        $states = $this->sessionScope->get(self::SESSION_STATE);
        return isset($states[$service]);
    }

    /**
     * Retrieve the authorization state for a given service
     *
     * @param string $service
     *
     * @throws \OAuth\Common\Storage\Exception\AuthorizationStateNotFoundException
     * @return string
     */
    public function retrieveAuthorizationState($service)
    {
        $service = $this->normalizeServiceName($service);

        if ($this->hasAuthorizationState($service)) {
            $states = $this->sessionScope->get(self::SESSION_STATE);
            return $states[$service];
        }

        throw new AuthorizationStateNotFoundException('State not found in session, are you sure you stored it?');
    }

    /**
     * Clear the authorization state of a given service
     *
     * @param string $service
     *
     * @return TokenStorageInterface
     */
    public function clearAuthorizationState($service)
    {
        $service = $this->normalizeServiceName($service);

        $states = $this->sessionScope->get(self::SESSION_STATE);
        if (array_key_exists($service, $states)) {
            unset($states, $service);
        }
        $this->sessionScope->set(self::SESSION_STATE, $states);

        return $this;
    }

    /**
     * Delete *ALL* user authorization states. Use with care. Most of the time you will likely
     * want to use clearAuthorization() instead.
     *
     * @return TokenStorageInterface
     */
    public function clearAllAuthorizationStates()
    {
        $this->sessionScope->set(self::SESSION_STATE, array());

        return $this;
    }
}