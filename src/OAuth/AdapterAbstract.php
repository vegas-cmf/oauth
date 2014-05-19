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

namespace Vegas\Security\OAuth;

use OAuth\Common\Consumer\Credentials;
use Phalcon\DI\InjectionAwareInterface;
use Phalcon\DiInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\Exception\InvalidApplicationKeyException;
use Vegas\Security\OAuth\Exception\InvalidApplicationSecretKeyException;
use Vegas\Security\OAuth\Exception\ServiceNotInitializedException;
use Vegas\Security\OAuth\Storage\Session;

/**
 * Class AdapterAbstract
 * @package Vegas\Security\OAuth
 */
abstract class AdapterAbstract implements InjectionAwareInterface
{
    use InjectionAwareTrait;

    /**
     * URI helper
     *
     * @var \OAuth\Common\Http\Uri\UriInterface
     */
    protected $currentUri;

    /**
     * Session storage instance
     *
     * @var Storage\Session
     */
    protected $sessionStorage;

    /**
     * Provided credentials
     *
     * @var Credentials
     */
    protected $credentials;

    /**
     * List of added provider scope
     *
     * @var array
     */
    protected $scopes = array();

    /**
     * @var \OAuth\Common\Service\ServiceInterface
     */
    protected $service;

    /**
     * Creates URI factory for building urls
     * Setups session storage
     *
     * @param DiInterface $di
     */
    public function __construct(DiInterface $di)
    {
        $this->setDI($di);

        $uriFactory = new \OAuth\Common\Http\Uri\UriFactory();
        $this->currentUri = $uriFactory->createFromSuperGlobalArray($_SERVER);
        $this->currentUri->setQuery('');

        $this->sessionStorage = new Session();
    }

    /**
     * Returns the name of current service
     *
     * @return mixed
     */
    abstract public function getServiceName();

    /**
     * Authentication process
     *
     * @return mixed
     */
    abstract public function authenticate();

    /**
     * Setups provider credentials
     *
     * @param array $credentials
     * @throws Exception\InvalidApplicationKeyException
     * @throws Exception\InvalidApplicationSecretKeyException
     */
    public function setupCredentials(array $credentials)
    {
        if (!array_key_exists('key', $credentials)) {
            throw new InvalidApplicationKeyException();
        }
        if (!array_key_exists('secret', $credentials)) {
            throw new InvalidApplicationSecretKeyException();
        }
        $this->credentials = new Credentials(
            $credentials['key'],
            $credentials['secret'],
            !isset($credentials['redirect_uri']) ? $this->getCurrentUri() : $credentials['redirect_uri']
        );
    }

    /**
     * Builds the full URI based on all the properties
     *
     * @return string
     */
    public function getCurrentUri()
    {
        return $this->currentUri->getAbsoluteUri();
    }

    /**
     * Sets provider scopes
     *
     * @param array $scopes
     * @return $this
     */
    public function setScopes(array $scopes = array())
    {
        $this->scopes = $scopes;

        return $this;
    }

    /**
     * Adds provider scope
     *
     * @param $scope
     * @return $this
     */
    public function addScope($scope)
    {
        if (!in_array($scope, $this->scopes)) {
            $this->scopes[] = $scope;
        }

        return $this;
    }

    /**
     * Initializes the OAuth service
     * The service is created by \OAuth\ServiceFactory upon service name returned from getServiceName() method
     *
     * @return $this
     */
    public function init()
    {
        $serviceFactory = new \OAuth\ServiceFactory();
        $this->service = $serviceFactory->createService(
            $this->getServiceName(), $this->credentials, $this->sessionStorage, $this->scopes
        );

        return $this;
    }

    /**
     * Calls indicated method on OAuth service
     *
     * @param $name
     * @param $args
     * @return mixed
     */
    public function __call($name, $args)
    {
        $this->assertServiceInstance();

        return call_user_func(array($this->service, $name), $args);
    }

    /**
     * Sends an authenticated API request to the path provided.
     * If the path provided is not an absolute URI, the base API Uri (service-specific) will be used.
     *
     * @param string|UriInterface $path
     * @param string              $method       HTTP method
     * @param array               $body         Request body if applicable (an associative array will
     *                                          automatically be converted into a urlencoded body)
     * @param array               $extraHeaders Extra headers if applicable. These will override service-specific
     *                                          any defaults.
     *
     * @return array                            Decoded response
     */
    public function request($path, $method = 'GET', $body = null, array $extraHeaders = array())
    {
        $this->assertServiceInstance();

        $response = $this->service->request($path, $method, $body, $extraHeaders);
        return json_decode($response, true);
    }

    /**
     * Determines if OAuth service is initialized
     *
     * @return bool
     * @throws Exception\ServiceNotInitializedException
     */
    protected function assertServiceInstance()
    {
        if (!$this->service instanceof \OAuth\Common\Service\ServiceInterface) {
            throw new ServiceNotInitializedException();
        }

        return true;
    }
} 