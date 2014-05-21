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
 
namespace Vegas\Security;

use OAuth\Common\Storage\TokenStorageInterface;
use Phalcon\DI\InjectionAwareInterface;
use Phalcon\DiInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\AdapterAbstract;
use Vegas\Security\OAuth\Exception\AdapterNotFoundException;
use Vegas\Security\OAuth\Exception\AdapterNotInitializedException;
use Vegas\Security\OAuth\Storage\Session;

/**
 * Class OAuth
 *
 * @package Vegas\Security
 */
class OAuth implements InjectionAwareInterface
{
    use InjectionAwareTrait;

    /**
     * @var TokenStorageInterface
     */
    protected $sessionStorage = null;

    /**
     * @param DiInterface $di
     */
    public function __construct(DiInterface $di)
    {
        $this->setDI($di);
        $this->setupEventsManager();

        $this->sessionStorage = $this->getDefaultSessionStorage();
    }

    /**
     * Setups events manager attaching custom events
     */
    protected function setupEventsManager()
    {
        //extracts default events manager
        $eventsManager = $this->di->getShared('eventsManager');
        //attaches new event oauth:beforeAuthorization
        $eventsManager->attach('oauth:beforeAuthorization', \Vegas\Security\OAuth\EventsManager\Authenticate::beforeAuthorization());
        $this->di->set('eventsManager', $eventsManager);
    }

    /**
     * @param $adapterName
     * @return OAuth
     * @throws OAuth\Exception\AdapterNotFoundException
     */
    public function obtainAdapterInstance($adapterName)
    {
        $adapterNamespace = __NAMESPACE__ . '\OAuth\Adapter\\' . ucfirst($adapterName);
        try {
            $reflectionClass = new \ReflectionClass($adapterNamespace);
            $adapterInstance = $reflectionClass->newInstanceArgs(array($this->getDI(), $this->sessionStorage));

            return $adapterInstance;
        } catch (\ReflectionException $ex) {
            throw new AdapterNotFoundException($adapterName);
        }
    }

    /**
     * @param TokenStorageInterface $sessionStorage
     * @return $this
     */
    public function setSessionStorage(TokenStorageInterface $sessionStorage)
    {
        $this->sessionStorage = $sessionStorage;

        return $this;
    }

    /**
     * @return Session
     */
    public function getDefaultSessionStorage()
    {
        return new Session();
    }
}