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

use Phalcon\DI\InjectionAwareInterface;
use Phalcon\DiInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\AdapterAbstract;
use Vegas\Security\OAuth\Exception\AdapterNotFoundException;
use Vegas\Security\OAuth\Exception\AdapterNotInitializedException;

/**
 * Class OAuth
 *
 * @method getServiceName()
 * @method authenticate()
 * @method setupCredentials(array $credentials)
 * @method getCurrentUri()
 * @method setScopes(array $scopes=array())
 * @method addScope($scope)
 * @method init()
 * @method request($path, $method = 'GET', $body = null, array $extraHeaders = array())
 *
 *
 * @package Vegas\Security
 */
class OAuth implements InjectionAwareInterface
{
    use InjectionAwareTrait;

    /**
     * @var AdapterAbstract
     */
    private $adapter;

    /**
     * @param DiInterface $di
     * @param AdapterAbstract $adapter
     */
    public function __construct(DiInterface $di, AdapterAbstract $adapter = null)
    {
        $this->setDI($di);
        $this->setupEventsManager();

        $this->adapter = $adapter;
    }

    /**
     * Setups events manager attaching custom events
     */
    protected function setupEventsManager()
    {
        //extracts default events manager
        $eventsManager = $this->di->getShared('eventsManager');
        //attaches new event oauth:beforeAuthentication and oauth:beforeAuthorization
//        $eventsManager->attach('oauth:beforeAuthentication', \Vegas\Security\OAuth\EventsManager\Authenticate::beforeAuthentication());
        $eventsManager->attach('oauth:beforeAuthorization', \Vegas\Security\OAuth\EventsManager\Authenticate::beforeAuthorization());
        $this->di->set('eventsManager', $eventsManager);
    }

    /**
     * @param $name
     * @return OAuth
     * @throws OAuth\Exception\AdapterNotFoundException
     */
    public function setAdapter($name)
    {
        $adapterNamespace = __NAMESPACE__ . '\OAuth\Adapter\\' . ucfirst($name);
        try {
            $reflectionClass = new \ReflectionClass($adapterNamespace);
            $adapterInstance = $reflectionClass->newInstance($this->getDI());

            $this->adapter = $adapterInstance;
        } catch (\ReflectionException $ex) {
            throw new AdapterNotFoundException($name);
        }

        return $this;
    }

    /**
     * @param $name
     * @param $args
     * @throws OAuth\Exception\AdapterNotInitializedException
     * @return mixed
     */
    public function __call($name, $args)
    {
        $this->assertAdapterInstance();

        return call_user_func(array($this->adapter, $name), $args);
    }

    /**
     * @return AdapterAbstract
     */
    public function getAdapter()
    {
        $this->assertAdapterInstance();
        return $this->adapter;
    }

    /**
     * Determines if adapter has been already initialized
     *
     * @param bool $throwException
     * @throws OAuth\Exception\AdapterNotInitializedException
     * @return bool
     */
    protected function assertAdapterInstance($throwException = true)
    {
        if (null == $this->adapter) {
            if ($throwException) {
                throw new AdapterNotInitializedException();
            }
            return false;
        }
        return true;
    }
}