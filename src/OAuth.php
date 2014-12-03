<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawek@amsterdam-standard.pl>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Security;

use OAuth\Common\Storage\TokenStorageInterface;
use Phalcon\DI\InjectionAwareInterface;
use Phalcon\DiInterface;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth\Exception\ServiceNotFoundException;
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

        $this->sessionStorage = $this->getDefaultSessionStorage();
    }

    /**
     * @param $adapterName
     * @return OAuth\ServiceAbstract
     * @throws OAuth\Exception\ServiceNotFoundException
     */
    public function obtainServiceInstance($adapterName)
    {
        $adapterNamespace = __NAMESPACE__ . '\OAuth\Service\\' . ucfirst($adapterName);
        try {
            $reflectionClass = new \ReflectionClass($adapterNamespace);
            $adapterInstance = $reflectionClass->newInstanceArgs(array($this->getDI(), $this->sessionStorage));

            return $adapterInstance;
        } catch (\ReflectionException $ex) {
            throw new ServiceNotFoundException($adapterName);
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