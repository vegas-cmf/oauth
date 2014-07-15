<?php
/**
 * This file is part of Vegas package
 *
 * @author Slawomir Zytko <slawomir.zytko@gmail.com>
 * @copyright Amsterdam Standard Sp. Z o.o.
 * @homepage http://vegas-cmf.github.io
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */
 
namespace Vegas\Security\OAuth;

/**
 * Simple class for object representation identity
 *
 * @package Vegas\Security\Authentication
 */
class Identity 
{
    /**
     * Identity values
     *
     * @var array
     */
    private $values = array();

    /**
     *
     * @param $service
     * @param $email
     */
    public function __construct($service, $email)
    {
        $this->values['service'] = $service;
        $this->values['email'] = $email;
    }

    /**
     * @return string
     */
    public function getEmail()
    {
        return $this->email;
    }

    /**
     * @return string
     */
    public function getService()
    {
        return $this->service;
    }

    /**
     * @param $name
     * @param $value
     */
    public function __set($name, $value)
    {
        $this->values[$name] = $value;
    }

    /**
     * Makes identity values accessible as object property
     * For example for get user ID
     * <code>
     * echo $identity->id;
     * </code>
     *
     * @param $name
     * @return null
     */
    public function __get($name)
    {
        return isset($this->values[$name]) ? $this->values[$name] : null;
    }


    /**
     * Makes identity values accessible by method calling
     * For example for get user ID
     * <code>
     * echo $identity->getId();
     * </code>
     *
     * @param $name
     * @param $args
     * @return null
     */
    public function __call($name, $args)
    {
        if (strpos($name, 'get') !== -1) {
            $name = lcfirst(str_replace('get', '', $name));
            if (!isset($this->values[$name])) return null;

            return $this->values[$name];
        }

        return null;
    }

    /**
     * @return array
     */
    public function toArray()
    {
        return $this->values;
    }
} 