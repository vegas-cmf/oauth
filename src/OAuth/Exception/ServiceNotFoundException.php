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
 
namespace Vegas\Security\OAuth\Exception;

use Vegas\Security\OAuth\Exception as OAuthException;

/**
 * Class ServiceNotFoundException
 * @package Vegas\Security\OAuth\Exception
 */
class ServiceNotFoundException extends OAuthException
{
    protected $message = 'Service \'%s\' does not exist';

    /**
     * @param string $adapterName
     */
    public function __construct($adapterName)
    {
        $this->message = sprintf($this->message, $adapterName);
    }
} 