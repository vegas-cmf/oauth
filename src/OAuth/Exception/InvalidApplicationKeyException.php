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
 
namespace Vegas\Security\OAuth\Exception;

use Vegas\Security\OAuth\Exception as OAuthException;

/**
 * Class InvalidApplicationKeyException
 * @package Vegas\Security\OAuth\Exception
 */
class InvalidApplicationKeyException extends OAuthException
{
    protected $message = 'Application key is invalid';
} 