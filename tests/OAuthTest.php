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

namespace Vegas\Tests\Security;

use Phalcon\DI;
use Vegas\DI\InjectionAwareTrait;
use Vegas\Security\OAuth;

class OAuthTest extends \PHPUnit_Framework_TestCase
{
    public function setUp()
    {
        $_SERVER['REQUEST_URI'] = '/login';
    }

    public function testCreateAdapterByItsName()
    {
        $di = DI::getDefault();

        $oauth = new OAuth($di);

        $this->assertInstanceOf('\Vegas\Security\OAuth\Service\Linkedin', $oauth->obtainServiceInstance('linkedin'));
        $this->setExpectedException('\Vegas\Security\OAuth\Exception\ServiceNotFoundException');
        $oauth->obtainServiceInstance('fake');
    }

    public function testCreateAdapterByItsClass()
    {
        $di = DI::getDefault();
        $oauth = new OAuth($di);
        $linkedin = new \Vegas\Security\OAuth\Service\Linkedin($di, $oauth->getDefaultSessionStorage());

        $this->assertInstanceOf('\Vegas\Security\OAuth\Service\Linkedin', $linkedin);
    }
} 