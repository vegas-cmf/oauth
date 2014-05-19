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

    public function testEventsManager()
    {
        $di = DI::getDefault();
        $eventsManager = $di->getShared('eventsManager');

//        $this->assertEmpty($eventsManager->getListeners('oauth:beforeAuthentication'));
        $this->assertEmpty($eventsManager->getListeners('oauth:beforeAuthorization'));

        $oauth = new OAuth($di);

//        $this->assertNotEmpty($eventsManager->getListeners('oauth:beforeAuthentication'));
        $this->assertNotEmpty($eventsManager->getListeners('oauth:beforeAuthorization'));

//        $response = $eventsManager->fire('oauth:beforeAuthentication', $di->get('dispatcher'), array('uri' => 'relative_uri'));
//        $this->assertEquals('relative_uri', $response->getHeaders()->get('Location'));
        $response = $eventsManager->fire('oauth:beforeAuthorization', $di->get('dispatcher'), array('uri' => 'authorization_uri'));
        $this->assertEquals('authorization_uri', $response->getHeaders()->get('Location'));
    }

    public function testCreateAdapterByItsName()
    {
        $di = DI::getDefault();

        $oauth = new OAuth($di);

        $this->assertInstanceOf('\Vegas\Security\OAuth\Adapter\Linkedin', $oauth->setAdapter('linkedin')->getAdapter());
        $this->setExpectedException('\Vegas\Security\OAuth\Exception\AdapterNotFoundException');
        $oauth->setAdapter('google');
    }

    public function testCreateOAuthWithAdapter()
    {
        $di = DI::getDefault();
        $linkedin = new OAuth\Adapter\Linkedin($di);
        $oauth = new OAuth($di, $linkedin);

        $this->assertInstanceOf('\Vegas\Security\OAuth\Adapter\Linkedin', $oauth->getAdapter());
    }
} 