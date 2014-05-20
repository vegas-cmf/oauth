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
 
namespace Vegas\Security\OAuth\EventsManager;


use Phalcon\Dispatcher;
use Phalcon\Events\Event;

/**
 * Class Authenticate
 *
 * Authentication process events
 *
 * @package Vegas\Security\OAuth\EventsManager
 */
class Authenticate
{
    /**
     * @return callable
     */
    public static function beforeAuthorization()
    {
        return function(Event $event, Dispatcher $dispatcher) {
            $eventData = $event->getData();
            $authorizationUri = $eventData['uri'];

            return $dispatcher->getDI()->get('response')->redirect($authorizationUri, true);
        };
    }
}