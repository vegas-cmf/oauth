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
namespace Oauth\Controllers\Frontend;
use User\Services\Exception\SignUpFailedException;
use Vegas\Security\Authentication\Exception\IdentityNotFoundException;
use Vegas\Security\OAuth\Exception\FailedAuthorizationException;

/**
 * Class AuthController
 * @package Oauth\Controllers\Frontend
 */
class OauthController extends \Vegas\Mvc\Controller\ControllerAbstract
{
    /**
     *
     */
    public function indexAction()
    {
        //oauth
        $oAuth = $this->serviceManager->getService('oauth:oauth');
        $oAuth->initialize();

        $this->view->linkedinUri = $oAuth->getAuthorizationUri('linkedin');
        $this->view->facebookUri = $oAuth->getAuthorizationUri('facebook');
        $this->view->googleUri = $oAuth->getAuthorizationUri('google');
    }

    /**
     * @return \Phalcon\Http\ResponseInterface
     */
    public function authorizeAction()
    {
        $this->view->disable();

        $serviceName = $this->dispatcher->getParam('service');
        $oauth = $this->serviceManager->getService('oauth:oauth');
        $oauth->initialize();

        try {
            //authorize given service
            $oauth->authorize($serviceName);

            /**
             * @var \Vegas\Security\OAuth\Identity $identity
             */
            $identity = $oauth->getIdentity($serviceName);
            //now you can create session for oauth identity
            //....

            return $this->response->redirect(array('for' => 'root'))->send();
        } catch(FailedAuthorizationException $ex) {
            $this->flashSession->message('error', $ex->getMessage());
            return $this->response->redirect(array('for' => 'login'))->send();
        }
    }

    /**
     * @return \Phalcon\Http\ResponseInterface
     */
    public function logoutAction()
    {
        $this->view->disable();

        $oauth = $this->serviceManager->getService('oauth:oauth');
        $oauth->initialize();

        $oauth->logout();

        return $this->response->redirect(array('for' => 'root'))->send();
    }
}
 
