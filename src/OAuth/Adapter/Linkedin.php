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
 
namespace Vegas\Security\OAuth\Adapter;

use Vegas\Security\OAuth\AdapterAbstract;

/**
 * Class Linkedin
 *
 * @see https://developer.linkedin.com/documents/authentication
 *
 * @package Vegas\Security\OAuth\Adapter
 */
class Linkedin extends AdapterAbstract
{
    /**
     * Name of oAuth service
     */
    const SERVICE_NAME = 'linkedin';

    /**
     * Your Profile Overview
     * Name, photo, headline, and current positions
     * GET /people/~
     *  * see person field list
     */
    const SCOPE_BASIC_PROFILE = 'r_basicprofile';

    /**
     * Your Full Profile
     * Full profile including experience, education, skills, and recommendations
     * GET /people/~
     *  * see person field list
     */
    const SCOPE_FULL_PROFILE = 'r_fullprofile';

    /**
     * Your Email Address
     * The primary email address you use for your LinkedIn account
     * GET /people/~/email-address
     */
    const SCOPE_EMAIL_ADDRESS = 'r_emailaddress';

    /**
     * Your Connections
     * Your 1st and 2nd degree connections
     * GET /people/~
     *  * see person field list
     */
    const SCOPE_NETWORK = 'r_network';

    /**
     * Your Contact Info
     * Retrieve and post updates to LinkedIn as you
     * GET /people/~/network/updates
     * POST /people/~/shares
     */
    const SCOPE_CONTACT_INFO = 'r_contactinfo';

    /**
     * Network Updates
     * Retrieve and post updates to LinkedIn as you
     * GET /people/~/network/updates
     * POST /people/~/shares
     */
    const SCOPE_NETWORK_UPDATES = 'rw_nus';

    /**
     * Company Page & Analytics
     * Edit company pages for which I am an Admin and post status updates on behalf of those companies
     * POST /companies/{id}/shares
     * GET companies/{id}/company-statistics
     */
    const SCOPE_COMPANY_ADMIN = 'rw_company_admin';

    /**
     * Group Discussions
     * Retrieve and post group discussions as you
     * GET & POST /groups
     * GET & POST /posts
     * GET & POST /people/~/group-memberships
     */
    const SCOPE_GROUPS = 'rw_groups';

    /**
     * Invitations and Messages
     * Send messages and invitations to connect as you
     * POST /people/~/mailbox
     */
    const SCOPE_MESSAGES = 'w_messages';

    /**
     * {@inheritdoc}
     */
    public function getServiceName()
    {
        return self::SERVICE_NAME;
    }

    /**
     * Sets all permissions, which user will be asked for during authentication process
     */
    public function setAllScopes()
    {
        $scopes = array();
        $reflectionClass = new \ReflectionClass(__CLASS__);
        foreach ($reflectionClass->getConstants() as $constantName => $constantValue) {
            if (strpos($constantName, 'SCOPE_') !== false) {
                $scopes = $constantValue;
            }
        }

        $this->setScopes($scopes);
    }

    /**
     * Authentication process
     *
     * @return \OAuth\Common\Http\Uri\UriInterface|string
     */
    public function authenticate()
    {
        $this->assertServiceInstance();

        $request = $this->di->get('request');
        $code = $request->getQuery('code', null);
        if (!is_null($code)) {
            $state = $request->getQuery('state', null);

            return  $this->service->requestAccessToken($code, $state);
        } elseif ($request->getQuery('go') === 'go') {
            $uri = $this->service->getAuthorizationUri();
            $this->getDI()->get('eventsManager')->fire('beforeAuthorization', $this->getDI()->get('dispatcher'), array(
                'uri'   =>  $uri
            ));

            return $uri;
        } else {
            $uri = $this->currentUri->getRelativeUri() . "?go=go";

            return $uri;
        }
    }
}