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
 
namespace Vegas\Security\OAuth\Service;

use Vegas\Security\OAuth\Identity;
use Vegas\Security\OAuth\ServiceAbstract;

/**
 * Class Linkedin
 *
 * @see https://developer.linkedin.com/documents/authentication
 *
 * @package Vegas\Security\OAuth\Service
 */
class Linkedin extends ServiceAbstract
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
     * @return Identity
     */
    public function getIdentity()
    {
        $response = $this->request('/people/~:(id,first-name,last-name,email-address,picture-url,public-profile-url)?format=json');

        $identity = new Identity($this->getServiceName(), $response['emailAddress']);
        $identity->id = $response['id'];
        $identity->first_name = $response['firstName'];
        $identity->last_name = $response['lastName'];
        $identity->picture = !isset($response['pictureUrl']) ? '' : $response['pictureUrl'];
        $identity->link = $response['publicProfileUrl'];


        return $identity;
    }
}