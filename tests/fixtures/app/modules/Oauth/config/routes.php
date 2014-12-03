<?php

return array(
    'oauth' => array(
        'route' => '/oauth',
        'paths' => array(
            'module'    =>  'Oauth',
            'controller' => 'Frontend\Oauth',
            'action' => 'index',

            'auth'  =>  false
        )
    ),
    'authorize' => array(
        'route' => '/oauth/{service}',
        'paths' => array(
            'module'    =>  'Oauth',
            'controller' => 'Frontend\Oauth',
            'action' => 'authorize',

            'auth'  =>  false
        )
    ),
    'logout' => array(
        'route' => '/oauth/logout',
        'paths' => array(
            'module'    =>  'Oauth',
            'controller' => 'Frontend\Oauth',
            'action' => 'logout',

            'auth'  =>  false
        )
    )
);
