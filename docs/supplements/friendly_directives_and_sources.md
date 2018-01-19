## Description
Friendly directives and sources are included as shorthands for some of the CSP directive and source keyword values. For example, it is possible to omit `-src` from most directives, and the surrounding single quotes from most source keywords.

The full array translation is below:


### Directives
```php
array(
    'default'   =>  'default-src',
    'script'    =>  'script-src',
    'style'     =>  'style-src',
    'image'     =>  'img-src',
    'img'       =>  'img-src',
    'font'      =>  'font-src',
    'child'     =>  'child-src',
    'base'      =>  'base-uri',
    'connect'   =>  'connect-src',
    'form'      =>  'form-action',
    'object'    =>  'object-src',
    'report'    =>  'report-uri',
    'reporting' =>  'report-uri'
);
```
### Sources
```php
array(
    'self'              => "'self'",
    'none'              => "'none'",
    'unsafe-inline'     => "'unsafe-inline'",
    'unsafe-eval'       => "'unsafe-eval'",
    'strict-dynamic'    => "'strict-dynamic'",
);
```
