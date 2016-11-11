# TODO
## pending
* In place of type hinting, fully document code with expected parameter types
* Greater granularity in safe-mode (allow user set defaults + user set 'unsafe' header additions)
* Better hpkp and hsts functions (flexible-ish input like the csp function)
* Add hpkpro function for hpkp in report only mode
* Greater 'strict-dynamic' integration
* Validate more header values

## done
* ~~HPKP reporting~~ **Added!**
* ~~Basic CSP analysis, and warnings when policy appears unsafe~~ **Added!**
* ~~Import hsts and hpkp policies, reconfigure safe-mode to use maximums only (do not remove manually set headers, but modify them if unsafe)~~ **Added!**
* ~~Remove type hinting and use custom type enforcement function that generates errors similar to those produced by type hinting in PHP 7. (backwards-compatibility for PHP 5)~~ **Added!**
