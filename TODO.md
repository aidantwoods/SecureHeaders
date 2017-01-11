# TODO
## pending
* Cookies: SameSite, __Host-*
* Write tests for cookie upgrades
* Look into populating internal header list with values set by server
* Greater granularity in safe-mode (allow user set defaults + user set 'unsafe' header additions)

## done
* ~~HPKP reporting~~ **Added!**
* ~~Basic CSP analysis, and warnings when policy appears unsafe~~ **Added!**
* ~~Import hsts and hpkp policies, reconfigure safe-mode to use maximums only (do not remove manually set headers, but modify them if unsafe)~~ **Added!**
* ~~Remove type hinting and use custom type enforcement function that generates errors similar to those produced by type hinting in PHP 7. (backwards-compatibility for PHP 5)~~ **Added!**
* ~~Greater 'strict-dynamic' integration~~ **Added!**
* ~~In place of type hinting, fully document code with expected parameter types~~ **Added!** (in Wiki)
* ~~Add hpkpro function for hpkp in report only mode~~ **Added!**

## long term goals
* Validate more header values

