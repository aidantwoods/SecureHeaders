# Contributing
Hi there! Thanks for considering making a contribution to SecureHeaders. PRs are
always welcome! 😀

## Before a Pull-Request is merged
Try to complete as many of these as possible before submitting a PR, but none
are manditory to submit (we can work to get everything checked off before merge
once the PR is submitted).

1. If you've added a new feature/fixed a bug/changed how SecureHeaders works
   in some way, it would be great if you added some tests to make sure your
   code 1. functions as expected now, 2. functions as expected when others make
   changes later.

   You should be able to find the general format for adding tests in the
   `tests/` folder in the root of this repo.
2. Make sure all the tests pass. These will be checked automagically when you
   submit a PR, but if you'd like to test locally – run `vendor/bin/phpunit`.
3. Make sure code styling matches [spec](#Code-Styling). In general, most code styling
   discrepancies can be fixed by running `vendor/bin/php-cs-fixer fix .`, but
   please take a look at the [Code Styling](#Code-Styling) guide anyway.
4. Make sure [Coding Conventions](#Coding-Conventions) are followed.


### Code Styling
Code styling in this repo follows PSR-2 generally, with the following
exceptions and additions:
1. All opening braces (`{`) must start on the **next** line
   e.g.
   ```php
   foreach ($Foo as $bar)
   {
       # do something
   }
   ```
   However, if an immediately preceding closing (`)`) is on its own line then
   you must place the opening (`{`) on the same line seperated by a single
   space. e.g.
   ```php
   public function hpkp(
       $pins,
       $maxAge = null,
       $subdomains = null,
       $reportUri = null,
       $reportOnly = null
   ) {
   ```

2. The not operator (`!`) must have whitespace on either side
3. Short array syntax must be used (`[]` and not `array()`)
4. Single-line text comments must use `#` and not `//`
5. Commented out code (if it is ever appropriate in the repo) must use
   `//` on each line and not `#`

### Coding Conventions
The following conventions are to be followed:
1. Aggressive type hints (compatible with PHP 5.4):
   * If you can type hint with PHP in function arguments, you should do that;
     otherwise
   * If the type of a variable must be of a certain type to work, and it is
     passed through a function, you must use the built in type assersion
     helper, e.g.
     ```php
     public function hpkp(
         $pins,
         $maxAge = null,
         $subdomains = null,
         $reportUri = null,
         $reportOnly = null
     ) {
         Types::assert(
             [
                 'string|array' => [$pins],
                 'int|string' => [$maxAge],
                 'string' => [$reportUri]
             ],
             [1, 2, 4]
         );
     ```

     The first argument of `Types::assert()` is an array of types mapping to an
     array of variables for which to assert the type. Multiple type allowances
     are seperated with a pipe (`|`).
     The second argument is an array of argument numbers, referring to the
     arguement numbers of the varibles in the order that they are given
     in the first array (this is used for debugging purposes so the argument
     number can be given).

     If all the arguments are given in order with no gaps, starting from one
     then the second array detailing the argument numbers may be omitted.

     Here's an other example:
     ```php
     public function cspHash(
         $friendlyDirective,
         $string,
         $algo = null,
         $isFile = null,
         $reportOnly = null
     ) {
         Types::assert(
             ['string' => [$friendlyDirective, $string, $algo]]
         );
     ```
