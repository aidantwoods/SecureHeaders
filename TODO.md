# TODO
* ~~HPKP reporting~~
* ~~Basic CSP analysis, and warnings when policy appears unsafe~~
* ~~Import hsts and hpkp policies, reconfigure safe-mode to use maximums only (do not remove manually set headers, but modify them if unsafe)~~
* ~~Remove type hinting and use custom type enforcement function that generates errors similar to those produced by type hinting in PHP 7. (backwards-compatibility for PHP 5)~~
* In place of type hinting, fully document code with expected parameter types
* Greater granularity in safe-mode (allow user set defaults + user set 'unsafe' header additions)
* Better hpkp and hsts functions (flexible-ish input like the csp function)
* Add hpkpro function for hpkp in report only mode
* ~~Possibly allow `->csp($directive, 'nonce')` as an alias for `csp_nonce($directive)` (If adding this, I'd also like to add a similar alias for `->csp_hash($directive, $value)` to keep everything consistent, but `csp->($directive, 'hash', $value)` would involve introduction of ordered triples into csp syntax – it's workable, but may get confusing. Especially if wanting to support the full `->csp_hash($directive, $value, $algo, $is_file)` options list. What's a good default for `$is_file`? Or should I allow ordered n-plets to include an `$algo`, or even `$is_file`? If an ordered n-plet is incomplete, should I discard the remaining arguments, or parse them separately? Should I allow booleans or integers for `$is_file` – weakening the reliability of a transform of `->csp` into `report_only` mode (booleans and integers are reserved for dictating this mode at present), or should I special case them if part of an ordered n-plet containing 'hash' in the value position? How can I tell whether the user wishes to leave `$is_file` unspecified, but does wish to specify `report_only` mode, or wants to specify `$is_file`, but does not want to specify `report_only` mode?).~~ Perhaps it is best to keep `csp_hash` and `csp_nonce` (for consistency) as a separate functions.
