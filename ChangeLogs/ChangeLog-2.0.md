# Changes in SecureHeaders 2.0

All notable changes of the SecureHeaders 2.0 release series are documented in
this file using the [Keep a CHANGELOG](http://keepachangelog.com/) principles.

## [2.0] - *2017-07-16*

### Added
* You can now easily integrate SecureHeaders with arbitrary frameworks by
  implementing the HttpAdapter (`Aidantwoods\SecureHeaders\Http\HttpAdapter`).

* Better cookie upgrades:
  Specifically incorporating the[`SameSite`](https://tools.ietf.org/html/draft-west-first-party-cookies-07#section-4.1)
  cookie attribute. The plan is for `SameSite=Lax` to be added in alongside the
  `HttpOnly` and `Secure` flags to sensitive looking cookies by default, and for
  this to be upgraded to `SameSite=Strict` if operating in
  [`strictMode`](https://github.com/aidantwoods/SecureHeaders/wiki/strictMode).

  `SameSite=Lax` already offers pretty good CSRF protection by preventing non
  GET requests or non top-level requests from sending cookies when coming from
  a cross-origin source. In other words cookies will not be sent when the
  request originates from a cross-origin unless request can be seen in the URL
  bar and any request data is also in the URL bar.

  Obviously this isn't a complete solution, so for those that want it stricter,
  I'll include the upgrade to `SameSite=Strict`. This is be able to be
  configured granularly similarly to how
  `HttpOnly` and `Secure` are [currently configured](https://github.com/aidantwoods/SecureHeaders/wiki/auto#auto_cookie_secure)
  or just by enabling `strictMode` to use `SameSite=Strict` (as said above).

* Add a new header by default:
  The new header being [`X-Permitted-Cross-Domain-Policies: none`](https://www.owasp.org/index.php/OWASP_Secure_Headers_Project#X-Permitted-Cross-Domain-Policies).
  As with other automatic headers, this will be done via a
  [header proposal](https://github.com/aidantwoods/SecureHeaders/wiki/header-proposals)
  – so this can be explicitly removed or modified as you prefer if the default
  is not desired.

* Add a new header by default:
  `Referrer-Policy: strict-origin-when-cross-origin` with a fallback policy of
  `no-referrer`.
  I've made `no-referrer` the fallback because is the only policy value
  (currently) supported by both Chrome and FF which guarantees that the full
  query string will remain private on cross-origin requests, and that no URL is
  leaked over the network on insecure requests (to the same origin).
  At time of writing latest stable on both Chrome and FF do not understand
  `strict-origin-when-cross-origin` and will use the fallback. Firefox is due to
  add support in v52. Chrome has a
  [bug report](https://bugs.chromium.org/p/chromium/issues/detail?id=627968)
  open.
  [Safari and other browsers](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy#Browser_compatibility)
  appear to offer no support. This is unfortunate. Hopefully there will be
  progress.

* Add a new header by default: `Expect-CT: max-age=0`.
  [Spec here](https://datatracker.ietf.org/doc/draft-stark-expect-ct/).
  This defaults to reporting mode, but will be configurable to operate in
  enforce mode, or just reporting with some `report-uri` specified.

### Changed
* SecureHeaders is now intended to be a composer library, meaning that the
  single `SecureHeaders.php` will no longer contain the whole library. However,
  you may now instead download and include/require the entire library via
  the `SecureHeaders.phar` release.

* The SecureHeaders class is now namespaced to
  `Aidantwoods\SecureHeaders\SecureHeaders;`

* Strict Mode now includes injecting the `SameSite` cookie attribute.

* Strict Mode now includes the `Expect-CT: max-age=31536000; enforce`
  as a header proposal.

* If SecureHeaders throws an exception, it'll only auto-send the headers when
  emitting that exception if `applyOnOutput` has been enabled (it is not on
  by default).

### Removed
* `doneOnOutput` and `done` are now `applyOnOutput` and `apply`. These new
  methods allow custom HttpAdapters to be used (so you can integrate more
  easily with frameworks), but if you supply no arguements the "global"
  HttpAdaper will be used (i.e. interact directly with PHPs `header()` and
  similar functions).

* `addHeader` has been removed. You should add headers with `header()` or via
  your framework now.

* `correctHeaderName` has been removed. Please ensure your header names are
  correct

* PHP 5.3 is no longer supported.
