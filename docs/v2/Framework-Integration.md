To get going with a custom framework, you'll want SecureHeaders to deal
directly with the framework's way of method of managing response headers.

To do this, you'll need to implement the `HttpAdapter` (don't worry, it's
only two methods!). It's located in `Aidantwoods\SecureHeaders\Http\HttpAdapter`
(or `src/Http/HttpAdapter.php` if you prefer the filepath to the namespace).

It's fairly important you read the interface description though, especially
regarding what to do with cookies (else you may lose the `SameSite` attribue)!

There may already be an implementation for what you want too, so make sure to
check the `src/Http` directory. At present, there are implementations to
work with PHPs "global" `header()` functions (the default `HttpAdapter`),
as well as for working with anything that implements PSR7's
`ResponseInterface`.

Once you've implemented your `HttpAdapter` (or found a working one),
simply provide an instance of that `HttpAdapter` to either
[`->apply`](apply) or [`->applyOnOutput`](applyOnOutput).

For example, let's say we have a `$Response` object, that implements PSR7's
`Psr\Http\Message\ResponseInterface`. We can use the
`Aidantwoods\SecureHeaders\Http\Psr7Adapter` like so (assuming `$Response`
is already defined):

```php
use Aidantwoods\SecureHeaders\Http\Psr7Adapter;
use Aidantwoods\SecureHeaders\SecureHeaders;

$Headers = new SecureHeaders;
$Headers->strictMode();

$Psr7Adapter = new Psr7Adapter($Response);

$Headers->apply($Psr7Adapter);
```

And that's it!

(Remember to look up what [`->strictMode`](strictMode) does before blindly
copy pasting that though 😉).