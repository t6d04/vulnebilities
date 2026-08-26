# Host header poisoning in the password reset flow leads to account takeover in `lavalite/cms`

## Package

- Ecosystem: Composer
- Package name: `lavalite/cms`

## Severity

- High
- CVSS v3.1: `8.1`
- Vector: `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N`

## Affected versions

- `10.x`
- Confirmed on repository `master` at commit `6b281860c480035b54d0a33eb686cf9977b0f634`

## Patched versions

- None known as of August 26, 2026

## Description

`lavalite/cms` exposes password reset endpoints under guard-scoped public routes such as `/admin/forgot-password`. The application disables Laravel's `TrustHosts` middleware in the default HTTP middleware stack and uses a custom password reset notification that generates absolute reset URLs from the current request origin via `url(route(..., false))`.

Because the reset URL origin is derived from the live request and unexpected `Host` headers are not rejected at the application layer, a remote attacker can submit a password reset request with an attacker-controlled `Host` header. The victim then receives a poisoned password reset email pointing to the attacker's domain. If the victim follows the link, the attacker can capture the valid reset token and use it against the legitimate application to reset the victim's password.

The issue affects administrator accounts as well because the `admin` guard uses the same `users` provider as the default user guard.

## Impact

A remote unauthenticated attacker can achieve full account takeover for accounts using the `users` provider, including administrator accounts, if the attacker knows the victim's email address and the victim clicks the poisoned reset link.

## Technical details

The bug is caused by a code path that combines three behaviors:

1. the application exposes password reset endpoints under guard-scoped public routes
2. the application does not enforce trusted-host validation in the HTTP middleware stack
3. the custom password reset notification generates an absolute URL from the current request origin

Those three pieces together create a host header poisoning issue in a security-sensitive flow.

### 1. Guard-scoped public password reset routes

In `routes/web.php`, the application mounts shared authentication routes under a dynamic `/{guard}` prefix for every configured guard. That means the same auth flow exists under paths such as:

- `/user/...`
- `/admin/...`
- `/client/...`

Inside that shared route file, `routes/auth.php` exposes the password reset request endpoint to unauthenticated users:

```php
Route::post('forgot-password', [PasswordResetLinkController::class, 'store'])
    ->name('password.email');
```

This is the public entrypoint. An attacker can directly invoke `/admin/forgot-password` without authentication.

### 2. The request guard is derived from the URL path

The guard-specific route group is paired with middleware that derives the active guard from the request path. In practice, a request to `/admin/forgot-password` executes in the `admin` guard context.

This matters because the later reset URL generation logic includes the current guard in the final reset path. The guard is not just cosmetic routing; it becomes part of the password reset link delivered to the victim.

### 3. Trusted host validation is disabled

In `app/Http/Kernel.php`, the global middleware stack leaves Laravel's host validation middleware disabled:

```php
protected $middleware = [
    // \App\Http\Middleware\TrustHosts::class,
    \App\Http\Middleware\TrustProxies::class,
    ...
];
```

Laravel provides `TrustHosts` specifically to reject requests whose `Host` header does not match the application's expected host patterns. Because it is disabled here, the application accepts attacker-controlled `Host` values at the application layer.

This is a critical part of the vulnerability. If the application rejects untrusted hosts before any URL generation occurs, the poisoning attempt fails early. Here, that protection is not active.

### 4. The password reset controller forwards the live request context into the reset flow

`app/Http/Controllers/Auth/PasswordResetLinkController.php` handles the public forgot-password request and passes it into Laravel's password broker:

```php
$status = Password::sendResetLink(
    $request->only('email')
);
```

On its own, this line is normal. The issue is that the downstream reset-link generation still occurs while the application is operating on the attacker-controlled HTTP request context, including the untrusted `Host` header.

### 5. The local user model uses a custom reset notification

The local `App\Models\User` model includes:

```php
use Litepie\User\Traits\CanResetPassword;
```

That trait overrides the reset notification dispatch path:

```php
public function sendPasswordResetNotification($token)
{
    $this->notify(new ResetPasswordNotification($token));
}
```

So the application does not rely solely on a default framework notification path. It explicitly routes password reset emails through Lavalite's custom notification class.

### 6. The custom notification builds the reset link from the current request origin

The core flaw is in `vendor/lavalite/framework/src/Litepie/User/Notifications/ResetPassword.php`:

```php
return url(route('guard.password.reset', [
    'token' => $this->token,
    'email' => $notifiable->getEmailForPasswordReset(),
    'guard' => current(explode('.', guard())),
], false));
```

This line has two important parts.

First:

```php
route('guard.password.reset', ..., false)
```

Using `false` here tells Laravel to generate a relative path, not a fully-qualified URL. The output is effectively a path like:

```text
/admin/reset-password/<token>?email=admin@target.example
```

Second:

```php
url(...)
```

`url()` takes that relative path and turns it into a fully-qualified absolute URL. To do that, Laravel needs a root origin such as:

```text
https://target.example
```

If no trusted canonical root is forced, Laravel derives that root from the current request. In this case, that means it can derive the host from the inbound `Host` header.

As a result, if the attacker sends:

```http
Host: attacker.example
```

the generated email link can become:

```text
https://attacker.example/admin/reset-password/<token>?email=admin%40target.example
```

That is the direct vulnerability.

### 7. Why the bug reaches administrator accounts

In `config/auth.php`, the `admin` guard uses the same `users` provider as the default user guard. That means administrative identities are part of the same password reset surface handled by this flow.

So the attack is not limited to low-privilege self-service accounts. If the attacker knows the email address of an administrator, the same poisoned reset flow can be used to capture that administrator's reset token and take over the account.

### 8. End-to-end exploitation flow

The full code-driven exploitation sequence is:

1. The attacker sends `POST /admin/forgot-password` with a chosen `Host` header.
2. The request is accepted because the route is public and `TrustHosts` is disabled.
3. The controller calls `Password::sendResetLink(...)`.
4. The `User` model dispatches Lavalite's custom reset notification.
5. The notification generates a reset path for the active `admin` guard.
6. `url(...)` converts that path into an absolute URL using the attacker-controlled request origin.
7. The victim receives an email pointing to the attacker's domain.
8. When the victim clicks the link, the attacker captures the valid reset token.
9. The attacker submits the captured token to the legitimate `/admin/reset-password` endpoint and sets a new password.

### 9. Why this is an application vulnerability, not only a deployment issue

This issue should not be dismissed as purely environmental.

The audited codebase itself contributes the vulnerability by:

- shipping with `TrustHosts` disabled in the default middleware stack
- using a custom notification that generates security-sensitive links from request-derived origin data
- exposing the reset flow under public guard-scoped routes, including the admin namespace

An upstream proxy or load balancer may reduce exploitability in some deployments if it strictly rewrites or validates `Host`, but that is only a partial environmental mitigation. The application code, as audited, contains the vulnerable behavior.

## Proof of concept

An attacker sends:

```http
POST /admin/forgot-password HTTP/1.1
Host: attacker.example
Content-Type: application/x-www-form-urlencoded

email=admin%40target.example
```

The victim receives a password reset email containing a link similar to:

```text
https://attacker.example/admin/reset-password/<token>?email=admin%40target.example
```

After the victim clicks the link and the attacker captures `<token>`, the attacker resets the password on the legitimate host:

```http
POST /admin/reset-password HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded

token=<captured-token>&email=admin%40target.example&password=NewStrongPassword123!&password_confirmation=NewStrongPassword123!
```

The attacker can then authenticate as the victim.

## Remediation

- Re-enable `\App\Http\Middleware\TrustHosts::class` in `app/Http/Kernel.php`.
- Generate password reset URLs from a trusted canonical application origin rather than the incoming request host.
- If a custom reset notification is retained, use a fixed trusted URL callback or equivalent canonical URL generation.
- Preserve guard-specific path handling if needed, but do not derive the URL origin from untrusted request metadata.

## Workarounds

If a full patch is not yet available:

- Enable `TrustHosts` in the application middleware stack.
- Enforce strict host validation at the reverse proxy or load balancer.
- Override the custom password reset notification so reset links always use the canonical application origin.
- If operationally acceptable, temporarily disable password reset flows for internet-exposed admin accounts until patched.

## References

Affected paths in `lavalite/cms`:

- `routes/web.php`
- `routes/auth.php`
- `app/Http/Kernel.php`
- `app/Http/Controllers/Auth/PasswordResetLinkController.php`
- `app/Models/User.php`
- `config/auth.php`

Affected dependency paths used in the verified chain:

- `vendor/lavalite/framework/src/Litepie/User/Traits/CanResetPassword.php`
- `vendor/lavalite/framework/src/Litepie/User/Notifications/ResetPassword.php`

## Credits

Reported by: `t6d`
