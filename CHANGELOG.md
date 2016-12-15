## 0.2.17 (December 15, 2016)

IMPROVEMENTS:

* Add token role support [GH-94]
* Add support for Python 2.6 [GH-92]
* Allow setting the explicit_max_ttl when creating a token [GH-81]
* Add support for write response wrapping [GH-85]

BUG FIXES:

* Fix app role endpoints for newer versions of Vault [GH-93]

## 0.2.16 (September 12, 2016)

Thanks to @otakup0pe, @nicr9, @marcoslopes, @caiotomazelli,
and @blarghmatey for their contributions!

IMPROVEMENTS:

* Add EC2 auth support [GH-61]
* Add support for token accessors [GH-69]
* Add support for response wrapping [GH-70]
* Add AppRole auth support [GH-77]

BUG FIXES:

* Fix `no_default_policy` parameter in `create_token` [GH-65]
* Fix EC2 auth double JSON parsing [GH-76]

## 0.2.15 (June 22nd, 2016)

Thanks to @blarghmatey, @stevenmanton, and @ahlinc for their contributions!

IMPROVEMENTS:

* Add methods for manipulating app/user IDs [GH-62]
* Add ability to automatically parse policies with pyhcl [GH-58]
* Add TTL option to `create_userpass` [GH-60]
* Add support for backing up keys on rekey [GH-57]
* Handle non-JSON error responses correctly [GH-46]

BUG FIXES:

* `is_authenticated` now handles new error type for Vault 0.6.0

## 0.2.14 (June 2nd, 2016)

BUG FIXES:

* Fix improper URL being used when leader redirection occurs [GH-56]

## 0.2.13 (May 31st, 2016)

IMPROVEMENTS:

* Add support for Requests sessions [GH-53]

BUG FIXES:

* Properly handle redirects from Vault server [GH-51]

## 0.2.12 (May 12th, 2016)

IMPROVEMENTS:

* Add support for `increment` in renewel of secret [GH-48]

BUG FIXES:

* Use unicode literals when constructing URLs [GH-50]

## 0.2.10 (April 8th, 2016)

IMPROVEMENTS:

* Add support for list operation [GH-47]

## 0.2.9 (March 18th, 2016)

IMPROVEMENTS:

* Add support for nonce during rekey operation [GH-42]
* Add get method for policies [GH-43]
* Add delete method for userpass auth backend [GH-45]
* Add support for response to rekey init

## 0.2.8 (February 2nd, 2016)

IMPROVEMENTS:

* Convenience methods for managing userpass and app-id entries
* Support for new API changes in Vault v0.4.0

## 0.2.7 (December 16th, 2015)

IMPROVEMENTS:

* Add support for PGP keys when rekeying [GH-28]

BUG FIXES:

* Fixed token metadata parameter [GH-27]

## 0.2.6 (October 30th, 2015)

IMPROVEMENTS:

* Add support for `revoke-self`
* Restrict `requests` dependency to modern version

## 0.2.5 (September 29th, 2015)

IMPROVEMENTS:

* Add support for API changes/additions in Vault v0.3.0

    * Tunable config on secret backends
    * MFA on username/password and LDAP auth backends
    * PGP encryption for unseal keys

## 0.2.4 (July 23rd, 2015)

BUG FIXES:

* Fix write response handling [GH-19]

## 0.2.3 (July 18th, 2015)

BUG FIXES

* Fix error handling for next Vault release

IMPROVEMENTS:

* Add support for rekey/rotate APIs

## 0.2.2 (June 12th, 2015)

BUG FIXES:

* Restrict `requests` dependency to 2.5.0 or later

IMPROVEMENTS:

* Return latest seal status from `unseal_multi`

## 0.2.1 (June 3rd, 2015)

BUG FIXES:

* Use arguments passed to `initialize` method

## 0.2.0 (May 25th, 2015)

BACKWARDS COMPATIBILITY NOTICE:

* Requires Vault 0.1.2 or later for `X-Vault-Token` header
* `auth_token` method removed in favor of `token` property
* `read` method no longer raises `hvac.exceptions.InvalidPath` on nonexistent paths

IMPROVEMENTS:

* Tolerate falsey URL in client constructor
* Add ability to auth without changing to new token
* Add `is_authenticated` convenience method
* Return `None` when reading nonexistent path

## 0.1.1 (May 20th, 2015)

IMPROVEMENTS:

* Add `is_sealed` convenience method
* Add `unseal_multi` convenience method

BUG FIXES:

* Remove secret_shares argument from `unseal` method

## 0.1.0 (May 17th, 2015)

* Initial release
