# Changelog

## 0.6.2 (July 19th, 2018)

BACKWARDS COMPATIBILITY NOTICE:

* With the newly added `hvac.adapters.Request` class, request kwargs can no longer be directly modified via the `_kwargs` attribute on the `Client` class. If runtime modifications to this dictionary are required, callers either need to explicitly pass in a new `adapter` instance with the desired settings via the `adapter` propery on the `Client` class *or* access the `_kwargs` property via the `adapter` property on the `Client` class.

See the [Advanced Usage](https://hvac.readthedocs.io/en/latest/advanced_usage.html#custom-requests-http-adapter) section of this module's documentation for additional details.

IMPROVEMENTS:

* sphinx documentation and [readthedocs.io project](https://hvac.readthedocs.io/en/latest/) added. [GH-222](https://github.com/ianunruh/hvac/pull/222)
* README.md included in setuptools metadata. [GH-222](https://github.com/ianunruh/hvac/pull/222)
* All `tune_secret_backend()` parameters now accepted. [GH-215](https://github.com/ianunruh/hvac/pull/215)
* Add `read_lease()` method [GH-218](https://github.com/ianunruh/hvac/pull/218)
* Added adapter module with `Request` class to abstract HTTP requests away from the `Client` class. [GH-223](https://github.com/ianunruh/hvac/pull/223)

Thanks to @bbayszczak, @jvanbrunschot-coolblue for their lovely contributions.

## 0.6.1 (July 5th, 2018)

IMPROVEMENTS:

* Update `unwrap()` method to match current Vault versions [GH-149]
* Initial support for Kubernetes authentication backend [GH-210]
* Initial support for Google Cloud Platform (GCP) authentication backend [GH-206]
* Update enable_secret_backend function to support kv version 2 [GH-201]


BUG FIXES:

* Change URL parsing to allow for routes in the base Vault address (e.g., `https://example.com/vault`) [GH-212].

Thanks to @mracter, @cdsf, @SiN, @seanmalloy, for their lovely contributions.

## 0.6.0 (June 14, 2018)

BACKWARDS COMPATIBILITY NOTICE:

* Token revocation now sends the token in the request payload. Requires Vault >0.6.5
* Various methods have new and/or re-ordered keyword arguments. Code calling these methods with positional arguments
may need to be modified.

IMPROVEMENTS:

* Ensure mount_point Parameter for All AWS EC2 Methods [GH-195]
* Add Methods for Auth Backend Tuning [GH-193]
* Customizable approle path / mount_point [GH-190]
* Add more methods for the userpass backend [GH-175]
* Add transit signature_algorithm parameter [GH-174]
* Add auth_iam_aws() method [GH-170]
* lookup_token function POST token not GET [GH-164]
* Create_role_secret_id with wrap_ttl & fix get_role_secret_id_accessor [GH-159]
* Fixed json() from dict bug and added additional arguments on auth_ec2() method [GH-157]
* Support specifying period when creating EC2 roles [GH-140]
* Added support for /sys/generate-root endpoint [GH-131] / [GH-199]
* Added "auth_cubbyhole" method [GH-119]
* Send token/accessor as a payload to avoid being logged [GH-117]
* Add AppRole delete_role method [GH-112]


BUG FIXES:

* Always Specify auth_type In create_ec2_role [GH-197]
* Fix "double parasing" of JSON response in auth_ec2 method [GH-181]

Thanks to @freimer, @ramiamar, @marcoslopes, @ianwestcott, @marc-sensenich, @sunghyun-lee, @jnaulty, @sijis,
@Myles-Steinhauser-Bose, @oxmane, @ltm, @bchannak, @tkinz27, @crmulliner, for their lovely contributions.

## 0.5.0 (February 20, 2018)

IMPROVEMENTS:

* Added `disallowed_policies` parameter to `create_token_role` method [GH-169]

Thanks to @morganda for their lovely contribution.

## 0.4.0 (February 1, 2018)

IMPROVEMENTS:

* Add support for the `period` parameter on token creation [GH-167]
* Add support for the `cidr_list` parameter for approle secrets [GH-114]

BUG FIXES:

* Documentation is now more accurate [GH-165] / [GH-154]

Thanks to @ti-mo, @dhoeric, @RAbraham, @lhdumittan, @ahsanali for
their lovely contributions.

## 0.3.0 (November 9, 2017)

This is just the highlights, there have been a bunch of changes!

IMPROVEVEMENTS:

* Some AppRole support [GH-77]
* Response Wrapping [GH-85]
* AWS EC2 stuff [GH-107], [GH-109]

BUG FIXES

* Better handling of various error states [GH-79], [GH-125]

Thanks to @ianwestcott, @s3u, @mracter, @intgr, @jkdihenkar, @gaelL,
@henriquegemignani, @bfeeser, @nicr9, @mwielgoszewski, @mtougeron
for their contributions!

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
