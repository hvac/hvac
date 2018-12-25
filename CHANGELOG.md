# Changelog

## 0.7.1 (December 19th, 2018)

IMPROVEMENTS:

* Support for the Okta auth method. [GH-341](https://github.com/hvac/hvac/pull/341)

BUG FIXES:

* Simplify redirect handling in `Adapter` class to fix issues following location headers with fully qualified URLs. Note: hvac now converts `//` to `/` within any paths. [GH-348](https://github.com/hvac/hvac/pull/348) 
* Fixed a bug where entity and group member IDs were not being passed in to Identity secrets engine group creation / updates. [GH-346](https://github.com/hvac/hvac/pull/346)
* Ensure all types of responses for the `read_health_status()` system backend method can be retrieved without exceptions being raised. [GH-347](https://github.com/hvac/hvac/pull/347)
* Fix `read_seal_status()` in `Client` class's `seal_status` property. [GH-354](https://github.com/hvac/hvac/pull/354)

DOCUMENTATION UPDATES:

* Example GCP auth method `login()` call with google-api-python-client usage added: [Example with google-api-python-client Usage](https://hvac.readthedocs.io/en/latest/usage/auth_methods/gcp.html#example-with-google-api-python-client-usage). [GH-350](https://github.com/hvac/hvac/pull/350)

MISCELLANEOUS:

* Note: Starting after release 0.7.0, `develop` is the main integration branch for the hvac project. The `master` branch is now intended to capture the state of the most recent release.
* Test cases for hvac are no longer included in the release artifacts published to PyPi. [GH-334](https://github.com/hvac/hvac/pull/334)
* The `create_or_update_policy` system backend method now supports a "pretty_print" argument for different JSON formatting. This allows create more viewable policy documents when retrieve existing policies (e.g., from within the Vault UI interface). [GH-342](https://github.com/hvac/hvac/pull/342)
* Explicit support for Vault v0.8.3 dropped. CI/CD tests updated to run against Vault v1.0.0. [GH-344](https://github.com/hvac/hvac/pull/344) 

## 0.7.0 (November 1st, 2018)

DEPRECATION NOTICES:

* All auth method classes are now accessible under the `auth` property on the `hvac.Client` class. [GH-310](https://github.com/hvac/hvac/pull/310). (E.g. the `github`, `ldap`, and `mfa` Client properties' methods are now accessible under `Client.auth.github`, etc.)
* All secrets engines classes are now accessible under the `secrets` property on the `hvac.Client` class. [GH-311](https://github.com/hvac/hvac/pull/311) (E.g. the `kv`, Client property's methods are now accessible under `Client.secrets.kv`)
* All system backend classes are now accessible under the `sys` property on the `hvac.Client` class. [GH-314](https://github.com/hvac/hvac/pull/314) ([GH-314] through [GH-325]) (E.g. methods such as `enable_secret_backend()` under the Client class are now accessible under `Client.sys.enable_secrets_engine()`, etc.)

IMPROVEMENTS:

* Support for Vault Namespaces. [GH-268](https://github.com/hvac/hvac/pull/268)
* Support for the Identity secrets engine. [GH-269](https://github.com/hvac/hvac/pull/269)
* Support for the GCP auth method. [GH-240](https://github.com/hvac/hvac/pull/240)
* Support for the Azure auth method. [GH-286](https://github.com/hvac/hvac/pull/286)
* Support for the Azure secrets engine. [GH-287](https://github.com/hvac/hvac/pull/287)
* Expanded Transit secrets engine support. [GH-303](https://github.com/hvac/hvac/pull/303)

Thanks to @tiny-dancer, @jacquat, @deejay1, @MJ111, @jasonarewhy, and @alexandernst for their lovely contributions.

## 0.6.4 (September 5th, 2018)

IMPROVEMENTS:

* New KV secret engine-related classes added. See the [KV documentation under hvac's readthedocs.io site for usage / examples](https://hvac.readthedocs.io/en/latest/usage/secrets_engines/kv.html). [GH-257](https://github.com/hvac/hvac/pull/257) / [GH-260](https://github.com/hvac/hvac/pull/260)

MISCELLANEOUS:

* Language classifiers are now being included with the distribution. [GH-247](https://github.com/hvac/hvac/pull/247)
* Token no longer being sent in URL path for the `Client.renew_token` method. [GH-250](https://github.com/hvac/hvac/pull/250)
* Support for the response structure in newer versions of Vault within the `Client.get_policy` method. [GH-254](https://github.com/hvac/hvac/pull/254)
* `config` and `plugin_name` parameters added to the `Client.enable_auth_backend` method. [GH-253](https://github.com/hvac/hvac/pull/253)

Thanks to @ijl, @rastut, @seuf, @downeast for their lovely contributions.

## 0.6.3 (August 8th, 2018)

DEPRECATION NOTICES:

* The `auth_github()` method within the `hvac.Client` class has been marked as deprecated and will be removed in hvac v0.8.0 (or later). Please update any callers of this method to use the `hvac.Client.github.login()` instead.
* The `auth_ldap()` method within the `hvac.Client` class has been marked as deprecated and will be removed in hvac v0.8.0 (or later). Please update any callers of this method to use the `hvac.Client.ldap.login()` instead.

IMPROVEMENTS:

* New Github auth method class added. See the [Github documentation for usage / examples](https://hvac.readthedocs.io/en/latest/usage/github.html). [GH-242](https://github.com/hvac/hvac/pull/242)
* New Ldap auth method class added. See the [Ldap documentation for usage / examples](https://hvac.readthedocs.io/en/latest/usage/ldap.html). [GH-244](https://github.com/hvac/hvac/pull/244)
* New Mfa auth method class added. See the [documentation for usage / examples](https://hvac.readthedocs.io/en/latest/usage/mfa.html). [GH-255](https://github.com/hvac/hvac/pull/255)
* `auth_aws_iam()` method updated to include "region" parameter for deployments in different AWS regions. [GH-243](https://github.com/hvac/hvac/pull/243)

DOCUMENTATION UPDATES:

* Additional guidance for how to configure hvac's `Client` class to leverage self-signed certificates / private CA bundles has been added at: [Making Use of Private CA](https://hvac.readthedocs.io/en/latest/advanced_usage.html#making-use-of-private-ca). [GH-230](https://github.com/hvac/hvac/pull/230)
* Docstring for `verify` `Client` parameter corrected and expanded. [GH-238](https://github.com/hvac/hvac/pull/238)

MISCELLANEOUS:

* Automated PyPi deploys via travis-ci removed. [GH-226](https://github.com/hvac/hvac/pull/226)
* Repository transferred to the new ["hvac" GitHub organization](https://github.com/hvac); thanks @ianunruh! [GH-227](https://github.com/hvac/hvac/pull/227)
* Codecov (automatic code coverage reports) added. [GH-229](https://github.com/hvac/hvac/pull/229) / [GH-228](https://github.com/hvac/hvac/pull/229)
* Tests subdirectory reorganized; now broken up by integration versus unit tests with subdirectories matching the module path for the code under test. [GH-236](https://github.com/hvac/hvac/pull/236)

Thanks to @otakup0pe, @FabianFrank, @andrewheald for their lovely contributions.

## 0.6.2 (July 19th, 2018)

BACKWARDS COMPATIBILITY NOTICE:

* With the newly added `hvac.adapters.Request` class, request kwargs can no longer be directly modified via the `_kwargs` attribute on the `Client` class. If runtime modifications to this dictionary are required, callers either need to explicitly pass in a new `adapter` instance with the desired settings via the `adapter` propery on the `Client` class *or* access the `_kwargs` property via the `adapter` property on the `Client` class.

See the [Advanced Usage](https://hvac.readthedocs.io/en/latest/advanced_usage.html#custom-requests-http-adapter) section of this module's documentation for additional details.

IMPROVEMENTS:

* sphinx documentation and [readthedocs.io project](https://hvac.readthedocs.io/en/latest/) added. [GH-222](https://github.com/hvac/hvac/pull/222)
* README.md included in setuptools metadata. [GH-222](https://github.com/hvac/hvac/pull/222)
* All `tune_secret_backend()` parameters now accepted. [GH-215](https://github.com/hvac/hvac/pull/215)
* Add `read_lease()` method [GH-218](https://github.com/hvac/hvac/pull/218)
* Added adapter module with `Request` class to abstract HTTP requests away from the `Client` class. [GH-223](https://github.com/hvac/hvac/pull/223)

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
