# Changelog

## 1.2.0

This is the last expected release before `v2.0.0`.

### 📢 Deprecations / Announcements

- ldap auth method - add missing `configure` params by vault api names ([GH-975](https://github.com/hvac/hvac/pull/975))
- expand Vault CI matrix, announce deprecation of Vault dynamic SSH keys ([GH-1023](https://github.com/hvac/hvac/pull/1023))
- Breaking changes coming to `Client.write` method ([GH-1034](https://github.com/hvac/hvac/issues/1034))
- Support for Python 3.6 & 3.7 will be dropped in `v2.0.0` ([GH-877](https://github.com/hvac/hvac/issues/877))
- Support for the Legacy MFA methods will be dropped from the `MFA` class in `v2.0.0` ([GH-1026](https://github.com/hvac/hvac/issues/1026))
- Breaking changes coming to Adapters' use of custom sessions ([GH-1040](https://github.com/hvac/hvac/issues/1040))

### 🚀 Features

- Add alias_name_source for Kubernetes Auth create_role ([GH-1039](https://github.com/hvac/hvac/pull/1039))
- add `Client.write_data` method ([GH-1028](https://github.com/hvac/hvac/pull/1028))
- ldap auth method - add missing `configure` params by vault api names ([GH-975](https://github.com/hvac/hvac/pull/975))
- Re-add arguments to create_or_update_role() from old API ([GH-842](https://github.com/hvac/hvac/pull/842))
- Add new argument (conflicting_alias_ids_to_keep) to merge_entities method ([GH-968](https://github.com/hvac/hvac/pull/968))
- Add impersonated account support to GCP secrets engine ([GH-1022](https://github.com/hvac/hvac/pull/1022))
- support "user_claim_json_pointer" in create_role() for JWT/OIDC auth method ([GH-1006](https://github.com/hvac/hvac/pull/1006))
- Add static account support to GCP secrets engine ([GH-956](https://github.com/hvac/hvac/pull/956))
- adding batch_input to transit.sign_data #988 ([GH-990](https://github.com/hvac/hvac/pull/990))
- Add a method to read static roles in the database engine ([GH-1009](https://github.com/hvac/hvac/pull/1009))
- feat: add support for `disable_local_ca_jwt` in the Kubernetes auth method ([GH-997](https://github.com/hvac/hvac/pull/997))

### 🐛 Bug Fixes

- add `Client.write_data` method ([GH-1028](https://github.com/hvac/hvac/pull/1028))
- Fix premature read on stream requests in the `sys.take_raft_snapshot` method ([GH-771](https://github.com/hvac/hvac/pull/771))
- fix(`__getattr__`): non-existent attribute lookup ([GH-982](https://github.com/hvac/hvac/pull/982))

### 📚 Documentation

- docs(secrets-engines): Add database secrets engine docs ([GH-1036](https://github.com/hvac/hvac/pull/1036))
- docs: make OIDC Authorization URL Request example work again. ([GH-1010](https://github.com/hvac/hvac/pull/1010))

### 🧰 Miscellaneous

- add tests and docs to sdist, improve build testing ([GH-1015](https://github.com/hvac/hvac/pull/1015))
- Bump certifi from 2022.9.14 to 2022.12.7 ([GH-1013](https://github.com/hvac/hvac/pull/1013))

## 1.1.1

### 🐛 Bug Fixes

- fix wrapped response for `auth.token.create` ([GH-966](https://github.com/hvac/hvac/pull/966))

## 1.1.0

### 📢 Deprecations / Announcements

- [`v3.0.0`](https://github.com/hvac/hvac/milestone/36) - The `certificate` parameter for `create_ca_certificate_role` will stop accepting file paths ([GH-914](https://github.com/hvac/hvac/pull/914))
- Please note that `hvac` intends to drop support for EoL Python versions ([GH-877](https://github.com/hvac/hvac/pull/877))
- [`v3.0.0`](https://github.com/hvac/hvac/milestone/36) - The default value of `raise_on_deleted_version` will change from `True` to `False` ([GH-955](https://github.com/hvac/hvac/issues/955))
- Allow for reading deleted secret versions (kv2) without an exception ([GH-907](https://github.com/hvac/hvac/pull/907))

### 🚀 Features

- Allow for reading deleted secret versions (kv2) without an exception ([GH-907](https://github.com/hvac/hvac/pull/907))
- AWS secret engine - fix `generate_credentials` for STS endpoint ([GH-934](https://github.com/hvac/hvac/pull/934))
- Add support for custom metadata in kv2 engine ([GH-805](https://github.com/hvac/hvac/pull/805))
- Add new field `auto_rotate_period` on transit key management ([GH-903](https://github.com/hvac/hvac/pull/903))

### 🐛 Bug Fixes

- Allow for reading deleted secret versions (kv2) without an exception ([GH-907](https://github.com/hvac/hvac/pull/907))
- fix vault client certificates loaded from envirnoment variables ([GH-943](https://github.com/hvac/hvac/pull/943))
- approle - fix metadata for generated secret IDs, re-add `wrap_ttl` ([GH-782](https://github.com/hvac/hvac/pull/782))
- AWS secret engine - fix `generate_credentials` for STS endpoint ([GH-934](https://github.com/hvac/hvac/pull/934))
- Propagate client's adapter to API categories ([GH-939](https://github.com/hvac/hvac/pull/939))
- don't cache on py3.6 windows combo ([GH-916](https://github.com/hvac/hvac/pull/916))
- Cert: Fix role certificate parameter ([GH-886](https://github.com/hvac/hvac/pull/886))

### 📚 Documentation

- add documentation for retries ([GH-948](https://github.com/hvac/hvac/pull/948))
- docs - sphinx - fail on warnings ([GH-949](https://github.com/hvac/hvac/pull/949))
- Create userpass.rst ([GH-775](https://github.com/hvac/hvac/pull/775))
- doc: update reference to removed method ([GH-942](https://github.com/hvac/hvac/pull/942))
- Documentation updates for use with a private CA ([GH-774](https://github.com/hvac/hvac/pull/774))
- Update Azure guideline with proper client variable ([GH-935](https://github.com/hvac/hvac/pull/935))
- Update wrapping.rst - example for unauthenticated unwrap ([GH-789](https://github.com/hvac/hvac/pull/789))
- Fix typo in the AWS auth method docs ([GH-911](https://github.com/hvac/hvac/pull/911))
- Replace Azure docs occurence to Kubernetes ([GH-904](https://github.com/hvac/hvac/pull/904))

### 🧰 Miscellaneous

- Remove deprecated python syntax ([GH-909](https://github.com/hvac/hvac/pull/909))

## 1.0.2

- Update dependencies. GH-897

## 1.0.1

### 🐛 Bug Fixes

- Add `role_name` parameter to `auth.token.create_orphan`. GH-891
- docs: Add RTD config. GH-894

### 📚 Documentation

- docs: Add RTD config. GH-894

## 1.0.0

- CI: Update Vault versions for integration tests. GH-884
- Tests: Handle 204 response in jwt test. GH-881
- Tests: Fix kubernetes integration test. GH-880
- Tests: Fix broken oidc test. GH-879
- Tests: Fix Azure test failure. GH-878
- Tests: Handle different response due to upstream change. GH-876
- Tests: Fix Github auth tests. GH-875
- Test utils: Fix OTP length for Vault >=1.10.0. GH-872
- Test utils: Migrate to packaging module's Version. GH-871
- Integration Tests: Fix GCP test error. GH-870
- build-test: Fix windows job. GH-845
- build-test: Add test. GH-844
- Bump version: 0.11.2 → 1.0.0. GH-829

### 💥 Breaking Changes

- Legacy MFA: Move mfa authentication method to legacy MFA method. GH-883
- Remove deprecated methods. GH-868
- Remove redundant code for Python <= 3.5. GH-822
- Drop Python 2 and EOL Python 3 versions. GH-819

### 🚀 Features

- Token: Add create orphaned token method. GH-869
- Allow configuring the possible salt lengths for RSA PSS signatures. GH-846
- ssh: Add secret engine. GH-811

### 🐛 Bug Fixes

- setup.py: Add encoding for long_description. GH-843
- Don't override user warning filters. GH-818

### 📚 Documentation

- Migrate to Poetry. GH-854
- docs(auth-methods): update kubernetes. GH-837
- README: Remove help wanted note. GH-848
- Update kubernetes authentication example. GH-827

### 🧰 Miscellaneous

- .gitignore: Add vscode config directory. GH-867
- Add stock version-resolver cfg for release-drafter. GH-836
- Release drafter tweaks. GH-835
- Add commitish to release-drafter.yml. GH-832
- Bump dependencies. GH-826
- Readding 3.6 support. GH-823
- Add support for Python 3.10. GH-821
- Fix CI. GH-812

## 0.11.2 (September 23rd, 2021)

Breakfix release to revert some unintended post-1.0 requirements changes.

### 🐛 Bug Fixes

- Revert `six` & `requests` Requirements Changes. GH-768

## 0.11.1 (September 22nd, 2021)

### 💥 Breaking Changes

- **Note**: This is _actually and truly_ (😝)  intended to by the last hvac release supporting Python 2.7.

  **Starting with hvac version `1.0.0`, Python versions `>=3.6` will be the only explictly supported versions.**
- Requirements - Cleanup & Upgrades (`install_requires` => `requests>=2.25.1` ). GH-741

### 🚀 Features

- Add X-Vault-Request header to all requests by default. GH-762
- Add token_type to kubernetes auth create_role. GH-760
- jwt: use login adapter and add `use_token` param. GH-746

### 🐛 Bug Fixes

- Fix Passing of `cert` Parameter From Client into Adapter Class. GH-743
- Removed vestigial accessor parameter from auth token revoke_self. GH-744
- Fix Client TLS `verify` Behavior . GH-745
- Fix incorrect recovery key backup path. GH-749

Thanks to @Tylerlhess, @anhdat, @ayav09, @bobmshannon, @bpatterson971, @briantist, @cmanfre4, @jeffwecan, Chris Manfre and tyhess for their lovely contributions.

## 0.11.0 (July 12th, 2021)

### 💥 Breaking Changes

- **Note**: This is intended to by the last hvac release supporting Python 2.7.

  **Starting with hvac version `1.0.0`, Python versions `>=3.6` will be the only explictly supported versions.**
- Userpass: Add `use_token` param on `login()`, Accept passthrough `**kwargs` on create user . GH-733

### 🚀 Features

- Support CA-related Environment Variables. GH-735
- Migrate Token Auth Methods to Dedicated Class. GH-734
- Allow Omission of Password Argument on Userpass `create_or_update_user()`. GH-714
- Add `token_ttl` & `token_max_ttl` Arguments to `ldap.configure()`. GH-707

### 🐛 Bug Fixes

- Fix Cert.login() handling of use_token argument. GH-720
- Use PUTs for AWS Secrets Engine STS Requests. GH-718

### 🧰 Miscellaneous

- Add deprecation notices for `Client()` k8s methods. GH-732
- Add deprecation notices for `Client()` approle methods. GH-731
- Deprecate AppID-related `Client()` Methods. GH-730
- Update Deprecated Usage In Documentation & Tests. GH-728
- Add `python_requires='>=2.7'` to setuptools Metadata. GH-727
- Transition to `black` Formatting + Updated PR Actions Workflow. GH-726

Thanks to @el-deano, @intgr, @jeffwecan, @pjaudiomv, @tp6783 and tyhess for their lovely contributions.

## 0.10.14 (May 21st, 2021)

### 🐛 Bug Fixes

- Python 2.7: Drop Trailing Comma In `Cert.login()`. GH-712

## 0.10.13 (May 20th, 2021)

### 🐛 Bug Fixes

- Refactor `Cert.login()` Conditional for Python 2.7 Syntax Support. GH-708

## 0.10.12 (May 19th, 2021)

### 🚀 Features

- Add default to `group_type` argument in `update_group` and `create_or_update_group_by_name`. GH-703
- Add Certificate Authentication Methods. GH-691

Thanks to @Tylerlhess, @jeffwecan, @matusf, @mblau-leaffilter and tyhess for their lovely contributions.

## 0.10.11 (May 7th, 2021)

### 🚀 Features

- Expand Transform class to include new(ish) tokenization methods. GH-696
- Add `delete_version_after` KvV2 Param - `configure()` / `update_metadata()`. GH-694

### 🧰 Miscellaneous

- Bump versions of Vault used in CI workflows. GH-695

Thanks to @jeffwecan for their lovely contributions.

## 0.10.10 (April 29th, 2021)

### 🚀 Features

- AWS Secrets Engine: Add support for iam_tags when creating roles. GH-684
- Add Active Directory generate credential capability. GH-657
- Add `policies` Parameter to Userpass `create_or_update_user()` Method. GH-562
- Add handling of unsupported HTTP methods inside adapter. GH-689
- Add Convenience `read_secret()` Method for KVv2 Class. GH-686

### 🧰 Miscellaneous

- Set daemon attribute instead of using setDaemon method that was deprecated in Python 3.10. GH-688

Thanks to @jeffwecan, @mblau-leaffilter, @nicholaswold, @sshishov, @tirkarthi, @tomwerneruk and @vamshideveloper for their lovely contributions.

## 0.10.9 (April 2nd, 2021)

### 🐛 Bug Fixes

- Send AppRole generate_secret_id Method Metadata Parameter as String GH-689

### 📚 Documentation

- Fix lambda authentication example in aws auth documentation. GH-675
- Docs(secret_engines/pki): Remove 'self' from examples. GH-676

Thanks to @JPoser, @fhemberger, @jeffwecan, @lperdereau and jposer for their lovely contributions.

## 0.10.8 (February 8th, 2021)

### 🚀 Features

- K8s Auth: Allow wildcards for service account and namespace. GH-669
- Add token_type support to create_kubernetes_role. GH-664

## 0.10.7 (February 1st, 2021)

### 🚀 Features

- Support database secrets static roles. GH-662

### 🧰 Miscellaneous

- Replace Travis CI w/ GitHub actions. GH-666

Thanks to @jeffwecan, @krish7919 and Krish for their lovely contributions.

## 0.10.6 (December 14th, 2020)

### 🚀 Features

- Enable response wrapping of PKI secrets. GH-649
- Fix OIDC login and add working example. GH-638
- Add rabbitmq vhost_topics parameter. GH-626
- Expand auth_methods module to support AppRole. GH-637

### 🐛 Bug Fixes

- Template "auth method not implemented" error message. GH-651
- Fix health.py read_health_status GET method. GH-653
- Fix transit constants for "generate_data_key". GH-632
- Fix PUT method in secrets engine kv_v1 to use PUT instead of POST. GH-629
- Remove Erroneous json() Calls In rabbitmq Class. GH-624

### 🧰 Miscellaneous

- Update health.py to match new Vault API query parameters. GH-635
- Remove Consul Secrets Engine create_or_update_role Policy Type Validation. GH-636

Thanks to @Angeall, @JJCella, @briantist, @derBroBro, @discogestalt, @dogfish182, @el-deano, @ghTravis, @godara01, @jeffwecan, @leongyh, @phickey, @tienthanh2509 and @tmcolby for their lovely contributions.

## 0.10.5 (July 26th, 2020)

### 🚀 Features

- Add JWT/OIDC Authentication Method Classes. GH-613
- Add Identity Tokens Methods and Documentation. GH-611
- Add P-521 to list of allowed key types. GH-608
- Add P-384 and RSA-3072 to list of allowed key types. GH-606

### 🐛 Bug Fixes

- Options not read by tune_mount_configuration. GH-603

### 📚 Documentation

- Add Autodoc Summaries. GH-612
- Correct Return Type Docstrings Within Transit Class. GH-609
- Transit engine docs for Encrypt Data now refer to encrypt_data. GH-601

### 🧰 Miscellaneous

- Update Vault version test matrix / Oldest Support Vault Version. GH-610

Thanks to @akdor1154, @jeffwecan, @ns-jshilkaitis and @trishankatdatadog for their lovely contributions.

## 0.10.4 (June 16th, 2020)

### 🚀 Features

- Extract "renew_self_token" from "renew_token". GH-598
- Add convenience step_down sys backend method. GH-597

### 📚 Documentation

- Update AWS Auth Docs With Latest Usage . GH-599

Thanks to @jeffwecan, @jm96441n and @pnijhara for their lovely contributions.

## 0.10.3 (May 24th, 2020)

### 🚀 Features

- Add Support For use_token_groups In LDAP Auth Method. GH-591
- Add Raft System Backend Methods. GH-594

Thanks to @finarfin and @jeffwecan for their lovely contributions.

## 0.10.2 (May 19th, 2020)

### 🚀 Features

- Create_role_secret_id: add token_bound_cidrs parameter. GH-585
- Add vault rekey verification methods. GH-586
- Add request data to exception objects. GH-583
- Add marshaling_algorithm to sign/verify params. GH-584
- Add issuer to kubernetes configuration. GH-575

### 🐛 Bug Fixes

- Remove json() calls (unneeded following JSONAdapter addition) GH-589

### 📚 Documentation

- Fix format errors in contributing for HTML docs. GH-577

Thanks to @TerryHowe, @and-semakin, @jeffwecan, @jschlyter, @jzck, @mdelaney and @scarabeusiv for their lovely contributions.

## 0.10.1 (April 7th, 2020)

### 💥 Breaking Changes

- Make returned responses more consistent. GH-537

*Note*: [GH-537](https://github.com/hvac/hvac/pull/537) changes some methods' return types from None to a request.Response
instance. For instance the `client.secrets.identity.lookup_entity` now returns a Response[204] (truthy) value instead of
None (falsy) when the lookup returns no results.
This change was made to simplify maintenance of response parsing within the hvac code base.

### 🚀 Features
- Add support for Transform secrets engine. GH-569

### 🐛 Bug Fixes

- Fix "Exception: member entities can't be set manually for external groups". GH-558

Thanks to @jeffwecan, @llamasoft and @msuszko for their lovely contributions.

## 0.10.0 (February 26th, 2020)

### 🚀 Features
- Add a correct endpoint for CRL retrieving . GH-547

### 📚 Documentation

- Fixes close quotes in example usage of read_secret_version. GH-557
- Fixes typo in docs: much -> must. GH-555

### 🧰 Miscellaneous

- Don't send optional parameters unless explicitly specified. GH-533

*Note*: [GH-533](https://github.com/hvac/hvac/pull/533) includes fundamental behavior involving sending parameters
to API requests to Vault. Many hvac method parameters that would have been sent with default arguments no
longer are included in requests to Vault. Notably, the following behavioral changes should be expected (copied from the
related PR comments):

Azure:
  - CHANGED: `create_role` parameter `policies` now accepts CSV string or list of strings

Database:
  - CHANGED: `create_role` documentation updated to something meaningful 🙃

GCP:
  - `configure` parameter `google_certs_endpoint` is deprecated
  - `create_role` parameter `project_id` is deprecated by `bound_projects` (list)

GitHub:
  - `configure` is missing a lot of parameters

LDAP:
  - CHANGED: `configure` parameters `user_dn` and `group_dn` made optional
    - Retained argument position to prevent being a breaking change
  - CHANGED: `hvac/constants/ldap.py` file removed as it is no longer used

MFA:
  - This entire endpoint is deprecated so I didn't bother updating it

Okta:
  - CHANGED: `configure` parameter `base_url` default value now differs from API documentation
    - This is likely just a [documentation issue](https://github.com/hashicorp/vault/issues/7653)
  - `register_user`, `read_user`, and `delete_user` duplicate URL parameter `username` in JSON payload
    - I left this one as-is as it doesn't appear to hurt anything
  - Ditto for `delete_group`, but `register_group` and `list_group` correctly omit it

PKI:
  - CHANGED: `sign_data` and `verify_signed_data` optional parameter `marshaling_algorithm` added

RADIUS:
  - `configure` is missing a lot of parameters
  - BUG: `register_user` attempted to convert `username` string into a CSV list (?!) for POST data
    - Didn't hurt anything as `username` is extracted from URL path in Vault server
  - BUG: `register_user` parameter `policies` never actually passed as parameter

System Backend:
  - Auth
    - `enable_auth_method` parameter `plugin_name` is deprecated
    - CHANGED: `enable_audit_device` optional parameter `local` was added
  - Init
    - `initialize` provides default for required API parameters `secret_shares` and `secret_threshold`
  - Key
    - `start_root_token_generation` parameter `otp` is deprecated

**Misc:**
  - There seems to be some discrepancy on how "extra arguments" are accepted:
    - Some methods use only `**kwargs` (e.g. `hvac/api/system_backend/auth.py`)
    - Some use `*args` and `**kwargs` (e.g. `hvac/api/secrets_engines/active_directory.py`)
    - `hvac/api/secrets_engines/pki.py` uses `extra_params={}`
  - Most argument names match API parameter names, but some don't
    - Example: `hvac/api/auth_methods/ldap.py` `configure` uses `user_dn` instead of `userdn`
    - Example: `hvac/api/system_backend/auth.py` `configure` uses `method_type` instead of `type`
  - Many methods duplicate URL parameters into JSON payload as well
    - This isn't necessary and fortunately Vault ignores the extra parameters
  - `ttl`, `max_ttl`, `policies`, `period`, `num_uses` and a few other fields are deprecated as of Vault version 1.2.0
    - https://github.com/hashicorp/vault/blob/master/CHANGELOG.md#120-july-30th-2019

Thanks to @findmyname666, @llamasoft, @moisesguimaraes, @philherbert and Adrian Eib for their lovely contributions.


## 0.9.6 (November 20th, 2019)

### 🚀 Features

- Added userpass auth method. GH-519
- added rabbitmq secrets backend. GH-540
- Quote/Escape all URL placeholders. GH-532

### 📚 Documentation

- Getting Started Guide and LDAP Auth Updates. GH-524

### 🧰 Miscellaneous

- Handle bad gateway from Vault. GH-542
- Fix GET/LIST typos. GH-536
- Fix Travis HEAD build + Overhaul install scripts. GH-535
- Improve Integration Test Error Handling. GH-531

Thanks to @DaveDeCaprio, @Dowwie, @drewmullen, @jeffwecan, @llamasoft and @vamshideveloper for their lovely contributions.

## 0.9.5 (July 19th, 2019)

### 🚀 Features

- Add Active Directory Secrets Engine Support. GH-508

### 📚 Documentation

- Include Recently Added Namespace Documentation In Toctree. GH-509

Thanks to @jeffwecan and @vamshideveloper for their lovely contributions.

## 0.9.4 (July 18th, 2019)

### 🚀 Features

- Add delete_namespace Method and Establish Namespace Documentation. GH-500

### 🐛 Bug Fixes

- Fix consul configure_access/create_or_update_role Method Return Values. GH-502

### 📚 Documentation

- Fix Database generate_credentials Docstring Params. GH-498

### 🧰 Miscellaneous

- Add config for updatedocs app. GH-495
- Add a Codeowners file for automatic reviewer assignments. GH-494

Thanks to @Tylerlhess, @drewmullen and @jeffwecan for their lovely contributions.


## 0.9.3 (July 7th, 2019)

### 🚀 Features

- Add Create and List Namespace System Backend Methods. GH-489
- Expanded Support for AWS Auth Method. GH-482
- Capabilities System Backend Support. GH-476

### 🐛 Bug Fixes

- GCP Auth Test Case Updates For Changes in Vault v1.1.1+. GH-487
- Change AWS `generate_credentials` request method to GET. GH-475

### 📚 Documentation

- Numerous Fixes and Doctest Support for Transit Secrets Engine. GH-486

### 🧰 Miscellaneous

- Start Using Enterprise (Trial) Version of Vault For Travis CI Builds. GH-478
- Update Travis CI Test Matrix With Latest Vault Version & Drop Python 3.6. GH-488
- Set up release-drafter / _mostly_ automated releases. GH-485

Thanks to @donjar, @fhemberger, @jeffwecan, @stevefranks and @stevenmanton for their lovely contributions.

## 0.9.2 (June 8th, 2019)

BUG FIXES:

* Fix kubernetes auth method list roles method. [GH-466](https://github.com/hvac/hvac/pull/466)
* Enable consul secrets engine. [GH-460](https://github.com/hvac/hvac/pull/460)
* Enable database secrets engine. [GH-455](https://github.com/hvac/hvac/pull/455)
* Many fixes for the database secrets engine. [GH-457](https://github.com/hvac/hvac/pull/457)

IMPROVEMENTS:

* The `enable_auth_method()`, `tune_auth_method()`, `enable_secrets_engine()`, `tune_mount_configuration()` system backend method now take arbitrary `**kwargs` parameters to provide greater support for variations in accepted parameters in the underlying Vault plugins.
* Azure auth params, add `num_uses`, change `bound_location` -> `bound_locations` and `bound_resource_group_names` -> `bound_resource_groups`. [GH-452](https://github.com/hvac/hvac/pull/452)

MISCELLANEOUS:

* The hvac project now has gitter chat enabled. Feel free to check it out for any online discussions related to this module at: [gitter.im/hvac/community](https://gitter.im/hvac/community))! [GH-465](https://github.com/hvac/hvac/pull/465)
* Added Vault agent socket listener usage example under the "advanced usage" documentation section at: [hvac.readthedocs.io](https://hvac.readthedocs.io/en/stable/advanced_usage.html#vault-agent-unix-socket-listener) [GH-468](https://github.com/hvac/hvac/issues/468)

Thanks to @denisvll, @Dudesons, and @drewmullen for their lovely contributions.

## 0.9.1 (May 25th, 2019)

BUG FIXES:

* Fix Azure list roles [GH-448](https://github.com/hvac/hvac/pull/448)

IMPROVEMENTS:
* Support for the PKI secrets engine. [GH-436](https://github.com/hvac/hvac/pull/436)

MISCELLANEOUS:

* `delete_roleset()` method added to GCP secrets engine support. [GH-449](https://github.com/hvac/hvac/pull/449)

Thanks to @nledez and @drewmullen for their lovely contributions.

## 0.9.0 (May 23rd, 2019)

BUG FIXES:

* Update path to azure.login() [GH-429](https://github.com/hvac/hvac/pull/429)
* AWS secrets engine generate credentials updated to a post request. [GH-430](https://github.com/hvac/hvac/pull/430)

IMPROVEMENTS:

* Support for the Radius auth method. [GH-420](https://github.com/hvac/hvac/pull/420)
* Support for the Database secrets engine. [GH-431](https://github.com/hvac/hvac/pull/431)
* Add the consul secret engine support [GH-432](https://github.com/hvac/hvac/pull/432)
* Support for the GCP secrets engine. [GH-443](https://github.com/hvac/hvac/pull/443)

MISCELLANEOUS:

* Remove logger call within adapters module [GH-445](https://github.com/hvac/hvac/pull/445)
* Add docs for auth_cubbyhole [GH-427](https://github.com/hvac/hvac/pull/427)

Thanks to @paulcaskey, @stevenmanton, @brad-alexander, @yoyomeng2, @JadeHayes, @Dudesons for their lovely contributions.

## 0.8.2 (April 4th, 2019)

BUG FIXES:

* Fix priority of client url and VAULT_ADDR environment variable. [GH-423](https://github.com/hvac/hvac/pull/423)
* Update setup.py to only compile hvac package. [GH-418](https://github.com/hvac/hvac/pull/418)

Thanks to @eltoder and @andytumelty for their lovely contributions.

## 0.8.1 (March 31st, 2019)

BUG FIXES:

* Fix `initialize()` method `recovery_shares` and `recovery_threshold` parameter validation regression. [GH-416](https://github.com/hvac/hvac/pull/416)

## 0.8.0 (March 29th, 2019)

BACKWARDS COMPATIBILITY NOTICE:

* The `Client()` class constructor now behaves similarly to Vault CLI in that it uses the `VAULT_ADDR` environmental variable for the Client URL when that variable is set. Along the same lines, when no token is passed into the `Client()` constructor, it will attempt to load a token from the `VAULT_TOKEN` environmental variable or the `~/.vault-token` file where available. [GH-411](https://github.com/hvac/hvac/pull/411)

IMPROVEMENTS:

* Support for the Kubernetes auth method. [GH-408](https://github.com/hvac/hvac/pull/408)

BUG FIXES:

* Fix for comparision `recovery_threshold` and `recovery_shares` during initialization. [GH-398](https://github.com/hvac/hvac/pull/398)
* Fix request method for AWS secrets engine `generate_credentials()` method. [GH-403](https://github.com/hvac/hvac/pull/403)
* Fix request parameter (`n_bytes` -> `bytes`) for Transit secrets engine `generate_random_bytes()` method. [GH-377](https://github.com/hvac/hvac/pull/377)

Thanks to @engstrom, @viralpoetry, @bootswithdefer, @steved, @kserrano, @spbsoluble, @uepoch, @singuliere, @frgaudet, @jsporna, & @mrsiesta for their lovely contributions.

## 0.7.2 (January 1st, 2019)

IMPROVEMENTS:

* Support for the AWS secrets engine. [GH-370](https://github.com/hvac/hvac/pull/370)

BUG FIXES:

* Fixes for intermittent test case failures. [GH-361](https://github.com/hvac/hvac/pull/361) & [GH-364](https://github.com/hvac/hvac/pull/364)

MISCELLANEOUS:

* Travis CI builds now run against Python 3.7 (along side the previously tested 2.7 and 3.6 versions). [GH-360](https://github.com/hvac/hvac/pull/360)
* Documentation build test case added. [GH-366](https://github.com/hvac/hvac/pull/366)
* Module version now managed by the `bumpversion` utility exclusively. [GH-369](https://github.com/hvac/hvac/pull/369)

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

* Note: Starting after release 0.7.0, `develop` is the main integration branch for the hvac project. The `main` branch is now intended to capture the state of the most recent release.
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
