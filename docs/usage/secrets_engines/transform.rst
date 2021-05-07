Transform
=========

.. contents::
   :local:
   :depth: 1

.. testsetup:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    client.sys.enable_secrets_engine(
        backend_type='transform',
    )

Encode/Decode Example
---------------------

:py:meth:`hvac.api.secrets_engines.Transform.encode`
:py:meth:`hvac.api.secrets_engines.Transform.decode`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    input_value = '1111-1111-1111-1111'

    role_name = 'hvac-role'
    transformation_name = 'hvac-fpe-credit-card'
    transformations = [transformation_name]

    # Create a role and a transformation
    client.secrets.transform.create_or_update_role(
        name=role_name,
        transformations=transformations,
    )
    client.secrets.transform.create_or_update_transformation(
        name=transformation_name,
        transform_type='fpe',
        template='builtin/creditcardnumber',
        tweak_source='internal',
        allowed_roles=[role_name],
    )

    # Use the role/transformation combination to encode a value
    encode_response = client.secrets.transform.encode(
        role_name=role_name,
        value=input_value,
        transformation=transformation_name,
    )
    print('The encoded value is: %s' % encode_response['data']['encoded_value'])

    # Use the role/transformation combination to decode a value
    decode_response = client.secrets.transform.decode(
        role_name=role_name,
        value=encode_response['data']['encoded_value'],
        transformation=transformation_name,
    )
    print('The decoded value is: %s' % decode_response['data']['decoded_value'])

.. testoutput:: transform

    The encoded value is: ...
    The decoded value is: 1111-1111-1111-1111

Create/Update Role
------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_role`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.secrets.transform.create_or_update_role(
        name='hvac-role',
        transformations=[
            'hvac-fpe-credit-card',
        ],
    )

Read Role
---------

:py:meth:`hvac.api.secrets_engines.Transform.read_role`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    role_name = 'hvac-role'
    client.secrets.transform.create_or_update_role(
        name=role_name,
        transformations=[
            'hvac-fpe-credit-card',
        ],
    )
    read_response = client.secrets.transform.read_role(
        name=role_name,
    )
    print('Role "{}" has the following transformations configured: {}'.format(
        role_name,
        ', '.join(read_response['data']['transformations']),
    ))

.. testoutput:: transform

    Role "hvac-role" has the following transformations configured: hvac-fpe-credit-card

List Roles
----------

:py:meth:`hvac.api.secrets_engines.Transform.list_roles`


.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    client.secrets.transform.create_or_update_role(
        name='hvac-role',
        transformations=[
            'hvac-fpe-credit-card',
        ],
    )
    list_response = client.secrets.transform.list_roles()
    print('List of transform role names: {}'.format(
        ', '.join(list_response['data']['keys']),
    ))

.. testoutput:: transform

    List of transform role names: hvac-role

Delete Role
-----------

:py:meth:`hvac.api.secrets_engines.Transform.delete_role`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    role_name = 'hvac-role'

    # Create a role
    client.secrets.transform.create_or_update_role(
        name=role_name,
        transformations=[
            'hvac-fpe-credit-card',
        ],
    )

    # Subsequently delete it...
    client.secrets.transform.delete_role(
        name=role_name,
    )

Create/Update Transformation
----------------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_transformation`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    transformation_name = 'hvac-fpe-credit-card'
    template = 'builtin/creditcardnumber'
    client.secrets.transform.create_or_update_transformation(
        name=transformation_name,
        transform_type='fpe',
        template=template,
        tweak_source='internal',
        allowed_roles=[
            'test-role'
        ],
    )

Read Transformation
-------------------

:py:meth:`hvac.api.secrets_engines.Transform.read_transformation`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    transformation_name = 'hvac-fpe-credit-card'
    template = 'builtin/creditcardnumber'
    client.secrets.transform.create_or_update_transformation(
        name=transformation_name,
        transform_type='fpe',
        template=template,
        tweak_source='internal',
        allowed_roles=[
            'hvac-role'
        ],
    )
    read_response = client.secrets.transform.read_transformation(
        name=transformation_name,
    )
    print('Transformation "{}" has the following type configured: {}'.format(
        transformation_name,
        read_response['data']['type'],
    ))

.. testoutput:: transform

    Transformation "hvac-fpe-credit-card" has the following type configured: fpe

List Transformations
--------------------

:py:meth:`hvac.api.secrets_engines.Transform.list_transformations`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    transformation_name = 'hvac-fpe-credit-card'
    template = 'builtin/creditcardnumber'
    client.secrets.transform.create_or_update_transformation(
        name=transformation_name,
        transform_type='fpe',
        template=template,
        tweak_source='internal',
        allowed_roles=[
            'hvac-role'
        ],
    )
    list_response = client.secrets.transform.list_transformations()
    print('List of transformations: {}'.format(
        ', '.join(list_response['data']['keys']),
    ))

.. testoutput:: transform

    List of transformations: hvac-fpe-credit-card

Delete Transformation
---------------------

:py:meth:`hvac.api.secrets_engines.Transform.delete_transformation`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    transformation_name = 'hvac-fpe-credit-card'
    template = 'builtin/creditcardnumber'

    # Create a transformation
    client.secrets.transform.create_or_update_transformation(
        name=transformation_name,
        transform_type='fpe',
        template=template,
        tweak_source='internal',
        allowed_roles=[
            'hvac-role'
        ],
    )

    # Subsequently delete it...
    client.secrets.transform.delete_role(
        name=role_name,
    )

Create/Update Template
----------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_template`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    template_name = 'hvac-template'
    create_response = client.secrets.transform.create_or_update_template(
        name=template_name,
        template_type='regex',
        pattern='(\\d{9})',
        alphabet='builtin/numeric',
    )

Read Template
-------------

:py:meth:`hvac.api.secrets_engines.Transform.read_template`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    template_name = 'hvac-template'
    client.secrets.transform.create_or_update_template(
        name=template_name,
        template_type='regex',
        pattern='(\\d{9})',
        alphabet='builtin/numeric',
    )
    read_response = client.secrets.transform.read_template(
        name=template_name,
    )
    print('Template "{}" has the following type configured: {}'.format(
        template_name,
        read_response['data']['type'],
    ))

.. testoutput:: transform

    Template "hvac-template" has the following type configured: regex

List Templates
--------------

:py:meth:`hvac.api.secrets_engines.Transform.list_templates`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    template_name = 'hvac-template'
    client.secrets.transform.create_or_update_template(
        name=template_name,
        template_type='regex',
        pattern='(\\d{9})',
        alphabet='builtin/numeric',
    )
    list_response = client.secrets.transform.list_templates()
    print('List of templates: {}'.format(
        ', '.join(list_response['data']['keys']),
    ))

.. testoutput:: transform

    List of templates: builtin/creditcardnumber, builtin/socialsecuritynumber, hvac-template

Delete Template
-------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.delete_template`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    template_name = 'hvac-template'
    client.secrets.transform.create_or_update_template(
        name=template_name,
        template_type='regex',
        pattern='(\\d{9})',
        alphabet='builtin/numeric',
    )

    # Subsequently delete it...
    client.secrets.transform.delete_template(
        name=template_name,
    )

Create/Update Alphabet
----------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_alphabet`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    alphabet_name = 'hvac-alphabet'
    alphabet_value = 'abc'
    client.secrets.transform.create_or_update_alphabet(
        name=alphabet_name,
        alphabet=alphabet_value,
    )

Read Alphabet
-------------

:py:meth:`hvac.api.secrets_engines.Transform.read_alphabet`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    alphabet_name = 'hvac-alphabet'
    alphabet_value = 'abc'
    client.secrets.transform.create_or_update_alphabet(
        name=alphabet_name,
        alphabet=alphabet_value,
    )
    read_response = client.secrets.transform.read_alphabet(
        name=alphabet_name,
    )
    print('Alphabet "{}" has this jazz: {}'.format(
        alphabet_name,
        read_response['data']['alphabet'],
    ))

.. testoutput:: transform

    Alphabet "hvac-alphabet" has this jazz: abc

List Alphabets
--------------

:py:meth:`hvac.api.secrets_engines.Transform.list_alphabets`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    alphabet_name = 'hvac-alphabet'
    alphabet_value = 'abc'
    client.secrets.transform.create_or_update_alphabet(
        name=alphabet_name,
        alphabet=alphabet_value,
    )
    list_response = client.secrets.transform.list_alphabets()
    print('List of alphabets: {}'.format(
        ', '.join(list_response['data']['keys']),
    ))

.. testoutput:: transform

   List of alphabets: builtin/alphalower, ..., hvac-alphabet

Delete Alphabet
---------------

:py:meth:`hvac.api.secrets_engines.Transform.delete_alphabet`

.. testcode:: transform
    :skipif: test_utils.vault_version_lt('1.4.0') or not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url='https://127.0.0.1:8200')

    alphabet_name = 'hvac-alphabet'
    alphabet_value = 'abc'

    # Create an alphabet
    client.secrets.transform.create_or_update_alphabet(
        name=alphabet_name,
        alphabet=alphabet_value,
    )

    # Subsequently delete it...
    client.secrets.transform.delete_alphabet(
        name=alphabet_name,
    )

Create Or Update FPE Transformation
-----------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_fpe_transformation`

.. automodule:: hvac.api.secrets_engines.Transform.create_or_update_fpe_transformation
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:

Create Or Update Masking Transformation
---------------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_masking_transformation`

.. automodule:: hvac.api.secrets_engines.Transform.create_or_update_masking_transformation
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Create Or Update Tokenization Transformation
--------------------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_tokenization_transformation`

.. automodule:: hvac.api.secrets_engines.Transform.create_or_update_tokenization_transformation
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Create Or Update Tokenization Store
-----------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.create_or_update_tokenization_store`

.. automodule:: hvac.api.secrets_engines.Transform.create_or_update_tokenization_store
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Encode
--------

:py:meth:`hvac.api.secrets_engines.Transform.encode`

.. automodule:: hvac.api.secrets_engines.Transform.encode
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Validate Token
--------------

:py:meth:`hvac.api.secrets_engines.Transform.validate_token`

.. automodule:: hvac.api.secrets_engines.Transform.validate_token
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Check Tokenization
------------------

:py:meth:`hvac.api.secrets_engines.Transform.check_tokenization`

.. automodule:: hvac.api.secrets_engines.Transform.check_tokenization
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Retrieve Token Metadata
-----------------------

:py:meth:`hvac.api.secrets_engines.Transform.retrieve_token_metadata`

.. automodule:: hvac.api.secrets_engines.Transform.retrieve_token_metadata
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Snapshot Tokenization State
---------------------------

:py:meth:`hvac.api.secrets_engines.Transform.snapshot_tokenization_state`

.. automodule:: hvac.api.secrets_engines.Transform.snapshot_tokenization_state
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Restore Tokenization State
--------------------------

:py:meth:`hvac.api.secrets_engines.Transform.restore_tokenization_state`

.. automodule:: hvac.api.secrets_engines.Transform.restore_tokenization_state
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Export Decoded Tokenization State
---------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.export_decoded_tokenization_state`

.. automodule:: hvac.api.secrets_engines.Transform.export_decoded_tokenization_state
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Rotate Tokenization Key
-----------------------

:py:meth:`hvac.api.secrets_engines.Transform.rotate_tokenization_key`

.. automodule:: hvac.api.secrets_engines.Transform.rotate_tokenization_key
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Update Tokenization Key Config
------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.update_tokenization_key_config`

.. automodule:: hvac.api.secrets_engines.Transform.update_tokenization_key_config
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


List Tokenization Key Configuration
-----------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.list_tokenization_key_configuration`

.. automodule:: hvac.api.secrets_engines.Transform.list_tokenization_key_configuration
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Read Tokenization Key Configuration
-----------------------------------

:py:meth:`hvac.api.secrets_engines.Transform.read_tokenization_key_configuration`

.. automodule:: hvac.api.secrets_engines.Transform.read_tokenization_key_configuration
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:


Trim Tokenization Key Version
-----------------------------

:py:meth:`hvac.api.secrets_engines.Transform.trim_tokenization_key_version`

.. automodule:: hvac.api.secrets_engines.Transform.trim_tokenization_key_version
    :members:
    :undoc-members:
    :show-inheritance:
    :noindex:
