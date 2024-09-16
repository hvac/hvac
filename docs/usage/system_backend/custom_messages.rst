Custom Messages
===============

.. contents::
   :local:
   :depth: 1

List Custom Messages
--------------------

.. automethod:: hvac.api.system_backend.CustomMessages.list_custom_messages
   :noindex:

Examples
````````

.. testcode:: sys_custom_messages
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # List all custom messages
    client.sys.list_custom_messages()

Create Custom Message
---------------------

.. automethod:: hvac.api.system_backend.CustomMessages.create_custom_messages
   :noindex:

Examples
````````

.. testcode:: sys_custom_messages
    :skipif: not test_utils.is_enterprise()

    import hvac
    from datetime import datetime, timedelta, timezone

    client = hvac.Client(url="https://127.0.0.1:8200")

    # Create a custom message
    client.sys.create_custom_messages(
        title="Maintenance Notice",
        message="Scheduled maintenance will occur on Saturday at 2 AM UTC.",
        start_time=datetime.now(timezone.utc).isoformat(),
        end_time=(datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    )

Delete Custom Message
---------------------

.. automethod:: hvac.api.system_backend.CustomMessages.delete_custom_messages
   :noindex:

Examples
````````

.. testcode:: sys_custom_messages
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Delete a custom message
    client.sys.delete_custom_messages("message-id-123")

Read Custom Message
-------------------

.. automethod:: hvac.api.system_backend.CustomMessages.read_custom_messages
   :noindex:

Examples
````````

.. testcode:: sys_custom_messages
    :skipif: not test_utils.is_enterprise()

    import hvac
    client = hvac.Client(url="https://127.0.0.1:8200")

    # Read a custom message
    client.sys.read_custom_messages("message-id-123")

Update Custom Message
---------------------

.. automethod:: hvac.api.system_backend.CustomMessages.update_custom_messages
   :noindex:

Examples
````````

.. testcode:: sys_custom_messages
    :skipif: not test_utils.is_enterprise()

    import hvac
    from datetime import datetime, timezone, timedelta

    client = hvac.Client(url="https://127.0.0.1:8200")

    # Update a custom message
    client.sys.update_custom_messages(
        id="message-id-123",
        title="Updated Maintenance Notice",
        message="Maintenance has been rescheduled to Sunday at 3 AM UTC.",
        start_time=datetime.now(timezone.utc).isoformat(),
        end_time=(datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    )
