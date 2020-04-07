#!/usr/bin/env python
# -*- coding: utf-8 -*-
from collections import OrderedDict

import requests
from bs4 import BeautifulSoup
from jinja2 import Template
import re

API_CLASS_TEMPLATE_STR = '''\
#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""{{ class_name }} methods module."""
from hvac.api.vault_api_base import VaultApiBase


DEFAULT_MOUNT_POINT = '{{ mount_point }}'


class {{ class_name }}(VaultApiBase):
    """{{ class_docstring }}.
    
    Reference: {{ reference_url }}
    """
    {% for name, method_details in methods.items() %}
    def {{ name }}(self{% for param_name, param_details in method_details.params.items() %}, {{ param_name }}{% if param_details.default %}={{ param_details.default }}{% endif %}{% endfor %}{% if method_details.routes|length > 1 %}, method='{{ method_details.routes[0].method}}'{% endif %}, mount_point=DEFAULT_MOUNT_POINT):
        """{{ method_details.route }}
        {{ method_details.docstring|join('\n')|indent(width=8) }}
        {% if method_details.routes|length <= 1 %}
        Supported methods:
            {%- for route in method_details.routes %}
            {{ route.method }}: {{ route.path }}.
            {%- endfor %}
        {% endif %}
        {% for param_name, param_details in method_details.params.items() %}
        :param {{ param_name }}: {{ param_details.description|indent(width=12) }}
        :type {{ param_name }}: {{ param_details.type }}
        {%- endfor %}
        {%- if method_details.routes|length > 1 %}
        :param method: Supported methods:
            {%- for route in method_details.routes %}
            {{ route.method }}: {{ route.path }}.
            {%- endfor %}
        :type method: str | unicode
        {%- endif %}
        :param mount_point: The "path" the method/backend was mounted on.
        :type mount_point: str | unicode
        :return: The response of the {{ name }} request.
        :rtype: requests.Response
        """
        {%- if method_details.params|length >= 2 or 'path' not in method_details.params and method_details.params %}
        params = {
            {%- for param_name in method_details.params.keys() if param_name != 'path' %}
            '{{ param_name }}': {{ param_name }},
            {%- endfor %}
        }
        {%- endif %}
        {%- if method_details.routes|length > 1 %}
        {%- for route in method_details.routes %}
        {% if loop.first %}
        if method == '{{ route.method }}':
        {%- else %}
        elif method == '{{ route.method }}':
        {%- endif %}
            api_path = '/v1{{ method_details.routes[0].path }}'.format(mount_point=mount_point{% if 'path' in method_details.params %}, path=path{% endif %})
            return self._adapter.{{ method_details.routes[0].method|lower }}(
                url=api_path,
                {%- if method_details.params|length >= 2 or 'path' not in method_details.params and method_details.params %}
                json=params,
                {%- endif %}
            )
        {%- endfor %}
        {% else %}
        api_path = '/v1{{ method_details.routes[0].path }}'.format(mount_point=mount_point{% if 'path' in method_details.params %}, path=path{% endif %})
        return self._adapter.{{ method_details.routes[0].method|lower }}(
            url=api_path,
            {%- if method_details.params|length >= 2 or 'path' not in method_details.params and method_details.params %}
            json=params,
            {%- endif %}
        )
{% endif %}
{%- endfor %}
'''  # NOQA

API_INTEGRATION_CLASS = '''\
from unittest import TestCase

from parameterized import parameterized

from hvac.api.auth_methods.{{ class_name|lower }} import DEFAULT_MOUNT_POINT
from hvac.tests import utils


class Test{{ class_name }}(utils.HvacIntegrationTestCase, TestCase):

    @classmethod
    def setUpClass(cls):
        super(Test{{ class_name }}, cls).setUpClass()

    def setUp(self):
        super(Test{{ class_name }}, self).setUp()

    def tearDown(self):
        super(Test{{ class_name }}, self).tearDown()

    {% for name, method_details in methods.items() %}
    @parameterized.expand([
        ('some_test',),
    ])
    def test_{{ name }}(self, test_label):
        raise NotImplementedError
    {% endfor %}
'''  # NOQA

API_UNIT_CLASS = '''\
from unittest import TestCase

import requests_mock
from parameterized import parameterized

from hvac.adapters import Request
from hvac.api.auth_methods import {{ class_name }}
from hvac.api.auth_methods.{{ class_name|lower }} import DEFAULT_MOUNT_POINT


class Test{{ class_name }}(TestCase):

    @classmethod
    def setUpClass(cls):
        super(Test{{ class_name }}, cls).setUpClass()

    def setUp(self):
        super(Test{{ class_name }}, self).setUp()

    def tearDown(self):
        super(Test{{ class_name }}, self).tearDown()

    {% for name, method_details in methods.items() %}
    @parameterized.expand([
        ('some_test',),
    ])
    @requests_mock.Mocker()
    def test_{{ name }}(self, test_label, requests_mocker):
        raise NotImplementedError
    {% endfor %}
'''  # NOQA

USAGE_DOCS = '''\
{{ class_name }} Auth Method
==================

.. note::
    Every method under the :py:attr:`Client class's {{ class_name|lower }} attribute<hvac.v1.Client.{{ class_name|lower }}>` includes a `mount_point` parameter that can be used to address the {{ class_name }} auth method under a custom mount path. E.g., If enabling the {{ class_name }} auth method using Vault's CLI commands via `vault secret enable -path=my-{{ class_name|lower }} {{ class_name|lower }}`", the `mount_point` parameter in :py:meth:`hvac.api.auth_methods.{{ class_name }}` methods would be set to "my-{{ class_name|lower }}".

Enabling the Auth Method
------------------------

:py:meth:`hvac.v1.Client.enable_secret_backend`

.. code:: python

    import hvac
    client = hvac.Client()

    {{ class_name|lower }}_secret_path = 'company-{{ class_name|lower }}'
    description = 'Auth method for use by team members in our company's {{ class_name }} organization'

    if '%s/' % {{ class_name|lower }}_secret_path not in vault_client.list_secret_backends():
        print('Enabling the {{ class_name|lower }} secret backend at mount_point: {path}'.format(
            path={{ class_name|lower }}_secret_path,
        ))
        client.enable_secret_backend(
            backend_type='{{ class_name|lower }}',
            description=description,
            mount_point={{ class_name|lower }}_secret_path,
        )

{% for name, method_details in methods.items() %}
{{ method_details.original_id }}
-------------------------------

:py:meth:`hvac.api.auth_methods.{{ class_name }}.{{ name }}`

.. code:: python

    import hvac
    client = hvac.Client()

    client.{{ class_name|lower }}.{{ name }}(
    )
{% endfor %}
''' # NOQA


def main():
    urls = {
        'Transform': {
            'docs_url': 'http://localhost:3000/api-docs/secret/transform',
            'default_mount_point': 'transform',
        },
        # 'Azure': {
        #     'docs_url': 'https://www.vaultproject.io/api/secret/azure/index.html',
        #     'default_mount_point': 'azure',
        # },
        # 'Gcp': {
        #     'docs_url': 'https://www.vaultproject.io/api/auth/gcp/index.html',
        #     'default_mount_point': 'secret',
        # },
        # 'KvV1': {
        #     'docs_url': 'https://www.vaultproject.io/api/secret/kv/kv-v1.html',
        #     'default_mount_point': 'secret',
        # },
        # 'KvV2': {
        #     'docs_url': 'https://www.vaultproject.io/api/secret/kv/kv-v2.html',
        #     'default_mount_point': 'secret',
        # },
        # 'Github': {
        #     'docs_url': 'https://www.vaultproject.io/api/auth/github/index.html',
        #     'default_mount_point': 'github',
        # },
        # 'Ldap': {
        #     'docs_url': 'https://www.vaultproject.io/api/auth/ldap/index.html',
        #     'default_mount_point': 'ldap',
        # },
        # 'AwsAuth': {
        #     'docs_url': 'https://www.vaultproject.io/api/auth/aws/index.html',
        #     'default_mount_point': 'aws',
        # },
        # 'AwsSecret': {
        #     'docs_url': 'https://www.vaultproject.io/api/secret/aws/index.html',
        #     'default_mount_point': 'aws',
        #
        # },
    }
    for class_name, details in urls.items():
        response = requests.get(
            url=details['docs_url']
        )
        response.encoding = 'utf-8'
        soup = BeautifulSoup(response.text, 'html.parser')
        # print(soup.prettify())
        methods = OrderedDict()
        inner_div = soup.find('div', id='inner')
        current_method_index = 1
        class_docstring = ' '.join(inner_div.find('h1').text.strip().split(' '))
        print(f'class_docstring: {class_docstring}')
        print(f'inner_div.find_all("h2"): {inner_div.find_all("h2")}')
        for method_heading in inner_div.find_all('h2'):
            # if method_heading.has_attr('class'):
            #     continue
            # load routes
            route_specs_table = method_heading.find_next_sibling('table')
            if route_specs_table is None:
                print('No route found for %s' % method_heading)
                continue
            anchors = method_heading.find_all("a")
            # breakpoint()
            original_id = anchors[0]['href']

            name = original_id.replace('-', '_')
            name = name.replace('#', '')
            pattern = re.compile(re.escape(class_name), re.IGNORECASE)
            name = pattern.sub('', name)
            pattern = re.compile(re.escape('method'), re.IGNORECASE)
            name = pattern.sub('', name)
            name = name.replace('__', '_')
            name = name.rstrip('_')
            name = name.replace('create_update', 'create_or_update')
            methods[name] = {
                'params': OrderedDict(),
                'routes': [

                ],
                'docstring': [],
                'original_id': original_id,
            }
            # current_tag = method_heading
            # for i in range(0, 5):
            #     print('%s: %s' % (i, current_tag.next_sibling))
            # get docs / text about method
            methods[name]['docstring'].append(method_heading.find_next_sibling('p').text)
            print(f'methods: {methods}')
            table_body = route_specs_table.find('tbody')
            rows = table_body.find_all('tr')
            for row in rows:
                cells = row.find_all('td')
                print(details['default_mount_point'], cells[1].text.strip())
                path = cells[1].text.strip()
                path = path.replace(details['default_mount_point'], '{mount_point}')
                if ':path' in path:
                    path = path.replace(':path', '{path}')
                    methods[name]['params']['path'] = {
                        'type': 'str | unicode',
                        'description': 'Path',
                        'default': None,
                    }
                methods[name]['routes'].append({
                    'method': cells[0].text.strip(),
                    'path': path,
                    'response': '',
                    # 'response': cells[2].text.strip(),
                })

            # now get params
            method_params = OrderedDict()
            params_heading = method_heading.find_next_sibling('h3')  # , id='parameters-%s' % current_method_index)
            params_unordered_list = params_heading.find_next_sibling('ul')
            param_list_items = params_unordered_list.find_all('li')
            for param_list_item in param_list_items:
                # our method for getting the parameter name and type
                # print(name)
                # print(param_list_item)
                code_tags = param_list_item.find_all('code')
                # print(code_tags)
                param_name = code_tags[0].text.strip().lstrip(':')
                try:
                    param_type = code_tags[1].text.strip().strip('()')
                except IndexError:
                    param_type = 'unknown'
                param_default = None
                if len(param_type.split(':')) > 1:
                    param_type, param_default = param_type.split(':', 1)
                    param_default = param_default.strip()

                    if param_default in ['false', 'true']:
                        param_default = param_default.capitalize()

                    if param_default == '[]':
                        param_default = 'None'

                    if any([d in param_default for d in ['required', 'optional']]):
                        param_default = None

                if 'string' in param_type:
                    param_type = 'str | unicode'
                elif 'int' in param_type:
                    param_type = 'int'
                elif 'bool' in param_type:
                    param_type = 'bool'
                if param_list_item.find('p'):
                    try:
                        param_description = ' '.join(param_list_item.find('p').contents[-1].strip().split(' ')[1:])
                    except TypeError:
                        param_description = 'TypeError'
                        pass
                else:
                    try:
                        param_description = ' '.join(param_list_item.contents[-1].strip().split(' ')[1:])
                    except TypeError:
                        param_description = 'TypeError'
                        pass
                method_params[param_name] = {
                    'type': param_type.strip(),
                    'description': param_description,
                    'default': param_default,
                }
            for param_name, param_details in method_params.items():
                if param_details['default'] is None:
                    methods[name]['params'][param_name] = param_details
            for param_name, param_details in method_params.items():
                if param_details['default'] is not None:
                    methods[name]['params'][param_name] = param_details

            current_method_index += 1

        t = Template(API_CLASS_TEMPLATE_STR)
        class_source_filename = class_name
        class_source_filename = '%s%s' % (class_source_filename[0].lower(), class_source_filename[1:])
        class_source_filename = ''.join('_%s' % c.lower() if c.isupper() else c for c in class_source_filename)
        class_source_filename = '%s.py' % class_source_filename
        class_source = t.render(
            default_mount_point=details['default_mount_point'],
            class_name=class_name,
            reference_url=details['docs_url'],
            class_docstring=class_docstring,
            methods=methods,
        )
        with open(class_source_filename, 'w') as f:
            f.writelines(class_source)

        integration_source_filename = 'test_integration_%s.py' % class_name.lower()
        t = Template(API_INTEGRATION_CLASS)
        integration_source = t.render(
            default_mount_point=details['default_mount_point'],
            class_name=class_name,
            reference_url=details['docs_url'],
            class_docstring=class_docstring,
            methods=methods,
        )
        with open(integration_source_filename, 'w') as f:
            f.writelines(integration_source)

        unit_source_filename = 'test_unit_%s.py' % class_name.lower()
        t = Template(API_UNIT_CLASS)
        unit_source = t.render(
            default_mount_point=details['default_mount_point'],
            class_name=class_name,
            reference_url=details['docs_url'],
            class_docstring=class_docstring,
            methods=methods,
        )
        with open(unit_source_filename, 'w') as f:
            f.writelines(unit_source)

        usage_filename = '%s.rst' % class_name.lower()
        t = Template(USAGE_DOCS)
        usage_docs_source = t.render(
            default_mount_point=details['default_mount_point'],
            class_name=class_name,
            reference_url=details['docs_url'],
            class_docstring=class_docstring,
            methods=methods,
        )
        with open(usage_filename, 'w') as f:
            f.writelines(usage_docs_source)
        # renderer = VaultDocsHvacApiClassRenderer(
        #     class_name=class_name,
        #     reference_url=url,
        # )
        # markdown_source = response.text
        # markdown_source = '\n'.join(markdown_source.splitlines()[7:])
        # # raise Exception(markdown_source)
        # markdown = mistune.Markdown(renderer=renderer)
        # body = markdown.parse(markdown_source)
        # print(body)
        # t = Template(API_CLASS_TEMPLATE_STR)
        #
        # print(renderer.render_class_source())


if __name__ == '__main__':
    main()
