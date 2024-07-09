"""
Tenable Cloud Security
===================

This package covers the Tenable Cloud Security interface.

.. autoclass:: TenableCS
    :members:


.. toctree::
    :hidden:
    :glob:

    exports
"""
import os
import warnings

from tenable.base.platform import APIPlatform
from .exports.api import ExportsAPI


class TenableCS(APIPlatform):
    """
    The Tenable Cloud Security object is the primary interaction point for users
    to interface with TCS via the pyTenable library.  All the API
    endpoint classes that have been written will be grafted onto this class.

    Args:
        api_key (str, optional):
            The user's API key for Tenable OT Security.  If an api key isn't
            specified, then the library will attempt to read the environment
            variable ``TOT_API_KEY`` to acquire the key.
        url (str, optional):
            The base URL used to connect to the Tenable OT Security service.
            If a URL isn't specified, then the library will attempt to read the
            environment variable ``TOT_URL`` to acquire the URL.

        **kwargs:
            arguments passed to :class:`tenable.base.platform.APIPlatform` for
            ConnectionAbortedErrorn management.


    Examples:
        Basic Example:

        >>> from tenable.cs import TenableCS
        >>> cs = TenableCS(api_key='SECRET_KEY',
        ..                 url='https://us2.app.ermetic.com/')

        Example with proper identification:

        >>> cs = TenableCS(api_key='SECRET_KEY',
        ...                url='https://us2.app.ermetic.com/',
        ...                vendor='Company Name',
        ...                product='My Awesome Widget',
        ...                build='1.0.0')

        Example with proper identification leveraging environment variables for
        the connection parameters:

        >>> ot = TenableOT(vendor='Company', product='Widget', build='1.0.0')
    """

    _env_base = "TCS"
    _ssl_verify = False
    _conv_json = True
    _base_path = 'api'

    def _session_auth(self, **kwargs):  # noqa: PLW0221,PLW0613
        msg = "Session Auth isn't supported with the Tenable Cloud Security"
        warnings.warn(msg)
        self._log.warning(msg)

    def _key_auth(self, api_key, **kwargs):  # noqa: PLW0221,PLW0613
        self._session.headers.update({"Authorization": f"Bearer {api_key}"})
        self._auth_mech = "keys"

    def _authenticate(self, **kwargs):
        kwargs["_key_auth_dict"] = kwargs.get(
            "_key_auth_dict",
            {"api_key": kwargs.get("api_key", os.getenv(f"{self._env_base}_API_KEY"))},
        )
        super()._authenticate(**kwargs)

    def graphql(self, **kwargs):
        """
        GraphQL Endpoint

        This singular method exposes the GraphQL API to the library.  As all
        keyword arguments are passed directly to the JSON body, it allows for a
        freeform interface into the GraphQL API.

        Args:
            **kwargs (dict, optional):
                The key/values that should be passed to the body of the GraphQL
                request.
                
        Example:
            >>> cs.graphql(
            ...     variables={'limit': 1,'filter': {'VulnerabilitySeverities': 
            ...               ['Critical']}}
            ...     query=\'\'\'
            ...         query getComputeVulns($filter: VirtualMachinesFilterInput, $limit: Int) {
            ...             VirtualMachines(first: $limit, filter: $filter) {
            ...                 nodes {
            ...                     Id
            ...                     AccountId
            ...                     CloudProvider
            ...                     OperatingSystem
            ...                 }
            ...             }
            ...         }
            ... \'\'\')
        """
        return self.post("graph", json=kwargs)

    @property
    def exports(self):
        return ExportsAPI(self)
