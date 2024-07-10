"""
Data Export Helper
==================

The methods exposed within the export module are designed to mimick the same
structure that Tenable Vulnerability Management uses for exporting data.
These methods ultimately translate to GraphQL queries and then are fed to the
Tenable CS API.

.. rst-class:: hide-signature
.. autoclass:: ExportsAPI
    :members:
"""

from typing import List, Dict, Optional, Union, Any
from tenable.base.endpoint import APIEndpoint
from tenable.cs.exports.iterator import CloudSecExportIterator
from tenable.cs.exports import queries

class ExportsAPI(APIEndpoint):
    def _list(self,
              query: str,
              model: str,
              limit: int = 200,
              return_json: bool = False,
              filters: Optional[Dict] = None,
              default_filters: Optional[Dict] = None,
              start_at: Optional[str] = None,
              iterable: Optional[Any] = CloudSecExportIterator,
              **kwargs
              ) -> Any:
        """
        Base listing method to be used for the exports.

        Args:
            query (str): The GraphQL Query to run
            model (str):
                The GraphQL Model that is to be returned from the API.  This
                name is what is used by the iterator to traverse the data
                page.
            limit (int, optional):
                The number of objects to be returned per page.
            start_at (str, optional):
                Start returning data after this object id.
            filters (dict, optional):
                List of filters to apply to restict the response to only the
                desired items.
            return_json (bool, optional):
                If `True`, then the instead of an iterator, the json response
                will be returned instead.
            default_filters (dict, optional):
                The default filters to appllied to the query first.  This is
                mainly used by the caller as part of passing through the
                filters parameter as well.
            iterable: (object, optional):
                The iterable object to return to the caller.

        Returns:
            Union[CloudSecExportIterator, dict]:
                By default the method will return an iterator that will handle
                pagination and return a single item at a time.  If return_json
                is set to `True` however, then the JSON response will be
                returned instead for that page.
        """
        default_filters = {} if default_filters is None else default_filters
        filters = {} if filters is None else filters

        # Iterate over the default filters and add them to the filter list
        # if they don't exist.
        for default_filter in default_filters:
            if default_filter not in filters:
                filters[default_filter] = default_filters[default_filter]
        variables = {
            'startAt': start_at,
            'limit': limit,
            'filter': filters,
        }
        if return_json:
            return self._api.graphql(query=query,
                                   variables=variables,
                                   **kwargs
                                   )
        return iterable(self._api,
                        _model=model,
                        _query=query,
                        _variables=variables,
                        **kwargs
                        )

    def _get_fields_for_type(self, object_type):
        variables={"object_type": object_type} 
        return self._api.graphql(
                                query=queries.GET_FIELDS_FOR_OBJECT_TYPE_QUERY,
                                variables=variables).json()['data']['__type']['fields']

    def compute_vulns(self,
                      filters: Optional[Dict] = None,
                      start_at: Optional[str] = None,
                      limit: Optional[int] = 200,
                      return_json: bool = False
                      ) -> Union[CloudSecExportIterator, Dict]:
        """
        No docs for you
        """
        default_filters = {
            'VulnerabilitySeverities': ['Critical', 'High', 'Medium', 'Low', 'Informational'],
        }
        return self._list(queries.COMPUTE_VULNS_QUERY,
                          model='VirtualMachines',
                          filters=filters,
                          default_filters=default_filters,
                          start_at=start_at,
                          limit=limit,
                          return_json=return_json
                          )
        
    def container_vulns(self,
                      filters: Optional[Dict] = None,
                      start_at: Optional[str] = None,
                      limit: Optional[int] = 200,
                      return_json: bool = False
                      ) -> Union[CloudSecExportIterator, Dict]:
        """
        No docs for you
        """
        default_filters = {
            'VulnerabilitySeverities': ['Critical', 'High', 'Medium', 'Low', 'Informational'],
        }
        return self._list(queries.CONTAINER_VULNS_QUERY,
                          model='ContainerImages',
                          filters=filters,
                          start_at=start_at,
                          default_filters=default_filters,
                          limit=limit,
                          return_json=return_json
                          )
        
    def compute_assets(self,
                    filters: Optional[Dict] = None,
                    start_at: Optional[str] = None,
                    limit: Optional[int] = 200,
                    return_json: bool = False
                    ) -> Union[CloudSecExportIterator, Dict]:
        """
        No docs for you
        """
        self._log.warn('The query that powers this only supports ec2 right now')
        default_filters = {
            'Types': [
                'AzureDbForMariaDbServer',
                'AwsRdsDatabaseInstance',
                'AwsEc2Instance',
                'AzureComputeVirtualMachine',
                'AzureComputeVirtualMachineScaleSetVirtualMachine',
                'GcpComputeInstance',
                'AwsRdsDatabaseInstance',
                'AzureClassicComputeVirtualMachine',
                'AzureVMwareVirtualmachine',
                'GcpSpannerDatabase',
                'OciComputeInstance',
                'AzureMySqlFlexibleServer',
                'AzureMySqlSingleServer',
                'AzurePostgreSqlFlexibleServer',
                'AzurePostgreSqlSingleServer',
                'AzureSqlServer',
                'GcpSqlInstance',
                'GcpBigtableInstance'
            ]
        }

        return self._list(queries.COMPUTE_ASSETS_QUERY,
                            model='Entities',
                            filters=filters,
                            default_filters=default_filters,
                            start_at=start_at,
                            limit=limit,
                            return_json=return_json
                        )
        
    def container_assets(self,
                    filters: Optional[Dict] = None,
                    start_at: Optional[str] = None,
                    limit: Optional[int] = 200,
                    return_json: bool = False
                    ) -> Union[CloudSecExportIterator, Dict]:
        """
        No docs for you
        """
        default_filters = {
            'Types': [
                'CiContainerImage',
                'AwsContainerImage',
                'AzureContainerImage',
                'GcpContainerImage',
                'OpContainerImage'
            ]
        }
        return self._list(queries.CONTAINER_ASSETS_QUERY,
                            model='Entities',
                            filters=filters,
                            default_filters=default_filters,
                            start_at=start_at,
                            limit=limit,
                            return_json=return_json
                        )