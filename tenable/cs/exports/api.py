from typing import List, Dict, Optional, Union, Any
from tenable.base.endpoint import APIEndpoint
from .iterator import CloudSecExportIterator
from . import queries


class ExportsAPI(APIEndpoint):
    def _list(self,
              query: str,
              model: str,
              limit: int = 200,
              return_json: bool = False,
              filters: Optional[List[Dict]] = None,
              default_filters: Optional[List[Dict]] = None,
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
            filters (list[dict], optional):
                List of filters to apply to restict the response to only the
                desired items.
            return_json (bool, optional):
                If `True`, then the instead of an iterator, the json response
                will be returned instead.
            default_filters (list[dict], optional):
                The default filters to appllied to the query first.  This is
                mainly used by the caller as part of passing through the
                filters parameter as well.
            iterable: (object, optional):
                The iterable object to return to the caller.

        Returns:
            Union[OTExportsIterator, dict]:
                By default the method will return an iterator that will handle
                pagination and return a single item at a time.  If return_json
                is set to `True` however, then the JSON response will be
                returned instead for that page.
        """
        default_filters = [] if default_filters is None else default_filters
        filters = [] if filters is None else filters

        # Iterate over the default filters and add them to the filter list
        # if they don't exist.
        for default_filter in default_filters:
            field = default_filter['field']
            if field not in [f.get('field') for f in filters]:
                filters.append(default_filter)

        filter = filters[0] if filters else None
        if len(filters) > 1:
            filter = {
                'op': 'And',
                'expressions': filters
            }

        variables = {
            'startAt': start_at,
            'limit': limit,
            'filter': filter,
        }

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
                          start_at=start_at,
                          limit=limit,
                          return_json=return_json
                          )
