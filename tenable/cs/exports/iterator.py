from typing import Dict
from restfly.iterator import APIIterator


class CloudSecExportIterator(APIIterator):
    """
    Tenable Cloud Security Exports Iterator
    """
    _model: str
    _query: str
    _variables: Dict

    def _get_page(self):
        """
        Fetches the next page of data from the GraphQL API
        """
        resp = self._api.graphql(query=self._query,
                                 variables=self._variables,
                                 )
        raw_page = resp.get('data', {}).get(self._model, {})
        self.page = raw_page.get('nodes', [])
        self._variables['startAt'] = raw_page.get('pageInfo', {})\
                                             .get('endCursor', None)
        self.total = raw_page.get('count')
        return self.page
