from typing import Dict
from restfly.iterator import APIIterator
import arrow
from sys import getsizeof

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
        if not hasattr(self, '_page_timer'):
            self._start_timer = arrow.utcnow().int_timestamp
            self._page_timer = arrow.utcnow().int_timestamp
        else:
            page_diff = arrow.utcnow().int_timestamp - self._page_timer
            content_size = getsizeof(str(self.page))/1024
            size_type = 'KB'
            if int(content_size) >= 1024:
                content_size = content_size/1024
                size_type = 'MB'
            self._log.info(f'It took {page_diff} seconds to download page {self.num_pages} with page size {self._variables['limit']} size {round(content_size, 2)}{size_type}')
            self._page_timer = arrow.utcnow().int_timestamp
        resp = self._api.graphql(query=self._query,
                                 variables=self._variables,
                                 ).json()
        raw_page = resp.get('data', {}).get(self._model, {})
        
        self.page = raw_page.get('nodes', [])
        self._variables['startAt'] = raw_page.get('pageInfo', {})\
                                             .get('endCursor', None)
        self.total = raw_page.get('count')
        return self.page
