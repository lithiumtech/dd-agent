# stdlib
from collections import namedtuple

WMIMetric = namedtuple('WMIMetric', ['name', 'value', 'tags'])

class InvalidWMIQuery(Exception):
    """
    Invalid WMI Query.
    """
    pass


class MissingTagBy(Exception):
    """
    WMI query returned multiple rows but no `tag_by` value was given.
    """
    pass


class TagQueryUniquenessFailure(Exception):
    """
    'Tagging query' did not return or returned multiple results.
    """
    pass
