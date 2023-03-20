from typing import Optional

from prompt_toolkit.auto_suggest import Suggestion, AutoSuggest
from prompt_toolkit.document import Document


class AutosuggestionAggregator(AutoSuggest):
    """
    Give suggestions based on the multiple other suggestors.

    The suggestors argument should be a list of other suggestors that are checked in the order the list is in.
    """

    def __init__(self, suggestors):
        self.suggestors = suggestors

    def get_suggestion(self, buffer: "Buffer", document: Document) -> Optional[Suggestion]:

        for suggestor in self.suggestors:
            suggestion = suggestor.get_suggestion(buffer, document)

            if suggestion:
                return suggestion

        return None
