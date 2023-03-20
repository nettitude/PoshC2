from typing import Optional

from prompt_toolkit.auto_suggest import Suggestion, AutoSuggest
from prompt_toolkit.document import Document


class AutoSuggestFromPoshExamples(AutoSuggest):
    """
    Give suggestions based on the lines examples of the helptext.
    """

    def __init__(self, examples):
        self.examples = examples

    def get_suggestion(self, buffer: "Buffer", document: Document) -> Optional[Suggestion]:

        for example in self.examples:
            if example.startswith(document.text.strip()):
                return Suggestion(example[len(document.text):])

        return None
