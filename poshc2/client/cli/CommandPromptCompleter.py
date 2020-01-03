import re
import glob
from prompt_toolkit.document import Document
from prompt_toolkit.completion import FuzzyWordCompleter, Completer, CompleteEvent, Completion
from typing import Callable, Dict, Iterable, List, Optional, Union


class FirstWordFuzzyWordCompleter(Completer):

    def __init__(self, words: Union[List[str], Callable[[], List[str]]],
                 meta_dict: Optional[Dict[str, str]] = None,
                 WORD: bool = False) -> None:

        self.words = words
        self.meta_dict = meta_dict or {}
        self.WORD = WORD

        self.fuzzy_word_completer = FuzzyWordCompleter(words=self.words, WORD=self.WORD)

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        pattern = re.compile(r"^[^\s]*$")
        if not pattern.match(document.text.strip()):
            return []
        return self.fuzzy_word_completer.get_completions(document, complete_event)


class FilePathCompleter(Completer):

    def __init__(self, path, glob: '*', meta_dict: Optional[Dict[str, str]] = None, WORD: bool = False) -> None:

        self.meta_dict = meta_dict or {}
        self.WORD = WORD
        self.path = path
        if not self.path.endswith("/"):
            self.path = self.path + "/"
        self.glob = glob

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        pattern = re.compile(r"^[^\s]*$")
        if not pattern.match(document.text.strip()):
            return []
        words = [x.replace(self.path, "") for x in glob.glob(self.path + document.text.strip() + self.glob)]
        return FuzzyWordCompleter(words=words, WORD=self.WORD).get_completions(document, complete_event)
