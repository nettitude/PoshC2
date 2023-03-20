import glob
import re
from typing import Callable, Dict, Iterable, List, Optional, Union

from prompt_toolkit.completion import WordCompleter, Completer, CompleteEvent, Completion
from prompt_toolkit.document import Document


class FirstWordCompleter(Completer):

    def __init__(self, words: Union[List[str], Callable[[], List[str]]], meta_dict: Optional[Dict[str, str]] = None, WORD: bool = False) -> None:
        self.words = sorted(set(words))
        self.meta_dict = meta_dict or {}
        self.WORD = WORD

        self.word_completer = WordCompleter(words=self.words, WORD=self.WORD)

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        pattern = re.compile(r"^\S*$")
        if not pattern.match(document.text.strip()):
            return []
        return self.word_completer.get_completions(document, complete_event)


class FilePathCompleter(Completer):

    def __init__(self, path, glob: '*', meta_dict: Optional[Dict[str, str]] = None, WORD: bool = False) -> None:

        self.meta_dict = meta_dict or {}
        self.WORD = WORD
        self.path = path
        if not self.path.endswith("/"):
            self.path = self.path + "/"
        self.glob = glob

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        pattern = re.compile(r"^\S*$")
        if not pattern.match(document.text.strip()):
            return []
        words = [x.replace(self.path, "") for x in glob.glob(self.path + document.text.strip() + self.glob)]
        return WordCompleter(words=sorted(words), WORD=self.WORD).get_completions(document, complete_event)
