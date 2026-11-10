"""Ingestion source abstraction. Implementations return normalized page text and stable source metadata."""
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from pypdf import PdfReader
from docx import Document as WordDocument

@dataclass
class SourceDocument:
    external_document_id: str
    title: str
    file_type: str
    pages: list[tuple[int|None,str]]
    modified_at: datetime|None = None

class BaseConnector(ABC):
    @abstractmethod
    async def fetch(self, source_id: str) -> SourceDocument: ...

class UploadConnector(BaseConnector):
    """Normalize an uploaded PDF/DOCX/TXT/Markdown file into page-aware text."""
    async def fetch(self, source_id: str) -> SourceDocument:
        path=Path(source_id); ext=path.suffix.lower()
        if ext==".pdf":
            pages=[(idx+1,page.extract_text() or "") for idx,page in enumerate(PdfReader(str(path)).pages)]
        elif ext==".docx":
            pages=[(1,"\n".join(p.text for p in WordDocument(str(path)).paragraphs))]
        elif ext in (".txt",".md"):
            pages=[(1,path.read_text(encoding="utf-8",errors="replace"))]
        else: raise ValueError("Supported formats are PDF, DOCX, TXT, and MD")
        return SourceDocument(path.name,path.stem,ext.lstrip("."),pages)
