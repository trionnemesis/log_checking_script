from __future__ import annotations
"""簡易的 FAISS 向量儲存，供日誌嵌入使用"""

import hashlib
import logging
import os
from pathlib import Path
from typing import List, Optional, Tuple

from .. import config

try:
    import faiss
except ImportError:  # pragma: no cover - optional
    faiss = None  # type: ignore

try:
    from sentence_transformers import SentenceTransformer
    EMBEDDING_MODEL_NAME_DEFAULT = 'paraphrase-multilingual-MiniLM-L12-v2'
    EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", EMBEDDING_MODEL_NAME_DEFAULT)
    SENTENCE_MODEL: Optional[SentenceTransformer] = SentenceTransformer(EMBEDDING_MODEL_NAME)
    if SENTENCE_MODEL:
        EMBED_DIM = SENTENCE_MODEL.get_sentence_embedding_dimension()
    else:
        EMBED_DIM = 384
except Exception:  # pragma: no cover - optional
    SENTENCE_MODEL = None
    EMBED_DIM = 384

logger = logging.getLogger(__name__)


def embed(text: str) -> List[float]:
    """取得文字的向量表示

    若系統已安裝 `sentence-transformers` 會直接產生真正的嵌入；
    否則使用 SHA-256 雜湊計算出假向量，方便在無依賴環境下測試。
    """

    if SENTENCE_MODEL:
        return SENTENCE_MODEL.encode(text, convert_to_numpy=True).tolist()
    digest = hashlib.sha256(text.encode('utf-8', 'replace')).digest()
    vec_template = list(digest)
    vec = []
    while len(vec) < EMBED_DIM:
        vec.extend(vec_template)
    return [v / 255.0 for v in vec[:EMBED_DIM]]


class VectorIndex:
    """封裝 FAISS Index，負責載入、儲存與查詢"""

    def __init__(self, path: Path, dimension: int) -> None:
        self.path = path
        self.dimension = dimension
        self.index: Optional[faiss.Index] = None  # type: ignore
        self._load()

    def _load(self):
        """讀取既有索引檔，如無則建立新索引"""

        if faiss is None:
            logger.warning("Faiss not installed; vector search disabled")
            return
        if self.path.exists():
            try:
                self.index = faiss.read_index(str(self.path))
                logger.info(f"Loaded FAISS index from {self.path}")
            except Exception as e:
                logger.error(f"Failed loading FAISS index: {e}")
                self.index = faiss.IndexFlatL2(self.dimension)
        else:
            self.index = faiss.IndexFlatL2(self.dimension)

    def save(self):
        """將索引寫入磁碟"""

        if faiss and self.index is not None:
            try:
                faiss.write_index(self.index, str(self.path))
                logger.info(f"Saved FAISS index to {self.path}")
            except Exception as e:
                logger.error(f"Failed saving FAISS index: {e}")

    def search(self, vec: List[float], k: int = 5) -> Tuple[List[int], List[float]]:
        """在索引中搜尋並回傳 (ids, 距離)"""

        import numpy as np
        if faiss is None or self.index is None or self.index.ntotal == 0:
            return [], []
        q = np.array([vec], dtype=np.float32)
        dists, ids = self.index.search(q, k)
        return ids[0].tolist(), dists[0].tolist()

    def add(self, vecs: List[List[float]]):
        """新增多個向量至索引"""

        import numpy as np
        if faiss and self.index is not None:
            to_add = np.array(vecs, dtype=np.float32)
            self.index.add(to_add)


VECTOR_DB = VectorIndex(config.VECTOR_DB_PATH, EMBED_DIM)
