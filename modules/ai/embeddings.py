"""
r3con v7.2 - ML Embeddings Engine PRO
TF-IDF + sentence-transformers + cosine similarity for RAG
Offline-first with fallback
"""
from __future__ import annotations
from typing import Dict, List, Any, Tuple
from pathlib import Path
import re
import math
from collections import Counter, defaultdict

class TFIDFEmbedder:
    """TF-IDF embedder 100% offline - no external deps."""

    def __init__(self):
        self.vocab: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.doc_count = 0
        self.fitted = False

    def _tokenize(self, text: str) -> List[str]:
        # Simple tokenization + normalization
        text = text.lower()
        # Keep code tokens
        tokens = re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}|[a-zA-Z]{2,}", text)
        # Filter stopwords
        stopwords = {"the", "and", "or", "is", "are", "was", "were", "in", "on", "at", "to", "for", "of", "with", "by", "this", "that", "it", "as", "an", "a", "be", "have", "has", "had", "will", "would", "can", "could", "should", "from", "not", "but", "what", "when", "where", "how", "why"}
        return [t for t in tokens if t not in stopwords and len(t) >= 2]

    def fit(self, documents: List[str]):
        """Fit TF-IDF on documents."""
        self.doc_count = len(documents)
        if self.doc_count == 0:
            return

        # Build vocab and document frequencies
        doc_freq = Counter()
        all_tokens = set()

        for doc in documents:
            tokens = set(self._tokenize(doc))
            all_tokens.update(tokens)
            for token in tokens:
                doc_freq[token] += 1

        # Create vocab index
        self.vocab = {token: idx for idx, token in enumerate(sorted(all_tokens))}

        # Calculate IDF
        self.idf = {}
        for token, freq in doc_freq.items():
            # Smooth IDF
            self.idf[token] = math.log((self.doc_count + 1) / (freq + 1)) + 1

        self.fitted = True

    def transform(self, text: str) -> Dict[int, float]:
        """Transform text to TF-IDF vector (sparse)."""
        if not self.fitted:
            return {}

        tokens = self._tokenize(text)
        if not tokens:
            return {}

        tf = Counter(tokens)
        total = len(tokens)

        vector = {}
        for token, count in tf.items():
            if token in self.vocab:
                tf_val = count / total
                idf_val = self.idf.get(token, 1.0)
                vector[self.vocab[token]] = tf_val * idf_val

        return vector

    def transform_dense(self, text: str) -> List[float]:
        """Transform to dense vector."""
        if not self.fitted or not self.vocab:
            return []

        sparse = self.transform(text)
        dense = [0.0] * len(self.vocab)
        for idx, val in sparse.items():
            if idx < len(dense):
                dense[idx] = val
        return dense

    def cosine_similarity(self, vec1: Dict[int, float], vec2: Dict[int, float]) -> float:
        """Cosine similarity for sparse vectors."""
        if not vec1 or not vec2:
            return 0.0

        # Dot product
        dot = 0.0
        for idx, val in vec1.items():
            if idx in vec2:
                dot += val * vec2[idx]

        # Norms
        norm1 = math.sqrt(sum(v*v for v in vec1.values()))
        norm2 = math.sqrt(sum(v*v for v in vec2.values()))

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot / (norm1 * norm2)

class SentenceTransformerEmbedder:
    """Sentence-transformers wrapper - optional heavy dependency."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self.model = None
        self.available = False
        self._try_load()

    def _try_load(self):
        try:
            from sentence_transformers import SentenceTransformer
            self.model = SentenceTransformer(self.model_name)
            self.available = True
        except ImportError:
            self.available = False
        except Exception:
            self.available = False

    def encode(self, texts: List[str]) -> List[List[float]]:
        if not self.available or not self.model:
            return []

        try:
            embeddings = self.model.encode(texts, show_progress_bar=False)
            return [emb.tolist() if hasattr(emb, 'tolist') else list(emb) for emb in embeddings]
        except Exception:
            return []

    def similarity(self, emb1: List[float], emb2: List[float]) -> float:
        if not emb1 or not emb2:
            return 0.0

        dot = sum(a*b for a, b in zip(emb1, emb2))
        norm1 = math.sqrt(sum(a*a for a in emb1))
        norm2 = math.sqrt(sum(b*b for b in emb2))

        if norm1 == 0 or norm2 == 0:
            return 0.0

        return dot / (norm1 * norm2)

class MLEmbeddingsEngine:
    """Unified ML Embeddings Engine - TF-IDF + sentence-transformers + hybrid."""

    def __init__(self, use_transformers: bool = True):
        self.tfidf = TFIDFEmbedder()
        self.transformer = SentenceTransformerEmbedder() if use_transformers else None
        self.use_transformers = use_transformers and (self.transformer.available if self.transformer else False)
        self.documents: List[str] = []
        self.doc_embeddings_tfidf: List[Dict[int, float]] = []
        self.doc_embeddings_transformer: List[List[float]] = []
        self.fitted = False

    def fit(self, documents: List[str]):
        """Fit on documents."""
        self.documents = documents
        if not documents:
            return

        # TF-IDF
        self.tfidf.fit(documents)
        self.doc_embeddings_tfidf = [self.tfidf.transform(doc) for doc in documents]

        # Transformer
        if self.use_transformers:
            self.doc_embeddings_transformer = self.transformer.encode(documents)

        self.fitted = True

    def search(self, query: str, top_k: int = 5, method: str = "hybrid") -> List[Dict[str, Any]]:
        """Search most similar documents to query."""
        if not self.fitted or not self.documents:
            return []

        results = []

        if method in ("tfidf", "hybrid"):
            query_vec = self.tfidf.transform(query)
            for idx, doc_vec in enumerate(self.doc_embeddings_tfidf):
                sim = self.tfidf.cosine_similarity(query_vec, doc_vec)
                results.append({
                    "index": idx,
                    "document": self.documents[idx],
                    "score": sim,
                    "method": "tfidf",
                })

        if method in ("transformer", "hybrid") and self.use_transformers:
            query_emb = self.transformer.encode([query])
            if query_emb and self.doc_embeddings_transformer:
                q_emb = query_emb[0]
                for idx, doc_emb in enumerate(self.doc_embeddings_transformer):
                    sim = self.transformer.similarity(q_emb, doc_emb)
                    # Merge with TF-IDF if hybrid
                    if method == "hybrid":
                        # Find existing result for this index
                        existing = next((r for r in results if r["index"] == idx), None)
                        if existing:
                            # Weighted average: 0.6 transformer + 0.4 tfidf
                            existing["score"] = 0.6 * sim + 0.4 * existing["score"]
                            existing["method"] = "hybrid"
                            existing["tfidf_score"] = existing["score"]
                            existing["transformer_score"] = sim
                        else:
                            results.append({
                                "index": idx,
                                "document": self.documents[idx],
                                "score": sim,
                                "method": "transformer",
                            })
                    else:
                        results.append({
                            "index": idx,
                            "document": self.documents[idx],
                            "score": sim,
                            "method": "transformer",
                        })

        # Sort by score desc
        results.sort(key=lambda x: x["score"], reverse=True)

        return results[:top_k]

    def cluster(self, n_clusters: int = 3) -> Dict[str, Any]:
        """Simple clustering via k-means on TF-IDF (heuristic)."""
        if not self.fitted or not self.documents:
            return {"status": "error", "error": "not_fitted"}

        # Simple k-means on dense TF-IDF vectors
        try:
            dense_vectors = [self.tfidf.transform_dense(doc) for doc in self.documents]
            if not dense_vectors or not dense_vectors[0]:
                return {"status": "error", "error": "empty_vectors"}

            # Initialize centroids randomly (first n docs)
            centroids = dense_vectors[:n_clusters]

            # 10 iterations k-means
            for _ in range(10):
                clusters = [[] for _ in range(n_clusters)]

                # Assign
                for idx, vec in enumerate(dense_vectors):
                    # Find closest centroid
                    best_cluster = 0
                    best_dist = float('inf')
                    for c_idx, centroid in enumerate(centroids):
                        # Euclidean distance
                        dist = sum((a-b)**2 for a, b in zip(vec, centroid))
                        if dist < best_dist:
                            best_dist = dist
                            best_cluster = c_idx
                    clusters[best_cluster].append(idx)

                # Update centroids
                new_centroids = []
                for cluster in clusters:
                    if not cluster:
                        new_centroids.append(centroids[len(new_centroids)])
                        continue
                    # Mean
                    mean = [0.0] * len(dense_vectors[0])
                    for idx in cluster:
                        for i, val in enumerate(dense_vectors[idx]):
                            mean[i] += val
                    mean = [v / len(cluster) for v in mean]
                    new_centroids.append(mean)
                centroids = new_centroids

            # Format result
            clustered = []
            for c_idx, cluster in enumerate(clusters):
                clustered.append({
                    "cluster_id": c_idx,
                    "size": len(cluster),
                    "documents": [self.documents[i][:200] for i in cluster[:5]],
                    "indices": cluster,
                })

            return {
                "status": "ok",
                "engine": "kmeans_tfidf",
                "n_clusters": n_clusters,
                "clusters": clustered,
            }

        except Exception as e:
            return {"status": "error", "error": str(e)[:500]}

    def get_stats(self) -> Dict[str, Any]:
        return {
            "fitted": self.fitted,
            "doc_count": len(self.documents),
            "vocab_size": len(self.tfidf.vocab),
            "use_transformers": self.use_transformers,
            "transformer_available": self.transformer.available if self.transformer else False,
            "transformer_model": self.transformer.model_name if self.transformer else None,
        }
