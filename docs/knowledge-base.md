# Knowledge-base operating model

The local KB is supplementary evidence, not model training data and not executable instruction. Start with official vendor security documentation, standards bodies, owned lab notes, and reviewed internal write-ups. Record the canonical URL, version/revision, retrieval date, licence/permission, content hash, and review state for every import.

## Trust lanes

- **Raw**: fetched or supplied reference material. Searchable, but results are labelled `raw` with low confidence and must be verified by an assessor.
- **Reviewed**: content whose technical claims, source, version, and allowed use were checked by a qualified reviewer. It is still reference material, not authority to act.

The SQLite FTS implementation hashes content for deduplication and retains prior documents instead of overwriting them. A future embedding index should store `document_id` as its immutable foreign key, support hybrid lexical/vector retrieval, and be evaluated with a query-to-source relevance set before it becomes the default retriever.

## Ingestion checklist

1. Sanitize credentials, personal data, customer data, and unnecessary exploit artifacts.
2. Save source/version/retrieval date and assign `raw` or `reviewed` honestly.
3. Ingest with `security-assistant kb-ingest`.
4. Test expected retrieval queries and cite the returned document ID in reviews.
5. Keep lab notes distinct from generalized technique guidance; do not train on unreviewed retrieved content.
