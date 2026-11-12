# Security changelog

Security-relevant findings and fixes for Docwraith, newest first. Docwraith parses
attacker-controlled files, so the threat model throughout is a hostile input
trying to harm or mislead the analyst who runs the tool. Functional and feature
changes live in the git history and the README, not here.

Severity reflects impact on the analyst running the scan, not on any document
author.

## 0.15.0

Execution isolation, the safety item the external review named as the missing
piece, plus a depth bound on nested containers.

### Process isolation

Each file is now scanned in a child process with an OS-enforced memory limit,
CPU-time limit and wall-clock timeout (`--isolate`, on by default on Linux and
macOS). If a document drives a parser into an allocation bomb, an infinite loop
or a crash, the kernel kills the child and the file is reported as an incomplete
scan while the run continues. This is the containment for the one safety risk
the tool cannot remove on its own, a bug in a parser dependency (pypdf, Pillow,
tesseract, msoffcrypto): isolation bounds its blast radius to a single file. A
`Dockerfile` and a "Running against untrusted input safely" README section add
the deployment-level sandbox (no network, read-only filesystem, dropped
capabilities, non-root) that confines filesystem and network reach as well.

### Nested-container depth bound

Archives nested inside archives and files embedded in PDFs are now followed, up
to `max_archive_depth` (default 3), with anything deeper reported as not
expanded rather than ignored or followed without bound. Each extracted member
is still subject to the member-count, total-size and per-member-size caps at
every level.

## 0.14.0

Fixes from an external source-code review (an independent audit by another
model), which confirmed one issue with a dynamic reproduction and raised
several more. The review's framing is adopted: scanner robustness and detection
accuracy are separate problems, and an incomplete scan must be a distinct
outcome from a clean one.

### SEC-010 (High) Duplicate archive member names could hide a member

- **What.** Each extracted member was written to a path derived from its name.
  Two members with the same name resolved to the same path, so a later member
  overwrote an earlier one, and both scan results pointed at the later file.
- **Impact.** An attacker could place a malicious document first and a benign
  one with the same name second. The malicious copy was overwritten before
  scanning and never analyzed, a silent detection bypass. Confirmed by dynamic
  reproduction in the external review.
- **Fix.** Each member is extracted under its own index-prefixed directory, so
  identical names cannot collide. The reported provenance name is unchanged.
- **Verification.** `test_duplicate_archive_members_both_scanned`.

### SEC-011 (High) Encrypted-Office decryption had no output-size cap

- **What.** The decrypted plaintext was streamed to a temp file with no size
  limit (noted as a residual in 0.13.1).
- **Impact.** A crafted encrypted file could decrypt to an enormous plaintext
  and fill the temp disk before any document-level guard applied.
- **Fix.** Decryption now writes through a size-limited wrapper that aborts past
  the configured total-size cap.
- **Verification.** `test_capped_writer_aborts`.

### SEC-012 (Medium-High) PDF parsing was not bounded by the resource caps

- **What.** The configured caps bounded archives, not PDF processing. Page count
  and per-page content-stream operation count were unbounded.
- **Impact.** A PDF with very many pages or a huge content stream could drive
  excessive memory and CPU in a scanner worker.
- **Fix.** A page-count cap and a per-page operation cap now apply, each
  recording an explicit incompleteness error when hit.
- **Residual.** These are in-process bounds. A single oversized object can still
  allocate inside pypdf before the cap applies, so untrusted PDFs should run
  under an OS memory and CPU limit, ideally in a disposable worker.

### SEC-013 (Medium) Direct Office scans skipped the member-count cap

- **What.** `max_members` was enforced only on the archive-extraction path.
  Office documents opened directly used a size check without a member-count
  check, and `scan_docx` had its own inline guard that omitted it entirely.
- **Impact.** A crafted Office document with a huge number of tiny zip members
  could consume excess memory or time.
- **Fix.** The shared `zip_size_guard` now enforces member count and total size,
  and every Office scanner, docx included, routes through it.
- **Verification.** `test_office_member_count_cap`.

### SEC-014 (Medium) Incomplete scans could look like clean results

- **What.** A parse failure was recorded as an error, but a file with both a
  finding and an unscanned malformed component returned the detection exit code
  with no separate signal that coverage was incomplete.
- **Impact.** A tool that looks for hidden content must distinguish "nothing
  found" from "not everything was inspected". CI relying on the exit code or a
  clean report could miss that a document was only partially analyzed.
- **Fix.** Completeness is now a first-class outcome: the JSON summary carries
  `scan_complete`, the SARIF run sets `executionSuccessful` to it, and the text
  report prints an explicit INCOMPLETE line. Any scan error makes a run
  incomplete even when findings were produced.
- **Verification.** `test_incomplete_scan_is_explicit`, `test_clean_scan_is_complete`.

### SEC-015 (Low-Medium) Standard-library XML fallback did not fail closed

- **What.** Without defusedxml the tool parsed with the standard library after a
  warning, including documents that declare a DTD.
- **Impact.** The standard library's resistance to entity-expansion attacks
  varies by version, so parsing DTD-bearing documents without defusedxml is an
  avoidable risk for a tool handling adversarial input.
- **Fix.** Without defusedxml, a document that declares a DTD is refused rather
  than parsed. Ordinary documents, which carry no DTD, are unaffected.
- **Verification.** `test_xml_doctype_failclosed_without_defusedxml`.

### SEC-016 (Low) Encoded-payload inspection budget could be flooded

- **What.** The base64 and hex decoder stopped after 12 candidate runs, counting
  every candidate including failed decodes.
- **Impact.** An attacker could place a wall of junk encoded runs ahead of the
  real payload to exhaust the budget, so the real payload was never decoded.
- **Fix.** The budget now counts decoded work with a far larger ceiling, caps
  reports separately, and emits an explicit "not fully inspected" finding when
  the ceiling is reached, rather than passing silently.
- **Verification.** `test_encoded_decoy_flood_does_not_bury_payload`.

### Detection-completeness gaps (acknowledged, not host-security issues)

The external review also listed detection gaps already recorded in the README's
"What Docwraith cannot detect" section: Excel formula and numeric-cell content,
hidden rows and columns and per-cell formatting, PDF optional-content layer
separation, image coverage when OCR is off, and full PDF rendering-state
modeling for occlusion. These affect detection accuracy, not the safety of the
host, and remain on the roadmap.

## 0.13.1

Second security review, covering the code added since 0.5.0: the PowerPoint,
Excel and OpenDocument parsers, external-reference and comment extraction, the
integrity checks, SARIF output, password handling, the encoded-payload decoder
and OCR. No injection, deserialization or command-execution surface was found
(no eval, exec, subprocess, pickle or yaml in the code; OCR shells out only
through pytesseract, which passes a temp-file path as a list argument, never a
shell string). Three defects were fixed and the residual risks are recorded.

### SEC-007 (Medium) Unbounded image decode on the OCR path

- **What.** With `--ocr`, embedded images are decoded before OCR. The per-image
  pixel cap was checked after decoding, and PIL's own ceiling (about 89
  megapixels) sits far above the tool's 25-megapixel cap.
- **Impact.** A document carrying an oversized image could cause a large memory
  allocation during decode before the cap applied. A decompression-style image
  bomb under `--ocr`.
- **Fix.** The zip-media path reads the image dimensions from the header and
  skips before `load()`, and PIL's global `MAX_IMAGE_PIXELS` is lowered to the
  configured cap before any decode, so an oversized image is refused at decode
  time on both the zip and PDF paths.
- **Verification.** Regression test `test_ocr_pixel_cap_enforced_at_decode`.
- **Residual.** A raw-encoded image in a PDF is built by pypdf from the object's
  declared width and height, which can allocate before PIL's open-time check
  applies. OCR is opt-in; run it under a memory ulimit for untrusted PDFs.

### SEC-008 (Low) Uncaught decoder crash on a non-UTF-8 option file

- **What.** `--password-file` and `--find-file` read their file as UTF-8 and did
  not catch `UnicodeDecodeError`, so a non-UTF-8 file crashed the tool with a
  traceback instead of a clean error.
- **Impact.** Availability and polish, not a memory-safety issue: the inputs are
  user-supplied, not attacker documents. A traceback is a poor failure mode for
  a tool run in a pipeline.
- **Fix.** Both paths now catch `UnicodeDecodeError` and exit through the normal
  argument-error path.
- **Verification.** Regression tests `test_binary_password_file_does_not_crash`
  and `test_binary_find_file_does_not_crash`.

### SEC-009 (Low) Nested encrypted-container recursion

- **What.** An encrypted Office file is decrypted to a temp file and rescanned.
  Nothing stopped a crafted file that decrypts to another encrypted container
  from recursing.
- **Impact.** A deliberately nested encrypted file could recurse until the stack
  or temp disk filled. Reaching it needs the optional msoffcrypto dependency and
  the correct password, so exposure is narrow.
- **Fix.** After decryption the result is type-sniffed; if it is again an
  encrypted container it is reported, not rescanned.

### Residual risks (accepted, documented)

- **Deeply nested XML.** A document with extreme element nesting can exhaust the
  recursion limit in the tree walk. It is caught per file and reported as a scan
  error rather than crashing the run, but it is not defended beyond that.
- **Parser dependencies.** pypdf, Pillow, tesseract and msoffcrypto parse hostile
  input. A bug in any of them is exposure the tool cannot prevent. Keep them
  current, and prefer running untrusted batches in a sandbox.
- **No decrypted-size cap.** msoffcrypto decryption writes the plaintext package
  to a temp file with no size ceiling, so a crafted encrypted bomb could fill
  temp space. The decrypted file is then subject to the normal archive caps.

## 0.5.0

Security review of the whole project. One real vulnerability, one case where the
documentation claimed a control that was not actually enforced, and several
hardening items.

### SEC-001 (High): Denial of service via crafted tar/tar.gz

- **What.** The tar path enumerated members with `tarfile.getmembers()`, which
  is eager: it decompresses the entire stream up front to build the member
  list. Size checks ran only afterward, per candidate member.
- **Impact.** A small `.tar.gz` could force decompression of a very large
  logical stream (a classic compression bomb), and an archive with a huge
  number of entries could exhaust memory building the member list, before any
  cap applied. Either hangs or crashes the scanning host.
- **Fix.** Switched to lazy iteration (`for m in tf:`), added a member-count cap
  (`max_members`, default 10000), and added a running size budget that counts
  every member rather than only extracted documents, so extraction aborts at
  the first guard instead of after full decompression.
- **Verification.** A 100000-member `.tar.gz` that previously walked the whole
  archive now aborts in about 0.3 seconds with `archive has more than 10000
  members`. Regression tests `test_archive_member_count_cap` and
  `test_archive_size_budget_counts_all_members`.

### SEC-002 (Medium): Decompression cap trusted the archive header

- **What.** `_copy_capped` wrote member contents with `shutil.copyfileobj` and
  no hard output limit. It relied on the size the archive declared, which the
  attacker controls. The README claimed extraction "rejects a decompression
  bomb," so the documented control was stronger than the code.
- **Impact.** A member whose header understated its real decompressed size could
  write more to disk than the per-member cap intended. In practice `zipfile`
  stops at the declared size, so zip was safe, but relying on that behavior
  rather than enforcing a limit is not a control.
- **Fix.** `_copy_capped` now counts bytes actually written, aborts past
  `max_member_bytes`, and deletes the partial file. The cap holds regardless of
  what any header claims.
- **Verification.** Regression test `test_copy_capped_hard_limit` (a stream
  longer than the cap raises and leaves no file).

### SEC-003 (Medium): Terminal escape injection via report output

- **What.** Finding snippets are quoted verbatim from the scanned document.
  Normalization stripped format characters but not C0/C1 control bytes, so an
  escape sequence in a document survived into the text report.
- **Impact.** A crafted document could embed ANSI escape sequences that rewrite
  the analyst's terminal when the report is viewed, including clearing the
  screen or forging a fabricated finding line. This is log/terminal injection,
  a real risk for a tool whose whole job is printing hostile content.
- **Fix.** The text report renders every control character, DEL, C1 byte and
  Unicode line separator as a visible `\xNN` escape (`sanitize()`), applied to
  snippets, messages, locations, hidden-reason labels and error text. JSON
  output was already safe because `json.dumps` escapes these.
- **Verification.** Regression tests `test_sanitize_unit` and
  `test_terminal_escapes_sanitized_in_report`.

### SEC-004 (Medium): Silent fall back to an unsafe XML parser

- **What.** `defusedxml` was optional. When it was absent the tool silently used
  the standard-library XML parser, and the only signal was a field in the JSON
  output.
- **Impact.** Without `defusedxml`, a malicious OOXML document gets the weaker
  parser, which is more exposed to entity-expansion ("billion laughs") attacks.
  An analyst had no obvious warning they were running without the hardened path.
- **Fix.** The tool now prints a prominent stderr warning when it falls back,
  and the README documents `defusedxml` as the recommended control for
  untrusted input.
- **Residual.** Making `defusedxml` a hard requirement was considered and not
  taken, to keep the tool runnable on a bare install; the warning is the
  compromise.

### SEC-005 (Low): Directory walk could follow symlinks

- **What.** The recursive directory walk used `Path.rglob`, which can descend
  through symlinked directories.
- **Impact.** A symlink inside a scanned tree could steer the scan outside the
  intended directory, or a symlink cycle could make it loop.
- **Fix.** The walk uses `os.walk(followlinks=False)` and skips symlinked files,
  so only real files inside the named tree are scanned.
- **Verification.** Regression test `test_symlink_in_directory_not_followed`.

### SEC-006 (Low): Unbounded whole-file reads

- **What.** The raw-byte provenance sweep and the raw-byte search read the whole
  file into memory with `path.read_bytes()`.
- **Impact.** A very large input could cause excess memory use during these
  byte-level sweeps.
- **Fix.** Both now read at most `max_member_bytes` via `read_bytes_capped`. The
  structured parsers still see the whole document through their own readers;
  only the supplementary byte sweeps are capped.

### Residual risks (accepted, documented in the README)

- **PDF parser trust.** The PDF path relies on `pypdf` to parse untrusted PDFs.
  A parser bug there is exposure Docwraith cannot prevent. Keep `pypdf` current.
- **No in-process resource limit.** There is no wall-clock or memory ceiling
  inside the process. For bulk or hostile input, run under `timeout` and a
  memory `ulimit`, ideally as an unprivileged user in a container.
- **RAR external tool.** RAR extraction shells out to `unrar`, `unar`, `bsdtar`
  or `7z` through `rarfile`. Those tools carry their own vulnerability history.
  Treat `.rar` as the highest-risk input and keep the backend patched. zip and
  tar require no external tool.
- **Independent review.** The 0.5.0 review was performed by the same party that
  wrote the code. SEC-001 was found by testing rather than reading, which is
  exactly the kind of bug an author's own review tends to miss. An independent
  review is still worthwhile before relying on this on hostile input at scale.

## 0.1.0 (baseline)

Initial controls shipped from the start, noted here for completeness:

- `defusedxml` preferred for OOXML parsing when available.
- Per-member read cap when reading docx parts (`read_member`).
- Archive member extraction confined to a temporary directory with
  path-traversal (zip-slip / tar `..`) rejection and symlink/hardlink member
  skipping.
- Content-based file type detection, so a renamed file is classified correctly
  rather than trusted by extension.
