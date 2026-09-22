# Win64 OWL overlay patches

Six BC4.52 sources need mdbcc's static-dispatcher and pointer-width changes for
the Win64 OWL build. Those originals are Borland and Microsoft copyright, so
this directory holds **only mdbcc's own edits**, as unified diffs. The patched
sources are built at compile time from your own BC4.52 tree and never enter the
repository.

`src/overlay.rs` applies them. `build_bc45_libs --target win64` and the
`railc_source_slice` / `owl_examples_product` harnesses each call it before any
Win64 job runs; all of them find the tree via `$MDBCC_BC45_ROOT`, else
`wrk_oracle/bc452/BC45`, else `C:\tmp\bc45`.

## Format

Each file is a plain `diff -U3` with LF line endings and two headers:

```
--- SOURCE/OWL/OWL.CPP     the original, relative to the BC4.52 root
+++ OWL.CPP                the output, relative to the generated overlay dir
```

The mapping therefore lives in the patches, not in the applier. Every hunk
applies at its stated old-line position with exact context matching; there is no
fuzz and no offset search, so a BC4.52 tree that differs from the one these were
cut against fails loudly rather than compiling something nobody wrote.

## Regenerating one

```sh
diff -U3 --strip-trailing-cr "$BC45/SOURCE/OWL/OWL.CPP" OWL.CPP
```

Keep the two header lines above in place of the ones `diff` emits, and keep the
result LF-terminated. The BC4.52 sources are CRLF; `--strip-trailing-cr` takes
the `\r` out of the patch, and the applier puts it back on output.
