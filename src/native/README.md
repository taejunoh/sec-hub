# macOS directory ACL reader

`darwin-acl-reader` is a bundled, ad-hoc signed universal executable containing
arm64 and x86_64 slices. The CLI invokes it directly with an already opened
directory inherited as descriptor 3. It performs no pathname lookup, writes,
network access or subprocess launch. Only macOS libSystem is required.

The reader checks directory metadata and extended ACLs using public macOS APIs.
It accepts an absent/empty ACL or DENY-only entries, and rejects ALLOW entries,
unknown entries and native inspection failures. `acl_get_fd_np` may report
ENOENT for an absent ACL: ENOENT alone is never accepted. A second successful
same-descriptor `fstatx_np` query must establish the absent property and matching
owner, mode and file identity. Darwin's documented EINVAL iterator exhaustion
is accepted only after `acl_valid` on the owned ACL copy.

The Node caller requires an exact success token, zero exit, no signal and empty
stderr, with a five-second deadline and 4 KiB combined output limit. Missing or
unusable binaries fail closed; there is no runtime compilation or fallback to
`ls`. Root and same-effective-uid processes remain trusted. This is permission
boundary enforcement, not confinement against a same-user attacker.

Maintainers can rebuild with Node and Xcode command-line tools on macOS:

```sh
node src/native/build-darwin-acl-reader.mjs
mkdir -p /path/to/rebuild
node src/native/build-darwin-acl-reader.mjs /path/to/rebuild/darwin-acl-reader
```

For reproducible bytes use the same C source, compiler/SDK, flags and output
basename `darwin-acl-reader`. The build script prints these inputs and hashes,
builds both architectures, signs with a fixed identifier and no timestamp, then
verifies both signatures. Modern dyld requires LC_UUID; the normal linker UUID
is retained and builds with the same basename were verified byte-identical
across separate directories. A changed toolchain may produce a different hash.

The shipped binary, this source and build script are included by the package's
`src/` rule. Tests verify package inclusion, executable permissions and a real
packed write without PATH tools. Native API fault-injection tests compile only
in the development test suite when Xcode is available; normal CLI execution
never invokes the build script.
