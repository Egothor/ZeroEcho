# Metadata benchmarks

The opt-in `:pki:metadataBenchmark` task runs JMH 1.37 on the repository's Java 25
toolchain. JMH and its annotation processor are confined to the
`metadataBenchmark` source set; they are not production dependencies and the
benchmark is not part of the ordinary test or build tasks.

Run from the repository root:

```bash
./gradlew :pki:metadataBenchmark --args='MetadataHotPathBenchmark -f 2 -wi 3 -w 1s -i 5 -r 1s -t 1 -bm avgt -tu ns -prof gc -jvmArgs "-Xms512m -Xmx512m" -rf json -rff build/reports/benchmarks/metadata.json'
```

The task uses the repository root as its working directory and creates
`build/reports/benchmarks`. Use different result filenames for before and after
measurements. Retain both JSON files, the source revision, benchmark source hash,
JDK version, operating system and processor details when comparing changes.
Run the same benchmark source, JVM settings and machine workload in both cases.
Avoid concurrent tests or other CPU-intensive work during measurements.

The fourteen cases measure implicit and explicit X.509 lookup for the first
classic signature rule (RSA/SHA-256), last classic signature rule (Ed448), first
PQC signature rule (ML-DSA-44), last PQC signature rule (SLH-DSA-SHAKE-256f),
nondefault RSA-PSS parameters (SHA-256 with 48-byte salt), and EC P-384 public-key
parameters, plus complete standard-binding and cryptographic parameter-set
catalog walks. Trial setup loads providers, resolves inputs, checks agreement of
both lookup forms and prints the actual catalog sizes. No key generation or
cryptographic operation is timed. Catalog walks retrieve descriptor collections
inside the measured operation and consume every descriptor through JMH's
blackhole; provider discovery happens before measurement.

The primary metric is average nanoseconds per operation; one walk operation
visits the complete catalog. The GC profiler records allocation per operation
and collection activity. JMH's score errors and per-fork measurements should be
considered alongside the means. These microbenchmarks do not establish server
throughput, certificate issuance latency, cold-start cost or a performance
guarantee. Correctness and compatibility are validated by separate tests.

For a short harness check, use one fork, no warmup, one 100 ms measurement and
omit GC profiling. Such a run is a smoke check, not performance evidence.
