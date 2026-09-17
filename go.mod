module github.com/dogukanturhal/jess

go 1.26.0

// Skeleton: dependencies are kept as comments until the data plane is
// implemented (ADR 0030 Phase 5), so the skeleton builds with no fetch.
// Researched library set (2026-05-27):
//   - golang.org/x/crypto/ssh                 SSH core + backend dial (BSD-3)
//   - github.com/charmbracelet/wish           SSH front / operator side (MIT)
//   - github.com/gliderlabs/ssh               SSH server framework (MIT)
//   - github.com/jackc/pgx/v5 (pgproto3)      Postgres wire proxy — NOT v4 (EOL) (MIT)
//   - github.com/hashicorp/yamux              reverse-tunnel stream mux (MPL-2.0)
//   - github.com/hashicorp/vault/api          SSH CA sign + dynamic DB creds + leases (MPL-2.0)
//   - github.com/spiffe/go-spiffe/v2          SVID mTLS for worker↔/operator↔controller (Apache-2.0)
//   - go.opentelemetry.io/otel                audit/trace to the shared funnel
// RDP rendering is a SEPARATE Rust worker (rust/rdp-render, Devolutions IronRDP) —
// not a Go dependency; Go ↔ Rust over a local UDS/gRPC.

require (
	github.com/coreos/go-oidc/v3 v3.18.0
	github.com/digitorus/timestamp v0.0.0-20250524132541-c45532741eea
	github.com/dogukanturhal/hexx-pep-core v1.1.0
	github.com/gliderlabs/ssh v0.3.8
	github.com/go-ldap/ldap/v3 v3.4.13
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/google/go-attestation v0.6.1
	github.com/google/go-tpm v0.9.8
	github.com/hashicorp/yamux v0.1.2
	github.com/jackc/pgx/v5 v5.9.2
	github.com/minio/minio-go/v7 v7.2.0
	github.com/prometheus/client_golang v1.23.2
	github.com/quic-go/quic-go v0.60.0
	github.com/quic-go/webtransport-go v0.11.0
	github.com/spiffe/go-spiffe/v2 v2.7.0
	golang.org/x/crypto v0.56.0
	golang.org/x/oauth2 v0.36.0
	k8s.io/api v0.31.4
	k8s.io/apimachinery v0.31.4
	k8s.io/client-go v0.31.4
)

require (
	github.com/Azure/go-ntlmssp v0.1.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/digitorus/pkcs7 v0.0.0-20230713084857-e76b763bdc49 // indirect
	github.com/dunglas/httpsfv v1.1.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.6 // indirect
	github.com/go-openapi/jsonreference v0.20.2 // indirect
	github.com/go-openapi/swag v0.22.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/gnostic-models v0.6.8 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/moby/spdystream v0.5.1 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
)

require (
	github.com/agnivade/levenshtein v1.2.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gorilla/websocket v1.5.3
	github.com/lestrrat-go/blackmagic v1.0.4 // indirect
	github.com/lestrrat-go/dsig v1.0.0 // indirect
	github.com/lestrrat-go/dsig-secp256k1 v1.0.0 // indirect
	github.com/lestrrat-go/httpcc v1.0.1 // indirect
	github.com/lestrrat-go/httprc/v3 v3.0.2 // indirect
	github.com/lestrrat-go/jwx/v3 v3.0.13 // indirect
	github.com/lestrrat-go/option/v2 v2.0.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/segmentio/asm v1.2.1 // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/tchap/go-patricia/v2 v2.3.3 // indirect
	github.com/valyala/fastjson v1.6.7 // indirect
	github.com/vektah/gqlparser/v2 v2.5.32 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/yashtewari/glob-intersection v0.2.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/go-mysql-org/go-mysql v1.15.0
	github.com/goccy/go-json v0.10.6 // indirect
	github.com/pingcap/errors v0.11.5-0.20260310054046-9c8b3586e4b2 // indirect
	github.com/pingcap/log v1.1.1-0.20260227082333-572e590d08f1 // indirect
	github.com/pingcap/tidb/pkg/parser v0.0.0-20260504140133-511dba1dbe17 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/google/uuid v1.6.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.18.6 // indirect
	github.com/klauspost/cpuid/v2 v2.2.11 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/open-policy-agent/opa v1.15.2
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.17.0 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.1 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.1 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/ini.v1 v1.67.2 // indirect
)
