// Copyright 2015 Matthew Holt and The Caddy Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package caddyhttp

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"testing"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func TestMarshalLogTLSConnState(t *testing.T) {
	for i, tc := range []struct {
		name  string
		state tls.ConnectionState
		curve float64
	}{
		{
			name: "hybrid post-quantum key exchange",
			state: tls.ConnectionState{
				Version:     tls.VersionTLS13,
				CipherSuite: tls.TLS_AES_256_GCM_SHA384,
				CurveID:     tls.X25519MLKEM768,
			},
			curve: 4588,
		},
		{
			name: "no key exchange",
			state: tls.ConnectionState{
				Version:     tls.VersionTLS12,
				CipherSuite: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
			curve: 0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			encoderCfg := zapcore.EncoderConfig{MessageKey: "msg"}
			core := zapcore.NewCore(zapcore.NewJSONEncoder(encoderCfg), zapcore.AddSync(&buf), zapcore.DebugLevel)
			zap.New(core).Info("test", zap.Object("tls", LoggableTLSConnState(tc.state)))

			var out map[string]any
			if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
				t.Fatalf("Test %d (%s): decoding log entry: %v; log: %s", i, tc.name, err, buf.String())
			}
			tlsObj, ok := out["tls"].(map[string]any)
			if !ok {
				t.Fatalf("Test %d (%s): expected a tls object, got %#v", i, tc.name, out["tls"])
			}
			if got := tlsObj["curve"]; got != tc.curve {
				t.Fatalf("Test %d (%s): curve = %v, want %v", i, tc.name, got, tc.curve)
			}
		})
	}
}
