// Copyright 2017 Kudelski Security and orijtech, Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package prunehorst

import (
	"testing"
)

func BenchmarkRandomBytes(b *testing.B) {
	var sk []byte
	var err error
	for i := 0; i < b.N; i++ {
		sk, err = randomBytes(10000)
	}
	if len(sk) > 0 {
	}
	if err != nil {
	}
	b.ReportAllocs()
}

func BenchmarkKeyPair(b *testing.B) {
	var pkSink, skSink []byte
	for i := 0; i < b.N; i++ {
		pkSink, skSink, _ = KeyPair()
		if len(pkSink) > 0 {
		}
		if len(skSink) > 0 {
		}
	}
	b.ReportAllocs()
}
