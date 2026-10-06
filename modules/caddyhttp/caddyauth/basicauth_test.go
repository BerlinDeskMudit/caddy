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

package caddyauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/caddyserver/caddy/v2"
)

// testBasicAuthHash is a bcrypt hash (cost 4) of the plaintext "correct horse".
const testBasicAuthHash = "$2a$04$XziKIb5ayw0suaNwlK.1vOqOj9gEveGnkq.anOrdVrnkN5z1bA2A."

func TestBasicAuthProvisionKeepsUnknownPlaceholdersInUsername(t *testing.T) {
	hba := HTTPBasicAuth{
		AccountList: []Account{
			{Username: "alice-{not-a-placeholder}", Password: testBasicAuthHash},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := hba.Provision(ctx); err != nil {
		t.Fatalf("provisioning failed: %v", err)
	}

	if _, ok := hba.Accounts["alice-{not-a-placeholder}"]; !ok {
		t.Fatalf("expected an account for the username as configured, got accounts %q", accountUsernames(hba))
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("alice-{not-a-placeholder}", "correct horse")
	user, authenticated, err := hba.Authenticate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("unexpected authentication error: %v", err)
	}
	if !authenticated {
		t.Fatalf("expected authentication to succeed for the username as configured, got accounts %q", accountUsernames(hba))
	}
	if user.ID != "alice-{not-a-placeholder}" {
		t.Fatalf("expected user ID %q, got %q", "alice-{not-a-placeholder}", user.ID)
	}
}

func TestBasicAuthProvisionExpandsKnownPlaceholdersInUsername(t *testing.T) {
	t.Setenv("CADDYTEST_BASICAUTH_USER", "bob")

	hba := HTTPBasicAuth{
		AccountList: []Account{
			{Username: "{env.CADDYTEST_BASICAUTH_USER}", Password: testBasicAuthHash},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	if err := hba.Provision(ctx); err != nil {
		t.Fatalf("provisioning failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("bob", "correct horse")
	_, authenticated, err := hba.Authenticate(httptest.NewRecorder(), req)
	if err != nil {
		t.Fatalf("unexpected authentication error: %v", err)
	}
	if !authenticated {
		t.Fatalf("expected the known placeholder to expand, got accounts %q", accountUsernames(hba))
	}
}

func TestBasicAuthProvisionRejectsDuplicatedUsernamesAfterExpansion(t *testing.T) {
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()

	for i, tc := range []struct {
		name      string
		env       map[string]string
		usernames []string
		wantError bool
	}{
		{
			name:      "literal duplicates",
			usernames: []string{"carol", "carol"},
			wantError: true,
		},
		{
			name:      "distinct placeholders expanding to the same value",
			env:       map[string]string{"X": "carol", "Y": "carol"},
			usernames: []string{"{env.X}", "{env.Y}"},
			wantError: true,
		},
		{
			name:      "literal username colliding with a placeholder",
			env:       map[string]string{"Y": "carol"},
			usernames: []string{"carol", "{env.Y}"},
			wantError: true,
		},
		{
			name:      "same placeholder repeated",
			env:       map[string]string{"X": "carol"},
			usernames: []string{"{env.X}", "{env.X}"},
			wantError: true,
		},
		{
			name:      "distinct expansions",
			env:       map[string]string{"X": "carol", "Z": "dave"},
			usernames: []string{"{env.X}", "{env.Z}"},
			wantError: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			accounts := make([]Account, 0, len(tc.usernames))
			for _, username := range tc.usernames {
				accounts = append(accounts, Account{Username: username, Password: testBasicAuthHash})
			}
			hba := HTTPBasicAuth{AccountList: accounts}
			if err := hba.Provision(ctx); tc.wantError && err == nil {
				t.Fatalf("Test %d (%s): expected error, got none; accounts %q", i, tc.name, accountUsernames(hba))
			} else if !tc.wantError && err != nil {
				t.Fatalf("Test %d (%s): unexpected error: %v", i, tc.name, err)
			}
		})
	}
}

func TestBasicAuthProvisionRejectsBracedPasswordInsteadOfRewritingIt(t *testing.T) {
	hba := HTTPBasicAuth{
		AccountList: []Account{
			// a password field carries a hash (MCF or base64), neither of which
			// can contain braces, so a braced value can only be a mistake and
			// must not be quietly rewritten into different valid base64
			{Username: "alice", Password: "ab{cd}ef"},
		},
	}
	ctx, cancel := caddy.NewContext(caddy.Context{Context: context.Background()})
	defer cancel()
	err := hba.Provision(ctx)
	if err == nil {
		t.Fatalf("expected provisioning to fail for a password with literal braces, instead it accepted the rewritten password %q", hba.Accounts["alice"].password)
	}
}

func accountUsernames(hba HTTPBasicAuth) []string {
	names := make([]string, 0, len(hba.Accounts))
	for name := range hba.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
