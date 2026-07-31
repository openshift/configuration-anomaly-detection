package main

import (
	"slices"
	"testing"
)

func TestLoadPDSignatures(t *testing.T) {
	tests := []struct {
		name     string
		envVar   string
		wantErr  bool
		wantSigs []string // every entry must appear in the returned slice
	}{
		{
			name:    "empty env var returns an error",
			envVar:  "",
			wantErr: true,
		},
		{
			name:     "single signature is loaded",
			envVar:   "secret-one",
			wantSigs: []string{"secret-one"},
		},
		{
			name:     "two comma-separated signatures are both loaded",
			envVar:   "secret-one,secret-two",
			wantSigs: []string{"secret-one", "secret-two"},
		},
		{
			name:     "two comma-separated signatures are both loaded even with extra whitespace",
			envVar:   " secret-one , secret-two ",
			wantSigs: []string{"secret-one", "secret-two"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PD_SIGNATURE", tt.envVar)

			sigs, err := loadPDSignatures()

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, want := range tt.wantSigs {
				if !slices.Contains(sigs, want) {
					t.Errorf("signature %q not found in result %v", want, sigs)
				}
			}
		})
	}
}
