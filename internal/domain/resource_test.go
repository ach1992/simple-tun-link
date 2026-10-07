package domain

import "testing"

func TestResourceClaimsConflictExactAndNetworkOverlap(t *testing.T) {
	tests := []struct {
		name string
		a    ResourceClaim
		b    ResourceClaim
		want bool
	}{
		{
			name: "exact interface",
			a:    ResourceClaim{Kind: ResourceInterface, Key: "stl0"},
			b:    ResourceClaim{Kind: ResourceInterface, Key: "stl0"},
			want: true,
		},
		{
			name: "address inside subnet",
			a:    ResourceClaim{Kind: ResourceLinkAddress, Key: "10.80.20.1"},
			b:    ResourceClaim{Kind: ResourceLinkSubnet, Key: "10.80.20.0/31"},
			want: true,
		},
		{
			name: "overlapping subnets",
			a:    ResourceClaim{Kind: ResourceLinkSubnet, Key: "10.80.20.0/30"},
			b:    ResourceClaim{Kind: ResourceLinkSubnet, Key: "10.80.20.0/31"},
			want: true,
		},
		{
			name: "different UDP ports",
			a:    ResourceClaim{Kind: ResourceUDPListenPort, Key: "51820"},
			b:    ResourceClaim{Kind: ResourceUDPListenPort, Key: "51821"},
			want: false,
		},
		{
			name: "same text different kind",
			a:    ResourceClaim{Kind: ResourceBackendID, Key: "7"},
			b:    ResourceClaim{Kind: ResourceXFRMID, Key: "7"},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResourceClaimsConflict(tt.a, tt.b)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("conflict = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceClaimValidatesCanonicalNetworkAndPortKeys(t *testing.T) {
	invalid := []ResourceClaim{
		{Kind: ResourceLinkAddress, Key: "010.080.020.001"},
		{Kind: ResourceLinkSubnet, Key: "10.80.20.1/31"},
		{Kind: ResourceUDPListenPort, Key: "051820"},
		{Kind: ResourceUDPListenPort, Key: "65536"},
	}
	for _, claim := range invalid {
		if err := claim.Validate(); err == nil {
			t.Fatalf("claim %#v unexpectedly valid", claim)
		}
	}
}
