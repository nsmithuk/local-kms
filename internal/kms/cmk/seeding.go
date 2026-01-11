package cmk

type SeedingKeyMaterial struct {
	// Symmetric example:
	BackingKeys []string `yaml:"BackingKeys,omitempty"` // hex strings

	// Asymmetric examples (ecdsa/rsa):
	PrivateKeyPem *string `yaml:"PrivateKeyPem,omitempty"` // multiline PEM
}
