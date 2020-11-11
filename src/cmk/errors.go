package cmk

type InvalidSigningAlgorithm struct{}

func (v *InvalidSigningAlgorithm) Error() string {
	return "invalid signing algorithm"
}

//---

type InvalidDigestLength struct{}

func (v *InvalidDigestLength) Error() string {
	return "invalid digest length"
}
