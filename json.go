package golm

// KeyPair contains a key par, consisting of a Curve25519
// and a corresponding ED25519 key.
type KeyPair struct {
	Curve25519 string `json:"curve25519"`
	ED25519    string `json:"ed25519"`
}

// OneTimeKeys contains multiple Curve25519 keys.
type OneTimeKeys struct {
	Curve25519 map[string]string `json:"curve25519"`
}

// Size returns the number of stored keys.
func (otk *OneTimeKeys) Size() int {
	return len(otk.Curve25519)
}

// ID returns the ID of the n-th curve25519 key.
func (otk *OneTimeKeys) ID(n int) string {
	if 0 <= n && n < len(otk.Curve25519) {
		i := 0
		for id := range otk.Curve25519 {
			if i == n {
				return id
			}
			i++
		}
	}
	return ""
}

// Curve returns the n-th curve25519 key.
func (otk *OneTimeKeys) Curve(n int) string {
	if 0 <= n && n < len(otk.Curve25519) {
		i := 0
		for _, key := range otk.Curve25519 {
			if i == n {
				return key
			}
			i++
		}
	}
	return ""
}
