package data

//
// ──────────────────────────────
// Helpers
// ──────────────────────────────
//

func aliasKey(arn string) []byte  { return []byte("alias/" + arn) }
func aliasPrefix(p string) []byte { return []byte("alias/" + p) }

func keyKey(arn string) []byte  { return []byte("key/" + arn) }
func keyPrefix(p string) []byte { return []byte("key/" + p) }

func tagPrefixForKey(arn string) []byte { return []byte("tag/" + arn + "/") }
func tagKey(arn, k string) []byte       { return []byte("tag/" + arn + "/" + k) }

func prefixEnd(prefix []byte) []byte {
	end := append([]byte(nil), prefix...)
	for i := len(end) - 1; i >= 0; i-- {
		if end[i] < 0xFF {
			end[i]++
			return end[:i+1]
		}
	}
	return nil
}
