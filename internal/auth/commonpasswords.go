package auth

import "strings"

// commonPasswords blocks the handful of choices that dominate credential
// stuffing lists. It is a floor, not a substitute for a breach-corpus check:
// the production upgrade is to screen candidates against Have I Been Pwned's
// k-anonymity range API, which never sees the password itself.
//
// Entries are compared lower-cased, and only after the length policy has run,
// so most of these are already excluded by MinPasswordLength.
var commonPasswords = map[string]struct{}{
	"123456789012":     {},
	"1234567890":       {},
	"qwertyuiop":       {},
	"password":         {},
	"password1":        {},
	"password123":      {},
	"passw0rd123":      {},
	"password1234":     {},
	"welcome123456":    {},
	"qwerty123456":     {},
	"iloveyou1234":     {},
	"letmein12345":     {},
	"administrator":    {},
	"changeme1234":     {},
	"secretpassword":   {},
	"trustno1234567":   {},
	"whatever12345":    {},
	"111111111111":     {},
	"000000000000":     {},
	"abcdefghijkl":     {},
	"aaaaaaaaaaaa":     {},
	"videocall1234":    {},
	"audiocall1234":    {},
	"cbback123456":     {},
	"monkey123456":     {},
	"dragon123456":     {},
	"sunshine1234":     {},
	"princess1234":     {},
	"football1234":     {},
	"baseball1234":     {},
	"superman1234":     {},
	"starwars1234":     {},
	"qazwsxedcrfv":     {},
	"zaq12wsxcde3":     {},
	"1qaz2wsx3edc":     {},
	"asdfghjkl123":     {},
	"loveyou123456":    {},
	"myp@ssw0rd123":    {},
	"p@ssword1234":     {},
	"admin1234567":     {},
	"welcome1234567":   {},
	"letmein1234567":   {},
	"qwertyuiop1234":   {},
	"thisisapassword":  {},
	"correcthorse":     {},
	"correctbatteryhs": {},
}

func isCommonPassword(password string) bool {
	_, found := commonPasswords[strings.ToLower(strings.TrimSpace(password))]
	return found
}
