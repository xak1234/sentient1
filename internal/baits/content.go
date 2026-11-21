package baits

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Gen produces believable fake content. A single persona is shared by all
// baits so they corroborate each other (same name in passwords.txt, the fake
// browser profile, FileZilla…). None of it relates to the real user.
type Gen struct {
	First, Last, Email, User string
	Year                     int
	Canary                   map[string]map[string]string // kind -> data (aws_keys: id/secret/region, web: url)
}

var (
	firstNames = []string{"Jordan", "Taylor", "Casey", "Morgan", "Riley", "Avery", "Jamie", "Quinn", "Reese", "Alex", "Drew", "Skyler", "Cameron", "Logan", "Parker"}
	lastNames  = []string{"Marsh", "Holloway", "Brennan", "Whitaker", "Calloway", "Prescott", "Lindqvist", "Okafor", "Delgado", "Ashford", "Kowalski", "Navarro", "Fairbanks", "Thornton"}
	domains    = []string{"outlook.com", "gmail.com", "proton.me", "yahoo.com", "hotmail.com"}
	pwWords    = []string{"Summer", "Brightwater", "Falcon", "Maple", "Riverside", "Copper", "Winter", "Harbor", "Lucky", "Thunder", "Velvet", "Orchid", "Granite", "Sunset"}
	// A slice of the BIP-39 English list.
	seedWords = strings.Fields(`abandon ability able about absorb abstract absurd access accident account accuse acid acoustic
		across action actor actual adapt address adjust admit adult advance advice afford again agent agree ahead aim air
		alarm album alert alien allow almost alone alpha already also alter always amazing among amount amused anchor ancient
		angle animal ankle announce annual answer antenna antique anxiety apart apology appear apple approve april arch arctic
		arena argue armor army arrange arrest arrive arrow artist artwork aspect assault asset assist assume athlete atom
		attack attend auction audit august aunt author auto autumn average avocado avoid awake aware away awesome awful
		bacon badge balance bamboo banana banner barely bargain barrel basket battle beach bean beauty become beef before
		begin behave believe below bench benefit best betray better beyond bicycle bird birth bitter black blade blame
		blanket blast bleak bless blind blood blossom blue blur blush board boat body boil bomb bone bonus book boost border
		boring borrow boss bottom bounce brain brand brass brave bread breeze brick bridge brief bright bring brisk broccoli
		broken bronze broom brother brown brush bubble buddy budget buffalo build bulb bulk bullet bundle bunker burden
		burger burst butter buyer buzz cabbage cabin cable cactus cage cake call calm camera camp canal cancel candy cannon
		canoe canvas canyon capable capital captain carbon card cargo carpet carry cart case cash casino castle casual
		catalog catch category cattle caught cause caution cave ceiling celery cement census century cereal certain chair
		chalk champion change chaos chapter charge chase cheap check cheese chef cherry chest chicken chief child chimney`)
)

func rint(n int) int {
	v, _ := rand.Int(rand.Reader, big.NewInt(int64(n)))
	return int(v.Int64())
}

func pick(xs []string) string { return xs[rint(len(xs))] }

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randAlnum(n int, alphabet string) string {
	var sb strings.Builder
	for i := 0; i < n; i++ {
		sb.WriteByte(alphabet[rint(len(alphabet))])
	}
	return sb.String()
}

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	alnum       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

// NewGen creates a random persona.
func NewGen() *Gen {
	g := &Gen{First: pick(firstNames), Last: pick(lastNames), Year: 1980 + rint(20), Canary: map[string]map[string]string{}}
	g.User = strings.ToLower(g.First[:1]+g.Last) + fmt.Sprint(g.Year%100)
	g.Email = strings.ToLower(g.First+"."+g.Last) + fmt.Sprint(g.Year) + "@" + pick(domains)
	return g
}

func (g *Gen) password() string {
	syms := "!#$%&*"
	switch rint(3) {
	case 0:
		return pick(pwWords) + fmt.Sprint(2015+rint(10)) + string(syms[rint(len(syms))])
	case 1:
		return randAlnum(4, alnum) + "-" + randAlnum(4, alnum) + "-" + randAlnum(4, alnum)
	default:
		return pick(pwWords) + "#" + pick(pwWords) + fmt.Sprint(rint(100))
	}
}

func genPasswordsTxt(g *Gen) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# keep this private!!\n\n")
	rows := [][2]string{
		{"email", g.Email},
		{"bank", g.User},
		{"amazon", g.Email},
		{"paypal", g.Email},
		{"router admin", "admin"},
		{"work vpn", strings.ToLower(g.First[:1] + g.Last)},
		{"steam", g.User + "_gg"},
	}
	for _, r := range rows {
		fmt.Fprintf(&b, "%-14s %-36s / %s\n", r[0], r[1], g.password())
	}
	if w := g.Canary["web"]; w["url"] != "" {
		fmt.Fprintf(&b, "\npassword manager backup: %s\n", w["url"])
	}
	b.WriteString("\ncrypto wallet seed is in the other file\n")
	return []byte(strings.ReplaceAll(b.String(), "\n", "\r\n"))
}

func (g *Gen) seed(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = pick(seedWords)
	}
	return out
}

func genSeedTxt(g *Gen) []byte {
	w := g.seed(12)
	s := fmt.Sprintf("MetaMask recovery phrase - DO NOT LOSE\r\n\r\n%s\r\n%s\r\n%s\r\n\r\nwallet address: 0x%s\r\n",
		strings.Join(w[:4], " "), strings.Join(w[4:8], " "), strings.Join(w[8:], " "), hex.EncodeToString(randBytes(20)))
	return []byte(s)
}

func genBackupCodes(g *Gen) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "BACKUP VERIFICATION CODES\r\n%s\r\n\r\n", g.Email)
	for i := 0; i < 10; i++ {
		fmt.Fprintf(&b, "%d. %04d %04d\r\n", i+1, rint(10000), rint(10000))
	}
	b.WriteString("\r\n(Each code can be used once)\r\n")
	return []byte(b.String())
}

func genKdbx(*Gen) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint32(0x9AA2D903)) // KeePass signature 1
	binary.Write(&b, binary.LittleEndian, uint32(0xB54BFB67)) // KDBX signature 2
	binary.Write(&b, binary.LittleEndian, uint32(0x00040001)) // version 4.1
	b.Write(randBytes(3000 + rint(4000)))
	return b.Bytes()
}

func genLocalState(g *Gen) []byte {
	key := base64.StdEncoding.EncodeToString(append([]byte("DPAPI"), randBytes(226)...))
	return []byte(fmt.Sprintf(`{"browser":{"enabled_labs_experiments":[],"last_redirect_origin":""},"os_crypt":{"audit_enabled":true,"encrypted_key":"%s"},"profile":{"info_cache":{"Default":{"active_time":%d.0,"name":"%s","user_name":"%s"}},"last_used":"Default"}}`,
		key, time.Now().Add(-48*time.Hour).Unix(), g.First, g.Email))
}

func genPreferences(g *Gen) []byte {
	return []byte(fmt.Sprintf(`{"account_info":[{"email":"%s","full_name":"%s %s"}],"profile":{"name":"%s"}}`, g.Email, g.First, g.Last, g.First))
}

// leveldb log record framing is irrelevant to a tripwire; what matters is that
// the files exist where stealers look and contain the strings they grep for.
func genMetamaskLog(g *Gen) []byte {
	vault := fmt.Sprintf(`{"data":"%s","iv":"%s","keyMetadata":{"algorithm":"PBKDF2","params":{"iterations":600000}},"salt":"%s"}`,
		base64.StdEncoding.EncodeToString(randBytes(420)), base64.StdEncoding.EncodeToString(randBytes(16)), base64.StdEncoding.EncodeToString(randBytes(32)))
	var b bytes.Buffer
	b.Write(randBytes(7))
	b.WriteString(`{"KeyringController":{"vault":"` + strings.ReplaceAll(vault, `"`, `\"`) + `"},"MetaMetricsController":{"participateInMetaMetrics":false}}`)
	b.Write(randBytes(64))
	return b.Bytes()
}

func genLevelDBManifest(*Gen) []byte {
	return append([]byte{0x56, 0x8a, 0x2e, 0x1b, 0x1c, 0x00, 0x01, 0x01, 0x1a}, []byte("leveldb.BytewiseComparator")...)
}

func genAtomicLog(g *Gen) []byte {
	var b bytes.Buffer
	b.Write(randBytes(7))
	fmt.Fprintf(&b, "_file://\x00\x01general_mnemonic\x01\"%s\"", base64.StdEncoding.EncodeToString(randBytes(180)))
	b.Write(randBytes(32))
	return b.Bytes()
}

func genSeco(*Gen) []byte {
	return append([]byte("SECO\x00\x00\x00\x00"), randBytes(900+rint(600))...)
}

func genExodusPassphrase(g *Gen) []byte {
	return []byte(fmt.Sprintf(`{"passphrase":"%s"}`, hex.EncodeToString(randBytes(32))))
}

func genElectrumWallet(g *Gen) []byte {
	xprv := "xprv9s21ZrQH143K" + randAlnum(95, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	xpub := "xpub661MyMwAqRbc" + randAlnum(95, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")
	return []byte(fmt.Sprintf(`{"addr_history":{},"keystore":{"seed":"%s","type":"bip32","xprv":"%s","xpub":"%s"},"seed_type":"segwit","seed_version":18,"use_encryption":false,"wallet_type":"standard"}`,
		strings.Join(g.seed(12), " "), xprv, xpub))
}

func genTDF(*Gen) []byte {
	return append([]byte("TDF$\x8a\x5c\x3f\x00"), randBytes(300+rint(500))...)
}

func genDiscordLdb(g *Gen) []byte {
	id := base64.RawStdEncoding.EncodeToString([]byte(fmt.Sprint(100000000000000000 + rint(899999999999999999))))
	token := id + "." + randAlnum(6, alnum) + "." + randAlnum(38, alnum+"-_")
	var b bytes.Buffer
	b.Write(randBytes(40))
	b.WriteString("_https://discord.com\x00\x01token\x01\"" + token + "\"")
	b.Write(randBytes(120))
	return b.Bytes()
}

func genSiteManager(g *Gen) []byte {
	pw := base64.StdEncoding.EncodeToString([]byte(g.password()))
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.67.1" platform="windows">
	<Servers>
		<Server>
			<Host>ftp.%s-studio.net</Host>
			<Port>21</Port>
			<Protocol>0</Protocol>
			<Type>0</Type>
			<User>%s</User>
			<Pass encoding="base64">%s</Pass>
			<Logontype>1</Logontype>
			<Name>website</Name>
		</Server>
	</Servers>
</FileZilla3>
`, strings.ToLower(g.Last), g.User, pw))
}

func genRecentServers(g *Gen) []byte {
	pw := base64.StdEncoding.EncodeToString([]byte(g.password()))
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<FileZilla3 version="3.67.1" platform="windows">
	<RecentServers>
		<Server>
			<Host>%d.%d.%d.%d</Host>
			<Port>22</Port>
			<Protocol>1</Protocol>
			<User>root</User>
			<Pass encoding="base64">%s</Pass>
		</Server>
	</RecentServers>
</FileZilla3>
`, 45+rint(100), rint(255), rint(255), 1+rint(250), pw))
}

func genAWSCredentials(g *Gen) []byte {
	id, secret, region := "AKIA"+randAlnum(16, upperDigits), randAlnum(40, alnum+"+/"), "us-east-1"
	if c := g.Canary["aws_keys"]; c["id"] != "" {
		id, secret = c["id"], c["secret"]
		if c["region"] != "" {
			region = c["region"]
		}
	}
	_ = region
	return []byte(fmt.Sprintf("[default]\r\naws_access_key_id = %s\r\naws_secret_access_key = %s\r\n", id, secret))
}

func genAWSConfig(g *Gen) []byte {
	region := "us-east-1"
	if c := g.Canary["aws_keys"]; c["region"] != "" {
		region = c["region"]
	}
	return []byte(fmt.Sprintf("[default]\r\nregion = %s\r\noutput = json\r\n", region))
}

func genSSHKey(*Gen) []byte {
	body := base64.StdEncoding.EncodeToString(append([]byte("openssh-key-v1\x00"), randBytes(1650)...))
	var b strings.Builder
	b.WriteString("-----BEGIN OPENSSH PRIVATE KEY-----\n")
	for len(body) > 70 {
		b.WriteString(body[:70] + "\n")
		body = body[70:]
	}
	b.WriteString(body + "\n-----END OPENSSH PRIVATE KEY-----\n")
	return []byte(b.String())
}

func genProfilesIni(*Gen) []byte {
	return []byte("[Profile0]\r\nName=default-release\r\nIsRelative=1\r\nPath=Profiles/q8m3kx2v.default-release\r\nDefault=1\r\n\r\n[General]\r\nStartWithLastProfile=1\r\nVersion=2\r\n")
}

func genFirefoxLogins(g *Gen) []byte {
	enc := func() string {
		return base64.StdEncoding.EncodeToString(append([]byte{0x30, 0x7a, 0x04, 0x10}, randBytes(118)...))
	}
	return []byte(fmt.Sprintf(`{"nextId":3,"logins":[{"id":1,"hostname":"https://accounts.google.com","encryptedUsername":"%s","encryptedPassword":"%s","encType":1,"timesUsed":14},{"id":2,"hostname":"https://www.paypal.com","encryptedUsername":"%s","encryptedPassword":"%s","encType":1,"timesUsed":3}],"version":3}`,
		enc(), enc(), enc(), enc()))
}

// genEmptySQLite returns a valid, empty SQLite 3 database (one page).
func genEmptySQLite(*Gen) []byte {
	const pageSize = 4096
	b := make([]byte, pageSize)
	copy(b, "SQLite format 3\x00")
	be := binary.BigEndian
	be.PutUint16(b[16:], pageSize)
	b[18], b[19] = 1, 1 // file format write/read version (legacy)
	b[21], b[22], b[23] = 64, 32, 32
	be.PutUint32(b[24:], 1)       // file change counter
	be.PutUint32(b[28:], 1)       // database size in pages
	be.PutUint32(b[44:], 4)       // schema format
	be.PutUint32(b[56:], 1)       // text encoding UTF-8
	be.PutUint32(b[92:], 1)       // version-valid-for
	be.PutUint32(b[96:], 3046001) // SQLITE_VERSION_NUMBER
	// sqlite_schema b-tree: empty table leaf page
	b[100] = 0x0D
	be.PutUint16(b[105:], pageSize)
	return b
}

// Persona serialises the fake identity so repairs recreate consistent content.
func (g *Gen) Persona() map[string]string {
	return map[string]string{"first": g.First, "last": g.Last, "email": g.Email, "user": g.User, "year": fmt.Sprint(g.Year)}
}

// GenFromPersona restores a Gen (falls back to a fresh persona).
func GenFromPersona(p map[string]string) *Gen {
	g := NewGen()
	if p["first"] == "" {
		return g
	}
	g.First, g.Last, g.Email, g.User = p["first"], p["last"], p["email"], p["user"]
	fmt.Sscan(p["year"], &g.Year)
	return g
}
