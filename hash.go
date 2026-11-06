// Copyright (c) 2019, The Garble Authors.
// See LICENSE for licensing information.

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"go/token"
	"go/types"
	"io"
	mathrand "math/rand"
	"os/exec"
	"strconv"
	"strings"

	"mvdan.cc/garble/internal/literals"
)

const buildIDSeparator = "/"

// splitActionID returns the action ID half of a build ID, the first hash.
func splitActionID(buildID string) string {
	return buildID[:strings.Index(buildID, buildIDSeparator)]
}

// splitContentID returns the content ID half of a build ID, the last hash.
func splitContentID(buildID string) string {
	return buildID[strings.LastIndex(buildID, buildIDSeparator)+1:]
}

// buildIDHashLength is the number of bytes each build ID hash takes,
// such as an action ID or a content ID.
const buildIDHashLength = 15

// decodeBuildIDHash decodes a build ID hash in base64, just like cmd/go does.
func decodeBuildIDHash(str string) []byte {
	h, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		panic(fmt.Sprintf("invalid hash %q: %v", str, err))
	}
	if len(h) != buildIDHashLength {
		panic(fmt.Sprintf("decodeBuildIDHash expects to result in a hash of length %d, got %d", buildIDHashLength, len(h)))
	}
	return h
}

// encodeBuildIDHash encodes a build ID hash in base64, just like cmd/go does.
func encodeBuildIDHash(h [sha256.Size]byte) string {
	return base64.RawURLEncoding.EncodeToString(h[:buildIDHashLength])
}

func alterToolVersion(tool string, args []string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.Output()
	if err != nil {
		if err, _ := err.(*exec.ExitError); err != nil {
			return fmt.Errorf("%v: %s", err, err.Stderr)
		}
		return err
	}
	line := string(bytes.TrimSpace(out)) // no trailing newline
	f := strings.Fields(line)
	if len(f) < 3 || f[0] != tool || f[1] != "version" || f[2] == "devel" && !strings.HasPrefix(f[len(f)-1], "buildID=") {
		return fmt.Errorf("%s -V=full: unexpected output:\n\t%s", args[0], line)
	}
	var toolID []byte
	if f[2] == "devel" {
		// On the development branch, use the content ID part of the build ID.
		toolID = decodeBuildIDHash(splitContentID(f[len(f)-1]))
	} else {
		// For a release, the output is like: "compile version go1.9.1 X:framepointer".
		// Use the whole line, as we can assume it's unique.
		toolID = []byte(line)
	}

	contentID := addGarbleToHash(toolID)
	// The part of the build ID that matters is the last, since it's the
	// "content ID" which is used to work out whether there is a need to redo
	// the action (build) or not. Since cmd/go parses the last word in the
	// output as "buildID=...", we simply add "+garble buildID=_/_/_/${hash}".
	// The slashes let us imitate a full binary build ID, but we assume that
	// the other hashes such as the action ID are not necessary, since the
	// only reader here is cmd/go and it only consumes the content ID.
	fmt.Printf("%s +garble buildID=_/_/_/%s\n", line, encodeBuildIDHash(contentID))
	return nil
}

var (
	hasher    = sha256.New()
	sumBuffer [sha256.Size]byte
)

// addGarbleToHash takes some arbitrary input bytes,
// typically a hash such as an action ID or a content ID,
// and returns a new hash which also contains garble's own deterministic inputs.
//
// This includes garble's own version, obtained via its own binary's content ID,
// as well as any other options which affect a build, such as GOGARBLE and -tiny.
func addGarbleToHash(inputHash []byte) [sha256.Size]byte {
	// Join the two content IDs together into a single base64-encoded sha256
	// sum. This includes the original tool's content ID, and garble's own
	// content ID.
	hasher.Reset()
	hasher.Write(inputHash)
	if len(sharedCache.BinaryContentID) == 0 {
		panic("missing binary content ID")
	}
	hasher.Write(sharedCache.BinaryContentID)

	// We also need to add the selected options to the full version string,
	// because all of them result in different output. We use spaces to
	// separate the env vars and flags, to reduce the chances of collisions.
	fmt.Fprintf(hasher, " GOGARBLE=%s", sharedCache.GOGARBLE)
	appendFlags(hasher, true)
	// addGarbleToHash returns the sum buffer, so we need a new copy.
	// Otherwise the next use of the global sumBuffer would conflict.
	var sumBuffer [sha256.Size]byte
	hasher.Sum(sumBuffer[:0])
	return sumBuffer
}

// appendFlags writes garble's own flags to w in string form.
// Errors are ignored, as w is always a buffer or hasher.
// If forBuildHash is set, only the flags affecting a build are written.
func appendFlags(w io.Writer, forBuildHash bool) {
	if flagLiterals {
		io.WriteString(w, " -literals")
	}
	if flagTiny {
		io.WriteString(w, " -tiny")
	}
	if flagDebug && !forBuildHash {
		// -debug doesn't affect the build result at all,
		// so don't give it separate entries in the build cache.
		// If the user really wants to see debug info for already built deps,
		// they can use "go clean cache" or the "-a" build flag to rebuild.
		io.WriteString(w, " -debug")
	}
	if flagDebugDir != "" && !forBuildHash {
		// -debugdir is a bit special.
		//
		// When passing down flags via -toolexec, keep the actual flag value.
		//
		// For build hashes, skip the flag entirely, as it doesn't affect
		// obfuscation output.
		io.WriteString(w, " -debugdir=")
		io.WriteString(w, flagDebugDir)
	}
	if flagSeed.present() {
		io.WriteString(w, " -seed=")
		io.WriteString(w, flagSeed.String())
	}
	if flagControlFlow && forBuildHash {
		io.WriteString(w, " -ctrlflow")
	}
	if literals.TestObfuscator != "" && forBuildHash {
		io.WriteString(w, literals.TestObfuscator)
	}
}

func buildidOf(path string) (string, error) {
	cmd := exec.Command("go", "tool", "buildid", path)
	out, err := cmd.Output()
	if err != nil {
		if err, _ := err.(*exec.ExitError); err != nil {
			return "", fmt.Errorf("%v: %s", err, err.Stderr)
		}
		return "", err
	}
	return string(out), nil
}

// toUpper uppercases an ASCII letter. It is byte-based since hashed names are
// built only from the ASCII letters in nameConsonants and nameVowels.
func toUpper(b byte) byte { return b - ('a' - 'A') }

func runtimeHashWithCustomSalt(salt []byte) uint32 {
	hasher.Reset()
	if !flagSeed.present() {
		runtimePkg, _ := sharedCache.ListedPackages.get("runtime")
		hasher.Write(runtimePkg.GarbleActionID[:])
	} else {
		hasher.Write(flagSeed.bytes)
	}
	hasher.Write(salt)
	sum := hasher.Sum(sumBuffer[:0])
	return binary.LittleEndian.Uint32(sum)
}

// magicValue returns random magic value based
// on user specified seed or the runtime package's GarbleActionID.
func magicValue() uint32 {
	return runtimeHashWithCustomSalt([]byte("magic"))
}

// entryOffKey returns random entry offset key
// on user specified seed or the runtime package's GarbleActionID.
func entryOffKey() uint32 {
	return runtimeHashWithCustomSalt([]byte("entryOffKey"))
}

func hashWithPackage(pkg *listedPackage, name string) string {
	// If the user provided us with an obfuscation seed,
	// we use that with the package import path directly..
	// Otherwise, we use GarbleActionID as a fallback salt.
	if !flagSeed.present() {
		return hashWithCustomSalt(pkg.GarbleActionID[:], name)
	}
	// Use a separator at the end of ImportPath as a salt,
	// to ensure that "pkgfoo.bar" and "pkg.foobar" don't both hash
	// as the same string "pkgfoobar".
	return hashWithCustomSalt([]byte(pkg.ImportPath+"|"), name)
}

// hashWithStruct is separate from hashWithPackage since Go
// allows converting between struct types across packages.
// Hashing struct field names differently between packages would break that.
//
// We hash field names with the "identity" struct type as a salt
// so that the same field name used in different struct types is obfuscated differently.
// In practice this means omitting struct field tags and unaliasing field types,
// given that those do not affect whether two types are identical.
func hashWithStruct(strct *types.Struct, field *types.Var) string {
	// Here we use a bundled and modified version of x/tools/go/types/typeutil.NewHasher.Hash
	// which includes two crucial modifications:
	//
	//   * struct field tags are not hashed
	//   * named types are hashed by name rather than by pointer
	//
	// TODO: rethink once the proposed go/types.Hash API in https://go.dev/issue/69420 is merged.
	salt := strconv.AppendUint(nil, uint64(typeutil_hash(strct)), 32)

	// If the user provided us with an obfuscation seed,
	// we only use the identity struct type as a salt.
	// Otherwise, we add garble's own inputs to the salt as a fallback.
	if !flagSeed.present() {
		withGarbleHash := addGarbleToHash(salt)
		salt = withGarbleHash[:]
	}
	return hashWithCustomSalt(salt, field.Name())
}

// Hashed names are rendered as a run of pronounceable syllables rather than
// base64, so that they read like ordinary Go identifiers instead of the
// high-entropy base64 strings which make a garbled binary easy to fingerprint.
//
// Each syllable encodes one checksum byte, with no loss, by splitting it into
// a consonant from nameConsonants and an ending from nameVowels. A name uses
// minSyllables to maxSyllables syllables, chosen from a checksum byte, so it
// carries 32 to 48 bits.
//
// The collision namespace is generally a single package, since that's where
// most hashed names are namespaced to. With a generous estimate of 10k names
// in one package, 32 bits gives roughly a 1% chance of any collision and 48
// bits well under one in a million; most packages have far fewer names. A
// collision would fail the build loudly with a duplicate name, never silently.
const (
	minSyllables = 4
	maxSyllables = 6

	// Checksum bytes we read: one per syllable, plus one for the count.
	neededSumBytes = maxSyllables + 1
)

// nameConsonants and nameVowels are indexed by the high and low nibble of a
// checksum byte, so both must hold exactly 16 entries. They avoid q, w, x and
// y to stay easy to read. Every entry is made only of letters, so a name is
// always a valid identifier.
var (
	nameConsonants = [16]string{"b", "c", "d", "f", "g", "h", "j", "k", "l", "m", "n", "p", "r", "s", "t", "v"}
	nameVowels     = [16]string{"a", "e", "i", "o", "u", "an", "en", "in", "on", "un", "ar", "er", "or", "al", "el", "us"}
)

// randomName generates a random name derived from the given baseName, using the provided random source.
func randomName(rand *mathrand.Rand, baseName string) string {
	salt := make([]byte, buildIDHashLength)
	if _, err := rand.Read(salt); err != nil {
		panic(err)
	}
	return hashWithCustomSalt(salt, baseName)
}

// hashWithCustomSalt returns a hashed version of name,
// including the provided salt as well as opts.Seed into the hash input.
//
// The result is always four bytes long. If the input was a valid identifier,
// the output remains equally exported or unexported. Note that this process is
// reproducible, but not reversible.
func hashWithCustomSalt(salt []byte, name string) string {
	if len(salt) == 0 {
		panic("hashWithCustomSalt: empty salt")
	}
	if name == "" {
		panic("hashWithCustomSalt: empty name")
	}

	hasher.Reset()
	hasher.Write(salt)
	hasher.Write(flagSeed.bytes)
	io.WriteString(hasher, name)
	sum := hasher.Sum(sumBuffer[:0])

	// sum[maxSyllables] is not used for a syllable, but it is still
	// deterministic and hard to predict, so we use it to pick the syllable
	// count evenly between minSyllables and maxSyllables.
	count := minSyllables + int(sum[maxSyllables])%(maxSyllables-minSyllables+1)

	var b strings.Builder
	for i := range count {
		b.WriteString(nameConsonants[sum[i]>>4])
		b.WriteString(nameVowels[sum[i]&0xf])
	}
	hashName := []byte(b.String())

	// The first letter is always a lowercase consonant, so the name is a valid
	// identifier. Valid identifiers should stay exported or unexported; a
	// package path, which is not an identifier, stays unexported.
	if token.IsIdentifier(name) && token.IsExported(name) {
		hashName[0] = toUpper(hashName[0])
	}
	return string(hashName)
}
