//
// Copyright (c) 2022 Markku Rossi
//
// All rights reserved.
//

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"log"
	"os"

	"github.com/google/tink/go/kwp/subtle"
)

type Filter func(block *[16]byte, seq int) error

func FilterCopy(block *[16]byte, seq int) error {
	return nil
}

func FilterRed(block *[16]byte, seq int) error {
	for i := 0; i+4 <= len(block); i += 4 {
		block[i+1] = 0
		block[i+2] = 0
	}
	return nil
}

func FilterGreen(block *[16]byte, seq int) error {
	for i := 0; i+4 <= len(block); i += 4 {
		block[i+0] = 0
		block[i+2] = 0
	}
	return nil
}

func FilterBlue(block *[16]byte, seq int) error {
	for i := 0; i+4 <= len(block); i += 4 {
		block[i+0] = 0
		block[i+1] = 0
	}
	return nil
}

var (
	cipherAES256 cipher.Block
	cipherGCM    cipher.AEAD
	cipherAESKWP *subtle.KWP
)

func init() {
	var err error
	var key [32]byte

	for i := 0; i < len(key); i++ {
		key[i] = byte(i)
	}

	cipherAES256, err = aes.NewCipher(key[:])
	if err != nil {
		log.Fatalf("failed to create AES256: %s", err)
	}

	cipherGCM, err = cipher.NewGCM(cipherAES256)
	if err != nil {
		log.Fatalf("failed to create AES256-GCM: %s", err)
	}

	cipherAESKWP, err = subtle.NewKWP(key[:])
	if err != nil {
		log.Fatalf("failed to create AES256-KWP: %s", err)
	}

}

func AESECB(block *[16]byte, seq int) error {
	cipherAES256.Encrypt(block[:], block[:])
	return nil
}

func AESGCM(block *[16]byte, seq int) error {
	var nonce [16]byte

	binary.BigEndian.PutUint64(nonce[0:8], uint64(seq))
	dst := cipherGCM.Seal(nil, nonce[0:cipherGCM.NonceSize()], block[:], nil)

	copy(block[:], dst)
	return nil
}

func AESKWP(block *[16]byte, seq int) error {
	result, err := cipherAESKWP.Wrap(block[:])
	if err != nil {
		return err
	}
	copy(block[:], result)
	return nil
}

func AESKWPFixedIVs(block *[16]byte, seq int) error {
	var plaintext [32]byte

	ivb := byte(seq % 8)
	for i := 0; i < 16; i++ {
		plaintext[i] = ivb
	}
	copy(plaintext[16:], block[:])

	result, err := cipherAESKWP.Wrap(plaintext[:])
	if err != nil {
		return err
	}
	copy(block[:], result[16:])
	return nil
}

func AESKWPRandomFixedIVs(block *[16]byte, seq int) error {
	var plaintext [32]byte
	var iv [1]byte

	_, err := rand.Read(iv[:])
	if err != nil {
		return err
	}

	ivb := byte(iv[0] % 8)
	for i := 0; i < 16; i++ {
		plaintext[i] = ivb
	}
	copy(plaintext[16:], block[:])

	result, err := cipherAESKWP.Wrap(plaintext[:])
	if err != nil {
		return err
	}
	copy(block[:], result[16:])
	return nil
}

func AESKWPRandomIV(block *[16]byte, seq int) error {
	var plaintext [32]byte

	_, err := rand.Read(plaintext[0:16])
	if err != nil {
		return err
	}

	copy(plaintext[16:], block[:])

	result, err := cipherAESKWP.Wrap(plaintext[:])
	if err != nil {
		return err
	}
	copy(block[:], result[16:])
	return nil
}

var filters = []struct {
	name string
	f    Filter
}{
	{
		name: "red",
		f:    FilterRed,
	},
	{
		name: "green",
		f:    FilterGreen,
	},
	{
		name: "blue",
		f:    FilterBlue,
	},
	{
		name: "AES-ECB",
		f:    AESECB,
	},
	{
		name: "AES-GCM",
		f:    AESGCM,
	},
	{
		name: "AES-KWP",
		f:    AESKWP,
	},
	{
		name: "AES-KWP-FixedIVs",
		f:    AESKWPFixedIVs,
	},
	{
		name: "AES-KWP-RandomFixedIVs",
		f:    AESKWPRandomFixedIVs,
	},
	{
		name: "AES-KWP-RandomIV",
		f:    AESKWPRandomIV,
	},
}

func main() {
	flag.Parse()
	log.SetFlags(0)

	for _, arg := range flag.Args() {
		err := processFile(arg)
		if err != nil {
			log.Fatalf("failed to process file '%s': %s\n", arg, err)
		}
	}
}

func processFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	m, _, err := image.Decode(f)
	if err != nil {
		return err
	}
	bounds := m.Bounds()
	width := bounds.Max.X - bounds.Min.X
	height := bounds.Max.Y - bounds.Min.Y

	log.Printf("%d\u00d7%d\n", width, height)

	for _, filter := range filters {

		output := image.NewNRGBA(image.Rectangle{
			Max: image.Point{
				X: width,
				Y: height,
			},
		})

		var zero [16]byte
		var block [16]byte
		var blockOfs int
		var seq int

		for y := 0; y < height; y++ {
			for x := 0; x < width; x++ {
				r, g, b, a := m.At(x, y).RGBA()
				block[blockOfs+0] = byte(r >> 8)
				block[blockOfs+1] = byte(g >> 8)
				block[blockOfs+2] = byte(b >> 8)
				block[blockOfs+3] = byte(a >> 8)
				blockOfs += 4

				if blockOfs >= len(block) {
					if err := filter.f(&block, seq); err != nil {
						return err
					}
					writeBlock(output, block[:], seq, x+1-blockOfs/4, y)
					blockOfs = 0
					seq++
					block = zero
				}
			}
			if blockOfs > 0 {
				if err := filter.f(&block, seq); err != nil {
					return err
				}
				writeBlock(output, block[:blockOfs], seq, width-blockOfs/4, y)
				blockOfs = 0
				seq++
				block = zero
			}
		}

		err := save(output, fmt.Sprintf("%s-%s.png", path, filter.name))
		if err != nil {
			return err
		}
	}
	return nil
}

func writeBlock(image *image.NRGBA, block []byte, seq, x, y int) {
	for i := 0; i+4 <= len(block); i += 4 {
		image.Set(x, y, color.NRGBA{
			R: block[i+0],
			G: block[i+1],
			B: block[i+2],
			A: block[i+3],
		})
		x++
	}
}

func save(image *image.NRGBA, name string) error {
	out, err := os.Create(name)
	if err != nil {
		return err
	}
	defer out.Close()

	return png.Encode(out, image)
}
