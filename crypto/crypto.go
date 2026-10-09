/*
   Vodafone-Station
   Copyright (C) 2026  hbuschbaum

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

package crypto

import (
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"github.com/CrimsonAIO/aesccm"
	log "github.com/sirupsen/logrus"
)

const (
	DEFAULT_PARANOIA     int = 10
	DEFAULT_NUMWORDS     int = 2
	DEFAULT_ITERATIONS   int = 1000
	DEFAULT_KEYSIZEBYTES int = 16
	DEFAULT_TAGLENGTH    int = 16
)

func Pbkdf2(password string, salt string, iterations int, keySizeBytes int) ([]byte, error) {
	log.WithFields(log.Fields{"password": password, "salt": salt, "iterations": iterations, "keySizeBytes": keySizeBytes}).Trace("Function Pbkdf2")
	hexSalt, err := hex.DecodeString(salt)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha256.New, password, hexSalt, iterations, keySizeBytes)
}

func CCMencrypt(derivedKey []byte, plainText string, iv string, authData string, tagLenBytes int) ([]byte, error) {
	log.WithFields(log.Fields{"derivedKey": derivedKey, "plainText": plainText, "iv": iv, "authData": authData, "tagLenBytes": tagLenBytes}).Trace("Function CCMencrypt")
	aesCypher, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}
	plainTextBytes := []byte(plainText)
	hexIv, err := hex.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	authDataBytes, err := hex.DecodeString(hex.EncodeToString([]byte(authData)))
	if err != nil {
		return nil, err
	}

	c, err := aesccm.NewCCM(aesCypher, len(hexIv), tagLenBytes)
	if err != nil {
		return nil, err
	}

	return c.Seal(nil, hexIv, plainTextBytes, authDataBytes), nil
}

func CCMdecrypt(derivedKey []byte, cipherText string, iv string, authData string, tagLenBytes int) ([]byte, error) {
	log.WithFields(log.Fields{"derivedKey": derivedKey, "cipherText": cipherText, "iv": iv, "authData": authData, "tagLenBytes": tagLenBytes}).Trace("Function CCMdecrypt")
	aesCypher, err := aes.NewCipher(derivedKey)
	if err != nil {
		return nil, err
	}

	hexIv, err := hex.DecodeString(iv)
	if err != nil {
		return nil, err
	}
	hexCipherText, err := hex.DecodeString(cipherText)
	if err != nil {
		return nil, err
	}
	authDataBytes, err := hex.DecodeString(hex.EncodeToString([]byte(authData)))
	if err != nil {
		return nil, err
	}

	c, err := aesccm.NewCCM(aesCypher, len(hexIv), tagLenBytes)
	if err != nil {
		return nil, err
	}
	return c.Open(nil, hexIv, hexCipherText, authDataBytes)
}
