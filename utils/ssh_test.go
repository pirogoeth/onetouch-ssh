package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	pubKey    = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAYQC08QWM1Es5IZmRMhbpwoyCzG0efWmaLcclkdeU5S/822eAjZBI6qMo76ZEXD9aM34ZRv9/fqqQEBxNd3/63R8vTQtjJ1JY/q4ucdWZR3nKhrDCNlM567Lz/pLQ2sl9TWM= test-user@test-host"
	pkFinger  = "8d:42:2d:81:96:ac:b1:cd:64:ba:a4:b5:36:d0:cc:f6"
	pkComment = "test-user@test-host"
)

func TestSSHFingerprint(t *testing.T) {
	finger, comment := PublicKeyFingerprint(pubKey)

	assert.Equal(t, finger, pkFinger)
	assert.Equal(t, comment, pkComment)
}

func TestValidatePublicKey(t *testing.T) {
	valid, err := ValidatePublicKey(pubKey)

	assert.Equal(t, valid, true)
	assert.Nil(t, err)

	valid, err = ValidatePublicKey("not a publickey at all...")

	assert.Equal(t, valid, false)
	assert.NotNil(t, err)
}
