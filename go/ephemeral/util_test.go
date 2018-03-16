package ephemeral

import (
	"testing"
	"time"

	keybase1 "github.com/keybase/client/go/protocol/keybase1"
	"github.com/stretchr/testify/require"
)

func TestDeleteExpiredKeys(t *testing.T) {
	now := keybase1.Time(time.Now().Unix())

	// Test empty
	expired := getExpiredGenerations(make(keyExpiryMap), now)
	expected := []keybase1.EkGeneration(nil)
	require.Equal(t, expected, expired)

	// Test with a single key that is not expired
	keyMap := keyExpiryMap{
		0: now,
	}
	expired = getExpiredGenerations(keyMap, now)
	expected = []keybase1.EkGeneration(nil)
	require.Equal(t, expected, expired)

	// Test with a single key that is expired
	keyMap = keyExpiryMap{
		0: now - KeyLifetimeSecs,
	}
	expired = getExpiredGenerations(keyMap, now)
	expected = []keybase1.EkGeneration{0}
	require.Equal(t, expected, expired)

	// Test with a 6 day gap, but no expiry
	keyMap = keyExpiryMap{
		0: now - keybase1.Time(time.Hour*24*6),
		1: now,
	}
	expired = getExpiredGenerations(keyMap, now)
	expected = []keybase1.EkGeneration(nil)
	require.Equal(t, expected, expired)

	// Test multiple gaps, only the last key is valid though.
	keyMap = make(keyExpiryMap)
	numKeys := 5
	for i := 0; i < numKeys; i++ {
		keyMap[keybase1.EkGeneration((numKeys - i - 1))] = now - KeyLifetimeSecs*keybase1.Time(i)
	}
	expired = getExpiredGenerations(keyMap, now)
	expected = []keybase1.EkGeneration{0, 1, 2}
	require.Equal(t, expected, expired)
}
