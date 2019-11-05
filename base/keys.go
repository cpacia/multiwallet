package base

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jinzhu/gorm"
	"golang.org/x/crypto/pbkdf2"
	"io"
	"time"
)

// LookaheadWindow is the number of keys to generate after the last
// unused key in the wallet. The key manager strives to maintain
// this buffer.
const LookaheadWindow = 20

// ErrEncryptedKeychain means the keychain is encrypted.
var ErrEncryptedKeychain = errors.New("keychain is encrypted")

// KeyManager manages a Bip44 keychain for each coin.
type KeyManager struct {
	db              database.Database
	internalPrivkey *hd.ExtendedKey
	internalPubkey  *hd.ExtendedKey

	externalPrivkey *hd.ExtendedKey
	externalPubkey  *hd.ExtendedKey

	coinType iwallet.CoinType

	addrFunc func(key *hd.ExtendedKey) (iwallet.Address, error)
}

// NewKeyManager instantiates a new KeyManger for the given coin with the provided keys.
//
// Note the following derivation path used by the KeyManager:
// Typical Bip44 derivation is:
//
// m / purpose' / coin_type' / account' / change / address_index
//
// It is assumed that the master private and master public keys passed in to this constructor
// are the `account` level keys and NOT the master keys for the entire multiwallet. It is done
// this way so that the KeyManager can only derive keys/address for its coin and cannot
// derive them for other coins.
//
// Further, We derive address in this class using only the master public key so if you wish to
// encrypt the keychain then you can pass in nil for the accountPrivKey and it wont be tracked here.
func NewKeyManager(db database.Database, coinType iwallet.CoinType, addressFunc func(key *hd.ExtendedKey) (iwallet.Address, error)) (*KeyManager, error) {
	var (
		externalPrivkey, externalPubkey, internalPrivkey, internalPubkey *hd.ExtendedKey
		coinRecord                                                       database.CoinRecord
	)
	err := db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", coinType.CurrencyCode()).Find(&coinRecord).Error
	})
	if err != nil {
		return nil, err
	}

	accountPubKey, err := hd.NewKeyFromString(coinRecord.MasterPub)
	if err != nil {
		return nil, err
	}

	if !coinRecord.EncryptedMasterKey {
		accountPrivKey, err := hd.NewKeyFromString(coinRecord.MasterPriv)
		if err != nil {
			return nil, err
		}
		externalPrivkey, internalPrivkey, err = generateAccountPrivKeys(accountPrivKey)
		if err != nil {
			return nil, err
		}
		externalPubkey, internalPubkey, err = generateAccountPubKeys(accountPubKey)
		if err != nil {
			return nil, err
		}
	} else {
		externalPubkey, internalPubkey, err = generateAccountPubKeys(accountPubKey)
		if err != nil {
			return nil, err
		}
	}

	km := &KeyManager{
		db:              db,
		internalPrivkey: internalPrivkey,
		internalPubkey:  internalPubkey,
		externalPrivkey: externalPrivkey,
		externalPubkey:  externalPubkey,
		coinType:        coinType,
		addrFunc:        addressFunc,
	}
	if err := km.ExtendKeychain(); err != nil {
		return nil, err
	}
	return km, nil
}

// SetPassphase encrypts the master private key in the database and
// deletes the internal and external private keys from memory.
func (km *KeyManager) SetPassphase(pw []byte) error {
	var (
		salt       = make([]byte, 32)
		rounds     = defaultKdfRounds
		keyLen     = defaultKeyLength
		coinRecord database.CoinRecord
	)

	return km.db.Update(func(tx database.Tx) error {
		err := tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&coinRecord).Error
		if err != nil {
			return err
		}

		if coinRecord.EncryptedMasterKey {
			return errors.New("keychain already encrypted")
		}

		plaintext := []byte(coinRecord.MasterPriv)

		_, err = rand.Read(salt)
		if err != nil {
			return err
		}
		dk := pbkdf2.Key(pw, salt, rounds, keyLen, sha512.New)

		block, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		ciphertext := make([]byte, aes.BlockSize+len(plaintext))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}

		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

		coinRecord.MasterPriv = base64.StdEncoding.EncodeToString(ciphertext)
		coinRecord.EncryptedMasterKey = true
		coinRecord.KdfRounds = rounds
		coinRecord.KdfKeyLen = keyLen
		coinRecord.Salt = salt

		km.externalPrivkey = nil
		km.internalPrivkey = nil

		return tx.Save(&coinRecord)
	})
}

func (km *KeyManager) ChangePassphrase(old, new []byte) error {
	if !km.IsEncrypted() {
		return errors.New("wallet is not encrypted")
	}

	var (
		salt       = make([]byte, 32)
		rounds     = defaultKdfRounds
		keyLen     = defaultKeyLength
		coinRecord database.CoinRecord
	)

	return km.db.Update(func(tx database.Tx) error {
		err := tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&coinRecord).Error
		if err != nil {
			return err
		}

		ciphertext, err := base64.StdEncoding.DecodeString(coinRecord.MasterPriv)
		if err != nil {
			return err
		}

		dk := pbkdf2.Key(old, coinRecord.Salt, coinRecord.KdfRounds, coinRecord.KdfKeyLen, sha512.New)

		block, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		if len(ciphertext) < aes.BlockSize {
			return errors.New("ciphertext too short")
		}
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]

		stream := cipher.NewCFBDecrypter(block, iv)

		// XORKeyStream can work in-place if the two arguments are the same.
		stream.XORKeyStream(ciphertext, ciphertext)

		plaintext := ciphertext

		_, err = rand.Read(salt)
		if err != nil {
			return err
		}

		dk = pbkdf2.Key(new, salt, rounds, keyLen, sha512.New)

		block, err = aes.NewCipher(dk)
		if err != nil {
			return err
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		ciphertext = make([]byte, aes.BlockSize+len(plaintext))
		iv = ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}

		stream = cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(ciphertext[aes.BlockSize:], plaintext)

		coinRecord.MasterPriv = base64.StdEncoding.EncodeToString(ciphertext)
		coinRecord.EncryptedMasterKey = true
		coinRecord.KdfRounds = rounds
		coinRecord.KdfKeyLen = keyLen
		coinRecord.Salt = salt

		return tx.Save(&coinRecord)
	})
}

// RemovePassphrase removes encryption from the master key and puts the
// external and internal keys back in memory.
func (km *KeyManager) RemovePassphrase(pw []byte) error {
	if !km.IsEncrypted() {
		return errors.New("wallet is not encrypted")
	}

	return km.db.Update(func(tx database.Tx) error {
		var coinRecord database.CoinRecord
		err := tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&coinRecord).Error
		if err != nil {
			return err
		}

		ciphertext, err := base64.StdEncoding.DecodeString(coinRecord.MasterPriv)
		if err != nil {
			return err
		}

		dk := pbkdf2.Key(pw, coinRecord.Salt, coinRecord.KdfRounds, coinRecord.KdfKeyLen, sha512.New)

		block, err := aes.NewCipher(dk)
		if err != nil {
			return err
		}

		// The IV needs to be unique, but not secure. Therefore it's common to
		// include it at the beginning of the ciphertext.
		if len(ciphertext) < aes.BlockSize {
			return errors.New("ciphertext too short")
		}
		iv := ciphertext[:aes.BlockSize]
		ciphertext = ciphertext[aes.BlockSize:]

		stream := cipher.NewCFBDecrypter(block, iv)

		// XORKeyStream can work in-place if the two arguments are the same.
		stream.XORKeyStream(ciphertext, ciphertext)

		key, err := hd.NewKeyFromString(string(ciphertext))
		if err != nil {
			return err
		}

		km.externalPrivkey, km.internalPrivkey, err = generateAccountPrivKeys(key)
		if err != nil {
			return err
		}

		coinRecord.MasterPriv = string(ciphertext)
		coinRecord.EncryptedMasterKey = false

		return tx.Save(&coinRecord)
	})
}

// Unlock will dcrypt the master key and store the external and internal
// private keys in memory for howLong.
func (km *KeyManager) Unlock(pw []byte, howLong time.Duration) error {
	if !km.IsEncrypted() {
		return errors.New("wallet is not encrypted")
	}

	var coinRecord database.CoinRecord
	err := km.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&coinRecord).Error
	})
	if err != nil {
		return err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(coinRecord.MasterPriv)
	if err != nil {
		return err
	}

	dk := pbkdf2.Key(pw, coinRecord.Salt, coinRecord.KdfRounds, coinRecord.KdfKeyLen, sha512.New)

	block, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < aes.BlockSize {
		return errors.New("ciphertext too short")
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)

	// XORKeyStream can work in-place if the two arguments are the same.
	stream.XORKeyStream(ciphertext, ciphertext)

	key, err := hd.NewKeyFromString(string(ciphertext))
	if err != nil {
		return err
	}

	km.externalPrivkey, km.internalPrivkey, err = generateAccountPrivKeys(key)
	if err != nil {
		return err
	}

	time.AfterFunc(howLong, func() {
		km.externalPrivkey = nil
		km.internalPrivkey = nil
	})
	return nil
}

// IsEncrypted returns whether or not this keychain is encrypted.
func (km *KeyManager) IsEncrypted() bool {
	return km.internalPrivkey == nil || km.externalPrivkey == nil
}

// GetAddresses returns all addresses in the wallet.
func (km *KeyManager) GetAddresses() ([]iwallet.Address, error) {
	var records []database.AddressRecord
	err := km.db.Update(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&records).Error
	})
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return nil, err
	}
	var addrs []iwallet.Address
	for _, rec := range records {
		addrs = append(addrs, rec.Address())
	}
	return addrs, nil
}

// CurrentAddress returns the first unused address.
func (km *KeyManager) CurrentAddress(change bool) (iwallet.Address, error) {
	var record database.AddressRecord
	err := km.db.View(func(tx database.Tx) error {
		return tx.Read().Order("key_index asc").Where("coin=?", km.coinType.CurrencyCode()).Where("used=?", false).Where("change=?", change).First(&record).Error
	})
	if err != nil {
		return iwallet.Address{}, err
	}
	return record.Address(), nil
}

// NewAddress returns a new, never before used address.
func (km *KeyManager) NewAddress(change bool) (iwallet.Address, error) {
	var address iwallet.Address
	err := km.db.Update(func(tx database.Tx) error {
		var record database.AddressRecord
		err := tx.Read().Order("key_index desc").Where("coin=?", km.coinType.CurrencyCode()).Where("change=?", change).First(&record).Error
		if err != nil {
			return err
		}
		var (
			index  = record.KeyIndex + 1
			newKey *hd.ExtendedKey
		)

		for {
			newKey, err = km.externalPubkey.Child(uint32(index))
			if err == nil {
				break
			}
			index++
		}

		address, err = km.addrFunc(newKey)
		if err != nil {
			return err
		}

		newRecord := &database.AddressRecord{
			Addr:     address.String(),
			KeyIndex: index,
			Change:   false,
			Used:     false,
			Coin:     km.coinType.CurrencyCode(),
		}
		if err := km.extendKeychain(tx); err != nil {
			return err
		}
		return tx.Save(&newRecord)
	})
	return address, err
}

// HasKey returns whether or not this wallet can derive the key for
// this address.
func (km *KeyManager) HasKey(addr iwallet.Address) (bool, error) {
	has := false
	err := km.db.View(func(tx database.Tx) error {
		var record database.AddressRecord
		err := tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Where("addr=?", addr.String()).First(&record).Error
		if err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		} else if err == nil {
			has = true
		}
		return nil
	})
	return has, err
}

// KeyForAddress returns the private key for the given address. If this wallet is not
// encrypted then accountPrivKey may be nil and it will generate and return the key.
// However, if the wallet is encrypted a unencrypted accountPrivKey must be passed in
// so we can derive the correct child key.
func (km *KeyManager) KeyForAddress(addr iwallet.Address, accountPrivKey *hd.ExtendedKey) (*hd.ExtendedKey, error) {
	var record database.AddressRecord
	err := km.db.View(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", km.coinType.CurrencyCode()).Where("addr=?", addr.String()).First(&record).Error
	})
	if err != nil {
		return nil, err
	}
	var (
		key             *hd.ExtendedKey
		externalPrivkey = km.externalPrivkey
		internalPrivkey = km.internalPrivkey
	)

	if (externalPrivkey == nil || internalPrivkey == nil) && accountPrivKey != nil {
		externalPrivkey, internalPrivkey, err = generateAccountPrivKeys(accountPrivKey)
		if err != nil {
			return nil, err
		}
	}

	if record.Change {
		if internalPrivkey == nil {
			return nil, ErrEncryptedKeychain
		}
		key, err = internalPrivkey.Child(uint32(record.KeyIndex))
	} else {
		if externalPrivkey == nil {
			return nil, ErrEncryptedKeychain
		}
		key, err = externalPrivkey.Child(uint32(record.KeyIndex))
	}
	return key, err
}

// MarkAddressAsUsed marks the given address as used and extends the keychain.
func (km *KeyManager) MarkAddressAsUsed(dbtx database.Tx, addr iwallet.Address) error {
	var record database.AddressRecord
	err := dbtx.Read().Where("coin=?", km.coinType.CurrencyCode()).Where("addr=?", addr.String()).First(&record).Error
	if err != nil {
		return err
	}
	record.Used = true

	if err := dbtx.Save(&record); err != nil {
		return err
	}

	return km.extendKeychain(dbtx)
}

// ExtendKeychain generates a buffer of 20 unused keys after the last used
// key in both the internal and external keychains. The reason we do this
// is to increase the likelihood that we will detect all our transactions
// when restoring from seed.
//
// The typical rescan workflow is:
// 1. Extend keychain
// 2. Query for transactions
// 3. If there are any transactions returned repeat steps 1 - 3 until
// there are no more transactions returned.
func (km *KeyManager) ExtendKeychain() error {
	return km.db.Update(func(tx database.Tx) error {
		return km.extendKeychain(tx)
	})
}

func (km *KeyManager) extendKeychain(tx database.Tx) error {
	internalUnused, externalUnused, err := km.getLookaheadWindows(tx)
	if err != nil {
		return err
	}
	if internalUnused < LookaheadWindow {
		if err := km.createNewKeys(tx, true, LookaheadWindow-internalUnused); err != nil {
			return err
		}
	}
	if externalUnused < LookaheadWindow {
		if err := km.createNewKeys(tx, false, LookaheadWindow-externalUnused); err != nil {
			return err
		}
	}
	return nil
}

func (km *KeyManager) createNewKeys(dbtx database.Tx, change bool, numKeys int) error {
	var record database.AddressRecord
	err := dbtx.Read().Order("key_index desc").Where("coin=?", km.coinType.CurrencyCode()).Where("used=?", true).Where("change=?", change).First(&record).Error
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return err
	}
	var (
		nextIndex     = record.KeyIndex + 1
		generatedKeys = 0
	)
	for generatedKeys < numKeys {
		// There is a small possibility bip32 keys can be invalid. The procedure in such cases
		// is to discard the key and derive the next one. This loop will continue until a valid key
		// is derived.
		var newKey *hd.ExtendedKey
		if change {
			newKey, err = km.internalPubkey.Child(uint32(nextIndex))
		} else {
			newKey, err = km.externalPubkey.Child(uint32(nextIndex))
		}
		if err != nil {
			nextIndex++
			continue
		}

		addr, err := km.addrFunc(newKey)
		if err != nil {
			return err
		}

		newRecord := &database.AddressRecord{
			Addr:     addr.String(),
			KeyIndex: nextIndex,
			Change:   change,
			Used:     false,
			Coin:     km.coinType.CurrencyCode(),
		}

		if err := dbtx.Save(&newRecord); err != nil {
			return err
		}
		generatedKeys++
		nextIndex++
	}
	return nil
}

func (km *KeyManager) getLookaheadWindows(dbtx database.Tx) (internalUnused, externalUnused int, err error) {
	var addressRecords []database.AddressRecord
	rerr := dbtx.Read().Where("coin=?", km.coinType.CurrencyCode()).Find(&addressRecords).Error
	if rerr != nil && !gorm.IsRecordNotFoundError(rerr) {
		err = rerr
		return
	}
	internalLastUsed := -1
	externalLastUsed := -1
	for _, rec := range addressRecords {
		if rec.Change && rec.Used && rec.KeyIndex > internalLastUsed {
			internalLastUsed = rec.KeyIndex
		}
		if !rec.Change && rec.Used && rec.KeyIndex > externalLastUsed {
			externalLastUsed = rec.KeyIndex
		}
	}
	for _, rec := range addressRecords {
		if rec.Change && !rec.Used && rec.KeyIndex > internalLastUsed {
			internalUnused++
		}
		if !rec.Change && !rec.Used && rec.KeyIndex > externalLastUsed {
			externalUnused++
		}
	}
	return
}

func generateAccountPrivKeys(accountPrivKey *hd.ExtendedKey) (external, internal *hd.ExtendedKey, err error) {
	// Change(0) = external
	external, err = accountPrivKey.Child(0)
	if err != nil {
		return nil, nil, err
	}
	// Change(1) = internal
	internal, err = accountPrivKey.Child(1)
	if err != nil {
		return nil, nil, err
	}
	return
}

func generateAccountPubKeys(accountPubKey *hd.ExtendedKey) (external, internal *hd.ExtendedKey, err error) {
	// Change(0) = external
	external, err = accountPubKey.Child(0)
	if err != nil {
		return nil, nil, err
	}
	// Change(1) = internal
	internal, err = accountPubKey.Child(1)
	if err != nil {
		return nil, nil, err
	}
	return
}
