package base

import (
	hd "github.com/btcsuite/btcutil/hdkeychain"
	"github.com/cpacia/multiwallet/database"
	iwallet "github.com/cpacia/wallet-interface"
	"github.com/jinzhu/gorm"
)

const LookaheadWindow = 20

type KeyManager struct {
	db              database.Database
	internalPrivkey *hd.ExtendedKey
	internalPubkey  *hd.ExtendedKey

	externalPrivkey *hd.ExtendedKey
	externalPubkey  *hd.ExtendedKey

	coin iwallet.CoinType

	addrFunc func(key *hd.ExtendedKey) (iwallet.Address, error)
}

func NewKeyManager(db database.Database, masterPrivKey, masterPubkey *hd.ExtendedKey, coinType iwallet.CoinType, addressFunc func(key *hd.ExtendedKey) (iwallet.Address, error)) (*KeyManager, error) {
	var internalPrivkey, internalPubkey, externalPrivkey, externalPubkey *hd.ExtendedKey
	if masterPrivKey != nil {
		// Account = 0
		account, err := masterPrivKey.Child(hd.HardenedKeyStart + 0)
		if err != nil {
			return nil, err
		}
		// Change(0) = external
		externalPrivkey, err = account.Child(0)
		if err != nil {
			return nil, err
		}
		externalPubkey, err = externalPrivkey.Neuter()
		if err != nil {
			return nil, err
		}
		// Change(1) = internal
		internalPrivkey, err = account.Child(1)
		if err != nil {
			return nil, err
		}
		internalPubkey, err = internalPrivkey.Neuter()
		if err != nil {
			return nil, err
		}
	} else {
		// Account = 0
		account, err := masterPubkey.Child(hd.HardenedKeyStart + 0)
		if err != nil {
			return nil, err
		}
		// Change(0) = external
		externalPubkey, err = account.Child(0)
		if err != nil {
			return nil, err
		}
		// Change(1) = internal
		internalPubkey, err = account.Child(1)
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
		coin:            coinType,
		addrFunc:        addressFunc,
	}
	if err := km.ExtendKeychain(); err != nil {
		return nil, err
	}
	return km, nil
}

func (km *KeyManager) GetAddresses() ([]iwallet.Address, error) {
	var records []database.AddressRecord
	err := km.db.Update(func(tx database.Tx) error {
		return tx.Read().Where("coin=?", km.coin.CurrencyCode()).Find(&records).Error
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

func (km *KeyManager) CurrentAddress() (iwallet.Address, error) {
	var record database.AddressRecord
	err := km.db.View(func(tx database.Tx) error {
		return tx.Read().Order("key_index asc").Where("coin=?", km.coin.CurrencyCode()).Where("used=?", false).Where("change=?", false).First(&record).Error
	})
	if err != nil {
		return iwallet.Address{}, err
	}
	return record.Address(), nil
}

func (km *KeyManager) NewAddress() (iwallet.Address, error) {
	var address iwallet.Address
	err := km.db.Update(func(tx database.Tx) error {
		var record database.AddressRecord
		err := tx.Read().Order("key_index desc").Where("coin=?", km.coin.CurrencyCode()).Where("change=?", false).First(&record).Error
		if err != nil {
			return err
		}
		newKey, err := km.externalPubkey.Child(uint32(record.KeyIndex + 1))
		if err != nil {
			return err
		}

		address, err = km.addrFunc(newKey)
		if err != nil {
			return err
		}

		newRecord := &database.AddressRecord{
			Addr:     address.String(),
			KeyIndex: record.KeyIndex + 1,
			Change:   false,
			Used:     false,
			Coin:     km.coin.CurrencyCode(),
		}
		if err := km.extendKeychain(tx); err != nil {
			return err
		}
		return tx.Save(&newRecord)
	})
	return address, err
}

func (km *KeyManager) HasKey(addr iwallet.Address) (bool, error) {
	has := false
	err := km.db.View(func(tx database.Tx) error {
		var record database.AddressRecord
		err := tx.Read().Where("coin=?", km.coin.CurrencyCode()).Where("addr=?", addr.String()).First(&record).Error
		if err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		} else if err == nil {
			has = true
		}
		return nil
	})
	return has, err
}

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
	err := dbtx.Read().Order("key_index desc").Where("coin=?", km.coin.CurrencyCode()).Where("used=?", true).Where("change=?", change).First(&record).Error
	if err != nil && !gorm.IsRecordNotFoundError(err) {
		return err
	}
	nextIndex := record.KeyIndex + 1
	for i := 0; i < numKeys; i++ {
		var newKey *hd.ExtendedKey
		if change {
			newKey, err = km.internalPubkey.Child(uint32(nextIndex + i))
		} else {
			newKey, err = km.externalPubkey.Child(uint32(nextIndex + i))
		}

		addr, err := km.addrFunc(newKey)
		if err != nil {
			return err
		}

		newRecord := &database.AddressRecord{
			Addr:     addr.String(),
			KeyIndex: nextIndex + i,
			Change:   change,
			Used:     false,
			Coin:     km.coin.CurrencyCode(),
		}

		if err := dbtx.Save(&newRecord); err != nil {
			return err
		}
	}
	return nil
}

func (km *KeyManager) getLookaheadWindows(dbtx database.Tx) (internalUnused, externalUnused int, err error) {
	var addressRecords []database.AddressRecord
	rerr := dbtx.Read().Where("coin=?", km.coin.CurrencyCode()).Find(&addressRecords).Error
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
