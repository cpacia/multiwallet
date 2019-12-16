package sqlitedb

import (
	"errors"
	"github.com/cpacia/multiwallet/database"
	"github.com/jinzhu/gorm"
	"testing"
)

func TestSqliteDB_UpdateAndView(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}

	err = db.Update(func(tx database.Tx) error {
		if err := tx.Migrate(&database.TransactionRecord{}); err != nil {
			return err
		}
		return tx.Save(&database.TransactionRecord{Txid: "abc"})
	})
	if err != nil {
		t.Error(err)
	}

	var txs []database.TransactionRecord
	err = db.View(func(tx database.Tx) error {
		if err := tx.Read().Find(&txs).Error; err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(txs) != 1 {
		t.Errorf("Db update failed. Expected %d txs got %d", 1, len(txs))
	}

	err = db.Update(func(tx database.Tx) error {
		err := errors.New("atomic update failure")

		if err := tx.Save(&database.TransactionRecord{Txid: "abc"}); err != nil {
			t.Fatal(err)
		}
		return err
	})
	if err == nil {
		t.Error("Update function did not return error")
	}

	var txs2 []database.TransactionRecord
	err = db.View(func(tx database.Tx) error {
		if err := tx.Read().Find(&txs2).Error; err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(txs2) > 1 {
		t.Error("Db update failed to roll back.")
	}
}

func TestSqliteDB_Rollback(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}

	err = db.Update(func(tx database.Tx) error {
		return tx.Migrate(&database.TransactionRecord{})
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.Update(func(tx database.Tx) error {
		if err := tx.Save(&database.TransactionRecord{Txid: "abc"}); err != nil {
			return err
		}
		return errors.New("failure :(")
	})
	if err == nil {
		t.Error("no error returned from update")
	}

	var txs []database.TransactionRecord
	err = db.View(func(tx database.Tx) error {
		if err := tx.Read().Find(&txs).Error; err != nil && !gorm.IsRecordNotFoundError(err) {
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(txs) != 0 {
		t.Error("Db update failed to roll back.")
	}
}

func TestSqliteDB_CRUD(t *testing.T) {
	db, err := NewMemoryDB()
	if err != nil {
		t.Fatal(err)
	}

	err = db.Update(func(tx database.Tx) error {
		if err := tx.Migrate(&database.UtxoRecord{}); err != nil {
			return err
		}
		return tx.Save(&database.UtxoRecord{
			Outpoint: "0000",
			Height: 1234,
		})
	})
	if err != nil {
		t.Error(err)
	}

	var utxos []database.UtxoRecord
	err = db.View(func(tx database.Tx) error {
		return tx.Read().Find(&utxos).Error
	})
	if err != nil {
		t.Error(err)
	}

	if len(utxos) != 1 {
		t.Error("Failed to save utxo to the database")
	}


	err = db.Update(func(tx database.Tx) error {
		return tx.Update("address", "abc", map[string]interface{}{"outpoint = ?": "0000"}, &database.UtxoRecord{})
	})
	if err != nil {
		t.Error(err)
	}

	var utxos2 []database.UtxoRecord
	err = db.View(func(tx database.Tx) error {
		return tx.Read().Find(&utxos2).Error
	})
	if err != nil {
		t.Error(err)
	}

	if len(utxos2) != 1 {
		t.Error("Failed to read utxo to the database")
	}

	if utxos2[0].Address != "abc" {
		t.Error("Failed to update model")
	}

	err = db.Update(func(tx database.Tx) error {
		return tx.Delete("address", "abc", &database.UtxoRecord{})
	})
	if err != nil {
		t.Error(err)
	}

	var utxos3 []database.UtxoRecord
	err = db.View(func(tx database.Tx) error {
		return tx.Read().Find(&utxos3).Error
	})
	if err != nil {
		t.Error(err)
	}

	if len(utxos3) != 0 {
		t.Error("Failed to delete utxo from the database")
	}
}