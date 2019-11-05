package database

func InitializeDatabase(db Database) error {
	return db.Update(func(tx Tx) error {
		models := []interface{}{
			&CoinRecord{},
			&UtxoRecord{},
			&TransactionRecord{},
			&AddressRecord{},
			&WatchedAddressRecord{},
		}
		for _, model := range models {
			if err := tx.Migrate(model); err != nil {
				return err
			}
		}
		return nil
	})
}
