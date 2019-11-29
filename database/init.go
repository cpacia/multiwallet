package database

func InitializeDatabase(db Database) error {
	return db.Update(func(tx Tx) error {
		models := []interface{}{
			&CoinRecord{},
			&UtxoRecord{},
			&TransactionRecord{},
			&AddressRecord{},
			&WatchedAddressRecord{},
			&UnconfirmedTransaction{},
		}
		for _, model := range models {
			if err := tx.Migrate(model); err != nil {
				return err
			}
		}
		return nil
	})
}
