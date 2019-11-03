package sqlitedb

import (
	"errors"
	"fmt"
	"github.com/cpacia/multiwallet/database"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite" // Import sqlite dialect
	"path"
	"sync"
)

const (
	dbName = "openbazaar.db"
)

var ErrReadOnly = errors.New("tx is read only")

// SqliteDB is an implementation of the Database interface using
// flat file store for the public data and a sqlite database.
type DB struct {
	db  *gorm.DB
	mtx sync.RWMutex
}

// NewSqliteDB instantiates a new db which satisfies the Database interface.
func NewSqliteDB(dataDir string) (database.Database, error) {
	db, err := gorm.Open("sqlite3", path.Join(dataDir, "datastore", dbName))
	if err != nil {
		return nil, err
	}
	return &DB{db: db, mtx: sync.RWMutex{}}, nil
}

// NewMemoryDB instantiates a new db which satisfies the Database interface.
// The sqlite db will be held in memory.
func NewMemoryDB(dataDir string) (database.Database, error) {
	db, err := gorm.Open("sqlite3", ":memory:")
	if err != nil {
		return nil, err
	}
	return &DB{db: db, mtx: sync.RWMutex{}}, nil
}

// View invokes the passed function in the context of a managed
// read-only transaction.  Any errors returned from the user-supplied
// function are returned from this function.
//
// Calling Rollback or Commit on the transaction passed to the
// user-supplied function will result in a panic.
func (fdb *DB) View(fn func(tx database.Tx) error) error {
	fdb.mtx.RLock()
	defer fdb.mtx.RUnlock()

	tx := readTx(fdb.db)
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Update invokes the passed function in the context of a managed
// read-write transaction.  Any errors returned from the user-supplied
// function will cause the transaction to be rolled back and are
// returned from this function.  Otherwise, the transaction is committed
// when the user-supplied function returns a nil error.
//
// Calling Rollback or Commit on the transaction passed to the
// user-supplied function will result in a panic.
func (fdb *DB) Update(fn func(tx database.Tx) error) error {
	fdb.mtx.Lock()
	defer fdb.mtx.Unlock()

	tx := writeTx(fdb.db)
	if err := fn(tx); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Close cleanly shuts down the database and syncs all data.  It will
// block until all database transactions have been finalized (rolled
// back or committed).
func (fdb *DB) Close() error {
	fdb.mtx.Lock()
	defer fdb.mtx.Unlock()

	return fdb.db.Close()
}

type tx struct {
	dbtx *gorm.DB

	rollbackCache []interface{}
	commitCache   []interface{}

	closed      bool
	isForWrites bool
}

type deleteListing string

func writeTx(db *gorm.DB) database.Tx {
	dbtx := db.Begin()
	return &tx{dbtx: dbtx, isForWrites: true}
}

func readTx(db *gorm.DB) database.Tx {
	return &tx{dbtx: db, isForWrites: false}
}

// Commit commits all changes that have been made to the db or public data.
// Depending on the backend implementation this could be to a cache that
// is periodically synced to persistent storage or directly to persistent
// storage.  In any case, all transactions which are started after the commit
// finishes will include all changes made by this transaction.  Calling this
// function on a managed transaction will result in a panic.
func (t *tx) Commit() error {
	if t.closed {
		panic("tx already closed")
	}

	defer func() { t.closed = true }()

	if !t.isForWrites {
		return nil
	}

	if err := t.dbtx.Commit().Error; err != nil {
		t.Rollback()
		return err
	}
	return nil
}

// Rollback undoes all changes that have been made to the db or public
// data.  Calling this function on a managed transaction will result in
// a panic.
func (t *tx) Rollback() error {
	if t.closed {
		panic("tx already closed")
	}

	defer func() { t.closed = true }()

	if !t.isForWrites {
		return nil
	}

	if err := t.dbtx.Rollback().Error; err != nil {
		return err
	}
	return nil
}

// Save will save the passed in model to the database. If it already exists
// it will be overridden.
func (t *tx) Save(model interface{}) error {
	if !t.isForWrites {
		return ErrReadOnly
	}
	return t.dbtx.Save(model).Error
}

// Read returns the underlying sql database in a read-only mode so that
// queries can be made against it.
func (t *tx) Read() *gorm.DB {
	return t.dbtx
}

func (t *tx) Update(key string, value interface{}, where map[string]interface{}, model interface{}) error {
	if !t.isForWrites {
		return ErrReadOnly
	}
	db := t.dbtx.Model(model)
	for k, v := range where {
		db = db.Where(k, v)
	}
	return db.UpdateColumn(key, value).Error
}

// Delete will delete all models of the given type from the database where
// field == key.
func (t *tx) Delete(key string, value interface{}, model interface{}) error {
	if !t.isForWrites {
		return ErrReadOnly
	}
	return t.dbtx.Where(fmt.Sprintf("%s = ?", key), value).Delete(model).Error
}

// Migrate will auto-migrate the database to from any previous schema for this
// model to the current schema.
func (t *tx) Migrate(model interface{}) error {
	if !t.isForWrites {
		return ErrReadOnly
	}
	return t.dbtx.AutoMigrate(model).Error
}
