module github.com/cpacia/multiwallet

go 1.13

require (
	github.com/Groestlcoin/go-groestl-hash v0.0.0-20181012171753-790653ac190c // indirect
	github.com/OpenBazaar/golang-socketio v0.0.0-20200109001351-4147b5f0d294
	github.com/StackExchange/wmi v0.0.0-20190523213315-cbe66965904d // indirect
	github.com/btcsuite/btcd v0.20.1-beta
	github.com/btcsuite/btcutil v0.0.0-20190425235716-9e5f4b9a998d
	github.com/btcsuite/btcwallet/wallet/txauthor v1.0.0
	github.com/btcsuite/btcwallet/wallet/txrules v1.0.0
	github.com/btcsuite/btcwallet/wallet/txsizes v1.0.0
	github.com/cenkalti/backoff v2.2.1+incompatible
	github.com/cpacia/proxyclient v0.0.0-20191212063311-f03265f1fade
	github.com/cpacia/wallet-interface v0.0.0-20200604163334-1be951c8f4bd
	github.com/dchest/blake256 v1.1.0 // indirect
	github.com/ethereum/go-ethereum v1.9.25
	github.com/gcash/bchd v0.15.3-0.20200229013353-8c1fa57b15e7
	github.com/gcash/bchutil v0.0.0-20200228172631-5e1930e5d630
	github.com/gcash/bchwallet v0.8.2
	github.com/go-ole/go-ole v1.2.4 // indirect
	github.com/gorilla/websocket v1.4.1
	github.com/jarcoal/httpmock v1.0.4
	github.com/ltcsuite/ltcd v0.20.1-beta
	github.com/ltcsuite/ltcutil v0.0.0-20191227053721-6bec450ea6ad
	github.com/ltcsuite/ltcwallet/wallet/txauthor v1.0.0
	github.com/ltcsuite/ltcwallet/wallet/txrules v1.0.0
	github.com/martinboehm/btcd v0.0.0-20190104121910-8e7c0427fee5
	github.com/martinboehm/btcutil v0.0.0-20191023112652-a3d2b8457b77
	github.com/mattn/go-colorable v0.1.4 // indirect
	github.com/mattn/go-isatty v0.0.9 // indirect
	github.com/mattn/go-runewidth v0.0.7 // indirect
	github.com/minio/blake2b-simd v0.0.0-20160723061019-3f5f724cb5b1
	github.com/natefinch/lumberjack v2.0.0+incompatible
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7
	github.com/pkg/errors v0.9.1 // indirect
	golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9
	google.golang.org/grpc v1.25.1
	gopkg.in/natefinch/lumberjack.v2 v2.0.0 // indirect
	gorm.io/driver/sqlite v1.1.3
	gorm.io/gorm v1.20.2
)

replace (
	github.com/Roasbeef/ltcutil/bech32 => github.com/ltcsuite/ltcutil v0.0.0-20190507133322-23cdfa9fcc3d
	github.com/lightninglabs/neutrino => github.com/lightninglabs/neutrino v0.11.0
)
