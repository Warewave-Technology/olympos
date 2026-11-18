package app

import (
	"github.com/Warewave-Technology/olympos/internal/backup"
	"github.com/Warewave-Technology/olympos/internal/backup/engines/postgres"
	"github.com/Warewave-Technology/olympos/internal/blob"
	"github.com/Warewave-Technology/olympos/internal/server"
)

// Backups (M2): API, scheduler and workers (SPEC §10).
func init() {
	Register(func(d *Deps) (Wiring, error) {
		postgres.SetDumpDir(d.Cfg.Backup.PgDumpDir)
		storage, err := storageOptions(d.Cfg)
		if err != nil {
			return Wiring{}, err
		}
		creds := &backup.Credentials{KV: d.KV, Envelope: d.Envelope}
		log := d.Log.With("component", "backup")

		d.Inventory.OnTargetGone = append(d.Inventory.OnTargetGone, backup.OnTargetGone)
		d.Inventory.OnTargetUpsert = append(d.Inventory.OnTargetUpsert, backup.OnTargetUpsert)

		api := &backup.API{DB: d.DB, Log: log, Dialer: d.Gateway, Creds: creds}
		sched := &backup.Scheduler{DB: d.DB, Log: log.With("loop", "scheduler"), DeadMansSwitchURL: d.Cfg.DeadMansSwitch.URL}
		blobs := blob.NewResolver(d.DB, d.KV, d.Envelope, d.Cred, blob.WithStorage(storage))
		worker := &backup.Worker{
			DB: d.DB, Log: log.With("loop", "worker"), Dialer: d.Gateway, Creds: creds,
			Blobs:  blobs,
			Global: d.Cfg.Backup.GlobalConcurrency, PerCluster: d.Cfg.Backup.PerClusterConcurrency,
		}
		// olympos-self: Olympos' own database (F17).
		self := &backup.SelfBackup{DB: d.DB, Log: log.With("loop", "olympos-self"), Blobs: blobs,
			DSN: d.SelfDB.DSN, Password: d.SelfDB.Password}
		return Wiring{
			Modules: []server.Module{api},
			Workers: []Worker{sched.Run, worker.Run, self.Run},
		}, nil
	})
}
