package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// schemaVersionKey is the top-level JSON key holding a file's schema version.
const schemaVersionKey = "schemaVersion"

// errSchemaTooNew reports a data file written by a newer TunnelDeck.
var errSchemaTooNew = errors.New("schema version is newer than supported")

// migration upgrades a decoded data file by exactly one schema version, in
// place. The loader sets schemaVersion afterwards.
type migration func(doc map[string]json.RawMessage) error

// migrations maps the version a step upgrades from to the step.
type migrations map[int]migration

// Registered migration steps. To change a file format: bump the file's
// current schema version and register the step from the previous version
// here, keyed by that previous version.
var (
	settingsMigrations = migrations{1: migrateSettingsV1ToV2, 2: migrateSettingsV2ToV3, 3: migrateSettingsV3ToV4}
	profilesMigrations = migrations{}
)

// documentSpec describes one versioned JSON data file.
type documentSpec struct {
	fileName       string
	currentVersion int
	migrations     migrations
}

// load decodes the file into target. A missing file leaves target untouched.
// Older versions are migrated step by step; newer versions and corrupted
// files are errors naming the file, and the file is never modified here.
func (d documentSpec) load(fsys fileSystem, dir string, target any) error {
	data, err := fsys.ReadFile(filepath.Join(dir, d.fileName))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", d.fileName, err)
	}
	doc, version, err := d.decodeVersioned(data)
	if err != nil {
		return err
	}
	if err := d.migrate(doc, version); err != nil {
		return err
	}
	if err := remarshal(doc, target); err != nil {
		return fmt.Errorf("%s is corrupted: %w", d.fileName, err)
	}
	return nil
}

func (d documentSpec) decodeVersioned(data []byte) (map[string]json.RawMessage, int, error) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, 0, fmt.Errorf("%s is corrupted: %w", d.fileName, err)
	}
	if doc == nil {
		return nil, 0, fmt.Errorf("%s is corrupted: top-level value is null", d.fileName)
	}
	version := 0 // files without a version predate versioning
	if raw, ok := doc[schemaVersionKey]; ok {
		if err := json.Unmarshal(raw, &version); err != nil {
			return nil, 0, fmt.Errorf("%s is corrupted: %s is not an integer", d.fileName, schemaVersionKey)
		}
	}
	if version > d.currentVersion {
		return nil, 0, fmt.Errorf("%s: %w: file has version %d, this TunnelDeck-VPN supports up to %d; upgrade TunnelDeck-VPN",
			d.fileName, errSchemaTooNew, version, d.currentVersion)
	}
	return doc, version, nil
}

func (d documentSpec) migrate(doc map[string]json.RawMessage, from int) error {
	for version := from; version < d.currentVersion; version++ {
		step, ok := d.migrations[version]
		if !ok {
			return fmt.Errorf("%s: no migration from schema version %d to %d", d.fileName, version, version+1)
		}
		if err := step(doc); err != nil {
			return fmt.Errorf("%s: migrate schema version %d to %d: %w", d.fileName, version, version+1, err)
		}
		doc[schemaVersionKey] = json.RawMessage(fmt.Sprint(version + 1))
	}
	return nil
}

// save encodes doc and writes it atomically.
func (d documentSpec) save(fsys fileSystem, dir string, doc any) error {
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("encode %s: %w", d.fileName, err)
	}
	if err := writeFileAtomic(fsys, filepath.Join(dir, d.fileName), data); err != nil {
		return fmt.Errorf("write %s: %w", d.fileName, err)
	}
	return nil
}

func remarshal(doc map[string]json.RawMessage, target any) error {
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}
