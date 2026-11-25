package store

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	"tunneldeck/internal/domain"
)

func TestConcurrentWriters(t *testing.T) {
	s, dir := newTestStore(t)
	const writers = 20

	var wg sync.WaitGroup
	errs := make(chan error, writers*3)
	for i := range writers {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, err := s.CreateProfile(openVPNProfile(fmt.Sprintf("profile-%d", i)))
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_, err := s.SetHostAccessRules([]domain.HostAccessRule{{Protocol: domain.TransportTCP, Port: 1000 + i}})
			errs <- err
		}()
		go func() {
			defer wg.Done()
			_ = s.ListProfiles()
			_ = s.HostAccessRules()
			errs <- s.SetLanguage(domain.LanguageGerman)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write failed: %v", err)
		}
	}

	reopened := openTestStore(t, dir, newCipher(t, 1))
	if n := len(reopened.ListProfiles()); n != writers {
		t.Fatalf("%d profiles on disk, want %d", n, writers)
	}
	if rules := reopened.HostAccessRules(); len(rules) != 1 {
		t.Fatalf("rules on disk = %+v, want the last complete list", rules)
	}
	assertNoTempFiles(t, dir)
}

func TestConcurrentDuplicateNamesAllowOnlyOne(t *testing.T) {
	s, _ := newTestStore(t)
	const attempts = 10

	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := s.CreateProfile(openVPNProfile("Same"))
			results <- err
		}()
	}
	wg.Wait()
	close(results)

	var ok, conflicts int
	for err := range results {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, domain.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 || conflicts != attempts-1 {
		t.Fatalf("%d created, %d conflicts; want 1 and %d", ok, conflicts, attempts-1)
	}
}

func TestConcurrentSetupAllowsOnlyOneAdmin(t *testing.T) {
	s, _ := newTestStore(t)
	const attempts = 10

	var wg sync.WaitGroup
	results := make(chan error, attempts)
	for i := range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.CreateAdminAccount(domain.AdminAccount{Username: fmt.Sprintf("admin%d", i), PasswordHash: "h"})
		}()
	}
	wg.Wait()
	close(results)

	var ok int
	for err := range results {
		switch {
		case err == nil:
			ok++
		case !errors.Is(err, domain.ErrSetupAlreadyDone):
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if ok != 1 {
		t.Fatalf("%d admin accounts created, want 1", ok)
	}
}
