package main

import (
	"errors"
	"fmt"
	"os"
)

const (
	batchSucceeded    = "succeeded"
	batchFailed       = "failed"
	batchNotAttempted = "not_attempted"
)

// destructiveBatchReport is the stable JSON envelope shared by destructive CLI
// batches. Results are always in requested order (except that a current-device
// revoke is deliberately moved last). complete describes execution of the request,
// while dryRun says that no mutations were attempted.
type destructiveBatchReport struct {
	Complete bool                     `json:"complete"`
	DryRun   bool                     `json:"dryRun"`
	Results  []destructiveBatchResult `json:"results"`
}

type destructiveBatchResult struct {
	ID                 string `json:"id"`
	Status             string `json:"status"`
	Error              string `json:"error,omitempty"`
	SnapshotsDeleted   int    `json:"snapshotsDeleted,omitempty"`
	SnapshotsRemaining int    `json:"snapshotsRemaining,omitempty"`
}

type destructiveBatchError struct{ cause error }

func (e *destructiveBatchError) Error() string { return e.cause.Error() }
func (e *destructiveBatchError) Unwrap() error { return e.cause }

func batchFailure(err error) error {
	if err == nil {
		return nil
	}
	return &destructiveBatchError{cause: err}
}

func newBatchResults(ids []string) []destructiveBatchResult {
	results := make([]destructiveBatchResult, len(ids))
	for i, id := range ids {
		results[i] = destructiveBatchResult{ID: id, Status: batchNotAttempted}
	}
	return results
}

func failBatchPreflight(results []destructiveBatchResult, failures map[int]error) error {
	var first error
	for i := range results {
		if err := failures[i]; err != nil {
			results[i].Status = batchFailed
			results[i].Error = err.Error()
			if first == nil {
				first = err
			}
		} else {
			results[i].Error = "preflight failed"
		}
	}
	return batchFailure(first)
}

func markBatchFailure(results []destructiveBatchResult, failed int, err error) error {
	results[failed].Status = batchFailed
	results[failed].Error = err.Error()
	for i := failed + 1; i < len(results); i++ {
		results[i].Status = batchNotAttempted
		results[i].Error = "an earlier operation failed"
	}
	return batchFailure(err)
}

func finishDestructiveBatch(report destructiveBatchReport, action string, err error) error {
	if flagJSON {
		if printErr := printJSON(report); printErr != nil {
			return errors.Join(err, printErr)
		}
		return err
	}
	for _, result := range report.Results {
		switch result.Status {
		case batchSucceeded:
			fmt.Fprintf(os.Stderr, "%s %s\n", action, result.ID)
		case batchFailed:
			fmt.Fprintf(os.Stderr, "failed to %s %s: %s\n", action, result.ID, result.Error)
		case batchNotAttempted:
			if result.Error != "" && !report.DryRun {
				fmt.Fprintf(os.Stderr, "did not %s %s: %s\n", action, result.ID, result.Error)
			}
		}
	}
	return err
}
