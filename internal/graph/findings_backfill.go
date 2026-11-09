package graph

import (
	"context"
	"errors"
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// BackfillCandidateFindings materializes every stored finding candidate in
// deterministic pages. It is idempotent because the planner is keyed by
// hypothesis id and never rewrites a candidate that already exists.
func BackfillCandidateFindings(
	ctx context.Context,
	store storage.FullStore,
	planner *VerifyPlanner,
	query agent.HypothesisQuery,
	pageSize int,
) (int, error) {
	if store == nil || planner == nil {
		return 0, errors.New("graph: candidate finding backfill needs a store and planner")
	}
	if pageSize <= 0 || pageSize > 500 {
		pageSize = 200
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	ensured := 0
	for offset := 0; ; {
		query.FindingCandidatesOnly = true
		query.Limit = pageSize
		query.Offset = offset
		hypotheses, total, err := store.ListHypotheses(query)
		if err != nil {
			return ensured, fmt.Errorf("graph: list finding candidates: %w", err)
		}
		if len(hypotheses) == 0 {
			return ensured, nil
		}
		for _, hypothesis := range hypotheses {
			if err := ctx.Err(); err != nil {
				return ensured, err
			}
			if _, err := planner.EnsureFinding(ctx, hypothesis.ID); err != nil {
				return ensured, fmt.Errorf("graph: materialize finding candidate %s: %w", hypothesis.ID, err)
			}
			ensured++
		}
		offset += len(hypotheses)
		if offset >= total {
			return ensured, nil
		}
	}
}
