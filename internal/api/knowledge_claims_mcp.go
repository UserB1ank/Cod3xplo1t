package api

import (
	"context"
	"encoding/json"
	"strconv"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/claim"
)

type claimNoteInput struct {
	ClaimID string `json:"claim_id"`
	claim.Input
}
type claimQueryInput struct {
	SnapshotID string `json:"snapshot_id,omitempty"`
	ClaimID    string `json:"claim_id,omitempty"`
	Revision   int64  `json:"revision,omitempty"`
	Cursor     int64  `json:"cursor,omitempty"`
	Limit      int    `json:"limit,omitempty"`
}

func (s *Server) registerClaimTools(server *sdk.Server, principal Principal, project, snapshot string, origin claim.Origin) {
	mutate := func(ctx context.Context, in claim.Input, claimID, suffix string) (*sdk.CallToolResult, any, error) {
		if in.SnapshotID == "" {
			in.SnapshotID = snapshot
		}
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, nil, err
		}
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil {
			return nil, nil, err
		}
		path := "POST /api/v1/projects/{projectID}/knowledge/claims"
		params := map[string]string{}
		if suffix != "" {
			path += "/{claimID}/" + suffix
			params["claimID"] = claimID
		}
		return s.callProjectAPI(claim.WithOrigin(ctx, origin), principal, project, projectAPIInput{Operation: path, Params: params, Body: body})
	}
	sdk.AddTool(server, &sdk.Tool{Name: "propose_claim", Description: "Persist a conjecture at a real source location in this project. category: vulnerability, control or business_rule. Specify conditions. request_key makes retries idempotent. This never changes verification verdicts; returned claim_id can receive questions and supporting or contradicting evidence."}, func(ctx context.Context, _ *sdk.CallToolRequest, in claim.Input) (*sdk.CallToolResult, any, error) {
		return mutate(ctx, in, "", "")
	})
	sdk.AddTool(server, &sdk.Tool{Name: "open_question", Description: "Record a specific missing premise or evidence needed to investigate a persisted claim. Include claim_id, request_key and statement; category, target and reference must be omitted. This records an open question without starting a worker."}, func(ctx context.Context, _ *sdk.CallToolRequest, in claimNoteInput) (*sdk.CallToolResult, any, error) {
		return mutate(ctx, in.Input, in.ClaimID, "questions")
	})
	sdk.AddTool(server, &sdk.Tool{Name: "attach_evidence", Description: "Attach checked evidence to claim_id. relation is supports, contradicts or context; statement explains its relevance. reference is source (target file/start_line/end_line), evidence (existing ID), or artifact (existing ID). Host checks scope and captures source excerpts. Evidence never automatically confirms a vulnerability."}, func(ctx context.Context, _ *sdk.CallToolRequest, in claimNoteInput) (*sdk.CallToolResult, any, error) {
		return mutate(ctx, in.Input, in.ClaimID, "evidence")
	})
	sdk.AddTool(server, &sdk.Tool{Name: "query_investigation_knowledge", Description: "Read accumulated conjectures, or one claim's observations, questions and evidence. Start here before repeating an investigation. Pagination uses the returned revision and next_cursor; later knowledge remains outside the fixed revision until refresh."}, func(ctx context.Context, _ *sdk.CallToolRequest, in claimQueryInput) (*sdk.CallToolResult, any, error) {
		if in.SnapshotID == "" {
			in.SnapshotID = snapshot
		}
		operation := "GET /api/v1/projects/{projectID}/knowledge/claims"
		params := map[string]string{}
		if in.ClaimID != "" {
			operation += "/{claimID}"
			params["claimID"] = in.ClaimID
		}
		query := map[string]string{"snapshot_id": in.SnapshotID, "revision": strconv.FormatInt(in.Revision, 10), "cursor": strconv.FormatInt(in.Cursor, 10), "limit": strconv.Itoa(in.Limit)}
		return s.callProjectAPI(ctx, principal, project, projectAPIInput{Operation: operation, Params: params, Query: query})
	})
}
