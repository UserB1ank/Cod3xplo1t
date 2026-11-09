package api

import (
	"context"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

type pathProposalToolInput struct {
	ViewID         string                  `json:"view_id"`
	RequestKey     string                  `json:"request_key"`
	EntryRef       string                  `json:"entry_ref"`
	TargetRef      string                  `json:"target_ref"`
	Basis          string                  `json:"basis"`
	Steps          []proposalStep          `json:"steps,omitempty"`
	Evidence       []proposalEvidenceInput `json:"evidence"`
	RelatedPathIDs []string                `json:"related_path_ids,omitempty"`
	Limitations    []string                `json:"limitations,omitempty"`
}

func (s *Server) registerPathProposalTools(server *sdk.Server, principal Principal, project, snapshot string, origin path.ProposalOrigin) {
	sdk.AddTool(server, &sdk.Tool{Name: "open_knowledge_view", Description: "Open the current immutable knowledge view for this snapshot. The host pins the code graph, attack surface and path layers and returns view_id for propose_path. Revision view ids from publications are not complete layer pins."}, func(ctx context.Context, _ *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, any, error) {
		return s.callProjectAPI(ctx, principal, project, projectAPIInput{
			Operation: "POST /api/v1/projects/{projectID}/knowledge/views",
			Body: map[string]any{
				"api_version": "codexploit/v1", "snapshot_id": snapshot,
				"layers": []string{"scg", "asg", "paths"},
			},
		})
	})
	sdk.AddTool(server, &sdk.Tool{Name: "propose_path", Description: "Submit a bounded review path proposal against view_id. The host verifies the entry, sensitive-operation target, observed ASG edges, evidence IDs/source ranges, pinned layers, request-key idempotency and per-run budget. basis=call_reachability requires a connected observed edge chain; basis=hypothesis keeps the missing connection explicit. New paths wait for human selection and never become dataflow or verified findings."}, func(ctx context.Context, _ *sdk.CallToolRequest, in pathProposalToolInput) (*sdk.CallToolResult, any, error) {
		body := map[string]any{
			"request_key": in.RequestKey, "entry_ref": in.EntryRef, "target_ref": in.TargetRef,
			"basis": in.Basis, "evidence": in.Evidence,
		}
		if len(in.Steps) > 0 {
			body["steps"] = in.Steps
		}
		if len(in.RelatedPathIDs) > 0 {
			body["related_path_ids"] = in.RelatedPathIDs
		}
		if len(in.Limitations) > 0 {
			body["limitations"] = in.Limitations
		}
		return s.callProjectAPI(path.WithProposalOrigin(ctx, origin), principal, project, projectAPIInput{
			Operation: "POST /api/v1/projects/{projectID}/knowledge/views/{viewID}/path-proposals",
			Params:    map[string]string{"viewID": in.ViewID}, Body: body,
		})
	})
}
