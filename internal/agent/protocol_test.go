package agent

import (
	"strings"
	"testing"
)

// The checklist is what turns "is this done?" into a question the orchestrator can
// answer. These tests pin both directions: a task must carry exactly one question
// per kind, and an answer must close every one of them before it may conclude.

func checklistTask() Task {
	return Task{
		SchemaVersion: SchemaVersionObligations,
		SnapshotID:    "snap-1", PathID: "path-1", AuditID: "audit-1",
		SecurityGoal: "sql_injection",
		SourceSinkRefs: SourceSinkRefs{
			EntryNodeID: "entry-1", TargetNodeID: "sink-1",
		},
		EvidenceRefs: []EvidenceRef{{Kind: EvidenceStatic, ID: "ev-1"}},
		Obligations: []Obligation{
			{ID: ObligationID("path-1", ObligationSource), Kind: ObligationSource, Subject: "input-1",
				Question: "Is the input attacker-controlled at its source?"},
			{ID: ObligationID("path-1", ObligationFlow), Kind: ObligationFlow, Subject: "entry-1->sink-1",
				Question: "Does the input reach the sensitive operation?"},
			{ID: ObligationID("path-1", ObligationControl), Kind: ObligationControl, Subject: "none_observed",
				Question: "Is a control absent or ineffective on this path?"},
			{ID: ObligationID("path-1", ObligationSink), Kind: ObligationSink, Subject: "sink-1",
				Question: "Is the target operation sensitive?"},
		},
	}
}

func closedVerdicts() []ObligationVerdict {
	return []ObligationVerdict{
		{Kind: ObligationSource, Verdict: VerdictMet},
		{Kind: ObligationFlow, Verdict: VerdictMet},
		{Kind: ObligationControl, Verdict: VerdictMet},
		{Kind: ObligationSink, Verdict: VerdictMet},
	}
}

func checklistAnswer() Answer {
	return Answer{
		SchemaVersion: SchemaVersionObligations,
		SecurityGoal:  "sql_injection",
		Hypothesis: HypothesisDraft{
			Statement: "the query parameter reaches db.Query unparameterised",
			Status:    HypothesisCandidate, Confidence: "medium",
		},
		Obligations: closedVerdicts(),
		Falsifier:   &Falsifier{Claim: "the value is validated before the query", Checked: false},
	}
}

func TestValidateTaskAcceptsTheObligationChecklist(t *testing.T) {
	task := checklistTask()
	if err := ValidateTask(task); err != nil {
		t.Fatalf("a well-formed checklist was rejected: %v", err)
	}
	// The same task without a checklist is a version 1 task and still valid.
	task.Obligations = nil
	task.SchemaVersion = SchemaVersion
	if err := ValidateTask(task); err != nil {
		t.Fatalf("a version 1 task was rejected: %v", err)
	}
}

func TestValidateTaskRejectsBrokenChecklists(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Task)
		want   string
	}{
		{"missing kind", func(task *Task) { task.Obligations = task.Obligations[:3] }, "one per kind"},
		{"duplicate kind", func(task *Task) {
			task.Obligations[1].Kind = ObligationSource
			task.Obligations[1].ID = ObligationID("path-1", "other")
		}, "appears more than once"},
		{"missing id", func(task *Task) { task.Obligations[0].ID = "" }, "id is required"},
		{"missing question", func(task *Task) { task.Obligations[0].Question = "" }, "question is required"},
		{"unknown version", func(task *Task) { task.SchemaVersion = 99 }, "schema_version is 99"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			task := checklistTask()
			tc.mutate(&task)
			err := ValidateTask(task)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateTask = %v, want a message containing %q", err, tc.want)
			}
		})
	}
}

func TestValidateAnswerClosesTheChecklist(t *testing.T) {
	task := checklistTask()
	cases := []struct {
		name   string
		mutate func(*Answer, *Task)
		want   string
	}{
		{"all closed is accepted", func(*Answer, *Task) {}, ""},
		{"missing verdict", func(answer *Answer, task *Task) {
			answer.Obligations = answer.Obligations[:3]
		}, "closes no verdict"},
		{"duplicate verdict", func(answer *Answer, task *Task) {
			answer.Obligations[1].Kind = ObligationSource
		}, "appears more than once"},
		{"unknown kind", func(answer *Answer, task *Task) {
			answer.Obligations[0].Kind = "something_else"
		}, "not a known obligation kind"},
		{"unknown verdict word", func(answer *Answer, task *Task) {
			answer.Obligations[0].Verdict = "probably"
		}, "is not one of"},
		{"open obligation without blocker", func(answer *Answer, task *Task) {
			answer.Obligations[1].Verdict = VerdictUnknown
		}, "must name a blocker"},
		{"open obligation with unknown blocker", func(answer *Answer, task *Task) {
			answer.Obligations[1].Verdict = VerdictUnknown
			answer.Obligations[1].Blocker = "i_am_not_sure"
		}, "must name a blocker"},
		{"open obligation under a candidate", func(answer *Answer, task *Task) {
			answer.Obligations[1] = ObligationVerdict{Kind: ObligationFlow, Verdict: VerdictUnknown, Blocker: BlockerUnresolvedCall}
		}, "only an inconclusive hypothesis"},
		{"open obligation under inconclusive", func(answer *Answer, task *Task) {
			answer.Hypothesis.Status = HypothesisInconclusive
			answer.Obligations[1] = ObligationVerdict{Kind: ObligationFlow, Verdict: VerdictUnknown, Blocker: BlockerUnresolvedCall}
		}, ""},
		{"closed verdict with a blocker", func(answer *Answer, task *Task) {
			answer.Obligations[0].Blocker = BlockerBudget
		}, "must not name a blocker"},
		{"answer version below the task", func(answer *Answer, task *Task) {
			answer.SchemaVersion = SchemaVersion
		}, "schema_version is 1"},
		{"reason too long", func(answer *Answer, task *Task) {
			answer.Obligations[0].Reason = strings.Repeat("x", MaxObligationReason+1)
		}, "reason exceeds"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			answer := checklistAnswer()
			tc.mutate(&answer, &task)
			err := ValidateAnswer(&answer, task)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateAnswer rejected a valid answer: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateAnswer = %v, want a message containing %q", err, tc.want)
			}
		})
	}
}

// TestValidateAnswerKeepsVersionOneCompatible is the compatibility promise: a run
// stored before the checklist existed must still decode and validate.
func TestValidateAnswerKeepsVersionOneCompatible(t *testing.T) {
	task := Task{
		SchemaVersion: SchemaVersion, SnapshotID: "snap-1", PathID: "path-1",
		SecurityGoal:   "sql_injection",
		SourceSinkRefs: SourceSinkRefs{EntryNodeID: "entry-1", TargetNodeID: "sink-1"},
		EvidenceRefs:   []EvidenceRef{{Kind: EvidenceStatic, ID: "ev-1"}},
	}
	answer := Answer{
		SchemaVersion: SchemaVersion, SecurityGoal: "sql_injection",
		Hypothesis: HypothesisDraft{Statement: "a v1 claim", Status: HypothesisCandidate, Confidence: "low"},
	}
	if err := ValidateAnswer(&answer, task); err != nil {
		t.Fatalf("a version 1 answer was rejected by a version 1 task: %v", err)
	}
}
