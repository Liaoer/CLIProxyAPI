package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
)

type Overall string

const (
	OverallHealthy  Overall = "healthy"
	OverallWarning  Overall = "warning"
	OverallCritical Overall = "critical"
)

type CheckStatus string

const (
	CheckPass CheckStatus = "pass"
	CheckWarn CheckStatus = "warn"
	CheckFail CheckStatus = "fail"
)

type ReasonCode string

const (
	ReasonRefreshTokenMissing       ReasonCode = "REFRESH_TOKEN_MISSING"
	ReasonIDTokenParseFailed        ReasonCode = "ID_TOKEN_PARSE_FAILED"
	ReasonAuthExpired               ReasonCode = "AUTH_EXPIRED"
	ReasonRefreshTokenReused        ReasonCode = "REFRESH_TOKEN_REUSED"
	ReasonActiveCodexMismatch       ReasonCode = "ACTIVE_CODEX_MISMATCH"
	ReasonActiveCodexAuthFileMissing ReasonCode = "ACTIVE_CODEX_AUTH_FILE_MISSING"
	ReasonAccountDisabled           ReasonCode = "ACCOUNT_DISABLED"
)

type Check struct {
	ID             string                 `json:"id"`
	Status         CheckStatus            `json:"status"`
	Severity       string                 `json:"severity"`
	Title          string                 `json:"title"`
	Message        string                 `json:"message"`
	ReasonCodes    []ReasonCode           `json:"reason_codes,omitempty"`
	Recommendation string                 `json:"recommendation,omitempty"`
	Action         string                 `json:"action,omitempty"`
	Evidence       map[string]any         `json:"evidence,omitempty"`
}

type AccountHealth struct {
	ID                string       `json:"id"`
	Name              string       `json:"name,omitempty"`
	Label             string       `json:"label,omitempty"`
	Provider          string       `json:"provider,omitempty"`
	Email             string       `json:"email,omitempty"`
	AccountID         string       `json:"account_id,omitempty"`
	Status            CheckStatus  `json:"status"`
	PrimaryReasonCode ReasonCode   `json:"primary_reason_code,omitempty"`
	ReasonCodes       []ReasonCode `json:"reason_codes,omitempty"`
	Summary           string       `json:"summary"`
	DisplayTitle      string       `json:"display_title,omitempty"`
	DisplayMessage    string       `json:"display_message,omitempty"`
	NextStep          string       `json:"next_step,omitempty"`
	Disabled          bool         `json:"disabled,omitempty"`
	Unavailable       bool         `json:"unavailable,omitempty"`
	LastError         string       `json:"last_error,omitempty"`
	LiveStatus        CheckStatus  `json:"live_status,omitempty"`
	LiveSummary       string       `json:"live_summary,omitempty"`
	LiveCheckedAt     string       `json:"live_checked_at,omitempty"`
}

type RecommendedAction struct {
	Action  string `json:"action"`
	Title   string `json:"title"`
	Message string `json:"message"`
	AuthID  string `json:"auth_id,omitempty"`
}

type Report struct {
	Overall           Overall              `json:"overall"`
	Mode              string               `json:"mode,omitempty"`
	Summary           string               `json:"summary"`
	Headline          string               `json:"headline,omitempty"`
	OperatorAdvice    string               `json:"operator_advice,omitempty"`
	GeneratedAt       string               `json:"generated_at"`
	Checks            []Check              `json:"checks"`
	Accounts          []AccountHealth      `json:"accounts"`
	RecommendedActions []RecommendedAction `json:"recommended_actions,omitempty"`
}

type Options struct {
	AuthManager         *coreauth.Manager
	ActiveCodexAuthPath func() (string, error)
	AuthID              string
	Deep                bool
	Now                 time.Time
}

type activeCodexTokens struct {
	AccountID string `json:"account_id"`
}

type activeCodexAuthFile struct {
	AccountID string           `json:"account_id"`
	Tokens    activeCodexTokens `json:"tokens"`
}

func Generate(ctx context.Context, opts Options) (*Report, error) {
	if opts.AuthManager == nil {
		return nil, errors.New("diagnostics: auth manager is required")
	}

	now := opts.Now.UTC()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	auths := opts.AuthManager.List()
	if opts.AuthID != "" {
		auths = filterAuthsByID(auths, opts.AuthID)
	}

	visibleAuths := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if shouldSkipDiagnosticsAuth(auth) {
			continue
		}
		visibleAuths = append(visibleAuths, auth)
	}
	auths = visibleAuths

	sort.Slice(auths, func(i, j int) bool {
		return auths[i].ID < auths[j].ID
	})

	mode := "static"
	if opts.Deep {
		mode = "deep"
	}

	report := &Report{
		Overall:     OverallHealthy,
		Mode:        mode,
		Summary:     defaultSummary(opts.Deep, 0),
		Headline:    defaultHeadline(opts.Deep, 0),
		OperatorAdvice: defaultOperatorAdvice(opts.Deep, OverallHealthy),
		GeneratedAt: now.Format(time.RFC3339),
		Checks:      []Check{},
		Accounts:    []AccountHealth{},
	}

	if len(auths) == 0 {
		return report, nil
	}

	var (
		anyMissingRefresh bool
		anyIDTokenFailure bool
		anyActiveWarn     bool
		activeReasonCodes []ReasonCode
		activeMessage     string
		activeAction      string
		anyLiveFail       bool
		anyLivePass       bool
	)

	activeCodexAccountID, activeCodexErr := readActiveCodexAccountID(opts.ActiveCodexAuthPath)
	activeAuthComparisonEnabled := opts.ActiveCodexAuthPath != nil

	for _, auth := range auths {
		account := AccountHealth{
			ID:          auth.ID,
			Name:        auth.FileName,
			Label:       auth.Label,
			Provider:    auth.Provider,
			Email:       metadataString(auth, "email"),
			AccountID:   metadataString(auth, "account_id"),
			Status:      CheckPass,
			Disabled:    auth.Disabled,
			Unavailable: auth.Unavailable,
			LastError:   lastErrorMessage(auth),
		}
		if account.Name == "" {
			account.Name = auth.ID
		}
		if account.Label == "" {
			account.Label = auth.Label
		}

		reasons := make([]ReasonCode, 0, 4)

		if auth.Disabled || auth.Status == coreauth.StatusDisabled {
			reasons = appendReason(reasons, ReasonAccountDisabled)
		}

		if metadataString(auth, "refresh_token") == "" {
			anyMissingRefresh = true
			reasons = appendReason(reasons, ReasonRefreshTokenMissing)
		}

		if account.AccountID == "" {
			if idToken := metadataString(auth, "id_token"); idToken != "" && !looksLikeJWT(idToken) {
				anyIDTokenFailure = true
				reasons = appendReason(reasons, ReasonIDTokenParseFailed)
			}
		}

		if msg := account.LastError; msg != "" {
			reasons = appendReason(reasons, classifyErrorReason(msg)...)
		}

		if activeAuthComparisonEnabled && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			if activeCodexErr != nil {
				anyActiveWarn = true
				activeReasonCodes = appendReason(activeReasonCodes, ReasonActiveCodexAuthFileMissing)
				activeMessage = "当前本机 Codex 激活认证文件缺失，无法确认托管账号是否与当前激活的 Codex 账号一致。"
				reasons = appendReason(reasons, ReasonActiveCodexAuthFileMissing)
			} else if account.AccountID != "" && activeCodexAccountID != "" && account.AccountID != activeCodexAccountID {
				anyActiveWarn = true
				activeReasonCodes = appendReason(activeReasonCodes, ReasonActiveCodexMismatch)
				activeMessage = "当前激活的 Codex 账号与托管账号不一致。"
				activeAction = "switch_codex"
				reasons = appendReason(reasons, ReasonActiveCodexMismatch)
			}
		}

		if opts.Deep && strings.EqualFold(strings.TrimSpace(auth.Provider), "codex") {
			refreshedAuth, err := opts.AuthManager.RefreshByID(ctx, auth.ID)
			account.LiveCheckedAt = now.Format(time.RFC3339)
			if err != nil {
				anyLiveFail = true
				account.LiveStatus = CheckFail
				account.LiveSummary = "在线刷新失败：" + strings.TrimSpace(err.Error())
				reasons = appendReason(reasons, classifyErrorReason(err.Error())...)
			} else {
				anyLivePass = true
				account.LiveStatus = CheckPass
				account.LiveSummary = "在线刷新通过。"
				if refreshedAuth != nil {
					if email := metadataString(refreshedAuth, "email"); email != "" {
						account.Email = email
					}
					if accountID := metadataString(refreshedAuth, "account_id"); accountID != "" {
						account.AccountID = accountID
					}
				}
			}
		}

		account.ReasonCodes = normalizeReasons(reasons)
		account.PrimaryReasonCode = pickPrimaryReason(account.ReasonCodes)
		applyDisplayFields(&account)
		account.Status = deriveAccountStatus(account)
		report.Accounts = append(report.Accounts, account)
	}

	report.Checks = append(report.Checks, buildRefreshTokenCheck(anyMissingRefresh))
	if anyIDTokenFailure {
		report.Checks = append(report.Checks, Check{
			ID:          "codex.id_token_parseable",
			Status:      CheckFail,
			Severity:    "critical",
			Title:       "Codex 认证文件中的 id_token 无法解析",
			Message:     "至少有一个账号缺少可识别的 account_id，且 id_token 无法解析，无法可靠识别账号身份。",
			ReasonCodes: []ReasonCode{ReasonIDTokenParseFailed},
		})
	}
	if activeAuthComparisonEnabled {
		report.Checks = append(report.Checks, buildActiveAuthCheck(anyActiveWarn, activeReasonCodes, activeMessage, activeAction))
	}
	if opts.Deep {
		report.Checks = append(report.Checks, buildLiveRefreshCheck(anyLiveFail, anyLivePass))
	}

	report.RecommendedActions = buildRecommendedActions(report.Accounts)
	report.Overall = deriveOverall(report.Accounts, report.Checks)
	report.Summary = buildSummary(opts.Deep, report)
	report.Headline = buildHeadline(opts.Deep, report)
	report.OperatorAdvice = buildOperatorAdvice(opts.Deep, report)

	return report, nil
}

func defaultSummary(deep bool, count int) string {
	if deep {
		if count == 0 {
			return "在线体检通过，当前没有可检查的账号。"
		}
		return fmt.Sprintf("已完成 %d 个账号的在线体检。", count)
	}
	if count == 0 {
		return "静态体检通过，当前没有可检查的账号。"
	}
	return fmt.Sprintf("已完成 %d 个账号的静态体检。", count)
}

func defaultHeadline(deep bool, count int) string {
	if deep {
		if count == 0 {
			return "在线体检通过，当前没有可检查的账号。"
		}
		return "在线体检已完成。"
	}
	if count == 0 {
		return "静态体检通过，当前没有可检查的账号。"
	}
	return "静态体检已完成。"
}

func defaultOperatorAdvice(deep bool, overall Overall) string {
	if deep && overall == OverallHealthy {
		return "无需额外处理，保持当前配置即可。"
	}
	if deep {
		return "按账号逐项处理问题后，再次运行在线体检确认全部通过。"
	}
	return "如需确认授权是否真实可用，请再次运行在线体检。"
}

func buildSummary(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "在线体检通过，未发现明显问题。"
		}
		return "静态体检通过，未发现明显问题。"
	}
	if deep {
		return fmt.Sprintf("在线体检发现 %d 个账号存在异常或风险。", len(failingAccounts(report.Accounts)))
	}
	return fmt.Sprintf("静态体检发现 %d 个账号存在异常或风险。", len(failingAccounts(report.Accounts)))
}

func buildHeadline(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "在线体检通过，未发现明显问题。"
		}
		return "静态体检通过，未发现明显问题。"
	}

	failing := failingAccounts(report.Accounts)
	if len(failing) == 0 {
		if deep {
			return "在线体检发现异常，请查看检查项。"
		}
		return "静态体检发现异常，请查看检查项。"
	}

	primary := failing[0].PrimaryReasonCode
	samePrimary := primary != ""
	for _, account := range failing[1:] {
		if account.PrimaryReasonCode != primary {
			samePrimary = false
			break
		}
	}

	if samePrimary {
		switch primary {
		case ReasonRefreshTokenReused:
			return fmt.Sprintf("在线体检发现 %d 个账号的 refresh token 已被其他来源轮换。", len(failing))
		case ReasonAuthExpired:
			return fmt.Sprintf("在线体检发现 %d 个账号的登录态已过期。", len(failing))
		case ReasonActiveCodexMismatch:
			return "当前激活的 Codex 账号与托管账号不一致。"
		case ReasonAccountDisabled:
			return fmt.Sprintf("在线体检发现 %d 个账号已被禁用。", len(failing))
		}
	}

	if deep {
		return "在线体检发现多种不同原因的认证问题，请按账号逐项处理。"
	}
	return "静态体检发现多种不同原因的认证问题，请按账号逐项处理。"
}

func buildOperatorAdvice(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "无需额外处理，保持当前配置即可。"
		}
		return "当前未发现明显问题，如需确认在线可用性，可再次运行在线体检。"
	}
	failing := failingAccounts(report.Accounts)
	if len(failing) == 0 {
		return "请查看检查项并按提示处理。"
	}
	primary := failing[0].PrimaryReasonCode
	samePrimary := primary != ""
	for _, account := range failing[1:] {
		if account.PrimaryReasonCode != primary {
			samePrimary = false
			break
		}
	}
	if samePrimary {
		switch primary {
		case ReasonRefreshTokenReused:
			return "建议按顺序处理：1. 回到原认证来源重新登录并获取新凭证；2. 重新同步或重新导入到 CLIProxyAPI；3. 再次运行在线体检确认通过。"
		case ReasonAuthExpired:
			return "请先重新登录对应账号，再重新同步或重新导入，然后再次运行在线体检。"
		case ReasonActiveCodexMismatch:
			return "请先切换本机当前激活的 Codex 账号，再重新运行在线体检。"
		}
	}
	if deep {
		return "请根据每个账号的下一步建议逐项处理，处理后再次运行在线体检确认全部通过。"
	}
	return "请根据每个账号的下一步建议逐项处理；如需确认真实可用性，请再次运行在线体检。"
}

func buildRefreshTokenCheck(anyMissing bool) Check {
	if anyMissing {
		return Check{
			ID:          "codex.refresh_token_present",
			Status:      CheckFail,
			Severity:    "critical",
			Title:       "Codex 账号缺少 refresh token",
			Message:     "至少有一个账号缺少 refresh token，无法执行在线刷新。",
			ReasonCodes: []ReasonCode{ReasonRefreshTokenMissing},
		}
	}
	return Check{
		ID:       "codex.refresh_token_present",
		Status:   CheckPass,
		Severity: "info",
		Title:    "Codex 账号 refresh token 完整",
		Message:  "所有参与体检的 Codex 账号都包含 refresh token。",
	}
}

func buildActiveAuthCheck(anyWarn bool, reasons []ReasonCode, message, action string) Check {
	if anyWarn {
		recommendation := strings.TrimSpace(message)
		if recommendation == "" {
			recommendation = "请确认当前激活的 Codex 账号与托管账号是否一致。"
		}
		return Check{
			ID:             "codex.active_auth_matches_managed_account",
			Status:         CheckWarn,
			Severity:       "warning",
			Title:          "当前 Codex 激活账号需要关注",
			Message:        recommendation,
			ReasonCodes:    normalizeReasons(reasons),
			Recommendation: recommendation,
			Action:         action,
		}
	}
	return Check{
		ID:       "codex.active_auth_matches_managed_account",
		Status:   CheckPass,
		Severity: "info",
		Title:    "当前 Codex 激活账号一致",
		Message:  "当前激活的 Codex 账号与托管账号一致，或当前无需进行此项比较。",
	}
}

func buildLiveRefreshCheck(anyFail, anyPass bool) Check {
	switch {
	case anyFail:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckFail,
			Severity: "critical",
			Title:    "Codex 在线刷新失败",
			Message:  "至少有一个账号在线刷新失败，请查看账号问题列表。",
		}
	case anyPass:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckPass,
			Severity: "info",
			Title:    "Codex 在线刷新通过",
			Message:  "所有参与在线体检的 Codex 账号都已通过在线刷新。",
		}
	default:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckWarn,
			Severity: "warning",
			Title:    "Codex 在线刷新未执行",
			Message:  "当前运行中没有对任何账号执行在线刷新。",
		}
	}
}

func buildRecommendedActions(accounts []AccountHealth) []RecommendedAction {
	out := make([]RecommendedAction, 0, len(accounts))
	seen := map[string]struct{}{}
	for _, account := range accounts {
		switch account.PrimaryReasonCode {
		case ReasonActiveCodexMismatch:
			action := RecommendedAction{
				Action:  "switch_codex",
				Title:   "切换当前 Codex 账号",
				Message: "当前激活的 Codex 账号与托管账号不一致，请先切换到对应账号后再重试。",
				AuthID:  account.ID,
			}
			key := action.Action + "|" + action.AuthID
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, action)
			}
		case ReasonRefreshTokenReused, ReasonAuthExpired, ReasonRefreshTokenMissing, ReasonAccountDisabled:
			action := RecommendedAction{
				Action:  "reauthorize_account",
				Title:   "重新授权账号",
				Message: fmt.Sprintf("账号 %s 在线刷新失败，建议重新授权或重新导入认证文件。", account.EmailOrFallback()),
				AuthID:  account.ID,
			}
			key := action.Action + "|" + action.AuthID
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				out = append(out, action)
			}
		}
	}
	return out
}

func deriveOverall(accounts []AccountHealth, checks []Check) Overall {
	overall := OverallHealthy
	for _, account := range accounts {
		switch account.Status {
		case CheckFail:
			return OverallCritical
		case CheckWarn:
			overall = OverallWarning
		}
	}
	for _, check := range checks {
		switch check.Status {
		case CheckFail:
			return OverallCritical
		case CheckWarn:
			if overall != OverallCritical {
				overall = OverallWarning
			}
		}
	}
	return overall
}

func deriveAccountStatus(account AccountHealth) CheckStatus {
	if account.LiveStatus == CheckFail {
		return CheckFail
	}
	switch account.PrimaryReasonCode {
	case ReasonRefreshTokenReused, ReasonAuthExpired, ReasonRefreshTokenMissing, ReasonAccountDisabled, ReasonIDTokenParseFailed:
		return CheckFail
	case ReasonActiveCodexMismatch, ReasonActiveCodexAuthFileMissing:
		return CheckWarn
	}
	if len(account.ReasonCodes) > 0 {
		return CheckWarn
	}
	if account.LiveStatus == CheckPass {
		return CheckPass
	}
	return CheckPass
}

func failingAccounts(accounts []AccountHealth) []AccountHealth {
	out := make([]AccountHealth, 0, len(accounts))
	for _, account := range accounts {
		if account.Status != CheckPass {
			out = append(out, account)
		}
	}
	return out
}

func pickPrimaryReason(reasons []ReasonCode) ReasonCode {
	priority := []ReasonCode{
		ReasonRefreshTokenReused,
		ReasonAuthExpired,
		ReasonRefreshTokenMissing,
		ReasonAccountDisabled,
		ReasonActiveCodexMismatch,
		ReasonActiveCodexAuthFileMissing,
		ReasonIDTokenParseFailed,
	}
	for _, want := range priority {
		for _, got := range reasons {
			if got == want {
				return got
			}
		}
	}
	if len(reasons) > 0 {
		return reasons[0]
	}
	return ""
}

func applyDisplayFields(account *AccountHealth) {
	if account == nil {
		return
	}
	switch account.PrimaryReasonCode {
	case ReasonRefreshTokenReused:
		account.DisplayTitle = "refresh token 已被其他来源轮换"
		account.DisplayMessage = "该账号的 refresh token 已被其他客户端或认证来源刷新并轮换，CLIProxyAPI 当前保存的是旧 token，需要重新登录并重新同步。"
		account.NextStep = "回到原认证来源重新登录，重新同步或重新导入到 CLIProxyAPI 后，再次运行在线体检。"
	case ReasonAuthExpired:
		account.DisplayTitle = "账号登录态已过期"
		account.DisplayMessage = "该账号的登录态已经过期，当前无法继续在线刷新。"
		account.NextStep = "重新登录对应账号，重新同步或重新导入后，再次运行在线体检。"
	case ReasonRefreshTokenMissing:
		account.DisplayTitle = "缺少 refresh token"
		account.DisplayMessage = "该账号认证内容不完整，缺少 refresh token，无法在线刷新。"
		account.NextStep = "重新获取完整认证并重新导入，然后再次运行在线体检。"
	case ReasonActiveCodexMismatch:
		account.DisplayTitle = "当前 Codex 激活账号不一致"
		account.DisplayMessage = "当前本机激活的 Codex 账号与托管账号不一致，这通常会导致切换或验证结果不符合预期。"
		account.NextStep = "先切换到对应的 Codex 账号，再重新运行在线体检。"
	case ReasonActiveCodexAuthFileMissing:
		account.DisplayTitle = "本机 Codex 激活认证文件缺失"
		account.DisplayMessage = "当前无法读取本机 Codex 的激活认证文件，因此无法确认托管账号是否与当前激活账号一致。"
		account.NextStep = "先确认本机 Codex 已正常登录，再重新运行在线体检。"
	case ReasonAccountDisabled:
		account.DisplayTitle = "账号已被禁用"
		account.DisplayMessage = "该账号当前处于 disabled 状态，CLIProxyAPI 不会继续使用它。"
		account.NextStep = "如需继续使用，请重新导入新的有效认证，或启用对应账号。"
	case ReasonIDTokenParseFailed:
		account.DisplayTitle = "账号身份信息无法解析"
		account.DisplayMessage = "该账号缺少可识别的 account_id，且 id_token 无法解析，无法可靠识别身份。"
		account.NextStep = "重新获取完整认证并重新导入。"
	default:
		if account.LiveStatus == CheckPass {
			account.DisplayTitle = "在线体检通过"
			account.DisplayMessage = "该账号在线刷新通过，当前未发现明显问题。"
			account.NextStep = "无需额外处理。"
		}
	}

	if account.DisplayTitle != "" {
		account.Summary = account.DisplayTitle
	}
	if account.Summary == "" {
		if account.LiveSummary != "" {
			account.Summary = account.LiveSummary
		} else if account.LastError != "" {
			account.Summary = account.LastError
		} else {
			account.Summary = "未发现明显问题。"
		}
	}
}

func readActiveCodexAccountID(resolve func() (string, error)) (string, error) {
	if resolve == nil {
		return "", nil
	}
	path, err := resolve()
	if err != nil {
		return "", err
	}
	path = strings.TrimSpace(path)
	if path == "" {
		return "", nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	var payload activeCodexAuthFile
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", err
	}
	if accountID := strings.TrimSpace(payload.Tokens.AccountID); accountID != "" {
		return accountID, nil
	}
	return strings.TrimSpace(payload.AccountID), nil
}

func filterAuthsByID(auths []*coreauth.Auth, id string) []*coreauth.Auth {
	id = strings.TrimSpace(id)
	if id == "" {
		return auths
	}
	filtered := make([]*coreauth.Auth, 0, len(auths))
	for _, auth := range auths {
		if auth != nil && auth.ID == id {
			filtered = append(filtered, auth)
		}
	}
	return filtered
}

func metadataString(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Metadata == nil {
		return ""
	}
	value, ok := auth.Metadata[key]
	if !ok || value == nil {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case fmt.Stringer:
		return strings.TrimSpace(typed.String())
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", typed))
	}
}

func lastErrorMessage(auth *coreauth.Auth) string {
	if auth == nil || auth.LastError == nil {
		return ""
	}
	return strings.TrimSpace(auth.LastError.Error())
}

func classifyErrorReason(message string) []ReasonCode {
	message = strings.ToLower(strings.TrimSpace(message))
	if message == "" {
		return nil
	}
	reasons := make([]ReasonCode, 0, 3)
	if strings.Contains(message, "refresh_token_reused") || strings.Contains(message, "session refresh blocked") {
		reasons = appendReason(reasons, ReasonRefreshTokenReused)
	}
	if strings.Contains(message, "authorization expired") || strings.Contains(message, "sign in again") || strings.Contains(message, "invalid_grant") {
		reasons = appendReason(reasons, ReasonAuthExpired)
	}
	if strings.Contains(message, "auth_disabled") || strings.Contains(message, "auth is disabled") {
		reasons = appendReason(reasons, ReasonAccountDisabled)
	}
	return reasons
}

func normalizeReasons(reasons []ReasonCode) []ReasonCode {
	if len(reasons) == 0 {
		return nil
	}
	seen := map[ReasonCode]struct{}{}
	out := make([]ReasonCode, 0, len(reasons))
	for _, reason := range reasons {
		if reason == "" {
			continue
		}
		if _, ok := seen[reason]; ok {
			continue
		}
		seen[reason] = struct{}{}
		out = append(out, reason)
	}
	return out
}

func appendReason(existing []ReasonCode, incoming ...ReasonCode) []ReasonCode {
	out := existing
	for _, reason := range incoming {
		if reason == "" {
			continue
		}
		duplicate := false
		for _, current := range out {
			if current == reason {
				duplicate = true
				break
			}
		}
		if !duplicate {
			out = append(out, reason)
		}
	}
	return out
}

func looksLikeJWT(token string) bool {
	token = strings.TrimSpace(token)
	return strings.Count(token, ".") == 2
}

func shouldSkipDiagnosticsAuth(auth *coreauth.Auth) bool {
	if auth == nil {
		return true
	}
	runtimeOnly := diagnosticsIsRuntimeOnlyAuth(auth)
	if runtimeOnly && (auth.Disabled || auth.Status == coreauth.StatusDisabled) {
		return true
	}
	path := strings.TrimSpace(diagnosticsAuthAttribute(auth, "path"))
	if path == "" || runtimeOnly {
		return false
	}
	if _, err := os.Stat(path); err == nil {
		return false
	} else if os.IsNotExist(err) {
		if auth.Disabled || auth.Status == coreauth.StatusDisabled || strings.EqualFold(strings.TrimSpace(auth.StatusMessage), "removed via management api") {
			return true
		}
	}
	return false
}

func diagnosticsAuthAttribute(auth *coreauth.Auth, key string) string {
	if auth == nil || auth.Attributes == nil {
		return ""
	}
	return auth.Attributes[key]
}

func diagnosticsIsRuntimeOnlyAuth(auth *coreauth.Auth) bool {
	if auth == nil || len(auth.Attributes) == 0 {
		return false
	}
	return strings.EqualFold(strings.TrimSpace(auth.Attributes["runtime_only"]), "true")
}

func (a AccountHealth) EmailOrFallback() string {
	if strings.TrimSpace(a.Email) != "" {
		return strings.TrimSpace(a.Email)
	}
	if strings.TrimSpace(a.Label) != "" {
		return strings.TrimSpace(a.Label)
	}
	if strings.TrimSpace(a.ID) != "" {
		return strings.TrimSpace(a.ID)
	}
	return "unknown"
}
