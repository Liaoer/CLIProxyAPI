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
				activeMessage = "褰撳墠 Codex 婵€娲昏璇佹枃浠剁己澶憋紝鏃犳硶纭鎵樼璐﹀彿鏄惁涓庢湰鏈?Codex 褰撳墠婵€娲昏处鍙蜂竴鑷淬€?
				reasons = appendReason(reasons, ReasonActiveCodexAuthFileMissing)
			} else if account.AccountID != "" && activeCodexAccountID != "" && account.AccountID != activeCodexAccountID {
				anyActiveWarn = true
				activeReasonCodes = appendReason(activeReasonCodes, ReasonActiveCodexMismatch)
				activeMessage = "褰撳墠 Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿涓嶄竴鑷淬€?
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
				account.LiveSummary = "鍦ㄧ嚎鍒锋柊澶辫触锛? + strings.TrimSpace(err.Error())
				reasons = appendReason(reasons, classifyErrorReason(err.Error())...)
			} else {
				anyLivePass = true
				account.LiveStatus = CheckPass
				account.LiveSummary = "鍦ㄧ嚎鍒锋柊閫氳繃銆?
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
			Title:       "Codex 璁よ瘉鏂囦欢涓殑 id_token 鏃犳硶瑙ｆ瀽",
			Message:     "鑷冲皯鏈変竴涓处鍙风己灏戝彲璇嗗埆鐨?account_id锛屼笖 id_token 鏃犳硶瑙ｆ瀽锛屾棤娉曞彲闈犺瘑鍒处鍙疯韩浠姐€?,
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
			return "鍦ㄧ嚎浣撴閫氳繃锛屽綋鍓嶆病鏈夊彲妫€鏌ョ殑璐﹀彿銆?
		}
		return fmt.Sprintf("宸插畬鎴?%d 涓处鍙风殑鍦ㄧ嚎浣撴銆?, count)
	}
	if count == 0 {
		return "闈欐€佷綋妫€閫氳繃锛屽綋鍓嶆病鏈夊彲妫€鏌ョ殑璐﹀彿銆?
	}
	return fmt.Sprintf("宸插畬鎴?%d 涓处鍙风殑闈欐€佷綋妫€銆?, count)
}

func defaultHeadline(deep bool, count int) string {
	if deep {
		if count == 0 {
			return "鍦ㄧ嚎浣撴閫氳繃锛屽綋鍓嶆病鏈夊彲妫€鏌ョ殑璐﹀彿銆?
		}
		return "鍦ㄧ嚎浣撴宸插畬鎴愩€?
	}
	if count == 0 {
		return "闈欐€佷綋妫€閫氳繃锛屽綋鍓嶆病鏈夊彲妫€鏌ョ殑璐﹀彿銆?
	}
	return "闈欐€佷綋妫€宸插畬鎴愩€?
}

func defaultOperatorAdvice(deep bool, overall Overall) string {
	if deep && overall == OverallHealthy {
		return "鏃犻渶棰濆澶勭悊锛屼繚鎸佸綋鍓嶉厤缃嵆鍙€?
	}
	if deep {
		return "寤鸿鎸夎处鍙烽€愰」澶勭悊寮傚父鍚庯紝鍐嶆杩愯鍦ㄧ嚎浣撴纭閫氳繃銆?
	}
	return "濡傞渶纭鎺堟潈鏄惁鐪熷疄鍙敤锛岃鍐嶈繍琛屼竴娆″湪绾夸綋妫€銆?
}

func buildSummary(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "鍦ㄧ嚎浣撴閫氳繃锛屾湭鍙戠幇鏄庢樉闂銆?
		}
		return "闈欐€佷綋妫€閫氳繃锛屾湭鍙戠幇鏄庢樉闂銆?
	}
	if deep {
		return fmt.Sprintf("鍦ㄧ嚎浣撴鍙戠幇 %d 涓处鍙峰瓨鍦ㄥ紓甯告垨椋庨櫓銆?, len(failingAccounts(report.Accounts)))
	}
	return fmt.Sprintf("闈欐€佷綋妫€鍙戠幇 %d 涓处鍙峰瓨鍦ㄥ紓甯告垨椋庨櫓銆?, len(failingAccounts(report.Accounts)))
}

func buildHeadline(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "鍦ㄧ嚎浣撴閫氳繃锛屾湭鍙戠幇鏄庢樉闂銆?
		}
		return "闈欐€佷綋妫€閫氳繃锛屾湭鍙戠幇鏄庢樉闂銆?
	}

	failing := failingAccounts(report.Accounts)
	if len(failing) == 0 {
		if deep {
			return "鍦ㄧ嚎浣撴鍙戠幇寮傚父锛岃鏌ョ湅妫€鏌ラ」銆?
		}
		return "闈欐€佷綋妫€鍙戠幇寮傚父锛岃鏌ョ湅妫€鏌ラ」銆?
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
			return fmt.Sprintf("鍦ㄧ嚎浣撴鍙戠幇 %d 涓处鍙风殑 refresh token 宸茶鍏朵粬瀹㈡埛绔?璁よ瘉婧愯疆鎹€?, len(failing))
		case ReasonAuthExpired:
			return fmt.Sprintf("鍦ㄧ嚎浣撴鍙戠幇 %d 涓处鍙风殑鐧诲綍鎬佸凡杩囨湡銆?, len(failing))
		case ReasonActiveCodexMismatch:
			return "褰撳墠 Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿涓嶄竴鑷淬€?
		case ReasonAccountDisabled:
			return fmt.Sprintf("鍦ㄧ嚎浣撴鍙戠幇 %d 涓处鍙峰凡琚鐢ㄣ€?, len(failing))
		}
	}

	if deep {
		return "鍦ㄧ嚎浣撴鍙戠幇澶氫釜涓嶅悓鍘熷洜鐨勮璇侀棶棰橈紝璇锋寜璐﹀彿閫愰」澶勭悊銆?
	}
	return "闈欐€佷綋妫€鍙戠幇澶氫釜涓嶅悓鍘熷洜鐨勮璇侀棶棰橈紝璇锋寜璐﹀彿閫愰」澶勭悊銆?
}

func buildOperatorAdvice(deep bool, report *Report) string {
	if report == nil {
		return ""
	}
	if report.Overall == OverallHealthy {
		if deep {
			return "鏃犻渶棰濆澶勭悊锛屼繚鎸佸綋鍓嶉厤缃嵆鍙€?
		}
		return "褰撳墠鏈彂鐜版槑鏄鹃棶棰橈紝濡傞渶纭鍦ㄧ嚎鍙敤鎬у彲鍐嶆墽琛屼竴娆″湪绾夸綋妫€銆?
	}
	failing := failingAccounts(report.Accounts)
	if len(failing) == 0 {
		return "璇锋煡鐪嬫鏌ラ」骞舵寜鎻愮ず澶勭悊銆?
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
			return "寤鸿鎸夐『搴忓鐞嗭細1. 鍥炲埌鍘熻璇佹潵婧愰噸鏂扮櫥褰曞苟鑾峰彇鏂拌璇侊紱2. 閲嶆柊鍚屾鎴栭噸鏂板鍏ュ埌 CLIProxyAPI锛?. 鍐嶆杩愯鍦ㄧ嚎浣撴纭閫氳繃銆?
		case ReasonAuthExpired:
			return "璇峰厛閲嶆柊鐧诲綍瀵瑰簲璐﹀彿锛屽啀閲嶆柊鍚屾鎴栭噸鏂板鍏ワ紝鐒跺悗鍐嶆杩愯鍦ㄧ嚎浣撴銆?
		case ReasonActiveCodexMismatch:
			return "璇峰厛鍒囨崲鏈満褰撳墠 Codex 婵€娲昏处鍙凤紝鍐嶉噸鏂拌繍琛屽湪绾夸綋妫€銆?
		}
	}
	if deep {
		return "璇锋牴鎹瘡涓处鍙风殑涓嬩竴姝ュ缓璁€愰」澶勭悊锛屽鐞嗗悗鍐嶆杩愯鍦ㄧ嚎浣撴纭閫氳繃銆?
	}
	return "璇锋牴鎹瘡涓处鍙风殑涓嬩竴姝ュ缓璁€愰」澶勭悊锛涘闇€纭鐪熷疄鍙敤鎬э紝璇峰啀杩愯鍦ㄧ嚎浣撴銆?
}

func buildRefreshTokenCheck(anyMissing bool) Check {
	if anyMissing {
		return Check{
			ID:          "codex.refresh_token_present",
			Status:      CheckFail,
			Severity:    "critical",
			Title:       "Codex 璐﹀彿缂哄皯 refresh token",
			Message:     "鑷冲皯鏈変竴涓处鍙风己灏?refresh token锛屾棤娉曟墽琛屽湪绾跨画鏈熴€?,
			ReasonCodes: []ReasonCode{ReasonRefreshTokenMissing},
		}
	}
	return Check{
		ID:       "codex.refresh_token_present",
		Status:   CheckPass,
		Severity: "info",
		Title:    "Codex 璐﹀彿 refresh token 瀹屾暣",
		Message:  "鎵€鏈夊弬涓庝綋妫€鐨?Codex 璐﹀彿閮藉寘鍚?refresh token銆?,
	}
}

func buildActiveAuthCheck(anyWarn bool, reasons []ReasonCode, message, action string) Check {
	if anyWarn {
		recommendation := strings.TrimSpace(message)
		if recommendation == "" {
			recommendation = "璇锋鏌ュ綋鍓?Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿鏄惁涓€鑷淬€?
		}
		return Check{
			ID:             "codex.active_auth_matches_managed_account",
			Status:         CheckWarn,
			Severity:       "warning",
			Title:          "Codex 褰撳墠婵€娲昏处鍙烽渶瑕佸叧娉?,
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
		Title:    "Codex 褰撳墠婵€娲昏处鍙蜂竴鑷?,
		Message:  "褰撳墠 Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿涓€鑷达紝鎴栨棤闇€杩涜璇ラ」姣旇緝銆?,
	}
}

func buildLiveRefreshCheck(anyFail, anyPass bool) Check {
	switch {
	case anyFail:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckFail,
			Severity: "critical",
			Title:    "Codex 鍦ㄧ嚎鍒锋柊澶辫触",
			Message:  "鑷冲皯鏈変竴涓处鍙峰湪鍦ㄧ嚎鍒锋柊鏃跺け璐ワ紝璇锋煡鐪嬭处鍙烽棶棰樺垪琛ㄣ€?,
		}
	case anyPass:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckPass,
			Severity: "info",
			Title:    "Codex 鍦ㄧ嚎鍒锋柊閫氳繃",
			Message:  "鎵€鏈夊弬涓庡湪绾夸綋妫€鐨?Codex 璐﹀彿閮介€氳繃浜嗗湪绾垮埛鏂般€?,
		}
	default:
		return Check{
			ID:       "codex.live_refresh",
			Status:   CheckWarn,
			Severity: "warning",
			Title:    "Codex 鍦ㄧ嚎鍒锋柊鏈墽琛?,
			Message:  "褰撳墠鏈浠讳綍璐﹀彿鎵ц鍦ㄧ嚎鍒锋柊銆?,
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
				Title:   "鍒囨崲褰撳墠 Codex 璐﹀彿",
				Message: "褰撳墠 Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿涓嶄竴鑷达紝璇峰厛鍒囨崲鍒板搴旇处鍙峰悗鍐嶉噸璇曘€?,
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
				Title:   "閲嶆柊鎺堟潈璐﹀彿",
				Message: fmt.Sprintf("璐﹀彿 %s 鍦ㄧ嚎鍒锋柊澶辫触锛屽缓璁噸鏂版巿鏉冩垨閲嶆柊瀵煎叆璁よ瘉鏂囦欢銆?, account.EmailOrFallback()),
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
		account.DisplayTitle = "refresh token 宸茶鍏朵粬鏉ユ簮杞崲"
		account.DisplayMessage = "璇ヨ处鍙风殑 refresh token 宸茶鍏朵粬瀹㈡埛绔?璁よ瘉婧愬埛鏂板苟杞崲锛孋LIProxyAPI 褰撳墠淇濆瓨鐨勬槸鏃?token锛岄渶瑕佸洖鍒拌璇佹潵婧愰噸鏂扮櫥褰曞苟閲嶆柊鍚屾銆?
		account.NextStep = "鍥炲埌鍘熻璇佹潵婧愰噸鏂扮櫥褰曪紝閲嶆柊鍚屾鎴栭噸鏂板鍏ュ埌 CLIProxyAPI 鍚庯紝鍐嶆杩愯鍦ㄧ嚎浣撴銆?
	case ReasonAuthExpired:
		account.DisplayTitle = "璐﹀彿鐧诲綍鎬佸凡杩囨湡"
		account.DisplayMessage = "璇ヨ处鍙风殑鐧诲綍鎬佸凡缁忚繃鏈燂紝褰撳墠鏃犳硶缁х画鍦ㄧ嚎鍒锋柊銆?
		account.NextStep = "閲嶆柊鐧诲綍瀵瑰簲璐﹀彿锛岄噸鏂板悓姝ユ垨閲嶆柊瀵煎叆鍚庯紝鍐嶆杩愯鍦ㄧ嚎浣撴銆?
	case ReasonRefreshTokenMissing:
		account.DisplayTitle = "缂哄皯 refresh token"
		account.DisplayMessage = "璇ヨ处鍙疯璇佸唴瀹逛笉瀹屾暣锛岀己灏?refresh token锛屾棤娉曞湪绾跨画鏈熴€?
		account.NextStep = "閲嶆柊鑾峰彇瀹屾暣璁よ瘉骞堕噸鏂板鍏ワ紝鐒跺悗鍐嶆杩愯鍦ㄧ嚎浣撴銆?
	case ReasonActiveCodexMismatch:
		account.DisplayTitle = "褰撳墠 Codex 婵€娲昏处鍙蜂笉涓€鑷?
		account.DisplayMessage = "褰撳墠鏈満 Codex 婵€娲昏处鍙蜂笌鎵樼璐﹀彿涓嶄竴鑷达紝杩欓€氬父浼氬鑷村垏鎹㈡垨楠岃瘉缁撴灉涓嶇鍚堥鏈熴€?
		account.NextStep = "鍏堝垏鎹㈠埌 Codex 涓搴旇处鍙凤紝鍐嶉噸鏂拌繍琛屽湪绾夸綋妫€銆?
	case ReasonActiveCodexAuthFileMissing:
		account.DisplayTitle = "鏈満 Codex 婵€娲昏璇佹枃浠剁己澶?
		account.DisplayMessage = "褰撳墠鏃犳硶璇诲彇鏈満 Codex 鐨勬縺娲昏璇佹枃浠讹紝鍥犳鏃犳硶纭鎵樼璐﹀彿鏄惁涓庡綋鍓嶆縺娲昏处鍙蜂竴鑷淬€?
		account.NextStep = "鍏堢‘璁ゆ湰鏈?Codex 宸叉甯哥櫥褰曪紝鍐嶉噸鏂拌繍琛屽湪绾夸綋妫€銆?
	case ReasonAccountDisabled:
		account.DisplayTitle = "璐﹀彿宸茶绂佺敤"
		account.DisplayMessage = "璇ヨ处鍙峰綋鍓嶅浜?disabled 鐘舵€侊紝CLIProxyAPI 涓嶄細缁х画浣跨敤瀹冦€?
		account.NextStep = "濡傞渶缁х画浣跨敤锛岃閲嶆柊瀵煎叆涓€鏉℃柊鐨勬湁鏁堣璇侊紝鎴栧惎鐢ㄥ搴旇处鍙枫€?
	case ReasonIDTokenParseFailed:
		account.DisplayTitle = "璐﹀彿韬唤淇℃伅鏃犳硶瑙ｆ瀽"
		account.DisplayMessage = "璇ヨ处鍙风己灏戝彲璇嗗埆鐨?account_id锛屼笖 id_token 鏃犳硶瑙ｆ瀽锛屾棤娉曞彲闈犺瘑鍒韩浠姐€?
		account.NextStep = "閲嶆柊鑾峰彇瀹屾暣璁よ瘉骞堕噸鏂板鍏ャ€?
	default:
		if account.LiveStatus == CheckPass {
			account.DisplayTitle = "鍦ㄧ嚎浣撴閫氳繃"
			account.DisplayMessage = "璇ヨ处鍙峰湪绾垮埛鏂伴€氳繃锛屽綋鍓嶆湭鍙戠幇鏄庢樉闂銆?
			account.NextStep = "鏃犻渶棰濆澶勭悊銆?
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
			account.Summary = "鏈彂鐜版槑鏄鹃棶棰樸€?
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
