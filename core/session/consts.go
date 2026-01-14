// @Author daixk 2025/12/7 17:22:00
package session

// TokenState 表示 Token 的逻辑状态
type TokenState string

const (
	TokenStateLogout   TokenState = "LOGOUT"      // Logout state | 主动登出
	TokenStateKickout  TokenState = "KICK_OUT"    // Kickout state | 被踢下线
	TokenStateReplaced TokenState = "BE_REPLACED" // Replaced state | 被顶下线
)

const (
	SessionKeyPrefix = "session:" // Storage key prefix | 存储键前缀
)
