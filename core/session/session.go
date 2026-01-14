package session

import (
	"context"
	"fmt"
	codec_json "github.com/click33/sa-token-go/codec/json"
	"github.com/click33/sa-token-go/core"
	"github.com/click33/sa-token-go/core/adapter"
	"github.com/click33/sa-token-go/storage/memory"
	"sync"
	"time"
)

// Session Session object for storing user data | 会话对象，用于存储用户数据
type Session struct {
	AuthType      string         `json:"authType"`      // Authentication system type | 认证体系类型
	ID            string         `json:"id"`            // Session ID | Session标识
	CreateTime    int64          `json:"createTime"`    // Creation time | 创建时间
	TerminalInfos []TerminalInfo `json:"terminalInfos"` // TerminalInfos Information | 终端信息
	Permissions   []string       `json:"permissions"`   // Permissions Information | 权限信息
	Roles         []string       `json:"roles"`         // Roles Information | 角色信息

	prefix     string          `json:"-" msgpack:"-"` // Key prefix | 键前缀
	mu         sync.RWMutex    `json:"-" msgpack:"-"` // Read-write lock | 读写锁
	storage    adapter.Storage `json:"-" msgpack:"-"` // Storage adapter | 存储适配器
	serializer adapter.Codec   `json:"-" msgpack:"-"` // Serializer adapter | 序列化器
}

// TerminalInfo terminal information | 终端信息
type TerminalInfo struct {
	Token    string `json:"token"`    // Token value | 令牌
	Device   string `json:"device"`   // Device type | 设备类型
	DeviceId string `json:"deviceId"` // Device ID | 设备ID
}

// NewSession Creates a new session | 创建新的Session
func NewSession(authType, prefix, id string, storage adapter.Storage, serializer adapter.Codec) *Session {
	// 创建一个内存存储适配器
	if storage == nil {
		storage = memory.NewStorage()
	}
	// 创建一个JSON序列化器
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	// 创建一个新的Session
	return &Session{
		AuthType:      authType,
		ID:            id,
		CreateTime:    time.Now().Unix(),
		TerminalInfos: make([]TerminalInfo, 0),
		Permissions:   make([]string, 0),
		Roles:         make([]string, 0),
		prefix:        prefix,
		storage:       storage,
		serializer:    serializer,
	}
}

// SetDependencies sets internal dependencies for a decoded session | 设置反序列化后的 Session 的内部依赖
func (s *Session) SetDependencies(prefix string, storage adapter.Storage, serializer adapter.Codec) {
	// 创建一个内存存储适配器
	if storage == nil {
		storage = memory.NewStorage()
	}
	// 创建一个JSON序列化器
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	s.prefix = prefix
	s.storage = storage
	s.serializer = serializer
}

// ============ Data Operations | 数据操作 ============

// Get returns stored session values by key.
func (s *Session) Get(key string) (any, bool) {
	if key == "" {
		return nil, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	switch key {
	case "permissions":
		return append([]string(nil), s.Permissions...), true
	case "roles":
		return append([]string(nil), s.Roles...), true
	case "loginId":
		return s.ID, true
	case "loginTime":
		return s.CreateTime, true
	default:
		return nil, false
	}
}

// Set updates stored session values by key.
func (s *Session) Set(ctx context.Context, key string, value any, ttl ...time.Duration) error {
	if key == "" {
		return core.ErrSessionInvalidDataKey
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	switch key {
	case "permissions":
		s.Permissions = toStringSlice(value)
	case "roles":
		s.Roles = toStringSlice(value)
	case "loginId":
		if v, ok := value.(string); ok {
			s.ID = v
		} else {
			return core.ErrSessionInvalidDataKey
		}
	case "loginTime":
		switch v := value.(type) {
		case int64:
			s.CreateTime = v
		case int:
			s.CreateTime = int64(v)
		case float64:
			s.CreateTime = int64(v)
		default:
			return core.ErrSessionInvalidDataKey
		}
	default:
		return core.ErrSessionInvalidDataKey
	}

	return s.save(ctx, ttl...)
}

func toStringSlice(v any) []string {
	switch val := v.(type) {
	case []string:
		return append([]string(nil), val...)
	case []any:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if str, ok := item.(string); ok && str != "" {
				result = append(result, str)
			}
		}
		return result
	default:
		return []string{}
	}
}

// AddPermissions adds permissions | 新增权限
func (s *Session) AddPermissions(ctx context.Context, permissions []string, ttl ...time.Duration) error {
	if len(permissions) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]struct{}, len(s.Permissions))
	for _, p := range s.Permissions {
		if p != "" {
			existing[p] = struct{}{}
		}
	}

	toAdd := make([]string, 0, len(permissions))
	for _, p := range permissions {
		if p == "" {
			continue
		}
		if _, exists := existing[p]; exists {
			continue
		}
		existing[p] = struct{}{}
		toAdd = append(toAdd, p)
	}

	if len(toAdd) == 0 {
		return nil
	}

	s.Permissions = append(s.Permissions, toAdd...)
	return s.save(ctx, ttl...)
}

// AddRoles adds roles | 新增角色
func (s *Session) AddRoles(ctx context.Context, roles []string, ttl ...time.Duration) error {
	if len(roles) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	existing := make(map[string]struct{}, len(s.Roles))
	for _, r := range s.Roles {
		if r != "" {
			existing[r] = struct{}{}
		}
	}

	toAdd := make([]string, 0, len(roles))
	for _, r := range roles {
		if r == "" {
			continue
		}
		if _, exists := existing[r]; exists {
			continue
		}
		existing[r] = struct{}{}
		toAdd = append(toAdd, r)
	}

	if len(toAdd) == 0 {
		return nil
	}

	s.Roles = append(s.Roles, toAdd...)
	return s.save(ctx, ttl...)
}

// RemovePermissions removes permissions | 删除权限
func (s *Session) RemovePermissions(ctx context.Context, permissions []string, ttl ...time.Duration) error {
	if len(permissions) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Permissions) == 0 {
		return nil
	}

	// 构建要删除的集合
	removeSet := make(map[string]struct{}, len(permissions))
	for _, p := range permissions {
		if p != "" {
			removeSet[p] = struct{}{}
		}
	}
	if len(removeSet) == 0 {
		return nil
	}

	// 原地删除（保持顺序）
	w := 0 // write index
	for r := 0; r < len(s.Permissions); r++ {
		if _, shouldRemove := removeSet[s.Permissions[r]]; !shouldRemove {
			if w != r {
				s.Permissions[w] = s.Permissions[r]
			}
			w++
		}
	}

	if w == len(s.Permissions) {
		// 没有删除任何元素
		return nil
	}

	// 截断 slice
	s.Permissions = s.Permissions[:w]

	return s.save(ctx, ttl...)
}

// RemoveRoles removes roles | 删除角色
func (s *Session) RemoveRoles(ctx context.Context, roles []string, ttl ...time.Duration) error {
	if len(roles) == 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Roles) == 0 {
		return nil
	}

	removeSet := make(map[string]struct{}, len(roles))
	for _, r := range roles {
		if r != "" {
			removeSet[r] = struct{}{}
		}
	}
	if len(removeSet) == 0 {
		return nil
	}

	w := 0
	for r := 0; r < len(s.Roles); r++ {
		if _, shouldRemove := removeSet[s.Roles[r]]; !shouldRemove {
			if w != r {
				s.Roles[w] = s.Roles[r]
			}
			w++
		}
	}

	if w == len(s.Roles) {
		return nil
	}

	s.Roles = s.Roles[:w]
	return s.save(ctx, ttl...)
}

// ClearPermissions clears all permissions | 清空所有权限
func (s *Session) ClearPermissions(ctx context.Context, ttl ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Permissions) == 0 {
		return nil
	}

	s.Permissions = make([]string, 0)
	return s.save(ctx, ttl...)
}

// ClearRoles clears all roles | 清空所有角色
func (s *Session) ClearRoles(ctx context.Context, ttl ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.Roles) == 0 {
		return nil
	}

	s.Roles = make([]string, 0)
	return s.save(ctx, ttl...)
}

// AddTerminal adds or updates a session terminal entry, preserving order | 添加或更新会话终端信息，保持原有顺序
func (s *Session) AddTerminal(ctx context.Context, terminal TerminalInfo, ttl ...time.Duration) error {
	if terminal.Token == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 查找是否已存在相同 Token（保持顺序：更新原位置）
	for i, t := range s.TerminalInfos {
		if t.Token == terminal.Token {
			s.TerminalInfos[i] = terminal // 替换，位置不变
			return s.save(ctx, ttl...)
		}
	}

	// 不存在：追加到末尾（保持插入顺序）
	s.TerminalInfos = append(s.TerminalInfos, terminal)
	return s.save(ctx, ttl...)
}

// RemoveTerminalByToken removes terminals by token, preserving the order of remaining terminals | 根据令牌删除终端信息，保留剩余终端的原有顺序
func (s *Session) RemoveTerminalByToken(ctx context.Context, token string, ttl ...time.Duration) error {
	if token == "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.TerminalInfos) == 0 {
		return nil
	}

	w := 0
	found := false
	for r := 0; r < len(s.TerminalInfos); r++ {
		if s.TerminalInfos[r].Token == token {
			found = true
			continue // 跳过要删除的
		}
		if w != r {
			s.TerminalInfos[w] = s.TerminalInfos[r]
		}
		w++
	}

	if !found {
		return nil
	}

	s.TerminalInfos = s.TerminalInfos[:w] // 截断，保持顺序
	return s.save(ctx, ttl...)
}

// RemoveTerminalInfosByDevice removes terminals by device and returns deleted tokens | 按设备类型删除终端并返回被清除的Token列表
func (s *Session) RemoveTerminalInfosByDevice(ctx context.Context, device string, ttl ...time.Duration) ([]string, error) {
	if device == "" {
		return nil, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.TerminalInfos) == 0 {
		return nil, nil
	}

	w := 0
	var removedTokens []string

	for r := 0; r < len(s.TerminalInfos); r++ {
		if s.TerminalInfos[r].Device == device {
			removedTokens = append(removedTokens, s.TerminalInfos[r].Token)
			continue
		}
		if w != r {
			s.TerminalInfos[w] = s.TerminalInfos[r]
		}
		w++
	}

	if len(removedTokens) == 0 {
		return nil, nil
	}

	s.TerminalInfos = s.TerminalInfos[:w]

	err := s.save(ctx, ttl...)
	return removedTokens, err
}

// ReplaceTerminals replaces all terminal infos with the provided list | 替换所有终端信息为新列表
func (s *Session) ReplaceTerminals(ctx context.Context, terminals []TerminalInfo, ttl ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 如果新列表为空，直接清空
	if len(terminals) == 0 {
		if len(s.TerminalInfos) == 0 {
			return nil // 无需保存
		}
		s.TerminalInfos = make([]TerminalInfo, 0)
		return s.save(ctx, ttl...)
	}

	// 深拷贝一份（避免外部修改影响内部状态）
	newList := make([]TerminalInfo, len(terminals))
	for i, t := range terminals {
		// 可选：跳过 Token 为空的终端（保持一致性，与 AddTerminal 行为一致）
		if t.Token == "" {
			continue
		}
		newList[i] = t
	}

	// 实际写入数量可能因跳过空 Token 而减少
	// 重新切片以去除跳过的项（如果需要严格过滤）
	filtered := make([]TerminalInfo, 0, len(terminals))
	for _, t := range terminals {
		if t.Token != "" {
			filtered = append(filtered, t)
		}
	}

	// 判断是否内容真正发生变化（可选优化）
	// 简化处理：直接赋值并保存（除非性能敏感，否则可接受）

	s.TerminalInfos = filtered
	return s.save(ctx, ttl...)
}

// ClearTerminalInfos clears all terminals | 清空所有终端信息
func (s *Session) ClearTerminalInfos(ctx context.Context, ttl ...time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.TerminalInfos) == 0 {
		return nil
	}

	s.TerminalInfos = make([]TerminalInfo, 0)
	return s.save(ctx, ttl...)
}

// Renew extends the session TTL without modifying content | 续期 Session 的 TTL，但不修改内容
func (s *Session) Renew(ctx context.Context, ttl time.Duration) error {
	if ttl < 0 {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Extend session TTL | 续期Session的TTL
	err := s.storage.Expire(ctx, s.getStorageKey(), ttl)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// Destroy Destroys session | 销毁Session
func (s *Session) Destroy(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Delete session from storage | 删除Session
	err := s.storage.Delete(ctx, s.getStorageKey())
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}

// ============ Internal Methods | 内部方法 ============

// getStorageKey Gets storage key for this session | 获取Session的存储键
func (s *Session) getStorageKey() string {
	return s.prefix + s.AuthType + SessionKeyPrefix + s.ID
}

// save Saves session to storage | 保存到存储
func (s *Session) save(ctx context.Context, ttl ...time.Duration) error {
	// Check if a positive TTL is explicitly provided
	if len(ttl) > 0 && ttl[0] > 0 {
		// Serialize session | 序列化Session
		data, err := s.serializer.Encode(s)
		if err != nil {
			return fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
		}

		// Save with the specified TTL
		err = s.storage.Set(ctx, s.getStorageKey(), data, ttl[0])
		if err != nil {
			return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
		}

		return nil
	}

	// No valid TTL provided: preserve existing TTL
	return s.saveKeepTTL(ctx)
}

// saveKeepTTL saves session while preserving its TTL | 保存 Session 并保留现有 TTL
func (s *Session) saveKeepTTL(ctx context.Context) error {
	// Serialize session | 序列化Session
	data, err := s.serializer.Encode(s)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrSerializeFailed, err)
	}

	// Get storage key for this session | 获取Session的存储键
	key := s.getStorageKey()

	// Try to get current TTL | 获取当前 TTL
	// -1: never expires | 永不过期
	// -2: key not found | key不存在
	// >0: remaining TTL | 剩余时间
	ttl, err := s.storage.TTL(ctx, key)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	// ttl <= 0 means: not found(-2), never expires(-1), or expired | 这些情况都保存为永久
	// ttl > 0: use original TTL | 使用原有TTL
	if ttl <= 0 {
		ttl = 0
	}

	// Save to storage with expiration | 使用过期时间保存（0 表示永不过期）
	err = s.storage.Set(ctx, key, data, ttl)
	if err != nil {
		return fmt.Errorf("%w: %v", core.ErrStorageUnavailable, err)
	}

	return nil
}
