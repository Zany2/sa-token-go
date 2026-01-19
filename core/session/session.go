package session

import (
	"context"
	codec_json "github.com/click33/sa-token-go/codec/json"
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
	LoginID  string `json:"loginId"`  // Login ID | 登录ID
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
func (s *Session) SetDependencies(storage adapter.Storage, serializer adapter.Codec) {
	// 创建一个内存存储适配器
	if storage == nil {
		storage = memory.NewStorage()
	}
	// 创建一个JSON序列化器
	if serializer == nil {
		serializer = codec_json.NewJSONSerializer()
	}

	s.storage = storage
	s.serializer = serializer
}

// RemoveAllTerminals removes all terminals and returns them | 删除所有终端并返回被删除的列表
func (s *Session) RemoveAllTerminals() []TerminalInfo {
	removed := s.TerminalInfos
	s.TerminalInfos = make([]TerminalInfo, 0)
	return removed
}

// RemoveTerminalsByDevice removes all terminals of the given device type, preserving order of others, and returns the removed list | 删除指定设备类型的所有终端（保持其他终端顺序），并返回被删除的终端列表
func (s *Session) RemoveTerminalsByDevice(device string) []TerminalInfo {
	if device == "" {
		return nil
	}

	var removed []TerminalInfo
	w := 0 // write index

	for r := 0; r < len(s.TerminalInfos); r++ {
		if s.TerminalInfos[r].Device == device {
			removed = append(removed, s.TerminalInfos[r])
			continue // skip: do not copy to write position
		}
		if w != r {
			s.TerminalInfos[w] = s.TerminalInfos[r]
		}
		w++
	}

	// Truncate the slice to new length
	s.TerminalInfos = s.TerminalInfos[:w]

	return removed
}

// GetFirstTerminalByDevice returns the first terminal matching the given device type, or an empty TerminalInfo if not found | 根据设备类型获取顺序第一个匹配的终端信息，未找到则返回空TerminalInfo
func (s *Session) GetFirstTerminalByDevice(device string) (TerminalInfo, bool) {
	if device == "" {
		return TerminalInfo{}, false
	}

	for _, t := range s.TerminalInfos {
		if t.Device == device {
			return t, true
		}
	}
	return TerminalInfo{}, false
}

// RemoveOldestTerminal removes and returns the oldest terminal (first in list), preserving order of others | 移除并返回最早的终端（列表中第一个），保持其余终端顺序
func (s *Session) RemoveOldestTerminal() (TerminalInfo, bool) {
	if len(s.TerminalInfos) == 0 {
		return TerminalInfo{}, false
	}

	oldest := s.TerminalInfos[0]
	s.TerminalInfos = s.TerminalInfos[1:]
	return oldest, true
}

// AddTerminalInfo adds a terminal info to the session | 向会话中添加一个终端信息
func (s *Session) AddTerminalInfo(terminalInfo TerminalInfo) {
	if s.TerminalInfos == nil {
		s.TerminalInfos = make([]TerminalInfo, 0, 1)
	}
	s.TerminalInfos = append(s.TerminalInfos, terminalInfo)
}

// RemoveTerminalInfo removes the terminal with the given token (if exists), preserving order of others | 根据Token删除对应的终端信息（如果存在），保持其余终端顺序
func (s *Session) RemoveTerminalInfo(tokenValue string) {
	if tokenValue == "" {
		return
	}

	for i, t := range s.TerminalInfos {
		if t.Token == tokenValue {
			s.TerminalInfos = append(s.TerminalInfos[:i], s.TerminalInfos[i+1:]...)
			return // only remove the first match
		}
	}
}

// GetTerminalsByDevice returns all terminals matching the given device type | 根据设备类型获取所有匹配的终端信息
func (s *Session) GetTerminalsByDevice(device string) []TerminalInfo {
	if device == "" {
		return nil
	}

	var result []TerminalInfo
	for _, t := range s.TerminalInfos {
		if t.Device == device {
			result = append(result, t)
		}
	}

	return result
}

// GetTokensByDevice returns all tokens of terminals matching the given device type | 根据设备类型获取所有匹配终端的Token列表
func (s *Session) GetTokensByDevice(device string) []string {
	if device == "" {
		return nil
	}

	var tokens []string
	for _, t := range s.TerminalInfos {
		if t.Device == device {
			tokens = append(tokens, t.Token)
		}
	}

	return tokens
}

// Save saves the session to storage | 保存Session到存储
func (s *Session) Save(ctx context.Context, key string, ttl time.Duration) error {
	encode, err := s.serializer.Encode(s)
	if err != nil {
		return err
	}
	return s.storage.Set(ctx, key, encode, ttl)
}

// ExtractTokens extracts all tokens from the session | 从Session中提取所有Token
func (s *Session) ExtractTokens() []string {
	tokenList := make([]string, len(s.TerminalInfos))
	for _, info := range s.TerminalInfos {
		tokenList = append(tokenList, info.Token)
	}
	return tokenList
}
