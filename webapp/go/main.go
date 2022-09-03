package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/labstack/echo-contrib/pprof"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/pkg/errors"
	"golang.org/x/sync/errgroup"
)

var (
	ErrInvalidRequestBody       error = fmt.Errorf("invalid request body")
	ErrInvalidMasterVersion     error = fmt.Errorf("invalid master version")
	ErrInvalidItemType          error = fmt.Errorf("invalid item type")
	ErrInvalidToken             error = fmt.Errorf("invalid token")
	ErrGetRequestTime           error = fmt.Errorf("failed to get request time")
	ErrExpiredSession           error = fmt.Errorf("session expired")
	ErrUserNotFound             error = fmt.Errorf("not found user")
	ErrUserDeviceNotFound       error = fmt.Errorf("not found user device")
	ErrItemNotFound             error = fmt.Errorf("not found item")
	ErrLoginBonusRewardNotFound error = fmt.Errorf("not found login bonus reward")
	ErrNoFormFile               error = fmt.Errorf("no such file")
	ErrUnauthorized             error = fmt.Errorf("unauthorized user")
	ErrForbidden                error = fmt.Errorf("forbidden")
	ErrGeneratePassword         error = fmt.Errorf("failed to password hash") //nolint:deadcode
)

const (
	DeckCardNumber      int = 3
	PresentCountPerPage int = 100

	SQLDirectory string = "../sql/"
	nShards             = 4
)

var dbHosts = []string{"133.152.6.250", "133.152.6.251", "133.152.6.252", "133.152.6.253"}

type Handler struct {
	dbs []*sqlx.DB

	initializedAt time.Time
}

func (h *Handler) use37() bool {
	return h.initializedAt.Add(1 * time.Second).Before(time.Now())
}

func (h *Handler) getUserDB(userID int64) *sqlx.DB {
	return h.dbs[userID%nShards]
}

func (h *Handler) getAdminDB() *sqlx.DB {
	return h.dbs[0]
}

func main() {
	rand.Seed(time.Now().UnixNano())
	time.Local = time.FixedZone("Local", 9*60*60)

	e := echo.New()
	pprof.Register(e)
	//e.Use(middleware.Logger())
	e.Use(middleware.Recover())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet, http.MethodPost},
		AllowHeaders: []string{"Content-Type", "x-master-version", "x-session"},
	}))

	// connect db
	dbs, err := connectDBs()
	if err != nil {
		e.Logger.Fatalf("failed to connect to db: %v", err)
	}
	defer func(dbs []*sqlx.DB) {
		for _, db := range dbs {
			db.Close()
		}
	}(dbs)

	// setting server
	e.Server.Addr = fmt.Sprintf(":%v", "8080")
	h := &Handler{
		dbs: dbs,
	}

	// e.Use(middleware.CORS())
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{}))

	// utility
	e.POST("/initialize", h.initialize)
	e.GET("/health", h.health)

	// feature
	API := e.Group("", h.apiMiddleware)
	API.POST("/user", h.createUser)
	API.POST("/login", h.login)
	sessCheckAPI := API.Group("", h.checkSessionMiddleware)
	sessCheckAPI.GET("/user/:userID/gacha/index", h.listGacha)
	sessCheckAPI.POST("/user/:userID/gacha/draw/:gachaID/:n", h.drawGacha)
	sessCheckAPI.GET("/user/:userID/present/index/:n", h.listPresent)
	sessCheckAPI.POST("/user/:userID/present/receive", h.receivePresent)
	sessCheckAPI.GET("/user/:userID/item", h.listItem)
	sessCheckAPI.POST("/user/:userID/card/addexp/:cardID", h.addExpToCard)
	sessCheckAPI.POST("/user/:userID/card", h.updateDeck)
	sessCheckAPI.POST("/user/:userID/reward", h.reward)
	sessCheckAPI.GET("/user/:userID/home", h.home)

	// admin
	adminAPI := e.Group("", h.adminMiddleware)
	adminAPI.POST("/admin/login", h.adminLogin)
	adminAuthAPI := adminAPI.Group("", h.adminSessionCheckMiddleware)
	adminAuthAPI.DELETE("/admin/logout", h.adminLogout)
	adminAuthAPI.GET("/admin/master", h.adminListMaster)
	adminAuthAPI.PUT("/admin/master", h.adminUpdateMaster)
	adminAuthAPI.GET("/admin/user/:userID", h.adminUser)
	adminAuthAPI.POST("/admin/user/:userID/ban", h.adminBanUser)

	e.Logger.Infof("Start server: address=%s", e.Server.Addr)
	e.Logger.Error(e.StartServer(e.Server))
}

func connectDBs() ([]*sqlx.DB, error) {
	dbs := make([]*sqlx.DB, 0, nShards)
	for _, host := range dbHosts {
		dsn := fmt.Sprintf(
			"isucon:isucon@tcp(%s:3306)/isucon?charset=utf8mb4&parseTime=true&loc=Asia%%2FTokyo&multiStatements=true&interpolateParams=true",
			host,
		)
		db, err := sqlx.Open("mysql", dsn)
		if err != nil {
			return nil, err
		}
		for {
			if err := db.Ping(); err == nil {
				break
			}
			log.Printf("failed to ping db: %v", err)
		}
		dbs = append(dbs, db)
	}
	return dbs, nil
}

// adminMiddleware
func (h *Handler) adminMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestAt := time.Now()
		c.Set("requestTime", requestAt.Unix())

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// apiMiddleware
func (h *Handler) apiMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		requestAt, err := time.Parse(time.RFC1123, c.Request().Header.Get("x-isu-date"))
		if err != nil {
			requestAt = time.Now()
		}
		c.Set("requestTime", requestAt.Unix())

		// マスタ確認
		masterVersion := new(VersionMaster)
		for _, mv := range getMasterVersions() {
			if mv.Status == 1 {
				masterVersion = mv
				break
			}
		}
		if masterVersion == nil {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("active master version is not found"))
		}

		if masterVersion.MasterVersion != c.Request().Header.Get("x-master-version") {
			return errorResponse(c, http.StatusUnprocessableEntity, ErrInvalidMasterVersion)
		}

		// check ban
		userID, err := getUserID(c)
		if err == nil && userID != 0 {
			isBan, err := h.checkBan(userID)
			if err != nil {
				return errorResponse(c, http.StatusInternalServerError, err)
			}
			if isBan {
				return errorResponse(c, http.StatusForbidden, ErrForbidden)
			}
		}

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// checkSessionMiddleware
func (h *Handler) checkSessionMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		sessID := c.Request().Header.Get("x-session")
		if sessID == "" {
			return errorResponse(c, http.StatusUnauthorized, ErrUnauthorized)
		}

		userID, err := getUserID(c)
		if err != nil {
			return errorResponse(c, http.StatusBadRequest, err)
		}

		requestAt, err := getRequestTime(c)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
		}

		userSession, ok := getUserSessionBySessionID(sessID)
		if !ok {
			return errorResponse(c, http.StatusUnauthorized, ErrUnauthorized)
		}

		if userSession.UserID != userID {
			return errorResponse(c, http.StatusForbidden, ErrForbidden)
		}

		if userSession.ExpiredAt < requestAt {
			clearUserSession(userSession)
			return errorResponse(c, http.StatusUnauthorized, ErrExpiredSession)
		}

		// next
		if err := next(c); err != nil {
			c.Error(err)
		}
		return nil
	}
}

// checkOneTimeToken
func (h *Handler) checkOneTimeToken(userID int64, token string, tokenType int, requestAt int64) error {
	tk := new(UserOneTimeToken)
	query := "SELECT * FROM user_one_time_tokens WHERE token=? AND token_type=? AND deleted_at IS NULL"
	if err := h.getUserDB(userID).Get(tk, query, token, tokenType); err != nil {
		if err == sql.ErrNoRows {
			return ErrInvalidToken
		}
		return err
	}

	if tk.ExpiredAt < requestAt {
		query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE token=?"
		if _, err := h.getUserDB(userID).Exec(query, requestAt, token); err != nil {
			return err
		}
		return ErrInvalidToken
	}

	// 使ったトークンを失効する
	query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE token=?"
	if _, err := h.getUserDB(userID).Exec(query, requestAt, token); err != nil {
		return err
	}

	return nil
}

// checkViewerID
func (h *Handler) checkViewerID(userID int64, viewerID string) error {
	query := "SELECT * FROM user_devices WHERE user_id=? AND platform_id=?"
	device := new(UserDevice)
	if err := h.getUserDB(userID).Get(device, query, userID, viewerID); err != nil {
		if err == sql.ErrNoRows {
			return ErrUserDeviceNotFound
		}
		return err
	}

	return nil
}

// checkBan
func (h *Handler) checkBan(userID int64) (bool, error) {
	return isBannedUser(userID), nil
}

// getRequestTime リクエストを受けた時間をコンテキストからunixtimeで取得する
func getRequestTime(c echo.Context) (int64, error) {
	v := c.Get("requestTime")
	if requestTime, ok := v.(int64); ok {
		return requestTime, nil
	}
	return 0, ErrGetRequestTime
}

// loginProcess ログイン処理
func (h *Handler) loginProcess(tx *sqlx.Tx, userID int64, requestAt int64) (*User, []*UserLoginBonus, []*UserPresent, error) {
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := tx.Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, ErrUserNotFound
		}
		return nil, nil, nil, err
	}

	// ログインボーナス処理
	loginBonuses, err := h.obtainLoginBonus(tx, user, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	// 全員プレゼント取得
	allPresents, err := h.obtainPresent(tx, userID, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	if err = tx.Get(&user.IsuCoin, "SELECT isu_coin FROM users WHERE id=?", user.ID); err != nil {
		if err == sql.ErrNoRows {
			return nil, nil, nil, ErrUserNotFound
		}
		return nil, nil, nil, err
	}

	user.UpdatedAt = requestAt
	user.LastActivatedAt = requestAt

	query = "UPDATE users SET updated_at=?, last_activated_at=? WHERE id=?"
	if _, err := tx.Exec(query, requestAt, requestAt, userID); err != nil {
		return nil, nil, nil, err
	}

	return user, loginBonuses, allPresents, nil
}

// isCompleteTodayLogin ログイン処理が終わっているか
func isCompleteTodayLogin(lastActivatedAt, requestAt time.Time) bool {
	return lastActivatedAt.Year() == requestAt.Year() &&
		lastActivatedAt.Month() == requestAt.Month() &&
		lastActivatedAt.Day() == requestAt.Day()
}

// obtainLoginBonus
func (h *Handler) obtainLoginBonus(tx *sqlx.Tx, user *User, requestAt int64) ([]*UserLoginBonus, error) {
	// login bonus masterから有効なログインボーナスを取得
	loginBonuses := make([]*LoginBonusMaster, 0)
	for _, lb := range getLoginBonusMasters() {
		if lb.ID != 3 && lb.StartAt <= requestAt {
			loginBonuses = append(loginBonuses, lb)
		}
	}

	loginBonusIDs := make([]int64, 0, len(loginBonuses))
	for _, lb := range loginBonuses {
		loginBonusIDs = append(loginBonusIDs, lb.ID)
	}
	query, params, err := sqlx.In("SELECT * FROM user_login_bonuses WHERE user_id=? AND login_bonus_id IN (?)", user.ID, loginBonusIDs)
	if err != nil {
		return nil, err
	}
	// 継続中のログインボーナス
	var progressingLoginBonuses []*UserLoginBonus
	if err := tx.Select(&progressingLoginBonuses, query, params...); err != nil {
		return nil, err
	}

	// まだ受け取り始めて無いログインボーナスを用意する
	userLoginBonusMap := make(map[int64]*UserLoginBonus, len(loginBonuses))
	for _, ulb := range progressingLoginBonuses {
		userLoginBonusMap[ulb.LoginBonusID] = ulb
	}
	for _, lb := range loginBonuses {
		if _, ok := userLoginBonusMap[lb.ID]; !ok {
			ubID, err := h.generateID()
			if err != nil {
				return nil, err
			}
			userLoginBonusMap[lb.ID] = &UserLoginBonus{
				ID:                 ubID,
				UserID:             user.ID,
				LoginBonusID:       lb.ID,
				LastRewardSequence: 0,
				LoopCount:          1,
				CreatedAt:          requestAt,
				UpdatedAt:          requestAt,
			}
		}
	}

	sendLoginBonuses := make([]*UserLoginBonus, 0, len(loginBonuses))
	rewardItems := make([]*UserPresent, 0, len(loginBonuses))
	for _, bonus := range loginBonuses {
		userBonus, ok := userLoginBonusMap[bonus.ID]
		if !ok {
			// ありえない
			return nil, errors.New("user bonus not found in userLoginBonusMap")
		}

		// ボーナス進捗更新
		if userBonus.LastRewardSequence < bonus.ColumnCount {
			userBonus.LastRewardSequence++
		} else {
			if bonus.Looped {
				userBonus.LoopCount += 1
				userBonus.LastRewardSequence = 1
			} else {
				// 上限まで付与完了
				continue
			}
		}
		userBonus.UpdatedAt = requestAt

		// 今回付与するリソース取得
		rewardItem := new(LoginBonusRewardMaster)
		for _, lbr := range getLoginBonusRewardMasters() {
			if lbr.LoginBonusID == bonus.ID && lbr.RewardSequence == userBonus.LastRewardSequence {
				rewardItem = lbr
				break
			}
		}
		if rewardItem == nil {
			return nil, ErrLoginBonusRewardNotFound
		}

		rewardItems = append(rewardItems, &UserPresent{
			ItemType: rewardItem.ItemType,
			ItemID:   rewardItem.ItemID,
			Amount:   int(rewardItem.Amount),
		})

		sendLoginBonuses = append(sendLoginBonuses, userBonus)
	}
	if err := h.obtainItems(tx, user, requestAt, rewardItems); err != nil {
		return nil, err
	}

	if len(sendLoginBonuses) > 0 {
		query = "INSERT INTO user_login_bonuses (id, user_id, login_bonus_id, last_reward_sequence, loop_count, created_at, updated_at, deleted_at) VALUES (:id, :user_id, :login_bonus_id, :last_reward_sequence, :loop_count, :created_at, :updated_at, :deleted_at) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), login_bonus_id=VALUES(login_bonus_id), last_reward_sequence=VALUES(last_reward_sequence), loop_count=VALUES(loop_count), created_at=VALUES(created_at), updated_at=VALUES(updated_at), deleted_at=VALUES(deleted_at)"
		if _, err := tx.NamedExec(query, sendLoginBonuses); err != nil {
			return nil, err
		}
	}

	return sendLoginBonuses, nil
}

// obtainPresent プレゼント付与処理
func (h *Handler) obtainPresent(tx *sqlx.Tx, userID int64, requestAt int64) ([]*UserPresent, error) {
	var normalPresents []*PresentAllMaster
	for _, pm := range getPresentAllMasters() {
		if pm.RegisteredStartAt <= requestAt && pm.RegisteredEndAt >= requestAt {
			normalPresents = append(normalPresents, pm)
		}
	}

	presentAllIDs := make([]int64, 0, len(normalPresents))
	for _, np := range normalPresents {
		presentAllIDs = append(presentAllIDs, np.ID)
	}
	var receivedHistories []*UserPresentAllReceivedHistory
	query, args, err := sqlx.In("SELECT * FROM user_present_all_received_history WHERE user_id=? AND present_all_id IN (?)", userID, presentAllIDs)
	if err != nil {
		return nil, err
	}
	if err := tx.Select(&receivedHistories, query, args...); err != nil {
		return nil, err
	}
	receivedHistoryMap := make(map[int64]*UserPresentAllReceivedHistory, len(receivedHistories))
	for _, h := range receivedHistories {
		receivedHistoryMap[h.PresentAllID] = h
	}

	// 全員プレゼント取得情報更新
	obtainPresents := make([]*UserPresent, 0, len(normalPresents))
	newHistories := make([]*UserPresentAllReceivedHistory, 0, len(normalPresents))
	for _, np := range normalPresents {
		// プレゼント配布済
		if _, ok := receivedHistoryMap[np.ID]; ok {
			continue
		}

		// user present boxに入れる
		pID, err := h.generateID()
		if err != nil {
			return nil, err
		}
		up := &UserPresent{
			ID:             pID,
			UserID:         userID,
			SentAt:         requestAt,
			ItemType:       np.ItemType,
			ItemID:         np.ItemID,
			Amount:         int(np.Amount),
			PresentMessage: np.PresentMessage,
			CreatedAt:      requestAt,
			UpdatedAt:      requestAt,
		}

		// historyに入れる
		phID, err := h.generateID()
		if err != nil {
			return nil, err
		}
		history := &UserPresentAllReceivedHistory{
			ID:           phID,
			UserID:       userID,
			PresentAllID: np.ID,
			ReceivedAt:   requestAt,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		newHistories = append(newHistories, history)

		obtainPresents = append(obtainPresents, up)
	}

	if len(obtainPresents) > 0 {
		queryBulkInsertPresents := "INSERT INTO user_presents(id, user_id, sent_at, item_type, item_id, amount, present_message, created_at, updated_at) VALUES (:id, :user_id, :sent_at, :item_type, :item_id, :amount, :present_message, :created_at, :updated_at)"
		if _, err := tx.NamedExec(queryBulkInsertPresents, obtainPresents); err != nil {
			return nil, err
		}
	}

	if len(newHistories) > 0 {
		queryBulkInsertHistories := "INSERT INTO user_present_all_received_history(id, user_id, present_all_id, received_at, created_at, updated_at) VALUES (:id, :user_id, :present_all_id, :received_at, :created_at, :updated_at)"
		if _, err := tx.NamedExec(queryBulkInsertHistories, newHistories); err != nil {
			return nil, err
		}
	}

	return obtainPresents, nil
}

func (h *Handler) obtainItems(tx *sqlx.Tx, user *User, requestAt int64, presents []*UserPresent) error {
	var addCoin int64
	cards := make([]*UserCard, 0, len(presents))
	itemPresents := make([]*UserPresent, 0, len(presents))

	for _, p := range presents {
		switch p.ItemType {
		case 1:
			addCoin += int64(p.Amount)
		case 2:
			item := new(ItemMaster)
			for _, im := range getItemMasters() {
				if im.ID == p.ItemID && im.ItemType == p.ItemType {
					item = im
					break
				}
			}
			if item == nil {
				return ErrItemNotFound
			}

			cID, err := h.generateID()
			if err != nil {
				return err
			}
			cards = append(cards, &UserCard{
				ID:           cID,
				UserID:       user.ID,
				CardID:       item.ID,
				AmountPerSec: *item.AmountPerSec,
				Level:        1,
				TotalExp:     0,
				CreatedAt:    requestAt,
				UpdatedAt:    requestAt,
			})
		case 3, 4:
			itemPresents = append(itemPresents, p)
		default:
			return ErrInvalidItemType
		}
	}

	if addCoin > 0 {
		totalCoin := user.IsuCoin + addCoin
		if _, err := tx.Exec("UPDATE users SET isu_coin=? WHERE id=?", totalCoin, user.ID); err != nil {
			return err
		}
	}

	if len(cards) > 0 {
		bulkInsertUserCardQuery := "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (:id, :user_id, :card_id, :amount_per_sec, :level, :total_exp, :created_at, :updated_at)"
		if _, err := tx.NamedExec(bulkInsertUserCardQuery, cards); err != nil {
			return err
		}
	}

	if len(itemPresents) > 0 {
		// check master exists
		for _, p := range itemPresents {
			item := new(ItemMaster)
			for _, im := range getItemMasters() {
				if im.ID == p.ItemID && im.ItemType == p.ItemType {
					item = im
					break
				}
			}
			if item == nil {
				return ErrItemNotFound
			}
		}

		itemIDs := make([]int64, 0, len(itemPresents))
		for _, p := range itemPresents {
			itemIDs = append(itemIDs, p.ItemID)
		}

		var havingItems []UserItem
		query, params, err := sqlx.In("SELECT * FROM user_items WHERE user_id=? AND item_id IN (?)", user.ID, itemIDs)
		if err != nil {
			return err
		}
		if err := tx.Select(&havingItems, query, params...); err != nil {
			return err
		}
		havingItemMap := make(map[int64]*UserItem, len(havingItems))
		for _, it := range havingItems {
			havingItemMap[it.ItemID] = &it
		}
		items := make([]*UserItem, 0, len(itemPresents))
		for _, p := range itemPresents {
			if it, ok := havingItemMap[p.ItemID]; ok {
				it.Amount += p.Amount
				it.UpdatedAt = requestAt
				items = append(items, it)
			} else {
				iID, err := h.generateID()
				if err != nil {
					return err
				}
				items = append(items, &UserItem{
					ID:        iID,
					UserID:    user.ID,
					ItemID:    p.ItemID,
					Amount:    p.Amount,
					CreatedAt: requestAt,
					UpdatedAt: requestAt,
				})
			}
		}
		if len(items) > 0 {
			query := "INSERT INTO user_items(id, user_id, item_type, item_id, amount, created_at, updated_at) VALUES (:id, :user_id, :item_type, :item_id, :amount, :created_at, :updated_at) ON DUPLICATE KEY UPDATE user_id=VALUES(user_id), item_type=VALUES(item_type), item_id=VALUES(item_id), amount=VALUES(amount), created_at=VALUES(created_at), updated_at=VALUES(updated_at)"
			if _, err := tx.NamedExec(query, items); err != nil {
				return err
			}
		}
	}

	return nil
}

// obtainItem アイテム付与処理
func (h *Handler) obtainItem(tx *sqlx.Tx, userID, itemID int64, itemType int, obtainAmount int64, requestAt int64) ([]int64, []*UserCard, []*UserItem, error) {
	obtainCoins := make([]int64, 0)
	obtainCards := make([]*UserCard, 0)
	obtainItems := make([]*UserItem, 0)

	switch itemType {
	case 1: // coin
		user := new(User)
		query := "SELECT * FROM users WHERE id=?"
		if err := tx.Get(user, query, userID); err != nil {
			if err == sql.ErrNoRows {
				return nil, nil, nil, ErrUserNotFound
			}
			return nil, nil, nil, err
		}

		query = "UPDATE users SET isu_coin=? WHERE id=?"
		totalCoin := user.IsuCoin + obtainAmount
		if _, err := tx.Exec(query, totalCoin, user.ID); err != nil {
			return nil, nil, nil, err
		}
		obtainCoins = append(obtainCoins, obtainAmount)

	case 2: // card(ハンマー)
		item := new(ItemMaster)
		for _, im := range getItemMasters() {
			if im.ID == itemID && im.ItemType == itemType {
				item = im
				break
			}
		}
		if item == nil {
			return nil, nil, nil, ErrItemNotFound
		}

		cID, err := h.generateID()
		if err != nil {
			return nil, nil, nil, err
		}
		card := &UserCard{
			ID:           cID,
			UserID:       userID,
			CardID:       item.ID,
			AmountPerSec: *item.AmountPerSec,
			Level:        1,
			TotalExp:     0,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		query := "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
		if _, err := tx.Exec(query, card.ID, card.UserID, card.CardID, card.AmountPerSec, card.Level, card.TotalExp, card.CreatedAt, card.UpdatedAt); err != nil {
			return nil, nil, nil, err
		}
		obtainCards = append(obtainCards, card)

	case 3, 4: // 強化素材
		item := new(ItemMaster)
		for _, im := range getItemMasters() {
			if im.ID == itemID && im.ItemType == itemType {
				item = im
				break
			}
		}
		if item == nil {
			return nil, nil, nil, ErrItemNotFound
		}
		// 所持数取得
		query := "SELECT * FROM user_items WHERE user_id=? AND item_id=?"
		uitem := new(UserItem)
		if err := tx.Get(uitem, query, userID, item.ID); err != nil {
			if err != sql.ErrNoRows {
				return nil, nil, nil, err
			}
			uitem = nil
		}

		if uitem == nil { // 新規作成
			uitemID, err := h.generateID()
			if err != nil {
				return nil, nil, nil, err
			}
			uitem = &UserItem{
				ID:        uitemID,
				UserID:    userID,
				ItemType:  item.ItemType,
				ItemID:    item.ID,
				Amount:    int(obtainAmount),
				CreatedAt: requestAt,
				UpdatedAt: requestAt,
			}
			query = "INSERT INTO user_items(id, user_id, item_id, item_type, amount, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
			if _, err := tx.Exec(query, uitem.ID, userID, uitem.ItemID, uitem.ItemType, uitem.Amount, requestAt, requestAt); err != nil {
				return nil, nil, nil, err
			}

		} else { // 更新
			uitem.Amount += int(obtainAmount)
			uitem.UpdatedAt = requestAt
			query = "UPDATE user_items SET amount=?, updated_at=? WHERE id=?"
			if _, err := tx.Exec(query, uitem.Amount, uitem.UpdatedAt, uitem.ID); err != nil {
				return nil, nil, nil, err
			}
		}

		obtainItems = append(obtainItems, uitem)

	default:
		return nil, nil, nil, ErrInvalidItemType
	}

	return obtainCoins, obtainCards, obtainItems, nil
}

// initialize 初期化処理
// POST /initialize
func (h *Handler) initialize(c echo.Context) error {
	rand.Seed(time.Now().UnixNano())

	eg, _ := errgroup.WithContext(context.TODO())
	for _, host := range dbHosts {
		host := host
		eg.Go(func() error {
			cmd := exec.Command("/bin/sh", "-c", SQLDirectory+"init.sh")
			cmd.Env = append(os.Environ(), "ISUCON_DB_HOST="+host)
			if out, err := cmd.CombinedOutput(); err != nil {
				c.Logger().Errorf("Failed to initialize %s: %v", string(out), err)
				return err
			}
			return nil
		})
	}
	if err := eg.Wait(); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if err := resetCache(h.dbs[0]); err != nil {
		c.Logger().Errorf("Failed to reset cache: %v", err)
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	runtime.GC()

	h.initializedAt = time.Now()
	return successResponse(c, &InitializeResponse{
		Language: "go",
	})
}

type InitializeResponse struct {
	Language string `json:"language"`
}

// createUser ユーザの作成
// POST /user
func (h *Handler) createUser(c echo.Context) error {
	// parse body
	defer c.Request().Body.Close()
	req := new(CreateUserRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if req.ViewerID == "" || req.PlatformType < 1 || req.PlatformType > 3 {
		return errorResponse(c, http.StatusBadRequest, ErrInvalidRequestBody)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	uID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	tx, err := h.getUserDB(uID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// ユーザ作成
	user := &User{
		ID:              uID,
		IsuCoin:         0,
		LastGetRewardAt: requestAt,
		LastActivatedAt: requestAt,
		RegisteredAt:    requestAt,
		CreatedAt:       requestAt,
		UpdatedAt:       requestAt,
	}
	query := "INSERT INTO users(id, last_activated_at, registered_at, last_getreward_at, created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?)"
	if _, err = tx.Exec(query, user.ID, user.LastActivatedAt, user.RegisteredAt, user.LastGetRewardAt, user.CreatedAt, user.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	udID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	userDevice := &UserDevice{
		ID:           udID,
		UserID:       user.ID,
		PlatformID:   req.ViewerID,
		PlatformType: req.PlatformType,
		CreatedAt:    requestAt,
		UpdatedAt:    requestAt,
	}
	query = "INSERT INTO user_devices(id, user_id, platform_id, platform_type, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
	_, err = tx.Exec(query, userDevice.ID, user.ID, req.ViewerID, req.PlatformType, requestAt, requestAt)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 初期デッキ付与
	initCard := new(ItemMaster)
	for _, im := range itemMasters {
		if im.ID == 2 {
			initCard = im
			break
		}
	}
	if initCard == nil {
		return errorResponse(c, http.StatusNotFound, ErrItemNotFound)
	}

	initCards := make([]*UserCard, 0, 3)
	for i := 0; i < 3; i++ {
		cID, err := h.generateID()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		card := &UserCard{
			ID:           cID,
			UserID:       user.ID,
			CardID:       initCard.ID,
			AmountPerSec: *initCard.AmountPerSec,
			Level:        1,
			TotalExp:     0,
			CreatedAt:    requestAt,
			UpdatedAt:    requestAt,
		}
		query = "INSERT INTO user_cards(id, user_id, card_id, amount_per_sec, level, total_exp, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
		if _, err := tx.Exec(query, card.ID, card.UserID, card.CardID, card.AmountPerSec, card.Level, card.TotalExp, card.CreatedAt, card.UpdatedAt); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		initCards = append(initCards, card)
	}

	deckID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	initDeck := &UserDeck{
		ID:        deckID,
		UserID:    user.ID,
		CardID1:   initCards[0].ID,
		CardID2:   initCards[1].ID,
		CardID3:   initCards[2].ID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
	}
	query = "INSERT INTO user_decks(id, user_id, user_card_id_1, user_card_id_2, user_card_id_3, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err := tx.Exec(query, initDeck.ID, initDeck.UserID, initDeck.CardID1, initDeck.CardID2, initDeck.CardID3, initDeck.CreatedAt, initDeck.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// ログイン処理
	user, loginBonuses, presents, err := h.loginProcess(tx, user.ID, requestAt)
	if err != nil {
		if err == ErrUserNotFound || err == ErrItemNotFound || err == ErrLoginBonusRewardNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		if err == ErrInvalidItemType {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// generate session
	sID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sessID, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sess := &Session{
		ID:        sID,
		UserID:    user.ID,
		SessionID: sessID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 86400,
	}
	updateUserSession(sess)

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &CreateUserResponse{
		UserID:           user.ID,
		ViewerID:         req.ViewerID,
		SessionID:        sess.SessionID,
		CreatedAt:        requestAt,
		UpdatedResources: makeUpdatedResources(requestAt, user, userDevice, initCards, []*UserDeck{initDeck}, nil, loginBonuses, presents),
	})
}

type CreateUserRequest struct {
	ViewerID     string `json:"viewerId"`
	PlatformType int    `json:"platformType"`
}

type CreateUserResponse struct {
	UserID           int64            `json:"userId"`
	ViewerID         string           `json:"viewerId"`
	SessionID        string           `json:"sessionId"`
	CreatedAt        int64            `json:"createdAt"`
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// login ログイン
// POST /login
func (h *Handler) login(c echo.Context) error {
	defer c.Request().Body.Close()
	req := new(LoginRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := h.getUserDB(req.UserID).Get(user, query, req.UserID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// check ban
	isBan, err := h.checkBan(user.ID)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if isBan {
		return errorResponse(c, http.StatusForbidden, ErrForbidden)
	}

	// viewer id check
	if err = h.checkViewerID(user.ID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	tx, err := h.getUserDB(user.ID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// sessionを更新
	sID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sessID, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	sess := &Session{
		ID:        sID,
		UserID:    req.UserID,
		SessionID: sessID,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 86400,
	}
	updateUserSession(sess)

	// すでにログインしているユーザはログイン処理をしない
	if isCompleteTodayLogin(time.Unix(user.LastActivatedAt, 0), time.Unix(requestAt, 0)) {
		user.UpdatedAt = requestAt
		user.LastActivatedAt = requestAt

		query = "UPDATE users SET updated_at=?, last_activated_at=? WHERE id=?"
		if _, err := tx.Exec(query, requestAt, requestAt, req.UserID); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		err = tx.Commit()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}

		return successResponse(c, &LoginResponse{
			ViewerID:         req.ViewerID,
			SessionID:        sess.SessionID,
			UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, nil, nil),
		})
	}

	// login process
	user, loginBonuses, presents, err := h.loginProcess(tx, req.UserID, requestAt)
	if err != nil {
		if err == ErrUserNotFound || err == ErrItemNotFound || err == ErrLoginBonusRewardNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		if err == ErrInvalidItemType {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &LoginResponse{
		ViewerID:         req.ViewerID,
		SessionID:        sess.SessionID,
		UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, loginBonuses, presents),
	})
}

type LoginRequest struct {
	ViewerID string `json:"viewerId"`
	UserID   int64  `json:"userId"`
}

type LoginResponse struct {
	ViewerID         string           `json:"viewerId"`
	SessionID        string           `json:"sessionId"`
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// listGacha ガチャ一覧
// GET /user/{userID}/gacha/index
func (h *Handler) listGacha(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	gachaMasterList := []*GachaMaster{}
	for _, gm := range getGachaMasters() {
		if gm.StartAt <= requestAt && gm.EndAt >= requestAt {
			gachaMasterList = append(gachaMasterList, gm)
		}
	}
	sort.Slice(gachaMasterList, func(i, j int) bool {
		return gachaMasterList[i].DisplayOrder < gachaMasterList[j].DisplayOrder
	})

	if len(gachaMasterList) == 0 {
		return successResponse(c, &ListGachaResponse{
			Gachas: []*GachaData{},
		})
	}

	// ガチャ排出アイテム取得
	var gachaItemMasters []*GachaItemMaster
	for _, gim := range getGachaItemMasters() {
		for _, g := range gachaMasterList {
			if g.ID == gim.GachaID {
				gachaItemMasters = append(gachaItemMasters, gim)
			}
		}
	}

	gachaDataList := make([]*GachaData, 0)
	for _, v := range gachaMasterList {
		var gachaItem []*GachaItemMaster
		for _, gim := range gachaItemMasters {
			if gim.GachaID == v.ID {
				gachaItem = append(gachaItem, gim)
			}
		}

		if len(gachaItem) == 0 {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha item"))
		}

		sort.Slice(gachaItem, func(i, j int) bool {
			return gachaItem[i].ID < gachaItem[j].ID
		})

		gachaDataList = append(gachaDataList, &GachaData{
			Gacha:     v,
			GachaItem: gachaItem,
		})
	}

	// genearte one time token
	query := "UPDATE user_one_time_tokens SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = h.getUserDB(userID).Exec(query, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tk, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	token := &UserOneTimeToken{
		ID:        tID,
		UserID:    userID,
		Token:     tk,
		TokenType: 1,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 600,
	}
	query = "INSERT INTO user_one_time_tokens(id, user_id, token, token_type, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err = h.getUserDB(userID).Exec(query, token.ID, token.UserID, token.Token, token.TokenType, token.CreatedAt, token.UpdatedAt, token.ExpiredAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &ListGachaResponse{
		OneTimeToken: token.Token,
		Gachas:       gachaDataList,
	})
}

type ListGachaResponse struct {
	OneTimeToken string       `json:"oneTimeToken"`
	Gachas       []*GachaData `json:"gachas"`
}

type GachaData struct {
	Gacha     *GachaMaster       `json:"gacha"`
	GachaItem []*GachaItemMaster `json:"gachaItemList"`
}

// drawGacha ガチャを引く
// POST /user/{userID}/gacha/draw/{gachaID}/{n}
func (h *Handler) drawGacha(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	gachaID := c.Param("gachaID")
	if gachaID == "" {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid gachaID"))
	}

	gachaCount, err := strconv.ParseInt(c.Param("n"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	if gachaCount != 1 && gachaCount != 10 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid draw gacha times"))
	}

	defer c.Request().Body.Close()
	req := new(DrawGachaRequest)
	if err = parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkOneTimeToken(userID, req.OneTimeToken, 1, requestAt); err != nil {
		if err == ErrInvalidToken {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	consumedCoin := int64(gachaCount * 1000)

	// userのisuconが足りるか
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err := h.getUserDB(userID).Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if user.IsuCoin < consumedCoin {
		return errorResponse(c, http.StatusConflict, fmt.Errorf("not enough isucon"))
	}

	// gachaIDからガチャマスタの取得
	gachaInfo := new(GachaMaster)
	for _, gm := range getGachaMasters() {
		if gm.ID == 37 && h.use37() && gm.StartAt <= requestAt {
			gachaInfo = gm
			break
		}
		if fmt.Sprintf("%d", gm.ID) == gachaID && gm.StartAt <= requestAt && gm.EndAt >= requestAt {
			gachaInfo = gm
			break
		}
	}
	if gachaInfo == nil {
		return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha"))
	}

	// gachaItemMasterからアイテムリスト取得
	gachaItemList := make([]*GachaItemMaster, 0)
	for _, gim := range getGachaItemMasters() {
		if gim.GachaID == gachaInfo.ID {
			gachaItemList = append(gachaItemList, gim)
		}
	}
	sort.Slice(gachaItemList, func(i, j int) bool {
		return gachaItemList[i].ID < gachaItemList[j].ID
	})
	if len(gachaItemList) == 0 {
		return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found gacha item"))
	}

	// weightの合計値を算出
	var sum int64
	for _, gim := range gachaItemList {
		sum += int64(gim.Weight)
	}

	// random値の導出 & 抽選
	result := make([]*GachaItemMaster, 0, gachaCount)
	for i := 0; i < int(gachaCount); i++ {
		random := rand.Int63n(sum)
		boundary := 0
		for _, v := range gachaItemList {
			boundary += v.Weight
			if random < int64(boundary) {
				result = append(result, v)
				break
			}
		}
	}

	tx, err := h.getUserDB(userID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// 直付与 => プレゼントに入れる
	presents := make([]*UserPresent, 0, gachaCount)
	for _, v := range result {
		pID, err := h.generateID()
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		present := &UserPresent{
			ID:             pID,
			UserID:         userID,
			SentAt:         requestAt,
			ItemType:       v.ItemType,
			ItemID:         v.ItemID,
			Amount:         v.Amount,
			PresentMessage: fmt.Sprintf("%sの付与アイテムです", gachaInfo.Name),
			CreatedAt:      requestAt,
			UpdatedAt:      requestAt,
		}
		presents = append(presents, present)
	}

	query = "INSERT INTO user_presents(id, user_id, sent_at, item_type, item_id, amount, present_message, created_at, updated_at) VALUES (:id, :user_id, :sent_at, :item_type, :item_id, :amount, :present_message, :created_at, :updated_at)"
	if _, err := tx.NamedExec(query, presents); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// isuconをへらす
	query = "UPDATE users SET isu_coin=? WHERE id=?"
	totalCoin := user.IsuCoin - consumedCoin
	if _, err := tx.Exec(query, totalCoin, user.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &DrawGachaResponse{
		Presents: presents,
	})
}

type DrawGachaRequest struct {
	ViewerID     string `json:"viewerId"`
	OneTimeToken string `json:"oneTimeToken"`
}

type DrawGachaResponse struct {
	Presents []*UserPresent `json:"presents"`
}

// listPresent プレゼント一覧
// GET /user/{userID}/present/index/{n}
func (h *Handler) listPresent(c echo.Context) error {
	n, err := strconv.Atoi(c.Param("n"))
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid index number (n) parameter"))
	}
	if n == 0 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("index number (n) should be more than or equal to 1"))
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid userID parameter"))
	}

	offset := PresentCountPerPage * (n - 1)
	presentList := []*UserPresent{}
	query := `
	SELECT * FROM user_presents 
	WHERE user_id = ? AND deleted_at IS NULL
	ORDER BY created_at DESC, id
	LIMIT ? OFFSET ?`
	if err = h.getUserDB(userID).Select(&presentList, query, userID, PresentCountPerPage, offset); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	var presentCount int
	if err = h.getUserDB(userID).Get(&presentCount, "SELECT COUNT(*) FROM user_presents WHERE user_id = ? AND deleted_at IS NULL", userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	isNext := false
	if presentCount > (offset + PresentCountPerPage) {
		isNext = true
	}

	return successResponse(c, &ListPresentResponse{
		Presents: presentList,
		IsNext:   isNext,
	})
}

type ListPresentResponse struct {
	Presents []*UserPresent `json:"presents"`
	IsNext   bool           `json:"isNext"`
}

// receivePresent プレゼント受け取り
// POST /user/{userID}/present/receive
func (h *Handler) receivePresent(c echo.Context) error {
	// read body
	defer c.Request().Body.Close()
	req := new(ReceivePresentRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if len(req.PresentIDs) == 0 {
		return errorResponse(c, http.StatusUnprocessableEntity, fmt.Errorf("presentIds is empty"))
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// user_presentsに入っているが未取得のプレゼント取得
	query := "SELECT * FROM user_presents WHERE id IN (?) AND deleted_at IS NULL"
	query, params, err := sqlx.In(query, req.PresentIDs)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	obtainPresent := []*UserPresent{}
	if err = h.getUserDB(userID).Select(&obtainPresent, query, params...); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if len(obtainPresent) == 0 {
		return successResponse(c, &ReceivePresentResponse{
			UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, nil, nil, nil, []*UserPresent{}),
		})
	}

	tx, err := h.getUserDB(userID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

	// 配布処理
	presents := make([]*UserPresent, 0, len(obtainPresent))
	for i := range obtainPresent {
		if obtainPresent[i].DeletedAt != nil {
			return errorResponse(c, http.StatusInternalServerError, fmt.Errorf("received present"))
		}

		obtainPresent[i].UpdatedAt = requestAt
		obtainPresent[i].DeletedAt = &requestAt
		presents = append(presents, obtainPresent[i])
	}

	presentIDs := make([]int64, 0, len(presents))
	for _, p := range presents {
		presentIDs = append(presentIDs, p.ID)
	}
	bulkUpdateQuery, params, err := sqlx.In("UPDATE user_presents SET deleted_at = ?, updated_at = ? WHERE id in (?)", requestAt, requestAt, presentIDs)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if _, err := tx.Exec(bulkUpdateQuery, params...); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	user := new(User)
	if err := tx.Get(user, "SELECT * FROM users WHERE id=?", userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if err := h.obtainItems(tx, user, requestAt, presents); err != nil {
		if err == ErrUserNotFound || err == ErrItemNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		if err == ErrInvalidItemType {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &ReceivePresentResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, nil, nil, nil, obtainPresent),
	})
}

type ReceivePresentRequest struct {
	ViewerID   string  `json:"viewerId"`
	PresentIDs []int64 `json:"presentIds"`
}

type ReceivePresentResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// listItem アイテムリスト
// GET /user/{userID}/item
func (h *Handler) listItem(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err = h.getUserDB(userID).Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	itemList := []*UserItem{}
	query = "SELECT * FROM user_items WHERE user_id = ?"
	if err = h.getUserDB(userID).Select(&itemList, query, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	cardList := make([]*UserCard, 0)
	query = "SELECT * FROM user_cards WHERE user_id=?"
	if err = h.getUserDB(userID).Select(&cardList, query, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// genearte one time token
	query = "UPDATE user_one_time_tokens SET deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = h.getUserDB(userID).Exec(query, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	tk, err := generateUUID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	token := &UserOneTimeToken{
		ID:        tID,
		UserID:    userID,
		Token:     tk,
		TokenType: 2,
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
		ExpiredAt: requestAt + 600,
	}
	query = "INSERT INTO user_one_time_tokens(id, user_id, token, token_type, created_at, updated_at, expired_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err = h.getUserDB(userID).Exec(query, token.ID, token.UserID, token.Token, token.TokenType, token.CreatedAt, token.UpdatedAt, token.ExpiredAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &ListItemResponse{
		OneTimeToken: token.Token,
		Items:        itemList,
		User:         user,
		Cards:        cardList,
	})
}

type ListItemResponse struct {
	OneTimeToken string      `json:"oneTimeToken"`
	User         *User       `json:"user"`
	Items        []*UserItem `json:"items"`
	Cards        []*UserCard `json:"cards"`
}

// addExpToCard 装備強化
// POST /user/{userID}/card/addexp/{cardID}
func (h *Handler) addExpToCard(c echo.Context) error {
	cardID, err := strconv.ParseInt(c.Param("cardID"), 10, 64)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// read body
	defer c.Request().Body.Close()
	req := new(AddExpToCardRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkOneTimeToken(userID, req.OneTimeToken, 2, requestAt); err != nil {
		if err == ErrInvalidToken {
			return errorResponse(c, http.StatusBadRequest, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// get target card
	allItemMasters := getItemMasters()
	card := new(TargetUserCardData)
	query := `
	SELECT uc.id , uc.user_id , uc.card_id , uc.amount_per_sec , uc.level, uc.total_exp
	FROM user_cards as uc
	WHERE uc.id = ? AND uc.user_id=?
	`
	if err = h.getUserDB(userID).Get(card, query, cardID, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	for _, im := range allItemMasters {
		if card.CardID == im.ID {
			card.BaseAmountPerSec = *im.AmountPerSec
			card.MaxLevel = *im.MaxLevel
			card.MaxAmountPerSec = *im.MaxAmountPerSec
			card.BaseExpPerLevel = *im.BaseExpPerLevel
			break
		}
	}

	if card.Level == card.MaxLevel {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("target card is max level"))
	}

	// 消費アイテムの所持チェック
	items := make([]*ConsumeUserItemData, 0)
	query = `
	SELECT ui.id, ui.user_id, ui.item_id, ui.item_type, ui.amount, ui.created_at, ui.updated_at
	FROM user_items as ui
	WHERE ui.item_type = 3 AND ui.id=? AND ui.user_id=?
	`
	for _, v := range req.Items {
		item := new(ConsumeUserItemData)
		if err = h.getUserDB(userID).Get(item, query, v.ID, userID); err != nil {
			if err == sql.ErrNoRows {
				return errorResponse(c, http.StatusNotFound, err)
			}
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		for _, im := range allItemMasters {
			if item.ItemID == im.ID {
				item.GainedExp = *im.GainedExp
				break
			}
		}

		if v.Amount > item.Amount {
			return errorResponse(c, http.StatusBadRequest, fmt.Errorf("item not enough"))
		}
		item.ConsumeAmount = v.Amount
		items = append(items, item)
	}

	// 経験値付与
	// 経験値をカードに付与
	for _, v := range items {
		card.TotalExp += v.GainedExp * v.ConsumeAmount
	}

	// lvup判定(lv upしたら生産性を加算)
	for {
		nextLvThreshold := int(float64(card.BaseExpPerLevel) * math.Pow(1.2, float64(card.Level-1)))
		if nextLvThreshold > card.TotalExp {
			break
		}

		// lv up処理
		card.Level += 1
		card.AmountPerSec += (card.MaxAmountPerSec - card.BaseAmountPerSec) / (card.MaxLevel - 1)
	}

	tx, err := h.getUserDB(userID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	defer tx.Rollback() //nolint:errcheck

	// cardのlvと経験値の更新、itemの消費
	query = "UPDATE user_cards SET amount_per_sec=?, level=?, total_exp=?, updated_at=? WHERE id=?"
	if _, err = tx.Exec(query, card.AmountPerSec, card.Level, card.TotalExp, requestAt, card.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	query = "UPDATE user_items SET amount=?, updated_at=? WHERE id=?"
	for _, v := range items {
		if _, err = tx.Exec(query, v.Amount-v.ConsumeAmount, requestAt, v.ID); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}

	// get response data
	resultCard := new(UserCard)
	query = "SELECT * FROM user_cards WHERE id=?"
	if err = tx.Get(resultCard, query, card.ID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found card"))
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	resultItems := make([]*UserItem, 0)
	for _, v := range items {
		resultItems = append(resultItems, &UserItem{
			ID:        v.ID,
			UserID:    v.UserID,
			ItemID:    v.ItemID,
			ItemType:  v.ItemType,
			Amount:    v.Amount - v.ConsumeAmount,
			CreatedAt: v.CreatedAt,
			UpdatedAt: requestAt,
		})
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &AddExpToCardResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, []*UserCard{resultCard}, nil, resultItems, nil, nil),
	})
}

type AddExpToCardRequest struct {
	ViewerID     string         `json:"viewerId"`
	OneTimeToken string         `json:"oneTimeToken"`
	Items        []*ConsumeItem `json:"items"`
}

type AddExpToCardResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

type ConsumeItem struct {
	ID     int64 `json:"id"`
	Amount int   `json:"amount"`
}

type ConsumeUserItemData struct {
	ID        int64 `db:"id"`
	UserID    int64 `db:"user_id"`
	ItemID    int64 `db:"item_id"`
	ItemType  int   `db:"item_type"`
	Amount    int   `db:"amount"`
	CreatedAt int64 `db:"created_at"`
	UpdatedAt int64 `db:"updated_at"`
	GainedExp int   `db:"gained_exp"`

	ConsumeAmount int // 消費量
}

type TargetUserCardData struct {
	ID           int64 `db:"id"`
	UserID       int64 `db:"user_id"`
	CardID       int64 `db:"card_id"`
	AmountPerSec int   `db:"amount_per_sec"`
	Level        int   `db:"level"`
	TotalExp     int   `db:"total_exp"`

	// lv1のときの生産性
	BaseAmountPerSec int `db:"base_amount_per_sec"`
	// 最高レベル
	MaxLevel int `db:"max_level"`
	// lv maxのときの生産性
	MaxAmountPerSec int `db:"max_amount_per_sec"`
	// lv1 -> lv2に上がるときのexp
	BaseExpPerLevel int `db:"base_exp_per_level"`
}

// updateDeck 装備変更
// POST /user/{userID}/card
func (h *Handler) updateDeck(c echo.Context) error {

	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// read body
	defer c.Request().Body.Close()
	req := new(UpdateDeckRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	if len(req.CardIDs) != DeckCardNumber {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid number of cards"))
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// カード所持情報のバリデーション
	query := "SELECT * FROM user_cards WHERE id IN (?)"
	query, params, err := sqlx.In(query, req.CardIDs)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}
	cards := make([]*UserCard, 0)
	if err = h.getUserDB(userID).Select(&cards, query, params...); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if len(cards) != DeckCardNumber {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid card ids"))
	}

	tx, err := h.getUserDB(userID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	defer tx.Rollback() //nolint:errcheck

	// update data
	query = "UPDATE user_decks SET updated_at=?, deleted_at=? WHERE user_id=? AND deleted_at IS NULL"
	if _, err = tx.Exec(query, requestAt, requestAt, userID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	udID, err := h.generateID()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	newDeck := &UserDeck{
		ID:        udID,
		UserID:    userID,
		CardID1:   req.CardIDs[0],
		CardID2:   req.CardIDs[1],
		CardID3:   req.CardIDs[2],
		CreatedAt: requestAt,
		UpdatedAt: requestAt,
	}
	query = "INSERT INTO user_decks(id, user_id, user_card_id_1, user_card_id_2, user_card_id_3, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)"
	if _, err := tx.Exec(query, newDeck.ID, newDeck.UserID, newDeck.CardID1, newDeck.CardID2, newDeck.CardID3, newDeck.CreatedAt, newDeck.UpdatedAt); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	err = tx.Commit()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &UpdateDeckResponse{
		UpdatedResources: makeUpdatedResources(requestAt, nil, nil, nil, []*UserDeck{newDeck}, nil, nil, nil),
	})
}

type UpdateDeckRequest struct {
	ViewerID string  `json:"viewerId"`
	CardIDs  []int64 `json:"cardIds"`
}

type UpdateDeckResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// reward ゲーム報酬受取
// POST /user/{userID}/reward
func (h *Handler) reward(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	// parse body
	defer c.Request().Body.Close()
	req := new(RewardRequest)
	if err := parseRequestBody(c, req); err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	if err = h.checkViewerID(userID, req.ViewerID); err != nil {
		if err == ErrUserDeviceNotFound {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 最後に取得した報酬時刻取得
	user := new(User)
	query := "SELECT * FROM users WHERE id=?"
	if err = h.getUserDB(userID).Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// 使っているデッキの取得
	deck := new(UserDeck)
	query = "SELECT * FROM user_decks WHERE user_id=? AND deleted_at IS NULL"
	if err = h.getUserDB(userID).Get(deck, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, err)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	cards := make([]*UserCard, 0)
	query = "SELECT * FROM user_cards WHERE id IN (?, ?, ?)"
	if err = h.getUserDB(userID).Select(&cards, query, deck.CardID1, deck.CardID2, deck.CardID3); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	if len(cards) != 3 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid cards length"))
	}

	// 経過時間*生産性のcoin (1椅子 = 1coin)
	pastTime := requestAt - user.LastGetRewardAt
	getCoin := int(pastTime) * (cards[0].AmountPerSec + cards[1].AmountPerSec + cards[2].AmountPerSec)

	// 報酬の保存(ゲームない通貨を保存)(users)
	user.IsuCoin += int64(getCoin)
	user.LastGetRewardAt = requestAt

	query = "UPDATE users SET isu_coin=?, last_getreward_at=? WHERE id=?"
	if _, err = h.getUserDB(userID).Exec(query, user.IsuCoin, user.LastGetRewardAt, user.ID); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	return successResponse(c, &RewardResponse{
		UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, nil, nil),
	})
}

type RewardRequest struct {
	ViewerID string `json:"viewerId"`
}

type RewardResponse struct {
	UpdatedResources *UpdatedResource `json:"updatedResources"`
}

// home ホーム取得
// GET /user/{userID}/home
func (h *Handler) home(c echo.Context) error {
	userID, err := getUserID(c)
	if err != nil {
		return errorResponse(c, http.StatusBadRequest, err)
	}

	requestAt, err := getRequestTime(c)
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, ErrGetRequestTime)
	}

	// 装備情報
	deck := new(UserDeck)
	query := "SELECT * FROM user_decks WHERE user_id=? AND deleted_at IS NULL"
	if err = h.getUserDB(userID).Get(deck, query, userID); err != nil {
		if err != sql.ErrNoRows {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		deck = nil
	}

	// 生産性
	cards := make([]*UserCard, 0)
	if deck != nil {
		cardIds := []int64{deck.CardID1, deck.CardID2, deck.CardID3}
		query, params, err := sqlx.In("SELECT * FROM user_cards WHERE id IN (?)", cardIds)
		if err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
		if err = h.getUserDB(userID).Select(&cards, query, params...); err != nil {
			return errorResponse(c, http.StatusInternalServerError, err)
		}
	}
	totalAmountPerSec := 0
	for _, v := range cards {
		totalAmountPerSec += v.AmountPerSec
	}

	// 経過時間
	user := new(User)
	query = "SELECT * FROM users WHERE id=?"
	if err = h.getUserDB(userID).Get(user, query, userID); err != nil {
		if err == sql.ErrNoRows {
			return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
		}
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	pastTime := requestAt - user.LastGetRewardAt

	return successResponse(c, &HomeResponse{
		Now:               requestAt,
		User:              user,
		Deck:              deck,
		TotalAmountPerSec: totalAmountPerSec,
		PastTime:          pastTime,
	})
}

type HomeResponse struct {
	Now               int64     `json:"now"`
	User              *User     `json:"user"`
	Deck              *UserDeck `json:"deck,omitempty"`
	TotalAmountPerSec int       `json:"totalAmountPerSec"`
	PastTime          int64     `json:"pastTime"` // 経過時間を秒単位で
}

// //////////////////////////////////////
// util

// health ヘルスチェック
func (h *Handler) health(c echo.Context) error {
	return c.String(http.StatusOK, "OK")
}

// errorResponse returns error.
func errorResponse(c echo.Context, statusCode int, err error) error {
	c.Logger().Errorf("status=%d, err=%+v", statusCode, errors.WithStack(err))

	return c.JSON(statusCode, struct {
		StatusCode int    `json:"status_code"`
		Message    string `json:"message"`
	}{
		StatusCode: statusCode,
		Message:    err.Error(),
	})
}

// successResponse responds success.
func successResponse(c echo.Context, v interface{}) error {
	return c.JSON(http.StatusOK, v)
}

// noContentResponse
func noContentResponse(c echo.Context, status int) error {
	return c.NoContent(status)
}

// generateID uniqueなIDを生成する
func (h *Handler) generateID() (int64, error) {
	return rand.Int63(), nil
}

// generateSessionID
func generateUUID() (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}

	return id.String(), nil
}

// getUserID gets userID by path param.
func getUserID(c echo.Context) (int64, error) {
	return strconv.ParseInt(c.Param("userID"), 10, 64)
}

// getEnv gets environment variable.
func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v == "" {
		return defaultVal
	} else {
		return v
	}
}

// parseRequestBody parses request body.
func parseRequestBody(c echo.Context, dist interface{}) error {
	buf, err := io.ReadAll(c.Request().Body)
	if err != nil {
		return ErrInvalidRequestBody
	}
	if err = json.Unmarshal(buf, &dist); err != nil {
		return ErrInvalidRequestBody
	}
	return nil
}

type UpdatedResource struct {
	Now  int64 `json:"now"`
	User *User `json:"user,omitempty"`

	UserDevice       *UserDevice       `json:"userDevice,omitempty"`
	UserCards        []*UserCard       `json:"userCards,omitempty"`
	UserDecks        []*UserDeck       `json:"userDecks,omitempty"`
	UserItems        []*UserItem       `json:"userItems,omitempty"`
	UserLoginBonuses []*UserLoginBonus `json:"userLoginBonuses,omitempty"`
	UserPresents     []*UserPresent    `json:"userPresents,omitempty"`
}

func makeUpdatedResources(
	requestAt int64,
	user *User,
	userDevice *UserDevice,
	userCards []*UserCard,
	userDecks []*UserDeck,
	userItems []*UserItem,
	userLoginBonuses []*UserLoginBonus,
	userPresents []*UserPresent,
) *UpdatedResource {
	return &UpdatedResource{
		Now:              requestAt,
		User:             user,
		UserDevice:       userDevice,
		UserCards:        userCards,
		UserItems:        userItems,
		UserDecks:        userDecks,
		UserLoginBonuses: userLoginBonuses,
		UserPresents:     userPresents,
	}
}

// //////////////////////////////////////
// entity

type User struct {
	ID              int64  `json:"id" db:"id"`
	IsuCoin         int64  `json:"isuCoin" db:"isu_coin"`
	LastGetRewardAt int64  `json:"lastGetRewardAt" db:"last_getreward_at"`
	LastActivatedAt int64  `json:"lastActivatedAt" db:"last_activated_at"`
	RegisteredAt    int64  `json:"registeredAt" db:"registered_at"`
	CreatedAt       int64  `json:"createdAt" db:"created_at"`
	UpdatedAt       int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt       *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserDevice struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	PlatformID   string `json:"platformId" db:"platform_id"`
	PlatformType int    `json:"platformType" db:"platform_type"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserBan struct {
	ID        int64  `db:"id"`
	UserID    int64  `db:"user_id"`
	CreatedAt int64  `db:"created_at"`
	UpdatedAt int64  `db:"updated_at"`
	DeletedAt *int64 `db:"deleted_at"`
}

type UserCard struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	CardID       int64  `json:"cardId" db:"card_id"`
	AmountPerSec int    `json:"amountPerSec" db:"amount_per_sec"`
	Level        int    `json:"level" db:"level"`
	TotalExp     int64  `json:"totalExp" db:"total_exp"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserDeck struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	CardID1   int64  `json:"cardId1" db:"user_card_id_1"`
	CardID2   int64  `json:"cardId2" db:"user_card_id_2"`
	CardID3   int64  `json:"cardId3" db:"user_card_id_3"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserItem struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	ItemType  int    `json:"itemType" db:"item_type"`
	ItemID    int64  `json:"itemId" db:"item_id"`
	Amount    int    `json:"amount" db:"amount"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserLoginBonus struct {
	ID                 int64  `json:"id" db:"id"`
	UserID             int64  `json:"userId" db:"user_id"`
	LoginBonusID       int64  `json:"loginBonusId" db:"login_bonus_id"`
	LastRewardSequence int    `json:"lastRewardSequence" db:"last_reward_sequence"`
	LoopCount          int    `json:"loopCount" db:"loop_count"`
	CreatedAt          int64  `json:"createdAt" db:"created_at"`
	UpdatedAt          int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt          *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserPresent struct {
	ID             int64  `json:"id" db:"id"`
	UserID         int64  `json:"userId" db:"user_id"`
	SentAt         int64  `json:"sentAt" db:"sent_at"`
	ItemType       int    `json:"itemType" db:"item_type"`
	ItemID         int64  `json:"itemId" db:"item_id"`
	Amount         int    `json:"amount" db:"amount"`
	PresentMessage string `json:"presentMessage" db:"present_message"`
	CreatedAt      int64  `json:"createdAt" db:"created_at"`
	UpdatedAt      int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt      *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserPresentAllReceivedHistory struct {
	ID           int64  `json:"id" db:"id"`
	UserID       int64  `json:"userId" db:"user_id"`
	PresentAllID int64  `json:"presentAllId" db:"present_all_id"`
	ReceivedAt   int64  `json:"receivedAt" db:"received_at"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
	UpdatedAt    int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt    *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type Session struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	SessionID string `json:"sessionId" db:"session_id"`
	ExpiredAt int64  `json:"expiredAt" db:"expired_at"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

type UserOneTimeToken struct {
	ID        int64  `json:"id" db:"id"`
	UserID    int64  `json:"userId" db:"user_id"`
	Token     string `json:"token" db:"token"`
	TokenType int    `json:"tokenType" db:"token_type"`
	ExpiredAt int64  `json:"expiredAt" db:"expired_at"`
	CreatedAt int64  `json:"createdAt" db:"created_at"`
	UpdatedAt int64  `json:"updatedAt" db:"updated_at"`
	DeletedAt *int64 `json:"deletedAt,omitempty" db:"deleted_at"`
}

// //////////////////////////////////////
// master

type GachaMaster struct {
	ID           int64  `json:"id" db:"id"`
	Name         string `json:"name" db:"name"`
	StartAt      int64  `json:"startAt" db:"start_at"`
	EndAt        int64  `json:"endAt" db:"end_at"`
	DisplayOrder int    `json:"displayOrder" db:"display_order"`
	CreatedAt    int64  `json:"createdAt" db:"created_at"`
}

type GachaItemMaster struct {
	ID        int64 `json:"id" db:"id"`
	GachaID   int64 `json:"gachaId" db:"gacha_id"`
	ItemType  int   `json:"itemType" db:"item_type"`
	ItemID    int64 `json:"itemId" db:"item_id"`
	Amount    int   `json:"amount" db:"amount"`
	Weight    int   `json:"weight" db:"weight"`
	CreatedAt int64 `json:"createdAt" db:"created_at"`
}

type ItemMaster struct {
	ID              int64  `json:"id" db:"id"`
	ItemType        int    `json:"itemType" db:"item_type"`
	Name            string `json:"name" db:"name"`
	Description     string `json:"description" db:"description"`
	AmountPerSec    *int   `json:"amountPerSec" db:"amount_per_sec"`
	MaxLevel        *int   `json:"maxLevel" db:"max_level"`
	MaxAmountPerSec *int   `json:"maxAmountPerSec" db:"max_amount_per_sec"`
	BaseExpPerLevel *int   `json:"baseExpPerLevel" db:"base_exp_per_level"`
	GainedExp       *int   `json:"gainedExp" db:"gained_exp"`
	ShorteningMin   *int64 `json:"shorteningMin" db:"shortening_min"`
	// CreatedAt       int64 `json:"createdAt"`
}

type LoginBonusMaster struct {
	ID          int64 `json:"id" db:"id"`
	StartAt     int64 `json:"startAt" db:"start_at"`
	EndAt       int64 `json:"endAt" db:"end_at"`
	ColumnCount int   `json:"columnCount" db:"column_count"`
	Looped      bool  `json:"looped" db:"looped"`
	CreatedAt   int64 `json:"createdAt" db:"created_at"`
}

type LoginBonusRewardMaster struct {
	ID             int64 `json:"id" db:"id"`
	LoginBonusID   int64 `json:"loginBonusId" db:"login_bonus_id"`
	RewardSequence int   `json:"rewardSequence" db:"reward_sequence"`
	ItemType       int   `json:"itemType" db:"item_type"`
	ItemID         int64 `json:"itemId" db:"item_id"`
	Amount         int64 `json:"amount" db:"amount"`
	CreatedAt      int64 `json:"createdAt" db:"created_at"`
}

type PresentAllMaster struct {
	ID                int64  `json:"id" db:"id"`
	RegisteredStartAt int64  `json:"registeredStartAt" db:"registered_start_at"`
	RegisteredEndAt   int64  `json:"registeredEndAt" db:"registered_end_at"`
	ItemType          int    `json:"itemType" db:"item_type"`
	ItemID            int64  `json:"itemId" db:"item_id"`
	Amount            int64  `json:"amount" db:"amount"`
	PresentMessage    string `json:"presentMessage" db:"present_message"`
	CreatedAt         int64  `json:"createdAt" db:"created_at"`
}

type VersionMaster struct {
	ID            int64  `json:"id" db:"id"`
	Status        int    `json:"status" db:"status"`
	MasterVersion string `json:"masterVersion" db:"master_version"`
}

// Cache
var (
	sessionIDCacheByUserID  map[int64]string
	sessionCacheBySessionID map[string]*Session
	muSessionCache          sync.RWMutex

	bansByUserID map[int64]struct{}
	muBans       sync.RWMutex

	masterVersions   []*VersionMaster
	muMasterVersions sync.RWMutex

	itemMasters   []*ItemMaster
	muItemMasters sync.RWMutex

	gachaMasters   []*GachaMaster
	muGachaMasters sync.RWMutex

	gachaItemMasters   []*GachaItemMaster
	muGachaItemMasters sync.RWMutex

	presentAllMasters   []*PresentAllMaster
	muPresentAllMasters sync.RWMutex

	loginBonusMasters   []*LoginBonusMaster
	muLoginBonusMasters sync.RWMutex

	loginBonusRewardMasters   []*LoginBonusRewardMaster
	muLoginBonusRewardMasters sync.RWMutex
)

func resetCache(db *sqlx.DB) error {
	muSessionCache.Lock()
	defer muSessionCache.Unlock()
	sessionIDCacheByUserID = make(map[int64]string, 10000)
	sessionCacheBySessionID = make(map[string]*Session, 10000)

	muBans.Lock()
	defer muBans.Unlock()
	var allBans []*UserBan
	if err := db.Select(&allBans, "SELECT * FROM user_bans"); err != nil {
		return err
	}
	bansByUserID = make(map[int64]struct{}, len(allBans))
	for _, ub := range allBans {
		bansByUserID[ub.UserID] = struct{}{}
	}

	muMasterVersions.Lock()
	defer muMasterVersions.Unlock()
	var allMasterVersions []*VersionMaster
	if err := db.Select(&allMasterVersions, "SELECT * FROM version_masters"); err != nil {
		return err
	}
	masterVersions = allMasterVersions

	muItemMasters.Lock()
	defer muItemMasters.Unlock()
	var allItemMasters []*ItemMaster
	if err := db.Select(&allItemMasters, "SELECT * FROM item_masters"); err != nil {
		return err
	}
	itemMasters = allItemMasters

	muGachaMasters.Lock()
	defer muGachaMasters.Unlock()
	var allGachaMasters []*GachaMaster
	if err := db.Select(&allGachaMasters, "SELECT * FROM gacha_masters"); err != nil {
		return err
	}
	gachaMasters = allGachaMasters

	muGachaItemMasters.Lock()
	defer muGachaItemMasters.Unlock()
	var allGachaItemMasters []*GachaItemMaster
	if err := db.Select(&allGachaItemMasters, "SELECT * FROM gacha_item_masters"); err != nil {
		return err
	}
	gachaItemMasters = allGachaItemMasters

	muPresentAllMasters.Lock()
	defer muPresentAllMasters.Unlock()
	var allPresentAllMasters []*PresentAllMaster
	if err := db.Select(&allPresentAllMasters, "SELECT * FROM present_all_masters"); err != nil {
		return err
	}
	presentAllMasters = allPresentAllMasters

	muLoginBonusMasters.Lock()
	defer muLoginBonusMasters.Unlock()
	var allLoginBonusMasters []*LoginBonusMaster
	if err := db.Select(&allLoginBonusMasters, "SELECT * FROM login_bonus_masters"); err != nil {
		return err
	}
	loginBonusMasters = allLoginBonusMasters

	muLoginBonusRewardMasters.Lock()
	defer muLoginBonusRewardMasters.Unlock()
	var allLoginBonusRewardMasters []*LoginBonusRewardMaster
	if err := db.Select(&allLoginBonusRewardMasters, "SELECT * FROM login_bonus_reward_masters"); err != nil {
		return err
	}
	loginBonusRewardMasters = allLoginBonusRewardMasters

	return nil
}

func getUserSessionBySessionID(sessID string) (*Session, bool) {
	muSessionCache.RLock()
	defer muSessionCache.RUnlock()
	sess, ok := sessionCacheBySessionID[sessID]
	if !ok {
		return nil, false
	}
	if sess == nil {
		return nil, false
	}
	return sess, true
}

func updateUserSession(sess *Session) {
	muSessionCache.Lock()
	defer muSessionCache.Unlock()
	if oldSessionID, ok := sessionIDCacheByUserID[sess.UserID]; ok {
		delete(sessionCacheBySessionID, oldSessionID)
	}
	sessionIDCacheByUserID[sess.UserID] = sess.SessionID
	sessionCacheBySessionID[sess.SessionID] = sess
}

func clearUserSession(sess *Session) {
	muSessionCache.Lock()
	defer muSessionCache.Unlock()
	delete(sessionIDCacheByUserID, sess.UserID)
	delete(sessionCacheBySessionID, sess.SessionID)
}

func isBannedUser(userID int64) bool {
	muBans.RLock()
	defer muBans.RUnlock()
	_, ok := bansByUserID[userID]
	return ok
}

func cacheUserBan(userID int64) {
	muBans.Lock()
	defer muBans.Unlock()
	bansByUserID[userID] = struct{}{}
}

func getMasterVersions() []*VersionMaster {
	muMasterVersions.RLock()
	defer muMasterVersions.RUnlock()
	return masterVersions
}

func cacheMasterVersions(masters []*VersionMaster) {
	muMasterVersions.Lock()
	defer muMasterVersions.Unlock()
	masterByID := make(map[int64]*VersionMaster, len(masterVersions)+len(masters))
	for _, mv := range masterVersions {
		masterByID[mv.ID] = mv
	}
	for _, mv := range masters {
		masterByID[mv.ID] = mv
	}
	masterVersions = make([]*VersionMaster, 0, len(masterByID))
	for _, mv := range masterByID {
		masterVersions = append(masterVersions, mv)
	}
}

func getItemMasters() []*ItemMaster {
	muItemMasters.RLock()
	defer muItemMasters.RUnlock()
	return itemMasters
}

func cacheItemMasters(masters []*ItemMaster) {
	muItemMasters.Lock()
	defer muItemMasters.Unlock()
	itemMap := make(map[int64]*ItemMaster, len(itemMasters)+len(masters))
	for _, item := range itemMasters {
		itemMap[item.ID] = item
	}
	for _, item := range masters {
		itemMap[item.ID] = item
	}
	itemMasters = make([]*ItemMaster, 0, len(itemMap))
	for _, item := range itemMap {
		itemMasters = append(itemMasters, item)
	}
}

func getGachaMasters() []*GachaMaster {
	muGachaMasters.RLock()
	defer muGachaMasters.RUnlock()
	return gachaMasters
}

func cacheGachaMasters(masters []*GachaMaster) {
	muGachaMasters.Lock()
	defer muGachaMasters.Unlock()
	gachaMap := make(map[int64]*GachaMaster, len(gachaMasters)+len(masters))
	for _, gacha := range gachaMasters {
		gachaMap[gacha.ID] = gacha
	}
	for _, gacha := range masters {
		gachaMap[gacha.ID] = gacha
	}
	gachaMasters = make([]*GachaMaster, 0, len(gachaMap))
	for _, gacha := range gachaMap {
		gachaMasters = append(gachaMasters, gacha)
	}
}

func getGachaItemMasters() []*GachaItemMaster {
	muGachaItemMasters.RLock()
	defer muGachaItemMasters.RUnlock()
	return gachaItemMasters
}

func cacheGachaItemMasters(masters []*GachaItemMaster) {
	muGachaItemMasters.Lock()
	defer muGachaItemMasters.Unlock()
	gachaItemMap := make(map[string]*GachaItemMaster, len(gachaItemMasters)+len(masters))
	for _, gi := range gachaItemMasters {
		gachaItemMap[fmt.Sprintf("%d-%d-%d", gi.GachaID, gi.ItemType, gi.ItemID)] = gi
	}
	for _, gi := range masters {
		gachaItemMap[fmt.Sprintf("%d-%d-%d", gi.GachaID, gi.ItemType, gi.ItemID)] = gi
	}
	gachaItemMasters = make([]*GachaItemMaster, 0, len(gachaItemMap))
	for _, gi := range gachaItemMap {
		gachaItemMasters = append(gachaItemMasters, gi)
	}
}

func getPresentAllMasters() []*PresentAllMaster {
	muPresentAllMasters.RLock()
	defer muPresentAllMasters.RUnlock()
	return presentAllMasters
}

func cachePresentAllMasters(masters []*PresentAllMaster) {
	muPresentAllMasters.Lock()
	defer muPresentAllMasters.Unlock()
	presentMap := make(map[int64]*PresentAllMaster, len(presentAllMasters)+len(masters))
	for _, p := range presentAllMasters {
		presentMap[p.ID] = p
	}
	for _, p := range masters {
		presentMap[p.ID] = p
	}
	presentAllMasters = make([]*PresentAllMaster, 0, len(presentMap))
	for _, p := range presentMap {
		presentAllMasters = append(presentAllMasters, p)
	}
}

func getLoginBonusMasters() []*LoginBonusMaster {
	muLoginBonusMasters.RLock()
	defer muLoginBonusMasters.RUnlock()
	return loginBonusMasters
}

func cacheLoginBonusMasters(masters []*LoginBonusMaster) {
	muLoginBonusMasters.Lock()
	defer muLoginBonusMasters.Unlock()
	loginBonusMap := make(map[int64]*LoginBonusMaster, len(loginBonusMasters)+len(masters))
	for _, lb := range loginBonusMasters {
		loginBonusMap[lb.ID] = lb
	}
	for _, lb := range masters {
		loginBonusMap[lb.ID] = lb
	}
	loginBonusMasters = make([]*LoginBonusMaster, 0, len(loginBonusMap))
	for _, lb := range loginBonusMap {
		loginBonusMasters = append(loginBonusMasters, lb)
	}
}

func getLoginBonusRewardMasters() []*LoginBonusRewardMaster {
	muLoginBonusRewardMasters.RLock()
	defer muLoginBonusRewardMasters.RUnlock()
	return loginBonusRewardMasters
}

func cacheLoginBonusRewardMasters(masters []*LoginBonusRewardMaster) {
	muLoginBonusRewardMasters.Lock()
	defer muLoginBonusRewardMasters.Unlock()
	loginBonusRewardMap := make(map[int64]*LoginBonusRewardMaster, len(loginBonusRewardMasters)+len(masters))
	for _, lbr := range loginBonusRewardMasters {
		loginBonusRewardMap[lbr.ID] = lbr
	}
	for _, lbr := range masters {
		loginBonusRewardMap[lbr.ID] = lbr
	}
	loginBonusRewardMasters = make([]*LoginBonusRewardMaster, 0, len(loginBonusRewardMap))
	for _, lbr := range loginBonusRewardMap {
		loginBonusRewardMasters = append(loginBonusRewardMasters, lbr)
	}
}
