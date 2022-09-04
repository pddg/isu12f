package main

import (
	"context"
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
		db.SetMaxIdleConns(32)
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
	oneTimeToken := getUserOneTimeToken(userID, tokenType)
	if oneTimeToken == nil {
		return ErrInvalidToken
	}

	if oneTimeToken.Token != token {
		return ErrInvalidToken
	}

	defer deleteUserOneTimeToken(userID, tokenType)

	if oneTimeToken.ExpiredAt < requestAt {
		return ErrInvalidToken
	}

	return nil
}

// checkViewerID
func (h *Handler) checkViewerID(userID int64, viewerID string) error {
	device := getUserDevice(userID, viewerID)
	if device == nil {
		return ErrUserDeviceNotFound
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
	user := getUser(userID)
	if user == nil {
		return nil, nil, nil, ErrUserNotFound
	}

	// ログインボーナス処理
	loginBonuses, err := h.obtainLoginBonus(user, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	// 全員プレゼント取得
	allPresents, err := h.obtainPresent(tx, userID, requestAt)
	if err != nil {
		return nil, nil, nil, err
	}

	// refresh user
	user = getUser(userID)
	if user == nil {
		return nil, nil, nil, ErrUserNotFound
	}

	user.UpdatedAt = requestAt
	user.LastActivatedAt = requestAt
	cacheUser(user)

	return user, loginBonuses, allPresents, nil
}

// isCompleteTodayLogin ログイン処理が終わっているか
func isCompleteTodayLogin(lastActivatedAt, requestAt time.Time) bool {
	return lastActivatedAt.Year() == requestAt.Year() &&
		lastActivatedAt.Month() == requestAt.Month() &&
		lastActivatedAt.Day() == requestAt.Day()
}

// obtainLoginBonus
func (h *Handler) obtainLoginBonus(user *User, requestAt int64) ([]*UserLoginBonus, error) {
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
	progressingLoginBonuses := batchGetUserLoginBonus(user.ID, loginBonusIDs)

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
	if err := h.obtainItems(user, requestAt, rewardItems); err != nil {
		return nil, err
	}

	if len(sendLoginBonuses) > 0 {
		updateUserLoginBonuses(user.ID, sendLoginBonuses)
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
	receivedHistories := batchGetUserPresentReceivedHistories(userID, presentAllIDs)
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
		bulkInsertUserPresentAllReceivedHistories(userID, newHistories)
	}

	return obtainPresents, nil
}

func (h *Handler) obtainItems(user *User, requestAt int64, presents []*UserPresent) error {
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
		user.IsuCoin += addCoin
		cacheUser(user)
	}

	if len(cards) > 0 {
		cacheUserCards(user.ID, cards)
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

		havingItems := batchGetUserItemsByItemIDs(user.ID, itemIDs)
		havingItemMap := make(map[int64]*UserItem, len(havingItems))
		for _, it := range havingItems {
			havingItemMap[it.ItemID] = it
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
			bulkUpsertUserItems(user.ID, items)
		}
	}

	return nil
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
	cacheUser(user)

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
	cacheUserDevice(userDevice)

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
		initCards = append(initCards, card)
	}
	cacheUserCards(user.ID, initCards)

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
	cacheNewUserDeck(initDeck)

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

	user := getUser(req.UserID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
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

		cacheUser(user)

		return successResponse(c, &LoginResponse{
			ViewerID:         req.ViewerID,
			SessionID:        sess.SessionID,
			UpdatedResources: makeUpdatedResources(requestAt, user, nil, nil, nil, nil, nil, nil),
		})
	}

	tx, err := h.getUserDB(user.ID).Beginx()
	if err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}
	defer tx.Rollback() //nolint:errcheck

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

	// generate one time token
	deleteUserOneTimeToken(userID, 1)
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
	cacheUserOneTimeToken(token)

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
	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
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

	query := "INSERT INTO user_presents(id, user_id, sent_at, item_type, item_id, amount, present_message, created_at, updated_at) VALUES (:id, :user_id, :sent_at, :item_type, :item_id, :amount, :present_message, :created_at, :updated_at)"
	if _, err := h.getUserDB(userID).NamedExec(query, presents); err != nil {
		return errorResponse(c, http.StatusInternalServerError, err)
	}

	// isuconをへらす
	user.IsuCoin -= consumedCoin
	cacheUser(user)

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

	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, err)
	}
	if err := h.obtainItems(user, requestAt, presents); err != nil {
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

	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
	}

	itemList := getAllUserItemsByUser(userID)

	cardList := getAllUserCardsByUser(userID)

	// generate one time token
	deleteUserOneTimeToken(userID, 2)
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
	cacheUserOneTimeToken(token)

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
	userCard := getUserCard(userID, cardID)
	if userCard == nil {
		return errorResponse(c, http.StatusNotFound, err)
	}
	card := &TargetUserCardData{
		ID:           userCard.ID,
		UserID:       userCard.UserID,
		CardID:       userCard.CardID,
		AmountPerSec: userCard.AmountPerSec,
		Level:        userCard.Level,
		TotalExp:     int(userCard.TotalExp),
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
	itemIDs := make([]int64, 0, len(req.Items))
	for _, item := range req.Items {
		itemIDs = append(itemIDs, item.ID)
	}
	userItems := batchGetType3UserItemsByIDs(userID, itemIDs)
	items := make([]*ConsumeUserItemData, 0, len(userItems))
	for _, ui := range userItems {
		items = append(items, &ConsumeUserItemData{
			ID:        ui.ID,
			UserID:    ui.UserID,
			ItemID:    ui.ItemID,
			ItemType:  ui.ItemType,
			Amount:    ui.Amount,
			CreatedAt: ui.CreatedAt,
			UpdatedAt: ui.UpdatedAt,
		})
	}
	itemMap := make(map[int64]*ConsumeUserItemData, len(items))
	for _, it := range items {
		itemMap[it.ID] = it
	}

	items = make([]*ConsumeUserItemData, 0, len(req.Items))
	for _, v := range req.Items {
		item, ok := itemMap[v.ID]
		if !ok {
			return errorResponse(c, http.StatusNotFound, errors.New("item not found"))
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

	// cardのlvと経験値の更新、itemの消費
	userCard.AmountPerSec = card.AmountPerSec
	userCard.Level = card.Level
	userCard.TotalExp = int64(card.TotalExp)
	userCard.UpdatedAt = requestAt
	updateUserCard(userID, userCard)

	for _, v := range items {
		updateUserItem(userID, v.ID, v.Amount-v.ConsumeAmount, requestAt)
	}

	// get response data
	resultCard := getUserCard(userID, card.ID)
	if resultCard == nil {
		return errorResponse(c, http.StatusNotFound, fmt.Errorf("not found card"))
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
	cards := batchGetUserCards(userID, req.CardIDs)
	if len(cards) != DeckCardNumber {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid card ids"))
	}

	// update data
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
	cacheNewUserDeck(newDeck)

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
	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
	}

	// 使っているデッキの取得
	deck := getUserActiveDeck(userID)
	if deck == nil {
		return errorResponse(c, http.StatusNotFound, err)
	}

	cards := batchGetUserCards(userID, []int64{deck.CardID1, deck.CardID2, deck.CardID3})
	if len(cards) != 3 {
		return errorResponse(c, http.StatusBadRequest, fmt.Errorf("invalid cards length"))
	}

	// 経過時間*生産性のcoin (1椅子 = 1coin)
	pastTime := requestAt - user.LastGetRewardAt
	getCoin := int(pastTime) * (cards[0].AmountPerSec + cards[1].AmountPerSec + cards[2].AmountPerSec)

	// 報酬の保存(ゲームない通貨を保存)(users)
	user.IsuCoin += int64(getCoin)
	user.LastGetRewardAt = requestAt

	cacheUser(user)

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
	deck := getUserActiveDeck(userID)

	// 生産性
	cards := make([]*UserCard, 0)
	if deck != nil {
		cardIds := []int64{deck.CardID1, deck.CardID2, deck.CardID3}
		cards = batchGetUserCards(userID, cardIds)
	}
	totalAmountPerSec := 0
	for _, v := range cards {
		totalAmountPerSec += v.AmountPerSec
	}

	// 経過時間
	user := getUser(userID)
	if user == nil {
		return errorResponse(c, http.StatusNotFound, ErrUserNotFound)
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
	if statusCode >= 500 {
		c.Logger().Errorf("status=%d, err=%+v", statusCode, errors.WithStack(err))
	}

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

	users   map[int64]*User
	muUsers sync.RWMutex

	userDevices   map[int64]map[string]*UserDevice
	muUserDevices sync.RWMutex

	userItems   map[int64][]*UserItem
	muUserItems sync.RWMutex

	userCards   map[int64][]*UserCard
	muUserCards sync.RWMutex

	userDecks   map[int64][]*UserDeck
	muUserDecks sync.RWMutex

	userLoginBonuses   map[int64][]*UserLoginBonus
	muUserLoginBonuses sync.RWMutex

	userPresentAllReceivedHistories   map[int64][]*UserPresentAllReceivedHistory
	muUserPresentAllReceivedHistories sync.RWMutex

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

	userGachaOneTimeTokens map[int64]*UserOneTimeToken
	userCardOneTimeTokens  map[int64]*UserOneTimeToken
	muOneTimeToken         sync.RWMutex
)

func resetCache(db *sqlx.DB) error {
	muSessionCache.Lock()
	defer muSessionCache.Unlock()
	sessionIDCacheByUserID = make(map[int64]string, 10000)
	sessionCacheBySessionID = make(map[string]*Session, 10000)

	muUsers.Lock()
	defer muUsers.Unlock()
	users = make(map[int64]*User, 50000)
	var allUsers []*User
	if err := db.Select(&allUsers, "SELECT * FROM users"); err != nil {
		return err
	}
	for _, u := range allUsers {
		users[u.ID] = u
	}

	muUserDevices.Lock()
	defer muUserDevices.Unlock()
	userDevices = make(map[int64]map[string]*UserDevice, 10000)
	var allUserDevices []*UserDevice
	if err := db.Select(&allUserDevices, "SELECT * FROM user_devices"); err != nil {
		return err
	}
	for _, ud := range allUserDevices {
		if _, ok := userDevices[ud.UserID]; !ok {
			userDevices[ud.UserID] = make(map[string]*UserDevice, 4)
		}
		userDevices[ud.UserID][ud.PlatformID] = ud
	}

	muUserItems.Lock()
	defer muUserItems.Unlock()
	userItems = make(map[int64][]*UserItem, 10000)
	var allUserItems []*UserItem
	if err := db.Select(&allUserItems, "SELECT * FROM user_items"); err != nil {
		return err
	}
	for _, ui := range allUserItems {
		if _, ok := userItems[ui.UserID]; !ok {
			userItems[ui.UserID] = make([]*UserItem, 0, 40)
		}
		userItems[ui.UserID] = append(userItems[ui.UserID], ui)
	}

	muUserCards.Lock()
	defer muUserCards.Unlock()
	userCards = make(map[int64][]*UserCard, 10000)
	var allUserCards []*UserCard
	if err := db.Select(&allUserCards, "SELECT * FROM user_cards"); err != nil {
		return err
	}
	for _, c := range allUserCards {
		if _, ok := userCards[c.UserID]; !ok {
			userCards[c.UserID] = make([]*UserCard, 0, 300)
		}
		userCards[c.UserID] = append(userCards[c.UserID], c)
	}

	muUserDecks.Lock()
	defer muUserDecks.Unlock()
	userDecks = make(map[int64][]*UserDeck, 10000)
	var allUserDecks []*UserDeck
	if err := db.Select(&allUserDecks, "SELECT * FROM user_decks"); err != nil {
		return err
	}
	for _, d := range allUserDecks {
		if cap(userDecks[d.UserID]) == 0 {
			userDecks[d.UserID] = make([]*UserDeck, 0, 4)
		}
		userDecks[d.UserID] = append(userDecks[d.UserID], d)
	}

	muUserLoginBonuses.Lock()
	defer muUserLoginBonuses.Unlock()
	userLoginBonuses = make(map[int64][]*UserLoginBonus, 10000)
	var allUserLoginBonuses []*UserLoginBonus
	if err := db.Select(&allUserLoginBonuses, "SELECT * FROM user_login_bonuses"); err != nil {
		return err
	}
	for _, lb := range allUserLoginBonuses {
		if cap(userLoginBonuses[lb.UserID]) == 0 {
			userLoginBonuses[lb.UserID] = make([]*UserLoginBonus, 0, 6)
		}
		userLoginBonuses[lb.UserID] = append(userLoginBonuses[lb.UserID], lb)
	}

	muUserPresentAllReceivedHistories.Lock()
	defer muUserPresentAllReceivedHistories.Unlock()
	userPresentAllReceivedHistories = make(map[int64][]*UserPresentAllReceivedHistory, 10000)
	var allUserPresentAllReceivedHistories []*UserPresentAllReceivedHistory
	if err := db.Select(&allUserPresentAllReceivedHistories, "SELECT * FROM user_present_all_received_history"); err != nil {
		return err
	}
	for _, h := range allUserPresentAllReceivedHistories {
		if cap(userPresentAllReceivedHistories[h.UserID]) == 0 {
			userPresentAllReceivedHistories[h.UserID] = make([]*UserPresentAllReceivedHistory, 0, 60)
		}
		userPresentAllReceivedHistories[h.UserID] = append(userPresentAllReceivedHistories[h.UserID], h)
	}

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

	muOneTimeToken.Lock()
	defer muOneTimeToken.Unlock()
	var allOneTimeTokens []*UserOneTimeToken
	if err := db.Select(&allOneTimeTokens, "SELECT * FROM user_one_time_tokens"); err != nil {
		return err
	}
	userGachaOneTimeTokens = make(map[int64]*UserOneTimeToken, 100000)
	userCardOneTimeTokens = make(map[int64]*UserOneTimeToken, 100000)
	for _, ot := range allOneTimeTokens {
		if ot.TokenType == 1 {
			userGachaOneTimeTokens[ot.UserID] = ot
		} else {
			userCardOneTimeTokens[ot.UserID] = ot
		}
	}

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

func getUser(userID int64) *User {
	muUsers.RLock()
	defer muUsers.RUnlock()
	return users[userID]
}

func cacheUser(user *User) {
	muUsers.Lock()
	defer muUsers.Unlock()
	users[user.ID] = user
}

func getUserDevice(userID int64, platformID string) *UserDevice {
	muUserDevices.RLock()
	defer muUserDevices.RUnlock()
	if userDevices[userID] == nil {
		return nil
	}
	return userDevices[userID][platformID]
}

func getAllUserDeviceByUser(userID int64) []*UserDevice {
	muUserDevices.RLock()
	defer muUserDevices.RUnlock()
	var ret []*UserDevice
	for _, ud := range userDevices[userID] {
		ret = append(ret, ud)
	}
	return ret
}

func cacheUserDevice(device *UserDevice) {
	muUserDevices.Lock()
	defer muUserDevices.Unlock()
	if userDevices[device.UserID] == nil {
		userDevices[device.UserID] = make(map[string]*UserDevice, 4)
	}
	userDevices[device.UserID][device.PlatformID] = device
}

func getAllUserItemsByUser(userID int64) []*UserItem {
	muUserItems.RLock()
	defer muUserItems.RUnlock()
	return userItems[userID]
}

func batchGetUserItemsByItemIDs(userID int64, itemIDs []int64) []*UserItem {
	muUserItems.RLock()
	defer muUserItems.RUnlock()
	ret := make([]*UserItem, 0, len(itemIDs))
	for _, ui := range userItems[userID] {
		for _, itemID := range itemIDs {
			if ui.ItemID == itemID {
				ret = append(ret, ui)
			}
		}
	}
	return ret
}

func batchGetType3UserItemsByIDs(userID int64, ids []int64) []*UserItem {
	muUserItems.RLock()
	defer muUserItems.RUnlock()
	ret := make([]*UserItem, 0, len(ids))
	for _, ui := range userItems[userID] {
		for _, id := range ids {
			if ui.ID == id && ui.ItemType == 3 {
				ret = append(ret, ui)
			}
		}
	}
	return ret
}

func updateUserItem(userID int64, id int64, amount int, updatedAt int64) {
	muUserItems.Lock()
	defer muUserItems.Unlock()
	for _, ui := range userItems[userID] {
		if ui.ID == id {
			ui.Amount = amount
			ui.UpdatedAt = updatedAt
			return
		}
	}
}

func bulkUpsertUserItems(userID int64, items []*UserItem) {
	muUserItems.Lock()
	defer muUserItems.Unlock()
	itemMap := make(map[int64]*UserItem, len(items)+len(userItems[userID]))
	for _, ui := range userItems[userID] {
		itemMap[ui.ID] = ui
	}
	for _, ui := range items {
		itemMap[ui.ID] = ui
	}
	userItems[userID] = make([]*UserItem, 0, len(itemMap))
	for _, ui := range itemMap {
		userItems[userID] = append(userItems[userID], ui)
	}
}

func getAllUserCardsByUser(userID int64) []*UserCard {
	muUserCards.RLock()
	defer muUserCards.RUnlock()
	return userCards[userID]
}

func getUserCard(userID int64, cardID int64) *UserCard {
	muUserCards.RLock()
	defer muUserCards.RUnlock()
	for _, uc := range userCards[userID] {
		if uc.ID == cardID {
			return uc
		}
	}
	return nil
}

func batchGetUserCards(userID int64, cardIDs []int64) []*UserCard {
	muUserCards.RLock()
	defer muUserCards.RUnlock()
	ret := make([]*UserCard, 0, len(cardIDs))
	for _, uc := range userCards[userID] {
		for _, cardID := range cardIDs {
			if uc.ID == cardID {
				ret = append(ret, uc)
			}
		}
	}
	return ret
}

func cacheUserCards(userID int64, cards []*UserCard) {
	muUserCards.Lock()
	defer muUserCards.Unlock()
	if cap(userCards[userID]) == 0 {
		userCards[userID] = make([]*UserCard, 0, 300)
	}
	for _, uc := range cards {
		userCards[userID] = append(userCards[userID], uc)
	}
}

func updateUserCard(userID int64, card *UserCard) {
	muUserCards.Lock()
	defer muUserCards.Unlock()
	for i, uc := range userCards[userID] {
		if uc.ID == card.ID {
			userCards[userID][i] = card
			return
		}
	}
}

func getAllUserDeckByUser(userID int64) []*UserDeck {
	muUserDecks.RLock()
	defer muUserDecks.RUnlock()
	return userDecks[userID]
}

func getUserActiveDeck(userID int64) *UserDeck {
	muUserDecks.RLock()
	defer muUserDecks.RUnlock()
	for _, ud := range userDecks[userID] {
		if ud.DeletedAt == nil {
			return ud
		}
	}
	return nil
}

func cacheNewUserDeck(deck *UserDeck) {
	muUserDecks.Lock()
	defer muUserDecks.Unlock()
	updatedAt := deck.CreatedAt
	for i := range userDecks[deck.UserID] {
		if userDecks[deck.UserID][i].DeletedAt == nil {
			userDecks[deck.UserID][i].UpdatedAt = updatedAt
			userDecks[deck.UserID][i].DeletedAt = &updatedAt
		}
	}
	if cap(userDecks[deck.UserID]) == 0 {
		userDecks[deck.UserID] = make([]*UserDeck, 0, 4)
	}
	userDecks[deck.UserID] = append(userDecks[deck.UserID], deck)
}

func getAllUserLoginBonusByUser(userID int64) []*UserLoginBonus {
	muUserLoginBonuses.RLock()
	defer muUserLoginBonuses.RUnlock()
	return userLoginBonuses[userID]
}

func batchGetUserLoginBonus(userID int64, bonusIDs []int64) []*UserLoginBonus {
	muUserLoginBonuses.RLock()
	defer muUserLoginBonuses.RUnlock()
	var ret []*UserLoginBonus
	for _, ub := range userLoginBonuses[userID] {
		for _, bonusID := range bonusIDs {
			if ub.LoginBonusID == bonusID {
				ret = append(ret, ub)
			}
		}
	}
	return ret
}

func updateUserLoginBonuses(userID int64, bonuses []*UserLoginBonus) {
	muUserLoginBonuses.Lock()
	defer muUserLoginBonuses.Unlock()
	bonusMap := make(map[int64]*UserLoginBonus, len(bonuses)+len(userLoginBonuses[userID]))
	for _, ub := range userLoginBonuses[userID] {
		bonusMap[ub.LoginBonusID] = ub
	}
	for _, ub := range bonuses {
		bonusMap[ub.LoginBonusID] = ub
	}
	userLoginBonuses[userID] = make([]*UserLoginBonus, 0, len(bonusMap))
	for _, ub := range bonusMap {
		userLoginBonuses[userID] = append(userLoginBonuses[userID], ub)
	}
}

func getAllUserPresentReceivedHistoriesByUser(userID int64) []*UserPresentAllReceivedHistory {
	muUserPresentAllReceivedHistories.RLock()
	defer muUserPresentAllReceivedHistories.RUnlock()
	return userPresentAllReceivedHistories[userID]
}

func batchGetUserPresentReceivedHistories(userID int64, presentIDs []int64) []*UserPresentAllReceivedHistory {
	muUserPresentAllReceivedHistories.RLock()
	defer muUserPresentAllReceivedHistories.RUnlock()
	ret := make([]*UserPresentAllReceivedHistory, 0, len(presentIDs))
	for _, up := range userPresentAllReceivedHistories[userID] {
		for _, presentID := range presentIDs {
			if up.PresentAllID == presentID {
				ret = append(ret, up)
			}
		}
	}
	return ret
}

func bulkInsertUserPresentAllReceivedHistories(userID int64, histories []*UserPresentAllReceivedHistory) {
	muUserPresentAllReceivedHistories.Lock()
	defer muUserPresentAllReceivedHistories.Unlock()
	if cap(userPresentAllReceivedHistories[userID]) == 0 {
		userPresentAllReceivedHistories[userID] = make([]*UserPresentAllReceivedHistory, 0, 60)
	}
	userPresentAllReceivedHistories[userID] = append(userPresentAllReceivedHistories[userID], histories...)
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

func getUserOneTimeToken(userID int64, tokenType int) *UserOneTimeToken {
	muOneTimeToken.RLock()
	defer muOneTimeToken.RUnlock()

	if tokenType == 1 {
		return userGachaOneTimeTokens[userID]
	}

	return userCardOneTimeTokens[userID]
}

func cacheUserOneTimeToken(token *UserOneTimeToken) {
	muOneTimeToken.Lock()
	defer muOneTimeToken.Unlock()

	if token.TokenType == 1 {
		userGachaOneTimeTokens[token.UserID] = token
	} else {
		userCardOneTimeTokens[token.UserID] = token
	}
}

func deleteUserOneTimeToken(userID int64, tokenType int) {
	muOneTimeToken.Lock()
	defer muOneTimeToken.Unlock()

	if tokenType == 1 {
		delete(userGachaOneTimeTokens, userID)
	} else {
		delete(userCardOneTimeTokens, userID)
	}
}
